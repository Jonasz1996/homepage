"""Noodplan: één document om af te drukken (of als pdf te bewaren) met wat er waar draait en hoe je het terugzet, ook
als het dashboard zelf plat ligt.

Per Proxmox-node elke VM en CT met IP, MAC, schijven en of elke schijf in de back-up zit, waar de back-ups staan (PBS,
datastore, jobs), één commando per VM/CT om hem terug te zetten, waar de kopieën van OPNsense en NPM staan, welke
sleutels je nodig hebt en waar ze liggen (nooit hun waarde), hoe je het dashboard zelf terugzet, en de adressen van
alles op IP (zonder DNS).

De worker maakt het elke maandag vanaf 6 uur (en wie op "nu bijwerken" klikt): uit wat de worker al bijhoudt
(back-updekking, cluster, apparaten, routes van NPM, kopieën van de configuratie, zelfcontrole) plus een paar vragen die
alleen lezen (config van elke VM/CT, status en netwerk van de nodes, de PBS-opslag in Proxmox, de nieuwste back-up per
VM/CT, de datastores van elke PBS). Lukt een bron niet, dan komt dat deel uit het vorige noodplan, met zijn datum.
Bewaard in AppState "noodplan"; staat de kopie buiten de container aan, dan ook als noodplan.html en noodplan.md naast
de dumps (leesbaar vanaf de share, zoals de dumps). Het document zelf maakt noodplan_doc.py.
"""

import asyncio
import ipaddress
import logging
import os
import re
import socket
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote, urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import proef
from ..config import get_settings
from ..db import ensure_state, job_lock
from ..deps import event, notify
from ..health import scan as hw, selfcheck
from ..health.security import SECRET_SAVED
from ..integrations import IntegrationError, build
from ..masking import mask, variants
from ..models import AppState, ConfigVersion, Device, Service, SshHost
from ..security import decrypt
from ..ssh_discovery import pick_ipv4
from . import configs, noodplan_doc as doc, restoretest
from .noodplan_doc import day

log = logging.getLogger("homepage.noodplan")

# Het document rekent ook met het moment van de week en maakt de commando's om terug te zetten: hier dezelfde.
HOUR, slot, next_slot = doc.HOUR, doc.slot, doc.next_slot
restore_command, storage_note = doc.restore_command, doc.storage_note

STATE_KEY = "noodplan"
RETRY = timedelta(hours=1)  # een mislukte poging: pas na een uur opnieuw
START_DELAY = timedelta(minutes=15)  # niet vlak na de start van de worker: coverage, cluster, devices, routes eerst
BUSY = timedelta(minutes=5)  # "running" ouder dan dit = een afgebroken run
STALE = timedelta(days=15)  # ouder: punt in Aandacht
OLD_SOURCE = timedelta(days=14)  # een deel dat zo lang uit een oud noodplan komt: punt in Aandacht
FILES = ("noodplan.html", "noodplan.md")
PARALLEL = 6  # gastconfigs tegelijk
DNS_WAIT = 3  # seconden per naam
# Eén bron voor de run én de proef: dezelfde paden.
PVE_CALLS = {"resources": "/cluster/resources", "storage": "/storage",
             "status": "/nodes/{node}/status", "network": "/nodes/{node}/network",
             "config": "/nodes/{node}/{type}/{vmid}/config",
             "content": "/nodes/{node}/storage/{storage}/content?content=backup",
             # alleen voor een draaiende VM/CT zonder vast IP die OPNsense niet zag:
             "lxc_ifs": "/nodes/{node}/lxc/{vmid}/interfaces",
             "agent": "/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces"}
PBS_CALLS = {"datastores": "/config/datastore"}
# Alleen deze sleutels uit de config van een VM/CT: alles anders (description, hookscript, cipassword, sshkeys, args,
# smbios1, lock, unused...) blijft weg, ook in het geheugen. Vrije tekst kan een wachtwoord bevatten.
KEEP = re.compile(r"^(net\d+|ipconfig\d+|rootfs|mp\d+|scsi\d+|virtio\d+|sata\d+|ide\d+|efidisk\d+|tpmstate\d+|"
                  r"hostpci\d+|usb\d+|dev\d+|onboot|startup|cores|memory|hostname|name|unprivileged|agent|arch|"
                  r"nameserver|searchdomain)$")
_DISK = re.compile(r"^(rootfs|mp\d+|scsi\d+|virtio\d+|sata\d+|ide\d+|efidisk\d+|tpmstate\d+)$")
_BOUND = re.compile(r"^(hostpci\d+|usb\d+|dev\d+)$")
_MAC = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.I)
ON = ("1", "true", "yes", "on")
OFF = ("0", "false", "no", "off")
ARCH = {"amd64": "x86_64", "x86_64": "x86_64", "arm64": "aarch64", "aarch64": "aarch64", "i386": "i686",
        "armhf": "armv7l"}


# --- puur: de config van een VM/CT lezen ---------------------------------------------------------------------------

def _opts(value) -> tuple[str, dict[str, str]]:
    """'local-lvm:vm-101-disk-0,size=32G' → ('local-lvm:vm-101-disk-0', {'size': '32G'}). Het eerste deel zonder = is
    de waarde zelf; staan er alleen sleutels (een netwerkkaart), dan is die leeg."""
    first, opts = "", {}
    for i, part in enumerate(str(value).split(",")):
        k, eq, v = part.partition("=")
        if i == 0 and not eq:
            first = part.strip()
        elif eq:
            opts[k.strip()] = v.strip()
    return first, opts


def parse_net(key: str, value, kind: str) -> dict:
    """qemu: virtio=BC:24:11:..,bridge=vmbr0,tag=20 → model, mac, bridge, tag. lxc: name=eth0,bridge=vmbr0,
    hwaddr=BC:..,ip=192.168.10.156/24,gw=...,tag=10 → mac, ip, gw, bridge, tag (ip=dhcp blijft "dhcp")."""
    _, o = _opts(value)
    out = {"if": key, "mac": None, "bridge": o.get("bridge"), "tag": int(o["tag"]) if o.get("tag", "").isdigit() else None,
           "ip": None, "gw": None, "model": None}
    if kind == "lxc":
        out["mac"] = (o.get("hwaddr") or "").lower() or None
        out["ip"] = o.get("ip") or None
        out["gw"] = o.get("gw") or None
        out["name"] = o.get("name")
    else:
        for k, v in o.items():
            if _MAC.match(v):
                out["model"], out["mac"] = k, v.lower()
                break
        out["mac"] = out["mac"] or (o.get("macaddr") or "").lower() or None
    return out


def parse_ipconfig(value) -> dict:
    """cloud-init: ip=192.168.0.30/24,gw=192.168.0.1 → ip, gw (ip=dhcp → "dhcp"; ip6 telt niet)."""
    _, o = _opts(value)
    return {"ip": o.get("ip") or None, "gw": o.get("gw") or None}


def parse_disk(key: str, value, kind: str) -> dict | None:
    """Een schijf, en of ze in de back-up zit (zoals vzdump): de rootfs van een CT altijd; een mount point van een CT
    met een volume alleen met backup=1 (de webinterface zet dat aan, de API niet); bind mounts en apparaten van een CT
    nooit; een schijf van een VM wel, behalve met backup=0. Een cd-rom (of "none"): None."""
    first, o = _opts(value)
    vol = o.get("volume") or first
    if vol == "none" or o.get("media") == "cdrom" or not vol:
        return None
    out = {"key": key, "storage": None, "size": o.get("size"), "mp": o.get("mp"), "bind": None, "in_backup": True,
           "why": None}
    if kind == "lxc" and vol.startswith("/"):
        out.update(bind=vol, in_backup=False, why="apparaat" if vol.startswith("/dev/") else "bind mount")
        return out
    out["storage"] = vol.split(":", 1)[0] if ":" in vol else None
    if kind == "lxc" and key != "rootfs":
        if (o.get("backup") or "").lower() not in ON:
            out.update(in_backup=False, why="mount point zonder backup=1")
    elif kind != "lxc" and (o.get("backup") or "").lower() in OFF:
        out.update(in_backup=False, why="backup=0")
    return out


def parse_bound(key: str, value, node: str | None) -> dict | None:
    """Wat een VM/CT aan een node bindt: PCI- of USB-doorgifte, een apparaat van de node in een CT. Met een mapping
    (Datacenter → Resource Mappings) kan hij op elke node met die mapping."""
    first, o = _opts(value)
    if o.get("mapping"):
        what = "PCI" if key.startswith("hostpci") else "USB"
        return {"key": key, "what": f"{what}-mapping {o['mapping']}", "mapping": o["mapping"]}
    if key.startswith("hostpci"):
        dev = o.get("host") or first
        return {"key": key, "what": f"PCI {dev}", "node": node} if dev else None
    if key.startswith("usb"):
        dev = o.get("host") or first
        if not dev or dev == "spice" or first == "spice":
            return None
        return {"key": key, "what": f"USB {dev}", "node": node}
    dev = o.get("path") or first
    return {"key": key, "what": f"apparaat {dev}", "node": node} if dev else None


def _int(v) -> int | None:
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def pick_config(cfg: dict, kind: str, node: str | None = None) -> dict:
    """Alleen wat in het noodplan hoort (KEEP); de rest wordt niet eens bekeken."""
    keep = {k: v for k, v in (cfg or {}).items() if isinstance(k, str) and KEEP.match(k)}
    nets, ipc = {}, {}
    disks, bound = [], []
    for k in sorted(keep, key=lambda k: (k != "rootfs", re.sub(r"\d+$", "", k), _int(re.sub(r"^\D+", "", k)) or 0)):
        v = keep[k]
        if k.startswith("net"):
            nets[k[3:]] = parse_net(k, v, kind)
        elif k.startswith("ipconfig"):
            ipc[k[8:]] = parse_ipconfig(v)
        elif _DISK.match(k):
            if d := parse_disk(k, v, kind):
                disks.append(d)
        elif _BOUND.match(k):
            if b := parse_bound(k, v, node):
                bound.append(b)
    for n, c in ipc.items():
        if n in nets:
            nets[n].update({x: c[x] for x in ("ip", "gw") if c.get(x)})
            nets[n]["cloudinit"] = True
    startup = _opts(keep.get("startup") or "")[1]
    agent = str(keep.get("agent") or "")
    return {"nets": [nets[n] for n in sorted(nets, key=lambda x: _int(x) or 0)], "disks": disks, "bound": bound,
            "onboot": str(keep.get("onboot", "0")).lower() in ON, "order": _int(startup.get("order")),
            "cores": _int(keep.get("cores")), "memory": _int(keep.get("memory")),
            "unprivileged": str(keep.get("unprivileged", "0")).lower() in ON,
            "agent": (agent.split(",")[0].removeprefix("enabled=")).lower() in ON,
            "arch": keep.get("arch"), "dns": {"nameserver": keep.get("nameserver"),
                                              "searchdomain": keep.get("searchdomain")}}


def parse_conf_text(text: str) -> dict:
    """De regels "sleutel: waarde" van een bewaarde .conf (configs.pve_text); snapshots ([naam]) tellen niet."""
    out = {}
    for line in (text or "").splitlines():
        if line.startswith("["):
            break
        k, sep, v = line.partition(":")
        if sep and k.strip() and not k.startswith("#"):
            out[k.strip()] = v.strip()
    return out


def static_ip(nets: list[dict]) -> tuple[str | None, str | None]:
    """Het eerste vaste IPv4 uit de config: (ip, "vast" of "vast (cloud-init)")."""
    for n in nets:
        ip = (n.get("ip") or "").split("/")[0]
        try:
            if ipaddress.ip_address(ip).version == 4:
                return ip, "vast (cloud-init)" if n.get("cloudinit") else "vast"
        except ValueError:
            continue
    return None, None


# --- puur: back-ups, nodes en jobs ---------------------------------------------------------------------------------

def newest_volids(items: list[dict]) -> dict[tuple[str, int], tuple[str, int, str | None]]:
    """Uit de inhoud van een PBS-opslag: per (lxc|qemu, vmid) de nieuwste back-up: (volid, ctime, vingerafdruk van de
    sleutel als ze versleuteld is)."""
    out: dict[tuple[str, int], tuple[str, int, str | None]] = {}
    for b in items or []:
        volid = str(b.get("volid") or "")
        sub = b.get("subtype") or ("lxc" if "/ct/" in volid else "qemu" if "/vm/" in volid else None)
        vmid = _int(b.get("vmid"))
        if not volid or sub not in ("lxc", "qemu") or vmid is None:
            continue
        t = _int(b.get("ctime")) or 0
        if (sub, vmid) not in out or t > out[(sub, vmid)][1]:
            enc = b.get("encrypted")
            out[(sub, vmid)] = (volid, t, str(enc) if enc else None)
    return out


def job_targets(job: dict, rows: list[dict], guests: list[dict]) -> dict:
    """Welke VM's/CT's een back-upjob neemt, uit de dekking (rows[].jobs: de jobs die elke VM/CT nemen). Een job voor
    "alle" krijgt ook de uitzonderingen: de VM's/CT's (op zijn node, als die ingesteld is) die hij niet neemt."""
    if not job.get("enabled", True):
        return {"targets": [], "except": []}
    targets = sorted({int(r["vmid"]) for r in rows if job.get("id") in (r.get("jobs") or [])})
    ex = []
    if job.get("all"):
        ex = sorted({int(g["vmid"]) for g in guests
                     if (not job.get("node") or g.get("node") == job["node"]) and int(g["vmid"]) not in targets})
    return {"targets": targets, "except": ex}


def node_ip(network: list[dict] | None, corosync: str | None) -> tuple[str | None, str]:
    """Het IP van de webinterface: dat van de interface met een gateway (de beheer-bridge), anders de eerste actieve
    bridge met een adres, anders het corosync-IP uit de clusterstatus (dat kan een apart netwerk zijn)."""
    ifs = [i for i in network or [] if isinstance(i, dict)]

    def v4(i: dict) -> str | None:
        a = (i.get("address") or i.get("cidr") or "").split("/")[0]
        try:
            return a if ipaddress.ip_address(a).version == 4 else None
        except ValueError:
            return None
    for i in ifs:
        if i.get("gateway") and v4(i):
            return v4(i), "netwerk"
    for i in ifs:
        if i.get("type") == "bridge" and i.get("active", 1) and v4(i):
            return v4(i), "netwerk"
    return (corosync, "corosync") if corosync else (None, "onbekend")


def node_arch(status: dict | None, guest_archs: list[str]) -> str | None:
    """x86_64 of aarch64: uit de kernel van de node (Proxmox 8.1 en nieuwer), anders uit de CT's erop."""
    m = ((status or {}).get("current-kernel") or {}).get("machine")
    if m:
        return str(m)
    for a in guest_archs:
        if a and ARCH.get(str(a)):
            return ARCH[str(a)]
    return None


# --- puur: wanneer ------------------------------------------------------------------------------------------------

def _at(iso) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(iso))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def is_busy(value: dict | None, now: datetime) -> bool:
    """Loopt er een noodplan (API of worker)? Een "running" van meer dan 5 minuten is een afgebroken run."""
    busy = (value or {}).get("running")
    at = _at(busy.get("at")) if isinstance(busy, dict) else None
    return at is not None and now - at < BUSY


def due(value: dict | None, now: datetime) -> bool:
    """Is het noodplan van deze week er nog niet (maandag vanaf 6 uur)? Niet terwijl er een loopt, en een mislukte
    poging pas na een uur opnieuw. Een noodplan met de knop na maandag 6 uur telt ook voor deze week."""
    value = value or {}
    if is_busy(value, now):
        return False
    tried = _at(value.get("tried"))
    if tried and now - tried < RETRY:
        return False
    at = _at(value.get("at"))
    return at is None or at < slot(now)


def problems(value: dict | None, now: datetime) -> list[tuple[str, str]]:
    """(sleutel, tekst) van wat er mis is met het noodplan: te oud, een deel dat al twee weken uit een oud noodplan
    komt, of iets dat de maskering moest vervangen. Voor Aandacht, de checklist en het venster."""
    v = value or {}
    at = _at(v.get("at"))
    if at is None:
        return []
    out = []
    if now - at > STALE:
        out.append(("oud", f"laatst bijgewerkt {day(at)}, {(now - at).days} dagen geleden"))
    for s in v.get("sources") or []:
        if s.get("ok") or s.get("covered"):
            continue
        # Sinds wanneer dat deel oud is: het laatste noodplan waarin het lukte, of (lukte het nog nooit) de eerste
        # mislukte poging. Eén week mislukt is nog geen punt: de cluster of PBS meldt de storing zelf al.
        since = _at(s.get("from")) or _at(s.get("failing_since"))
        if since is not None and now - since > OLD_SOURCE:
            out.append((f"bron:{s.get('key')}", f"{s.get('name')}: {s.get('error') or 'fout'}, "
                        + (f"dit deel komt uit het noodplan van {day(since)}" if s.get("from") else
                           "dit deel ontbreekt")))
    if v.get("masked"):
        kinds = ", ".join(v.get("masked_kinds") or []) or "?"
        out.append(("masker", f"er stond iets in dat op een geheim leek ({kinds}); dat is vervangen door ***. Kijk na "
                              "waar het staat"))
    return out


# --- adressen ------------------------------------------------------------------------------------------------------

def _is_ip(host: str | None) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def _route(routes: dict | None, name: str) -> dict | None:
    from .routes import Table
    return Table(routes).entry(name)


async def _resolve(name: str) -> str | None:
    """Eén naam opzoeken in DNS (IPv4, hoogstens 3 s), zoals routes._npm_ip."""
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(name, None, family=socket.AF_INET),
                                       DNS_WAIT)
    except (OSError, TimeoutError, asyncio.TimeoutError, UnicodeError):
        return None
    return infos[0][4][0] if infos else None


def _swap(url: str, scheme: str | None, ip: str, port: int | None) -> str:
    p = urlsplit(url)
    host = f"[{ip}]" if ":" in ip else ip
    port = port if port is not None else p.port
    return f"{scheme or p.scheme}://{host}" + (f":{port}" if port else "") + (p.path if p.path not in ("", "/") else "")


def _lan(ip: str) -> bool:
    """Een LAN-adres: een publiek adres uit DNS (bv. van Cloudflare) of loopback is niet het IP van het systeem."""
    a = ipaddress.ip_address(ip)
    return a.is_private and not (a.is_loopback or a.is_link_local or a.is_unspecified)


async def ip_from_url(url: str | None, routes: dict | None, npm_ip: str | None) -> tuple[str | None, str, str | None]:
    """(IP, hoe, adres op IP) voor een adres: staat er al een IP in → "ip"; kent NPM de naam met een IP als doel → dat
    doel, "npm"; anders DNS (3 s), als dat een LAN-adres geeft en niet het IP van NPM zelf → "dns"; anders (None,
    "onbekend", None)."""
    host = urlsplit(url or "").hostname
    if not host:
        return None, "onbekend", None
    if _is_ip(host):
        return host, "ip", _swap(url, None, host, None)
    e = _route(routes, host)
    if e and _is_ip(e.get("host")):
        return e["host"], "npm", _swap(url, e.get("scheme"), e["host"], e.get("port"))
    ip = await _resolve(host)
    if ip and _lan(ip) and ip != npm_ip and not (e and ip == e.get("via")):
        return ip, "dns", _swap(url, None, ip, None)
    return None, "onbekend", None


def dns_names(urls: list[str | None], routes: dict | None) -> list[str]:
    """De namen die ip_from_url in DNS zou opzoeken: geen IP en niet in NPM met een IP als doel (voor de run én de
    proef)."""
    out = []
    for url in urls:
        host = urlsplit(url or "").hostname
        if not host or _is_ip(host) or host in out:
            continue
        e = _route(routes, host)
        if not (e and _is_ip(e.get("host"))):
            out.append(host)
    return out


# --- bestanden buiten de container ---------------------------------------------------------------------------------

def dir_problem(dst: Path) -> str | None:
    """Waarom er niet in de map van de kopie buiten de container geschreven kan worden (zoals de zelfcontrole)."""
    if not dst.is_dir():
        return f"map {dst} bestaat niet (koppel er een NAS-share, PBS-opslag of USB-schijf aan)"
    if not os.access(dst, os.W_OK):
        return f"geen schrijfrechten op {dst} voor gebruiker homepage"
    return None


def write_offsite(dst: Path, html: str, md: str) -> dict:
    """noodplan.html en noodplan.md naar de map van de kopie buiten de container, leesbaar (0644) zoals de dumps, wat
    het umask van het proces ook is. Eerst als .part, dan in één keer op zijn plaats."""
    if err := dir_problem(dst):
        return {"files": [], "error": err}
    done = []
    for name, text in zip(FILES, (html, md)):
        part = dst / f".{name}.part"
        try:
            part.write_text(text, encoding="utf-8")
            os.chmod(part, 0o644)
            os.replace(part, dst / name)
        except OSError as e:
            part.unlink(missing_ok=True)
            return {"files": done, "error": str(e)[:300]}
        done.append(name)
    return {"files": done, "error": None}


# --- wat het dashboard al weet -------------------------------------------------------------------------------------

# Tegels met een beheerpagina die in "toegang zonder DNS" komt (naast de nodes, de PBS'en en het dashboard zelf).
TILE_TYPES = {"opnsense": "OPNsense", "npm": "Nginx Proxy Manager", "zabbix": "Zabbix", "adguard": "AdGuard Home",
              "homeassistant": "Home Assistant"}
# Deze tegels krijgen geen plaats als "dienst" op een VM/CT: ze staan al apart in het noodplan.
NOT_PLACED = ("proxmox", "proxmoxbackupserver", "opnsense", "npm")
_FP = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2})+$", re.I)


async def sources(db: AsyncSession) -> list[dict]:
    """Elke Proxmox- en PBS-tegel: dezelfde lijst voor de run en de proef."""
    rows = (await db.execute(select(Service).where(Service.type.in_(("proxmox", "proxmoxbackupserver")))
                             .order_by(Service.id))).scalars()
    out = []
    for s in rows:
        kind = "pve" if s.type == "proxmox" else "pbs"
        out.append({"key": f"{kind}:{s.id}", "kind": kind, "service": s, "name": s.name})
    return out


def _connect(srcs: list[dict], http) -> None:
    """Het integratie-object per bron (nog geen verzoek): met de sessie nog open, want een tegel aan een API uit
    API-beheer leest die API mee."""
    for s in srcs:
        try:
            s["integ"] = build(s["service"], http)
            s["base"] = s["integ"].base
        except IntegrationError as e:
            s["integ"], s["base"], s["error"] = None, None, str(e)[:300]


async def _value(db: AsyncSession, key: str) -> dict:
    st = await db.get(AppState, key)
    return dict(st.value) if st and isinstance(st.value, dict) else {}


def _iso(dt: datetime | None) -> str | None:
    if dt is None:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).isoformat()


def _lan_open() -> bool | None:
    """Laat nginx het hele LAN rechtstreeks binnen (install.sh schrijft het in /etc/homepage/nginx)? None: onbekend."""
    try:
        text = get_settings().nginx_file.read_text()
    except OSError:
        return None
    st = {k.strip(): v.strip() for k, _, v in (line.partition("=") for line in text.splitlines())}
    return st.get("lan") != "dicht"


async def _snapshot(db: AsyncSession) -> dict:
    """Alles wat de worker al bijhoudt, als gewone dicts: daarna gaat de sessie dicht (geen transactie open tijdens
    de API-vragen). Alleen wat in het noodplan komt: van de wachtzin van secret.key.enc alleen de datum, van OIDC
    alleen of het aan staat en de host, van de kopieën van de config alleen naam, datum en aantal (de inhoud van de
    nieuwste .conf per VM/CT blijft versleuteld tot de node zelf geen antwoord geeft)."""
    from ..routers.versie import installed

    s = get_settings()
    oidc = await _value(db, "oidc")
    rt = await _value(db, restoretest.STATE_KEY)
    last_test = next(iter(rt.get("history") or []), None) or {}
    tunnels = []
    for st in (await db.execute(select(AppState).where(AppState.key.like("net_tunnel:%"))
                                .order_by(AppState.key))).scalars():
        sid = _int(st.key.split(":", 1)[1])
        for t in (st.value or {}).get("items") or []:
            tunnels.append({"service_id": sid, "name": t.get("name"), "status": t.get("status"),
                            "connections": t.get("connections")})
    by_mac, by_ip = {}, {}
    for d in (await db.execute(select(Device).where(Device.ip.is_not(None)).order_by(Device.last_seen))).scalars():
        by_mac[(d.mac or "").lower()] = {"ip": d.ip, "seen": _iso(d.last_seen)}
        by_ip[d.ip] = (d.mac or "").lower()  # de laatst geziene wint
    ssh = {}
    for src, host in (await db.execute(select(SshHost.source, SshHost.host)
                                       .where(SshHost.source.like("pve:%")))).all():
        if _is_ip(host):
            ssh[src.rsplit(":", 1)[-1]] = host
    over = await configs.overview(db)
    pve_items = {o["id"]: o for o in over if o["kind"] == "pve"}
    conf: dict[int, list[dict]] = {}
    if pve_items:
        for item, ts, content in (await db.execute(select(ConfigVersion.item, ConfigVersion.ts, ConfigVersion.content)
                                                   .where(ConfigVersion.id.in_(list(pve_items))))).all():
            _, svc, vmid = (item.split(":") + ["", ""])[:3]
            if (v := _int(vmid)) is not None:
                conf.setdefault(v, []).append({"service_id": _int(svc), "at": _iso(ts), "content": content})
    for copies in conf.values():
        copies.sort(key=lambda c: c["at"] or "", reverse=True)
    tiles = [{"id": t.id, "name": t.name, "type": t.type, "url": t.url, "parent_id": t.parent_id,
              "check": {k: (t.check or {}).get(k) for k in ("type", "target")}}
             for t in (await db.execute(select(Service).order_by(Service.id))).scalars()]
    return {
        "coverage": await _value(db, "coverage"), "cluster": await _value(db, "cluster"),
        "routes": {"hosts": (await _value(db, "npm_routes")).get("hosts") or {}},
        "selfcheck": await _value(db, selfcheck.STATE_KEY),
        "offsite_key_at": (await _value(db, selfcheck.KEY_STATE)).get("at"),
        "secret_saved_at": (await _value(db, SECRET_SAVED)).get("at"),
        "restore_test": {k: last_test.get(k) for k in ("at", "ok", "name", "source_vmid")} if last_test else None,
        "config_last": await _value(db, configs.LAST_KEY), "config_settings": await configs.settings(db),
        "oidc": {"enabled": bool(oidc.get("enabled")), "issuer": oidc.get("issuer") or None},
        "tunnels": tunnels, "by_mac": by_mac, "by_ip": by_ip, "ssh": ssh,
        "configs": [{"kind": o["kind"], "name": o["name"], "ts": _iso(o["ts"]), "versions": o["versions"]} for o in over],
        "pve_conf": conf, "tiles": tiles,
        "offsite_on": bool((await hw.settings(db)).get("offsite")),
        "versions": await selfcheck.db_versions(db), "versie": installed(), "lan_open": _lan_open(),
        "settings": {"syslog_target": s.syslog_target or None, "npm_ip": s.npm_ip or None,
                     "secret_key_file": str(s.secret_key_file), "backup_dir": str(s.backup_dir),
                     "offsite_dir": str(s.offsite_dir)},
    }


# --- Proxmox -------------------------------------------------------------------------------------------------------

def _encryption(v) -> str | bool:
    """encryption-key uit storage.cfg: een vingerafdruk of 1. Iets anders wordt alleen "ja": nooit een sleutel
    bewaren, ook niet als een versie van Proxmox er ooit meer zou teruggeven."""
    if v in (None, "", 0, "0", False):
        return False
    return str(v) if _FP.match(str(v)) else True


async def _live_ip(px, node: str, kind: str, vmid: int) -> tuple[str | None, str | None, str | None]:
    """(IP, hoe, waarom niet) van een draaiende VM/CT zonder vast IP die OPNsense niet zag: de interfaces van een CT,
    de guest agent van een VM (de config is er al, die wordt niet opnieuw gevraagd)."""
    try:
        if kind == "lxc":
            ifs = await px.get(PVE_CALLS["lxc_ifs"].format(node=node, vmid=vmid))
            ip = pick_ipv4([(i.get("name", ""), i.get("inet") or "") for i in ifs or [] if isinstance(i, dict)])
            return (ip, "CT-interfaces", None) if ip else (None, None, "geen IPv4 in de CT")
        data = await px.get(PVE_CALLS["agent"].format(node=node, vmid=vmid))
        result = data.get("result", []) if isinstance(data, dict) else []
        ip = pick_ipv4([(i.get("name", ""), a.get("ip-address", "")) for i in result if isinstance(i, dict)
                        for a in i.get("ip-addresses") or [] if a.get("ip-address-type") == "ipv4"])
        return (ip, "guest agent", None) if ip else (None, None, "geen IPv4 van de guest agent")
    except IntegrationError as e:
        text = str(e)
        if "403" in text:
            return None, None, "geen rechten (" + ("VM.Audit" if kind == "lxc" else "VM.GuestAgent.Audit") + ")"
        if kind == "qemu" and ("500" in text or "agent" in text.lower()):
            return None, None, "geen QEMU guest agent"
        return None, None, text[:120]


def _prev_nodes(prev: dict, names: set[str]) -> dict[str, dict]:
    return {n["name"]: n for c in (prev.get("data") or {}).get("clusters") or [] for n in c.get("nodes") or []
            if n.get("name") in names}


def _copy(snap: dict, svc_id: int, vmid: int) -> dict | None:
    """De nieuwste bewaarde .conf van deze VM/CT, bij voorkeur van dezelfde tegel."""
    copies = snap["pve_conf"].get(vmid) or []
    return next((c for c in copies if c["service_id"] == svc_id), copies[0] if copies else None)


async def _pve(src: dict, px, snap: dict, prev: dict) -> dict:
    """Eén Proxmox-tegel: nodes, VM's en CT's met hun config, IP en back-ups, de PBS-opslag en de back-upjobs.
    Alleen de lijst van de cluster moet lukken; de rest mag elk apart mislukken (dan staat er "onbekend")."""
    svc = src["service"]
    sem = asyncio.Semaphore(PARALLEL)

    async def get(path: str):
        async with sem:
            return await px.get(path)

    async def safe(path: str):
        try:
            return await get(path)
        except IntegrationError:
            return None

    res = [r for r in await get(PVE_CALLS["resources"]) if isinstance(r, dict)]
    node_rows = sorted((r for r in res if r.get("type") == "node" and r.get("node")), key=lambda r: r["node"])
    names = [r["node"] for r in node_rows]
    online = [r["node"] for r in node_rows if r.get("status") == "online"]
    guest_rows = sorted((r for r in res if r.get("type") in ("lxc", "qemu") and not r.get("template")
                         and _int(r.get("vmid")) is not None), key=lambda r: int(r["vmid"]))

    storage = await safe(PVE_CALLS["storage"])
    stores = [{"storage": s.get("storage"), "server": s.get("server"), "datastore": s.get("datastore"),
               "namespace": s.get("namespace") or "", "fingerprint": s.get("fingerprint"),
               "username": s.get("username"),
               "encrypted": _encryption(s.get("encryption-key")) if isinstance(storage, list) else None,
               "master_key": bool(s.get("master-pubkey")), "enabled": str(s.get("disable") or "0").lower() not in ON,
               "nodes": [n for n in str(s.get("nodes") or "").split(",") if n]}
              for s in storage or [] if isinstance(s, dict) and s.get("type") == "pbs" and s.get("storage")]

    async def node_info(name: str) -> tuple[dict | None, list | None]:
        st, net = await asyncio.gather(safe(PVE_CALLS["status"].format(node=name)),
                                       safe(PVE_CALLS["network"].format(node=name)))
        return st if isinstance(st, dict) else None, net if isinstance(net, list) else None

    async def config(r: dict) -> tuple[dict | None, str | None, str | None]:
        kind, node, vmid = r["type"], r.get("node"), int(r["vmid"])
        try:
            cfg = await get(PVE_CALLS["config"].format(node=node, type=kind, vmid=vmid))
            if isinstance(cfg, dict):
                return pick_config(cfg, kind, node), "api", None
        except IntegrationError:
            pass
        if copy := _copy(snap, svc.id, vmid):
            try:
                return pick_config(parse_conf_text(decrypt(copy["content"])), kind, node), "kopie", copy["at"]
            except Exception:  # noqa: BLE001 - een andere secret.key of een kapotte kopie: dan onbekend
                log.warning("noodplan: kopie van de config van %s niet te lezen", vmid)
        return None, None, None

    async def content(s: dict) -> tuple[str, dict]:
        node = next((n for n in online if not s["nodes"] or n in s["nodes"]), None)
        if not s["enabled"] or node is None:
            return s["storage"], {}
        items = await safe(PVE_CALLS["content"].format(node=node, storage=quote(s["storage"])))
        return s["storage"], newest_volids(items if isinstance(items, list) else [])

    infos, confs, vols = await asyncio.gather(
        asyncio.gather(*(node_info(n) for n in online)), asyncio.gather(*(config(r) for r in guest_rows)),
        asyncio.gather(*(content(s) for s in stores)))
    infos = dict(zip(online, infos))
    vols = dict(vols)
    for s in stores:
        # Geen sleutel in storage.cfg maar wel versleutelde back-ups: dan is de sleutel er toch nodig.
        if not s["encrypted"]:
            fp = next((enc for v in (vols.get(s["storage"]) or {}).values() if (enc := v[2])), None)
            s["encrypted"] = _encryption(fp) if fp else s["encrypted"]

    cov = next((c for c in snap["coverage"].get("clusters") or [] if set(c.get("nodes") or []) & set(names)), {})
    cov_at = _at(snap["coverage"].get("at"))
    rows = {int(r["vmid"]): r for r in cov.get("rows") or [] if _int(r.get("vmid")) is not None}
    guests, live = [], []
    for r, (cfg, frm, cat) in zip(guest_rows, confs):
        kind, vmid, node = r["type"], int(r["vmid"]), r.get("node")
        c, row = cfg or {}, rows.get(vmid) or {}
        mine = {sto: v[(kind, vmid)] for sto, v in vols.items() if (kind, vmid) in v}
        g = {"vmid": vmid, "type": kind, "name": r.get("name") or str(vmid), "node": node, "status": r.get("status"),
             "onboot": bool(c.get("onboot")), "order": c.get("order"), "cores": c.get("cores"),
             "memory": c.get("memory"), "arch": c.get("arch"), "unprivileged": c.get("unprivileged"),
             "nets": c.get("nets") or [], "dns": c.get("dns") or {}, "disks": c.get("disks") or [],
             "bound": c.get("bound") or [], "config_from": frm, "config_at": cat,
             "ip": None, "ip_from": None, "ip_why": None,
             "backups": [{"pbs": x.get("pbs"), "store": x.get("store"), "ns": x.get("ns"), "count": x.get("count"),
                          "last": (cov_at - timedelta(seconds=x["age"])).replace(microsecond=0).isoformat()
                          if cov_at and isinstance(x.get("age"), (int, float)) else None}
                         for x in row.get("copies") or []],
             "volids": {sto: v[0] for sto, v in mine.items()},
             "encrypted": next((v[2] for v in mine.values() if v[2]), None),
             "jobs": row.get("jobs") or [],
             "coverage": {"level": row.get("level"), "why": row.get("why")} if row else None,
             "restore_test": row.get("restore"), "services": [], "roles": []}
        ip, how = static_ip(g["nets"])
        if not ip:
            for n in g["nets"]:
                if d := snap["by_mac"].get((n.get("mac") or "").lower()):
                    ip, how = d["ip"], f"ARP/DHCP (OPNsense), gezien {day(d['seen'])}"
                    break
        if not ip and (h := snap["ssh"].get(f"{kind}/{vmid}")):
            ip, how = h, "SSH-host"
        g["ip"], g["ip_from"] = ip, how
        if not ip:
            if g["status"] != "running":
                g["ip_why"] = ("staat uit" if g["status"] == "stopped" else "node niet bereikbaar" if node not in online
                               else f"status {g['status'] or 'onbekend'}") + (
                    ", IP via DHCP" if any(n.get("ip") == "dhcp" for n in g["nets"]) else "")
            elif kind == "qemu" and cfg is not None and not c.get("agent"):
                g["ip_why"] = "geen QEMU guest agent (staat uit in de config)"
            else:
                live.append(g)
        guests.append(g)

    async def fill(g: dict) -> None:
        async with sem:
            g["ip"], g["ip_from"], g["ip_why"] = await _live_ip(px, g["node"], g["type"], g["vmid"])
    await asyncio.gather(*(fill(g) for g in live))

    clu = next((c for c in snap["cluster"].get("items") or []
                if {n.get("name") for n in c.get("nodes") or []} & set(names)), {})
    coro = {n.get("name"): n for n in clu.get("nodes") or []}
    before = _prev_nodes(prev, set(names))
    nodes = []
    for r in node_rows:
        name, on = r["node"], r.get("status") == "online"
        st, net = infos.get(name, (None, None))
        cn, pn = coro.get(name) or {}, before.get(name) or {}
        ip, frm = node_ip(net, cn.get("ip"))
        ip_at = None
        if frm != "netwerk" and pn.get("ip") and pn.get("ip_from") in ("netwerk", "vorig"):
            # Offline (of het netwerk van de node niet te lezen): het IP van de webinterface uit het vorige noodplan.
            ip, frm = pn["ip"], "vorig"
            ip_at = pn.get("ip_at") if pn.get("ip_from") == "vorig" else prev.get("at")
        cpu = (st or {}).get("cpuinfo") or {}
        nodes.append({"name": name, "ip": ip, "ip_from": frm, "ip_at": ip_at, "corosync_ip": cn.get("ip"),
                      "mac": snap["by_ip"].get(ip) or pn.get("mac"), "online": on,
                      "version": cn.get("version") or pn.get("version"),
                      "arch": node_arch(st, [g.get("arch") for g in guests if g["node"] == name and g["type"] == "lxc"])
                      or pn.get("arch"),
                      "cpu": cpu.get("model") or pn.get("cpu"), "cpus": cpu.get("cpus") or pn.get("cpus"),
                      "mem": ((st or {}).get("memory") or {}).get("total") or pn.get("mem")})
    jobs = []
    for j in cov.get("jobs") or []:
        jobs.append({k: j.get(k) for k in ("id", "schedule", "storage", "enabled", "all", "node", "pool", "pbs",
                                           "server", "datastore")} | job_targets(j, list(rows.values()), guests))
    return {"key": src["key"], "service": svc.name, "name": clu.get("cluster"), "quorate": clu.get("quorate"),
            "qdevice": (clu.get("qdevice") or {}).get("host"), "stale_from": None, "nodes": nodes, "guests": guests,
            "pbs_storages": [{k: v for k, v in s.items() if k != "nodes"} for s in stores], "jobs": jobs}


# --- PBS -----------------------------------------------------------------------------------------------------------

async def _pbs(src: dict, integ, snap: dict, ips: dict) -> dict:
    """Eén PBS-tegel: datastores met hun pad (niet de opmerking: vrije tekst), aangevuld met wat de back-updekking
    al weet (gebruik, groepen, syncs, remotes, TLS-vingerafdruk)."""
    svc = src["service"]
    stores = [s for s in await integ.get(PBS_CALLS["datastores"]) or [] if isinstance(s, dict) and s.get("name")]
    base = urlsplit(src.get("base") or "")
    cov = next((p for p in snap["coverage"].get("pbs") or [] if p.get("service_id") == svc.id), None) or next(
        (p for p in snap["coverage"].get("pbs") or [] if p.get("host") and p.get("host") == base.hostname
         and p.get("port") == base.port), {})
    used = {s.get("store"): s for s in cov.get("stores") or []}
    ip, how, direct = ips.get(src.get("base")) or (None, "onbekend", None)
    return {"key": src["key"], "name": svc.name, "url": direct or src.get("base"), "ip": ip, "how": how,
            "fingerprint": cov.get("fingerprint"), "runs_on": None, "stale_from": None,
            "stores": [{"store": s["name"], "path": s.get("path"), "used": (used.get(s["name"]) or {}).get("used"),
                        "total": (used.get(s["name"]) or {}).get("total"),
                        "groups": (used.get(s["name"]) or {}).get("groups")} for s in stores],
            "syncs": [{k: x.get(k) for k in ("id", "store", "remote", "remote_store", "schedule", "direction")}
                      for x in cov.get("syncs") or []],
            "remotes": [{"name": x.get("name"), "host": x.get("host")} for x in cov.get("remotes") or []]}


# --- samenvoegen, plaatsen, toegang --------------------------------------------------------------------------------

def _source_name(src: dict, entry: dict | None) -> str:
    if src["kind"] == "pve" and entry and entry.get("nodes"):
        return "Proxmox " + ", ".join(n["name"] for n in entry["nodes"])
    return doc.pbs_label(src["name"]) if src["kind"] == "pbs" else f"Proxmox-tegel {src['name']}"


def _merge(srcs: list[dict], fresh: dict[str, dict | None], failures: dict[str, str], prev: dict,
           now: datetime, dup: dict[str, set] | None = None) -> tuple[dict, list[dict]]:
    """De nieuwe delen, en voor elke bron die deze keer niet lukte het deel uit het vorige noodplan, met de datum van
    het laatste noodplan waarin die bron wel lukte (die blijft staan, hoeveel weken het ook mislukt). Een oud deel
    van een cluster die er via een andere tegel al vers staat, valt weg. dup: de nodes van een tweede tegel naar
    dezelfde cluster (die staat er zelf nooit in); die onthoudt de bronrij, voor als die tegel later niet lukt."""
    dup = dup or {}
    pd = prev.get("data") or {}
    old = {e.get("key"): e for e in (pd.get("clusters") or []) + (pd.get("pbs") or [])}
    old_src = {s.get("key"): s for s in prev.get("sources") or []}
    clusters = [c for c in fresh.values() if c and c["key"].startswith("pve:")]
    pbs = [p for p in fresh.values() if p and p["key"].startswith("pbs:")]
    live = {c["key"] for c in clusters}
    by_key = {s["key"]: s for s in srcs}
    out = []
    for s in srcs:
        key = s["key"]
        if key not in failures:
            out.append({"key": key, "name": _source_name(s, fresh.get(key)), "ok": True}
                       | ({"nodes": sorted(dup[key])} if key in dup else {}))
            continue
        pe, ps = old.get(key), old_src.get(key) or {}
        row = {"key": key, "name": _source_name(s, pe) if pe else ps.get("name") or _source_name(s, None),
               "ok": False, "error": failures[key]}
        mine = {n.get("name") for n in pe.get("nodes") or []} if pe else set(ps.get("nodes") or [])
        if key.startswith("pve:") and mine:
            if not pe:
                row["nodes"] = sorted(mine)
            # Dezelfde cluster staat er via een andere tegel: vers, of (stond deze tegel er zelf nooit in) ook uit
            # een vorig noodplan.
            twin = next((c for c in clusters if (not pe or c["key"] in live)
                         and mine & {n.get("name") for n in c.get("nodes") or []}), None)
            if twin:
                row["covered"] = _source_name(by_key[twin["key"]], twin)
                out.append(row)
                continue
        if pe:
            since = pe.get("stale_from") or prev.get("at")
            (clusters if key.startswith("pve:") else pbs).append({**pe, "stale_from": since})
            row["from"] = since
        else:
            row["from"] = None
            row["failing_since"] = ps.get("failing_since") or now.isoformat()
        out.append(row)
    order = {s["key"]: i for i, s in enumerate(srcs)}
    clusters.sort(key=lambda e: order.get(e["key"], 0))
    pbs.sort(key=lambda e: order.get(e["key"], 0))
    return {"clusters": clusters, "pbs": pbs}, out


def _access_urls(snap: dict, srcs: list[dict]) -> list[str]:
    """De adressen waarvan het noodplan het IP zoekt (voor de run én de proef): elke PBS, de beheertegels en de
    OIDC-provider."""
    urls = [s["base"] for s in srcs if s["kind"] == "pbs" and s.get("base")]
    urls += [t["url"] for t in snap["tiles"] if t["type"] in TILE_TYPES and t.get("url")]
    if snap["oidc"]["enabled"] and snap["oidc"]["issuer"]:
        urls.append(snap["oidc"]["issuer"])
    return list(dict.fromkeys(urls))


def _npm_ip(snap: dict) -> str | None:
    if snap["settings"]["npm_ip"]:
        return snap["settings"]["npm_ip"]
    host = next((urlsplit(t["url"] or "").hostname for t in snap["tiles"] if t["type"] == "npm"), None)
    return host if _is_ip(host) else None


async def _lookup(urls: list[str], routes: dict, npm_ip: str | None) -> dict[str, tuple]:
    found = await asyncio.gather(*(ip_from_url(u, routes, npm_ip) for u in urls))
    return dict(zip(urls, found))


def _place(snap: dict, data: dict, ips: dict) -> None:
    """Welke tegels op welke VM/CT draaien (zonder de netwerkkaart): het IP in het adres of het doel van de check, of
    het IP waar NPM die naam naartoe stuurt; een tegel onder een andere zonder eigen treffer gaat mee met zijn
    ouder. En de rollen: het dashboard zelf, OPNsense, NPM, een PBS."""
    from .routes import name_and_path

    gs = doc.guests(data)
    by_ip: dict[str, dict] = {}
    for g in gs:
        g["services"], g["roles"] = [], []
        if g.get("ip"):
            by_ip.setdefault(g["ip"], g)

    def guest_for(host: str | None) -> dict | None:
        if not host:
            return None
        if _is_ip(host):
            return by_ip.get(host.strip("[]"))
        e = _route(snap["routes"], host)
        return by_ip.get(e["host"]) if e and _is_ip(e.get("host")) else None

    tiles = [t for t in snap["tiles"] if t["type"] not in NOT_PLACED]
    placed = {}
    for t in tiles:
        for host in (urlsplit(t.get("url") or "").hostname, name_and_path(t["check"], t.get("url"))[0]):
            if g := guest_for(host):
                placed[t["id"]] = g
                break
    for t in tiles:
        if t["id"] not in placed and t.get("parent_id") in placed:
            placed[t["id"]] = placed[t["parent_id"]]
    for t in tiles:
        if g := placed.get(t["id"]):
            g["services"].append({"name": t["name"], "url": t.get("url")})

    def role(ip: str | None, name: str) -> dict | None:
        g = by_ip.get(ip) if ip else None
        if g and name not in g["roles"]:
            g["roles"].append(name)
        return g
    role(snap["settings"]["syslog_target"], "dashboard")
    for t in snap["tiles"]:
        if t["type"] in ("opnsense", "npm"):
            role((ips.get(t.get("url")) or (None,))[0], t["type"])
    role(snap["settings"]["npm_ip"], "npm")
    node_of = {n.get("ip"): n["name"] for c in data["clusters"] for n in c.get("nodes") or [] if n.get("ip")}
    for p in data["pbs"]:
        g = role(p.get("ip"), f"pbs:{p['name']}")
        p["runs_on"] = doc.where(g) if g else (f"node {node_of[p['ip']]}" if p.get("ip") in node_of else None)


def _what(label: str, name: str) -> str:
    return label if name.strip().lower() in (label.lower(), "") else f"{label} ({name})"


def _access(snap: dict, data: dict, ips: dict) -> list[dict]:
    """Toegang zonder DNS: elk systeem op zijn IP."""
    by_ip = {g["ip"]: g for g in doc.guests(data) if g.get("ip")}
    rows = []
    for c in data["clusters"]:
        for n in c.get("nodes") or []:
            ip = n.get("ip")
            rows.append({"kind": "pve", "name": n["name"], "what": f"Proxmox {n['name']}", "ip": ip,
                         "url": f"https://{ip}:8006" if ip else None,
                         "how": {"corosync": "corosync", "vorig": "vorig"}.get(n.get("ip_from"), "node") if ip else
                         "onbekend", "note": f"ssh root@{ip}" if ip else "IP onbekend"})
    for p in data["pbs"]:
        rows.append({"kind": "pbs", "name": p["name"], "what": doc.pbs_label(p["name"]), "ip": p.get("ip"),
                     "url": p.get("url"), "how": p.get("how") or "onbekend", "note": p.get("runs_on") or "",
                     "runs_on": p.get("runs_on")})
    for t in snap["tiles"]:
        if t["type"] not in TILE_TYPES or not t.get("url"):
            continue
        ip, how, direct = ips.get(t["url"]) or (None, "onbekend", None)
        on = doc.where(by_ip.get(ip)) if ip else None
        rows.append({"kind": t["type"], "name": t["name"], "what": _what(TILE_TYPES[t["type"]], t["name"]), "ip": ip,
                     "url": direct or t["url"], "how": how, "note": on or "", "runs_on": on})
    o = data.get("oidc") or {}
    if o.get("enabled") and snap["oidc"]["issuer"]:
        ip, how, direct = ips.get(snap["oidc"]["issuer"]) or (None, "onbekend", None)
        rows.append({"kind": "oidc", "name": "Authentik", "what": "Aanmelden (OIDC)", "ip": ip,
                     "url": direct or snap["oidc"]["issuer"], "how": how,
                     "note": "ligt het plat: meld je aan met wachtwoord en 2FA"})
    dash = data.get("dashboard") or {}
    me = dash.get("guest")
    if dash.get("ip"):
        if dash.get("lan_open"):
            rows.append({"kind": "dashboard", "name": "dashboard", "what": "Dit dashboard", "ip": dash["ip"],
                         "url": f"http://{dash['ip']}", "how": "lan", "note": doc.where(me) or ""})
        else:
            dom = next(iter(dash.get("domains") or []), None)
            rows.append({"kind": "dashboard", "name": "dashboard", "what": "Dit dashboard", "ip": dash["ip"],
                         "url": f"https://{dom}" if dom else None, "how": "via_npm",
                         "note": (f"in de container: pct enter {me['vmid']} op {me['node']}" if me else
                                  "in de container van het dashboard")})
    return rows


def _dashboard(snap: dict, data: dict) -> dict:
    s, sc = snap["settings"], snap["selfcheck"]
    me = doc.by_role(data, "dashboard")
    ip = s["syslog_target"] or (me or {}).get("ip")
    hosts = snap["routes"].get("hosts") or {}
    off = sc.get("offsite") or {}
    latest = off.get("latest")
    ver, rs = sc.get("verified") or {}, sc.get("restore") or {}
    return {"versie": snap["versie"].get("versie"), "kanaal": snap["versie"].get("kanaal"), "ip": ip,
            "guest": {k: me.get(k) for k in ("type", "vmid", "node", "name")} if me else None,
            "domains": sorted(n for n, e in hosts.items() if ip and not n.startswith("*") and (e or {}).get("host") == ip),
            "lan_open": snap["lan_open"], "secret_key_file": s["secret_key_file"], "backup_dir": s["backup_dir"],
            "offsite_on": snap["offsite_on"], "offsite_dir": s["offsite_dir"],
            "dumps": [{k: d.get(k) for k in ("name", "at", "size")} for d in (sc.get("backups") or [])[:1]],
            "verified": {"ok": ver.get("ok"), "why": ver.get("why")},
            "restore": {"status": rs.get("status"), "at": rs.get("at"), "last_ok": rs.get("last_ok")},
            "offsite": {"enabled": off.get("enabled"), "dir": off.get("dir"), "count": off.get("count"),
                        "latest": latest.get("name") if isinstance(latest, dict) else latest, "key": off.get("key"),
                        "key_stale": off.get("key_stale"), "at": off.get("at"), "error": off.get("error")},
            "offsite_key_at": snap["offsite_key_at"], "secret_saved_at": snap["secret_saved_at"],
            "versions": snap["versions"]}


def _rest(snap: dict, data: dict, ips: dict) -> dict:
    """Configkopieën, OIDC, tunnels, hersteltest, aantal namen in NPM."""
    cfg, last = snap["config_settings"], snap["config_last"]
    pve = [o for o in snap["configs"] if o["kind"] == "pve"]
    issuer = snap["oidc"]["issuer"]
    names = {t["id"]: t["name"] for t in snap["tiles"]}
    return {
        "configs": {"hour": cfg.get("hour", 2), "on": {k: bool(cfg.get(k)) for k in ("opnsense", "npm", "pve")},
                    "last": {"at": last.get("at"), "errors": [{"source": e.get("source"), "error": e.get("error")}
                                                             for e in last.get("errors") or []]},
                    "items": [o for o in snap["configs"] if o["kind"] != "pve"],
                    "pve": {"count": len(pve), "ts": max((o["ts"] for o in pve if o["ts"]), default=None)} if pve
                    else None},
        "oidc": {"enabled": snap["oidc"]["enabled"], "host": urlsplit(issuer).hostname if issuer else None,
                 "ip": (ips.get(issuer) or (None,))[0] if issuer else None},
        "tunnels": [{"service": names.get(t["service_id"], "Cloudflare"), "name": t["name"], "status": t["status"],
                     "connections": t["connections"]} for t in snap["tunnels"]],
        "restore_test": snap["restore_test"],
        "npm": {"domains": len(snap["routes"].get("hosts") or {})},
    }


def counts(data: dict | None) -> dict:
    d = data or {}
    gs = doc.guests(d)
    return {"nodes": sum(len(c.get("nodes") or []) for c in d.get("clusters") or []), "guests": len(gs),
            "pbs": len(d.get("pbs") or []), "domains": (d.get("npm") or {}).get("domains") or 0,
            "zonder_backup": sum(1 for g in gs if (g.get("coverage") or {}).get("level") == "err"),
            "niet_in_backup": sum(1 for g in gs for k in g.get("disks") or [] if not k.get("in_backup"))}


# --- het document, gemaskeerd --------------------------------------------------------------------------------------

async def known(db: AsyncSession) -> list[str]:
    from ..diagnose import known_secrets
    return variants(await known_secrets(db))


def render_with(value: dict, fmt: str, secrets: list[str]) -> tuple[str, int, list[str]]:
    """Het document als HTML of Markdown, door de maskering. Vond die iets, dan nog eens met een opmerking bovenaan
    (en weer gemaskeerd): (tekst, aantal vervangen, soorten)."""
    def one(masked: list[str] | None = None) -> str:
        bl = doc.blocks(value, masked)
        return doc.to_html(bl, f"Noodplan {doc.day(value.get('at'))}") if fmt == "html" else doc.to_md(bl)
    found: Counter = Counter()
    text = mask(one(), secrets, found)
    if not found:
        return text, 0, []
    kinds = sorted(found)
    n = sum(found.values())
    log.warning("noodplan: %s gemaskeerd (%s)", n, ", ".join(kinds))
    return mask(one(kinds), secrets), n, kinds


async def render(db: AsyncSession, value: dict, fmt: str) -> tuple[str, int, list[str]]:
    return render_with(value, fmt, await known(db))


# --- de run --------------------------------------------------------------------------------------------------------

def _offsite_notice(db: AsyncSession, snap: dict, offsite: dict, alerts: dict) -> None:
    """Eén melding (meldingencentrum, niet naar de gsm) als het noodplan niet buiten de container raakt terwijl de
    kopie van de dumps daar wel lukt; mislukt die ook, dan meldt de zelfcontrole het al."""
    err = offsite.get("error") if offsite.get("enabled") else None
    own = (snap["selfcheck"].get("offsite") or {})
    own_broken = bool(own.get("error")) and own.get("count") is None
    if not offsite.get("enabled"):
        alerts["offsite"] = None
    elif err:
        if not own_broken and alerts.get("offsite") != err:
            notify(db, "Noodplan niet buiten de container", err, level="warn", source="homepage", push=False)
            alerts["offsite"] = err
    elif alerts.get("offsite"):
        event(db, "gezondheid", "Noodplan staat weer buiten de container", f"noodplan.html en noodplan.md in "
              f"{offsite.get('dir')}", level="ok")
        alerts["offsite"] = None


async def run(maker, http, trigger: str = "week", user: str | None = None, now: datetime | None = None) -> dict:
    """Het noodplan maken en bewaren (en buiten de container zetten als die kopie aan staat). Eén tegelijk over API en
    worker heen; geen transactie open tijdens de API-vragen of het schrijven naar de share."""
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    started = time.monotonic()
    async with maker() as lk, job_lock(lk, "noodplan") as ok:
        if not ok:
            return {"skipped": "loopt al"}
        async with maker() as db:
            st = await ensure_state(db, STATE_KEY, {})
            prev = dict(st.value or {})
            if is_busy(prev, now):
                return {"skipped": "loopt al"}
            st.value = {**prev, "running": {"at": now.isoformat(), "by": user or "worker", "pid": os.getpid()},
                        "tried": now.isoformat()}
            snap, srcs = await _snapshot(db), await sources(db)
            # De bekende geheimen: voor de foutteksten van buiten (die gaan naar de browser) en het document.
            secrets = await known(db)
            _connect(srcs, http)
            await db.commit()
        try:
            ips = await _lookup(_access_urls(snap, srcs), snap["routes"], _npm_ip(snap))
            fresh: dict[str, dict | None] = {}
            failures: dict[str, str] = {}
            seen: list[set] = []
            dup: dict[str, set] = {}
            for s in srcs:
                if s["integ"] is None:
                    failures[s["key"]] = mask(s["error"], secrets)
                    continue
                try:
                    if s["kind"] == "pve":
                        c = await _pve(s, s["integ"], snap, prev)
                        mine = {n["name"] for n in c["nodes"]}
                        if any(mine & x for x in seen):
                            dup[s["key"]] = mine
                            continue  # een tweede tegel naar dezelfde cluster
                        seen.append(mine)
                    else:
                        c = await _pbs(s, s["integ"], snap, ips)
                    fresh[s["key"]] = c
                except IntegrationError as e:
                    failures[s["key"]] = mask(str(e)[:300], secrets)
            data, srcs_out = _merge(srcs, fresh, failures, prev, now, dup)
            _place(snap, data, ips)
            data["dashboard"] = _dashboard(snap, data)
            data |= _rest(snap, data, ips)
            data["access"] = _access(snap, data, ips)
            value = {"v": 1, "at": now.isoformat(), "trigger": trigger, "by": user,
                     "seconds": round(time.monotonic() - started), "sources": srcs_out, "data": data}
            # B: renderen, niets schrijven.
            html, masked, kinds = render_with(value, "html", secrets)
            md = render_with(value, "md", secrets)[0]
            s = get_settings()
            offsite = {"enabled": snap["offsite_on"], "dir": str(s.offsite_dir), "files": [], "error": None,
                       "at": (prev.get("offsite") or {}).get("at")}
            if snap["offsite_on"]:
                w = await asyncio.to_thread(write_offsite, Path(s.offsite_dir), html, md)
                # "at" = de laatste keer dat het lukte (zoals bij de zelfcontrole).
                offsite |= w | ({"at": now.isoformat()} if not w.get("error") else {})
            # C: bewaren en melden (alerts opnieuw gelezen: een andere run kan intussen gemeld hebben).
            async with maker() as db:
                st = await ensure_state(db, STATE_KEY, {})
                alerts = dict((st.value or {}).get("alerts") or {})
                _offsite_notice(db, snap, offsite, alerts)
                n = counts(data)
                bad = [x["name"] for x in srcs_out if not x["ok"] and not x.get("covered")]
                event(db, "gezondheid", "Noodplan bijgewerkt",
                      f"{n['nodes']} nodes, {n['guests']} VM's en CT's"
                      + (f", kopie in {offsite['dir']}" if offsite["enabled"] and not offsite["error"] else "")
                      + (f"; geen antwoord van {', '.join(bad)} (dat deel komt uit een vorig noodplan)" if bad else "")
                      + (f" (op vraag van {user})" if user else ""), level="warn" if bad else "info")
                st.value = {**value, "tried": now.isoformat(), "running": None, "offsite": offsite,
                            "masked": masked, "masked_kinds": kinds, "alerts": alerts}
                await db.commit()
            return {"ok": True, "at": value["at"]}
        except BaseException as e:
            # Marker weg, "tried" blijft: de volgende poging pas na RETRY. Waarom het mislukte blijft staan tot een
            # run wel lukt (gemaskeerd: het gaat naar de browser); niet bij afbreken (de worker of API stopt).
            why = mask(f"{type(e).__name__}: {str(e)[:200]}", secrets)
            failed = {"failed": {"at": now.isoformat(), "error": why}} if isinstance(e, Exception) else {}
            async with maker() as db:
                st = await ensure_state(db, STATE_KEY, {})
                st.value = {**(st.value or {}), "running": None, **failed}
                await db.commit()
            raise


def status(value: dict | None, running: bool, now: datetime, offsite_on: bool, offsite_dir: str) -> dict:
    """Wat GET /api/noodplan teruggeeft: nooit het document of de gegevens zelf, alleen datums, fouten en aantallen."""
    v = value or {}
    at = _at(v.get("at"))
    busy = v.get("running") if is_busy(v, now) else None
    return {"at": v.get("at"), "next": next_slot(now).isoformat() if at and at >= slot(now) else None,
            "running": running, "running_by": (busy or {}).get("by") if running else None,
            "trigger": v.get("trigger"), "by": v.get("by"), "seconds": v.get("seconds"),
            "sources": [{k: x.get(k) for k in ("key", "name", "ok", "error", "from", "covered") if k in x}
                        for x in v.get("sources") or []],
            "offsite": v.get("offsite") or {"enabled": offsite_on, "dir": offsite_dir},
            "counts": counts(v.get("data")) if at else None,
            "masked": v.get("masked") or 0, "masked_kinds": v.get("masked_kinds") or [], "failed": v.get("failed"),
            "problems": [{"key": k, "text": t} for k, t in problems(v, now)]}


def _call(table: dict, key: str, calls: list[str], prefix: str, **kw) -> str:
    """Een pad uit PVE_CALLS of PBS_CALLS zoals de run het vraagt, met {node}, {vmid} ... waar die per keer verschillen."""
    if f"{prefix}:{key}" not in calls:
        calls.append(f"{prefix}:{key}")
    return "GET /api2/json" + table[key].format(**kw)


async def proef_plan(db: AsyncSession, http, now: datetime | None = None) -> dict:
    """Wat "nu bijwerken" zou doen, zonder één verzoek naar buiten en zonder DNS: uit de tegels, de back-updekking en
    de cluster die de worker al heeft, met dezelfde paden en dezelfde lijst namen als de run."""
    now = now or datetime.now(timezone.utc)
    value = await _value(db, STATE_KEY)
    snap, srcs = await _snapshot(db), await sources(db)
    _connect(srcs, http)
    calls: list[str] = []
    steps, skipped = [], []
    pve = [x for x in srcs if x["kind"] == "pve"]
    for src in pve:
        machine = f"{src['name']} ({src['base'] or 'adres onbekend'})"
        if src["integ"] is None:
            skipped.append(proef.skip(machine, src["error"]))
            continue
        who = proef.api_who(src["integ"].token_id())
        svc = src["service"]
        cov = next((c for c in snap["coverage"].get("clusters") or [] if c.get("service_id") == svc.id), {})
        clu = next((c for c in snap["cluster"].get("items") or [] if c.get("service_id") == svc.id), {})
        names = sorted(cov.get("nodes") or [n.get("name") for n in clu.get("nodes") or [] if n.get("name")])
        n = len(cov.get("rows") or [])
        stores = sorted({j["storage"] for j in cov.get("jobs") or [] if j.get("pbs") and j.get("storage")})
        lines = [_call(PVE_CALLS, "resources", calls, "pve"), _call(PVE_CALLS, "storage", calls, "pve"),
                 f"{_call(PVE_CALLS, 'status', calls, 'pve', node='{node}')} en "
                 f"{_call(PVE_CALLS, 'network', calls, 'pve', node='{node}')}  ({', '.join(names) or 'elke node'})",
                 _call(PVE_CALLS, "config", calls, "pve", node="{node}", type="{qemu|lxc}", vmid="{vmid}")
                 + (f"  ({n} keer, één per VM/CT)" if n else "  (één per VM/CT)")]
        lines += [_call(PVE_CALLS, "content", calls, "pve", node=names[0] if names else "{node}", storage=sto)
                  for sto in stores] or [_call(PVE_CALLS, "content", calls, "pve", node="{node}", storage="{PBS-opslag}")
                                         + "  (per PBS-opslag)"]
        steps.append(proef.step(machine, "proxmox-api", "\n".join(lines), who=who,
                                note="alleen lezen, met het leestoken"))
        steps.append(proef.step(machine, "proxmox-api",
                                _call(PVE_CALLS, "lxc_ifs", calls, "pve", node="{node}", vmid="{vmid}") + "\n"
                                + _call(PVE_CALLS, "agent", calls, "pve", node="{node}", vmid="{vmid}")
                                + (f"  (hoogstens {n} keer samen)" if n else ""), who=who,
                                when="voor een draaiende VM/CT zonder vast IP die OPNsense niet zag",
                                on_fail="het IP blijft onbekend in het noodplan"))
    for src in (x for x in srcs if x["kind"] == "pbs"):
        machine = f"{doc.pbs_label(src['name'])} ({src['base'] or 'adres onbekend'})"
        if src["integ"] is None:
            skipped.append(proef.skip(machine, src["error"]))
            continue
        steps.append(proef.step(machine, "pbs-api", _call(PBS_CALLS, "datastores", calls, "pbs"),
                                who=proef.api_who(src["integ"].secrets.get("username")),
                                note="alleen lezen; de opmerking bij een datastore komt niet in het noodplan"))
    here = "dashboard (deze container)"
    names = dns_names(_access_urls(snap, srcs), snap["routes"])
    if names:
        steps.append(proef.step(here, "dashboard", f"DNS opzoeken ({DNS_WAIT} s per naam): {', '.join(names)}",
                                when="tegels met een naam die niet in NPM staat"))
    else:
        skipped.append(proef.skip("DNS opzoeken", "elke tegel heeft een IP of staat in NPM"))
    dst = Path(get_settings().offsite_dir)
    if snap["offsite_on"]:
        steps.append(proef.step(here, "dashboard", f"schrijft {' en '.join(FILES)} naar {dst} (leesbaar: 0644, zoals "
                                "de dumps)", when="de kopie buiten de container aan staat",
                                on_fail="een melding in het dashboard (niet naar de gsm); het noodplan in het dashboard "
                                        "is er wel"))
        err = await asyncio.to_thread(dir_problem, dst)
        dir_check = proef.check(f"Map {dst}", err is None, err or "bestaat en is beschrijfbaar")
    else:
        skipped.append(proef.skip(f"{' en '.join(FILES)} naar {dst}", "de kopie buiten de container staat uit"))
        dir_check = proef.check(f"Map {dst}", None, "kopie buiten de container staat uit")
    cov_at = snap["coverage"].get("at")
    busy = value.get("running") if is_busy(value, now) else None
    checks = [dir_check,
              proef.check("Back-updekking", True if cov_at else None,
                          f"van {doc.when(cov_at)}" if cov_at else "nog niet opgehaald: zonder dekking staat bij elke "
                                                                   "VM/CT \"onbekend\" als back-up"),
              proef.check("Er loopt geen ander noodplan", not busy,
                          f"bezig sinds {doc.when(busy.get('at'))} ({busy.get('by')})" if busy else None)]
    after = [f"Het noodplan in het dashboard wordt vervangen (nu: van {doc.when(value['at'])})." if value.get("at")
             else "Het eerste noodplan komt in het dashboard.", "Een regel op de tijdlijn."]
    warnings = [] if pve else ["Geen Proxmox-tegel: het noodplan bevat dan alleen het dashboard zelf."]
    return proef.plan("Noodplan bijwerken", steps, checks=checks, skipped=skipped, after=after, warnings=warnings,
                      now=now, calls=calls)
