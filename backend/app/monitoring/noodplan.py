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
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import noodplan_doc as doc
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
    for k in sorted(keep, key=lambda k: (re.sub(r"\d+$", "", k), _int(re.sub(r"^\D+", "", k)) or 0)):
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


async def ip_from_url(url: str | None, routes: dict | None, npm_ip: str | None) -> tuple[str | None, str, str | None]:
    """(IP, hoe, adres op IP) voor een adres: staat er al een IP in → "ip"; kent NPM de naam met een IP als doel → dat
    doel, "npm"; anders DNS (3 s), tenzij dat het IP van NPM zelf geeft → "dns"; anders (None, "onbekend", None)."""
    host = urlsplit(url or "").hostname
    if not host:
        return None, "onbekend", None
    if _is_ip(host):
        return host, "ip", _swap(url, None, host, None)
    e = _route(routes, host)
    if e and _is_ip(e.get("host")):
        return e["host"], "npm", _swap(url, e.get("scheme"), e["host"], e.get("port"))
    ip = await _resolve(host)
    if ip and ip != npm_ip and not (e and ip == e.get("via")):
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

def write_offsite(dst: Path, html: str, md: str) -> dict:
    """noodplan.html en noodplan.md naar de map van de kopie buiten de container, leesbaar (0644) zoals de dumps, wat
    het umask van het proces ook is. Eerst als .part, dan in één keer op zijn plaats."""
    if not dst.is_dir():
        return {"files": [], "error": f"map {dst} bestaat niet (koppel er een NAS-share, PBS-opslag of USB-schijf aan)"}
    if not os.access(dst, os.W_OK):
        return {"files": [], "error": f"geen schrijfrechten op {dst} voor gebruiker homepage"}
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
