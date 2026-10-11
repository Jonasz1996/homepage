"""Nieuwe service in één keer: proxy host en certificaat in NPM, het record (of de tunnelregel) in Cloudflare, een
rewrite in AdGuard, de tegel met zijn check en de CT/VM in een back-upjob. En omgekeerd: een service opruimen.

Alles begint met een proef: elke call met machine, als wie en de inhoud, zonder iets te doen. De echte run draagt de
hash van die proef; de server bouwt het plan opnieuw op en weigert als het intussen veranderde. De stappen lopen één na
één in de API (een certificaat van Let's Encrypt duurt tot anderhalve minuut), stoppen bij de eerste fout en onthouden
wat er al gemaakt is, zodat "ongedaan maken" precies dat weer weghaalt. De back-up is de enige stap die niet stopt: lukt
die niet, dan werkt de service gewoon en zegt de run dat de back-up niet ingesteld is.

De proefstap en de echte call komen telkens uit dezelfde bouwsteen (Op), zoals in monitoring/healing.py.

Opruimen raakt alleen <label>.<zone>: records van NPM (of met het commentaar van dit dashboard), tunnelregels naar NPM,
een rewrite voor die naam, de proxy host met alleen die naam, zijn eigen certificaat en de tegel. DNS eerst, zodat er
nooit een naam naar een host wijst die al weg is; de tegel als laatste.

De runs staan in één AppState-rij (geen migratie); welke run echt nog loopt, weet alleen dit proces (_running).
"""

import asyncio
import copy
import hashlib
import ipaddress
import json
import logging
import re
import secrets
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from . import proef, ssh_discovery
from .config import get_settings
from .db import ensure_state
from .deps import notify
from .health import domains
from .integrations import Integration, IntegrationError, build, from_api
from .integrations import cloudflare as cfm
from .integrations import npm as npmm
from .layout import record_revision
from .masking import mask
from .models import ApiConnection, AppState, Group, Page, Service, SshHost, User
from .monitoring import coverage, routes
from .monitoring.engine import active

log = logging.getLogger("homepage.nieuweservice")

STATE_KEY = "nieuwe_service"        # {"runs": [run, ...]}, nieuwste eerst
KEEP_RUNS = 30
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")   # één DNS-label, zoals een wildcardcertificaat dekt
COMMENT = "homepage: nieuwe service"
ORDER_CREATE = ("npm_host", "cf_ingress", "cf_record", "npm_cert", "npm_attach", "lan_dns", "tile", "backup")
ORDER_CLEANUP = ("cf_record", "cf_ingress", "lan_dns", "npm_host", "npm_cert", "backup", "tile")
LE_TIMEOUT, STEP_TIMEOUT = 120, 30
GUEST_TTL = 900                      # s; de run kijkt een onthouden CT/VM na met één call
ADMIN_PORTS = {81: "NPM-beheer", 8006: "Proxmox VE", 8007: "PBS", 9443: "Portainer", 9090: "Cockpit", 10000: "Webmin"}
ADDR = ("A", "AAAA", "CNAME")
TUNNEL_CNAME = re.compile(r"^([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.cfargotunnel\.com$")
SRC_RE = re.compile(r"^pve:(\d+):(lxc|qemu)/(\d+)$")
LOGIN_RE = re.compile(r"auth_request|outpost|authentik", re.I)
KIND_LABEL = {"npm": "NPM", "cloudflare": "Cloudflare DNS", "adguard": "AdGuard"}
GUEST_KIND = {"lxc": "CT", "qemu": "VM"}

# Runs die in dit proces lopen. Een run die "bezig" bewaard staat maar hier niet in zit, liep toen de API herstartte.
_running: set[str] = set()
_lock = asyncio.Lock()
# ip -> (CT/VM of None, wanneer opgezocht)
_guest_cache: dict[str, tuple[dict | None, float]] = {}


def _now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _norm(name) -> str:
    return routes._norm(name or "")


def _host_of(url: str | None) -> str | None:
    try:
        h = urlsplit(url or "").hostname
    except ValueError:
        return None
    return _norm(h) if h else None


def _forward(h: dict) -> str:
    return f"{h.get('forward_scheme')}://{h.get('forward_host')}:{h.get('forward_port')}"


def _ids(value) -> list[int]:
    return sorted(set(coverage._ids(value)))


# --- systemen en domein ---------------------------------------------------------------------------------------------

@dataclass
class System:
    label: str            # naam van de API in API-beheer, of van de tegel
    ref: str              # "api:3" of "tile:12"
    integ: Integration


@dataclass
class Systems:
    npm: System | None = None
    cf: System | None = None
    adguard: System | None = None
    pve: list[System] = field(default_factory=list)
    # Elke Proxmox-tegel → de cluster die het dashboard gebruikt (twee tegels naar dezelfde cluster: één keer).
    pve_by_tile: dict[int, System] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def pve_ref(self, ref: str) -> System | None:
        return next((p for p in self.pve if p.ref == ref), None)


@dataclass
class Snap:
    """Wat een plan uit de database nodig heeft, in één keer gelezen (daarna geen open transactie meer)."""
    sysm: Systems
    tiles: list[dict]
    groups: dict[int, str]
    ssh: list[tuple[str, str]]
    zabbix: list[dict]
    apis: dict[tuple[str, int], str]


async def _first(db: AsyncSession, clients, kind: str, notes: list[str]) -> System | None:
    """Eerst API's uit API-beheer, dan tegels zonder API (zoals health/security.proxmox_tokens)."""
    found: list[System] = []
    for a in (await db.execute(select(ApiConnection).where(ApiConnection.kind == kind).order_by(ApiConnection.id))).scalars():
        try:
            found.append(System(a.name, f"api:{a.id}", from_api(a, {}, clients)))
        except IntegrationError as e:
            notes.append(f"API {a.name}: {e}")
    for s in (await db.execute(select(Service).where(Service.type == kind, Service.api_id.is_(None))
                                .order_by(Service.id))).scalars():
        try:
            found.append(System(s.name, f"tile:{s.id}", build(s, clients)))
        except IntegrationError as e:
            notes.append(f"tegel {s.name}: {e}")
    if len(found) > 1:
        notes.append(f"meerdere {KIND_LABEL[kind]}-API's: het dashboard gebruikt {found[0].label}")
    return found[0] if found else None


async def gather(db: AsyncSession, clients) -> Snap:
    """Alles uit de database, daarna de verbinding terug (geen open transactie tijdens de calls naar buiten, zoals
    routers/integrations.py). Proxmox: de Proxmox-tegels, zoals hw → back-ups en het zoeken van SSH-hosts."""
    notes: list[str] = []
    sysm = Systems(npm=await _first(db, clients, "npm", notes), cf=await _first(db, clients, "cloudflare", notes),
                   adguard=await _first(db, clients, "adguard", notes), notes=notes)
    services = (await db.execute(select(Service).order_by(Service.id))).scalars().all()
    pve_tiles = []
    for s in services:
        if s.type == "proxmox":
            try:
                pve_tiles.append((s, build(s, clients)))
            except IntegrationError as e:
                notes.append(f"Proxmox-tegel {s.name}: {e}")
    if not pve_tiles and (await db.execute(select(ApiConnection.id).where(ApiConnection.kind == "proxmox").limit(1))).first():
        notes.append("Proxmox-API zonder tegel: back-ups en het zoeken van de CT/VM gebruiken alleen Proxmox-tegels "
                     "(zoals hw → back-ups)")
    tiles = [{"id": s.id, "name": s.name, "url": s.url, "host": _host_of(s.url), "active": active(s.check)}
             for s in services]
    groups = {g.id: f"{p.name} / {g.name}" for g, p in (await db.execute(select(Group, Page).join(Page))).all()}
    ssh = [(h.host, h.source) for h in (await db.execute(select(SshHost).where(SshHost.source.like("pve:%")))).scalars()]
    zst = await db.get(AppState, "zabbix")
    zabbix = [h for h in ((zst.value or {}).get("hosts") or []) if isinstance(h, dict)] if zst else []
    apis = {}
    for a in (await db.execute(select(ApiConnection))).scalars():
        p = urlsplit(a.url or "")
        try:
            port = p.port or (443 if p.scheme == "https" else 80)
        except ValueError:
            continue
        if p.hostname:
            apis[(p.hostname.lower(), port)] = a.name
    await db.close()
    seen: dict[frozenset, System] = {}
    for s, integ in pve_tiles:
        try:
            nodes = frozenset(r.get("node") for r in await integ.get("/cluster/resources?type=node") if r.get("node"))
        except IntegrationError as e:
            notes.append(f"Proxmox-tegel {s.name}: {mask(str(e))[:200]}")
            continue
        if nodes not in seen:
            seen[nodes] = System(s.name, f"tile:{s.id}", integ)
            sysm.pve.append(seen[nodes])
        sysm.pve_by_tile[s.id] = seen[nodes]
    return Snap(sysm, tiles, groups, ssh, zabbix, apis)


def _wildcard_zones(certs: list[dict] | None) -> list[str]:
    out = set()
    for c in certs or []:
        for n in c.get("domain_names") or []:
            n = _norm(n)
            if n.startswith("*.") and (z := domains.clean(n[2:])):
                out.add(z)
    return sorted(out)


def zone_of(sysm: Systems, certs: list[dict] | None) -> tuple[str | None, str]:
    """(zone, waar ze vandaan komt). De browser kiest het domein nooit."""
    if sysm.cf:
        z = domains.clean(sysm.cf.integ.config.get("zone") or "")
        return (z, "uit Cloudflare DNS") if z else (None, "zone ontbreekt of klopt niet in de Cloudflare DNS-API")
    zones = _wildcard_zones(certs)
    if len(zones) == 1:
        return zones[0], "uit het wildcardcertificaat in NPM"
    if zones:
        return None, f"meerdere wildcardcertificaten in NPM ({', '.join(zones)}): maak een Cloudflare DNS-API met de zone"
    return None, "geen Cloudflare DNS-API en geen wildcardcertificaat in NPM"


async def zone_light(db: AsyncSession) -> str | None:
    """Het domein zonder een call naar buiten: de zone van de Cloudflare DNS-API, anders het enige *.domein in de
    certificaten uit de laatste ronde van de routes."""
    a = (await db.execute(select(ApiConnection).where(ApiConnection.kind == "cloudflare").order_by(ApiConnection.id)
                          .limit(1))).scalar_one_or_none()
    if a is not None:
        return domains.clean(str((a.config or {}).get("zone") or ""))
    s = (await db.execute(select(Service).where(Service.type == "cloudflare", Service.api_id.is_(None))
                          .order_by(Service.id).limit(1))).scalar_one_or_none()
    if s is not None:
        return domains.clean(str((s.config or {}).get("zone") or ""))
    st = await db.get(AppState, routes.KEY)
    names = [{"domain_names": e.get("cert_names") or []} for e in ((st.value or {}).get("hosts") or {}).values()] if st else []
    zones = _wildcard_zones(names)
    return zones[0] if len(zones) == 1 else None


def in_zone(fqdn: str | None, zone: str | None) -> bool:
    """Precies <label>.<zone>: nooit de zone zelf, een wildcard, een diepere naam of een IP."""
    if not fqdn or not zone:
        return False
    label, _, rest = _norm(fqdn).partition(".")
    return rest == zone and bool(LABEL_RE.match(label))


# --- de CT/VM achter een IP -------------------------------------------------------------------------------------------

def _guest_public(g: dict | None) -> dict | None:
    return {k: g.get(k) for k in ("type", "vmid", "name", "node", "pool", "status", "how")} if g else None


async def _guest_row(sysx: System, tile: int, vmid: int, how: str) -> dict | None:
    fresh = await sysx.integ.guest(vmid)
    if fresh is None:
        return None
    return {"tile": tile, "pve": sysx.ref, "type": fresh["type"], "vmid": fresh["vmid"], "name": fresh.get("name"),
            "node": fresh.get("node"), "pool": fresh.get("pool"), "status": fresh.get("status"), "how": how}


async def find_guest(db: AsyncSession, clients, snap: Snap, ip: str, *, at_run: bool = False) -> tuple[dict | None, str | None]:
    """(CT/VM met dit IP, of None; fout). Eerst de SSH-hosts uit Proxmox, anders alle machines opzoeken (zoals ⟳ pve in
    de terminal). Onthouden voor GUEST_TTL; de run kijkt een onthouden CT/VM na met één call."""
    sysm = snap.sysm
    if not sysm.pve:
        return None, None
    hit = _guest_cache.get(ip)
    now = time.monotonic()
    if hit and now - hit[1] < GUEST_TTL:
        g = hit[0]
        if g is None or not at_run:
            return (dict(g) if g else None), None
        sysx = sysm.pve_ref(g["pve"])
        if sysx is not None:
            try:
                fresh = await sysx.integ.guest(g["vmid"])
                if fresh:
                    got, _ = await ssh_discovery._guest_ip(sysx.integ, fresh["node"], fresh["type"], fresh["vmid"],
                                                           fresh.get("status") == "running")
                    if got == ip:
                        g = {**g, **{k: fresh.get(k) for k in ("node", "type", "pool", "status", "name")}}
                        _guest_cache[ip] = (g, now)
                        return dict(g), None
            except IntegrationError:
                pass
    found = None
    for host, source in snap.ssh:
        m = SRC_RE.match(source or "")
        if host == ip and m and int(m.group(1)) in sysm.pve_by_tile:
            found = (sysm.pve_by_tile[int(m.group(1))], int(m.group(3)), "SSH-host")
            break
    try:
        if found is None:
            items = (await ssh_discovery.discover(db, clients))["items"]
            await db.close()
            for i in items:
                m = SRC_RE.match(i.get("source") or "")
                if i.get("host") == ip and m and int(m.group(1)) in sysm.pve_by_tile:
                    found = (sysm.pve_by_tile[int(m.group(1))], int(m.group(3)), "Proxmox")
                    break
        g = None
        if found:
            sysx, vmid, how = found
            g = await _guest_row(sysx, int(sysx.ref.split(":")[1]), vmid, how)
    except IntegrationError as e:
        return None, mask(str(e))[:200]
    _guest_cache[ip] = (g, now)
    return (dict(g) if g else None), None


# --- bouwstenen: de proefstap en de echte call uit dezelfde waarden -------------------------------------------------

@dataclass
class Op:
    key: str                     # npm_host | cf_ingress | cf_record | npm_cert | npm_attach | lan_dns | tile | backup
    title: str                   # per stap getoond
    proef: dict                  # proef.step(...)
    go: Callable[[dict], Awaitable[dict]]            # ctx -> {"detail", "created"?, "removed"?, "skipped"?}
    # Na een fout of time-out: is het toch gebeurd? Dan staat het bij wat er al gemaakt is.
    verify: Callable[[dict], Awaitable[dict | None]] | None = None
    timeout: int = STEP_TIMEOUT
    fatal: bool = True           # False: de run gaat door en eindigt "klaar" met een waarschuwing
    # Wat deze stap maakt, zonder het nummer dat de server pas geeft: om het later terug te vinden.
    spec: dict | None = None


def _add(created: list[dict], rec: dict | None) -> None:
    if rec and not any(c.get("kind") == rec.get("kind") and c.get("id", c.get("label")) == rec.get("id", rec.get("label"))
                       for c in created):
        created.append(rec)


def _created(ctx: dict, kind: str) -> dict:
    rec = next((c for c in ctx["created"] if c.get("kind") == kind), None)
    if rec is None:
        raise IntegrationError(f"{kind} uit een vorige stap ontbreekt")
    return rec


def _npm_machine(s: System) -> str:
    return f"NPM ({urlsplit(s.integ.base).netloc})"


def _npm_who(s: System) -> str:
    return f"NPM-gebruiker {s.integ.user(True) or '?'}"


def _cf_machine(s: System) -> str:
    return f"Cloudflare, zone {s.integ.zone or '?'}"


def _cf_who(s: System) -> str:
    return f"API-token van '{s.label}'"


def _ag_machine(s: System) -> str:
    return f"AdGuard ({urlsplit(s.integ.base).netloc})"


def _ag_who(s: System) -> str:
    return f"gebruiker {s.integ.secrets.get('username') or '?'}"


def _pve_machine(s: System) -> str:
    return f"Proxmox VE ({s.label})"


def _pve_who(s: System) -> str:
    return proef.api_who(s.integ.token_id(write=True))


def _guest_label(kind: str | None, vmid) -> str:
    return f"{GUEST_KIND.get(kind or '', 'CT/VM')} {vmid}"


async def find_created(sysm: Systems, spec: dict, maker=None) -> dict | None:
    """Het object dat een stap volgens spec maakte, zoals het nu bestaat (met zijn nummer), of None."""
    kind = spec.get("kind")
    if kind == "npm_host" and sysm.npm:
        for h in await sysm.npm.integ.proxy_hosts(write=True):
            if routes._names(h) == [spec["name"]] and _forward(h) == spec["forward"]:
                return {**spec, "id": int(h["id"]), "label": f"NPM-host #{int(h['id'])}"}
    elif kind == "cf_record" and sysm.cf:
        for r in await sysm.cf.integ.records(spec["name"]):
            if r["type"] == spec["type"] and _norm(r["content"]) == spec["content"] and r.get("comment") == COMMENT:
                return {**spec, "id": r["id"], "label": f"{spec['type']}-record in Cloudflare"}
    elif kind == "cf_ingress" and sysm.cf:
        tc = await sysm.cf.integ.tunnel_config(spec["account"], spec["tunnel"])
        if any(_norm(r.get("hostname")) == spec["hostname"] and r.get("service") == spec["service"]
               for r in tc["config"].get("ingress") or []):
            return {**spec, "label": "tunnelregel"}
    elif kind == "npm_cert" and sysm.npm:
        for c in await sysm.npm.integ.certificates(write=True):
            if c.get("provider") == "letsencrypt" and routes._names(c) == [spec["name"]]:
                return {**spec, "id": int(c["id"]), "label": f"certificaat #{int(c['id'])}"}
    elif kind == "lan_dns" and sysm.adguard:
        if any(r["domain"] == spec["domain"] and r["answer"] == spec["answer"] for r in await sysm.adguard.integ.rewrites()):
            return {**spec, "label": "rewrite in AdGuard"}
    elif kind == "backup" and (px := sysm.pve_ref(spec["pve"])):
        what = _guest_label(spec.get("type"), spec["vmid"])
        if spec["how"] == "pool":
            g = await px.integ.guest(spec["vmid"])
            if g and g.get("pool") == spec["pool"]:
                return {**spec, "label": f"{what} in pool {spec['pool']}"}
        else:
            j = next((j for j in await px.integ.backup_jobs() if j.get("id") == spec["job"]), None)
            if j and int(spec["vmid"]) in _ids(j.get("vmid")):
                return {**spec, "label": f"{what} in back-upjob {spec['job']}"}
    elif kind == "tile" and maker is not None:
        async with maker() as db:
            s = (await db.execute(select(Service).where(Service.url == spec["url"], Service.name == spec["name"])
                                  .order_by(Service.id.desc()).limit(1))).scalar_one_or_none()
            if s is not None:
                return {**spec, "id": s.id, "label": f"tegel {s.name}"}
    return None


def _verify(sysm: Systems, spec: dict):
    async def verify(ctx: dict) -> dict | None:
        return await find_created(sysm, spec, ctx.get("maker"))
    return verify


def op_npm_host_add(npm: System, sysm: Systems, body: dict, fqdn: str) -> Op:
    method, path, data = npmm.host_create_request(body)
    spec = {"kind": "npm_host", "name": fqdn, "forward": _forward(body)}
    step = proef.step(_npm_machine(npm), "npm-api", f"{method} {npm.integ.base}/api{path}", who=_npm_who(npm), data=data,
                      on_fail="stopt hier: er is nog niets anders gemaakt",
                      note="daarna leest het dashboard de host opnieuw: weigerde nginx de configuratie, dan stopt het "
                           "hier en haalt ongedaan maken de host weg")

    async def go(ctx: dict) -> dict:
        res = await npm.integ.send(method, path, data)
        hid = int((res or {})["id"])
        # Eerst noteren, dan pas nakijken: ook een host die nginx weigert, moet ongedaan maken kunnen weghalen.
        _add(ctx["created"], {**spec, "id": hid, "label": f"NPM-host #{hid}"})
        # NPM geeft de host terug van vóór nginx hem laadde (en antwoordt ook 2xx als nginx weigert): opnieuw lezen.
        host = await npm.integ.get(npmm.host_get_request(hid)[1], write=True)
        if err := npmm.nginx_failed(host if isinstance(host, dict) else {}):
            raise IntegrationError(err)
        return {"detail": f"host #{hid}"}
    return Op("npm_host", "proxy host in NPM", step, go, _verify(sysm, spec), spec=spec)


def op_cf_ingress_add(cf: System, sysm: Systems, account: str, tunnel: str, rule: dict, version, before: str) -> Op:
    method, path, _ = cfm.tunnel_put_request(account, tunnel, {})
    fqdn = rule["hostname"]
    spec = {"kind": "cf_ingress", "account": account, "tunnel": tunnel, "hostname": fqdn, "service": rule["service"]}
    step = proef.step(_cf_machine(cf), "cloudflare-api", f"{method} {cf.integ.base}{path}", who=_cf_who(cf),
                      data={"regel": rule, "voor": before, "versie": version},
                      note="de hele configuratie van de tunnel gaat terug met alleen deze regel erbij; veranderde de "
                           "tunnel na de proef, dan stopt het hier", on_fail="stopt; ongedaan maken haalt de proxy host weg")

    async def go(ctx: dict) -> dict:
        tc = await cf.integ.tunnel_config(account, tunnel)
        if tc["version"] != version:
            raise IntegrationError("de tunnel veranderde intussen in Cloudflare: doe de proef opnieuw")
        config = copy.deepcopy(tc["config"])
        ingress = list(config.get("ingress") or [])
        ingress.insert(_catch_all(ingress), rule)
        config["ingress"] = ingress
        await cf.integ.send(*cfm.tunnel_put_request(account, tunnel, config))
        return {"detail": f"{fqdn} → {rule['service']}", "created": {**spec, "label": "tunnelregel"}}
    return Op("cf_ingress", "tunnelregel in Cloudflare", step, go, _verify(sysm, spec), spec=spec)


def op_cf_record_add(cf: System, sysm: Systems, zone_id: str, rec: dict) -> Op:
    method, path, data = cfm.record_create_request(zone_id, rec)
    spec = {"kind": "cf_record", "zone": zone_id, "name": rec["name"], "type": rec["type"], "content": rec["content"]}
    step = proef.step(_cf_machine(cf), "cloudflare-api", f"{method} {cf.integ.base}{path}", who=_cf_who(cf), data=data,
                      note="pas met dit record is de naam bereikbaar: het komt na de proxy host",
                      on_fail="stopt; ongedaan maken haalt wat er al is weer weg")

    async def go(ctx: dict) -> dict:
        res = await cf.integ.send(method, path, data) or {}
        rid = str(res["id"])
        return {"detail": f"{rec['type']} → {rec['content']}",
                "created": {**spec, "id": rid, "label": f"{rec['type']}-record in Cloudflare"}}
    return Op("cf_record", "DNS-record in Cloudflare", step, go, _verify(sysm, spec), spec=spec)


def op_npm_cert_add(npm: System, sysm: Systems, fqdn: str, version, email: str | None) -> Op:
    method, path, data = npmm.cert_create_request(fqdn, version, email)
    spec = {"kind": "npm_cert", "name": fqdn}
    step = proef.step(_npm_machine(npm), "npm-api", f"{method} {npm.integ.base}/api{path}", who=_npm_who(npm), data=data,
                      wait=f"tot {LE_TIMEOUT} s: Let's Encrypt kijkt via poort 80 of de naam echt naar NPM wijst",
                      on_fail="stopt; de host werkt dan zonder https tot je zelf een certificaat kiest, of je maakt "
                              "alles ongedaan")

    async def go(ctx: dict) -> dict:
        res = await npm.integ.send(method, path, data, timeout=LE_TIMEOUT) or {}
        cid = int(res["id"])
        return {"detail": f"certificaat #{cid}", "created": {**spec, "id": cid, "label": f"certificaat #{cid}"}}
    return Op("npm_cert", "certificaat van Let's Encrypt", step, go, _verify(sysm, spec), timeout=LE_TIMEOUT + 15,
              spec=spec)


def op_npm_attach(npm: System) -> Op:
    data = {"certificate_id": "<certificaat uit de vorige stap>", "ssl_forced": True, "http2_support": True}
    step = proef.step(_npm_machine(npm), "npm-api", f"PUT {npm.integ.base}/api/nginx/proxy-hosts/<host uit stap 1>",
                      who=_npm_who(npm), data=data, note="daarna opnieuw lezen: weigerde nginx, dan stopt het hier")

    async def go(ctx: dict) -> dict:
        hid, cid = _created(ctx, "npm_host")["id"], _created(ctx, "npm_cert")["id"]
        method, path, body = npmm.host_update_request(hid, {"certificate_id": cid, "ssl_forced": True, "http2_support": True})
        await npm.integ.send(method, path, body)
        host = await npm.integ.get(npmm.host_get_request(hid)[1], write=True)
        if err := npmm.nginx_failed(host if isinstance(host, dict) else {}):
            raise IntegrationError(err)
        return {"detail": f"certificaat #{cid} aan host #{hid}, https verplicht"}
    return Op("npm_attach", "certificaat aan de host", step, go)


def op_lan_dns_add(ag: System, sysm: Systems, fqdn: str, answer: str) -> Op:
    method, path, data = ag.integ.rewrite_request(True, fqdn, answer)
    spec = {"kind": "lan_dns", "domain": fqdn, "answer": answer}
    step = proef.step(_ag_machine(ag), "adguard-api", f"{method} {ag.integ.base}{path}", who=_ag_who(ag), data=data)

    async def go(ctx: dict) -> dict:
        await ag.integ.send(method, path, data)
        return {"detail": f"{fqdn} → {answer}", "created": {**spec, "label": "rewrite in AdGuard"}}
    return Op("lan_dns", "naam in AdGuard (thuis)", step, go, _verify(sysm, spec), spec=spec)


def op_tile_add(sysm: Systems, tile: dict, group_label: str, who: str) -> Op:
    spec = {"kind": "tile", "name": tile["name"], "url": tile["url"]}
    step = proef.step("dashboard", "dashboard", f"tegel '{tile['name']}' in {group_label}", who=who,
                      data={"url": tile["url"], "check": tile["check"] or None, "zabbix": tile["config"].get("zabbix")})

    async def go(ctx: dict) -> dict:
        async with ctx["maker"]() as db:
            if await db.get(Group, tile["group_id"]) is None:
                raise IntegrationError("die groep bestaat niet meer")
            pos = (await db.execute(select(func.coalesce(func.max(Service.position), -1))
                                    .where(Service.group_id == tile["group_id"]))).scalar_one() + 1
            s = Service(group_id=tile["group_id"], name=tile["name"], url=tile["url"], icon=tile["icon"], position=pos,
                        type="link", config=tile["config"], check=tile["check"])
            db.add(s)
            user = await db.get(User, ctx["user_id"]) if ctx.get("user_id") else None
            await record_revision(db, user, f"Service '{tile['name']}' toegevoegd (nieuwe service)")
            await db.commit()
            sid = s.id
            # De routes meteen vernieuwen, zodat de check de nieuwe host al kent (anders tot 5 minuten via de naam).
            try:
                await routes.refresh(db, ctx["clients"])
                await db.commit()
            except Exception:  # noqa: BLE001 - de tegel bestaat; de worker vernieuwt de routes zelf binnen 5 minuten
                log.warning("routes vernieuwen na een nieuwe tegel mislukt", exc_info=True)
            routes.forget()
        return {"detail": f"tegel #{sid}", "created": {**spec, "id": sid, "label": f"tegel {tile['name']}"}}
    return Op("tile", "tegel met check", step, go, _verify(sysm, spec), spec=spec)


def op_backup_pool_add(px: System, sysm: Systems, pool: str, guest: dict) -> Op:
    vmid = guest["vmid"]
    method, path, data = px.integ.pool_update_request(pool, vmid)
    spec = {"kind": "backup", "how": "pool", "pve": px.ref, "pool": pool, "vmid": vmid, "type": guest["type"]}
    what = _guest_label(guest["type"], vmid)
    step = proef.step(_pve_machine(px), "proxmox-api", f"{method} {px.integ.base}{path}", who=_pve_who(px), data=data,
                      on_fail="de service werkt gewoon; de run eindigt met 'back-up niet ingesteld'")

    async def go(ctx: dict) -> dict:
        g = await px.integ.guest(vmid)
        if g is None:
            raise IntegrationError(f"{what} niet meer gevonden in Proxmox")
        if g.get("pool") == pool:
            return {"detail": f"{what} zat al in pool {pool}"}
        if g.get("pool"):
            raise IntegrationError(f"{what} zit nu in pool {g['pool']}: niet verplaatst")
        await px.integ.send(method, path, data)
        return {"detail": f"{what} in pool {pool}", "created": {**spec, "label": f"{what} in pool {pool}"}}
    return Op("backup", "in de back-up (pool)", step, go, _verify(sysm, spec), fatal=False, spec=spec)


def op_backup_job_add(px: System, sysm: Systems, job: str, guest: dict, before: list[int]) -> Op:
    vmid = guest["vmid"]
    method, path, data = px.integ.job_update_request(job, [*before, vmid])
    spec = {"kind": "backup", "how": "job", "pve": px.ref, "job": job, "vmid": vmid, "type": guest["type"]}
    what = _guest_label(guest["type"], vmid)
    step = proef.step(_pve_machine(px), "proxmox-api", f"{method} {px.integ.base}{path}", who=_pve_who(px), data=data,
                      note="eerst opnieuw gelezen: veranderde de lijst van de job intussen, dan gebeurt er niets",
                      on_fail="de service werkt gewoon; de run eindigt met 'back-up niet ingesteld'")

    async def go(ctx: dict) -> dict:
        j = next((j for j in await px.integ.backup_jobs() if j.get("id") == job), None)
        if j is None:
            raise IntegrationError(f"back-upjob {job} bestaat niet meer")
        if _ids(j.get("vmid")) != sorted(set(before)):
            raise IntegrationError(f"back-upjob {job} veranderde intussen: doe de proef opnieuw")
        await px.integ.send(method, path, data)
        return {"detail": f"{what} in back-upjob {job}", "created": {**spec, "label": f"{what} in back-upjob {job}"}}
    return Op("backup", "in de back-up (job)", step, go, _verify(sysm, spec), fatal=False, spec=spec)


# --- weghalen (opruimen en ongedaan maken) ----------------------------------------------------------------------------

def _gone(what: str) -> dict:
    return {"detail": f"{what} was al weg", "skipped": True}


def _changed(what: str) -> dict:
    return {"detail": f"{what} veranderd, niet verwijderd", "skipped": True}


def op_cf_record_del(cf: System, zone_id: str, rec: dict, fqdn: str, targets: set[tuple[str, str]],
                     expect: str | None = None, note: str | None = None) -> Op:
    method, path, _ = cfm.record_delete_request(zone_id, rec["id"])
    what = f"{rec['type']}-record"
    step = proef.step(_cf_machine(cf), "cloudflare-api", f"{method} {cf.integ.base}{path}", who=_cf_who(cf),
                      data={"type": rec["type"], "naam": fqdn, "inhoud": rec["content"]}, note=note)

    async def go(ctx: dict) -> dict:
        r = next((r for r in await cf.integ.records(fqdn) if r["id"] == rec["id"]), None)
        if r is None:
            return _gone(what)
        content = _norm(r["content"])
        ok = _norm(r["name"]) == fqdn and r["type"] in ADDR and (
            content == expect if expect is not None else (r["type"], content) in targets or r.get("comment") == COMMENT)
        if not ok:
            return _changed(what)
        await cf.integ.send(method, path)
        return {"detail": f"{r['type']} → {r['content']} weg", "removed": {"kind": "cf_record", "label": f"{what} {fqdn}"}}
    return Op("cf_record", "DNS-record in Cloudflare weg", step, go, spec={"kind": "cf_record"})


def op_cf_ingress_del(cf: System, account: str, tunnel: str, fqdn: str, service: str, note: str | None = None) -> Op:
    method, path, _ = cfm.tunnel_put_request(account, tunnel, {})
    step = proef.step(_cf_machine(cf), "cloudflare-api", f"{method} {cf.integ.base}{path}", who=_cf_who(cf),
                      data={"weg": {"hostname": fqdn, "service": service}},
                      note=note or "de hele configuratie van de tunnel gaat terug, zonder deze regel")

    async def go(ctx: dict) -> dict:
        tc = await cf.integ.tunnel_config(account, tunnel)
        config = copy.deepcopy(tc["config"])
        ingress = list(config.get("ingress") or [])
        keep = [r for r in ingress if not (_norm(r.get("hostname")) == fqdn and r.get("service") == service)]
        if len(keep) == len(ingress):
            return _gone("tunnelregel")
        config["ingress"] = keep
        await cf.integ.send(*cfm.tunnel_put_request(account, tunnel, config))
        return {"detail": f"regel {fqdn} → {service} weg", "removed": {"kind": "cf_ingress", "label": "tunnelregel"}}
    return Op("cf_ingress", "tunnelregel in Cloudflare weg", step, go)


def op_lan_dns_del(ag: System, fqdn: str, answer: str, note: str | None = None) -> Op:
    method, path, data = ag.integ.rewrite_request(False, fqdn, answer)
    step = proef.step(_ag_machine(ag), "adguard-api", f"{method} {ag.integ.base}{path}", who=_ag_who(ag), data=data,
                      note=note)

    async def go(ctx: dict) -> dict:
        if not any(r["domain"] == fqdn and r["answer"] == answer for r in await ag.integ.rewrites()):
            return _gone("rewrite")
        await ag.integ.send(method, path, data)
        return {"detail": f"{fqdn} → {answer} weg", "removed": {"kind": "lan_dns", "label": "rewrite in AdGuard"}}
    return Op("lan_dns", "naam in AdGuard weg", step, go)


def op_npm_host_del(npm: System, host_id: int, fqdn: str, expect: str | None = None, note: str | None = None) -> Op:
    method, path, _ = npmm.host_delete_request(host_id)
    step = proef.step(_npm_machine(npm), "npm-api", f"{method} {npm.integ.base}/api{path}", who=_npm_who(npm),
                      note=note or "eerst opnieuw gelezen: heeft de host intussen een andere naam of een ander doel, "
                                   "dan blijft hij staan")

    async def go(ctx: dict) -> dict:
        h = next((h for h in await npm.integ.proxy_hosts(write=True) if int(h.get("id") or 0) == int(host_id)), None)
        if h is None:
            return _gone(f"host #{host_id}")
        if routes._names(h) != [fqdn] or (expect is not None and _forward(h) != expect):
            return _changed(f"host #{host_id}")
        await npm.integ.send(method, path)
        return {"detail": f"host #{host_id} weg", "removed": {"kind": "npm_host", "label": f"NPM-host #{host_id}"}}
    return Op("npm_host", "proxy host in NPM weg", step, go)


def op_npm_cert_del(npm: System, cert_id: int, fqdn: str, note: str | None = None) -> Op:
    method, path, _ = npmm.cert_delete_request(cert_id)
    step = proef.step(_npm_machine(npm), "npm-api", f"{method} {npm.integ.base}/api{path}", who=_npm_who(npm),
                      note=note or "alleen als geen enkele host het certificaat nog gebruikt")

    async def go(ctx: dict) -> dict:
        c = next((c for c in await npm.integ.certificates(write=True) if int(c.get("id") or 0) == int(cert_id)), None)
        if c is None:
            return _gone(f"certificaat #{cert_id}")
        if c.get("provider") != "letsencrypt" or routes._names(c) != [fqdn]:
            return _changed(f"certificaat #{cert_id}")
        hosts = [*await npm.integ.proxy_hosts(write=True), *await npm.integ.redirection_hosts(write=True),
                 *await npm.integ.dead_hosts(write=True)]
        if users := [h for h in hosts if int(h.get("certificate_id") or 0) == int(cert_id)]:
            return {"detail": f"certificaat #{cert_id} blijft: nog gebruikt door host #{users[0].get('id')}",
                    "skipped": True}
        await npm.integ.send(method, path)
        return {"detail": f"certificaat #{cert_id} weg", "removed": {"kind": "npm_cert", "label": f"certificaat #{cert_id}"}}
    return Op("npm_cert", "certificaat in NPM weg", step, go)


def op_backup_pool_del(px: System, pool: str, vmid: int, kind: str | None, note: str | None = None) -> Op:
    method, path, data = px.integ.pool_update_request(pool, vmid, remove=True)
    what = _guest_label(kind, vmid)
    step = proef.step(_pve_machine(px), "proxmox-api", f"{method} {px.integ.base}{path}", who=_pve_who(px), data=data,
                      note=note)

    async def go(ctx: dict) -> dict:
        g = await px.integ.guest(vmid)
        if g is None or g.get("pool") != pool:
            return {"detail": f"{what} zat niet (meer) in pool {pool}", "skipped": True}
        await px.integ.send(method, path, data)
        return {"detail": f"{what} uit pool {pool}", "removed": {"kind": "backup", "label": f"{what} uit pool {pool}"}}
    return Op("backup", "uit de back-up (pool)", step, go, fatal=False)


def op_backup_job_del(px: System, job: str, vmid: int, kind: str | None, rest: list[int], note: str | None = None) -> Op:
    method, path, data = px.integ.job_update_request(job, rest)
    what = _guest_label(kind, vmid)
    step = proef.step(_pve_machine(px), "proxmox-api", f"{method} {px.integ.base}{path}", who=_pve_who(px), data=data,
                      note=note or "eerst opnieuw gelezen: alleen dit nummer gaat eruit")

    async def go(ctx: dict) -> dict:
        j = next((j for j in await px.integ.backup_jobs() if j.get("id") == job), None)
        ids = _ids((j or {}).get("vmid"))
        if j is None or vmid not in ids:
            return {"detail": f"{what} zat niet (meer) in back-upjob {job}", "skipped": True}
        left = [i for i in ids if i != vmid]
        if not left:
            raise IntegrationError(f"back-upjob {job} zou leeg worden: haal hem zelf weg in Proxmox")
        await px.integ.send(*px.integ.job_update_request(job, left))
        return {"detail": f"{what} uit back-upjob {job}", "removed": {"kind": "backup", "label": f"{what} uit job {job}"}}
    return Op("backup", "uit de back-up (job)", step, go, fatal=False)


def op_tile_del(service_id: int, name: str, fqdn: str, who: str, note: str | None = None) -> Op:
    step = proef.step("dashboard", "dashboard", f"tegel '{name}' verwijderen", who=who, data={"tegel": service_id},
                      note=note or "alleen als de tegel nog naar deze naam wijst")

    async def go(ctx: dict) -> dict:
        async with ctx["maker"]() as db:
            s = await db.get(Service, service_id)
            if s is None:
                return _gone(f"tegel {name}")
            if _host_of(s.url) != fqdn:
                return _changed(f"tegel {name}")
            await db.delete(s)
            user = await db.get(User, ctx["user_id"]) if ctx.get("user_id") else None
            await record_revision(db, user, f"Service '{name}' verwijderd (opruimen)")
            await db.commit()
        routes.forget()
        return {"detail": f"tegel {name} weg", "removed": {"kind": "tile", "label": f"tegel {name}"}}
    return Op("tile", "tegel weg", step, go)


# --- plannen ----------------------------------------------------------------------------------------------------------

@dataclass
class Plan:
    ops: list[Op]
    plan: dict        # proef.plan(...) met kan, waarom, hash, fqdn, guest
    services: list[int] = field(default_factory=list)   # tegels die weg zouden gaan (voor de 2FA bij een lopende check)

    @property
    def hash(self) -> str:
        return plan_hash(self.ops)


def plan_hash(ops: list[Op]) -> str:
    """Wat de run uitvoert: per stap machine, via, call en inhoud. De checks tellen niet mee."""
    raw = [[o.proef.get("machine"), o.proef.get("via"), o.proef.get("call"), o.proef.get("data")] for o in ops]
    return hashlib.sha256(json.dumps(raw, sort_keys=True, default=str).encode()).hexdigest()[:16]


class _Acc:
    """Wat een plan verzamelt: checks (B = blokkeert), overgeslagen stappen, waarschuwingen."""

    def __init__(self) -> None:
        self.checks: list[dict] = []
        self.skipped: list[dict] = []
        self.after: list[str] = []
        self.warnings: list[str] = []
        self.why: list[str] = []
        self.ops: list[Op] = []

    def check(self, what: str, ok: bool | None, detail: str | None = None, block: str | None = None) -> None:
        self.checks.append(proef.check(what, ok, detail))
        if block:
            self.why.append(block)

    def skip(self, what: str, why: str) -> None:
        self.skipped.append(proef.skip(what, why))

    def plan(self, title: str, order: tuple[str, ...], **extra) -> Plan:
        ops = sorted(self.ops, key=lambda o: order.index(o.key))
        p = Plan(ops, {})
        p.plan = proef.plan(title, [o.proef for o in ops], checks=self.checks, skipped=self.skipped, after=self.after,
                            warnings=self.warnings, kan=not self.why and bool(ops), waarom=self.why, hash=p.hash,
                            **extra)
        return p


@dataclass
class Pattern:
    kind: str                 # tunnel | portforward | gemengd | onbekend
    lead: str | None          # de meest gebruikte vorm (ook bij gemengd)
    top: tuple[str, str] | None
    n: int
    text: str

    @property
    def tunnel(self) -> str | None:
        m = TUNNEL_CNAME.match(self.top[1]) if self.top and self.top[0] == "CNAME" else None
        return m.group(1) if m else None


def _kind_of(rtype: str, content: str, zone: str, apex: set[str]) -> str:
    if rtype == "CNAME" and TUNNEL_CNAME.match(content):
        return "tunnel"
    if rtype == "CNAME" and content == zone:
        return "portforward"
    if rtype in ("A", "AAAA"):
        if content in apex:
            return "portforward"
        try:
            if ipaddress.ip_address(content).is_global:
                return "portforward"
        except ValueError:
            pass
    return "anders"


def npm_targets(records: list[dict], names: set[str], zone: str, skip: str | None = None) -> set[tuple[str, str]]:
    """Waar de namen van NPM in Cloudflare naartoe wijzen ((type, inhoud)), plus de zone zelf en haar adressen."""
    out = {(r["type"], _norm(r["content"])) for r in records
           if r["type"] in ADDR and _norm(r["name"]) in names and _norm(r["name"]) != skip}
    out |= {("CNAME", zone)} | {(r["type"], _norm(r["content"])) for r in records
                                 if _norm(r["name"]) == zone and r["type"] in ("A", "AAAA")}
    return out


def pattern_of(records: list[dict], names: set[str], zone: str) -> Pattern:
    """Hoe de namen van NPM nu in Cloudflare staan: wat het meest voorkomt, kopieert het dashboard."""
    apex = {_norm(r["content"]) for r in records if _norm(r["name"]) == zone and r["type"] in ("A", "AAAA")}
    pairs = [(r["type"], _norm(r["content"])) for r in records if r["type"] in ADDR and _norm(r["name"]) in names]
    if not pairs:
        return Pattern("onbekend", None, None, 0, "geen record van een naam uit NPM gevonden")
    kinds = Counter(_kind_of(t, c, zone, apex) for t, c in pairs)
    lead, n = kinds.most_common(1)[0]
    top = Counter(p for p in pairs if _kind_of(*p, zone, apex) == lead).most_common(1)[0][0]
    kind = lead if n / len(pairs) >= 0.8 and lead != "anders" else "gemengd"
    shown = f"{top[0]} → {top[1][:8]}….cfargotunnel.com" if lead == "tunnel" else f"{top[0]} → {top[1]}"
    if kind == "tunnel":
        text = f"{len(pairs)} namen van NPM: {shown} (tunnel)"
    elif kind == "portforward":
        text = f"{len(pairs)} namen van NPM: {shown} (port-forward)"
    else:
        text = f"gemengd: {n} van {len(pairs)} namen van NPM als {shown}"
    return Pattern(kind, lead, top, len(pairs), text)


def _catch_all(ingress: list[dict]) -> int:
    """Waar een nieuwe regel komt: vlak voor de regel zonder hostname (http_status:404), anders achteraan."""
    return next((i for i, r in enumerate(ingress) if not r.get("hostname")), len(ingress))


def _svc_host(service) -> str | None:
    return _host_of(str(service or "")) if "://" in str(service or "") else None


def tunnel_rule(ingress: list[dict], fqdn: str, npm_hosts: set[str]) -> dict | None:
    """Een nieuwe regel naar het voorbeeld van de regels naar NPM: de meest gebruikte service, met originRequest van
    zo'n regel. Een vaste Host of SNI die gelijk is aan de eigen naam van het voorbeeld wordt de nieuwe naam; een regel
    met een andere vaste waarde is geen voorbeeld."""
    usable = []
    for r in ingress:
        name = _norm(r.get("hostname"))
        if not name or name.startswith("*") or r.get("path") or _svc_host(r.get("service")) not in npm_hosts:
            continue
        o = r.get("originRequest") or {}
        fixed = [o.get(k) for k in ("httpHostHeader", "originServerName") if o.get(k)]
        if all(_norm(v) == name for v in fixed):
            usable.append(r)
    if not usable:
        return None
    service = Counter(r["service"] for r in usable).most_common(1)[0][0]
    ex = next(r for r in usable if r["service"] == service)
    rule: dict = {"hostname": fqdn, "service": service}
    if ex.get("originRequest"):
        rule["originRequest"] = {k: (fqdn if k in ("httpHostHeader", "originServerName") else v)
                                 for k, v in ex["originRequest"].items()}
    return rule


def _routes_all(ingress: list[dict], zone: str, npm_hosts: set[str]) -> bool:
    """Brengt deze tunnel elke naam van de zone naar NPM (een regel *.zone, of een vangnet naar NPM)?"""
    for r in ingress:
        name = _norm(r.get("hostname"))
        if name == f"*.{zone}" or (not name and _svc_host(r.get("service")) in npm_hosts):
            return True
    return False


def _allows(acl: dict, ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for c in acl.get("clients") or []:
        if c.get("directive") != "allow":
            continue
        try:
            if addr in ipaddress.ip_network(str(c.get("address") or "").strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


async def plan_create(db: AsyncSession, clients, body, *, at_run: bool = False, who: str = "") -> Plan:
    """Het plan voor een nieuwe service. Leest alleen. at_run: het plan van de echte run (geen TCP-proef, de CT/VM
    met één call nagekeken)."""
    snap = await gather(db, clients)
    sysm = snap.sysm
    acc = _Acc()
    ip, port, label = str(body.ip), int(body.port), body.name
    extra = {"fqdn": None, "guest": None}

    npm = sysm.npm
    if npm is None:
        acc.check("NPM-API aanwezig", False, "Geen NPM-API in API-beheer",
                  "Geen NPM-API: maak in API-beheer een API van soort npm (Nginx Proxy Manager)")
        return acc.plan("Nieuwe service", ORDER_CREATE, **extra)
    n = npm.integ
    try:
        hosts = await n.proxy_hosts(write=True)
        redirs, dead = await n.redirection_hosts(write=True), await n.dead_hosts(write=True)
        certs = await n.certificates(write=True)
        acls = await n.access_lists(write=True)
        me_w = await n.me(True)
        me_r = await n.me(False) if n.split else me_w
    except IntegrationError as e:
        msg = mask(str(e))[:200]
        acc.check(f"NPM ({npm.label}) bereikbaar", False, msg, f"NPM: {msg}")
        return acc.plan("Nieuwe service", ORDER_CREATE, **extra)
    acc.check(f"NPM-API aanwezig: {npm.label}", True)

    zone, where = zone_of(sysm, certs)
    if zone is None:
        acc.check("domein", False, where, f"Geen domein: {where}")
        return acc.plan("Nieuwe service", ORDER_CREATE, **extra)
    acc.check(f"domein: {zone}", True, where)
    fqdn = f"{label}.{zone}"
    extra["fqdn"] = fqdn
    title = f"Nieuwe service {fqdn}"
    publiek = body.exposure == "publiek"

    # Naam vrij in NPM: ook een redirection- of 404-host met die naam beantwoordt NPM al.
    taken = next((h for h in [*hosts, *redirs, *dead] if fqdn in routes._names(h)), None)
    acc.check("naam vrij in NPM", taken is None, f"{fqdn} staat al in NPM (host #{taken.get('id')})" if taken else fqdn,
              f"{fqdn} staat al in NPM" if taken else None)

    # Certificaat: eerst een wildcard (of een certificaat voor precies deze naam), anders Let's Encrypt.
    fits = [c for c in certs if routes._names(c) and routes._covers(routes._names(c), fqdn)]
    fits.sort(key=lambda c: (str(c.get("expires_on") or ""), int(c.get("id") or 0)), reverse=True)
    cert, le, version, email = (fits[0] if fits else None), False, None, (me_w.get("email") or None)
    if body.cert == "geen":
        cert = None
        acc.check("certificaat: geen", None, "alleen http; de tegel krijgt http://")
    elif body.cert == "letsencrypt" or (body.cert == "auto" and cert is None):
        cert = None
        if not publiek:
            acc.check("certificaat", False, "geen wildcardcertificaat voor deze naam",
                      "Een naam voor thuis krijgt geen certificaat van Let's Encrypt: maak een wildcardcertificaat "
                      f"*.{zone} in NPM, of kies 'geen (alleen http)'")
        else:
            le = True
            version = await n.version()
            v = ".".join(map(str, version)) if version else "?"
            if version is None:
                acc.check("certificaat: Let's Encrypt", False, "NPM-versie onbekend",
                          "NPM-versie onbekend: het dashboard weet niet hoe het certificaat aan te vragen")
            elif not email:
                acc.check("certificaat: Let's Encrypt", False, "de schrijfgebruiker van NPM heeft geen e-mailadres",
                          "Let's Encrypt vraagt een e-mailadres: geef de schrijfgebruiker in NPM een echt e-mailadres")
            else:
                acc.check(f"certificaat: Let's Encrypt (NPM {v}, e-mail van de schrijfgebruiker)", True, email)
                acc.warnings.append("Let's Encrypt lukt alleen als het NPM op poort 80 bereikt (port-forward 80, of een "
                                    f"tunnel naar http://…:80). Let's Encrypt registreert het e-mailadres {email}.")
    else:
        days = npmm.days_left(cert.get("expires_on"))
        acc.check(f"certificaat: {cert.get('nice_name') or ', '.join(cert.get('domain_names') or [])} (#{cert.get('id')}"
                  + (f", nog {days:.0f} dagen)" if days is not None else ")"), True)

    ok, why = npmm.can_write(me_w, need_cert=le)
    acc.check(f"NPM-schrijfgebruiker ({n.user(True)}) mag proxy hosts beheren en ziet alle hosts", ok, why,
              None if ok else f"NPM-schrijfgebruiker: {why}")
    if (me_r.get("permissions") or {}).get("visibility", "all") != "all" and "admin" not in (me_r.get("roles") or []):
        acc.check("NPM-leesgebruiker ziet alle hosts", False, "ziet alleen zijn eigen hosts")
        acc.warnings.append("De leesgebruiker van NPM ziet alleen zijn eigen hosts: hw → routes en de melding voor "
                            "nieuwe hosts missen de hosts van de schrijfgebruiker. Zet Item Visibility op All Items.")
    if not n.split:
        acc.warnings.append("Eén NPM-gebruiker voor lezen en schrijven: maak een tweede (README → Nieuwe service).")

    if not at_run:
        reach, err = await routes._probe((ip, port))
        acc.check(f"backend {ip}:{port} bereikbaar vanaf het dashboard", True if reach else None,
                  None if reach else f"{err}: misschien een firewall tussen de VLAN's; NPM kan er wel aan kunnen")

    # Cloudflare: zone, records, het patroon en de tunnel.
    cf = sysm.cf
    records: list[dict] = []
    zone_id = None
    names = {x for h in [*hosts, *redirs, *dead] for x in routes._names(h)}
    pattern = Pattern("onbekend", None, None, 0, "geen Cloudflare DNS-API")
    if cf is None:
        acc.check("Cloudflare DNS-API", None if not publiek else False, "geen Cloudflare DNS-API in API-beheer",
                  "Geen Cloudflare DNS-API: zonder kan alleen 'alleen thuis'" if publiek else None)
    else:
        try:
            zone_id = await cf.integ.zone_id()
            records = await cf.integ.records()
            acc.check("Cloudflare-token werkt (zone gevonden)", True)
        except IntegrationError as e:
            msg = mask(str(e))[:200]
            acc.check("Cloudflare-token werkt", False, msg, f"Cloudflare: {msg}" if publiek else None)
            cf = None
    if cf is not None:
        mine = [r for r in records if _norm(r["name"]) == fqdn and r["type"] in ADDR]
        acc.check("naam vrij in Cloudflare (A/AAAA/CNAME)", not mine,
                  f"{mine[0]['type']} → {mine[0]['content']}" if mine else None,
                  f"Cloudflare heeft al een record voor {fqdn}" if mine else None)
        pattern = pattern_of(records, names - {fqdn}, zone)
        acc.check(f"patroon: {pattern.text}", pattern.kind in ("tunnel", "portforward") or None,
                  block="Geen record van een NPM-naam gevonden: het dashboard weet niet hoe de naam publiek te maken"
                  if publiek and pattern.kind == "onbekend" else None)
        if publiek and pattern.kind == "gemengd":
            if pattern.lead in ("tunnel", "portforward"):
                acc.warnings.append(f"De namen van NPM staan verschillend in Cloudflare; het dashboard volgt de meest "
                                    f"gebruikte vorm ({pattern.top[0]} → {pattern.top[1]}).")
            else:
                acc.why.append("Geen duidelijk patroon in Cloudflare: maak het record zelf")
    wild = [r for r in records if _norm(r["name"]) == f"*.{zone}" and r["type"] in ADDR]
    npm_ip = await routes._npm_ip(n.base)
    npm_hosts = {h for h in (npm_ip, _host_of(n.base)) if h}

    # De tunnel: welke regels, en brengt hij elke naam naar NPM?
    account = cf.integ.account if cf else ""
    tunnel_id = pattern.tunnel if pattern.lead == "tunnel" else None
    tc, tc_err = None, None
    if cf is not None and tunnel_id:
        if not cfm.ACCOUNT_RE.match(account):
            tc_err = "zet account (32 tekens) in de Cloudflare DNS-API: nodig voor de tunnel"
        else:
            try:
                tc = await cf.integ.tunnel_config(account, tunnel_id)
            except IntegrationError as e:
                tc_err = mask(str(e))[:200]

    if publiek and cf is not None and zone_id:
        if tunnel_id and pattern.lead == "tunnel" and pattern.kind in ("tunnel", "gemengd"):
            ingress = (tc or {}).get("config", {}).get("ingress") or []
            if tc_err:
                acc.check("tunnel", False, tc_err, f"Tunnel: {tc_err}")
            elif tc.get("source") != "cloudflare":
                acc.check("tunnel: lokaal beheerd", None, "config.yml op de machine van cloudflared")
                acc.skip("tunnelregel", "lokaal beheerde tunnel")
                acc.warnings.append(f"Lokaal beheerde tunnel: zet de hostname {fqdn} zelf in config.yml van cloudflared.")
            elif any(_norm(r.get("hostname")) in (fqdn, f"*.{zone}") for r in ingress):
                acc.check("tunnel: regel nodig", True, "de tunnel heeft al een regel die de naam dekt")
                acc.skip("tunnelregel", "de tunnel heeft al een regel voor deze naam of *." + zone)
            else:
                rule = tunnel_rule(ingress, fqdn, npm_hosts)
                if rule is None:
                    acc.check("tunnel: voorbeeldregel naar NPM zonder vaste Host", False, "geen bruikbare regel",
                              "Geen voorbeeldregel naar NPM in de tunnel (of elke regel heeft een andere vaste Host): "
                              "maak de tunnelregel zelf")
                else:
                    before = (ingress[_catch_all(ingress)] if _catch_all(ingress) < len(ingress) else {}).get("service")
                    acc.check("tunnel: eigen regel nodig, naar het voorbeeld van de andere", True, rule["service"])
                    acc.ops.append(op_cf_ingress_add(cf, sysm, account, tunnel_id, rule, tc.get("version"),
                                                     before or "einde"))
        proxied_wild = [r for r in wild if r.get("proxied")]
        if proxied_wild:
            acc.skip("DNS-record", f"*.{zone} in Cloudflare dekt de naam al")
        elif pattern.lead in ("tunnel", "portforward") and pattern.kind != "onbekend":
            rtype, content = ("CNAME", pattern.top[1]) if pattern.lead == "tunnel" else ("CNAME", zone)
            rec = {"type": rtype, "name": fqdn, "content": content, "proxied": True, "ttl": 1, "comment": COMMENT}
            acc.ops.append(op_cf_record_add(cf, sysm, zone_id, rec))
    elif not publiek:
        acc.skip("DNS-record in Cloudflare", "alleen thuis: geen publiek record")

    # Toegangslijst (alleen thuis: verplicht, tenzij de namen alleen via een tunnel zonder wildcard naar buiten gaan).
    by_id = {int(a.get("id") or 0): a for a in acls}
    lan_lists = [a for a in acls if npmm.lan_only(a)[0]]
    copied = None
    if body.bescherming_van:
        copied = next((h for h in hosts if int(h.get("id") or 0) == body.bescherming_van), None)
        if copied is None:
            acc.check("zelfde bescherming als", False, f"host #{body.bescherming_van} niet gevonden",
                      f"Host #{body.bescherming_van} niet gevonden in NPM")
    acl_id = body.access_list_id or (int(copied.get("access_list_id") or 0) if copied else 0) or None
    acl = by_id.get(acl_id) if acl_id else None
    if acl_id and acl is None:
        acc.check("toegangslijst", False, f"#{acl_id} bestaat niet", f"Toegangslijst #{acl_id} bestaat niet in NPM")
    if not publiek:
        tunnel_open = False
        if pattern.kind == "tunnel":
            to_tunnel = [r for r in wild if r["type"] == "CNAME" and TUNNEL_CNAME.match(_norm(r["content"]))]
            if to_tunnel:
                tunnel_open = tc_err is not None or _routes_all((tc or {}).get("config", {}).get("ingress") or [],
                                                                zone, npm_hosts)
        if tunnel_open:
            acc.check("alleen thuis: niet bereikbaar van buiten", False, "*.{zone} gaat via de tunnel naar NPM",
                      "Via de tunnel is elke naam publiek. Een toegangslijst helpt daar niet: dat verkeer komt van "
                      "cloudflared op je LAN.")
        elif pattern.kind == "tunnel":
            acc.check("alleen thuis: niet bereikbaar van buiten", True, "geen wildcard via de tunnel; geen record")
            if acl is None and lan_lists:
                acc.warnings.append(f"Aanbevolen: toegangslijst {lan_lists[0].get('name')} (alleen thuis), ook als "
                                    "de naam niet in Cloudflare staat.")
        elif acl is None and body.poort_443_dicht:
            acc.check("alleen thuis: toegangslijst", None, "geen: op jouw woord staat poort 443 van NPM niet open")
            acc.warnings.append("Op jouw woord: zonder toegangslijst is deze naam publiek als poort 443 toch "
                                "doorgestuurd is.")
        elif acl is None:
            acc.check("alleen thuis: toegangslijst", False, "nodig", "Voor 'alleen thuis' is een toegangslijst in NPM "
                      "nodig die alleen je LAN en VPN toelaat (bv. LAN met 192.168.0.0/16): wie poort 443 van NPM "
                      "bereikt, haalt anders elke naam op")
    if acl is not None:
        ok, why = npmm.lan_only(acl)
        need = not publiek
        acc.check(f"toegangslijst {acl.get('name')} laat alleen LAN/VPN toe", ok if need else (ok or None), why,
                  f"Toegangslijst {acl.get('name')} {why}" if need and not ok else None)
    shown = acl if acl is not None else (lan_lists[0] if not publiek and lan_lists else None)
    if shown is not None:
        dash_ip = (get_settings().syslog_target or "").strip()
        if not dash_ip:
            acc.check(f"toegangslijst {shown.get('name')} laat het dashboard toe", None,
                      "het IP van het dashboard is niet ingesteld (HOMEPAGE_SYSLOG_TARGET)")
        else:
            allowed = _allows(shown, dash_ip)
            acc.check(f"toegangslijst {shown.get('name')} laat het dashboard ({dash_ip}) toe", allowed)
            if not allowed:
                acc.warnings.append(f"Toegangslijst {shown.get('name')} laat het dashboard ({dash_ip}) niet toe: de "
                                    "check gaat via NPM en de tegel wordt dan rood.")

    # Bescherming en beheerpagina's naar internet.
    protected = [h for h in hosts if int(h.get("access_list_id") or 0) or LOGIN_RE.search(str(h.get("advanced_config") or ""))]
    acc.check(f"bescherming: {len(protected)} van {len(hosts)} hosts hebben een toegangslijst of login", True)
    adv = str(copied.get("advanced_config") or "") if copied else ""
    if publiek and hosts and len(protected) * 2 >= len(hosts) and not acl_id and not LOGIN_RE.search(adv):
        acc.warnings.append(f"De meeste hosts hebben een toegangslijst of login; {fqdn} krijgt er geen. Kies 'zelfde "
                            "bescherming als' om die van een andere host over te nemen.")
    admin = ADMIN_PORTS.get(port) or snap.apis.get((ip, port))
    if admin:
        acc.check(f"beheerpagina: {admin}?", None, f"{ip}:{port}")
        if publiek:
            acc.warnings.append(f"Dit lijkt de beheerpagina van {admin}: die zet je liever niet op internet.")

    # De proxy host zelf.
    host_body = {"domain_names": [fqdn], "forward_scheme": body.scheme, "forward_host": ip, "forward_port": port,
                 "certificate_id": int(cert["id"]) if cert else 0, "ssl_forced": bool(cert),
                 "http2_support": bool(cert), "hsts_enabled": False, "hsts_subdomains": False, "block_exploits": True,
                 "caching_enabled": False, "allow_websocket_upgrade": bool(body.websockets),
                 "access_list_id": acl_id or 0, "advanced_config": adv, "locations": []}
    acc.ops.append(op_npm_host_add(npm, sysm, host_body, fqdn))
    if le and version is not None and email:
        acc.ops.append(op_npm_cert_add(npm, sysm, fqdn, version, email))
        acc.ops.append(op_npm_attach(npm))

    # Thuis: AdGuard, als er nog geen rewrite naar NPM is.
    ag = sysm.adguard
    if ag is None:
        acc.check("LAN-DNS: geen AdGuard", None, "zet de naam zelf in je LAN-DNS als het nodig is")
    elif not npm_ip:
        acc.skip("naam in AdGuard", "het IP van NPM is onbekend")
    else:
        try:
            rw = [r for r in await ag.integ.rewrites() if r["enabled"]]
        except IntegrationError as e:
            rw = None
            acc.skip("naam in AdGuard", f"AdGuard: {mask(str(e))[:200]}")
        if rw is not None:
            cover = next((r for r in rw if r["domain"] in (fqdn, f"*.{zone}") and r["answer"] == npm_ip), None)
            other = next((r for r in rw if r["domain"] == fqdn and r["answer"] != npm_ip), None)
            if cover:
                acc.check(f"LAN-DNS: {cover['domain']} wijst in AdGuard al naar NPM", True)
                acc.skip("naam in AdGuard", f"{cover['domain']} wijst al naar {npm_ip}")
            elif other:
                acc.check("LAN-DNS", None, f"AdGuard stuurt {fqdn} naar {other['answer']}")
                acc.skip("naam in AdGuard", f"er is al een rewrite naar {other['answer']}: pas die zelf aan")
            else:
                acc.check("LAN-DNS: exacte rewrite in AdGuard nodig", True)
                acc.ops.append(op_lan_dns_add(ag, sysm, fqdn, npm_ip))

    # Tegel en Zabbix.
    zhost = next((h for h in snap.zabbix if ip in (h.get("ips") or [])), None)
    acc.check("Zabbix: host met dit IP", True if zhost else None,
              (zhost.get("name") or zhost.get("host")) if zhost else "geen; 'automatisch' koppelt ook op naam")
    url = f"{'https' if cert or le else 'http'}://{fqdn}"
    if body.tile is not None:
        same = next((t for t in snap.tiles if t["host"] == fqdn), None)
        if body.tile.group_id not in snap.groups:
            acc.check("tegel", False, "die groep bestaat niet", "De gekozen groep bestaat niet (meer)")
        elif same:
            acc.check("tegel: geen tegel met dit adres", None, f"{same['name']} wijst al naar {fqdn}")
            acc.skip("tegel", f"er is al een tegel voor {fqdn} ({same['name']})")
        else:
            acc.check("tegel: geen tegel met dit adres", True)
            pick = (body.zabbix or "").strip()
            tile = {"group_id": body.tile.group_id, "name": body.tile.label.strip(), "url": url, "icon": f"{label}.png",
                    "config": {"zabbix": pick} if pick else {},
                    "check": {"type": "http", "interval": 60} if body.tile.check else {}}
            acc.ops.append(op_tile_add(sysm, tile, snap.groups[body.tile.group_id], who))
    else:
        acc.skip("tegel", "niet gevraagd")

    # De CT/VM en de back-up.
    guest, gerr = await find_guest(db, clients, snap, ip, at_run=at_run)
    extra["guest"] = _guest_public(guest)
    if guest:
        acc.check(f"{_guest_label(guest['type'], guest['vmid'])} {guest.get('name') or ''} op {guest.get('node')} "
                  "heeft dit IP", True, f"gevonden via {guest['how']}")
    else:
        acc.check("CT/VM met dit IP", None, gerr or "niet gevonden in Proxmox (een fysieke machine, of geen Proxmox-tegel)")
    if body.backup and guest:
        await _plan_backup_add(acc, sysm, guest, body.backup_job)
    elif not body.backup:
        acc.skip("back-up", "niet gevraagd")
    else:
        acc.skip("back-up", "geen CT/VM met dit IP gevonden")

    # Daarna.
    if acl_id:
        acc.after.append(f"de check gaat via NPM ({npm_ip or '?'}) en heeft de toegangslijst nodig")
    else:
        acc.after.append(f"de check gaat rechtstreeks naar {ip}:{port} zodra de routes vernieuwd zijn (meteen na de tegel)")
    acc.after.append("hw → back-ups toont de dekking binnen 30 minuten")
    acc.after.append("de nachtelijke kopie van NPM toont de nieuwe host in Configuratiewijzigingen")
    for note in sysm.notes:
        acc.warnings.append(note)
    return acc.plan(title, ORDER_CREATE, **extra)


async def _plan_backup_add(acc: _Acc, sysm: Systems, guest: dict, wanted: str | None) -> None:
    """Een job die naar een PBS schrijft: via zijn pool (minste rechten) of zijn lijst van VMID's. Nooit fataal."""
    px = sysm.pve_ref(guest["pve"])
    what = _guest_label(guest["type"], guest["vmid"])
    try:
        jobs = await px.integ.backup_jobs()
        stores = {s.get("storage"): s.get("type") for s in await px.integ.storages()}
    except IntegrationError as e:
        acc.skip("back-up", f"Proxmox: {mask(str(e))[:200]}")
        return
    g = {"node": guest.get("node"), "vmid": int(guest["vmid"]), "pool": guest.get("pool")}
    covered = [j for j in jobs if coverage.covers(j, g)]
    if covered:
        j = covered[0]
        via = f" (via pool {j['pool']})" if j.get("pool") else ""
        acc.check(f"back-up: {what} zit al in back-upjob {j.get('id')}{via}", True)
        acc.skip("back-up", f"zit al in back-upjob {j.get('id')}{via}")
        return
    cands = [j for j in jobs if coverage._on(j.get("enabled", 1)) and stores.get(j.get("storage")) == "pbs"
             and not j.get("dumpdir") and not coverage._on(j.get("all", 0))
             and (not j.get("node") or j.get("node") == g["node"])]
    if wanted:
        cands = [j for j in cands if j.get("id") == wanted]
        if not cands:
            acc.check("back-up", None, f"back-upjob {wanted} kan niet (niet naar een PBS, uit, of voor een andere node)")
            acc.skip("back-up", f"back-upjob {wanted} kan niet")
            return
    pools = [j for j in cands if j.get("pool")]
    lists = sorted((j for j in cands if not j.get("pool")), key=lambda j: len(_ids(j.get("vmid"))), reverse=True)
    reasons = []
    for j in [*pools, *lists]:
        if j.get("pool"):
            if g["pool"]:
                reasons.append(f"zit al in pool {g['pool']}: niet verplaatst")
                continue
            need = [("Pool.Allocate", f"/pool/{j['pool']}"), ("VM.Allocate", f"/vms/{g['vmid']}")]
        else:
            need = [("Sys.Modify", "/"), ("Datastore.Allocate", f"/storage/{j.get('storage')}")]
        missing = []
        try:
            for priv, path in need:
                if priv not in await px.integ.privs_at(path):
                    missing.append(f"{priv} op {path}")
        except IntegrationError as e:
            reasons.append(f"rechten niet op te vragen: {mask(str(e))[:120]}")
            continue
        if missing:
            reasons.append(f"het actietoken mist {', '.join(missing)} (README → Nieuwe service)")
            continue
        try:
            if j.get("pool"):
                op = op_backup_pool_add(px, sysm, j["pool"], guest)
                acc.check(f"back-up: {what} in pool {j['pool']} van back-upjob {j.get('id')}", True,
                          "rechten van het actietoken in orde")
            else:
                op = op_backup_job_add(px, sysm, j.get("id"), guest, _ids(j.get("vmid")))
                acc.check(f"back-up: back-upjob {j.get('id')} krijgt {what} erbij", True,
                          "rechten van het actietoken in orde")
        except IntegrationError as e:
            reasons.append(str(e))
            continue
        acc.ops.append(op)
        return
    why = reasons[0] if reasons else "geen back-upjob naar een PBS (aan, zonder dumpdir, niet 'alles')"
    acc.check("back-up", None, why)
    acc.skip("back-up", why)


# --- opruimen ---------------------------------------------------------------------------------------------------------

class Refused(Exception):
    """Een naam die opruimen niet mag raken (422)."""


async def plan_cleanup(db: AsyncSession, clients, body, *, who: str = "") -> Plan:
    snap = await gather(db, clients)
    sysm = snap.sysm
    acc = _Acc()
    npm, cf = sysm.npm, sysm.cf
    hosts = redirs = dead = certs = None
    if npm:
        try:
            hosts = await npm.integ.proxy_hosts(write=True)
            redirs, dead = await npm.integ.redirection_hosts(write=True), await npm.integ.dead_hosts(write=True)
            certs = await npm.integ.certificates(write=True)
        except IntegrationError as e:
            msg = mask(str(e))[:200]
            acc.check(f"NPM ({npm.label}) bereikbaar", False, msg, f"NPM: {msg}")
            npm = None
    zone, where = zone_of(sysm, certs)
    if body.service_id is not None:
        tile = next((t for t in snap.tiles if t["id"] == body.service_id), None)
        if tile is None:
            raise Refused("Tegel niet gevonden")
        fqdn = tile["host"] or ""
    else:
        fqdn = _norm(body.fqdn or "")
    if zone is None:
        acc.check("domein", False, where, f"Geen domein: {where}")
        return acc.plan("Opruimen", ORDER_CLEANUP, fqdn=None)
    if not in_zone(fqdn, zone):
        raise Refused(f"Alleen namen als x.{zone}")
    acc.check(f"naam: {fqdn}", True, where)

    # NPM: hosts met precies deze naam, en hun eigen certificaat.
    gone_hosts: list[dict] = []
    if npm:
        names = {x for h in [*hosts, *redirs, *dead] for x in routes._names(h)}
        for h in hosts:
            hn = routes._names(h)
            if fqdn not in hn:
                continue
            if hn != [fqdn]:
                acc.skip(f"NPM-host #{h.get('id')}", f"heeft ook {', '.join(x for x in hn if x != fqdn)}")
                continue
            gone_hosts.append(h)
            acc.ops.append(op_npm_host_del(npm, int(h["id"]), fqdn))
        for h in [*redirs, *dead]:
            if fqdn in routes._names(h):
                acc.skip(f"redirection- of 404-host #{h.get('id')}", "geen proxy host: pas die zelf aan in NPM")
        gone_ids = {int(h["id"]) for h in gone_hosts}
        for cid in sorted({int(h.get("certificate_id") or 0) for h in gone_hosts} - {0}):
            c = next((c for c in certs if int(c.get("id") or 0) == cid), None)
            if c is None:
                continue
            if c.get("provider") != "letsencrypt" or routes._names(c) != [fqdn]:
                acc.skip(f"certificaat #{cid}", f"{c.get('nice_name') or ', '.join(c.get('domain_names') or [])} "
                         "blijft: niet alleen voor deze naam")
            elif any(int(h.get("certificate_id") or 0) == cid and int(h.get("id") or 0) not in gone_ids
                     for h in [*hosts, *redirs, *dead]):
                acc.skip(f"certificaat #{cid}", "blijft: een andere host gebruikt het")
            else:
                acc.ops.append(op_npm_cert_del(npm, cid, fqdn))
    else:
        names = set()
        acc.check("NPM", None, "geen NPM-API: proxy hosts niet nagekeken")

    # Cloudflare: alleen A/AAAA/CNAME naar NPM of met het commentaar van dit dashboard.
    if cf:
        try:
            zone_id = await cf.integ.zone_id()
            records = await cf.integ.records()
        except IntegrationError as e:
            msg = mask(str(e))[:200]
            acc.check("Cloudflare", False, msg, f"Cloudflare: {msg}")
            cf, records, zone_id = None, [], None
    if cf:
        targets = npm_targets(records, names, zone, skip=fqdn)
        tunnels = set()
        for r in records:
            m = TUNNEL_CNAME.match(_norm(r["content"])) if r["type"] == "CNAME" else None
            if m and (_norm(r["name"]) == fqdn or _norm(r["name"]) in names):
                tunnels.add(m.group(1))
        for r in records:
            if _norm(r["name"]) != fqdn:
                continue
            pair = (r["type"], _norm(r["content"]))
            if r["type"] in ADDR and (pair in targets or r.get("comment") == COMMENT):
                acc.ops.append(op_cf_record_del(cf, zone_id, r, fqdn, targets))
            elif r["type"] in ADDR:
                acc.skip(f"{r['type']}-record", f"naar {r['content']} blijft: wijst niet naar NPM")
            else:
                acc.skip(f"{r['type']}-record", "blijft: niet van NPM")
        npm_ip = await routes._npm_ip(npm.integ.base) if npm else None
        npm_hosts = {h for h in (npm_ip, _host_of(npm.integ.base) if npm else None) if h}
        account = cf.integ.account
        for t in sorted(tunnels):
            if not cfm.ACCOUNT_RE.match(account):
                acc.skip("tunnelregels", "geen account-id in de Cloudflare DNS-API: niet nagekeken")
                break
            try:
                tc = await cf.integ.tunnel_config(account, t)
            except IntegrationError as e:
                acc.skip("tunnelregels", f"Cloudflare: {mask(str(e))[:200]}")
                continue
            if tc.get("source") != "cloudflare":
                acc.skip("tunnelregel", "lokaal beheerde tunnel: haal de regel zelf uit config.yml")
                continue
            for r in tc["config"].get("ingress") or []:
                if _norm(r.get("hostname")) != fqdn:
                    continue
                if _svc_host(r.get("service")) in npm_hosts:
                    acc.ops.append(op_cf_ingress_del(cf, account, t, fqdn, r["service"]))
                else:
                    acc.skip("tunnelregel", f"regel naar {r.get('service')} gaat niet naar NPM: pas die zelf aan")
    else:
        acc.check("Cloudflare", None, "geen Cloudflare DNS-API: records niet nagekeken")

    # AdGuard.
    if sysm.adguard:
        try:
            for r in await sysm.adguard.integ.rewrites():
                if r["domain"] == fqdn:
                    acc.ops.append(op_lan_dns_del(sysm.adguard, fqdn, r["answer"]))
        except IntegrationError as e:
            acc.skip("naam in AdGuard", f"AdGuard: {mask(str(e))[:200]}")

    # Tegels.
    gone_tiles = [t for t in snap.tiles if t["host"] == fqdn]
    for t in gone_tiles:
        acc.ops.append(op_tile_del(t["id"], t["name"], fqdn, who))

    # De back-up: alleen op vraag, en alleen als niets anders dat IP nog gebruikt.
    if body.backup:
        ips = {str(h.get("forward_host")) for h in gone_hosts}
        gone_ids = {int(h["id"]) for h in gone_hosts}
        for ip in sorted(ips):
            still = [h for h in hosts or [] if str(h.get("forward_host")) == ip and int(h.get("id") or 0) not in gone_ids]
            tiles = [t for t in snap.tiles if t["host"] == ip]
            if still or tiles:
                acc.skip("back-up", f"{ip} wordt nog gebruikt (host #{still[0].get('id')})" if still
                         else f"{ip} heeft nog een tegel ({tiles[0]['name']})")
                continue
            guest, gerr = await find_guest(db, clients, snap, ip)
            if guest is None:
                acc.skip("back-up", gerr or f"geen CT/VM met IP {ip}")
                continue
            await _plan_backup_del(acc, sysm, guest)
    else:
        acc.skip("back-up", "niet gevraagd (één CT draait vaak meer dan één service)")
    p = acc.plan(f"Opruimen van {fqdn}", ORDER_CLEANUP, fqdn=fqdn)
    p.services = [t["id"] for t in gone_tiles]
    return p


async def _plan_backup_del(acc: _Acc, sysm: Systems, guest: dict, note: str | None = None) -> None:
    px = sysm.pve_ref(guest["pve"])
    vmid, kind = int(guest["vmid"]), guest["type"]
    what = _guest_label(kind, vmid)
    try:
        jobs = await px.integ.backup_jobs()
    except IntegrationError as e:
        acc.skip("back-up", f"Proxmox: {mask(str(e))[:200]}")
        return
    g = {"node": guest.get("node"), "vmid": vmid, "pool": guest.get("pool")}
    found = False
    for j in jobs:
        if not coverage.covers(j, g):
            continue
        found = True
        if coverage._on(j.get("all", 0)):
            acc.skip("back-up", f"back-upjob {j.get('id')} neemt alles: {what} blijft erin")
            continue
        if j.get("pool"):
            need = [("Pool.Allocate", f"/pool/{j['pool']}"), ("VM.Allocate", f"/vms/{vmid}")]
        else:
            need = [("Sys.Modify", "/"), ("Datastore.Allocate", f"/storage/{j.get('storage')}")]
            rest = [i for i in _ids(j.get("vmid")) if i != vmid]
            if not rest:
                acc.skip("back-up", f"back-upjob {j.get('id')} zou leeg worden: haal hem zelf weg in Proxmox")
                continue
        try:
            missing = [f"{p} op {path}" for p, path in need if p not in await px.integ.privs_at(path)]
        except IntegrationError as e:
            acc.skip("back-up", f"rechten niet op te vragen: {mask(str(e))[:120]}")
            continue
        if missing:
            acc.skip("back-up", f"het actietoken mist {', '.join(missing)}")
            continue
        if j.get("pool"):
            acc.ops.append(op_backup_pool_del(px, j["pool"], vmid, kind, note))
        else:
            acc.ops.append(op_backup_job_del(px, j.get("id"), vmid, kind, rest, note))
        return
    if not found:
        acc.skip("back-up", f"{what} zit in geen back-upjob")


# --- ongedaan maken ---------------------------------------------------------------------------------------------------

async def plan_undo(db: AsyncSession, clients, run: dict, *, who: str = "") -> Plan:
    """Weghalen wat deze run maakte, met de strenge controles (zelfde inhoud, zelfde doel). Een stap waarvan de
    uitkomst onbekend is, zoekt het object op zijn naam op: gevonden, dan mee weg."""
    snap = await gather(db, clients)
    sysm = snap.sysm
    acc = _Acc()
    fqdn = run.get("fqdn")
    created = list(run.get("created") or [])
    for s in run.get("steps") or []:
        spec = s.get("spec")
        if s.get("status") not in ("fout", "onbekend") or not spec:
            continue
        if any(c.get("kind") == spec.get("kind") for c in created):
            continue
        try:
            found = await find_created(sysm, spec)
        except IntegrationError as e:
            acc.skip(s.get("title") or spec["kind"], f"niet na te gaan: {mask(str(e))[:200]}")
            continue
        if found:
            created.append({**found, "note": f"uitkomst van stap {s['nr']} onbekend: gevonden, dus mee weg"})
    for c in created:
        kind, note = c.get("kind"), c.get("note")
        if kind == "npm_host" and sysm.npm:
            acc.ops.append(op_npm_host_del(sysm.npm, int(c["id"]), fqdn, expect=c.get("forward"), note=note))
        elif kind == "npm_cert" and sysm.npm:
            acc.ops.append(op_npm_cert_del(sysm.npm, int(c["id"]), fqdn, note=note))
        elif kind == "cf_record" and sysm.cf:
            acc.ops.append(op_cf_record_del(sysm.cf, c["zone"], c, fqdn, set(), expect=c["content"], note=note))
        elif kind == "cf_ingress" and sysm.cf:
            acc.ops.append(op_cf_ingress_del(sysm.cf, c["account"], c["tunnel"], c["hostname"], c["service"], note=note))
        elif kind == "lan_dns" and sysm.adguard:
            acc.ops.append(op_lan_dns_del(sysm.adguard, c["domain"], c["answer"], note=note))
        elif kind == "tile":
            acc.ops.append(op_tile_del(int(c["id"]), c["name"], fqdn, who, note=note))
        elif kind == "backup" and (px := sysm.pve_ref(c["pve"])):
            if c["how"] == "pool":
                acc.ops.append(op_backup_pool_del(px, c["pool"], int(c["vmid"]), c.get("type"), note))
            else:
                try:
                    j = next((j for j in await px.integ.backup_jobs() if j.get("id") == c["job"]), None)
                except IntegrationError as e:
                    acc.skip(c.get("label") or "back-up", f"Proxmox: {mask(str(e))[:200]}")
                    continue
                rest = [i for i in _ids((j or {}).get("vmid")) if i != int(c["vmid"])]
                if j is None or not rest:
                    acc.skip(c.get("label") or "back-up", "back-upjob weg of zou leeg worden: zelf nakijken in Proxmox")
                    continue
                acc.ops.append(op_backup_job_del(px, c["job"], int(c["vmid"]), c.get("type"), rest, note))
        else:
            acc.skip(c.get("label") or str(kind), "de API daarvoor staat niet meer in API-beheer")
    if not created:
        acc.check("wat deze run maakte", None, "niets gevonden")
    p = acc.plan(f"Ongedaan maken: {fqdn}", ORDER_CLEANUP, fqdn=fqdn)
    p.services = [int(c["id"]) for c in created if c.get("kind") == "tile"]
    return p


# --- records zonder host --------------------------------------------------------------------------------------------

async def orphans(db: AsyncSession, clients) -> dict:
    """Records die dit dashboard maakte (met zijn commentaar) en waarvan NPM de naam niet meer kent, bv. na een host
    die met de hand in NPM verwijderd is. Alleen op vraag (het tabblad opruimen), geen worker."""
    snap = await gather(db, clients)
    sysm = snap.sysm
    if sysm.cf is None:
        return {"items": [], "error": None}
    if sysm.npm is None:
        return {"items": [], "error": "Geen NPM-API: niet na te gaan"}
    try:
        n = sysm.npm.integ
        hosts = routes.build_hosts(await n.proxy_hosts(write=True), None, 0, None,
                                   [(await n.redirection_hosts(write=True), ""), (await n.dead_hosts(write=True), "")])
    except IntegrationError as e:
        return {"items": [], "error": f"NPM: {mask(str(e))[:200]}"}
    try:
        records = await sysm.cf.integ.records()
    except IntegrationError as e:
        return {"items": [], "error": f"Cloudflare: {mask(str(e))[:200]}"}
    table = routes.Table({"hosts": hosts})
    items = [{"name": _norm(r["name"]), "type": r["type"], "content": r["content"]} for r in records
             if r.get("comment") == COMMENT and table.entry(r["name"]) is None]
    return {"items": sorted(items, key=lambda i: i["name"]), "error": None}


# --- wat het formulier nodig heeft ------------------------------------------------------------------------------------

OPTIONS_TTL = 60
OPTION_KINDS = ("npm", "cloudflare", "adguard", "proxmox")
# {"key": ..., "at": monotonic, "value": {...}}: het venster gaat vaak open; welke run loopt, rekent de router live.
_options: dict = {}


async def options_key(db: AsyncSession) -> str:
    """Verandert als een API van een van deze soorten (of een tegel ervan) verandert."""
    apis = (await db.execute(select(ApiConnection.id, ApiConnection.updated_at)
                             .where(ApiConnection.kind.in_(OPTION_KINDS)).order_by(ApiConnection.id))).all()
    tiles = (await db.execute(select(Service.id, Service.api_id).where(Service.type.in_(OPTION_KINDS))
                              .order_by(Service.id))).all()
    return json.dumps([[[str(x) for x in r] for r in apis], [[str(x) for x in r] for r in tiles]])


async def options(db: AsyncSession, clients) -> dict:
    """Systemen, domein, certificaten, toegangslijsten en back-upjobs voor het formulier. Leest alleen, en nooit een
    geheim: geen meta van een certificaat, geen token, alleen namen en nummers."""
    snap = await gather(db, clients)
    sysm = snap.sysm
    notes = list(sysm.notes)
    systems: dict = {"npm": None, "cloudflare": None, "adguard": None,
                     "proxmox": [{"label": p.label} for p in sysm.pve], "zabbix": bool(snap.zabbix)}
    out = {"domain": None, "npm_version": None, "systems": systems, "pattern": "onbekend", "certs": [],
           "access_lists": [], "protected_hosts": [], "jobs": [],
           "zabbix_hosts": sorted(({"host": str(h.get("host") or ""), "name": str(h.get("name") or h.get("host") or ""),
                                    "ips": [str(i) for i in h.get("ips") or []]} for h in snap.zabbix if h.get("host")),
                                  key=lambda h: h["name"].lower()),
           "notes": notes}
    certs, names = None, set()
    if sysm.npm:
        n = sysm.npm.integ
        systems["npm"] = {"label": sysm.npm.label, "write": n.user(True), "split": n.split, "sees_all": None}
        try:
            hosts = await n.proxy_hosts(write=True)
            other = [*await n.redirection_hosts(write=True), *await n.dead_hosts(write=True)]
            certs = await n.certificates(write=True)
            acls = await n.access_lists(write=True)
            me = await n.me(True)
        except IntegrationError as e:
            notes.append(f"NPM: {mask(str(e))[:200]}")
        else:
            systems["npm"]["sees_all"] = ("admin" in (me.get("roles") or [])
                                          or (me.get("permissions") or {}).get("visibility") == "all")
            version = await n.version()
            out["npm_version"] = ".".join(map(str, version)) if version else None
            names = {x for h in [*hosts, *other] for x in routes._names(h)}
            for c in certs:
                if not c.get("id"):
                    continue
                days = npmm.days_left(c.get("expires_on"))
                out["certs"].append({"id": int(c["id"]), "name": c.get("nice_name") or ", ".join(c.get("domain_names") or []),
                                     "wildcard": any(str(d).startswith("*.") for d in c.get("domain_names") or []),
                                     "days": round(days) if days is not None else None})
            for a in acls:
                if a.get("id"):
                    ok, why = npmm.lan_only(a)
                    out["access_lists"].append({"id": int(a["id"]), "name": str(a.get("name") or ""), "lan_only": ok,
                                                "why": why})
            out["protected_hosts"] = [{"id": int(h["id"]), "name": (routes._names(h) or ["?"])[0]} for h in hosts
                                      if h.get("id") and (int(h.get("access_list_id") or 0)
                                                          or LOGIN_RE.search(str(h.get("advanced_config") or "")))]
    zone, where = zone_of(sysm, certs)
    out["domain"] = zone
    if zone is None:
        notes.append(where)
    if sysm.cf:
        c = sysm.cf.integ
        systems["cloudflare"] = {"label": sysm.cf.label, "zone": c.zone,
                                 "tunnel_account": bool(cfm.ACCOUNT_RE.match(c.account))}
        if zone:
            try:
                out["pattern"] = pattern_of(await c.records(), names, zone).kind
            except IntegrationError as e:
                notes.append(f"Cloudflare: {mask(str(e))[:200]}")
    if sysm.adguard:
        systems["adguard"] = {"label": sysm.adguard.label}
    for p in sysm.pve:
        try:
            jobs = await p.integ.backup_jobs()
            stores = {s.get("storage"): s.get("type") for s in await p.integ.storages()}
        except IntegrationError as e:
            notes.append(f"Proxmox ({p.label}): {mask(str(e))[:200]}")
            continue
        for j in jobs:
            if not j.get("id"):
                continue
            label = f"{j['id']} → {j.get('storage')}" + (f", pool {j['pool']}" if j.get("pool") else "")
            label += ", alles" if coverage._on(j.get("all", 0)) else ""
            label += f", {j['schedule']}" if j.get("schedule") else ""
            out["jobs"].append({"id": str(j["id"]), "label": label, "pool": j.get("pool") or None,
                                "pbs": stores.get(j.get("storage")) == "pbs" and not j.get("dumpdir")
                                and not coverage._on(j.get("all", 0)) and coverage._on(j.get("enabled", 1))})
    return out


# --- runs -------------------------------------------------------------------------------------------------------------

RUN_FIELDS = ("id", "kind", "of", "fqdn", "by", "at", "updated_at", "status", "warning", "input", "hash", "created",
              "removed", "error", "undone_by")


def _interrupt(r: dict) -> None:
    r["status"] = "onderbroken"
    for s in r.get("steps") or []:
        if s.get("status") == "bezig":
            s["status"] = "onbekend"
    r["error"] = r.get("error") or "onderbroken: de homepage herstartte tijdens de run"


def effective(run: dict) -> dict:
    """De run zoals hij nu is: "bezig" zonder taak in dit proces liep tijdens een herstart."""
    r = copy.deepcopy(run)
    if r.get("status") == "bezig" and r.get("id") not in _running:
        _interrupt(r)
    r["can_undo"] = (r.get("kind") == "maken" and r.get("status") in ("gestopt", "onderbroken")
                     and not r.get("undone_by"))
    return r


def run_out(run: dict, calls: bool = True) -> dict:
    r = effective(run)
    steps = [{k: v for k, v in s.items() if k != "spec" and (calls or k != "call")} for s in r.get("steps") or []]
    return {**{k: r.get(k) for k in RUN_FIELDS}, "steps": steps, "can_undo": r["can_undo"]}


def runs_of(value: dict | None) -> list[dict]:
    return [r for r in (value or {}).get("runs") or [] if isinstance(r, dict)]


def busy(value: dict | None) -> dict | None:
    """De run die nu echt loopt (in dit proces), of None. Telkens opnieuw berekend."""
    return next((r for r in runs_of(value) if r.get("status") == "bezig" and r.get("id") in _running), None)


async def start(db: AsyncSession, kind: str, plan: Plan, body: dict, user: User, of: str | None = None) -> dict:
    """De run bewaren met alle stappen op "wacht". De aanroeper houdt _lock vast en commit."""
    now = datetime.now(timezone.utc)
    run = {"id": f"ns-{now:%Y%m%d-%H%M%S}-{secrets.token_hex(2)}", "kind": kind, "of": of, "fqdn": plan.plan.get("fqdn"),
           "by": user.username, "at": _now(), "updated_at": _now(), "status": "bezig", "warning": None, "input": body,
           "hash": plan.hash,
           "steps": [{"nr": i, "key": o.key, "title": o.title, "call": o.proef.get("call"), "status": "wacht",
                      "detail": None, "started_at": None, "finished_at": None, "fatal": o.fatal, "spec": o.spec}
                     for i, o in enumerate(plan.ops, 1)],
           "created": [], "removed": [], "error": None, "undone_by": None}
    st = await ensure_state(db, STATE_KEY, {"runs": []})
    runs = [run, *runs_of(st.value)]
    keep = runs[:KEEP_RUNS] + [r for r in runs[KEEP_RUNS:] if r.get("status") == "bezig"]
    st.value = {**(st.value or {}), "runs": keep}
    _running.add(run["id"])
    return run


async def _save(maker, run_id: str, fn) -> dict | None:
    """De run aanpassen in een eigen korte sessie (fn(run, runs, db)) en meteen bewaren."""
    async with maker() as db:
        st = await ensure_state(db, STATE_KEY, {"runs": []})
        value = copy.deepcopy(st.value or {})
        runs = runs_of(value)
        run = next((r for r in runs if r.get("id") == run_id), None)
        if run is None:
            return None
        fn(run, runs, db)
        run["updated_at"] = _now()
        st.value = {**value, "runs": runs}
        await db.commit()
        return run


def _step(run: dict, nr: int, **kw) -> None:
    for s in run["steps"]:
        if s["nr"] == nr:
            s.update(kw)


def _labels(items: list[dict]) -> str:
    return ", ".join(i.get("label") or i.get("kind") or "?" for i in items) or "niets"


def _finish_notify(db: AsyncSession, run: dict) -> None:
    fqdn, kind = run.get("fqdn"), run.get("kind")
    tile = next((c.get("id") for c in run.get("created") or [] if c.get("kind") == "tile"), None)
    if run["status"] == "gestopt":
        nr = next((s for s in run["steps"] if s["status"] == "fout"), {"nr": "?", "title": "?"})
        made = (f" Al gemaakt: {_labels(run['created'])}. Ongedaan maken: Beheer → Nieuwe service → geschiedenis."
                if kind == "maken" else f" Al verwijderd: {_labels(run['removed'])}.")
        what = {"maken": "Nieuwe service", "opruimen": "Opruimen van", "ongedaan": "Ongedaan maken van"}[kind]
        notify(db, f"{what} {fqdn} gestopt", mask(f"Gestopt bij stap {nr['nr']} ({nr['title']}): {nr.get('detail')}."
                                                  + made), level="warn", source="nieuweservice",
               key=f"ns:{run['id']}", service_id=tile)
    elif kind == "maken":
        body = f"{_labels(run['created'])}."
        if run.get("warning"):
            body += f" Back-up niet ingesteld: {run['warning']}. hw → back-ups toont hem rood tot dat geregeld is."
        notify(db, f"Nieuwe service {fqdn} klaar", mask(body), level="warn" if run.get("warning") else "info",
               source="nieuweservice", service_id=tile, push=False)
    else:
        what = "Opgeruimd" if kind == "opruimen" else "Ongedaan gemaakt"
        body = f"Weg: {_labels(run['removed'])}." + (f" Let op: {run['warning']}." if run.get("warning") else "")
        notify(db, f"{what}: {fqdn}", mask(body), level="info", source="nieuweservice", push=False)


async def execute(maker, run_id: str, ops: list[Op], clients, user_id: int | None = None) -> None:
    """De stappen één na één. Stopt bij de eerste fout van een stap die telt; een fout van de back-up wordt een
    waarschuwing. Na een herstart of een crash wordt de run "onderbroken" en de lopende stap "onbekend"."""
    ctx = {"maker": maker, "clients": clients, "created": [], "removed": [], "user_id": user_id}
    done = False
    try:
        for nr, op in enumerate(ops, 1):
            await _save(maker, run_id, lambda r, runs, db, nr=nr: _step(r, nr, status="bezig", started_at=_now()))
            res, err = None, None
            try:
                res = await asyncio.wait_for(op.go(ctx), op.timeout)
            except (asyncio.TimeoutError, TimeoutError):
                err = f"geen antwoord binnen {op.timeout} s"
            except IntegrationError as e:
                err = mask(str(e))[:300]
            except Exception as e:  # noqa: BLE001 - een vreemd antwoord mag de run niet laten hangen
                log.warning("nieuwe service: stap %s mislukt", op.key, exc_info=True)
                err = f"onverwacht antwoord ({type(e).__name__})"
            if err is None:
                res = res or {}
                _add(ctx["created"], res.get("created"))
                if res.get("removed"):
                    ctx["removed"].append(res["removed"])

                def ok(r, runs, db, nr=nr, res=res):
                    _step(r, nr, status="overgeslagen" if res.get("skipped") else "ok",
                          detail=mask(str(res.get("detail") or ""))[:300], finished_at=_now())
                    r["created"], r["removed"] = list(ctx["created"]), list(ctx["removed"])
                await _save(maker, run_id, ok)
                continue
            if op.verify:
                try:
                    _add(ctx["created"], await asyncio.wait_for(op.verify(ctx), STEP_TIMEOUT))
                except Exception:  # noqa: BLE001 - nakijken is extra; de stap is hoe dan ook mislukt
                    pass

            def failed(r, runs, db, nr=nr, op=op, err=err):
                _step(r, nr, status="fout", detail=err, finished_at=_now())
                r["created"], r["removed"] = list(ctx["created"]), list(ctx["removed"])
                if op.fatal:
                    r["status"] = "gestopt"
                    r["error"] = f"stap {nr} ({op.title}): {err}"
                    _finish_notify(db, r)
                else:
                    r["warning"] = err if op.key == "backup" else f"{op.title}: {err}"
            await _save(maker, run_id, failed)
            if op.fatal:
                done = True
                return

        def finish(r, runs, db):
            r["status"] = "klaar"
            r["created"], r["removed"] = list(ctx["created"]), list(ctx["removed"])
            if r.get("kind") == "ongedaan" and (orig := next((x for x in runs if x.get("id") == r.get("of")), None)):
                orig["status"], orig["undone_by"] = "ongedaan", r["id"]
            _finish_notify(db, r)
        await _save(maker, run_id, finish)
        done = True
    finally:
        if not done:
            def broken(r, runs, db):
                _interrupt(r)
                r["created"], r["removed"] = list(ctx["created"]), list(ctx["removed"])
            try:
                await _save(maker, run_id, broken)
            except Exception:  # noqa: BLE001 - effective() toont hem dan toch als onderbroken
                log.warning("nieuwe service: run %s niet als onderbroken bewaard", run_id, exc_info=True)
        _running.discard(run_id)


async def mark_interrupted(db: AsyncSession) -> int:
    """Bij het opstarten: runs die "bezig" bewaard staan, kan niemand meer afmaken."""
    st = await db.get(AppState, STATE_KEY)
    if st is None:
        return 0
    value = copy.deepcopy(st.value or {})
    n = 0
    for r in runs_of(value):
        if r.get("status") == "bezig":
            _interrupt(r)
            n += 1
    if n:
        st.value = value
    return n
