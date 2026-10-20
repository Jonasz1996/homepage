"""Hersteltest van back-ups: één keer per maand een CT uit PBS terugzetten op een vrij ID, zonder netwerk, kijken of
hij opstart en blijft draaien, en hem daarna weer weggooien. Zo weet je dat de back-ups ook echt terug te zetten zijn.

Alles via de Proxmox-API van een Proxmox-tegel; de PBS-datastore moet in Proxmox als opslag (type pbs) gekoppeld zijn.
Staat standaard uit: aanzetten in het mini dashboard van een PBS-tegel (of Ctrl+K → hersteltest).
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..db import ensure_state
from ..deps import notify
from ..integrations import IntegrationError, build
from ..models import Service
from .checks import HttpClients
from .upgrade import wait_task

log = logging.getLogger("homepage.restoretest")

STATE_KEY = "restoretest"
MARKER = "homepage-hersteltest"
DEFAULTS = {"enabled": False, "service_id": None, "node": "", "pbs": "", "storage": "", "day": 1, "hour": 5,
            "vmid_from": 9900, "only": []}
KEEP = 24
BOOT_WAIT = 30  # zo lang moet de CT na het starten blijven draaien
STALE = timedelta(hours=2)  # een run die zo lang "bezig" is, is onderbroken (herstart van de worker)
_NET = re.compile(r"^net\d+$")


def settings(value: dict | None) -> dict:
    return {**DEFAULTS, **((value or {}).get("settings") or {})}


def slot(cfg: dict, now: datetime) -> datetime:
    """Het moment van de test deze maand (lokale tijd)."""
    local = now.astimezone()
    return local.replace(day=min(max(int(cfg["day"]), 1), 28), hour=int(cfg["hour"]), minute=0, second=0,
                         microsecond=0)


def due(value: dict | None, now: datetime) -> bool:
    cfg = settings(value)
    busy = (value or {}).get("running")
    if not cfg["enabled"] or (busy and now - datetime.fromisoformat(busy["at"]) < STALE):
        return False
    s = slot(cfg, now)
    last = (value or {}).get("last_at")
    return now >= s and (not last or datetime.fromisoformat(last) < s)


def next_run(value: dict | None, now: datetime) -> datetime | None:
    cfg = settings(value)
    if not cfg["enabled"]:
        return None
    s = slot(cfg, now)
    last = (value or {}).get("last_at")
    if now < s or not last or datetime.fromisoformat(last) < s:
        return s
    local = s.replace(day=1) + timedelta(days=32)
    return slot(cfg, local.replace(day=1))


async def _call(px, method: str, path: str, **kw):
    data = await px.request(method, "/api2/json" + path, headers=px.headers(write=method != "GET"), **kw)
    return (data or {}).get("data")


async def options(px) -> dict:
    """Wat er te kiezen valt: nodes, PBS-opslag en doelopslag per node, en de CT's met een back-up."""
    res = await px.resources()
    nodes = sorted(r["node"] for r in res if r.get("type") == "node" and r.get("status") == "online")
    stores = await px.get("/storage")
    pbs = sorted(s["storage"] for s in stores if s.get("type") == "pbs")
    targets = {}
    for n in nodes:
        try:
            targets[n] = sorted(s["storage"] for s in await px.get(f"/nodes/{n}/storage?content=rootdir&enabled=1"))
        except IntegrationError:
            targets[n] = []
    return {"nodes": nodes, "pbs": pbs, "targets": targets,
            "guests": sorted(({"vmid": r["vmid"], "name": r.get("name")} for r in res if r.get("type") == "lxc"
                              and not r.get("template")), key=lambda g: g["vmid"])}


async def backups(px, node: str, pbs: str) -> dict[int, dict]:
    """Laatste CT-back-up per vmid op de PBS-opslag."""
    out: dict[int, dict] = {}
    for b in await px.get(f"/nodes/{node}/storage/{quote(pbs)}/content?content=backup"):
        if b.get("subtype") != "lxc" and "/ct/" not in str(b.get("volid")):
            continue
        vmid = int(b.get("vmid") or 0)
        if vmid and (vmid not in out or (b.get("ctime") or 0) > (out[vmid].get("ctime") or 0)):
            out[vmid] = b
    return out


def choose(found: dict[int, dict], cfg: dict, history: list[dict]) -> dict | None:
    """De CT die het langst niet getest is (nooit getest gaat voor), bij gelijkspel het laagste vmid."""
    only = {int(x) for x in cfg.get("only") or []}
    cands = [v for v in found if not only or v in only]
    if not cands:
        return None
    last = {}
    for h in reversed(history):
        if h.get("source_vmid"):
            last[h["source_vmid"]] = h["at"]
    vmid = min(cands, key=lambda v: (last.get(v, ""), v))
    return found[vmid]


async def free_vmid(px, start: int) -> int:
    used = {int(r["vmid"]) for r in await px.resources() if r.get("vmid") is not None}
    for v in range(start, start + 200):
        if v not in used:
            return v
    raise IntegrationError(f"Geen vrij ID gevonden vanaf {start}")


async def _remove(px, node: str, vmid: int, need_marker: bool) -> None:
    """Stoppen en weggooien, maar alleen de test-CT zelf."""
    conf = await _call(px, "GET", f"/nodes/{node}/lxc/{vmid}/config") or {}
    if need_marker and MARKER not in str(conf.get("description") or ""):
        raise IntegrationError(f"CT {vmid} is geen test-CT van de homepage; niet verwijderd")
    cur = await _call(px, "GET", f"/nodes/{node}/lxc/{vmid}/status/current") or {}
    if cur.get("status") == "running":
        await wait_task(px, node, await _call(px, "POST", f"/nodes/{node}/lxc/{vmid}/status/stop"), timeout=180)
    upid = await _call(px, "DELETE", f"/nodes/{node}/lxc/{vmid}?purge=1&destroy-unreferenced-disks=1")
    await wait_task(px, node, upid, timeout=600)


async def _save(maker: async_sessionmaker, **changes) -> dict:
    async with maker() as db:
        st = await ensure_state(db, STATE_KEY, {})
        value = {**(st.value or {}), **changes}
        st.value = value
        await db.commit()
        return value


async def run(maker: async_sessionmaker, http: HttpClients, manual: bool = False) -> dict:
    """Eén hersteltest. Geeft het resultaat terug (ook bij een fout)."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    async with maker() as db:
        st = await ensure_state(db, STATE_KEY, {})
        value = dict(st.value or {})
        busy = value.get("running")
        if busy and now - datetime.fromisoformat(busy["at"]) < STALE:
            return {"ok": False, "error": "Er loopt al een hersteltest"}
        cfg = settings(value)
        svc = await db.get(Service, cfg["service_id"]) if cfg["service_id"] else None
        if svc is None or svc.type != "proxmox":
            svc = (await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars().first()
        history = list(value.get("history") or [])
        value["running"] = {"at": now.isoformat(), "step": "back-up zoeken"}
        st.value = value
        await db.commit()
    stale = busy  # een onderbroken test van vroeger: die CT eerst opruimen

    result = {"at": now.isoformat(), "ok": False, "manual": manual, "step": "back-up zoeken"}
    node = vmid = None
    created = False
    started = asyncio.get_running_loop().time()

    async def step(name: str, record: bool = True) -> None:
        if record:  # opruimen na een fout: de stap waarop het misliep blijft in het resultaat
            result["step"] = name
        await _save(maker, running={"at": now.isoformat(), "step": name, "vmid": vmid, "node": node,
                                    "source_vmid": result.get("source_vmid")})

    try:
        if svc is None:
            raise IntegrationError("Geen Proxmox-tegel gevonden")
        px = build(svc, http)
        if stale and stale.get("vmid") and stale.get("node"):
            try:
                await _remove(px, stale["node"], int(stale["vmid"]), need_marker=True)
            except IntegrationError as e:
                log.warning("Oude test-CT %s niet opgeruimd: %s", stale.get("vmid"), e)
        opts = await options(px)
        node = cfg["node"] if cfg["node"] in opts["nodes"] else (opts["nodes"] or [None])[0]
        pbs = cfg["pbs"] if cfg["pbs"] in opts["pbs"] else (opts["pbs"] or [None])[0]
        if not node:
            raise IntegrationError("Geen Proxmox-node online")
        if not pbs:
            raise IntegrationError("Geen PBS-opslag gekoppeld in Proxmox (Datacenter → Storage → Add → Proxmox Backup Server)")
        backup = choose(await backups(px, node, pbs), cfg, history)
        if backup is None:
            raise IntegrationError(f"Geen CT-back-ups gevonden op {pbs}")
        src = int(backup["vmid"])
        names = {g["vmid"]: g["name"] for g in opts["guests"]}
        result.update(source_vmid=src, name=names.get(src) or f"CT {src}", volid=backup["volid"], node=node,
                      backup_at=datetime.fromtimestamp(backup.get("ctime") or 0, timezone.utc).isoformat(),
                      size=backup.get("size"))
        vmid = await free_vmid(px, int(cfg["vmid_from"]))
        result["vmid"] = vmid
        await step("terugzetten")
        data = {"vmid": vmid, "ostemplate": backup["volid"], "restore": 1, "unique": 1, "start": 0,
                "hostname": f"hersteltest-{src}", "description": f"{MARKER}: kopie van CT {src}, wordt zo weer verwijderd"}
        if cfg["storage"]:
            data["storage"] = cfg["storage"]
        upid = await _call(px, "POST", f"/nodes/{node}/lxc", data=data)
        created = True
        await wait_task(px, node, upid, timeout=3600)
        result["restore_seconds"] = round(asyncio.get_running_loop().time() - started)

        await step("netwerk loskoppelen")
        conf = await _call(px, "GET", f"/nodes/{node}/lxc/{vmid}/config") or {}
        change = {"onboot": 0}
        nets = sorted(k for k in conf if _NET.match(k))
        if nets:
            change["delete"] = ",".join(nets)
        await _call(px, "PUT", f"/nodes/{node}/lxc/{vmid}/config", data=change)

        await step("opstarten")
        await wait_task(px, node, await _call(px, "POST", f"/nodes/{node}/lxc/{vmid}/status/start"), timeout=180)
        await asyncio.sleep(BOOT_WAIT)
        cur = await _call(px, "GET", f"/nodes/{node}/lxc/{vmid}/status/current") or {}
        if cur.get("status") != "running":
            raise IntegrationError(f"De CT startte, maar draait na {BOOT_WAIT} s niet meer ({cur.get('status')})")
        result["ok"] = True
        result["step"] = "klaar"
    except IntegrationError as e:
        result["error"] = str(e)
    except Exception as e:  # noqa: BLE001 - het resultaat moet altijd bewaard worden
        log.exception("hersteltest")
        result["error"] = f"Onverwachte fout: {type(e).__name__}"
    finally:
        if created:
            try:
                await step("opruimen", record=False)
                await _remove(px, node, vmid, need_marker=True)
            except Exception as e:  # noqa: BLE001
                result["cleanup_error"] = str(e)
        result["seconds"] = round(asyncio.get_running_loop().time() - started)
        history = [result, *history][:KEEP]
        await _save(maker, running=None, last_at=now.isoformat(), history=history)
        async with maker() as db:
            _report(db, result, svc.id if svc else None)
            await db.commit()
    return result


def _report(db: AsyncSession, r: dict, service_id: int | None) -> None:
    what = f"{r.get('name') or 'CT'} ({r.get('source_vmid') or '?'})"
    if r["ok"]:
        body = f"Back-up van {r['backup_at'][:16].replace('T', ' ')} teruggezet als CT {r['vmid']} op {r['node']}, " \
               f"opgestart en weer verwijderd ({r['seconds']} s)."
        notify(db, f"Hersteltest geslaagd: {what}", body, level="ok", source="backup", service_id=service_id)
    else:
        notify(db, f"Hersteltest mislukt: {what}", f"Bij {r['step']}: {r.get('error')}", level="err", source="backup",
               service_id=service_id)
    if r.get("cleanup_error"):
        notify(db, f"Test-CT {r.get('vmid')} niet opgeruimd", f"{r['cleanup_error']}. Verwijder hem zelf in Proxmox.",
               level="warn", source="backup", service_id=service_id)
