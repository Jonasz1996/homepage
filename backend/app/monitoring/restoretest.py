"""Hersteltest van back-ups: één keer per maand een CT uit PBS terugzetten op een vrij ID, zonder netwerk, kijken of
hij opstart en blijft draaien, en hem daarna weer weggooien. Zo weet je dat de back-ups ook echt terug te zetten zijn.

Alles via de Proxmox-API van een Proxmox-tegel; de PBS-datastore moet in Proxmox als opslag (type pbs) gekoppeld zijn.
Staat standaard uit: aanzetten in het mini dashboard van een PBS-tegel (of Ctrl+K → hersteltest).

Proef: plan() doet dezelfde keuzes als run() (node, PBS-opslag, welke back-up, vrij ID) en toont de calls die run()
daarna zou doen, gebouwd met dezelfde functies (restore_call, detach_call, ...). Met "alleen proef" aan maakt de
maandelijkse run alleen zo'n plan: op de tijdlijn en in dry_history, nooit in de geschiedenis.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .. import proef
from ..db import ensure_state
from ..deps import notify
from ..integrations import IntegrationError, build
from ..models import Service
from .checks import HttpClients
from .upgrade import wait_task

log = logging.getLogger("homepage.restoretest")

STATE_KEY = "restoretest"
MARKER = "homepage-hersteltest"
# dry: alleen proef, de maandelijkse run toont alleen wat hij zou doen.
DEFAULTS = {"enabled": False, "service_id": None, "node": "", "pbs": "", "storage": "", "day": 1, "hour": 5,
            "vmid_from": 9900, "only": [], "dry": False}
KEEP = 24
BOOT_WAIT = 30  # zo lang moet de CT na het starten blijven draaien
STALE = timedelta(hours=2)  # een run die zo lang "bezig" is, is onderbroken (herstart van de worker)
# Hoe lang op elke Proxmox-taak gewacht wordt (seconden).
RESTORE_WAIT, START_WAIT, STOP_WAIT, DELETE_WAIT = 3600, 180, 180, 600
_NET = re.compile(r"^net\d+$")
# Wat het dashboard nodig heeft op het actietoken (zie setupcheck: RESTORE_PRIVS plus aan- en uitzetten).
POWER_PRIVS = ("VM.PowerMgmt",)
PURGE_NOTE = "purge=1 haalt het ID ook uit back-up-, replicatie- en HA-jobs"


def settings(value: dict | None) -> dict:
    return {**DEFAULTS, **((value or {}).get("settings") or {})}


def slot(cfg: dict, now: datetime) -> datetime:
    """Het moment van de test deze maand (lokale tijd)."""
    local = now.astimezone()
    return local.replace(day=min(max(int(cfg["day"]), 1), 28), hour=int(cfg["hour"]), minute=0, second=0,
                         microsecond=0)


def is_busy(value: dict | None, now: datetime) -> bool:
    """Loopt er een test die niet onderbroken is? Dan weigeren run(), ▶ nu testen en de proef."""
    busy = (value or {}).get("running")
    return bool(busy) and now - datetime.fromisoformat(busy["at"]) < STALE


def due(value: dict | None, now: datetime) -> bool:
    cfg = settings(value)
    if not cfg["enabled"] or is_busy(value, now):
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


def _tested(history: list[dict]) -> dict[int, str]:
    """Per CT wanneer hij het laatst getest is."""
    last = {}
    for h in reversed(history):
        if h.get("source_vmid"):
            last[h["source_vmid"]] = h["at"]
    return last


def choose(found: dict[int, dict], cfg: dict, history: list[dict]) -> dict | None:
    """De CT die het langst niet getest is (nooit getest gaat voor), bij gelijkspel het laagste vmid."""
    only = {int(x) for x in cfg.get("only") or []}
    cands = [v for v in found if not only or v in only]
    if not cands:
        return None
    last = _tested(history)
    vmid = min(cands, key=lambda v: (last.get(v, ""), v))
    return found[vmid]


async def free_vmid(px, start: int, gone: set[int] | frozenset = frozenset()) -> int:
    """Het eerste ID vanaf start dat de tegel niet kent. gone: wat de test eerst nog verwijdert (voor de proef; de
    echte test vraagt het pas na dat opruimen)."""
    used = {int(r["vmid"]) for r in await px.resources() if r.get("vmid") is not None} - set(gone)
    for v in range(start, start + 200):
        if v not in used:
            return v
    raise IntegrationError(f"Geen vrij ID gevonden vanaf {start}")


async def pick(px, cfg: dict, history: list[dict]) -> dict:
    """Node, PBS-opslag en back-up: dezelfde keuze voor de echte test en de proef. Leest alleen."""
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
    return {"node": node, "pbs": pbs, "backup": backup, "src": src, "name": names.get(src) or f"CT {src}"}


# --- wat iets verandert: één bouwer per call, voor de echte test én de proef ---------------------------------------

def restore_call(node: str, vmid: int, backup: dict, cfg: dict) -> tuple[str, str, dict]:
    src = int(backup["vmid"])
    data = {"vmid": vmid, "ostemplate": backup["volid"], "restore": 1, "unique": 1, "start": 0,
            "hostname": f"hersteltest-{src}", "description": f"{MARKER}: kopie van CT {src}, wordt zo weer verwijderd"}
    if cfg["storage"]:
        data["storage"] = cfg["storage"]
    return "POST", f"/nodes/{node}/lxc", data


def detach_call(node: str, vmid: int, conf: dict) -> tuple[str, str, dict]:
    """Niet mee opstarten met de node, en elke netwerkkaart van de kopie weg: zo komt hij nooit op het netwerk."""
    change = {"onboot": 0}
    nets = sorted(k for k in conf if _NET.match(k))
    if nets:
        change["delete"] = ",".join(nets)
    return "PUT", f"/nodes/{node}/lxc/{vmid}/config", change


def start_call(node: str, vmid: int) -> tuple[str, str, None]:
    return "POST", f"/nodes/{node}/lxc/{vmid}/status/start", None


def stop_call(node: str, vmid: int) -> tuple[str, str, None]:
    return "POST", f"/nodes/{node}/lxc/{vmid}/status/stop", None


def delete_call(node: str, vmid: int) -> tuple[str, str, None]:
    return "DELETE", f"/nodes/{node}/lxc/{vmid}?purge=1&destroy-unreferenced-disks=1", None


async def _do(px, call: tuple[str, str, dict | None]):
    method, path, data = call
    return await _call(px, method, path, **({} if data is None else {"data": data}))


async def _inspect(px, node: str, vmid: int, need_marker: bool) -> bool:
    """Wat _remove eerst leest: is het wel de test-CT (merkteken in de beschrijving), en draait hij?"""
    conf = await _call(px, "GET", f"/nodes/{node}/lxc/{vmid}/config") or {}
    if need_marker and MARKER not in str(conf.get("description") or ""):
        raise IntegrationError(f"CT {vmid} is geen test-CT van de homepage; niet verwijderd")
    cur = await _call(px, "GET", f"/nodes/{node}/lxc/{vmid}/status/current") or {}
    return cur.get("status") == "running"


async def _remove(px, node: str, vmid: int, need_marker: bool) -> None:
    """Stoppen en weggooien, maar alleen de test-CT zelf."""
    if await _inspect(px, node, vmid, need_marker):
        await wait_task(px, node, await _do(px, stop_call(node, vmid)), timeout=STOP_WAIT)
    await wait_task(px, node, await _do(px, delete_call(node, vmid)), timeout=DELETE_WAIT)


async def _save(maker: async_sessionmaker, **changes) -> dict:
    async with maker() as db:
        st = await ensure_state(db, STATE_KEY, {})
        value = {**(st.value or {}), **changes}
        st.value = value
        await db.commit()
        return value


async def service(db: AsyncSession, cfg: dict) -> Service | None:
    """De Proxmox-tegel van de test: de ingestelde, anders de eerste."""
    svc = await db.get(Service, cfg["service_id"]) if cfg["service_id"] else None
    if svc is None or svc.type != "proxmox":
        svc = (await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars().first()
    return svc


# --- proef -----------------------------------------------------------------------------------------------------------

def _px_step(machine: str, who: str, call: tuple[str, str, dict | None], **kw) -> dict:
    method, path, data = call
    return proef.step(machine, "proxmox-api", f"{method} /api2/json{path}", who=who, data=data, **kw)


def _remove_steps(machine: str, who: str, node: str, vmid: int, running: bool | None) -> list[dict]:
    """De calls van _remove. running None: nog niet te weten (de kopie bestaat pas tijdens de test)."""
    out = []
    if running is not False:
        out.append(_px_step(machine, who, stop_call(node, vmid), wait=f"Proxmox-taak, max {STOP_WAIT} s",
                            when=f"als CT {vmid} draait" if running is None else None))
    out.append(_px_step(machine, who, delete_call(node, vmid), wait=f"Proxmox-taak, max {DELETE_WAIT} s",
                        note=f"alleen als de beschrijving van CT {vmid} het merkteken {MARKER} heeft (vlak ervoor "
                             f"opnieuw gelezen); {PURGE_NOTE}"))
    return out


def _gb(n) -> str:
    return f"{n / 1e9:.1f} GB" if isinstance(n, (int, float)) else "?"


def _local(epoch) -> str:
    return datetime.fromtimestamp(epoch or 0, timezone.utc).astimezone().strftime("%d/%m/%Y %H:%M")


async def _nextid(px, vmid: int) -> dict:
    """free_vmid kijkt naar de tegel, en die kan op één node gefilterd zijn; Proxmox zelf kent de hele cluster."""
    what = f"ID {vmid} vrij in de hele cluster"
    try:
        await _call(px, "GET", f"/cluster/nextid?vmid={vmid}")
    except IntegrationError as e:
        # Bestaat het ID al, dan antwoordt Proxmox met 400 ("VM ... already exists").
        if "HTTP 400" in str(e):
            return proef.check(what, False, "Proxmox zegt dat het ID al bestaat: het terugzetten zou mislukken")
        return proef.check(what, None, f"niet na te gaan: {e}")
    return proef.check(what, True, "volgens Proxmox (/cluster/nextid)")


async def _space(px, node: str, cfg: dict, backup: dict) -> dict:
    if not cfg["storage"]:
        return proef.check("vrije ruimte", None, "terugzetten op de opslag uit de back-up: welke dat is, staat pas in "
                           "de back-up zelf")
    what = f"vrije ruimte op {cfg['storage']} ({node})"
    try:
        st = await _call(px, "GET", f"/nodes/{node}/storage/{quote(cfg['storage'])}/status") or {}
    except IntegrationError as e:
        return proef.check(what, None, f"niet na te gaan: {e}")
    avail, size = st.get("avail"), backup.get("size")
    if not isinstance(avail, (int, float)) or not isinstance(size, (int, float)):
        return proef.check(what, None, f"vrij {_gb(avail)}, back-up {_gb(size)}")
    return proef.check(what, avail >= size, f"vrij {_gb(avail)}, back-up {_gb(size)} (ongecomprimeerd)")


async def _rights(svc: Service, http) -> dict:
    """Dezelfde rechtencheck als de instellingen-checklist, op een eigen integratie: _privs zet er het actietoken in."""
    from ..setupcheck import RESTORE_PRIVS, _privs  # setupcheck importeert deze module zelf
    need = RESTORE_PRIVS + POWER_PRIVS
    try:
        integ = build(svc, http)
    except IntegrationError as e:
        return proef.check("rechten (actietoken)", None, str(e))
    what = "rechten (actietoken)" if integ.split else "rechten (het enige token)"
    _, act, err = await _privs(integ)
    if act is None:
        return proef.check(what, None, f"niet op te vragen ({(err or 'geen antwoord').removeprefix('actietoken: ')})")
    miss = [p for p in need if p not in act]
    return proef.check(what, not miss, f"mist {', '.join(miss)}" if miss else ", ".join(need))


async def plan(svc: Service | None, http, value: dict | None, manual: bool = True,
               now: datetime | None = None) -> dict:
    """Wat run() zou doen, zonder het te doen: dezelfde keuzes (pick, free_vmid) en de calls die run() daarna doet,
    met dezelfde bouwers. Leest alleen, en kijkt nog wat extra na (ID vrij in de hele cluster, vrije ruimte, rechten).
    Bewaart niets; de aanroeper houdt geen databasesessie open."""
    value = value or {}
    cfg = settings(value)
    history = list(value.get("history") or [])
    stale = value.get("running")  # de aanroeper weigert al als er een test loopt: dit is een onderbroken test
    checks, steps, skipped, warnings = [], [], [], []
    failed = ["de test komt als mislukt in de geschiedenis, met een melding (fout, ook naar de gsm)"]
    if svc is None:
        checks.append(proef.check("Proxmox-tegel", False, "Geen Proxmox-tegel gevonden"))
        return proef.plan("Hersteltest zou mislukken: geen Proxmox-tegel", [], checks=checks, after=failed, now=now)
    checks.append(proef.check("Proxmox-tegel", True, svc.name))
    try:
        px = build(svc, http)
        who = proef.api_who(px.token_id(write=True))
        gone: set[int] = set()
        if stale and stale.get("vmid") and stale.get("node"):
            sn, sv = stale["node"], int(stale["vmid"])
            try:
                running = await _inspect(px, sn, sv, need_marker=True)
            except IntegrationError as e:
                skipped.append(proef.skip(f"oude test-CT {sv} op {sn} opruimen", f"{e}. De test gaat gewoon verder."))
            else:
                checks.append(proef.check(f"oude test-CT {sv} op {sn}", True,
                                          f"van een onderbroken test ({stale.get('at')}), met het merkteken"))
                steps += _remove_steps(f"{sn} via tegel {svc.name}", who, sn, sv, running)
                warnings.append(f"Eerst wordt CT {sv} op {sn} verwijderd, van een test die onderbroken werd. "
                                f"Let op: {PURGE_NOTE}.")
                gone.add(sv)
        job = await pick(px, cfg, history)
        node, pbs, src, backup = job["node"], job["pbs"], job["src"], job["backup"]
        checks.append(proef.check("node", True, f"{node} (" + ("ingesteld" if cfg["node"] == node else "eerste die online is"
                                  + (f"; {cfg['node']} is niet online" if cfg["node"] else "")) + ")"))
        checks.append(proef.check("PBS-opslag", True, f"{pbs} (" + ("ingesteld" if cfg["pbs"] == pbs else "eerste"
                                  + (f"; {cfg['pbs']} niet gevonden" if cfg["pbs"] else "")) + ")"))
        tested = _tested(history).get(src)
        why = f"het langst niet getest (laatst {tested[:10]})" if tested else "nog nooit getest"
        if cfg["only"]:
            why += f", uit {', '.join(str(v) for v in cfg['only'])}"
        checks.append(proef.check("back-up", True, f"{job['name']} ({src}) van {_local(backup.get('ctime'))}, "
                                  f"{_gb(backup.get('size'))}: {why}"))
        vmid = await free_vmid(px, int(cfg["vmid_from"]), gone)
    except IntegrationError as e:
        checks.append(proef.check("back-up zoeken", False, str(e)))
        return proef.plan(f"Hersteltest zou mislukken bij back-up zoeken: {e}", steps, checks=checks, skipped=skipped,
                          after=failed, warnings=warnings, now=now)
    checks.append(proef.check("vrij ID", True, f"CT {vmid}, het eerste vrije vanaf {cfg['vmid_from']}"
                              + (" (na het opruimen hierboven)" if vmid in gone else "")))
    if vmid in gone:
        # Nu nog bezet door de oude test-CT; Proxmox zou "bestaat al" zeggen, maar die gaat eerst weg.
        checks.append(proef.check(f"ID {vmid} vrij in de hele cluster", None,
                                  "nu nog bezet door de oude test-CT, die eerst verwijderd wordt"))
    else:
        checks.append(await _nextid(px, vmid))
    checks.append(await _space(px, node, cfg, backup))
    checks.append(await _rights(svc, http))

    m = f"{node} via tegel {svc.name}"
    steps.append(_px_step(m, who, restore_call(node, vmid, backup, cfg), wait=f"Proxmox-taak, max {RESTORE_WAIT} s",
                          on_fail="mislukt bij terugzetten; is de CT al aangemaakt, dan wordt hij toch opgeruimd"))
    steps.append(_px_step(m, who, detach_call(node, vmid, {}), note="plus delete= met elke netX-regel van de kopie "
                          "(pas na het terugzetten te zien): zo komt hij nooit op je netwerk"))
    steps.append(_px_step(m, who, start_call(node, vmid), wait=f"Proxmox-taak, max {START_WAIT} s; dan {BOOT_WAIT} s "
                          "wachten en GET …/status/current: moet running zijn",
                          on_fail="mislukt bij opstarten; de kopie wordt toch opgeruimd"))
    steps += _remove_steps(m, who, node, vmid, None)
    after = ["het resultaat komt bovenaan in de geschiedenis (de volgende test kiest dan een andere CT) en in de kolom "
             "hersteltest van hw → back-ups",
             "een melding: geslaagd (alleen naar de gsm als de vorige mislukte) of mislukt (fout, ook naar de gsm)",
             "lukt het opruimen niet: een melding en een aandachtspunt om de CT zelf te verwijderen"]
    return proef.plan(f"Hersteltest zou {job['name']} ({src}) terugzetten als CT {vmid} op {node}, opstarten en weer "
                      "verwijderen", steps, checks=checks, skipped=skipped, after=after, warnings=warnings, now=now,
                      source_vmid=src, vmid=vmid, node=node, manual=manual)


async def _dry(maker: async_sessionmaker, http: HttpClients, svc: Service | None, value: dict,
               now: datetime) -> dict:
    """Alleen proef: het plan op de tijdlijn en in dry_history, en last_at zodat due() pas volgende maand weer afgaat.
    Nooit "running" of "history": die sturen de rotatie, de dekking, de aandacht en de checklist."""
    try:
        p = await plan(svc, http, value, manual=False, now=now)
    except Exception as e:  # noqa: BLE001 - anders probeert de worker het elke minuut opnieuw
        log.exception("hersteltest (proef)")
        p = proef.plan("Hersteltest: proef mislukt", [], checks=[
            proef.check("plan maken", False, f"Onverwachte fout: {type(e).__name__}")], now=now)
    async with maker() as db:
        st = await ensure_state(db, STATE_KEY, {})
        v = dict(st.value or {})
        v["dry_history"] = [{"at": now.isoformat(), "plan": p, "manual": False}, *(v.get("dry_history") or [])][:KEEP]
        v["last_at"] = now.isoformat()
        st.value = v
        proef.record(db, "backup", p["title"], p, service_id=svc.id if svc else None)
        await db.commit()
    return {"ok": True, "proef": True, "at": now.isoformat(), "plan": p}


async def run(maker: async_sessionmaker, http: HttpClients, manual: bool = False) -> dict:
    """Eén hersteltest. Geeft het resultaat terug (ook bij een fout). Staat "alleen proef" aan, dan maakt de
    automatische test alleen een plan; ▶ nu testen test altijd echt."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    async with maker() as db:
        st = await ensure_state(db, STATE_KEY, {})
        value = dict(st.value or {})
        if is_busy(value, now):
            return {"ok": False, "error": "Er loopt al een hersteltest"}
        cfg = settings(value)
        svc = await service(db, cfg)
        history = list(value.get("history") or [])
        dry = cfg["dry"] and not manual
        if not dry:
            st.value = {**value, "running": {"at": now.isoformat(), "step": "back-up zoeken"}}
        await db.commit()
    if dry:
        return await _dry(maker, http, svc, value, now)
    stale = value.get("running")  # een onderbroken test van vroeger: die CT eerst opruimen

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
        job = await pick(px, cfg, history)
        node, src, backup = job["node"], job["src"], job["backup"]
        result.update(source_vmid=src, name=job["name"], volid=backup["volid"], node=node,
                      backup_at=datetime.fromtimestamp(backup.get("ctime") or 0, timezone.utc).isoformat(),
                      size=backup.get("size"))
        vmid = await free_vmid(px, int(cfg["vmid_from"]))
        result["vmid"] = vmid
        await step("terugzetten")
        upid = await _do(px, restore_call(node, vmid, backup, cfg))
        created = True
        await wait_task(px, node, upid, timeout=RESTORE_WAIT)
        result["restore_seconds"] = round(asyncio.get_running_loop().time() - started)

        await step("netwerk loskoppelen")
        conf = await _call(px, "GET", f"/nodes/{node}/lxc/{vmid}/config") or {}
        await _do(px, detach_call(node, vmid, conf))

        await step("opstarten")
        await wait_task(px, node, await _do(px, start_call(node, vmid)), timeout=START_WAIT)
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
            _report(db, result, svc.id if svc else None, failed_before=len(history) > 1 and not history[1].get("ok"))
            await db.commit()
    return result


def _report(db: AsyncSession, r: dict, service_id: int | None, failed_before: bool = False) -> None:
    what = f"{r.get('name') or 'CT'} ({r.get('source_vmid') or '?'})"
    if r["ok"]:
        body = f"Back-up van {r['backup_at'][:16].replace('T', ' ')} teruggezet als CT {r['vmid']} op {r['node']}, " \
               f"opgestart en weer verwijderd ({r['seconds']} s)."
        # Alleen naar een gsm voor storingen als de vorige test mislukte: elke maand "geslaagd" is daar ruis.
        notify(db, f"Hersteltest geslaagd: {what}", body, level="ok", source="backup", service_id=service_id,
               key="hersteltest", recovers="err" if failed_before else None)
    else:
        notify(db, f"Hersteltest mislukt: {what}", f"Bij {r['step']}: {r.get('error')}", level="err", source="backup",
               service_id=service_id, key="hersteltest")
    if r.get("cleanup_error"):
        notify(db, f"Test-CT {r.get('vmid')} niet opgeruimd", f"{r['cleanup_error']}. Verwijder hem zelf in Proxmox.",
               level="warn", source="backup", service_id=service_id)
