"""Updates installeren vanuit het dashboard: eerst een snapshot, dan apt, dan kijken of de services nog leven.

Waar kan een snapshot?
- een container op een node ("ssh:3:ct:105"): `pct snapshot` via SSH op de node, geen extra API-rechten;
- een SSH-host die zelf een VM of CT uit Proxmox is (bron "pve:1:lxc/105"): via de Proxmox-API (VM.Snapshot);
- een fysieke node of een andere machine: geen snapshot. Dat moet je dan bewust aanvinken.

Lukt de installatie niet, of is een service daarna down, dan kan je met één klik terug naar de snapshot.
's Nachts automatisch kan ook, alleen voor beveiligingsupdates en alleen waar een snapshot kan; gaat het daar
mis, dan draait de homepage zelf terug.

Proefmodus: describe_batch, describe_rollback en describe_cleanup tonen wat installeren, terugdraaien of snapshots
opruimen zou doen, zonder het te doen. Ze bouwen hun commando's en calls met dezelfde functies als het echte werk
(snapshot_call, install_cmd, rollback_call, delsnapshot_call), zodat de proef niet kan afwijken.
"""

import asyncio
import logging
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit

import asyncssh
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .. import proef
from ..deps import event, notify
from ..integrations import IntegrationError, build
from ..models import AppState, Service, SshHost, UpdateRun
from ..ssh_exec import SshFail, command, connect, run
from ..ssh_login import Login, defaults, login_for
from .checks import HttpClients, check_service

log = logging.getLogger("homepage.upgrade")

SNAP_PREFIX = "hp-upd-"
SETTINGS_KEY = "update_settings"
AUTO_KEY = "update_auto_last"
# Het laatste plan van de nachtelijke run en van het opruimen, als die alleen als proef lopen.
AUTO_PROEF_KEY = "update_auto_proef"
CLEANUP_PROEF_KEY = "update_cleanup_proef"
# proef: de nachtelijke updates alleen als proef; cleanup_proef: snapshots opruimen alleen als proef.
DEFAULTS = {"auto": False, "hour": 4, "keep_days": 7, "proef": False, "cleanup_proef": False}
INSTALL_TIMEOUT = 1800
CHECK_WAIT = 20
CHECK_RETRIES = 3
CHECK_GAP = 10
MAX_OUTPUT = 60000
DONE = ("ok", "fout", "services_down", "teruggedraaid", "terugdraaien_mislukt", "geannuleerd")
SNAP_TIMEOUT = 600
ROLLBACK_TIMEOUT = 900
# Alleen beveiligingsupdates, maar de scan vindt er (niet meer) voor deze machine: de run doet dan niets.
NO_SECURITY = "geen beveiligingsupdates meer open"
PKG_RE = re.compile(r"^[a-z0-9][a-z0-9+.\-]*(:[a-z0-9]+)?$")
GUEST_RE = re.compile(r"^pve:(\d+):(lxc|qemu)/(\d+)$")

INSTALL = r"""
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a APT_LISTCHANGES_FRONTEND=none
O="-y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
if command -v apt-get >/dev/null 2>&1; then
  apt-get update -q </dev/null || exit 100
  if [ -n "$PKGS" ]; then
    apt-get $O install --only-upgrade $PKGS </dev/null
  elif command -v pveversion >/dev/null 2>&1 || command -v proxmox-backup-manager >/dev/null 2>&1; then
    apt-get $O dist-upgrade </dev/null
  else
    apt-get $O upgrade --with-new-pkgs </dev/null
  fi
  rc=$?
elif command -v apk >/dev/null 2>&1; then
  apk update -q </dev/null && apk upgrade </dev/null
  rc=$?
else
  echo "Geen apt of apk op deze machine"
  exit 127
fi
[ -f /var/run/reboot-required ] && echo "@@REBOOT"
exit $rc
"""


@dataclass
class Plan:
    key: str
    name: str
    host: SshHost | None = None
    vmid: int | None = None          # pct exec op de node
    snap: dict | None = None         # waar de snapshot kan
    why: str | None = None           # waarom installeren niet kan
    nosnap: str | None = None        # waarom er geen snapshot kan
    extra_hosts: set[str] = field(default_factory=set)

    @property
    def can(self) -> bool:
        return self.why is None


async def plan_for(db: AsyncSession, key: str, name: str | None = None) -> Plan:
    p = Plan(key, name or key)
    if m := re.fullmatch(r"ssh:(\d+):ct:(\d+)", key):
        h = await db.get(SshHost, int(m[1]))
        if h is None:
            p.why = "SSH-host bestaat niet meer"
            return p
        p.host, p.vmid = h, int(m[2])
        p.snap = {"kind": "pct", "host_id": h.id, "vmid": p.vmid}
        guest = (await db.execute(select(SshHost).where(SshHost.source.like(f"pve:%:lxc/{p.vmid}")))).scalars().first()
        if guest:
            p.extra_hosts.add(guest.host.lower())
    elif m := re.fullmatch(r"ssh:(\d+)", key):
        h = await db.get(SshHost, int(m[1]))
        if h is None:
            p.why = "SSH-host bestaat niet meer"
            return p
        p.host = h
        g = GUEST_RE.match(h.source or "")
        if g:
            p.snap = {"kind": "api", "service_id": int(g[1]), "type": g[2], "vmid": int(g[3])}
        else:
            p.nosnap = "fysieke machine: hier kan geen snapshot"
    elif m := re.fullmatch(r"pve:(\d+):(.+)", key):
        node = m[2]
        h = (await db.execute(select(SshHost).where(SshHost.source == f"pve:{m[1]}:node/{node}"))).scalars().first()
        h = h or (await db.execute(select(SshHost).where(func.lower(SshHost.name) == node.lower()))).scalars().first()
        if h is None:
            p.why = f"Node {node} staat nog niet in de terminal: importeer hem met ⟳ pve en open hem één keer"
            return p
        p.host = h
        p.nosnap = "Proxmox-node: hier kan geen snapshot"
    else:
        p.why = "Dit soort updates installeer je niet vanuit het dashboard"
        return p
    if name is None and p.host:
        p.name = f"CT {p.vmid} op {p.host.name}" if p.vmid else p.host.name
    if p.host and not p.host.host_key:
        p.why = "Open eerst één keer een terminal naar deze host om de hostsleutel te bevestigen"
    return p


def plan_out(p: Plan) -> dict:
    return {"can": p.can, "why": p.why, "snapshot": (p.snap or {}).get("kind"), "nosnap": p.nosnap}


async def settings(db: AsyncSession) -> dict:
    st = await db.get(AppState, SETTINGS_KEY)
    return {**DEFAULTS, **(st.value if st else {})}


def _pkgs(packages: list[str] | None) -> str:
    return " ".join(p for p in (packages or []) if PKG_RE.match(p))


def script(packages: list[str] | None) -> str:
    return f"PKGS={shlex.quote(_pkgs(packages))}\n{INSTALL}"


def security_packages(updates_state: dict | None, key: str) -> list[str]:
    for t in (updates_state or {}).get("targets", []):
        if t["key"] == key:
            return [p["n"] for p in t.get("packages", []) if p.get("sec") and PKG_RE.match(p.get("n") or "")]
    return []


def run_packages(updates_state: dict | None, key: str, security_only: bool) -> list[str] | None:
    """Wat een run installeert: None = alles wat openstaat; een lege lijst = niets te doen (NO_SECURITY)."""
    return security_packages(updates_state, key) if security_only else None


# --- bouwstenen: dezelfde commando's en calls voor het echte werk en voor de proef ----------------

def snap_name(now: datetime | None = None) -> str:
    return f"{SNAP_PREFIX}{(now or datetime.now()).strftime('%Y%m%d-%H%M%S')}"


def snap_desc(now: datetime | None = None) -> str:
    return f"voor updates via homepage, {(now or datetime.now()).strftime('%d/%m/%Y %H:%M')}"


def _px_path(snap: dict, tail: str = "") -> str:
    # Zonder node (de proef kon hem niet opzoeken) een "?"; de echte run zoekt hem altijd eerst op.
    return f"/nodes/{snap.get('node') or '?'}/{snap['type']}/{snap['vmid']}/snapshot{tail}"


def snapshot_call(snap: dict, name: str, desc: str) -> dict:
    """De snapshot vooraf: `pct snapshot` via SSH op de node, of een POST naar de Proxmox-API."""
    if snap["kind"] == "pct":
        return {"via": "ssh", "cmd": f"pct snapshot {int(snap['vmid'])} {name} --description {shlex.quote(desc)}"}
    return {"via": "proxmox-api", "method": "POST", "path": _px_path(snap),
            "data": {"snapname": name, "description": desc}}


def install_cmd(plan: Plan, login: Login, packages: list[str] | None) -> str:
    """Het installatiescript zoals het over SSH vertrekt: in een container via pct exec, met sudo -n als het moet."""
    return command(script(packages), login, plan.vmid)


def rollback_call(snap: dict) -> dict:
    if snap["kind"] == "pct":
        v = int(snap["vmid"])
        return {"via": "ssh", "cmd": f"pct rollback {v} {snap['name']} && (pct status {v} | grep -q running || pct start {v})"}
    return {"via": "proxmox-api", "method": "POST", "path": _px_path(snap, f"/{snap['name']}/rollback"),
            "data": {"start": 1}}


def delsnapshot_call(snap: dict) -> dict:
    if snap["kind"] == "pct":
        return {"via": "ssh", "cmd": f"pct delsnapshot {int(snap['vmid'])} {snap['name']}"}
    return {"via": "proxmox-api", "method": "DELETE", "path": _px_path(snap, f"/{snap['name']}")}


def auto_targets(updates_state: dict | None) -> list[tuple[str, str]]:
    """Wat 's nachts aan de beurt komt: elke machine met beveiligingsupdates, in de volgorde van de scan."""
    return [(t["key"], t["name"]) for t in (updates_state or {}).get("targets", [])
            if t.get("security") and not t.get("error")]


async def refusal(db: AsyncSession, plan: Plan, snapshot: bool) -> dict | None:
    """Waarom er voor deze machine geen run kan komen, of None als het kan."""
    if not plan.can:
        return {"key": plan.key, "name": plan.name, "why": plan.why}
    if not plan.snap and snapshot:
        return {"key": plan.key, "name": plan.name, "why": plan.nosnap or "geen snapshot mogelijk", "nosnap": True}
    busy = (await db.execute(select(UpdateRun.id).where(UpdateRun.target == plan.key,
                                                        UpdateRun.status.not_in(DONE)))).first()
    if busy:
        return {"key": plan.key, "name": plan.name, "why": "er loopt al een installatie"}
    return None


# --- Proxmox ---------------------------------------------------------------------------------

PX_API = "/api2/json"


async def _px_service(db: AsyncSession, http: HttpClients, snap: dict):
    svc = await db.get(Service, snap["service_id"])
    if svc is None or svc.type != "proxmox":
        raise IntegrationError("De Proxmox-tegel van deze machine bestaat niet meer")
    return build(svc, http)


async def _px_node(px, snap: dict) -> None:
    """Zet de node van de VM of CT in snap (GET /cluster/resources), als die er nog niet in staat."""
    if not snap.get("node"):
        for r in await px.resources():
            if r.get("vmid") == snap["vmid"] and r.get("type") == snap["type"]:
                snap["node"] = r.get("node")
        if not snap.get("node"):
            raise IntegrationError(f"{snap['type']} {snap['vmid']} niet gevonden in Proxmox")


async def _px_guest(db: AsyncSession, http: HttpClients, snap: dict):
    px = await _px_service(db, http, snap)
    await _px_node(px, snap)
    return px


async def wait_task(px, node: str, upid: str, timeout: float = 600) -> None:
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        st = await px.get(f"/nodes/{node}/tasks/{quote(upid, safe='')}/status")
        if isinstance(st, dict) and st.get("status") == "stopped":
            if st.get("exitstatus") != "OK":
                raise IntegrationError(f"Proxmox-taak mislukt: {st.get('exitstatus')}")
            return
        if asyncio.get_running_loop().time() > deadline:
            raise IntegrationError("Proxmox-taak duurt te lang")
        await asyncio.sleep(2)


async def _px_call(px, method: str, path: str, **kw) -> str:
    data = await px.request(method, PX_API + path, headers=px.headers(write=method != "GET"), **kw)
    return (data or {}).get("data") or ""


async def _px_send(px, c: dict) -> str:
    """Een call uit snapshot_call, rollback_call of delsnapshot_call."""
    return await _px_call(px, c["method"], c["path"], **({"data": c["data"]} if c.get("data") else {}))


def _rights(e: Exception, right: str) -> str:
    msg = str(e)
    return f"{msg} — het Proxmox-token heeft {right} nodig" if "te weinig rechten" in msg else msg


# --- uitvoeren -------------------------------------------------------------------------------

class Runner:
    """Eén run: houdt de uitvoer bij en schrijft ze regelmatig weg zodat de browser kan meekijken."""

    def __init__(self, maker: async_sessionmaker, run_id: int, http: HttpClients):
        self.maker, self.id, self.http = maker, run_id, http
        self.lines: list[str] = []
        self._flushed = 0.0

    def say(self, line: str) -> None:
        self.lines.append(line.rstrip("\n"))

    @property
    def output(self) -> str:
        out = "\n".join(self.lines)
        return out[-MAX_OUTPUT:]

    async def save(self, force: bool = False, **fields) -> None:
        now = asyncio.get_running_loop().time()
        if not force and not fields and now - self._flushed < 1.5:
            return
        self._flushed = now
        async with self.maker() as db:
            r = await db.get(UpdateRun, self.id)
            r.output = self.output
            for k, v in fields.items():
                setattr(r, k, v)
            await db.commit()


async def _snapshot(rn: Runner, db: AsyncSession, plan: Plan, conn, login, name: str) -> dict:
    snap = {**plan.snap, "name": name}
    desc = snap_desc()
    if snap["kind"] == "pct":
        rn.say(f"$ pct snapshot {plan.vmid} {name}")
        rc, out, err = await run(conn, snapshot_call(snap, name, desc)["cmd"], login, timeout=SNAP_TIMEOUT)
        for line in (out + err).splitlines():
            rn.say(line)
        if rc != 0:
            hint = " (de opslag van deze container kan geen snapshots, bv. 'dir')" if "snapshot feature is not available" in (out + err) else ""
            raise SshFail(f"snapshot mislukt{hint}")
        snap["node"] = plan.host.name
    else:
        px = await _px_guest(db, rn.http, snap)
        # Op de Proxmox-taak wachten duurt tot tien minuten: geen transactie open, de verbinding terug naar de pool.
        await db.commit()
        rn.say(f"Proxmox: snapshot {name} van {snap['type']} {snap['vmid']} op {snap['node']}")
        try:
            upid = await _px_send(px, snapshot_call(snap, name, desc))
            await wait_task(px, snap["node"], upid, timeout=SNAP_TIMEOUT)
        except IntegrationError as e:
            raise IntegrationError(_rights(e, "VM.Snapshot")) from e
    snap["at"] = datetime.now(timezone.utc).isoformat()
    rn.say("snapshot klaar")
    return snap


async def related(db: AsyncSession, plan: Plan) -> list[Service]:
    hosts = {x.lower() for x in plan.extra_hosts}
    ids = set()
    if plan.host and plan.vmid is None:
        hosts.add(plan.host.host.lower())
        if plan.host.service_id:
            ids.add(plan.host.service_id)
    n = plan.name.lower()
    out = []
    for s in (await db.execute(select(Service))).scalars():
        # Alleen checks die je nu kunt nakijken: een push-check wacht op signalen, een gepauzeerde staat uit.
        check = s.check or {}
        if not check.get("type") or check.get("paused") or check.get("type") == "push":
            continue
        url_host = (urlsplit(s.url).hostname or "").lower() if s.url else ""
        tgt = str((s.check or {}).get("target") or "").lower()
        tgt_host = (urlsplit(tgt).hostname if "//" in tgt else tgt.split(":")[0]) or ""
        if (s.id in ids or url_host in hosts or tgt_host in hosts or s.name.lower() == n
                or (url_host and url_host.split(".")[0] == n)):
            out.append(s)
    return out


async def _checks(rn: Runner, services: list[Service]) -> list[dict]:
    if not services:
        rn.say("geen gekoppelde services om na te kijken")
        return []
    rn.say(f"wachten {CHECK_WAIT} s, dan {len(services)} service(s) nakijken: {', '.join(s.name for s in services)}")
    await rn.save(force=True, status="controleren")
    await asyncio.sleep(CHECK_WAIT)
    result = {}
    todo = list(services)
    for attempt in range(CHECK_RETRIES):
        outcomes = await asyncio.gather(*(check_service(rn.maker, s.id, s.check, s.url, rn.http) for s in todo))
        for s, o in zip(todo, outcomes):
            result[s.id] = {"service_id": s.id, "name": s.name, "ok": o.ok, "error": o.error}
        todo = [s for s in todo if not result[s.id]["ok"]]
        if not todo:
            break
        if attempt < CHECK_RETRIES - 1:
            rn.say(f"nog down: {', '.join(s.name for s in todo)}; opnieuw over {CHECK_GAP} s")
            await asyncio.sleep(CHECK_GAP)
    for c in result.values():
        rn.say(f"  ✓ {c['name']}" if c["ok"] else f"  ✗ {c['name']}: {c['error']}")
    return list(result.values())


async def execute(maker: async_sessionmaker, run_id: int, http: HttpClients, packages: list[str] | None = None) -> str:
    """Voert run run_id uit. Geeft de eindstatus terug."""
    rn = Runner(maker, run_id, http)
    async with maker() as db:
        r = await db.get(UpdateRun, run_id)
        plan = await plan_for(db, r.target, r.target_name)
        want_snap = r.snapshot is not None
        r.status, r.started_at = "snapshot" if want_snap else "installeren", datetime.now(timezone.utc)
        await db.commit()
    if not plan.can:
        await rn.save(force=True, status="fout", error=plan.why, finished_at=datetime.now(timezone.utc))
        return "fout"
    async with maker() as db:
        login = await login_for(db, plan.host, await defaults(db))
    snap = None
    status, error, rc, reboot = "fout", None, None, False
    try:
        async with connect(plan.host, login, keepalive=30) as conn:
            if want_snap:
                async with maker() as db:
                    snap = await _snapshot(rn, db, plan, conn, login, snap_name())
                await rn.save(force=True, snapshot=snap, status="installeren")
            rn.say(f"$ apt upgrade{' (alleen beveiliging: ' + ', '.join(packages) + ')' if packages else ''}"
                   f"{f' in CT {plan.vmid}' if plan.vmid else ''}")
            proc = await conn.create_process(install_cmd(plan, login, packages), stderr=asyncssh.STDOUT)
            try:
                async with asyncio.timeout(INSTALL_TIMEOUT):
                    async for line in proc.stdout:
                        if line.startswith("@@REBOOT"):
                            reboot = True
                            continue
                        if line.strip():
                            rn.say(line)
                        await rn.save()
                    await proc.wait()
            except TimeoutError as e:
                proc.terminate()
                raise SshFail(f"installatie duurde langer dan {INSTALL_TIMEOUT // 60} min") from e
            rc = proc.exit_status if proc.exit_status is not None else -1
            rn.say(f"exitcode {rc}")
    except (SshFail, IntegrationError, OSError, asyncssh.Error) as e:
        error = str(e) or type(e).__name__
        rn.say(f"✗ {error}")
        await rn.save(force=True, status="fout", error=error, exit_code=rc, snapshot=snap,
                      finished_at=datetime.now(timezone.utc))
        await _finish(maker, run_id, plan, "fout", error)
        return "fout"
    if rc != 0:
        status, error = "fout", f"apt stopte met exitcode {rc}"
        checks = None
    else:
        async with maker() as db:
            services = await related(db, plan)
        checks = await _checks(rn, services)
        down = [c["name"] for c in checks if not c["ok"]]
        status = "services_down" if down else "ok"
        error = f"down na de updates: {', '.join(down)}" if down else None
    if reboot:
        rn.say("herstart nodig om alles te laden (kernel of bibliotheken)")
    await rn.save(force=True, status=status, error=error, exit_code=rc, reboot_needed=reboot, checks=checks,
                  finished_at=datetime.now(timezone.utc))
    await _finish(maker, run_id, plan, status, error)
    return status


async def _finish(maker: async_sessionmaker, run_id: int, plan: Plan, status: str, error: str | None) -> None:
    async with maker() as db:
        r = await db.get(UpdateRun, run_id)
        auto = r.trigger == "auto"
        can_back = bool(r.snapshot and r.snapshot.get("name"))
        if status == "ok":
            event(db, "updates", f"{r.target_name}: updates geïnstalleerd"
                  + (" (snapshot " + r.snapshot["name"] + ")" if can_back else ""),
                  "Herstart nodig." if r.reboot_needed else None, level="ok", data={"run": r.id})
        elif not auto:
            notify(db, f"Updates op {r.target_name} {'mislukt' if status == 'fout' else 'geïnstalleerd, maar services zijn down'}",
                   (error or "") + ("\nTerugdraaien naar de snapshot kan vanuit apt → installaties." if can_back else ""),
                   level="err", source="updates")
        await db.commit()


async def rollback(maker: async_sessionmaker, run_id: int, http: HttpClients) -> str:
    rn = Runner(maker, run_id, http)
    async with maker() as db:
        r = await db.get(UpdateRun, run_id)
        rn.lines = (r.output or "").splitlines()
        snap = dict(r.snapshot or {})
        name = r.target_name
        if not snap.get("name") or snap.get("removed_at"):
            raise ValueError("Deze run heeft geen snapshot (meer)")
        r.status = "terugdraaien"
        await db.commit()
    rn.say(f"--- terugdraaien naar snapshot {snap['name']} ---")
    try:
        if snap["kind"] == "pct":
            async with maker() as db:
                h = await db.get(SshHost, snap["host_id"])
                if h is None:
                    raise SshFail("De node van deze container staat niet meer in de terminal")
                login = await login_for(db, h, await defaults(db))
            async with connect(h, login) as conn:
                rc, out, err = await run(conn, rollback_call(snap)["cmd"], login, timeout=ROLLBACK_TIMEOUT)
            for line in (out + err).splitlines():
                rn.say(line)
            if rc != 0:
                raise SshFail(f"pct rollback stopte met exitcode {rc}")
        else:
            async with maker() as db:
                px = await _px_guest(db, http, snap)
            try:
                upid = await _px_send(px, rollback_call(snap))
                await wait_task(px, snap["node"], upid, timeout=ROLLBACK_TIMEOUT)
            except IntegrationError as e:
                raise IntegrationError(_rights(e, "VM.Snapshot.Rollback")) from e
    except (SshFail, IntegrationError, OSError, asyncssh.Error) as e:
        rn.say(f"✗ {e}")
        await rn.save(force=True, status="terugdraaien_mislukt", error=str(e))
        async with maker() as db:
            notify(db, f"Terugdraaien van {name} mislukt", str(e), level="err", source="updates")
            await db.commit()
        return "terugdraaien_mislukt"
    rn.say("✓ teruggedraaid en gestart")
    await rn.save(force=True, status="teruggedraaid", rolled_back_at=datetime.now(timezone.utc))
    async with maker() as db:
        event(db, "updates", f"{name}: teruggedraaid naar {snap['name']}", level="warn", data={"run": run_id})
        await db.commit()
    return "teruggedraaid"


async def cleanup_todo(db: AsyncSession, keep_days: int, now: datetime | None = None) -> list[tuple[int, dict, str]]:
    """De eigen snapshots die nu weg mogen: (run, snapshot, machine)."""
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=keep_days)
    # Al opgeruimde snapshots meteen in SQL overslaan (JSON_EXTRACT op SQLite, ->> op PostgreSQL). Vaste volgorde:
    # de proef toont ze zoals het opruimen ze afwerkt.
    runs = (await db.execute(select(UpdateRun).where(UpdateRun.status.in_(("ok", "teruggedraaid")),
                                                      UpdateRun.finished_at < cutoff,
                                                      UpdateRun.snapshot["removed_at"].as_string().is_(None))
                             .order_by(UpdateRun.id))).scalars().all()
    return [(r.id, dict(r.snapshot), r.target_name) for r in runs
            if r.snapshot and r.snapshot.get("name", "").startswith(SNAP_PREFIX) and not r.snapshot.get("removed_at")]


async def cleanup_snapshots(maker: async_sessionmaker, http: HttpClients) -> int:
    """Eigen snapshots van geslaagde runs na keep_days opruimen; mislukte laten we staan."""
    async with maker() as db:
        cfg = await settings(db)
        if cfg.get("cleanup_proef"):
            # Alleen proef: noteren wat weg zou gaan. Niets verwijderen, removed_at blijft leeg.
            p = await describe_cleanup(db, http)
            prev = await db.get(AppState, CLEANUP_PROEF_KEY)
            # Dit loopt elke 6 uur: alleen op de tijdlijn als er andere snapshots weg zouden gaan dan vorige keer.
            if _snapset(prev.value if prev else None) != _snapset(p):
                proef.record(db, "updates", "snapshots van updates opruimen", p)
            await _keep(db, CLEANUP_PROEF_KEY, p)
            await db.commit()
            return 0
        todo = await cleanup_todo(db, cfg["keep_days"])
    n = 0
    for run_id, snap, _ in todo:
        try:
            c = delsnapshot_call(snap)
            if snap["kind"] == "pct":
                async with maker() as db:
                    h = await db.get(SshHost, snap["host_id"])
                    login = await login_for(db, h, await defaults(db)) if h else None
                if h is None:
                    continue
                async with connect(h, login) as conn:
                    rc, out, err = await run(conn, c["cmd"], login, timeout=SNAP_TIMEOUT)
                if rc != 0 and "does not exist" not in (out + err):
                    raise SshFail((err or out).strip()[-200:])
            else:
                async with maker() as db:
                    px = await _px_guest(db, http, snap)
                upid = await _px_send(px, c)
                await wait_task(px, snap["node"], upid, timeout=SNAP_TIMEOUT)
        except (SshFail, IntegrationError, OSError, asyncssh.Error) as e:
            log.info("snapshot %s opruimen mislukt: %s", snap.get("name"), e)
            continue
        async with maker() as db:
            r = await db.get(UpdateRun, run_id)
            r.snapshot = {**snap, "removed_at": datetime.now(timezone.utc).isoformat()}
            await db.commit()
        n += 1
    return n


async def mark_interrupted(db: AsyncSession, triggers: tuple[str, ...]) -> int:
    """Bij het opstarten: runs die nog liepen toen het proces stopte, kan niemand meer afmaken. Zonder dit blijft
    zo'n doel voor altijd "bezig" (create_runs weigert dan). API en worker ruimen elk hun eigen runs op:
    manuele runs lopen in de API, nachtelijke (auto) in de worker."""
    now = datetime.now(timezone.utc)
    runs = (await db.execute(select(UpdateRun).where(UpdateRun.status.not_in(DONE),
                                                     UpdateRun.trigger.in_(triggers)))).scalars().all()
    for r in runs:
        # Halverwege terugdraaien: niet zeker dat de snapshot teruggezet is.
        r.status = "terugdraaien_mislukt" if r.status == "terugdraaien" else "fout"
        r.error = "onderbroken door herstart"
        r.finished_at = now
    return len(runs)


async def create_runs(db: AsyncSession, keys: list[tuple[str, str | None]], security_only: bool, snapshot: bool,
                      trigger: str, user_id: int | None) -> tuple[list[UpdateRun], list[dict]]:
    """Runs aanmaken voor (sleutel, naam); wat niet kan komt terug met de reden."""
    runs, refused = [], []
    for key, name in keys:
        plan = await plan_for(db, key, name)
        if why := await refusal(db, plan, snapshot):
            refused.append(why)
            continue
        r = UpdateRun(target=key, target_name=plan.name, trigger=trigger, security_only=security_only, status="wacht",
                      snapshot={"kind": plan.snap["kind"]} if (snapshot and plan.snap) else None, user_id=user_id,
                      reboot_needed=False)
        db.add(r)
        runs.append(r)
    await db.flush()
    return runs, refused


async def run_batch(maker: async_sessionmaker, http: HttpClients, run_ids: list[int], auto_rollback: bool = False) -> None:
    """Na elkaar, zodat niet alles tegelijk herstart. Bij een automatische run: zelf terugdraaien als het misgaat."""
    for rid in run_ids:
        async with maker() as db:
            r = await db.get(UpdateRun, rid)
            st = await db.get(AppState, "updates")
            packages = run_packages(st.value if st else None, r.target, r.security_only)
            if r.security_only and not packages:
                r.status, r.error, r.finished_at = "ok", NO_SECURITY, datetime.now(timezone.utc)
                await db.commit()
                continue
        try:
            status = await execute(maker, rid, http, packages)
        except Exception as e:
            log.exception("updates installeren mislukt")
            async with maker() as db:
                r = await db.get(UpdateRun, rid)
                r.status, r.error, r.finished_at = "fout", f"onverwachte fout: {type(e).__name__}", datetime.now(timezone.utc)
                await db.commit()
            continue
        if auto_rollback and status in ("fout", "services_down"):
            async with maker() as db:
                r = await db.get(UpdateRun, rid)
                has_snap = bool(r.snapshot and r.snapshot.get("name"))
                name, err = r.target_name, r.error
            back = await rollback(maker, rid, http) if has_snap else None
            async with maker() as db:
                notify(db, f"Nachtelijke updates op {name} mislukt" + (", teruggedraaid" if back == "teruggedraaid" else ""),
                       err, level="err" if back != "teruggedraaid" else "warn", source="updates")
                await db.commit()


async def auto_updates(maker: async_sessionmaker, http: HttpClients, now: datetime | None = None) -> list[int]:
    """Elke nacht op het ingestelde uur: beveiligingsupdates waar een snapshot kan."""
    now = now or datetime.now().astimezone()
    async with maker() as db:
        cfg = await settings(db)
        if not cfg["auto"] or now.hour != int(cfg["hour"]):
            return []
        last = await db.get(AppState, AUTO_KEY)
        today = now.date().isoformat()
        if last and last.value.get("date") == today:
            return []
        if last:
            last.value = {"date": today}
        else:
            db.add(AppState(key=AUTO_KEY, value={"date": today}))
        if cfg.get("proef"):
            # Alleen proef: noteren wat er zou gebeuren. Geen runs, geen meldingen en geen scan daarna (leeg terug).
            p = await describe_auto(db, http, now)
            proef.record(db, "updates", "nachtelijke updates", p)
            await _keep(db, AUTO_PROEF_KEY, p)
            await db.commit()
            return []
        st = await db.get(AppState, "updates")
        keys = auto_targets(st.value if st else None)
        runs, _ = await create_runs(db, keys, security_only=True, snapshot=True, trigger="auto", user_id=None)
        await db.commit()
        ids = [r.id for r in runs]
    if ids:
        await run_batch(maker, http, ids, auto_rollback=True)
    return ids


# --- proef -----------------------------------------------------------------------------------
# Wat installeren, terugdraaien en opruimen zouden doen, gebouwd met de bouwstenen hierboven. Niets uitvoeren en niets
# wegschrijven: geen runs, geen meldingen, geen scan achteraf.

def _local(ts) -> str:
    """Tijdstip zoals op het scherm (lokale tijd): 11/10 14:30."""
    try:
        dt = datetime.fromisoformat(ts) if isinstance(ts, str) else ts
    except ValueError:
        return "?"
    if dt is None:
        return "?"
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc).astimezone().strftime("%d/%m %H:%M")


def _api_call(c: dict) -> str:
    return f"{c['method']} {PX_API}{c['path']}"


def _px_machine(px, snap: dict) -> str:
    where = f" ({px.base})" if px is not None else ""
    return f"{snap['type']} {snap['vmid']} op node {snap.get('node') or '?'}{where}"


def _px_who(px) -> str:
    # Het token dat _px_call voor een POST of DELETE gebruikt (het actietoken als dat er is), nooit het geheim.
    token_id = getattr(px, "token_id", None)
    return proef.api_who(token_id(write=True) if token_id else None)


def _service_label(s: Service) -> str:
    c = s.check or {}
    target = c.get("target") or s.url or ""
    return f"{s.name} ({c.get('type')}{f' {target}' if target else ''})"


async def _login(db: AsyncSession, h: SshHost, d: dict) -> tuple[Login | None, str | None]:
    try:
        return await login_for(db, h, d), None
    except Exception as e:  # sleutel of wachtwoord niet te ontsleutelen: de echte run loopt hier ook vast
        return None, f"de SSH-login is niet te lezen ({type(e).__name__})"


async def _keep(db: AsyncSession, key: str, value: dict) -> None:
    st = await db.get(AppState, key)
    if st:
        st.value = value
    else:
        db.add(AppState(key=key, value=value))


def _snapset(p: dict | None) -> set:
    return {(s.get("run"), s.get("name")) for s in (p or {}).get("snapshots") or []}


def install_summary(packages: list[str] | None, scanned: dict | None, checked_at: str | None) -> str:
    """Wat het installatiescript doet, leesbaar. Welke tak het neemt, kiest de machine zelf: apt als die er is, anders apk."""
    if packages:
        what = f"alleen de beveiligingsupdates ({len(packages)}) uit de scan van {_local(checked_at)}"
        apt = f"apt-get update, dan apt-get install --only-upgrade {_pkgs(packages)}"
        apk = "apk update && apk upgrade (alles: apk kent geen lijst met beveiligingsupdates)"
    else:
        what = (f"alle openstaande ({scanned.get('count', 0)}) uit de scan van {_local(checked_at)}" if scanned else
                "alle openstaande (deze machine staat niet in de laatste scan)")
        apt = "apt-get update, dan apt-get dist-upgrade op een Proxmox-node of PBS, anders apt-get upgrade --with-new-pkgs"
        apk = "apk update && apk upgrade"
    return f"{what}; de machine kiest zelf:\n  met apt: {apt}\n  met apk: {apk}"


async def describe_batch(db: AsyncSession, http: HttpClients, keys: list[tuple[str, str | None]], *,
                         security_only: bool, snapshot: bool, trigger: str, title: str | None = None,
                         refused: list[dict] = (), warnings: list[str] = (), now: datetime | None = None) -> dict:
    """Proef van create_runs + run_batch: per machine de snapshot, apt, de services nakijken en terugdraaien, in de
    volgorde van de echte run. Leest de database en vraagt voor een snapshot via de API hooguit de node op
    (GET /cluster/resources); maakt geen runs aan en verstuurt niets. refused: wat de aanroeper zelf al weigerde."""
    now = now or datetime.now().astimezone()
    auto = trigger == "auto"
    st = await db.get(AppState, "updates")
    state = st.value if st else {}
    scanned = {t["key"]: t for t in state.get("targets", [])}
    cfg = await settings(db)
    d = await defaults(db)
    name, desc = snap_name(now), snap_desc(now)
    items, out_refused, skipped = [], [], []
    for key, nm in keys:
        plan = await plan_for(db, key, nm)
        if why := await refusal(db, plan, snapshot):
            out_refused.append(why)
            extra = ""
            if why.get("nosnap"):
                extra = ": 's nachts wordt hier nooit geïnstalleerd" if auto else ": installeren kan alleen bewust zonder snapshot"
            skipped.append(proef.skip(plan.name, why["why"] + extra))
            continue
        packages = run_packages(state, key, security_only)
        if security_only and not packages:
            skipped.append(proef.skip(plan.name, f"{NO_SECURITY}: de run staat meteen op gelukt, zonder SSH"))
            continue
        login, err = await _login(db, plan.host, d)
        if err:
            skipped.append(proef.skip(plan.name, f"{err}: de run zou mislukken"))
            continue
        # Zoals _snapshot: een kopie van plan.snap met de naam erbij; _px_node vult er de node in.
        it = {"plan": plan, "login": login, "packages": packages, "services": await related(db, plan),
              "snap": {**plan.snap, "name": name} if snapshot else None, "px": None, "px_error": None}
        if it["snap"] and it["snap"]["kind"] == "api":
            try:
                it["px"] = await _px_service(db, http, it["snap"])
            except IntegrationError as e:
                it["px_error"] = str(e)
        items.append(it)
    for x in refused:
        out_refused.append(x)
        skipped.append(proef.skip(x.get("name") or x["key"], x["why"]))
    # Alles gelezen: geen transactie open terwijl Proxmox antwoordt.
    await db.commit()
    for it in items:
        if it["px"] is not None:
            try:
                await _px_node(it["px"], it["snap"])
            except IntegrationError as e:
                it["px_error"] = str(e)

    steps, checks, after = [], [], []
    for it in items:
        plan, login, snap, n = it["plan"], it["login"], it["snap"], it["plan"].name
        who, node = proef.ssh_who(login), proef.ssh_machine(plan.host, login)
        root = login.username == "root"
        checks.append(proef.check(f"{n}: hostsleutel van {plan.host.name} bevestigd", True))
        checks.append(proef.check(f"{n}: inloggen als {login.username}", True if root else None,
                                  None if root else "met sudo -n: lukt alleen als sudo geen wachtwoord vraagt"))
        failed = f"'Nachtelijke updates op {n} mislukt'" if auto else f"'Updates op {n} mislukt'"
        if snap:
            c = snapshot_call(snap, name, desc)
            stop = f"stoppen voor apt: niets geïnstalleerd, run mislukt en een melding {failed}"
            if c["via"] == "ssh":
                checks.append(proef.check(f"{n}: snapshot kan", True, f"pct snapshot op node {plan.host.name}"))
                steps.append(proef.step(node, "ssh", c["cmd"], who=who, script=command(c["cmd"], login),
                                        wait=f"max. {SNAP_TIMEOUT // 60} min", on_fail=stop,
                                        note="de naam krijgt het tijdstip van de echte run"))
            else:
                checks.append(proef.check(f"{n}: snapshot via de Proxmox-API", None if it["px_error"] else True,
                                          it["px_error"] or f"{snap['type']} {snap['vmid']} staat op node {snap['node']}"))
                steps.append(proef.step(_px_machine(it["px"], snap), "proxmox-api", _api_call(c), who=_px_who(it["px"]),
                                        data=c["data"], wait=f"tot de Proxmox-taak klaar is, max. {SNAP_TIMEOUT // 60} min",
                                        on_fail=stop + " (het token heeft VM.Snapshot nodig)",
                                        note="de naam krijgt het tijdstip van de echte run"))
        if auto:
            on_fail = f"run mislukt; de homepage draait zelf terug naar de snapshot en stuurt een melding {failed}"
        elif snap:
            on_fail = f"run mislukt en een melding {failed}; terugdraaien kan met de knop"
        else:
            on_fail = f"run mislukt en een melding {failed}; terugdraaien kan niet: geen snapshot"
        t = scanned.get(plan.key)
        steps.append(proef.step(
            proef.ssh_machine(plan.host, login, plan.vmid), "ssh",
            install_summary(it["packages"], t, (t or {}).get("checked_at") or state.get("checked_at")),
            who=who, script=install_cmd(plan, login, it["packages"]),
            wait=f"max. {INSTALL_TIMEOUT // 60} min; de uitvoer loopt mee in apt → installaties", on_fail=on_fail,
            note="NEEDRESTART_MODE=a: needrestart herstart zelf de services die het nodig hebben; eigen "
                 "configuratiebestanden blijven staan (--force-confold). Vraagt de machine een herstart, dan zie je "
                 "'herstart nodig': de homepage herstart niets zelf."))
        if it["services"]:
            down = ("run 'services down'; de homepage draait zelf terug naar de snapshot en stuurt een melding" if auto else
                    f"run 'services down' en een melding 'Updates op {n} geïnstalleerd, maar services zijn down'")
            steps.append(proef.step("dashboard", "dashboard",
                                    "nakijken: " + ", ".join(_service_label(s) for s in it["services"]),
                                    wait=f"{CHECK_WAIT} s na apt, dan tot {CHECK_RETRIES} pogingen met {CHECK_GAP} s ertussen",
                                    when="als apt lukt (exitcode 0)", on_fail=down))
        else:
            checks.append(proef.check(f"{n}: gekoppelde services", None, "geen gevonden: na de updates wordt niets nagekeken"))
        if snap:
            c = rollback_call(snap)
            when = ("als apt mislukt of een service down blijft: automatisch" if auto else
                    "als jij terug wil: met de knop terugdraaien in apt → installaties")
            bad = f"run 'terugdraaien mislukt' en een melding 'Terugdraaien van {n} mislukt'"
            if c["via"] == "ssh":
                steps.append(proef.step(node, "ssh", c["cmd"], who=who, script=command(c["cmd"], login),
                                        wait=f"max. {ROLLBACK_TIMEOUT // 60} min", when=when, on_fail=bad))
            else:
                steps.append(proef.step(_px_machine(it["px"], snap), "proxmox-api", _api_call(c), who=_px_who(it["px"]),
                                        data=c["data"], wait=f"tot de Proxmox-taak klaar is, max. {ROLLBACK_TIMEOUT // 60} min",
                                        when=when, on_fail=bad + " (het token heeft VM.Snapshot.Rollback nodig)"))

    notes = list(warnings)
    if items:
        if not auto:
            after.append("in het auditlog: updates installeren")
        after.append("per machine die lukt: op de tijdlijn '<naam>: updates geïnstalleerd"
                     + (" (snapshot hp-upd-…)'" if snapshot else "'"))
        after.append("per machine die mislukt: een melding 'Nachtelijke updates op <naam> mislukt' (met ', teruggedraaid' "
                     "als de snapshot terug staat)" if auto else
                     "per machine die mislukt: een melding 'Updates op <naam> mislukt' of '… geïnstalleerd, maar services "
                     "zijn down'")
        after.append("de updates opnieuw scannen: SSH en apt-get update op alle opgevolgde machines")
        if snapshot:
            after.append(f"de snapshot van een geslaagde run wordt na {cfg['keep_days']} dagen opgeruimd")
        notes.append(f"De pakketten komen uit de scan van {_local(state.get('checked_at'))}; de echte run kijkt vlak "
                     "voor elke machine opnieuw in de laatste scan.")
        if len(items) > 1:
            notes.append("Eén machine na de andere, in deze volgorde: zo herstart niet alles tegelijk.")
        if not snapshot:
            notes.append("Zonder snapshot: terugdraaien kan niet.")
    title = title or ("Updates installeren" + (", alleen beveiliging" if security_only else "")
                      + (", met snapshot vooraf" if snapshot else ", zonder snapshot"))
    return proef.plan(title, steps, checks=checks, skipped=skipped, after=after, warnings=notes, now=now,
                      refused=out_refused, runs=[{"key": it["plan"].key, "name": it["plan"].name} for it in items])


async def describe_auto(db: AsyncSession, http: HttpClients, now: datetime | None = None) -> dict:
    """Proef van de nachtelijke run: wat er vannacht zou gebeuren, los van het uur en of hij vandaag al liep."""
    cfg = await settings(db)
    st = await db.get(AppState, "updates")
    notes = []
    if not cfg["auto"]:
        notes.append("De nachtelijke updates staan uit: zo zou het gaan als ze aan stonden.")
    elif cfg.get("proef"):
        notes.append("Alleen proef staat aan: 's nachts wordt dit enkel genoteerd, er wordt niets geïnstalleerd.")
    return await describe_batch(db, http, auto_targets(st.value if st else None), security_only=True, snapshot=True,
                                trigger="auto", title=f"Nachtelijke beveiligingsupdates om {int(cfg['hour']):02d}:00",
                                warnings=notes, now=now)


async def describe_rollback(db: AsyncSession, http: HttpClients, r: UpdateRun) -> dict:
    """Proef van rollback(): terug naar de snapshot van deze run, met het commando of de call die zou vertrekken."""
    snap = dict(r.snapshot or {})
    n = r.target_name
    c = rollback_call(snap)
    steps, skipped = [], []
    bad = f"run 'terugdraaien mislukt' en een melding 'Terugdraaien van {n} mislukt'"
    if c["via"] == "ssh":
        h = await db.get(SshHost, snap["host_id"])
        login, err = (await _login(db, h, await defaults(db)) if h else
                      (None, "de node van deze container staat niet meer in de terminal"))
        if err:
            skipped.append(proef.skip(n, f"{err}: terugdraaien zou mislukken"))
        else:
            steps.append(proef.step(proef.ssh_machine(h, login), "ssh", c["cmd"], who=proef.ssh_who(login),
                                    script=command(c["cmd"], login), wait=f"max. {ROLLBACK_TIMEOUT // 60} min",
                                    on_fail=bad, note=f"CT {snap['vmid']} wordt daarna gestart als hij niet draait"))
    else:
        try:
            px = await _px_service(db, http, snap)
        except IntegrationError as e:
            skipped.append(proef.skip(n, f"{e}: terugdraaien zou mislukken"))
        else:
            steps.append(proef.step(_px_machine(px, snap), "proxmox-api", _api_call(c), who=_px_who(px), data=c["data"],
                                    wait=f"tot de Proxmox-taak klaar is, max. {ROLLBACK_TIMEOUT // 60} min",
                                    on_fail=bad + " (het token heeft VM.Snapshot.Rollback nodig)",
                                    note="start: 1 = de machine daarna weer starten"))
    return proef.plan(f"{n} terugdraaien naar {snap['name']}", steps,
                      checks=[proef.check(f"snapshot {snap['name']}", True, f"gemaakt {_local(snap.get('at'))}")],
                      skipped=skipped,
                      after=["in het auditlog: updates terugdraaien",
                             f"de run krijgt 'teruggedraaid' en op de tijdlijn '{n}: teruggedraaid naar {snap['name']}'"],
                      warnings=[f"Alles wat sinds de snapshot ({_local(snap.get('at'))}) op {n} veranderde, gaat verloren."])


async def describe_cleanup(db: AsyncSession, http: HttpClients, now: datetime | None = None) -> dict:
    """Proef van cleanup_snapshots: welke eigen snapshots de volgende keer weg zouden gaan, en welke blijven."""
    now = now or datetime.now(timezone.utc)
    cfg = await settings(db)
    keep = cfg["keep_days"]
    todo = await cleanup_todo(db, keep, now)
    d = await defaults(db)
    steps, skipped = [], []
    again = "de snapshot blijft staan; over 6 uur opnieuw"
    for _, snap, tname in todo:
        what = f"{snap['name']} van {tname}"
        c = delsnapshot_call(snap)
        if c["via"] == "ssh":
            h = await db.get(SshHost, snap["host_id"])
            if h is None:
                skipped.append(proef.skip(what, "de node staat niet meer in de terminal: wordt overgeslagen"))
                continue
            login, err = await _login(db, h, d)
            if err:
                skipped.append(proef.skip(what, f"{err}: het opruimen zou hier stoppen"))
                continue
            steps.append(proef.step(proef.ssh_machine(h, login), "ssh", c["cmd"], who=proef.ssh_who(login),
                                    script=command(c["cmd"], login), wait=f"max. {SNAP_TIMEOUT // 60} min",
                                    on_fail=f"{again} (bestaat hij al niet meer, dan telt hij als opgeruimd)"))
        else:
            try:
                px = await _px_service(db, http, snap)
            except IntegrationError as e:
                skipped.append(proef.skip(what, f"{e}: wordt overgeslagen, over 6 uur opnieuw"))
                continue
            steps.append(proef.step(_px_machine(px, snap), "proxmox-api", _api_call(c), who=_px_who(px),
                                    wait=f"tot de Proxmox-taak klaar is, max. {SNAP_TIMEOUT // 60} min", on_fail=again))
    # Wat (nog) blijft staan, met de reden: uit de laatste 200 runs.
    ids = {run_id for run_id, _, _ in todo}
    for r in (await db.execute(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(200))).scalars():
        s = r.snapshot or {}
        if r.id in ids or not str(s.get("name") or "").startswith(SNAP_PREFIX) or s.get("removed_at"):
            continue
        if r.status in ("ok", "teruggedraaid"):
            why = (f"nog geen {keep} dagen oud: gaat weg na {_local(r.finished_at + timedelta(days=keep))}"
                   if r.finished_at else "de run is nog niet klaar")
        elif r.status in DONE:
            why = f"run '{r.status}': alleen snapshots van geslaagde runs worden opgeruimd"
        else:
            why = "de run loopt nog"
        skipped.append(proef.skip(f"{s['name']} van {r.target_name}", why))
    notes = ["Opruimen staat op alleen proef: er wordt niets verwijderd."] if cfg.get("cleanup_proef") else []
    return proef.plan(f"Eigen snapshots van updates opruimen (ouder dan {keep} dagen)", steps,
                      checks=[proef.check(f"bewaren: {keep} dagen", True,
                                          f"snapshots van geslaagde runs van voor {_local(now - timedelta(days=keep))}")],
                      skipped=skipped,
                      after=["per opgeruimde snapshot: de run toont '(opgeruimd)' en terugdraaien kan niet meer"] if steps else [],
                      warnings=notes,
                      snapshots=[{"run": run_id, "name": snap["name"], "target": tname} for run_id, snap, tname in todo])
