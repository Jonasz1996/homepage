"""Updates installeren vanuit het dashboard: eerst een snapshot, dan apt, dan kijken of de services nog leven.

Waar kan een snapshot?
- een container op een node ("ssh:3:ct:105"): `pct snapshot` via SSH op de node, geen extra API-rechten;
- een SSH-host die zelf een VM of CT uit Proxmox is (bron "pve:1:lxc/105"): via de Proxmox-API (VM.Snapshot);
- een fysieke node of een andere machine: geen snapshot. Dat moet je dan bewust aanvinken.

Lukt de installatie niet, of is een service daarna down, dan kan je met één klik terug naar de snapshot.
's Nachts automatisch kan ook, alleen voor beveiligingsupdates en alleen waar een snapshot kan; gaat het daar
mis, dan draait de homepage zelf terug.
"""

import asyncio
import logging
import re
import shlex
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from urllib.parse import quote, urlsplit

import asyncssh
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..deps import event, notify
from ..integrations import IntegrationError, build
from ..models import AppState, Service, SshHost, UpdateRun
from ..ssh_exec import SshFail, command, connect, run
from ..ssh_login import defaults, login_for
from .checks import HttpClients, run_check

log = logging.getLogger("homepage.upgrade")

SNAP_PREFIX = "hp-upd-"
SETTINGS_KEY = "update_settings"
AUTO_KEY = "update_auto_last"
DEFAULTS = {"auto": False, "hour": 4, "keep_days": 7}
INSTALL_TIMEOUT = 1800
CHECK_WAIT = 20
CHECK_RETRIES = 3
CHECK_GAP = 10
MAX_OUTPUT = 60000
DONE = ("ok", "fout", "services_down", "teruggedraaid", "terugdraaien_mislukt", "geannuleerd")
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
        h = h or (await db.execute(select(SshHost).where(SshHost.name.ilike(node)))).scalars().first()
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


def script(packages: list[str] | None) -> str:
    pk = " ".join(p for p in (packages or []) if PKG_RE.match(p))
    return f"PKGS={shlex.quote(pk)}\n{INSTALL}"


def security_packages(updates_state: dict | None, key: str) -> list[str]:
    for t in (updates_state or {}).get("targets", []):
        if t["key"] == key:
            return [p["n"] for p in t.get("packages", []) if p.get("sec") and PKG_RE.match(p.get("n") or "")]
    return []


# --- Proxmox ---------------------------------------------------------------------------------

async def _px_guest(db: AsyncSession, http: HttpClients, snap: dict):
    svc = await db.get(Service, snap["service_id"])
    if svc is None or svc.type != "proxmox":
        raise IntegrationError("De Proxmox-tegel van deze machine bestaat niet meer")
    px = build(svc, http)
    if not snap.get("node"):
        for r in await px.resources():
            if r.get("vmid") == snap["vmid"] and r.get("type") == snap["type"]:
                snap["node"] = r.get("node")
        if not snap.get("node"):
            raise IntegrationError(f"{snap['type']} {snap['vmid']} niet gevonden in Proxmox")
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
    data = await px.request(method, "/api2/json" + path, headers=px.headers(), **kw)
    return (data or {}).get("data") or ""


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
    desc = f"voor updates via homepage, {datetime.now().strftime('%d/%m/%Y %H:%M')}"
    if snap["kind"] == "pct":
        rn.say(f"$ pct snapshot {plan.vmid} {name}")
        rc, out, err = await run(conn, f"pct snapshot {plan.vmid} {name} --description {shlex.quote(desc)}",
                                 login, timeout=600)
        for line in (out + err).splitlines():
            rn.say(line)
        if rc != 0:
            hint = " (de opslag van deze container kan geen snapshots, bv. 'dir')" if "snapshot feature is not available" in (out + err) else ""
            raise SshFail(f"snapshot mislukt{hint}")
        snap["node"] = plan.host.name
    else:
        px = await _px_guest(db, rn.http, snap)
        rn.say(f"Proxmox: snapshot {name} van {snap['type']} {snap['vmid']} op {snap['node']}")
        try:
            upid = await _px_call(px, "POST", f"/nodes/{snap['node']}/{snap['type']}/{snap['vmid']}/snapshot",
                                  data={"snapname": name, "description": desc})
            await wait_task(px, snap["node"], upid)
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
        if not (s.check or {}).get("type"):
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
        outcomes = await asyncio.gather(*(run_check(s.check, s.url, rn.http) for s in todo))
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
                    snap = await _snapshot(rn, db, plan, conn, login, f"{SNAP_PREFIX}{datetime.now().strftime('%Y%m%d-%H%M%S')}")
                await rn.save(force=True, snapshot=snap, status="installeren")
            rn.say(f"$ apt upgrade{' (alleen beveiliging: ' + ', '.join(packages) + ')' if packages else ''}"
                   f"{f' in CT {plan.vmid}' if plan.vmid else ''}")
            proc = await conn.create_process(command(script(packages), login, plan.vmid), stderr=asyncssh.STDOUT)
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
            v = int(snap["vmid"])
            async with connect(h, login) as conn:
                rc, out, err = await run(conn, f"pct rollback {v} {snap['name']} && "
                                               f"(pct status {v} | grep -q running || pct start {v})", login, timeout=900)
            for line in (out + err).splitlines():
                rn.say(line)
            if rc != 0:
                raise SshFail(f"pct rollback stopte met exitcode {rc}")
        else:
            async with maker() as db:
                px = await _px_guest(db, http, snap)
            try:
                upid = await _px_call(px, "POST", f"/nodes/{snap['node']}/{snap['type']}/{snap['vmid']}/snapshot/"
                                                  f"{snap['name']}/rollback", data={"start": 1})
                await wait_task(px, snap["node"], upid, timeout=900)
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


async def cleanup_snapshots(maker: async_sessionmaker, http: HttpClients) -> int:
    """Eigen snapshots van geslaagde runs na keep_days opruimen; mislukte laten we staan."""
    async with maker() as db:
        keep = (await settings(db))["keep_days"]
        cutoff = datetime.now(timezone.utc) - timedelta(days=keep)
        runs = (await db.execute(select(UpdateRun).where(UpdateRun.status.in_(("ok", "teruggedraaid")),
                                                          UpdateRun.finished_at < cutoff))).scalars().all()
        todo = [(r.id, dict(r.snapshot)) for r in runs
                if r.snapshot and r.snapshot.get("name", "").startswith(SNAP_PREFIX) and not r.snapshot.get("removed_at")]
    n = 0
    for run_id, snap in todo:
        try:
            if snap["kind"] == "pct":
                async with maker() as db:
                    h = await db.get(SshHost, snap["host_id"])
                    login = await login_for(db, h, await defaults(db)) if h else None
                if h is None:
                    continue
                async with connect(h, login) as conn:
                    rc, out, err = await run(conn, f"pct delsnapshot {int(snap['vmid'])} {snap['name']}", login, timeout=600)
                if rc != 0 and "does not exist" not in (out + err):
                    raise SshFail((err or out).strip()[-200:])
            else:
                async with maker() as db:
                    px = await _px_guest(db, http, snap)
                upid = await _px_call(px, "DELETE", f"/nodes/{snap['node']}/{snap['type']}/{snap['vmid']}/snapshot/{snap['name']}")
                await wait_task(px, snap["node"], upid)
        except (SshFail, IntegrationError, OSError, asyncssh.Error) as e:
            log.info("snapshot %s opruimen mislukt: %s", snap.get("name"), e)
            continue
        async with maker() as db:
            r = await db.get(UpdateRun, run_id)
            r.snapshot = {**snap, "removed_at": datetime.now(timezone.utc).isoformat()}
            await db.commit()
        n += 1
    return n


async def create_runs(db: AsyncSession, keys: list[tuple[str, str | None]], security_only: bool, snapshot: bool,
                      trigger: str, user_id: int | None) -> tuple[list[UpdateRun], list[dict]]:
    """Runs aanmaken voor (sleutel, naam); wat niet kan komt terug met de reden."""
    runs, refused = [], []
    for key, name in keys:
        plan = await plan_for(db, key, name)
        name = plan.name
        if not plan.can:
            refused.append({"key": key, "name": name, "why": plan.why})
            continue
        if not plan.snap and snapshot:
            refused.append({"key": key, "name": name, "why": plan.nosnap or "geen snapshot mogelijk",
                            "nosnap": True})
            continue
        busy = (await db.execute(select(UpdateRun.id).where(UpdateRun.target == key,
                                                            UpdateRun.status.not_in(DONE)))).first()
        if busy:
            refused.append({"key": key, "name": name, "why": "er loopt al een installatie"})
            continue
        r = UpdateRun(target=key, target_name=name, trigger=trigger, security_only=security_only, status="wacht",
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
            packages = security_packages(st.value if st else None, r.target) if r.security_only else None
            if r.security_only and not packages:
                r.status, r.error, r.finished_at = "ok", "geen beveiligingsupdates meer open", datetime.now(timezone.utc)
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
        st = await db.get(AppState, "updates")
        keys = [(t["key"], t["name"]) for t in (st.value.get("targets", []) if st else [])
                if t.get("security") and not t.get("error")]
        runs, _ = await create_runs(db, keys, security_only=True, snapshot=True, trigger="auto", user_id=None)
        await db.commit()
        ids = [r.id for r in runs]
    if ids:
        await run_batch(maker, http, ids, auto_rollback=True)
    return ids
