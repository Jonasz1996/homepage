"""Alle machines scannen en de jobs, runs en meldingen bijwerken.

Elke SSH-host met een bevestigde hostsleutel krijgt het probe-script; een Proxmox-node scant ook zijn
draaiende containers (pct exec), behalve containers die al zelf als SSH-host gescand worden. Jobs die
cluster-breed gelden (Proxmox-back-ups, replicatie) komen één keer in de lijst, met de taken van alle nodes.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import event, notify
from ..models import AppState, CronJob, CronRun, SshHost
from ..ssh_exec import SshFail, connect, run
from ..ssh_login import Login, defaults, login_for
from . import links, probe
from .schedule import BadSchedule, next_after, parse_calendar, parse_cron, per_day, prev_before, tz_of

log = logging.getLogger("homepage.cron")

CRON_EVERY = 15 * 60
STATE_KEY = "cron"
KEEP_RUNS = timedelta(days=60)
KEEP_REMOVED = timedelta(days=30)
# Jobs die vaker lopen dan dit per dag: geen aparte run per keer uit de cronlog (wel teller en laatste keer).
MAX_LOGGED_PER_DAY = 48
PARALLEL = 8
SCAN_TIMEOUT = 600

_LXC_SOURCE = re.compile(r":lxc/(\d+)$")


def spec_of(job: CronJob | dict):
    st = job["sched_type"] if isinstance(job, dict) else job.sched_type
    sc = job["schedule"] if isinstance(job, dict) else job.schedule
    try:
        if st == "cron":
            return parse_cron(sc)
        if st == "calendar":
            return parse_calendar(sc)
    except BadSchedule:
        return None
    return None


# --- Scannen ------------------------------------------------------------------------------

def _machine(key: str, name: str, h: SshHost, vmid: int | None = None, **kw) -> dict:
    return {"key": key, "name": name, "host_id": h.id, "host": h.host, "ssh_name": h.name, "vmid": vmid,
            "node": h.name if vmid is not None else None, "error": None, "jobs": [], "runs": [], "cronlog": [],
            "log_ok": False, "tz": "UTC", "hostname": "", "pve": {}, "pbs": {}, **kw}


async def scan_host(h: SshHost, login: Login, skip_cts: set[int]) -> list[dict]:
    base = f"ssh:{h.id}"
    try:
        async with connect(h, login) as conn:
            rc, out, err = await run(conn, probe.script(skip_cts), login, timeout=SCAN_TIMEOUT)
            if "@@HOST" not in out:
                msg = (err.strip().splitlines() or [f"exitcode {rc}"])[-1]
                if "sudo" in msg:
                    msg = f"{login.username} mag geen sudo zonder wachtwoord: {msg}"
                return [_machine(base, h.name, h, error=msg[:300])]
            machines = []
            for kind, name, text in probe.split_machines(out):
                if kind == "host":
                    m = _machine(base, h.name, h)
                else:
                    vmid_s, _, ct_name = (name or "").partition(" ")
                    if not vmid_s.isdigit():
                        continue
                    m = _machine(f"{base}:ct:{vmid_s}", ct_name or f"CT {vmid_s}", h, int(vmid_s))
                p = probe.parse(text, m["key"])
                m.update(jobs=p["jobs"], runs=p["runs"], cronlog=p["cronlog"], log_ok=p["log_ok"],
                         tz=p["meta"]["tz"], hostname=p["meta"]["hostname"], pve=p["pve"], pbs=p["pbs"])
                machines.append(m)
            # Tweede ronde: de scripts die jobs aanroepen, om ook daarin naar doelen te zoeken.
            for m in machines:
                paths = probe.script_paths(m["jobs"])
                if not paths:
                    continue
                try:
                    _, sout, _ = await run(conn, probe.read_scripts(paths), login, m["vmid"], timeout=60)
                except SshFail:
                    continue
                scripts = probe.parse_scripts(sout)
                for j in m["jobs"]:
                    if j["kind"] not in ("cron", "timer"):
                        continue
                    texts = [(p, t) for p, t in scripts.items() if p in j["command"] or
                             any(p.endswith("/" + s) for s in j.get("extra", {}).get("scripts", []))]
                    if texts:
                        j["extra"]["script_path"] = texts[0][0]
                        j["extra"]["script"] = "\n".join(t for _, t in texts)[:20000]
                        j["targets"] = links.extract(j)
            return machines
    except SshFail as e:
        return [_machine(base, h.name, h, error=str(e))]


async def collect(db: AsyncSession) -> tuple[list[dict], list[dict]]:
    hosts = (await db.execute(select(SshHost).order_by(SshHost.id))).scalars().all()
    d = await defaults(db)
    ready = [h for h in hosts if h.host_key]
    direct_cts = {int(m.group(1)) for h in ready if h.source and (m := _LXC_SOURCE.search(h.source))}
    sem = asyncio.Semaphore(PARALLEL)

    async def one(h: SshHost):
        login = await login_for(db, h, d)
        async with sem:
            return await scan_host(h, login, direct_cts)

    results = await asyncio.gather(*(one(h) for h in ready), return_exceptions=True)
    machines: list[dict] = []
    for h, r in zip(ready, results):
        if isinstance(r, BaseException):
            log.warning("cronscan van %s mislukt: %r", h.name, r)
            machines.append(_machine(f"ssh:{h.id}", h.name, h, error=type(r).__name__))
        else:
            machines.extend(r)
    via_node = {m["vmid"] for m in machines if m["vmid"] is not None and not m["error"]}
    pending = [{"host_id": h.id, "name": h.name, "host": h.host} for h in hosts if not h.host_key and not (
        h.source and (m := _LXC_SOURCE.search(h.source)) and int(m.group(1)) in via_node)]
    return machines, pending


# --- Opslaan ---------------------------------------------------------------------------------

def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt and dt.tzinfo is None else dt


def _cluster_target(machines: list[dict]) -> dict[str, tuple[str, str]]:
    """Proxmox-cluster-id → (target, naam). Eén node zonder cluster: die node zelf."""
    out = {}
    for m in machines:
        if m["pve"]:
            cid = probe._cluster_id(m["pve"])
            nodes = [s for s in m["pve"].get("status") or [] if isinstance(s, dict) and s.get("type") == "node"]
            if cid != m["pve"].get("node") and len(nodes) > 1:
                out.setdefault(cid, (f"pve:{cid}", f"cluster {cid}"))
            else:
                out.setdefault(cid, (m["key"], m["name"]))
    return out


class Store:
    def __init__(self, db: AsyncSession, now: datetime):
        self.db = db
        self.now = now
        self.alerts: list[tuple[CronJob, str | None, str | None]] = []

    async def run_rows(self, job: CronJob) -> dict[datetime, CronRun]:
        rows = (await self.db.execute(select(CronRun).where(
            CronRun.job_id == job.id, CronRun.started_at >= self.now - timedelta(days=3)))).scalars().all()
        return {_aware(r.started_at).replace(microsecond=0): r for r in rows}

    async def add_run(self, job: CronJob, existing: dict, started: datetime, **kw) -> None:
        started = started.replace(microsecond=0)
        # Cron en de wrapper loggen dezelfde start soms een seconde verschillend.
        row = existing.get(started) or existing.get(started - timedelta(seconds=1)) or existing.get(started + timedelta(seconds=1))
        if row:
            for k, v in kw.items():
                if v is not None and (k != "status" or row.status in ("gestart", "bezig")):
                    setattr(row, k, v)
            return
        row = CronRun(job_id=job.id, started_at=started, **kw)
        self.db.add(row)
        existing[started] = row


def _set(job: CronJob, d: dict) -> None:
    for k in ("kind", "source", "user", "schedule", "sched_type", "command", "raw", "name", "enabled", "system",
              "targets", "extra"):
        if k in d:
            setattr(job, k, d[k])


async def store(db: AsyncSession, machines: list[dict], pending: list[dict]) -> dict:
    now = datetime.now(timezone.utc)
    st = Store(db, now)
    state = await db.get(AppState, STATE_KEY)
    known_targets = {t["key"] for t in (state.value.get("targets", []) if state else [])}
    existing = {j.key: j for j in (await db.execute(select(CronJob))).scalars()}
    clusters = _cluster_target(machines)
    seen: dict[str, CronJob] = {}
    scanned_targets: set[str] = set()
    added, removed, changed = [], [], []
    pve_tasks: dict[str, list[dict]] = {}

    for m in machines:
        if m["error"]:
            continue
        scanned_targets.add(m["key"])
        for d in m["jobs"]:
            target, tname = m["key"], m["name"]
            if d.get("cluster"):
                cid = d["key"].split(":")[1]
                target, tname = clusters.get(cid, (target, tname))
                scanned_targets.add(target)
                pve_tasks.setdefault(d["key"], []).extend(d.get("pve_tasks") or [])
                if d["key"] in seen:
                    seen[d["key"]].extra = {**seen[d["key"]].extra, "nodes_seen": sorted(
                        set(seen[d["key"]].extra.get("nodes_seen", [])) | set(d["extra"].get("nodes_seen", [])))}
                    continue
            job = existing.get(d["key"])
            if job is None:
                job = CronJob(key=d["key"], target=target, target_name=tname, first_seen=now, monitored=False,
                              muted=False, runs_24h=0)
                db.add(job)
                existing[d["key"]] = job
                if target in known_targets:
                    added.append(job)
            elif job.removed_at:
                job.removed_at = None
                added.append(job)
            _set(job, d)
            job.target, job.target_name = target, tname
            job.host_id, job.vmid, job.tz = m["host_id"], m["vmid"] if not d.get("cluster") else None, m["tz"]
            job.monitored = bool(d.get("monitored"))
            job.wid = d.get("wid") or job.wid
            job.last_seen = now
            for k in ("next_run_at", "last_run_at", "last_status", "last_exit", "last_duration"):
                if d.get(k) is not None:
                    setattr(job, k, d[k])
            seen[d["key"]] = job
    await db.flush()

    # Verdwenen jobs (alleen op machines die deze keer wel gescand zijn).
    for key, job in existing.items():
        if key not in seen and job.removed_at is None and job.target in scanned_targets:
            job.removed_at = now
            removed.append(job)
    # Zelfde commando met een ander schema = gewijzigd, niet weg + nieuw.
    for r in list(removed):
        for a in list(added):
            if a.target == r.target and a.source == r.source and a.command == r.command and a.kind == r.kind:
                changed.append((r, a))
                removed.remove(r)
                added.remove(a)
                break

    by_machine = {m["key"]: m for m in machines if not m["error"]}
    for job in seen.values():
        m = by_machine.get(job.target) or next((x for x in machines if x["host_id"] == job.host_id and x["vmid"] is None), None)
        await _runs(st, job, m or {}, pve_tasks.get(job.key, []))

    for r, a in changed:
        event(db, "cron", f"{a.target_name}: schema van {a.name} gewijzigd", f"{r.schedule} → {a.schedule}",
              data={"job_id": a.id})
    for a in added:
        if not a.system:
            event(db, "cron", f"{a.target_name}: nieuwe job {a.name}", f"{a.schedule}  {a.command[:300]}",
                  data={"job_id": a.id})
    for r in removed:
        if not r.system:
            event(db, "cron", f"{r.target_name}: job {r.name} verdwenen", r.command[:300], data={"job_id": r.id})
    for job, old, new in st.alerts:
        _alert(db, job, old, new)

    await db.execute(delete(CronRun).where(CronRun.started_at < now - KEEP_RUNS))
    await db.execute(delete(CronJob).where(CronJob.removed_at.is_not(None), CronJob.removed_at < now - KEEP_REMOVED))

    value = {
        "scanned_at": now.isoformat(),
        "targets": [{k: m[k] for k in ("key", "name", "host_id", "host", "ssh_name", "vmid", "node", "error",
                                       "log_ok", "tz", "hostname")} | {"jobs": len(m["jobs"]),
                                                                        "pve": _pve_meta(m["pve"]),
                                                                        "pbs": bool(m["pbs"])}
                    for m in machines],
        "clusters": {cid: {"target": t, "name": n} for cid, (t, n) in clusters.items()},
        "pending": pending,
    }
    state = await db.get(AppState, STATE_KEY)
    if state:
        state.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value


def _pve_meta(pve: dict) -> dict | None:
    if not pve:
        return None
    nodes = [{"name": s.get("name"), "ip": s.get("ip"), "online": bool(s.get("online"))}
             for s in pve.get("status") or [] if isinstance(s, dict) and s.get("type") == "node"]
    return {"node": pve.get("node"), "cluster": probe._cluster_id(pve), "nodes": nodes,
            "storage": [{"storage": s.get("storage"), "type": s.get("type"), "server": s.get("server"),
                         "datastore": s.get("datastore")} for s in pve.get("storage") or [] if isinstance(s, dict)]}


async def _runs(st: Store, job: CronJob, m: dict, tasks: list[dict]) -> None:
    now = st.now
    old_status = job.last_status
    spec = spec_of(job)
    tz = tz_of(job.tz)
    existing = await st.run_rows(job)

    if job.kind == "cron":
        times = sorted(t for t, user, cmd in m.get("cronlog", []) if user == job.user and cmd in (job.raw, job.command))
        job.runs_24h = sum(1 for t in times if t > now - timedelta(hours=24))
        frequent = spec is not None and per_day(spec) > MAX_LOGGED_PER_DAY
        wraps = [r for r in m.get("runs", []) if job.wid and r["wid"] == job.wid]
        if times:
            job.last_run_at = max(times[-1], _aware(job.last_run_at) or times[-1])
            if not wraps:
                job.last_status = "gestart" if job.last_status not in ("ok", "fout") or not job.monitored else job.last_status
        if not frequent and not wraps:
            for t in times:
                await st.add_run(job, existing, t, status="gestart", trigger="schema")
        for r in sorted(wraps, key=lambda r: r["started_at"]):
            status = "ok" if r["exit_code"] == 0 else "fout"
            await st.add_run(job, existing, r["started_at"], ended_at=r["ended_at"], exit_code=r["exit_code"],
                             status=status, trigger="schema", output=r["output"])
            job.last_run_at, job.last_status, job.last_exit = r["started_at"], status, r["exit_code"]
            job.last_duration = (r["ended_at"] - r["started_at"]).total_seconds() if r["ended_at"] else None
        # Gemist: de cronlog werkt op deze machine, maar de laatste geplande keer staat er niet in.
        if spec and job.enabled and not job.system and m.get("log_ok"):
            exp = prev_before(spec, now - timedelta(minutes=3), tz)
            first = _aware(job.first_seen)
            if exp and exp > max(first, now - timedelta(hours=probe.LOG_HOURS - 2)):
                starts = times + [r["started_at"] for r in wraps]
                hit = any(exp - timedelta(minutes=2) <= t <= exp + timedelta(minutes=10) for t in starts)
                if not hit:
                    job.last_status = "gemist"
                elif job.last_status == "gemist":
                    job.last_status = "ok" if wraps and wraps[-1]["exit_code"] == 0 else "gestart"
    elif job.kind == "timer":
        ex = job.extra or {}
        if job.last_run_at and ex.get("started"):
            started = datetime.fromisoformat(ex["started"])
            ended = datetime.fromisoformat(ex["ended"]) if ex.get("ended") else None
            await st.add_run(job, existing, started, ended_at=ended, exit_code=job.last_exit,
                             status=job.last_status or "gestart", trigger="schema", output=ex.get("output"))
    elif job.kind == "pve-backup":
        await _pve_backup_runs(st, job, existing, tasks, spec, tz)
    elif job.kind == "pve-repl":
        if job.last_run_at:
            await st.add_run(job, existing, _aware(job.last_run_at), status=job.last_status or "ok", trigger="schema",
                             output=(job.extra or {}).get("error"))
    elif job.kind.startswith("pbs-"):
        d = next((x for x in m.get("jobs", []) if x["key"] == job.key), {})
        tl = sorted(d.get("pbs_tasks") or [], key=lambda t: t["started_at"])
        for t in tl[-30:]:
            await st.add_run(job, existing, t["started_at"], ended_at=t["ended_at"], status=t["status"],
                             trigger="schema", output=t["output"])
        if tl:
            last = tl[-1]
            job.last_run_at, job.last_status = last["started_at"], last["status"]
            job.last_duration = (last["ended_at"] - last["started_at"]).total_seconds() if last["ended_at"] else None
        job.runs_24h = sum(1 for t in tl if t["started_at"] > now - timedelta(hours=24))

    if job.sched_type == "interval" and job.last_run_at and not job.next_run_at:
        try:
            job.next_run_at = _aware(job.last_run_at) + timedelta(seconds=float(job.schedule))
        except ValueError:
            pass
    elif spec and job.kind not in ("timer", "pve-repl"):
        job.next_run_at = next_after(spec, now, tz) if job.enabled else None
    if not job.enabled:
        job.next_run_at = None

    if old_status != job.last_status:
        st.alerts.append((job, old_status, job.last_status))


async def _pve_backup_runs(st: Store, job: CronJob, existing: dict, tasks: list[dict], spec, tz) -> None:
    """vzdump-taken horen bij deze job als ze vlak na een geplande keer starten (per node één taak)."""
    now = st.now
    if not spec:
        return
    node = (job.extra or {}).get("node")
    groups: dict[tuple[str, datetime], list[dict]] = {}
    for t in tasks:
        if node and t["node"] != node:
            continue
        sched = prev_before(spec, t["started_at"] + timedelta(seconds=90), tz, horizon_days=2)
        if sched and t["started_at"] - sched <= timedelta(minutes=20):
            groups.setdefault((t["node"], sched), []).append(t)
    last = None
    for (n, sched), ts in sorted(groups.items(), key=lambda kv: kv[0][1]):
        first = min(ts, key=lambda t: t["started_at"])
        ends = [t["ended_at"] for t in ts if t["ended_at"]]
        bad = [t for t in ts if t["status"] == "fout"]
        running = any(t["status"] == "bezig" for t in ts)
        status = "bezig" if running else "fout" if bad else "ok"
        out = "; ".join(f"{n}: {t['output'] or 'bezig'}" for t in ts)[:4000]
        await st.add_run(job, existing, first["started_at"], ended_at=max(ends) if ends and not running else None,
                         status=status, trigger="schema", output=out)
        if last is None or first["started_at"] >= last[0]:
            last = (first["started_at"], status, (max(ends) - first["started_at"]).total_seconds() if ends else None)
    job.runs_24h = sum(1 for (_, s) in groups if s > now - timedelta(hours=24))
    if last:
        job.last_run_at, job.last_status, job.last_duration = last
    exp = prev_before(spec, now - timedelta(minutes=30), tz)
    if job.enabled and exp and exp > _aware(job.first_seen) and tasks:
        if not any(exp - timedelta(minutes=2) <= t["started_at"] <= exp + timedelta(hours=3) for t in tasks):
            job.last_status = "gemist"


def _alert(db: AsyncSession, job: CronJob, old: str | None, new: str | None) -> None:
    if job.system or job.muted or old is None and new not in ("fout", "gemist"):
        return
    name = job.alias or job.name
    where = job.target_name
    if new == "fout":
        why = f"exitcode {job.last_exit}" if job.last_exit not in (None, 0) else (job.extra or {}).get("error") or ""
        notify(db, f"Cronjob mislukt: {name} op {where}", why or None, level="err", source="cron",
               data={"job_id": job.id})
    elif new == "gemist":
        notify(db, f"Cronjob niet gelopen: {name} op {where}",
               "De laatste geplande keer staat niet in de log. Stond de machine uit, of is cron gestopt?",
               level="warn", source="cron", data={"job_id": job.id})
    elif new == "ok" and old in ("fout", "gemist"):
        event(db, "cron", f"{name} op {where} loopt weer goed", level="ok", data={"job_id": job.id})


async def run_scan(db: AsyncSession) -> dict:
    machines, pending = await collect(db)
    return await store(db, machines, pending)
