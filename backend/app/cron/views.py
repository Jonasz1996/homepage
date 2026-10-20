"""Wat de cronweergave toont: jobs met hun laatste runs, de agenda met botsingen en de verbanden."""

from datetime import datetime, timedelta, timezone
from statistics import median

from ..models import CronJob, CronRun
from . import links
from .schedule import describe, describe_interval, occurrences, per_day, tz_of
from .scan import _aware, spec_of

RUNNABLE = {"cron", "timer"}
DENSE_PER_DAY = 24


def schedule_text(job: CronJob) -> str:
    if job.sched_type == "reboot":
        return "bij het opstarten"
    if job.sched_type == "interval":
        try:
            return describe_interval(float(job.schedule)) + " (na de vorige keer)"
        except ValueError:
            return job.schedule
    spec = spec_of(job)
    if spec:
        return describe(spec)
    return job.schedule or "niet gepland"


def job_out(job: CronJob, recent: list[CronRun] | None = None, full: bool = False) -> dict:
    ex = job.extra or {}
    out = {
        "id": job.id, "target": job.target, "target_name": job.target_name, "host_id": job.host_id, "vmid": job.vmid,
        "kind": job.kind, "source": job.source, "user": job.user, "schedule": job.schedule, "sched_type": job.sched_type,
        "when": schedule_text(job), "command": job.command if full else job.command[:400], "name": job.alias or job.name,
        "auto_name": job.name, "alias": job.alias, "enabled": job.enabled, "system": job.system,
        "monitored": job.monitored, "wid": job.wid if job.monitored else None, "muted": job.muted, "targets": job.targets or [], "tz": job.tz,
        "next_run_at": job.next_run_at, "last_run_at": job.last_run_at, "last_status": job.last_status,
        "last_exit": job.last_exit, "last_duration": job.last_duration, "runs_24h": job.runs_24h,
        "removed_at": job.removed_at, "first_seen": job.first_seen,
        "can_run": job.kind in RUNNABLE and job.removed_at is None,
        "can_monitor": job.kind == "cron" and job.removed_at is None,
        "description": ex.get("description") or ex.get("what") or "",
        "script_path": ex.get("script_path"),
        "recent": [{"s": r.status, "t": r.started_at, "d": (r.ended_at - r.started_at).total_seconds()
                    if r.ended_at and r.started_at else None} for r in (recent or [])],
    }
    if full:
        out["extra"] = {k: v for k, v in ex.items() if k not in ("output",)}
        out["raw"] = job.raw
    return out


def run_out(r: CronRun) -> dict:
    return {"id": r.id, "started_at": r.started_at, "ended_at": r.ended_at, "exit_code": r.exit_code,
            "status": r.status, "trigger": r.trigger, "output": r.output,
            "duration": (r.ended_at - r.started_at).total_seconds() if r.ended_at else None}


# --- Machines koppelen ----------------------------------------------------------------------

def resolver(state: dict) -> tuple[links.Resolver, dict[str, dict]]:
    """Alle bekende machines (uit de laatste scan) + Proxmox-nodes, met hun namen en IP's."""
    res = links.Resolver()
    machines: dict[str, dict] = {}
    targets = state.get("targets", [])
    for t in targets:
        machines[t["key"]] = {"id": t["key"], "label": t["name"], "kind": "ct" if t.get("vmid") is not None else "machine",
                              "node": t.get("node"), "vmid": t.get("vmid"), "error": t.get("error")}
        names = [t["name"], t.get("hostname")]
        if t.get("vmid") is None:
            names += [t.get("host"), t.get("ssh_name")]
        res.add(t["key"], *names)
        if t.get("vmid") is not None:
            res.add(t["key"], f"vmid:{t['vmid']}")
    for t in targets:
        for n in (t.get("pve") or {}).get("nodes", []):
            mid = res.find(n.get("name"))
            if not mid:
                mid = f"pvenode:{n['name']}"
                machines.setdefault(mid, {"id": mid, "label": n["name"], "kind": "machine", "node": None})
                res.add(mid, n.get("name"))
            res.add(mid, n.get("ip"))
    for cid, c in (state.get("clusters") or {}).items():
        if c["target"] not in machines:
            machines[c["target"]] = {"id": c["target"], "label": c["name"], "kind": "cluster"}
    return res, machines


def _target_node(t: dict, res: links.Resolver, machines: dict, storage: dict[str, dict]) -> str | None:
    ty, ref = t.get("type"), str(t.get("ref") or "")
    if ty in ("path",):
        return None
    if ty == "guest":
        return res.find(f"vmid:{ref}")
    if ty == "storage":
        st = storage.get(ref)
        if st and st.get("server"):
            return res.find(st["server"]) or _ext(machines, "host", st["server"], st["server"])
        return _ext(machines, "storage", ref, f"storage {ref}")
    mid = res.find(ref)
    if mid:
        return mid
    label = {"ping": f"heartbeat {ref}", "cloud": f"cloud: {ref}", "web": ref}.get(ty, ref)
    return _ext(machines, ty, ref, label)


def _ext(machines: dict, ty: str, ref: str, label: str) -> str:
    mid = f"ext:{ty}:{ref.lower()}"
    machines.setdefault(mid, {"id": mid, "label": label, "kind": "external", "type": ty})
    return mid


def _storage_map(state: dict) -> dict[str, dict]:
    out = {}
    for t in state.get("targets", []):
        for s in (t.get("pve") or {}).get("storage", []):
            if s.get("storage"):
                out.setdefault(s["storage"], s)
    return out


def edges_for(job: CronJob, res: links.Resolver, machines: dict, storage: dict) -> list[dict]:
    ex = job.extra or {}
    src = job.target
    if job.kind == "pve-repl":
        a = res.find(ex.get("source_node")) or src
        b = res.find(ex.get("target")) or _ext(machines, "host", str(ex.get("target")), str(ex.get("target")))
        return [{"from": a, "to": b, "via": "replicatie", "label": f"CT/VM {ex.get('guest')}"}]
    out = []
    for t in job.targets or []:
        if t.get("type") == "datastore":
            continue
        dst = _target_node(t, res, machines, storage)
        if not dst or dst == src:
            continue
        a, b = (dst, src) if t.get("dir") == "in" else (src, dst)
        out.append({"from": a, "to": b, "via": t.get("via") or job.kind, "label": t.get("label") or ""})
    return out


def graph(jobs: list[CronJob], state: dict) -> dict:
    res, machines = resolver(state)
    storage = _storage_map(state)
    edges, badges = [], {}
    for j in jobs:
        if j.removed_at:
            continue
        for e in edges_for(j, res, machines, storage):
            edges.append({**e, "job": j.id, "name": j.alias or j.name, "when": schedule_text(j), "status": j.last_status,
                          "kind": j.kind, "enabled": j.enabled})
        if j.kind in ("pbs-verify", "pbs-gc", "pbs-prune"):
            badges.setdefault(j.target, []).append({"job": j.id, "name": j.alias or j.name, "when": schedule_text(j),
                                                     "status": j.last_status})
    used = {e["from"] for e in edges} | {e["to"] for e in edges} | set(badges)
    # Containers bij hun node (zo zie je de cluster), ook als ze zelf geen verbanden hebben.
    nodes = [m for k, m in machines.items() if k in used]
    return {"nodes": nodes, "edges": edges, "badges": badges,
            "machines": sorted(machines.values(), key=lambda m: (m.get("kind") != "cluster", m.get("label") or ""))}


# --- Agenda ----------------------------------------------------------------------------

def _duration(job: CronJob, runs: list[CronRun]) -> float:
    ds = [(r.ended_at - r.started_at).total_seconds() for r in runs if r.ended_at and r.started_at]
    if ds:
        return max(30.0, median(ds))
    if job.last_duration:
        return max(30.0, job.last_duration)
    return links.default_duration(job.kind, {t.get("via") for t in job.targets or []})


def resources(job: CronJob, res: links.Resolver, machines: dict, storage: dict) -> set[str]:
    # Replicatie is incrementeel en kort: die telt niet mee voor botsingen.
    heavy = job.kind in ("pve-backup", "pbs-sync", "pbs-verify", "pbs-gc", "pbs-prune") or any(t.get("via") in links.HEAVY_VIA for t in job.targets or [])
    if not heavy:
        return set()
    out = {f"m:{job.target}"}
    ex = job.extra or {}
    for t in job.targets or []:
        if t.get("type") == "datastore":
            out.add(f"ds:{job.target}/{ex.get('store')}")
            continue
        mid = _target_node(t, res, machines, storage)
        if mid:
            out.add(f"m:{mid}")
            if t.get("datastore"):
                out.add(f"ds:{mid}/{t['datastore']}")
    if job.kind == "pbs-sync":
        out.add(f"ds:{job.target}/{ex.get('store')}")
    return out


def agenda(jobs: list[CronJob], runs: dict[int, list[CronRun]], state: dict, hours: int,
           with_system: bool = False) -> dict:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    start = now - timedelta(hours=1)
    end = now + timedelta(hours=hours)
    res, machines = resolver(state)
    storage = _storage_map(state)
    rows: dict[str, dict] = {}
    occ_all = []
    for j in jobs:
        if j.removed_at or not j.enabled or (j.system and not with_system):
            continue
        dur = _duration(j, runs.get(j.id, []))
        row = rows.setdefault(j.target, {"target": j.target, "name": j.target_name, "items": [], "dense": []})
        spec = spec_of(j)
        if spec is not None:
            if per_day(spec) > DENSE_PER_DAY:
                row["dense"].append({"job": j.id, "name": j.alias or j.name, "when": schedule_text(j)})
                continue
            times = occurrences(spec, start, end, tz_of(j.tz), limit=400)
        elif j.sched_type == "interval" and j.next_run_at:
            step = float(j.schedule)
            if step < 86400 / DENSE_PER_DAY:
                row["dense"].append({"job": j.id, "name": j.alias or j.name, "when": schedule_text(j)})
                continue
            t, times = _aware(j.next_run_at), []
            while t < end and len(times) < 400:
                if t >= start:
                    times.append(t)
                t += timedelta(seconds=step)
        elif j.next_run_at and start <= _aware(j.next_run_at) < end:
            times = [_aware(j.next_run_at)]
        else:
            continue
        rs = resources(j, res, machines, storage)
        for t in times:
            item = {"job": j.id, "name": j.alias or j.name, "kind": j.kind, "start": t,
                    "end": t + timedelta(seconds=dur), "status": j.last_status, "heavy": bool(rs)}
            row["items"].append(item)
            if rs:
                occ_all.append({**item, "res": rs})
    found = links.conflicts(occ_all)
    names = {m["id"]: m["label"] for m in machines.values()}
    for c in found:
        kind, _, ref = c["on"].partition(":")
        if kind == "ds":
            mid, _, ds = ref.rpartition("/")
            c["on_label"] = f"datastore {ds} op {names.get(mid, mid)}"
        else:
            c["on_label"] = names.get(ref, ref)
    return {"start": start, "end": end, "now": now,
            "rows": sorted((r for r in rows.values() if r["items"] or r["dense"]), key=lambda r: r["name"].lower()),
            "conflicts": found, "busy": links.busy_hours(occ_all, start, hours + 1)}
