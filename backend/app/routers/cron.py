"""Cronjobs van alle machines: overzicht, agenda, verbanden, bewaken, nu uitvoeren en live meekijken."""

import asyncio
import contextlib
import json
import logging
import shlex
from datetime import datetime, timedelta, timezone

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..cron import views, wrap
from ..cron.probe import wid_for
from ..cron.scan import STATE_KEY, run_scan, spec_of
from ..cron.schedule import occurrences, tz_of
from ..db import get_db
from ..deps import audit, current_user, recent_auth
from ..models import AppState, AuditLog, CronJob, CronRun, SshHost, User
from ..ssh_exec import SshFail, command as ssh_command, connect, run
from ..ssh_login import login_for
from .ssh import _send, _ws_user

router = APIRouter(prefix="/api/cron", tags=["cron"])
log = logging.getLogger("homepage.api")

RECENT = 14
MAX_OUTPUT = 16000
RUN_TIMEOUT = 3600

_scan: asyncio.Task | None = None


async def _state(db: AsyncSession) -> dict:
    st = await db.get(AppState, STATE_KEY)
    return dict(st.value) if st else {}


async def _recent(db: AsyncSession, days: int = 14) -> dict[int, list[CronRun]]:
    rows = (await db.execute(select(CronRun).where(
        CronRun.started_at >= datetime.now(timezone.utc) - timedelta(days=days)).order_by(CronRun.started_at.desc()))).scalars()
    out: dict[int, list[CronRun]] = {}
    for r in rows:
        lst = out.setdefault(r.job_id, [])
        if len(lst) < RECENT:
            lst.append(r)
    return out


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    state = await _state(db)
    jobs = (await db.execute(select(CronJob).order_by(CronJob.target_name, CronJob.kind, CronJob.name))).scalars().all()
    recent = await _recent(db)
    out = [views.job_out(j, list(reversed(recent.get(j.id, [])))) for j in jobs]
    active = [j for j in jobs if not j.removed_at and not j.system]
    counts: dict[str, dict] = {}
    for j in jobs:
        if j.removed_at:
            continue
        c = counts.setdefault(j.target, {"jobs": 0, "system": 0, "fout": 0, "gemist": 0})
        c["system" if j.system else "jobs"] += 1
        if not j.system and j.last_status in ("fout", "gemist"):
            c[j.last_status] += 1
    targets = state.get("targets", [])
    for cid, c in (state.get("clusters") or {}).items():
        if not any(t["key"] == c["target"] for t in targets):
            targets = [{"key": c["target"], "name": c["name"], "cluster": True, "error": None}] + targets
    for t in targets:
        t["counts"] = counts.get(t["key"], {"jobs": 0, "system": 0, "fout": 0, "gemist": 0})
    upcoming = sorted((j for j in active if j.next_run_at and j.enabled), key=lambda j: views._aware(j.next_run_at))[:6]
    return {
        "scanned_at": state.get("scanned_at"), "running": bool(_scan and not _scan.done()),
        "targets": targets, "pending": state.get("pending", []), "jobs": out,
        "summary": {"jobs": len(active), "fout": sum(1 for j in active if j.last_status == "fout"),
                    "gemist": sum(1 for j in active if j.last_status == "gemist"),
                    "monitored": sum(1 for j in active if j.monitored),
                    "upcoming": [{"id": j.id, "name": j.alias or j.name, "target_name": j.target_name,
                                  "at": j.next_run_at} for j in upcoming]},
    }


@router.get("/summary")
async def summary(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Voor de knop in de titelbalk: hoeveel jobs er mislukten of niet liepen."""
    rows = (await db.execute(select(CronJob.last_status).where(
        CronJob.removed_at.is_(None), CronJob.system.is_(False), CronJob.muted.is_(False),
        CronJob.last_status.in_(("fout", "gemist"))))).scalars().all()
    return {"fout": rows.count("fout"), "gemist": rows.count("gemist")}


async def _run_scan(session_factory) -> None:
    gen = session_factory()
    try:
        db = await anext(gen)
        await run_scan(db)
        await db.commit()
    except Exception:
        log.exception("cronjobs scannen mislukt")
    finally:
        await gen.aclose()


@router.post("/scan", status_code=status.HTTP_202_ACCEPTED)
async def scan(request: Request, user: User = Depends(current_user)):
    global _scan
    if _scan and not _scan.done():
        raise HTTPException(status.HTTP_409_CONFLICT, "Er loopt al een scan")
    _scan = asyncio.create_task(_run_scan(request.app.dependency_overrides.get(get_db, get_db)))
    return {"ok": True}


@router.get("/agenda")
async def agenda(hours: int = 24, system: bool = False, user: User = Depends(current_user),
                 db: AsyncSession = Depends(get_db)):
    hours = min(max(hours, 1), 168)
    jobs = (await db.execute(select(CronJob).where(CronJob.removed_at.is_(None)))).scalars().all()
    return views.agenda(jobs, await _recent(db, 30), await _state(db), hours, system)


@router.get("/graph")
async def graph(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    jobs = (await db.execute(select(CronJob).where(CronJob.removed_at.is_(None)))).scalars().all()
    return views.graph(jobs, await _state(db))


async def _job(db: AsyncSession, job_id: int) -> CronJob:
    job = await db.get(CronJob, job_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Job niet gevonden")
    return job


@router.get("/jobs/{job_id}")
async def job_detail(job_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    job = await _job(db, job_id)
    runs = (await db.execute(select(CronRun).where(CronRun.job_id == job.id)
                             .order_by(CronRun.started_at.desc()).limit(60))).scalars().all()
    out = views.job_out(job, list(reversed(runs[:RECENT])), full=True)
    out["runs"] = [views.run_out(r) for r in runs]
    spec = spec_of(job)
    now = datetime.now(timezone.utc)
    out["next"] = occurrences(spec, now, now + timedelta(days=40), tz_of(job.tz), limit=5) if spec and job.enabled else []
    ok = [r for r in runs if r.status == "ok"]
    out["stats"] = {"runs": len(runs), "ok": len(ok), "fout": sum(1 for r in runs if r.status == "fout"),
                    "avg_s": round(sum(r_d for r in ok if (r_d := views.run_out(r)["duration"]) is not None) /
                                   max(1, sum(1 for r in ok if r.ended_at)), 1) if ok else None}
    return out


class JobPatch(BaseModel):
    alias: str | None = Field(default=None, max_length=120)
    muted: bool | None = None


@router.patch("/jobs/{job_id}")
async def patch_job(job_id: int, body: JobPatch, request: Request, user: User = Depends(current_user),
                    db: AsyncSession = Depends(get_db)):
    job = await _job(db, job_id)
    if "alias" in body.model_fields_set:
        job.alias = (body.alias or "").strip() or None
    if body.muted is not None:
        job.muted = body.muted
    await audit(db, request, user, "cron_job_changed", job=job.name, target=job.target_name,
                alias=job.alias, muted=job.muted)
    await db.commit()
    return views.job_out(job)


async def _host(db: AsyncSession, job: CronJob) -> SshHost:
    h = await db.get(SshHost, job.host_id) if job.host_id else None
    if h is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Geen SSH-host meer voor deze machine")
    return h


class MonitorIn(BaseModel):
    on: bool


@router.post("/jobs/{job_id}/monitor")
async def monitor(job_id: int, body: MonitorIn, request: Request, user: User = Depends(recent_auth),
                  db: AsyncSession = Depends(get_db)):
    job = await _job(db, job_id)
    if job.kind != "cron" or job.removed_at:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Alleen cronregels kunnen bewaakt worden")
    h = await _host(db, job)
    login = await login_for(db, h)
    rawline = (job.extra or {}).get("rawline") or ""
    wid = job.wid or wid_for(job.key)
    try:
        async with connect(h, login) as conn:
            if body.on:
                rc, out, err = await run(conn, wrap.install_script(), login, job.vmid, timeout=60)
                if "@@OK" not in out:
                    raise SshFail(f"Wrapper installeren mislukt: {(err or out).strip()[-200:]}")
            rc, out, err = await run(conn, wrap.read_script(job.source, job.user), login, job.vmid, timeout=60)
            if "@@END" not in out:
                raise SshFail(f"Kon {job.source} niet lezen: {(err or out).strip()[-200:]}")
            content = out[: out.rindex("@@END")]
            new, new_line, new_cmd = wrap.rewrite(content, rawline, job.raw, wid, body.on)
            if new != content:
                rc, out, err = await run(conn, wrap.write_script(job.source, job.user, new), login, job.vmid, timeout=60)
                if "@@OK" not in out:
                    raise SshFail(f"Wegschrijven mislukt: {(err or out).strip()[-200:]}")
    except wrap.WrapError as e:
        raise HTTPException(status.HTTP_409_CONFLICT, str(e)) from e
    except SshFail as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    # Nieuwe regel en commando bijhouden, zodat aan/uit de volgende keer klopt zonder eerst te scannen.
    job.extra = {**(job.extra or {}), "rawline": new_line}
    job.raw = new_cmd
    job.monitored, job.wid = body.on, wid
    await audit(db, request, user, "cron_monitor", job=job.name, target=job.target_name, on=body.on)
    await db.commit()
    return views.job_out(job)


# --- Nu uitvoeren (live uitvoer) en live meekijken --------------------------------------------

def _run_script(job: CronJob) -> str:
    if job.kind == "timer":
        u = shlex.quote((job.extra or {}).get("unit") or "")
        return (f"journalctl -f -n 0 -o cat -u {u} 2>/dev/null & J=$!; sleep 0.5; systemctl start --no-block {u} || exit $?; "
                f"sleep 1; while :; do s=$(systemctl show -p ActiveState --value {u}); "
                f"case \"$s\" in activating|active|deactivating|reloading) sleep 1;; *) break;; esac; done; sleep 1; "
                f"kill $J 2>/dev/null; r=$(systemctl show -p ExecMainStatus --value {u}); exit ${{r:-0}}")
    if job.user and job.user != "root":
        return f"cd ~{shlex.quote(job.user)} 2>/dev/null; exec runuser -u {shlex.quote(job.user)} -- sh -c {shlex.quote(job.command)}"
    return f"cd ~ 2>/dev/null; exec sh -c {shlex.quote(job.command)}"


@router.websocket("/ws/run/{job_id}")
async def run_now(ws: WebSocket, job_id: int, db: AsyncSession = Depends(get_db)):
    await ws.accept()
    user, why = await _ws_user(ws, db)
    if user is None:
        await _send(ws, t="error", m=why)
        await ws.close(4401)
        return
    job = await db.get(CronJob, job_id)
    if job is None or job.kind not in views.RUNNABLE or not job.host_id:
        await _send(ws, t="error", m="Deze job kan je niet zelf starten")
        await ws.close()
        return
    h = await db.get(SshHost, job.host_id)
    login = await login_for(db, h)
    ip = ws.client.host if ws.client else None
    started = datetime.now(timezone.utc).replace(microsecond=0)
    db.add(AuditLog(user_id=user.id, action="cron_run", ip=ip, detail={"job": job.name, "target": job.target_name}))
    await db.commit()
    buf = bytearray()
    code = None
    try:
        async with connect(h, login, keepalive=30) as conn:
            await _send(ws, t="status", m=f"{job.target_name}: {job.command[:200]}")
            proc = await conn.create_process(ssh_command(_run_script(job), login, job.vmid), encoding=None,
                                             stderr=asyncssh.STDOUT)

            async def pump():
                while True:
                    data = await proc.stdout.read(65536)
                    if not data:
                        break
                    buf.extend(data)
                    del buf[:-MAX_OUTPUT * 2]
                    await ws.send_bytes(data)

            async def stop():
                while True:
                    msg = await ws.receive()
                    if msg["type"] == "websocket.disconnect":
                        return "weg"
                    if msg.get("text") and json.loads(msg["text"]).get("t") == "stop":
                        return "stop"

            t1, t2 = asyncio.create_task(pump()), asyncio.create_task(stop())
            done, pending = await asyncio.wait({t1, t2}, timeout=RUN_TIMEOUT, return_when=asyncio.FIRST_COMPLETED)
            if t1 in done:
                await proc.wait()
                code = proc.exit_status
            else:
                with contextlib.suppress(Exception):
                    proc.kill()
                proc.close()
            for t in pending:
                t.cancel()
    except SshFail as e:
        await _send(ws, t="error", m=str(e))
    except WebSocketDisconnect:
        pass
    ended = datetime.now(timezone.utc)
    text = buf.decode("utf-8", "replace")[-MAX_OUTPUT:]
    status_ = "ok" if code == 0 else "fout" if code is not None else "gestopt"
    db.add(CronRun(job_id=job.id, started_at=started, ended_at=ended, exit_code=code, status=status_[:12],
                   trigger="manueel", output=text or None))
    await db.commit()
    with contextlib.suppress(Exception):
        await _send(ws, t="exit", code=code, s=round((ended - started).total_seconds(), 1))
        await ws.close()


def _tail_script(units: list[str]) -> str:
    match = "SYSLOG_IDENTIFIER=CRON SYSLOG_IDENTIFIER=cron SYSLOG_IDENTIFIER=CROND SYSLOG_IDENTIFIER=hp-cron"
    if units:
        match += " + " + " ".join(f"_SYSTEMD_UNIT={shlex.quote(u)}" for u in units[:40])
    return ("if command -v journalctl >/dev/null 2>&1; then exec journalctl -f -n 150 -o short-iso --no-pager "
            f"{match}; else tail -n 150 -F /var/log/cron /var/log/cron.log /var/log/messages 2>/dev/null | "
            "grep --line-buffered -iE 'cron|hp-cron'; fi")


@router.websocket("/ws/tail/{target}")
async def tail(ws: WebSocket, target: str, db: AsyncSession = Depends(get_db)):
    """Live de cronlog van één machine: CRON, de wrapper en de diensten achter de eigen timers."""
    await ws.accept()
    user, why = await _ws_user(ws, db, reauth=False)
    if user is None:
        await _send(ws, t="error", m=why)
        await ws.close(4401)
        return
    parts = target.split(":")
    if len(parts) not in (2, 4) or parts[0] != "ssh" or not parts[1].isdigit() or (len(parts) == 4 and (
            parts[2] != "ct" or not parts[3].isdigit())):
        await _send(ws, t="error", m="Onbekende machine")
        await ws.close()
        return
    h = await db.get(SshHost, int(parts[1]))
    if h is None:
        await _send(ws, t="error", m="Host niet gevonden")
        await ws.close()
        return
    vmid = int(parts[3]) if len(parts) == 4 else None
    units = [(j.extra or {}).get("unit") for j in (await db.execute(select(CronJob).where(
        CronJob.target == target, CronJob.kind == "timer", CronJob.system.is_(False),
        CronJob.removed_at.is_(None)))).scalars()]
    login = await login_for(db, h)
    try:
        async with connect(h, login, keepalive=30) as conn:
            await _send(ws, t="ready")
            proc = await conn.create_process(ssh_command(_tail_script([u for u in units if u]), login, vmid),
                                             encoding=None, stderr=asyncssh.STDOUT)

            async def pump():
                while True:
                    data = await proc.stdout.read(65536)
                    if not data:
                        break
                    await ws.send_bytes(data)

            async def wait_close():
                while (await ws.receive())["type"] != "websocket.disconnect":
                    pass

            t1, t2 = asyncio.create_task(pump()), asyncio.create_task(wait_close())
            _, pending = await asyncio.wait({t1, t2}, timeout=4 * 3600, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            proc.close()
    except SshFail as e:
        await _send(ws, t="error", m=str(e))
    except WebSocketDisconnect:
        return
    with contextlib.suppress(Exception):
        await ws.close()
