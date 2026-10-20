"""Back-updekking per VM/CT (hw → back-ups) en een sync tussen twee PBS'en."""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside, ssh_exec
from ..db import get_db
from ..deps import audit, current_user, notify, recent_auth
from ..models import AppState, User
from ..monitoring import coverage, pbssync
from .integrations import clients
from .upgrade import _maker

router = APIRouter(prefix="/api/backups", tags=["backups"])
log = logging.getLogger("homepage.api")
_task: asyncio.Task | None = None


async def _value(db: AsyncSession) -> dict:
    st = await db.get(AppState, coverage.STATE_KEY)
    return dict(st.value) if st else {}


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    value = await _value(db)
    sync = pbssync.propose(value)
    ssh = {p["service_id"]: getattr(await pbssync.ssh_host(db, p), "name", None)
           for p in value.get("pbs") or [] if p.get("service_id")}
    return {"at": value.get("at"), "clusters": value.get("clusters") or [], "pbs": value.get("pbs") or [],
            "counts": coverage.counts(value), "sync": sync, "ssh": ssh, "running": bool(_task and not _task.done())}


async def _refresh(maker) -> None:
    try:
        async with maker() as db:
            await coverage.run_coverage(db, clients)
            await db.commit()
    except Exception:
        log.exception("back-updekking ophalen mislukt")


@router.post("/refresh", status_code=status.HTTP_202_ACCEPTED)
async def refresh(request: Request, user: User = Depends(current_user)):
    global _task
    if not (_task and not _task.done()):
        _task = asyncio.create_task(_refresh(_maker(request)))
    return {"ok": True}


class PlanIn(BaseModel):
    source_id: int
    target_id: int
    host: str = Field(max_length=253)
    port: int = 8007
    src_store: str = Field(max_length=64)
    dst_store: str = Field(max_length=64)
    schedule: str = Field(max_length=5)
    fingerprint: str = Field(default="", max_length=95)


async def _check(db: AsyncSession, body: PlanIn) -> dict:
    try:
        return pbssync.check(await _value(db), body.model_dump())
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e


@router.post("/sync/plan")
async def plan(body: PlanIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Het plan nakijken en de commando's per machine."""
    c = await _check(db, body)
    hs, hd = await pbssync.ssh_host(db, c["src"]), await pbssync.ssh_host(db, c["dst"])
    return {"level": c["level"], "notes": c["notes"], "plan": c["plan"], "commands": pbssync.commands(c),
            "source": c["src"]["name"], "target": c["dst"]["name"],
            "ssh": {"source": hs.name if hs else None, "target": hd.name if hd else None}}


@router.post("/sync/create", dependencies=[outside.guard("terminal")])
async def create(body: PlanIn, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """De sync zelf instellen via SSH op beide PBS'en."""
    c = await _check(db, body)
    p = c["plan"]
    try:
        hs, hd = await pbssync.hosts(db, c)
    except ValueError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(e)) from e
    await audit(db, request, user, "pbs_sync_create", source=c["src"]["name"], target=c["dst"]["name"],
                job=p["job"], schedule=p["schedule"])
    await db.commit()
    try:
        steps = await pbssync.create(db, c, hs, hd)
    except ssh_exec.SshFail as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    notify(db, f"PBS-sync ingesteld: {c['src']['name']} → {c['dst']['name']}",
           f"Sync-job {p['job']} op {c['dst']['name']}, elke dag om {p['schedule']}.", level="ok", source="backup")
    await db.commit()
    return {"ok": True, "log": steps}
