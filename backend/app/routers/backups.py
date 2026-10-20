"""Back-updekking per VM/CT (hw → back-ups) en een sync tussen twee PBS'en."""

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside, ssh_exec
from ..db import get_db, job_lock
from ..deps import audit, current_user, notify, recent_auth
from ..models import AppState, User
from ..monitoring import coverage, pbssync
from ..ssh_login import login_for
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


@router.post("/sync/proef", dependencies=[outside.guard("terminal")])
async def proef(body: PlanIn, request: Request, controle: bool = True, user: User = Depends(current_user),
                db: AsyncSession = Depends(get_db)):
    """Proef: wat "stap 1 en 2 zelf uitvoeren" zou doen, zonder iets te veranderen. Met controle (en bevestigde
    hostsleutels) lopen de proefscripts via SSH op beide PBS'en: die kijken wat er al bestaat en tonen de rest. Dat
    meldt zich als root aan, dus net als de echte knop: in het auditlog, en van buitenaf alleen met de terminal."""
    c = await _check(db, body)
    p = c["plan"]
    hs, hd = await pbssync.ssh_host(db, c["src"]), await pbssync.ssh_host(db, c["dst"])
    # Alleen de gebruikersnaam wordt getoond, nooit de sleutel of het wachtwoord.
    ls, ld = [await login_for(db, h) if h else None for h in (hs, hd)]
    ran = None
    if controle and hs and hd and hs.host_key and hd.host_key:
        async with job_lock(db, "pbs-sync") as ok:
            if not ok:
                raise HTTPException(status.HTTP_409_CONFLICT, "Er wordt al een PBS-sync ingesteld of nagekeken")
            await audit(db, request, user, "pbs_sync_proef", source=c["src"]["name"], target=c["dst"]["name"],
                        job=p["job"], schedule=p["schedule"])
            await db.commit()
            ran = await pbssync.proef_run(db, c, hs, hd)
    return {"plan": pbssync.proef_plan(c, await _value(db), hs, hd, ls, ld, ran),
            "log": pbssync.proef_log(c, hs, hd, ran) if ran else []}


@router.post("/sync/create", dependencies=[outside.guard("terminal")])
async def create(body: PlanIn, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """De sync zelf instellen via SSH op beide PBS'en."""
    c = await _check(db, body)
    p = c["plan"]
    hs, hd = await pbssync.ssh_host(db, c["src"]), await pbssync.ssh_host(db, c["dst"])
    # Dezelfde voorcontrole als de proef (daar met ✕): weigeren voor er iets op de bron verandert.
    if why := pbssync.blocked(c, hs, hd):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "; ".join(why))
    async with job_lock(db, "pbs-sync") as ok:
        if not ok:
            raise HTTPException(status.HTTP_409_CONFLICT, "Er wordt al een PBS-sync ingesteld of nagekeken")
        await audit(db, request, user, "pbs_sync_create", source=c["src"]["name"], target=c["dst"]["name"],
                    job=p["job"], schedule=p["schedule"])
        await db.commit()
        try:
            r = await pbssync.create(db, c, hs, hd)
        except ssh_exec.SshFail as e:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    if r["job_existed"]:
        # Het script laat een bestaande sync-job staan: niet beweren dat het uur nu klopt.
        notify(db, f"PBS-sync bijgewerkt: {c['src']['name']} → {c['dst']['name']}",
               f"Sync-job {p['job']} op {c['dst']['name']} bestond al en is niet aangepast (uur en datastores blijven "
               f"zoals ze waren). Het token en de remote {p['remote']} zijn vernieuwd.", level="ok", source="backup")
    else:
        notify(db, f"PBS-sync ingesteld: {c['src']['name']} → {c['dst']['name']}",
               f"Sync-job {p['job']} op {c['dst']['name']}, elke dag om {p['schedule']}.", level="ok", source="backup")
    await db.commit()
    return {"ok": True, "log": r["log"], "job_existed": r["job_existed"]}
