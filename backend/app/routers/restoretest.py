"""Hersteltest van back-ups: instellingen, geschiedenis en een test op vraag."""

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..db import ensure_state, get_db
from ..deps import audit, current_user, recent_auth
from ..integrations import IntegrationError, build
from ..models import AppState, Service, User
from ..monitoring import restoretest
from .integrations import clients
from .upgrade import _maker

router = APIRouter(prefix="/api/restoretest", tags=["restoretest"])
_task: asyncio.Task | None = None


def _out(value: dict | None) -> dict:
    value = value or {}
    return {"settings": restoretest.settings(value), "history": value.get("history") or [],
            "running": value.get("running"), "next": restoretest.next_run(value, datetime.now(timezone.utc))}


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, restoretest.STATE_KEY)
    return _out(st.value if st else None)


@router.get("/options")
async def options(service_id: int | None = None, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Nodes, PBS-opslag, doelopslag en CT's van een Proxmox-tegel, om uit te kiezen."""
    svcs = list((await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars())
    svc = next((s for s in svcs if s.id == service_id), svcs[0] if svcs else None)
    base = {"services": [{"id": s.id, "name": s.name} for s in svcs], "service_id": svc.id if svc else None}
    if svc is None:
        return {**base, "error": "Nog geen Proxmox-tegel"}
    await db.close()
    try:
        return {**base, **await restoretest.options(build(svc, clients))}
    except IntegrationError as e:
        return {**base, "error": str(e)}


class SettingsIn(BaseModel):
    enabled: bool = False
    service_id: int | None = None
    node: str = Field(default="", max_length=63, pattern=r"^[A-Za-z0-9.-]*$")
    pbs: str = Field(default="", max_length=100, pattern=r"^[A-Za-z0-9._-]*$")
    storage: str = Field(default="", max_length=100, pattern=r"^[A-Za-z0-9._-]*$")
    day: int = Field(default=1, ge=1, le=28)
    hour: int = Field(default=5, ge=0, le=23)
    vmid_from: int = Field(default=9900, ge=100, le=999_000_000)
    only: list[int] = Field(default_factory=list, max_length=200)


@router.put("/settings", dependencies=[outside.guard("acties")])
async def put_settings(body: SettingsIn, request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    if body.service_id is not None:
        svc = await db.get(Service, body.service_id)
        if svc is None or svc.type != "proxmox":
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Kies een Proxmox-tegel")
    st = await ensure_state(db, restoretest.STATE_KEY, {})
    st.value = {**(st.value or {}), "settings": body.model_dump()}
    await audit(db, request, user, "restoretest_settings", enabled=body.enabled, node=body.node, pbs=body.pbs)
    await db.commit()
    return _out(st.value)


@router.post("/run", status_code=status.HTTP_202_ACCEPTED, dependencies=[outside.guard("acties")])
async def run_now(request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    global _task
    st = await db.get(AppState, restoretest.STATE_KEY)
    busy = (st.value or {}).get("running") if st else None
    if (_task and not _task.done()) or (
            busy and datetime.now(timezone.utc) - datetime.fromisoformat(busy["at"]) < restoretest.STALE):
        raise HTTPException(status.HTTP_409_CONFLICT, "Er loopt al een hersteltest")
    await audit(db, request, user, "restoretest_run")
    await db.commit()
    _task = asyncio.create_task(restoretest.run(_maker(request), clients, manual=True))
    return {"ok": True}
