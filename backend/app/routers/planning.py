"""Gepland onderhoud (vensters vooraf vastleggen) en de clusterstatus van Proxmox."""

import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_user
from ..models import AppState, Group, MaintenanceWindow, Service, User
from ..monitoring import cluster, planned
from .integrations import clients

router = APIRouter(prefix="/api", tags=["planning"])
log = logging.getLogger("homepage.api")


async def _out(db: AsyncSession, w: MaintenanceWindow, now: datetime) -> dict:
    target = await db.get(Service, w.service_id) if w.service_id else await db.get(Group, w.group_id)
    run = planned.active(w, now)
    nxt = planned.next_run(w, now)
    return {"id": w.id, "name": w.name, "service_id": w.service_id, "group_id": w.group_id,
            "target": target.name if target else "?", "repeat": w.repeat, "start": w.start, "minutes": w.minutes,
            "weekdays": w.weekdays or [], "enabled": w.enabled, "text": planned.describe(w),
            "active_until": run[1] if run else None, "next": nxt}


@router.get("/maintenance/windows")
async def windows(service_id: int | None = None, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    q = select(MaintenanceWindow).order_by(MaintenanceWindow.id)
    if service_id:
        # Ook de vensters van de groep waar de service in zit.
        svc = await db.get(Service, service_id)
        q = q.where(or_(MaintenanceWindow.service_id == service_id,
                        MaintenanceWindow.group_id == (svc.group_id if svc else -1)))
    now = datetime.now(timezone.utc)
    return [await _out(db, w, now) for w in (await db.execute(q)).scalars().all()]


class WindowIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    service_id: int | None = None
    group_id: int | None = None
    repeat: str = Field(default="once", pattern="^(once|daily|weekly)$")
    start: datetime
    minutes: int = Field(ge=5, le=7 * 24 * 60)
    weekdays: list[int] = Field(default_factory=list, max_length=7)
    enabled: bool = True

    @model_validator(mode="after")
    def check(self):
        if (self.service_id is None) == (self.group_id is None):
            raise ValueError("Kies een service of een groep")
        if any(d < 0 or d > 6 for d in self.weekdays):
            raise ValueError("Weekdag 0 (maandag) tot 6 (zondag)")
        if self.repeat == "weekly" and not self.weekdays:
            raise ValueError("Kies minstens één weekdag")
        if self.start.tzinfo is None:
            self.start = self.start.astimezone()
        return self


async def _check(db: AsyncSession, body: WindowIn) -> None:
    if body.service_id and await db.get(Service, body.service_id) is None:
        raise HTTPException(422, "Service niet gevonden")
    if body.group_id and await db.get(Group, body.group_id) is None:
        raise HTTPException(422, "Groep niet gevonden")


async def _apply_now(db: AsyncSession) -> None:
    # Meteen toepassen, niet wachten op de worker: een venster dat al loopt, geldt direct.
    await planned.apply(db)


@router.post("/maintenance/windows", status_code=status.HTTP_201_CREATED)
async def create_window(body: WindowIn, request: Request, user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    await _check(db, body)
    w = MaintenanceWindow(**body.model_dump(), created_at=datetime.now(timezone.utc))
    w.weekdays = sorted(set(body.weekdays))
    db.add(w)
    await db.flush()
    await _apply_now(db)
    await audit(db, request, user, "maintenance_planned", name=w.name, when=planned.describe(w))
    await db.commit()
    return await _out(db, w, datetime.now(timezone.utc))


async def _window(db: AsyncSession, wid: int) -> MaintenanceWindow:
    w = await db.get(MaintenanceWindow, wid)
    if w is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    return w


@router.put("/maintenance/windows/{wid}")
async def update_window(wid: int, body: WindowIn, request: Request, user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    w = await _window(db, wid)
    await _check(db, body)
    await planned.stop(db, w)
    for k, v in body.model_dump().items():
        setattr(w, k, v)
    w.weekdays = sorted(set(body.weekdays))
    await db.flush()
    await _apply_now(db)
    await audit(db, request, user, "maintenance_planned", name=w.name, when=planned.describe(w))
    await db.commit()
    return await _out(db, w, datetime.now(timezone.utc))


@router.delete("/maintenance/windows/{wid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_window(wid: int, request: Request, user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    w = await _window(db, wid)
    await planned.stop(db, w)
    await audit(db, request, user, "maintenance_unplanned", name=w.name)
    await db.delete(w)
    await db.commit()


# --- cluster ---------------------------------------------------------------------------------------

_run: asyncio.Task | None = None


@router.get("/cluster")
async def cluster_status(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, cluster.STATE_KEY)
    value = dict(st.value) if st else {}
    # Kandidaten voor de QDevice: een PBS staat los van de cluster en draait toch altijd.
    pbs = [{"name": s.name, "host": urlsplit(s.url or "").hostname}
           for s in (await db.execute(select(Service).where(Service.type == "proxmoxbackupserver")
                                      .order_by(Service.name))).scalars()]
    return {"at": value.get("at"), "items": value.get("items", []), "summary": cluster.summary(value),
            "running": bool(_run and not _run.done()), "qnetd": [p for p in pbs if p["host"]]}


async def _bg(factory) -> None:
    gen = factory()
    try:
        db = await anext(gen)
        await cluster.run_cluster(db, clients)
        await db.commit()
    except Exception:
        log.exception("clusterstatus ophalen mislukt")
    finally:
        await gen.aclose()


@router.post("/cluster/refresh", status_code=status.HTTP_202_ACCEPTED)
async def cluster_refresh(request: Request, user: User = Depends(current_user)):
    global _run
    if not (_run and not _run.done()):
        _run = asyncio.create_task(_bg(request.app.dependency_overrides.get(get_db, get_db)))
    return {"ok": True}
