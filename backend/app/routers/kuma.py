"""Uptime Kuma vervangen: monitors vergelijken met de tegels en wat ontbreekt overnemen (import → Uptime Kuma)."""

import re

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import kuma
from ..db import get_db
from ..deps import audit, current_user
from ..integrations import IntegrationError
from ..layout import record_revision
from ..models import Group, Service, User
from .integrations import clients

router = APIRouter(prefix="/api/kuma", tags=["kuma"])
TARGET = re.compile(r"^[A-Za-z0-9.:\[\]-]{1,255}$")


class CompareIn(BaseModel):
    url: str = Field(max_length=500)
    api_key: str = Field(max_length=200)
    insecure: bool = False


@router.post("/compare")
async def compare(body: CompareIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Welke monitors van Kuma het dashboard al volgt, welke een tegel zonder check hebben en welke ontbreken."""
    services = list((await db.execute(select(Service))).scalars())
    try:
        monitors = await kuma.fetch(body.url, body.api_key, clients.get(body.insecure))
    except IntegrationError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    rows = kuma.compare(monitors, services)
    counts = {k: sum(1 for r in rows if r["state"] == k) for k in ("gedekt", "zonder-check", "ontbreekt", "niet-overnemen")}
    return {"monitors": rows, "counts": counts}


class CheckIn(BaseModel):
    type: str = Field(pattern=r"^(http|tcp|ping|dns)$")
    target: str | None = None
    interval: int = Field(default=60, ge=30, le=3600)

    @field_validator("target")
    @classmethod
    def _target(cls, v):
        if v and not TARGET.match(v):
            raise ValueError("ongeldig doel")
        return v


class NewIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    url: str = Field(max_length=500, pattern=r"^https?://")
    check: CheckIn


class ExistingIn(BaseModel):
    service_id: int
    check: CheckIn


class ApplyIn(BaseModel):
    group_id: int | None = None
    add: list[NewIn] = Field(default_factory=list, max_length=500)
    checks: list[ExistingIn] = Field(default_factory=list, max_length=500)


@router.post("/apply")
async def apply(body: ApplyIn, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Ontbrekende monitors als tegel met check toevoegen, en bestaande tegels zonder check er een geven."""
    if body.add and (body.group_id is None or await db.get(Group, body.group_id) is None):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Kies een groep voor de nieuwe tegels")
    added = checked = 0
    if body.add:
        names = {n.lower() for n in (await db.execute(select(Service.name))).scalars()}
        pos = (await db.execute(select(func.coalesce(func.max(Service.position), -1))
                                .where(Service.group_id == body.group_id))).scalar_one() + 1
        for a in body.add:
            if a.name.strip().lower() in names:
                continue
            names.add(a.name.strip().lower())
            icon = re.sub(r"[^a-z0-9-]+", "-", a.name.lower()).strip("-")
            db.add(Service(group_id=body.group_id, name=a.name.strip(), url=a.url, icon=f"{icon}.png" if icon else None,
                           position=pos, type="link", config={}, check=a.check.model_dump(exclude_none=True)))
            pos += 1
            added += 1
    for c in body.checks:
        svc = await db.get(Service, c.service_id)
        if svc is None or (svc.check or {}).get("type"):
            continue
        svc.check = c.check.model_dump(exclude_none=True)
        checked += 1
    if added or checked:
        await record_revision(db, user, f"Uptime Kuma overgenomen: {added} tegels, {checked} checks")
        await audit(db, request, user, "kuma_import", added=added, checks=checked)
    await db.commit()
    return {"added": added, "checks": checked}
