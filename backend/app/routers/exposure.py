"""Netwerk › publiek (monitoring/exposure.py): welke namen van buitenaf bereikbaar zijn, en wat ervoor staat.

Alleen lezen naar Cloudflare, NPM en OPNsense: geen knop verandert daar iets. "Bewust open" markeren legt een alarm
stil en vraagt daarom een recente 2FA (confirm_silence), met een regel in het auditlog en een melding."""

import asyncio
import time
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, confirm_silence, current_session, current_user
from ..models import Session, User
from ..monitoring import exposure
from . import integrations as integrations_router

router = APIRouter(prefix="/api/exposure", tags=["publiek"])

_last_refresh = 0.0
_busy = asyncio.Lock()


@router.get("")
async def get_exposure(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await exposure.view(db)


@router.post("/refresh")
async def refresh(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Nu nakijken in plaats van op de worker te wachten (elk uur). Niet twee keer kort na elkaar."""
    global _last_refresh
    if _busy.locked() or time.monotonic() - _last_refresh < exposure.REFRESH_GAP:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Net vernieuwd, probeer zo opnieuw")
    async with _busy:
        _last_refresh = time.monotonic()
        await exposure.run_exposure(db, integrations_router.clients)
        await db.commit()
    return await exposure.view(db)


class IntendedIn(BaseModel):
    name: str = Field(min_length=1, max_length=253)
    reason: str = Field(min_length=3, max_length=120)


async def _locked_marks(db: AsyncSession) -> tuple[dict, dict]:
    """De uitkomst en de markeringen, op slot in dezelfde volgorde als de ronde (exposure, dan exposure_intended)."""
    st = await exposure._locked(db, exposure.STATE_KEY)
    marks = await exposure._locked(db, exposure.MARKS_KEY)
    return dict(st.value or {}), marks


@router.put("/intended")
async def intend(body: IntendedIn, request: Request, sess: Session = Depends(current_session),
                 user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    name = body.name.strip().lower()
    reason = body.reason.strip()
    value, marks = await _locked_marks(db)
    items = dict((marks.value or {}).get("items") or {})
    row = next((r for r in exposure.apply_marks(value, items).get("rows") or [] if r["name"] == name), None)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Naam niet gevonden")
    if row["base"] not in exposure.MARKABLE:
        raise HTTPException(status.HTTP_409_CONFLICT, "Alleen open namen, wildcards en records zonder host of elders kan "
                                                      "je als bewust markeren")
    title = f"Bewust zo: {name}" if row["base"] in ("wees", "elders") else f"Bewust open: {name}"
    await confirm_silence(db, request, sess, user, title, "exposure_intended", name=name, reason=reason)
    items[name] = {"reason": reason, "by": user.username, "at": datetime.now(timezone.utc).isoformat(),
                   "sig": row["sig"]}
    marks.value = {**(marks.value or {}), "items": items}
    await exposure.write_summary(db, items)
    await db.commit()
    return await exposure.view(db)


@router.delete("/intended/{name}")
async def unintend(name: str, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Weer als probleem tonen. Zonder 2FA: het alarm wordt luider, niet stiller."""
    name = name.strip().lower()
    _, marks = await _locked_marks(db)
    items = dict((marks.value or {}).get("items") or {})
    if items.pop(name, None) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Naam niet gevonden")
    await audit(db, request, user, "exposure_intended_removed", name=name)
    marks.value = {**(marks.value or {}), "items": items}
    await exposure.write_summary(db, items)
    await db.commit()
    return await exposure.view(db)


@router.get("/proef")
async def proef(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """"welke calls?": wat een ronde opvraagt, waar en als wie. Er wordt niets verstuurd."""
    return await exposure.plan_calls(db, integrations_router.clients)
