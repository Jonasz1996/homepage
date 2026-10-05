"""Checks rechtstreeks achter NPM (monitoring/routes.py): wat er rechtstreeks gaat, wat niet en waarom, aan/uit."""

import time

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state, get_db
from ..deps import audit, current_user
from ..models import User
from ..monitoring import routes
from . import integrations as integrations_router

router = APIRouter(prefix="/api", tags=["npm"])

REFRESH_GAP = 15
_last_refresh = 0.0


@router.get("/npm/routes")
async def get_routes(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await routes.overview(db)


class RoutesIn(BaseModel):
    enabled: bool


@router.put("/npm/routes")
async def set_routes(body: RoutesIn, request: Request, user: User = Depends(current_user),
                     db: AsyncSession = Depends(get_db)):
    st = await ensure_state(db, routes.KEY, {})
    st.value = {**(st.value or {}), "enabled": body.enabled}
    await audit(db, request, user, "npm_routes", enabled=body.enabled)
    await db.commit()
    routes.forget()
    return await routes.overview(db)


@router.post("/npm/routes/refresh")
async def refresh_routes(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Nu opnieuw: na een nieuwe firewallregel of een wijziging in NPM hoef je dan geen 5 minuten te wachten."""
    global _last_refresh
    if time.monotonic() - _last_refresh < REFRESH_GAP:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Net vernieuwd, probeer zo opnieuw")
    _last_refresh = time.monotonic()
    await routes.refresh(db, integrations_router.clients, force_probe=True)
    await db.commit()
    return await routes.overview(db)
