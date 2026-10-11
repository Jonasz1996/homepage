"""Diagnose-export (knop onder !): één bestand om bij een foutmelding te voegen. Zie diagnose.py."""

import asyncio

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .. import diagnose, outside
from ..db import get_db
from ..deps import audit, recent_auth
from ..models import User

router = APIRouter(prefix="/api/diagnose", tags=["diagnose"])
# Eén export tegelijk: de checklist erin vraagt de API van elke tegel.
_lock = asyncio.Lock()


@router.get("", dependencies=[outside.guard("downloads")])
async def download(request: Request, frontend: int | None = Query(default=None, ge=0, le=100000),
                   user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """Versies, checklist, fouten per integratie en de laatste logregels als JSON-bestand. Geheimen gemaskeerd, maar
    met namen en IP-adressen: zoals een configuratie downloaden vraagt het een recente 2FA en staat het van buitenaf
    uit. frontend: het hoogste nummer uit "wat is er nieuw" dat de browser kent."""
    if _lock.locked():
        raise HTTPException(status.HTTP_409_CONFLICT, "Er wordt al een diagnose gemaakt")
    async with _lock:
        data = await diagnose.build(db, user, frontend)
    name = data.get("bestand") or "homepage-diagnose.json"
    resp = JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="{name}"'})
    await audit(db, request, user, "diagnose_download",
                sections=[k for k, v in data.items() if isinstance(v, (dict, list))],
                masked=data.get("gemaskeerd") or {}, bytes=len(resp.body))
    await db.commit()
    return resp
