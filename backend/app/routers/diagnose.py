"""Diagnose-export (knop onder !): één bestand om bij een foutmelding te voegen. Zie diagnose.py."""

import asyncio
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.ext.asyncio import AsyncSession

from .. import diagnose, outside
from ..db import get_db
from ..deps import audit, recent_auth
from ..models import User

router = APIRouter(prefix="/api/diagnose", tags=["diagnose"])
# Eén export tegelijk: de checklist erin vraagt de API van elke tegel.
_lock = asyncio.Lock()


class DiagnoseIn(BaseModel):
    """frontend: het hoogste nummer uit "wat is er nieuw" dat de browser kent. browser: de ring van de browser (zijn
    laatste fouten en mislukte verzoeken); de server houdt er de laatste diagnose.BROWSER van over en kort elke tekst in.
    Een regel die geen object is, slaat hij over: een vreemde regel mag de diagnose niet tegenhouden."""
    model_config = ConfigDict(extra="forbid")
    frontend: int | None = Field(default=None, ge=0, le=100000)
    browser: list[Any] = Field(default_factory=list, max_length=4 * diagnose.BROWSER)


async def _download(request: Request, user: User, db: AsyncSession, frontend: int | None,
                    ring: list | None) -> JSONResponse:
    if _lock.locked():
        raise HTTPException(status.HTTP_409_CONFLICT, "Er wordt al een diagnose gemaakt")
    async with _lock:
        data = await diagnose.build(db, user, frontend, ring)
    name = data.get("bestand") or "homepage-diagnose.json"
    resp = JSONResponse(data, headers={"Content-Disposition": f'attachment; filename="{name}"'})
    # Van de ring van de browser alleen hoeveel regels: de inhoud komt alleen in het bestand zelf.
    await audit(db, request, user, "diagnose_download",
                sections=[k for k, v in data.items() if isinstance(v, (dict, list))],
                masked=data.get("gemaskeerd") or {}, bytes=len(resp.body),
                **({"browser": len(ring)} if ring is not None else {}))
    await db.commit()
    return resp


@router.get("", dependencies=[outside.guard("downloads")])
async def download(request: Request, frontend: int | None = Query(default=None, ge=0, le=100000),
                   user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """Versies, checklist, fouten per integratie en de laatste logregels als JSON-bestand. Geheimen gemaskeerd, maar
    met namen en IP-adressen: zoals een configuratie downloaden vraagt het een recente 2FA en staat het van buitenaf
    uit. frontend: het hoogste nummer uit "wat is er nieuw" dat de browser kent."""
    return await _download(request, user, db, frontend, None)


@router.post("", dependencies=[outside.guard("downloads")])
async def download_with_browser(body: DiagnoseIn, request: Request, user: User = Depends(recent_auth),
                                db: AsyncSession = Depends(get_db)):
    """Hetzelfde bestand, met wat de browser zelf bijhield. Die ring wordt gemaskeerd met dezelfde bekende geheimen
    en nergens bewaard (niet in de database, niet in een log)."""
    return await _download(request, user, db, body.frontend, body.browser)
