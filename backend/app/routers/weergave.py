"""Weergave: een eigen achtergrond voor het dashboard (een afbeelding die je uploadt of van een adres laat ophalen),
met of zonder de effecten van aiverslag erboven (radiale gloed, scanlijnen, zwevende punten).

De instellingen gelden voor het hele dashboard (elk toestel), in app_state 'achtergrond'. De afbeelding zelf staat in
de tabel achtergrond. Of de effecten bewegen, blijft per toestel (Effecten in het menu, fx.js)."""

import hashlib
import ipaddress
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..db import ensure_state, get_db
from ..deps import audit, current_user
from ..models import Achtergrond, AppState, User

router = APIRouter(prefix="/api/achtergrond", tags=["weergave"])

STATE_KEY = "achtergrond"
DEFAULT = {"effecten": True, "dimmen": 35, "vervagen": 0}
# Een upload gaat door nginx (client_max_body_size 4m); de browser verkleint een grote foto eerst.
MAX_UPLOAD = 3_900_000
# Van een adres: groter mag, het gaat niet door nginx.
MAX_URL = 12_000_000

# Alleen gewone beeldformaten, herkend aan hun eerste bytes (niet aan wat de afzender zegt). Geen SVG: dat kan script
# bevatten.
def sniff(data: bytes) -> str | None:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[4:12] in (b"ftypavif", b"ftypavis"):
        return "image/avif"
    return None


class Instellingen(BaseModel):
    effecten: bool = True
    dimmen: int = Field(default=35, ge=0, le=90)
    vervagen: int = Field(default=0, ge=0, le=20)


class UrlIn(BaseModel):
    url: str = Field(min_length=8, max_length=500)


async def _settings(db: AsyncSession) -> dict:
    st = await db.get(AppState, STATE_KEY)
    return {**DEFAULT, **((st.value or {}) if st else {})}


async def _info(db: AsyncSession) -> dict:
    row = (await db.execute(select(Achtergrond.sha, Achtergrond.mime, Achtergrond.bron, Achtergrond.updated_at)
                            .limit(1))).first()
    beeld = None
    if row:
        beeld = {"url": f"/api/achtergrond/beeld/{row.sha}", "mime": row.mime, "bron": row.bron,
                 "sinds": row.updated_at.isoformat()}
    return {**await _settings(db), "beeld": beeld}


@router.get("")
async def get_background(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await _info(db)


@router.put("")
async def put_settings(data: Instellingen, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await ensure_state(db, STATE_KEY)
    st.value = data.model_dump()
    await db.commit()
    return await _info(db)


async def _store(db: AsyncSession, request: Request, user: User, data: bytes, bron: str | None) -> dict:
    mime = sniff(data)
    if mime is None:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                            "Geen afbeelding die het dashboard kent: gebruik PNG, JPEG, WebP, GIF of AVIF")
    await db.execute(delete(Achtergrond))
    db.add(Achtergrond(mime=mime, data=data, sha=hashlib.sha256(data).hexdigest(), bron=bron,
                       updated_at=datetime.now(timezone.utc)))
    await audit(db, request, user, "achtergrond", bron=bron or "upload", bytes=len(data))
    await db.commit()
    return await _info(db)


@router.post("/beeld")
async def upload(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """De afbeelding als ruwe body (zoals de uploads van bestanden)."""
    data = bytearray()
    async for chunk in request.stream():
        data += chunk
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "Te groot (meer dan 3,9 MB)")
    if not data:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Leeg bestand")
    return await _store(db, request, user, bytes(data), None)


def _check_url(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Alleen een gewoon http(s)-adres")
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        ip = None
    if ip is not None and (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Dat adres kan niet")
    return url.strip()


# Het ophalen gaat via de container: van buitenaf hoort dat bij "acties" (anders kan wie het adres kent je LAN
# aftasten). Thuis gewoon.
@router.post("/url", dependencies=[outside.guard("acties")])
async def from_url(data: UrlIn, request: Request, user: User = Depends(current_user),
                   db: AsyncSession = Depends(get_db)):
    url = _check_url(data.url)
    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True, verify=False,
                                     headers={"User-Agent": "homepage-dashboard"}) as client:
            async with client.stream("GET", url) as r:
                if r.status_code >= 400:
                    raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Het adres antwoordde met fout {r.status_code}")
                body = bytearray()
                async for chunk in r.aiter_bytes():
                    body += chunk
                    if len(body) > MAX_URL:
                        raise HTTPException(413, "Te groot (meer dan 12 MB)")
    except httpx.HTTPError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Ophalen lukte niet: {type(e).__name__}") from None
    if not body:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Het adres gaf niets terug")
    return await _store(db, request, user, bytes(body), url[:500])


@router.delete("/beeld")
async def remove(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await db.execute(delete(Achtergrond))
    await audit(db, request, user, "achtergrond", bron="verwijderd")
    await db.commit()
    return await _info(db)


@router.get("/beeld/{sha}")
async def image(sha: str, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    row = (await db.execute(select(Achtergrond).limit(1))).scalar_one_or_none()
    if row is None or row.sha != sha:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Geen achtergrond")
    # De sha zit in het adres: een nieuwe afbeelding is een nieuw adres, dus mag de browser deze lang bewaren.
    return Response(row.data, media_type=row.mime,
                    headers={"Cache-Control": "private, max-age=31536000, immutable"})
