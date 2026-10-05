"""Push-monitors (zoals in Uptime Kuma): een script, een automatisering in Home Assistant of de back-up van een VPS
roept een geheim adres aan. Blijft dat langer uit dan verwacht, dan is de service down.

Hetzelfde adres als in Kuma: /api/push/<token>?status=up&msg=OK&ping=, dus een bestaand script verandert alleen van
host en token. Het adres zelf is het geheim (32 willekeurige bytes). Deze route schrijft alleen de laatste slag weg;
de worker beslist over up of down (monitoring/push.py).
"""

import hashlib
import json
import math
import secrets
import time
import unicodedata
from collections import deque
from datetime import datetime, timezone
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, client_ip, current_user, recent_auth
from ..models import PushMonitor, Service, User
from ..outside import where
from ..security import LoginLimiter, decrypt, encrypt

router = APIRouter(prefix="/api", tags=["push"])

PER_MINUTE = 30
MAX_MISSES = 20
MAX_BODY = 16 * 1024
MAX_MSG = 300
MAX_PING = 600_000
_recent: dict[int, deque] = {}
# Wie adressen probeert te raden: na 20 missers per IP een 429, zonder nog in de database te kijken.
_misses = LoginLimiter()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _clean(v) -> str | None:
    """Geen stuurtekens (nieuwe regels, escapes voor de terminal) in meldingen en logs."""
    if v is None:
        return None
    s = "".join(c for c in str(v) if c in "\t\r\n" or unicodedata.category(c) != "Cc")
    s = " ".join(s.split())[:MAX_MSG]
    return s or None


def _ping(v) -> float | None:
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) and 0 <= f <= MAX_PING else None


async def _body(request: Request) -> dict:
    """status, msg en ping mogen ook in een formulier of JSON staan (POST)."""
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Te groot")
    text = raw.decode("utf-8", "replace").strip()
    if not text:
        return {}
    if "json" in request.headers.get("content-type", "") or text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            return {}
        return data if isinstance(data, dict) else {}
    return {k: v[0] for k, v in parse_qs(text).items()}


@router.api_route("/push/{token}", methods=["GET", "POST"])
async def beat(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    if len(token) < 20 or len(token) > 100:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onbekend adres")
    ip = client_ip(request) or "?"
    if _misses.blocked(ip, limit=MAX_MISSES):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Te veel onbekende adressen")
    mon = (await db.execute(select(PushMonitor).where(PushMonitor.token_hash == _hash(token)))).scalar_one_or_none()
    # Van buitenaf alleen als dat aanstaat; anders even onbekend als een fout adres.
    if mon is None or (not mon.outside and (await where(request, db))["outside"]):
        _misses.fail(ip)
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onbekend adres")
    q = _recent.setdefault(mon.service_id, deque())
    now = time.monotonic()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= PER_MINUTE:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Te veel signalen")
    q.append(now)
    params = dict(request.query_params)
    if request.method == "POST":
        for k, v in (await _body(request)).items():
            params.setdefault(k, v)
    # Zoals Kuma: alles behalve "up" is down (een tikfout valt zo op).
    ok = str(params.get("status") or "up").strip().lower() == "up"
    msg = _clean(params.get("msg"))
    at = datetime.now(timezone.utc)
    mon.last_at, mon.last_ok, mon.last_msg, mon.last_ping = at, ok, msg, _ping(params.get("ping"))
    if not ok:
        mon.last_down_at, mon.last_down_msg = at, msg
    mon.count = PushMonitor.count + 1
    await db.commit()
    return {"ok": True}


# --- beheer ------------------------------------------------------------------------------------------

def _out(m: PushMonitor | None) -> dict:
    if m is None:
        return {"path": None, "outside": False, "last_at": None, "last_ok": None, "last_msg": None,
                "last_ping": None, "count": 0}
    return {"path": f"/api/push/{decrypt(m.token)}", "outside": m.outside, "last_at": m.last_at,
            "last_ok": m.last_ok, "last_msg": m.last_msg, "last_ping": m.last_ping, "count": m.count}


async def _service(db: AsyncSession, sid: int) -> Service:
    s = await db.get(Service, sid)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    return s


async def _monitor(db: AsyncSession, sid: int) -> PushMonitor:
    m = await db.get(PushMonitor, sid)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nog geen push-adres")
    return m


class PushIn(BaseModel):
    outside: bool


@router.get("/services/{service_id}/push")
async def get_push(service_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await _service(db, service_id)
    return _out(await db.get(PushMonitor, service_id))


@router.post("/services/{service_id}/push")
async def create_push(service_id: int, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    s = await _service(db, service_id)
    m = await db.get(PushMonitor, service_id)
    if m is None:
        token = secrets.token_urlsafe(32)
        m = PushMonitor(service_id=s.id, token=encrypt(token), token_hash=_hash(token), outside=False, count=0)
        db.add(m)
        await audit(db, request, user, "push_created", service=s.name)
        try:
            await db.commit()
        except IntegrityError:
            # Twee keer tegelijk aangeklikt: het eerste adres blijft.
            await db.rollback()
            m = await _monitor(db, service_id)
    return _out(m)


@router.post("/services/{service_id}/push/rotate")
async def rotate_push(service_id: int, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    """Nieuw adres; het oude werkt meteen niet meer."""
    s = await _service(db, service_id)
    m = await _monitor(db, service_id)
    token = secrets.token_urlsafe(32)
    m.token, m.token_hash = encrypt(token), _hash(token)
    await audit(db, request, user, "push_rotated", service=s.name)
    await db.commit()
    return _out(m)


@router.patch("/services/{service_id}/push")
async def change_push(service_id: int, body: PushIn, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    s = await _service(db, service_id)
    m = await _monitor(db, service_id)
    m.outside = body.outside
    await audit(db, request, user, "push_changed", service=s.name, outside=body.outside)
    await db.commit()
    return _out(m)
