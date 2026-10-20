"""Webhooks: een eigen adres per bron (Proxmox, PBS, Uptime Kuma, Home Assistant, ...). Wat daar binnenkomt,
wordt een melding in het meldingencentrum, met de juiste ernst en gekoppeld aan een service.

Het adres zelf is het geheim (32 willekeurige bytes): POST /api/hooks/<token>, zonder login.
"""

import hashlib
import json
import secrets
import time
from collections import deque
from datetime import datetime, timezone
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_user, notify
from ..models import Service, User, WebhookSource
from ..security import decrypt, encrypt

router = APIRouter(prefix="/api", tags=["hooks"])

KINDS = ("proxmox", "pbs", "uptimekuma", "homeassistant", "generic")
MAX_BODY = 64 * 1024
PER_MINUTE = 60
LEVELS = {"info": "info", "notice": "info", "debug": "info", "ok": "ok", "success": "ok", "up": "ok",
          "resolved": "ok", "warning": "warn", "warn": "warn", "unknown": "warn", "down": "err", "error": "err",
          "err": "err", "critical": "err", "crit": "err", "fatal": "err", "alert": "err", "emergency": "err"}
_recent: dict[int, deque] = {}


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _text(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False)[:2000]
    s = str(v).strip()
    return s or None


def parse(kind: str, raw: bytes, content_type: str) -> tuple[str, str | None, str]:
    """(titel, tekst, ernst) uit wat een tool stuurt: JSON, een formulier of gewone tekst."""
    text = raw.decode("utf-8", "replace")
    data = None
    if "json" in content_type or text.lstrip().startswith(("{", "[")):
        try:
            data = json.loads(text)
        except ValueError:
            data = None
    elif "form" in content_type:
        data = {k: v[0] for k, v in parse_qs(text).items()}
    if not isinstance(data, dict):
        first, _, rest = text.strip().partition("\n")
        return (first[:200] or "(lege melding)", rest.strip() or None, "info")
    if kind == "uptimekuma" or "heartbeat" in data:
        hb, mon = data.get("heartbeat") or {}, data.get("monitor") or {}
        st = hb.get("status")
        level = {0: "err", 1: "ok", 2: "warn", 3: "info"}.get(st, "info")
        name = mon.get("name") or "Uptime Kuma"
        state = {0: "down", 1: "weer up", 2: "wacht", 3: "in onderhoud"}.get(st)
        title = f"{name} {state}" if state else _text(data.get("msg")) or "testbericht"
        return title, _text(hb.get("msg")) or _text(data.get("msg")), level
    title = next((_text(data[k]) for k in ("title", "subject", "summary", "name", "event") if data.get(k)), None)
    body = next((_text(data[k]) for k in ("message", "body", "text", "msg", "description", "details") if data.get(k)), None)
    sev = next((str(data[k]).lower() for k in ("severity", "level", "priority", "status", "state") if data.get(k)), "")
    level = LEVELS.get(sev, "info")
    if not title:
        title, body = (body or "melding").split("\n", 1)[0], body
    return title[:200], body, level


@router.post("/hooks/{token}", status_code=status.HTTP_202_ACCEPTED)
async def receive(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    if len(token) < 20 or len(token) > 100:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onbekend adres")
    src = (await db.execute(select(WebhookSource).where(WebhookSource.token_hash == _hash(token)))).scalar_one_or_none()
    if src is None or not src.enabled:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onbekend adres")
    q = _recent.setdefault(src.id, deque())
    now = time.monotonic()
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= PER_MINUTE:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Te veel meldingen")
    q.append(now)
    raw = b""
    async for chunk in request.stream():
        raw += chunk
        if len(raw) > MAX_BODY:
            raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Te groot")
    title, body, level = parse(src.kind, raw, request.headers.get("content-type", ""))
    notify(db, f"{src.name}: {title}"[:200], (body or "")[:4000] or None, level=level, source="webhook",
           service_id=src.service_id)
    src.count += 1
    src.last_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}


# --- beheer ------------------------------------------------------------------------------------------

def _out(s: WebhookSource) -> dict:
    return {"id": s.id, "name": s.name, "kind": s.kind, "token": decrypt(s.token), "service_id": s.service_id,
            "enabled": s.enabled, "count": s.count, "last_at": s.last_at, "created_at": s.created_at}


class SourceIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    kind: str = Field(default="generic", pattern="^(" + "|".join(KINDS) + ")$")
    service_id: int | None = None
    enabled: bool = True


@router.get("/webhooks")
async def list_sources(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(WebhookSource).order_by(WebhookSource.name))).scalars()
    return [_out(s) for s in rows]


async def _check_service(db: AsyncSession, sid: int | None) -> None:
    if sid is not None and await db.get(Service, sid) is None:
        raise HTTPException(422, "Service niet gevonden")


@router.post("/webhooks", status_code=status.HTTP_201_CREATED)
async def create_source(body: SourceIn, request: Request, user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    await _check_service(db, body.service_id)
    token = secrets.token_urlsafe(32)
    s = WebhookSource(name=body.name.strip(), kind=body.kind, service_id=body.service_id, enabled=body.enabled,
                      token=encrypt(token), token_hash=_hash(token), count=0)
    db.add(s)
    await audit(db, request, user, "webhook_added", name=s.name, kind=s.kind)
    await db.commit()
    return _out(s)


@router.patch("/webhooks/{sid}")
async def update_source(sid: int, body: SourceIn, request: Request, user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    s = await db.get(WebhookSource, sid)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    await _check_service(db, body.service_id)
    s.name, s.kind, s.service_id, s.enabled = body.name.strip(), body.kind, body.service_id, body.enabled
    await audit(db, request, user, "webhook_changed", name=s.name, enabled=s.enabled)
    await db.commit()
    return _out(s)


@router.post("/webhooks/{sid}/rotate")
async def rotate_source(sid: int, request: Request, user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    """Nieuw adres; het oude werkt meteen niet meer."""
    s = await db.get(WebhookSource, sid)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    token = secrets.token_urlsafe(32)
    s.token, s.token_hash = encrypt(token), _hash(token)
    await audit(db, request, user, "webhook_rotated", name=s.name)
    await db.commit()
    return _out(s)


@router.delete("/webhooks/{sid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_source(sid: int, request: Request, user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    s = await db.get(WebhookSource, sid)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    await audit(db, request, user, "webhook_deleted", name=s.name)
    await db.delete(s)
    await db.commit()
