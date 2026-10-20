"""Meldingen op je gsm (web push): toestellen aanmelden, testen, wijzigen en afmelden.

Aanmelden vraagt een recente 2FA-bevestiging. Vernieuwt de browser zelf het pushadres (kan maanden na het
inloggen gebeuren), dan geeft de service worker dat door met het geheim dat hij bij het aanmelden kreeg.
"""

import hashlib
import hmac
import json
import secrets
from typing import Literal
from urllib.parse import urlsplit

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, client_ip, current_user, notify, recent_auth
from ..models import PushSubscription, User
from ..monitoring import webpush
from ..security import LoginLimiter, decrypt_json, encrypt

router = APIRouter(prefix="/api/webpush", tags=["webpush"])

renew_limiter = LoginLimiter()
RENEW_MAX_FAILURES = 10
_DUMMY = "0" * 64

Level = Literal["err", "warn", "info"]


def make_client() -> httpx.AsyncClient:
    """Voor de testknop (tests vervangen dit door een nep-pushdienst)."""
    return httpx.AsyncClient(timeout=webpush.TIMEOUT)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


class KeysIn(BaseModel):
    p256dh: str = Field(max_length=200)
    auth: str = Field(max_length=100)


class SubscriptionIn(BaseModel):
    endpoint: str = Field(max_length=1000)
    keys: KeysIn


class SubscribeIn(SubscriptionIn):
    label: str = Field(min_length=1, max_length=80)
    min_level: Level = "err"


class ChangeIn(BaseModel):
    label: str | None = Field(default=None, min_length=1, max_length=80)
    min_level: Level | None = None


class RenewIn(BaseModel):
    id: int
    renew: str = Field(max_length=200)
    subscription: SubscriptionIn


def _data(body: SubscriptionIn) -> dict:
    if not webpush.endpoint_ok(body.endpoint):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Dit pushadres wordt niet aanvaard")
    if webpush.check_keys(body.keys.p256dh, body.keys.auth) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Ongeldige sleutels van de browser")
    return {"endpoint": body.endpoint, "p256dh": body.keys.p256dh, "auth": body.keys.auth}


def _origin(request: Request) -> str | None:
    return request.headers.get("origin") or f"{request.url.scheme}://{request.url.netloc}"


def _out(s: PushSubscription) -> dict:
    return {"id": s.id, "label": s.label, "min_level": s.min_level, "created_at": s.created_at,
            "last_ok_at": s.last_ok_at, "last_error": s.last_error, "fail_count": s.fail_count,
            "gone": s.gone_at is not None}


async def _get(db: AsyncSession, sid: int) -> PushSubscription:
    s = await db.get(PushSubscription, sid)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    return s


def _host(endpoint: str) -> str | None:
    return urlsplit(endpoint).hostname


@router.get("/key")
async def public_key(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    state = await webpush.keys(db)
    await db.commit()
    return {"public_key": state["public"]}


@router.get("/subscriptions")
async def list_subscriptions(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(PushSubscription).order_by(PushSubscription.id))).scalars()
    return [_out(s) for s in rows]


@router.post("/subscriptions", status_code=status.HTTP_201_CREATED)
async def subscribe(body: SubscribeIn, request: Request, user: User = Depends(recent_auth),
                    db: AsyncSession = Depends(get_db)):
    data = _data(body)
    await webpush.keys(db)
    await webpush.set_sub(db, _origin(request))
    renew = secrets.token_urlsafe(32)
    h = webpush.endpoint_hash(body.endpoint)
    s = (await db.execute(select(PushSubscription).where(PushSubscription.endpoint_hash == h))).scalar_one_or_none()
    if s is None:
        s = PushSubscription(user_id=user.id, endpoint_hash=h, fail_count=0, warned=False)
        db.add(s)
    # Hetzelfde toestel opnieuw: dezelfde rij, met nieuwe sleutels en een nieuw vernieuwgeheim.
    s.user_id, s.data, s.min_level = user.id, encrypt(json.dumps(data)), body.min_level
    s.label = body.label.strip() or "toestel"
    s.renew_hash, s.prev_renew_hash = _sha(renew), None
    s.fail_count, s.warned, s.last_error, s.gone_at = 0, False, None, None
    await audit(db, request, user, "webpush_added", label=s.label, min_level=s.min_level, host=_host(body.endpoint))
    await db.commit()
    return {"id": s.id, "renew": renew}


@router.patch("/subscriptions/{sid}")
async def change_subscription(sid: int, body: ChangeIn, request: Request, user: User = Depends(recent_auth),
                              db: AsyncSession = Depends(get_db)):
    s = await _get(db, sid)
    if body.label is not None:
        s.label = body.label.strip() or s.label
    if body.min_level is not None:
        s.min_level = body.min_level
    await audit(db, request, user, "webpush_changed", label=s.label, min_level=s.min_level)
    await db.commit()
    return _out(s)


@router.delete("/subscriptions/{sid}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_subscription(sid: int, request: Request, user: User = Depends(recent_auth),
                              db: AsyncSession = Depends(get_db)):
    s = await _get(db, sid)
    label = s.label
    await audit(db, request, user, "webpush_removed", label=label)
    await db.delete(s)
    # Bron "auth": komt ook op toestellen die alleen storingen krijgen (wie meldingen stillegt, wil je weten).
    notify(db, f"Meldingen op {label} uitgezet"[:200], "Dit toestel krijgt geen meldingen meer.", level="warn",
           source="auth")
    await db.commit()


@router.post("/subscriptions/{sid}/test")
async def test_subscription(sid: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s = await _get(db, sid)
    async with make_client() as client:
        error = await webpush.send_test(db, client, s)
    await db.commit()
    return {"ok": error is None, "error": error}


async def _rotate(db: AsyncSession, s: PushSubscription, used: str | None) -> str:
    """Nieuw vernieuwgeheim, alleen als het bewaarde nog hetzelfde is als bij het lezen: van twee vernieuwingen
    tegelijk lukt er maar één (de andere krijgt 409 en houdt zo geen geheim over dat niet werkt). used: het geheim
    dat nu gebruikt werd; dat mag daarna nog één ding, exact hetzelfde verzoek herhalen."""
    renew = secrets.token_urlsafe(32)
    values = {"renew_hash": _sha(renew)} | ({"prev_renew_hash": used} if used else {})
    res = await db.execute(update(PushSubscription).where(PushSubscription.id == s.id,
                                                          PushSubscription.renew_hash == s.renew_hash)
                           .values(**values).execution_options(synchronize_session=False))
    if res.rowcount != 1:
        await db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "Intussen al vernieuwd")
    return renew


@router.put("/subscriptions/renew")
async def renew_subscription(body: RenewIn, request: Request, db: AsyncSession = Depends(get_db)):
    """Zonder sessie: de service worker doet dit op de achtergrond. Het vernieuwgeheim is het bewijs."""
    who = f"webpush:{client_ip(request) or '?'}"
    if renew_limiter.blocked(who, limit=RENEW_MAX_FAILURES):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Te veel pogingen")
    s = await db.get(PushSubscription, body.id)
    presented = _sha(body.renew)
    same = hmac.compare_digest(s.renew_hash if s else _DUMMY, presented)
    # Het vorige geheim mag alleen nog exact hetzelfde verzoek herhalen (het antwoord ging onderweg verloren): zelfde
    # adres als nu bewaard. Een ander adres ermee aanmelden kan niet.
    replay = bool(s and s.prev_renew_hash and hmac.compare_digest(s.prev_renew_hash, presented)
                  and s.endpoint_hash == webpush.endpoint_hash(body.subscription.endpoint))
    if s is None or not (same or replay):
        renew_limiter.fail(who)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ongeldig vernieuwgeheim")
    if replay:
        renew = await _rotate(db, s, None)
        await db.commit()
        return {"ok": True, "id": s.id, "renew": renew}
    data = _data(body.subscription)
    # Een browser blijft bij zijn eigen pushdienst (Chrome bij Google, Safari bij Apple). Een ander adres bij een
    # andere dienst is dus niet dit toestel.
    try:
        old = decrypt_json(s.data).get("endpoint") or ""
    except Exception:  # noqa: BLE001 - onleesbare oude rij: dan het nieuwe adres zonder vergelijking
        old = ""
    if old and webpush.service_of(old) != webpush.service_of(body.subscription.endpoint):
        renew_limiter.fail(who)
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Andere pushdienst: zet het toestel opnieuw aan")
    h = webpush.endpoint_hash(body.subscription.endpoint)
    if h != s.endpoint_hash:
        # Had de pagina dit nieuwe adres al aangemeld, dan is dat hetzelfde toestel: één rij houden.
        await db.execute(delete(PushSubscription).where(PushSubscription.endpoint_hash == h,
                                                        PushSubscription.id != s.id))
    # Elk geheim werkt één keer: wie een oud geheim kopieerde, kan er niets meer mee. Voorwaardelijk, zodat van twee
    # vernieuwingen tegelijk met hetzelfde geheim er maar één lukt (de andere krijgt 409, en houdt zo geen geheim
    # over dat niet werkt).
    renew = await _rotate(db, s, presented)
    s.endpoint_hash, s.data = h, encrypt(json.dumps(data))
    s.fail_count, s.warned, s.last_error, s.gone_at = 0, False, None, None
    await audit(db, request, None, "webpush_renewed", label=s.label, host=_host(body.subscription.endpoint))
    # Bron "auth": komt op elk toestel. Een vernieuwing die je niet verwacht, zie je zo meteen.
    notify(db, f"Pushadres van {s.label} vernieuwd"[:200],
           "De browser van dat toestel meldde zich opnieuw aan bij de pushdienst. Verwachtte je dat niet, zet het "
           "toestel dan uit in 🔔 → gsm en opnieuw aan.", level="warn", source="auth")
    await db.commit()
    return {"ok": True, "id": s.id, "renew": renew}

