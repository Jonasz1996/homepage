from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from starlette.requests import HTTPConnection
from sqlalchemy.ext.asyncio import AsyncSession

from .config import get_settings
from .db import get_db
from .models import AuditLog, Event, Notification, Session, User
from .security import token_id

COOKIE = "hp_session"
CSRF_HEADER = "x-requested-with"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def client_ip(request: Request) -> str | None:
    # uvicorn draait met --proxy-headers achter nginx, dus dit is het echte IP.
    return request.client.host if request.client else None


def client_country(request: HTTPConnection) -> str | None:
    """Landcode die nginx meegeeft (CF-IPCountry, alleen als het verzoek via NPM kwam)."""
    cc = (request.headers.get("x-country") or "").strip().upper()
    return cc if len(cc) == 2 and cc.isalpha() and cc not in ("XX", "T1") else None


SEEN_EVERY = timedelta(minutes=5)


def secure_cookie(request: Request) -> bool:
    mode = str(get_settings().cookie_secure).strip().lower()
    if mode in ("true", "1", "yes"):
        return True
    if mode in ("false", "0", "no"):
        return False
    # uvicorn zet het schema uit X-Forwarded-Proto (NPM → nginx), anders http.
    return request.url.scheme == "https"


async def csrf_guard(conn: HTTPConnection) -> None:
    """Een ander domein kan geen eigen header meesturen zonder CORS-toestemming,
    dus deze header bewijst dat het verzoek van onze eigen frontend komt.
    WebSockets controleren zelf de Origin (zie routers/ssh.py)."""
    if conn.scope["type"] != "http":
        return
    request = conn
    if request.scope["method"] in UNSAFE and request.headers.get(CSRF_HEADER) != "homepage":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF-header ontbreekt")


async def optional_session(request: Request, db: AsyncSession = Depends(get_db)) -> Session | None:
    token = request.cookies.get(COOKIE)
    if not token:
        return None
    sess = await db.get(Session, token_id(token))
    if sess is None:
        return None
    now = datetime.now(timezone.utc)
    expires = sess.expires_at.replace(tzinfo=sess.expires_at.tzinfo or timezone.utc)
    if expires < now:
        await db.delete(sess)
        await db.commit()
        return None
    # Glijdende sessie: wie het dashboard gebruikt, blijft ingelogd.
    lifetime = timedelta(days=get_settings().session_days)
    changed = False
    if expires - now < lifetime / 2:
        sess.expires_at = now + lifetime
        request.state.renew_cookie = (token, lifetime)
        changed = True
    seen = sess.last_seen_at.replace(tzinfo=sess.last_seen_at.tzinfo or timezone.utc) if sess.last_seen_at else None
    if seen is None or now - seen > SEEN_EVERY:
        sess.last_seen_at = now
        sess.ip = client_ip(request) or sess.ip
        sess.country = client_country(request) or sess.country
        changed = True
    if changed:
        await db.commit()
    return sess


async def current_session(sess: Session | None = Depends(optional_session)) -> Session:
    if sess is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Niet ingelogd")
    return sess


async def current_user(sess: Session = Depends(current_session)) -> User:
    """Volledig ingelogd: wachtwoord en TOTP zijn allebei gecontroleerd."""
    if not (sess.mfa_ok and sess.user.totp_enabled):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2FA vereist")
    return sess.user


async def recent_auth(sess: Session = Depends(current_session), user: User = Depends(current_user)) -> User:
    """Voor gevoelige acties: wachtwoord of TOTP moet recent ingegeven zijn."""
    limit = timedelta(minutes=get_settings().reauth_minutes)
    auth_at = sess.auth_at.replace(tzinfo=sess.auth_at.tzinfo or timezone.utc)
    if datetime.now(timezone.utc) - auth_at > limit:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "reauth_required")
    return user


async def audit(db: AsyncSession, request: Request, user: User | None, action: str, **detail) -> None:
    db.add(AuditLog(user_id=user.id if user else None, action=action, detail=detail, ip=client_ip(request)))


# Bron van een melding → soort gebeurtenis op de tijdlijn.
EVENT_KIND = {"monitor": "storing", "backup": "backup", "capaciteit": "capaciteit", "log": "log", "npm": "wijziging",
              "updates": "updates", "herstart": "herstart", "netwerk": "netwerk", "actie": "actie",
              "auth": "toegang", "cron": "cron",
              "hardware": "gezondheid", "snapshots": "gezondheid", "domein": "gezondheid", "homepage": "gezondheid"}


def event(db: AsyncSession, kind: str, title: str, body: str | None = None, level: str = "info",
          service_id: int | None = None, data: dict | None = None) -> None:
    """Alleen op de tijdlijn, zonder melding."""
    db.add(Event(kind=kind, title=title[:200], body=body, level=level, service_id=service_id, data=data or {}))


def notify(db: AsyncSession, title: str, body: str | None = None, level: str = "info",
           source: str = "system", service_id: int | None = None, data: dict | None = None) -> None:
    """Melding in het meldingencentrum, en ook op de tijdlijn (behalve het weekrapport zelf)."""
    db.add(Notification(title=title, body=body, level=level, source=source, service_id=service_id))
    if source != "rapport":
        event(db, EVENT_KIND.get(source, "melding"), title, body, level, service_id, data)
