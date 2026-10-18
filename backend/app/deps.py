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


def cf_forged(conn: HTTPConnection) -> bool:
    """Had het verzoek een header van Cloudflare die niet van Cloudflare kwam? nginx zet dit (zie outside.py)."""
    return conn.headers.get("x-homepage-cf-forged") == "1"


def limit_ip(request: HTTPConnection) -> str:
    """Het IP voor de limieten op mislukte pogingen. Bij een vervalste header van Cloudflare één gedeelde sleutel: dan
    kan het IP gekozen zijn (NPM gelooft X-Real-IP van het LAN), en levert een ander IP geen extra pogingen op."""
    return "cf-vervalst" if cf_forged(request) else client_ip(request) or "?"


def client_country(request: HTTPConnection) -> str | None:
    """Landcode die nginx meegeeft (CF-IPCountry, alleen als NPM het verzoek van Cloudflare of een tunnel kreeg)."""
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
    # Webhooks komen van andere tools (Proxmox, Uptime Kuma, ...): het geheime adres is daar de beveiliging.
    if request.scope["path"].startswith(("/api/hooks/", "/api/push/")):
        return
    if request.scope["method"] in UNSAFE and request.headers.get(CSRF_HEADER) != "homepage":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF-header ontbreekt")


async def optional_session(request: Request, db: AsyncSession = Depends(get_db)) -> Session | None:
    """De sessie van dit verzoek. Zonder login (zie zonderlogin.py): een echte sessie krijgt het kenmerk zonder_login
    (geen 2FA-code meer), en wie geen sessie heeft, krijgt een vluchtige sessie van de eerste gebruiker."""
    from . import zonderlogin

    sess = await _cookie_session(request, db)
    cfg = await zonderlogin.settings(db)
    if sess is not None and sess.mfa_ok and sess.user.totp_enabled:
        if await zonderlogin.learn(request, db, cfg):
            await db.commit()
        ok, _, out = await zonderlogin.check_full(request, db, cfg)
        if ok:
            # Gewone attributen, geen kolommen: gelden alleen voor dit verzoek. Van buitenaf vragen de vier gevaarlijke
            # functies met een echte sessie nog altijd een verse 2FA (fresh_auth): een gestolen cookie volstaat niet.
            sess.zonder_login = True
            sess.zonder_buiten = out
        return sess
    if (await zonderlogin.check(request, db, cfg))[0] and (user := await zonderlogin.home_user(db)):
        request.state.zonder_login = True
        return zonderlogin.transient(user, request)
    return sess


async def _cookie_session(request: Request, db: AsyncSession) -> Session | None:
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
    """Volledig ingelogd: wachtwoord en TOTP zijn allebei gecontroleerd (of zonder login, zie optional_session)."""
    if not (sess.mfa_ok and sess.user.totp_enabled):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2FA vereist")
    return sess.user


async def recent_auth(sess: Session = Depends(current_session), user: User = Depends(current_user)) -> User:
    """Voor gevoelige acties: wachtwoord of TOTP moet recent ingegeven zijn. Zonder login vraagt niets een code."""
    if getattr(sess, "zonder_login", False):
        return user
    return await fresh_auth(sess, user)


async def fresh_auth(sess: Session, user: User) -> User:
    """Een verse 2FA, ook zonder login (voor de gevaarlijke functies van buitenaf met een echte sessie)."""
    limit = timedelta(minutes=get_settings().reauth_minutes)
    auth_at = sess.auth_at.replace(tzinfo=sess.auth_at.tzinfo or timezone.utc)
    if datetime.now(timezone.utc) - auth_at > limit:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "reauth_required")
    return user


async def audit(db: AsyncSession, request: Request, user: User | None, action: str, **detail) -> None:
    if getattr(request.state, "zonder_login", False):
        detail = {**detail, "zonder_login": True}
    db.add(AuditLog(user_id=user.id if user else None, action=action, detail=detail, ip=client_ip(request)))


# Bron van een melding → soort gebeurtenis op de tijdlijn.
EVENT_KIND = {"monitor": "storing", "backup": "backup", "capaciteit": "capaciteit", "log": "log", "npm": "wijziging",
              "updates": "updates", "herstart": "herstart", "netwerk": "netwerk", "actie": "actie",
              "auth": "toegang", "cron": "cron",
              "hardware": "gezondheid", "snapshots": "gezondheid", "domein": "gezondheid", "homepage": "gezondheid",
              "herstel": "actie", "config": "wijziging", "apparaat": "netwerk",
              "cluster": "gezondheid", "webhook": "melding", "buitencheck": "netwerk", "blootstelling": "netwerk",
              "nieuweservice": "actie"}


def event(db: AsyncSession, kind: str, title: str, body: str | None = None, level: str = "info",
          service_id: int | None = None, data: dict | None = None) -> None:
    """Alleen op de tijdlijn, zonder melding."""
    db.add(Event(kind=kind, title=title[:200], body=body, level=level, service_id=service_id, data=data or {}))


def notify(db: AsyncSession, title: str, body: str | None = None, level: str = "info",
           source: str = "system", service_id: int | None = None, data: dict | None = None,
           push: bool = True, key: str | None = None, recovers: str | None = None) -> None:
    """Melding in het meldingencentrum, en ook op de tijdlijn (behalve het weekrapport zelf).
    push=False: niet naar de gsm (web push), alleen hier. key: over welke storing het gaat (nieuwer nieuws erover
    vervangt het oudere op de gsm). recovers: bij herstel, het niveau van de storing die voorbij is."""
    db.add(Notification(title=title[:200], body=body, level=level, source=source, service_id=service_id,
                        pushed_at=None if push else datetime.now(timezone.utc), push_key=key and key[:120],
                        recovers=recovers if level == "ok" else None))
    if source != "rapport":
        event(db, EVENT_KIND.get(source, "melding"), title, body, level, service_id, data)


SILENCE_HINT = "Was jij dit niet, kijk dan in ⚿ naar de sessies."


async def confirm_silence(db: AsyncSession, request: Request, sess: Session, user: User, title: str, action: str,
                          service_id: int | None = None, **detail) -> None:
    """Iets dat meldingen stillegt (onderhoud, een cronjob dempen, een webhook of logregel uit, een
    beveiligingspunt negeren): net als een check pauzeren vraagt dat een recente 2FA, komt het in het auditlog en krijg
    je er een melding van, ook op je gsm (bron auth, niveau warn). Anders is dat wat iemand met een gestolen sessie als
    eerste zou doen. Aanroepen vóór de wijziging: zonder 2FA verandert er niets."""
    await recent_auth(sess, user)
    await audit(db, request, user, action, **detail)
    notify(db, title, SILENCE_HINT, level="warn", source="auth", service_id=service_id)
