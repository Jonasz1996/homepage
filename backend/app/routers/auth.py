import hmac
import math
import time
from datetime import datetime, timedelta, timezone

import pyotp
import segno
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value

from ..config import get_settings
from ..db import get_db
from ..deps import (COOKIE, audit, client_country, client_ip, current_session, current_user, limit_ip, notify,
                    optional_session, recent_auth, secure_cookie)
from ..models import AuditLog, Session, User
from ..monitoring import webpush
from ..security import (
    DEVICE_COOKIE,
    DEVICE_DAYS,
    USER_FAILURE_FACTOR,
    check_setup_token,
    decrypt,
    device_ok,
    device_token,
    encrypt,
    hash_password_async,
    limiter,
    new_token,
    password_slot,
    read_device,
    token_id,
    verify_password_async,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])

ISSUER = "homepage"


class SetupIn(BaseModel):
    token: str
    username: str = Field(min_length=2, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    password: str = Field(min_length=12, max_length=256)


class LoginIn(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=256)
    code: str | None = Field(default=None, max_length=10)


class CodeIn(BaseModel):
    code: str = Field(max_length=10)


class ReauthIn(BaseModel):
    # Alleen de 2FA-code: met het wachtwoord alleen kan het niet meer. Optioneel, zodat een verzoek zonder code een
    # gewone mislukte poging is (401, geteld en in de auditlog) en geen 422.
    code: str | None = Field(default=None, max_length=10)


class PasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=12, max_length=256)


_clock = time.time
# Het toestelcookie van een sessie die al ingelogd is, wordt hoogstens zo vaak vernieuwd (zie state).
DEVICE_REFRESH = 30 * 86400


def _totp_step(user: User, code: str | None) -> int | None:
    """De stap van 30 s (vorige, huidige of volgende) waar de code bij hoort. Een gebruikte stap (of een oudere)
    telt niet, zodat een afgekeken code niet nog eens kan dienen."""
    if not code or not user.totp_secret:
        return None
    totp = pyotp.TOTP(decrypt(user.totp_secret))
    given = code.replace(" ", "").encode()
    now = int(_clock()) // totp.interval
    for step in (now - 1, now, now + 1):
        if step > (user.totp_last_step or -1) and hmac.compare_digest(totp.generate_otp(step).encode(), given):
            return step
    return None


async def _claim_totp(db: AsyncSession, user: User, code: str | None) -> bool:
    """Klopt de code, dan de stap meteen in de database opeisen, voorwaardelijk: van twee verzoeken tegelijk met
    dezelfde code lukt er zo maar één (allebei lazen ze de rij nog vóór de ander bewaarde). De aanroeper bewaart."""
    step = _totp_step(user, code)
    if step is None:
        return False
    r = await db.execute(update(User).where(User.id == user.id, or_(User.totp_last_step.is_(None),
                                                                    User.totp_last_step < step))
                         .values(totp_last_step=step).execution_options(synchronize_session=False))
    if r.rowcount != 1:
        return False
    set_committed_value(user, "totp_last_step", step)
    return True


def _too_many() -> HTTPException:
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Te veel pogingen, probeer later opnieuw")


def _closed_for_new() -> HTTPException:
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                         "Te veel foute pogingen voor deze gebruikersnaam: nieuwe toestellen moeten even wachten. "
                         "Op een toestel waarop je al eens inlogde, lukt het wel.")


def _busy() -> HTTPException:
    # Telt niet als mislukte poging: er is niets gecontroleerd.
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Even te druk, probeer zo opnieuw")


def _set_device(request: Request, response: Response, user: User) -> None:
    """Dit toestel onthouden, een jaar lang (bij elke login opnieuw): hier geldt de limiet per gebruikersnaam niet.
    Lax: ook de terugkeer van Authentik (een navigatie van een ander domein) stuurt het mee."""
    dev = read_device(request.cookies.get(DEVICE_COOKIE))
    keep = dev["d"] if device_ok(dev, user) else None
    response.set_cookie(
        DEVICE_COOKIE, device_token(user.id, user.username, user.password_hash, keep), max_age=DEVICE_DAYS * 86400,
        httponly=True, secure=secure_cookie(request), samesite="lax", path="/api/auth",
    )


def new_ip_notice(db: AsyncSession, request: Request, user: User, known: bool, via: str = "") -> None:
    """Melding bij een login vanaf een ander IP dan de vorige. Op een bekend toestel ter info, anders een waarschuwing.
    Vóór last_login_ip bijgewerkt wordt."""
    ip = client_ip(request) or "?"
    if user.last_login_ip and user.last_login_ip != ip:
        cc = client_country(request)
        where = f"{ip}{f' ({cc})' if cc else ''}{' (bekend toestel)' if known else ''}"
        notify(db, "Login vanaf nieuw IP", f"{user.username} logde in{via} vanaf {where}.",
               level="info" if known else "warn", source="auth")


async def _start_session(db: AsyncSession, request: Request, response: Response, user: User, mfa_ok: bool) -> None:
    s = get_settings()
    token = new_token()
    now = datetime.now(timezone.utc)
    db.add(Session(
        id=token_id(token), user_id=user.id, mfa_ok=mfa_ok, created_at=now, auth_at=now,
        expires_at=now + timedelta(days=s.session_days), ip=client_ip(request), country=client_country(request),
        last_seen_at=now, user_agent=(request.headers.get("user-agent") or "")[:255],
    ))
    response.set_cookie(
        COOKIE, token, max_age=s.session_days * 86400, httponly=True,
        secure=secure_cookie(request), samesite="strict", path="/",
    )
    if mfa_ok:
        _set_device(request, response, user)


async def _user_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(User))).scalar_one()


@router.get("/state")
async def state(request: Request, response: Response, db: AsyncSession = Depends(get_db),
                sess: Session | None = Depends(optional_session)):
    user = sess.user if sess else None
    mfa_ok = bool(sess and sess.mfa_ok and user.totp_enabled)
    if mfa_ok:
        # Al ingelogd met 2FA, dus een bekend toestel: ook als het inlogde voor er toestelcookies waren. En een toestel
        # dat nooit opnieuw hoeft in te loggen (de sessie glijdt mee), houdt zo zijn cookie.
        dev = read_device(request.cookies.get(DEVICE_COOKIE))
        if not device_ok(dev, user) or time.time() - dev["t"] > DEVICE_REFRESH:
            _set_device(request, response, user)
    return {
        "setup_required": await _user_count(db) == 0,
        "user": {"username": user.username, "totp_enabled": user.totp_enabled} if user else None,
        "mfa_ok": mfa_ok,
        "site_name": get_settings().site_name,
    }


@router.post("/setup")
async def setup(data: SetupIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    if await _user_count(db) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Er bestaat al een account")
    if not check_setup_token(data.token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ongeldige setup-code")
    with password_slot() as free:
        if not free:
            raise _busy()
        pw_hash = await hash_password_async(data.password)
    user = User(username=data.username, password_hash=pw_hash)
    db.add(user)
    await db.flush()
    await _start_session(db, request, response, user, mfa_ok=False)
    await audit(db, request, user, "setup")
    await db.commit()
    return {"ok": True}


@router.get("/totp/enroll")
async def totp_enroll(sess: Session = Depends(current_session), db: AsyncSession = Depends(get_db)):
    user = sess.user
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA staat al aan")
    if not user.totp_secret:
        user.totp_secret = encrypt(pyotp.random_base32())
        await db.commit()
    secret = decrypt(user.totp_secret)
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.username, issuer_name=ISSUER)
    # Donker op wit: omgekeerde QR-codes worden door veel apps niet gelezen.
    svg = segno.make(uri, error="m").svg_inline(scale=5, dark="#000", light="#fff", border=3)
    return {"secret": secret, "uri": uri, "qr_svg": svg}


@router.post("/totp/enable")
async def totp_enable(data: CodeIn, request: Request, sess: Session = Depends(current_session),
                      db: AsyncSession = Depends(get_db)):
    user = sess.user
    if user.totp_enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "2FA staat al aan")
    if not await _claim_totp(db, user, data.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code klopt niet")
    user.totp_enabled = True
    sess.mfa_ok = True
    sess.auth_at = datetime.now(timezone.utc)
    await audit(db, request, user, "totp_enabled")
    notify(db, "2FA ingeschakeld", f"Voor gebruiker {user.username}.", level="ok", source="auth")
    await db.commit()
    return {"ok": True}


def _closed_notice(db: AsyncSession, user: User, key: str, limit: int) -> None:
    """Gaat de teller per gebruikersnaam dicht, dan één melding (ook op de gsm), niet bij elke poging daarna."""
    secs = limiter.newly_locked(key, limit)
    if secs:
        notify(db, "Inloggen dicht voor nieuwe toestellen",
               f"{limit} mislukte pogingen voor {user.username} binnen {get_settings().login_window_minutes} min. "
               f"Nieuwe toestellen kunnen de komende {math.ceil(secs / 60)} min niet inloggen (langer als de pogingen "
               f"doorgaan). Op een toestel waarop je al eens inlogde, lukt het wel.",
               level="warn", source="auth", key="login-dicht")


@router.post("/login")
async def login(data: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    s = get_settings()
    ip = client_ip(request) or "?"
    name = data.username.lower()
    # Foute wachtwoorden tellen per IP (streng) en per gebruikersnaam (ruim, zie USER_FAILURE_FACTOR). Op een toestel
    # waarop deze gebruiker al met 2FA inlogde, telt niet de teller per gebruikersnaam (die kan iedereen vullen) maar
    # een strenge per toestel. Foute 2FA-codes na een juist wachtwoord tellen streng per gebruiker, ook op een bekend
    # toestel: wie dat doet, kent het wachtwoord al.
    dev = read_device(request.cookies.get(DEVICE_COOKIE))
    dev = dev if dev and dev["n"] == name else None
    ip_key, user_key, totp_key = f"ip:{limit_ip(request)}", f"user:{name}", f"totp:{name}"
    user_limit = s.login_max_failures * USER_FAILURE_FACTOR
    name_key, name_limit = (f"dev:{dev['d']}", s.login_max_failures) if dev else (user_key, user_limit)
    if limiter.blocked(ip_key, totp_key):
        raise _too_many()
    if limiter.blocked(name_key, limit=name_limit):
        raise _too_many() if dev else _closed_for_new()
    with password_slot() as free:
        if not free:
            raise _busy()
        # Nog vóór de eerste await als mislukt tellen: zo zien verzoeken tegelijk elkaars poging, en raken er niet
        # meer door dan de limiet. Klopt het wachtwoord, dan wordt dit teruggedraaid of gewist.
        limiter.fail(ip_key, name_key)
        user = (await db.execute(select(User).where(func.lower(User.username) == name))).scalar_one_or_none()
        if dev and not device_ok(dev, user):
            # Een cookie van vóór een nieuw wachtwoord: toch een onbekend toestel, met de teller per gebruikersnaam.
            limiter.undo(name_key)
            dev, name_key = None, user_key
            if limiter.blocked(user_key, limit=user_limit):
                limiter.undo(ip_key)
                raise _closed_for_new()
            limiter.fail(user_key)
        pw_hash = user.password_hash if user else None
        # De verbinding terug naar de pool terwijl argon2 rekent (user blijft bruikbaar: expire_on_commit=False).
        await db.commit()
        ok = await verify_password_async(pw_hash, data.password)
    if not ok:
        await audit(db, request, user, "login_failed", username=data.username[:64])
        if user is not None and not dev:
            _closed_notice(db, user, user_key, user_limit)
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Onjuiste gebruikersnaam of wachtwoord")
    if user.totp_enabled:
        if not data.code:
            # Het wachtwoord klopte: deze tussenstap telt niet als mislukte poging.
            limiter.undo(ip_key, name_key)
            return {"ok": False, "code_required": True}
        # De teller voor 2FA-codes pas na het wachtwoord (een fout wachtwoord met een code erbij mag de 2FA van de
        # eigenaar niet dichtzetten), maar wel zonder await tussen kijken en tellen.
        if limiter.blocked(totp_key):
            limiter.undo(ip_key, name_key)
            raise _too_many()
        limiter.fail(totp_key)
        if not await _claim_totp(db, user, data.code):
            await audit(db, request, user, "login_failed_totp")
            if not dev:
                _closed_notice(db, user, user_key, user_limit)
            await db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2FA-code klopt niet")
    # Op een bekend toestel blijft de teller per gebruikersnaam staan: die geldt hier niet, en wissen zou ze weer
    # openzetten voor wie ze vulde.
    limiter.reset(ip_key, name_key, totp_key)
    new_ip_notice(db, request, user, known=dev is not None)
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = ip
    await _start_session(db, request, response, user, mfa_ok=user.totp_enabled)
    await audit(db, request, user, "login")
    await db.commit()
    return {"ok": True, "mfa_ok": user.totp_enabled}


def _confirm_keys(request: Request, sess: Session) -> tuple[str, str]:
    """Bevestigen (reauth, wachtwoord wijzigen) telt apart van het inloggen, per sessie en per IP. Niet per gebruiker:
    dan kon een gestolen sessie met foute codes het bevestigen op al je andere toestellen dichtzetten."""
    return f"confirm:{sess.id}", f"confirm-ip:{limit_ip(request)}"


@router.post("/reauth")
async def reauth(data: ReauthIn, request: Request, sess: Session = Depends(current_session),
                 user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    keys = _confirm_keys(request, sess)
    if limiter.blocked(*keys):
        raise _too_many()
    limiter.fail(*keys)  # vóór de eerste await, zoals bij het inloggen
    if not await _claim_totp(db, user, data.code):
        await audit(db, request, user, "reauth_failed")
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bevestiging mislukt")
    limiter.reset(*keys)
    sess.auth_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}


@router.post("/password")
async def change_password(data: PasswordIn, request: Request, response: Response,
                          sess: Session = Depends(current_session), user: User = Depends(recent_auth),
                          db: AsyncSession = Depends(get_db)):
    # recent_auth: met alleen een (gestolen) sessie en het wachtwoord kan het niet, er hoort een verse 2FA-code bij.
    keys = _confirm_keys(request, sess)
    if limiter.blocked(*keys):
        raise _too_many()
    with password_slot() as free:
        if not free:
            raise _busy()
        limiter.fail(*keys)  # vóór de eerste await
        await db.commit()  # geen verbinding vasthouden terwijl argon2 rekent
        ok = await verify_password_async(user.password_hash, data.current)
        new_hash = await hash_password_async(data.new) if ok else None
    if not ok:
        await audit(db, request, user, "password_change_failed")
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Huidig wachtwoord klopt niet")
    limiter.reset(*keys)
    user.password_hash = new_hash
    # Alle andere sessies afmelden, en de vernieuwgeheimen van de gsm's laten vervallen. Het nieuwe wachtwoord maakt
    # ook alle bekende toestellen weer onbekend (hun cookie hangt aan de hash); dit toestel krijgt hieronder een nieuw.
    await db.execute(delete(Session).where(Session.user_id == user.id, Session.id != sess.id))
    await webpush.forget_renew(db, user.id)
    await audit(db, request, user, "password_changed")
    notify(db, "Wachtwoord gewijzigd", f"Voor {user.username}, vanaf {client_ip(request) or '?'}. Alle andere "
           f"apparaten zijn afgemeld.", level="warn", source="auth")
    await db.commit()
    _set_device(request, response, user)
    return {"ok": True}


@router.post("/logout")
async def logout(request: Request, response: Response, sess: Session | None = Depends(optional_session),
                 db: AsyncSession = Depends(get_db)):
    if sess:
        await audit(db, request, sess.user, "logout")
        await db.delete(sess)
        await db.commit()
    request.state.renew_cookie = None
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


# --- Sessies en auditlog ----------------------------------------------------------

def _session_out(s: Session, current: str) -> dict:
    return {"id": s.id[:16], "current": s.id == current, "ip": s.ip, "country": s.country,
            "user_agent": s.user_agent, "created_at": s.created_at, "last_seen_at": s.last_seen_at or s.created_at,
            "expires_at": s.expires_at, "mfa_ok": s.mfa_ok}


@router.get("/sessions")
async def list_sessions(sess: Session = Depends(current_session), user: User = Depends(current_user),
                        db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(Session).where(Session.user_id == user.id)
                             .order_by(Session.created_at.desc()))).scalars().all()
    out = [_session_out(s, sess.id) for s in rows]
    return sorted(out, key=lambda x: (not x["current"], -x["last_seen_at"].timestamp()))


@router.delete("/sessions/{short_id}")
async def revoke_session(short_id: str, request: Request, sess: Session = Depends(current_session),
                         user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    # Naar buiten toe tonen we alleen de eerste 16 tekens van de sessie-id (zelf al een hash).
    if len(short_id) != 16 or sess.id.startswith(short_id):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Gebruik afmelden voor je eigen sessie")
    target = (await db.execute(select(Session).where(Session.user_id == user.id,
                                                     Session.id.startswith(short_id, autoescape=True)))).scalars().first()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sessie niet gevonden")
    await audit(db, request, user, "session_revoked", ip=target.ip, country=target.country)
    await db.delete(target)
    await db.commit()
    return {"ok": True}


@router.post("/sessions/revoke-others")
async def revoke_others(request: Request, sess: Session = Depends(current_session),
                        user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    result = await db.execute(delete(Session).where(Session.user_id == user.id, Session.id != sess.id))
    await webpush.forget_renew(db, user.id)
    await audit(db, request, user, "sessions_revoked", count=result.rowcount)
    await db.commit()
    return {"ok": True, "count": result.rowcount}


@router.get("/audit")
async def audit_log(before_id: int | None = None, action: str | None = None, limit: int = 100,
                    user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    limit = max(1, min(limit, 500))
    stmt = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit)
    if before_id is not None:
        stmt = stmt.where(AuditLog.id < before_id)
    if action:
        stmt = stmt.where(AuditLog.action.startswith(action[:64]))
    rows = (await db.execute(stmt)).scalars().all()
    names = {u.id: u.username for u in (await db.execute(select(User))).scalars()}
    return {"items": [{"id": a.id, "ts": a.ts, "action": a.action, "detail": a.detail, "ip": a.ip,
                       "user": names.get(a.user_id)} for a in rows],
            "more": len(rows) == limit}
