import hmac
import time
from datetime import datetime, timedelta, timezone

import pyotp
import segno
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import get_db
from ..deps import (COOKIE, audit, client_country, client_ip, current_session, current_user, notify, optional_session,
                    recent_auth, secure_cookie)
from ..models import AuditLog, Session, User
from ..monitoring import webpush
from ..security import (
    USER_FAILURE_FACTOR,
    check_setup_token,
    decrypt,
    encrypt,
    hash_password,
    limiter,
    new_token,
    token_id,
    verify_password,
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
    password: str | None = Field(default=None, max_length=256)
    code: str | None = Field(default=None, max_length=10)


class PasswordIn(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=12, max_length=256)


_clock = time.time


def _totp_ok(user: User, code: str | None) -> bool:
    """Code van de vorige, huidige of volgende stap van 30 s. Een gebruikte stap (of een oudere) wordt
    daarna geweigerd, zodat een afgekeken code niet nog eens kan dienen. De aanroeper bewaart."""
    if not code or not user.totp_secret:
        return False
    totp = pyotp.TOTP(decrypt(user.totp_secret))
    given = code.replace(" ", "").encode()
    now = int(_clock()) // totp.interval
    for step in (now - 1, now, now + 1):
        if step > (user.totp_last_step or -1) and hmac.compare_digest(totp.generate_otp(step).encode(), given):
            user.totp_last_step = step
            return True
    return False


def _too_many() -> HTTPException:
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Te veel pogingen, probeer later opnieuw")


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


async def _user_count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(User))).scalar_one()


@router.get("/state")
async def state(db: AsyncSession = Depends(get_db), sess: Session | None = Depends(optional_session)):
    user = sess.user if sess else None
    return {
        "setup_required": await _user_count(db) == 0,
        "user": {"username": user.username, "totp_enabled": user.totp_enabled} if user else None,
        "mfa_ok": bool(sess and sess.mfa_ok and user.totp_enabled),
        "site_name": get_settings().site_name,
    }


@router.post("/setup")
async def setup(data: SetupIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    if await _user_count(db) > 0:
        raise HTTPException(status.HTTP_409_CONFLICT, "Er bestaat al een account")
    if not check_setup_token(data.token):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Ongeldige setup-code")
    user = User(username=data.username, password_hash=hash_password(data.password))
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
    if not _totp_ok(user, data.code):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Code klopt niet")
    user.totp_enabled = True
    sess.mfa_ok = True
    sess.auth_at = datetime.now(timezone.utc)
    await audit(db, request, user, "totp_enabled")
    notify(db, "2FA ingeschakeld", f"Voor gebruiker {user.username}.", level="ok", source="auth")
    await db.commit()
    return {"ok": True}


@router.post("/login")
async def login(data: LoginIn, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    ip = client_ip(request) or "?"
    name = data.username.lower()
    # Foute wachtwoorden tellen per IP (streng) en per gebruikersnaam (ruim, zie USER_FAILURE_FACTOR).
    # Foute 2FA-codes na een juist wachtwoord tellen ook streng per gebruiker: die kent het wachtwoord al.
    ip_key, user_key, totp_key = f"ip:{ip}", f"user:{name}", f"totp:{name}"
    if limiter.blocked(ip_key, totp_key) or limiter.blocked(
            user_key, limit=get_settings().login_max_failures * USER_FAILURE_FACTOR):
        raise _too_many()
    user = (await db.execute(select(User).where(User.username == data.username))).scalar_one_or_none()
    if not verify_password(user.password_hash if user else None, data.password):
        limiter.fail(ip_key, user_key)
        await audit(db, request, user, "login_failed", username=data.username[:64])
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Onjuiste gebruikersnaam of wachtwoord")
    if user.totp_enabled:
        if not data.code:
            return {"ok": False, "code_required": True}
        if not _totp_ok(user, data.code):
            limiter.fail(ip_key, user_key, totp_key)
            await audit(db, request, user, "login_failed_totp")
            await db.commit()
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "2FA-code klopt niet")
    limiter.reset(ip_key, user_key, totp_key)
    if user.last_login_ip and user.last_login_ip != ip:
        cc = client_country(request)
        notify(db, "Login vanaf nieuw IP", f"{user.username} logde in vanaf {ip}{f' ({cc})' if cc else ''}.",
               level="warn", source="auth")
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = ip
    await _start_session(db, request, response, user, mfa_ok=user.totp_enabled)
    await audit(db, request, user, "login")
    await db.commit()
    return {"ok": True, "mfa_ok": user.totp_enabled}


def _confirm_keys(request: Request, user: User) -> tuple[str, str]:
    """Bevestigen (reauth, wachtwoord wijzigen) telt apart van het inloggen, per gebruiker en per IP."""
    return f"confirm:{user.id}", f"confirm-ip:{client_ip(request) or '?'}"


@router.post("/reauth")
async def reauth(data: ReauthIn, request: Request, sess: Session = Depends(current_session),
                 user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    keys = _confirm_keys(request, user)
    if limiter.blocked(*keys):
        raise _too_many()
    ok = (data.password and verify_password(user.password_hash, data.password)) or _totp_ok(user, data.code)
    if not ok:
        limiter.fail(*keys)
        await audit(db, request, user, "reauth_failed")
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Bevestiging mislukt")
    limiter.reset(*keys)
    sess.auth_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}


@router.post("/password")
async def change_password(data: PasswordIn, request: Request, sess: Session = Depends(current_session),
                          user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    keys = _confirm_keys(request, user)
    if limiter.blocked(*keys):
        raise _too_many()
    if not verify_password(user.password_hash, data.current):
        limiter.fail(*keys)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Huidig wachtwoord klopt niet")
    limiter.reset(*keys)
    user.password_hash = hash_password(data.new)
    # Alle andere sessies afmelden, en de vernieuwgeheimen van de gsm's laten vervallen.
    await db.execute(delete(Session).where(Session.user_id == user.id, Session.id != sess.id))
    await webpush.forget_renew(db, user.id)
    await audit(db, request, user, "password_changed")
    await db.commit()
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
