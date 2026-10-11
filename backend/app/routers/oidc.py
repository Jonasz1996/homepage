"""Inloggen met Authentik (OpenID Connect). Instellingen staan in de database, aan te passen in het dashboard.

Een login via Authentik geldt alleen voor de gebruiker die dat Authentik-account zelf gekoppeld heeft (⚿ → authentik,
ingelogd met wachtwoord en 2FA, met een verse bevestiging). Het dashboard herkent het account aan de uitgever en de
vaste ID uit het ID-token (iss en sub), nooit aan de naam: die kan veranderen of bij iemand anders terechtkomen.
"""

import json
import secrets
import time
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, client_ip, current_session, current_user, notify, recent_auth, secure_cookie
from ..models import AppState, Session, User
from ..oidc import OidcError, check_claims, discovery, has_mfa, jwks, pkce_pair, subject_is_name, verify_signature
from ..security import DEVICE_COOKIE, decrypt, device_ok, encrypt, read_device
from .auth import _start_session, new_ip_notice

router = APIRouter(prefix="/api/auth/oidc", tags=["oidc"])

KEY = "oidc"
STATE_COOKIE = "hp_oidc"
STATE_TTL = 600
# Na een koppeling (gelukt of niet) terug naar ⚿ → authentik.
LINK_TARGET = "/?open=security&tab=sso"
NOT_LINKED = ("Dit Authentik-account is nog niet gekoppeld: log in met wachtwoord en 2FA en koppel het onder "
              "⚿ → authentik")
NO_MFA = ("Authentik meldt geen 2FA voor deze login (amr-claim). Zet 2FA aan in je Authentik-flow, of zet "
          "'Authentik moet 2FA melden' uit.")
SUBJECT_MODE = ("Authentik geeft je gebruikersnaam of e-mailadres door als vaste ID (sub): die kan veranderen of later "
                "bij iemand anders terechtkomen. Zet in Authentik bij de provider 'Subject mode' op 'Based on the "
                "User's hashed ID' en koppel opnieuw.")
_clients: dict[bool, httpx.AsyncClient] = {}


def client(insecure: bool = False) -> httpx.AsyncClient:
    if insecure not in _clients:
        _clients[insecure] = httpx.AsyncClient(verify=not insecure, follow_redirects=False, timeout=8)
    return _clients[insecure]


async def _settings(db: AsyncSession) -> dict:
    st = await db.get(AppState, KEY)
    return dict(st.value) if st else {}


async def _seen_issuer(db: AsyncSession, iss: str) -> None:
    """De issuer die Authentik nu meldt (net nagekeken tegen de discovery) onthouden als hij veranderde sinds het
    opslaan: anders bleef een koppeling bij die issuer in ⚿ → authentik en de checklist "verouderd" tot je de
    instellingen opnieuw opsloeg, ook al werkt inloggen."""
    st = await db.get(AppState, KEY)
    if st is not None and st.value.get("iss") != iss:
        st.value = {**st.value, "iss": iss}


def _redirect_uri(request: Request, cfg: dict) -> str:
    base = (cfg.get("redirect_base") or str(request.base_url)).rstrip("/")
    return base + "/api/auth/oidc/callback"


def _enabled(cfg: dict) -> bool:
    return bool(cfg.get("enabled") and cfg.get("issuer") and cfg.get("client_id"))


def _name(cfg: dict, claims: dict) -> str:
    """De naam bij Authentik, alleen om te tonen (auditlog, ⚿ → authentik): herkennen gebeurt op de sub."""
    return str(claims.get(cfg.get("username_claim") or "preferred_username") or "")[:64]


@router.get("")
async def public_config(db: AsyncSession = Depends(get_db)):
    """Voor het loginscherm: staat de knop aan, en met welk opschrift."""
    cfg = await _settings(db)
    return {"enabled": _enabled(cfg), "label": cfg.get("label") or "Authentik"}


class SettingsIn(BaseModel):
    enabled: bool = False
    issuer: str = Field(default="", max_length=300)
    client_id: str = Field(default="", max_length=200)
    # None = ongewijzigd, "" = wissen.
    client_secret: str | None = Field(default=None, max_length=500)
    label: str = Field(default="Authentik", max_length=40)
    require_mfa: bool = True
    username_claim: str = Field(default="preferred_username", pattern=r"^[A-Za-z0-9_.-]{1,40}$")
    insecure: bool = False
    redirect_base: str = Field(default="", max_length=300)

    @field_validator("issuer", "redirect_base")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if v and not v.lower().startswith(("https://", "http://")):
            raise ValueError("Moet met https:// beginnen")
        return v


@router.get("/settings")
async def read_settings(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    cfg = await _settings(db)
    # Gekoppeld bij een andere issuer dan die van nu (bv. na een andere slug of hostnaam): inloggen zoekt op de
    # issuer die Authentik nu meldt, dus die koppeling werkt niet meer.
    stale = bool(user.oidc_sub and cfg.get("iss") and user.oidc_issuer != cfg["iss"])
    return {"enabled": bool(cfg.get("enabled")), "issuer": cfg.get("issuer", ""), "client_id": cfg.get("client_id", ""),
            "has_secret": bool(cfg.get("client_secret")), "label": cfg.get("label") or "Authentik",
            "require_mfa": cfg.get("require_mfa", True), "username_claim": cfg.get("username_claim") or "preferred_username",
            "insecure": bool(cfg.get("insecure")), "redirect_base": cfg.get("redirect_base", ""),
            "redirect_uri": _redirect_uri(request, cfg),
            # Het gekoppelde Authentik-account van deze gebruiker (de sub zelf gaat niet naar de browser).
            "linked": bool(user.oidc_sub) and not stale, "link_stale": stale, "linked_name": user.oidc_name or "",
            "linked_issuer": user.oidc_issuer or ""}


@router.put("/settings")
async def put_settings(data: SettingsIn, request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    cfg = await _settings(db)
    new = data.model_dump(exclude={"client_secret"})
    new["client_secret"] = cfg.get("client_secret")
    if data.client_secret is not None:
        new["client_secret"] = encrypt(data.client_secret) if data.client_secret else None
    # De issuer zoals Authentik hem meldt (die staat in elk ID-token): daaraan ziet read_settings of de koppeling nog
    # klopt. Uit staat er niets te controleren; dezelfde issuer houdt wat er al stond.
    new["iss"] = cfg.get("iss") if data.issuer == cfg.get("issuer") else None
    if data.enabled:
        if not (data.issuer and data.client_id):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Vul issuer en client-id in")
        await db.commit()  # geen transactie open terwijl de provider antwoordt
        try:
            disc = await discovery(client(data.insecure), data.issuer, fresh=True)
        except OidcError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Issuer niet bruikbaar: {e}") from e
        new["iss"] = disc.get("issuer") or None
    st = await db.get(AppState, KEY)
    if st:
        st.value = new
    else:
        db.add(AppState(key=KEY, value=new))
    await audit(db, request, user, "oidc_settings_changed", enabled=data.enabled, issuer=data.issuer)
    await db.commit()
    return await read_settings(request, user, db)


async def _authorize(request: Request, db: AsyncSession, cfg: dict, **extra) -> tuple[str, str]:
    """Begin van een login of koppeling: (adres bij Authentik, inhoud van het state-cookie, met extra erin).
    Gooit OidcError als de provider niet bruikbaar is."""
    # Geen transactie open laten terwijl de provider antwoordt.
    await db.commit()
    disc = await discovery(client(bool(cfg.get("insecure"))), cfg["issuer"])
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = pkce_pair()
    params = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": _redirect_uri(request, cfg),
              "scope": "openid profile email", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    if extra.get("m") == "link":
        # Koppelen: Authentik vraagt opnieuw wie je bent, zodat niet stil het account gekoppeld wordt waarmee deze browser
        # toevallig bij Authentik ingelogd is (bv. akadmin).
        params["prompt"] = "login"
    cookie = encrypt(json.dumps({"s": state, "n": nonce, "v": verifier, "t": time.time(), **extra}))
    return disc["authorization_endpoint"] + "?" + urlencode(params), cookie


def _state_cookie(request: Request, response: Response, value: str) -> None:
    # Lax: de terugkeer van Authentik is een gewone navigatie, die mag dit cookie meesturen.
    response.set_cookie(STATE_COOKIE, value, max_age=STATE_TTL, httponly=True, secure=secure_cookie(request),
                        samesite="lax", path="/api/auth/oidc")


@router.get("/start")
async def start(request: Request, db: AsyncSession = Depends(get_db)):
    cfg = await _settings(db)
    if not _enabled(cfg):
        return RedirectResponse("/?" + urlencode({"login_error": "Inloggen via Authentik staat uit"}), status_code=303)
    try:
        url, cookie = await _authorize(request, db, cfg)
    except OidcError as e:
        return RedirectResponse("/?" + urlencode({"login_error": str(e)}), status_code=303)
    resp = RedirectResponse(url, status_code=303)
    _state_cookie(request, resp, cookie)
    return resp


@router.post("/link")
async def link(request: Request, response: Response, sess: Session = Depends(current_session),
               user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """Authentik-account koppelen: een gewone login bij Authentik, maar de terugkeer bewaart het account bij deze
    gebruiker in plaats van in te loggen. Het (versleutelde) state-cookie zegt dat, en bij welke sessie het hoort: het
    sessiecookie is strikt en komt niet mee met de terugkeer van Authentik."""
    cfg = await _settings(db)
    if not _enabled(cfg):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Zet inloggen via Authentik eerst aan en sla op")
    try:
        url, cookie = await _authorize(request, db, cfg, m="link", u=user.id, sid=sess.id)
    except OidcError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Authentik niet bruikbaar: {e}") from e
    _state_cookie(request, response, cookie)
    return {"url": url}


@router.delete("/link")
async def unlink(request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    if user.oidc_sub:
        await audit(db, request, user, "oidc_unlinked", name=user.oidc_name, sub=user.oidc_sub[:64])
        user.oidc_issuer = user.oidc_sub = user.oidc_name = None
        await db.commit()
    return await read_settings(request, user, db)


def _done(target: str) -> HTMLResponse:
    # Via een eigen pagina doorsturen: zo is de volgende navigatie "same-site" en stuurt de browser
    # het (strikte) sessiecookie meteen mee.
    t = escape(target, quote=True)
    # (Een meta-refresh; inline scripts mogen niet van de Content-Security-Policy.)
    resp = HTMLResponse(f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={t}">'
                        f'<a href="{t}">verder</a>')
    resp.delete_cookie(STATE_COOKIE, path="/api/auth/oidc")
    return resp


def _linking(saved: dict | None) -> bool:
    return bool(saved and saved.get("m") == "link")


def _back(saved: dict | None, reason: str, login_page: bool = False) -> HTMLResponse:
    """Terug met de fout: naar het loginscherm, of bij een koppeling naar ⚿ → authentik."""
    if _linking(saved) and not login_page:
        return _done(LINK_TARGET + "&" + urlencode({"oidc_error": reason}))
    return _done("/?" + urlencode({"login_error": reason}))


async def _fail(db: AsyncSession, request: Request, saved: dict | None, reason: str, user: User | None = None,
                login_page: bool = False, **detail) -> HTMLResponse:
    if _linking(saved):
        if user is None and isinstance(saved.get("u"), int):
            user = await db.get(User, saved["u"])
        await audit(db, request, user, "oidc_link_failed", reason=reason, **detail)
    else:
        await audit(db, request, user, "login_failed_oidc", reason=reason, **detail)
    await db.commit()
    return _back(saved, reason, login_page)


@router.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None,
                   db: AsyncSession = Depends(get_db)):
    cfg = await _settings(db)
    # Geen transactie open laten terwijl de provider antwoordt.
    await db.commit()
    try:
        saved = json.loads(decrypt(request.cookies.get(STATE_COOKIE) or ""))
    except Exception:
        saved = None
    if not isinstance(saved, dict):
        saved = None
    valid = bool(saved and state and secrets.compare_digest(saved.get("s", ""), state)
                 and time.time() - saved.get("t", 0) <= STATE_TTL)
    # Zonder geldig state-cookie kwam het verzoek niet van een login die hier begon: niet in de auditlog,
    # anders kan iedereen die vol schrijven.
    if error:
        reason = f"Authentik weigerde: {error[:80]}"
        return await _fail(db, request, saved, reason) if valid else _back(saved, reason)
    if not valid:
        return _back(saved, f"{'Koppelen' if _linking(saved) else 'Login'} verlopen of ongeldig, probeer opnieuw")
    if not _enabled(cfg) or not code:
        return await _fail(db, request, saved, "Inloggen via Authentik staat uit")
    http = client(bool(cfg.get("insecure")))
    secret = decrypt(cfg["client_secret"]) if cfg.get("client_secret") else None
    try:
        disc = await discovery(http, cfg["issuer"])
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": _redirect_uri(request, cfg),
                "client_id": cfg["client_id"], "code_verifier": saved["v"]}
        try:
            r = await http.post(disc["token_endpoint"], data=form,
                                auth=httpx.BasicAuth(cfg["client_id"], secret) if secret else None)
        except httpx.HTTPError as e:
            raise OidcError(f"Token ophalen mislukt ({type(e).__name__})") from e
        if r.status_code != 200:
            raise OidcError(f"Token ophalen mislukt (HTTP {r.status_code})")
        try:
            body = r.json()
        except ValueError as e:
            # Bv. een HTML-pagina van een proxy ertussen.
            raise OidcError("Token-antwoord van de provider is geen JSON") from e
        if not isinstance(body, dict):
            raise OidcError("Token-antwoord van de provider is geen JSON-object")
        id_token = body.get("id_token")
        if not id_token or not isinstance(id_token, str):
            raise OidcError("Geen ID-token ontvangen")
        keys = await jwks(http, disc["jwks_uri"]) if disc.get("jwks_uri") else []
        try:
            _, claims = verify_signature(id_token, keys, secret)
        except OidcError:
            if not disc.get("jwks_uri"):
                raise
            # Misschien heeft de provider nieuwe sleutels: één keer opnieuw ophalen.
            _, claims = verify_signature(id_token, await jwks(http, disc["jwks_uri"], fresh=True), secret)
        check_claims(claims, disc["issuer"], cfg["client_id"], saved["n"])
    except OidcError as e:
        return await _fail(db, request, saved, str(e))
    if _linking(saved):
        return await _link(db, request, cfg, saved, claims)

    # Alleen het gekoppelde account (uitgever en vaste ID), nooit op naam: die kan van iemand anders zijn.
    iss, sub, name = claims["iss"], claims["sub"], _name(cfg, claims)
    user = (await db.execute(select(User).where(User.oidc_sub == sub, User.oidc_issuer == iss))).scalar_one_or_none()
    if user is None:
        return await _fail(db, request, saved, NOT_LINKED, username=name, sub=sub[:64])
    if not user.totp_enabled:
        return await _fail(db, request, saved, "Dit account heeft nog geen 2FA in het dashboard", user)
    if cfg.get("require_mfa", True) and not has_mfa(claims):
        return await _fail(db, request, saved, NO_MFA, user)

    user.oidc_name = name or user.oidc_name
    await _seen_issuer(db, iss)
    new_ip_notice(db, request, user, known=device_ok(read_device(request.cookies.get(DEVICE_COOKIE)), user),
                  via=" via Authentik")
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = client_ip(request) or "?"
    resp = _done("/")
    await _start_session(db, request, resp, user, mfa_ok=True)
    await audit(db, request, user, "login", method="oidc", amr=claims.get("amr"))
    await db.commit()
    return resp


async def _link(db: AsyncSession, request: Request, cfg: dict, saved: dict, claims: dict) -> HTMLResponse:
    """Terugkeer van een koppeling: het Authentik-account bewaren bij de gebruiker die ze startte, als die sessie nog
    bestaat en volledig ingelogd is (wachtwoord en 2FA). Er komt geen nieuwe sessie bij."""
    sess = await db.get(Session, str(saved.get("sid") or ""))
    user = sess.user if sess else None
    alive = sess is not None and sess.expires_at.replace(tzinfo=sess.expires_at.tzinfo or timezone.utc) \
        > datetime.now(timezone.utc)
    if not (alive and sess.user_id == saved.get("u") and sess.mfa_ok and user.totp_enabled):
        # Niet (meer) ingelogd: de fout hoort op het loginscherm.
        return await _fail(db, request, saved, "Koppelen mislukt: je bent intussen afgemeld. Log opnieuw in en "
                                               "probeer het nog eens.", login_page=True)
    if cfg.get("require_mfa", True) and not has_mfa(claims):
        return await _fail(db, request, saved, NO_MFA, user)
    iss, sub, name = claims["iss"], claims["sub"], _name(cfg, claims)
    if subject_is_name(claims, cfg.get("username_claim") or "preferred_username"):
        return await _fail(db, request, saved, SUBJECT_MODE, user, sub=sub[:64])
    other = (await db.execute(select(User).where(User.oidc_sub == sub, User.id != user.id))).scalar_one_or_none()
    if other is not None:
        return await _fail(db, request, saved, f"Dit Authentik-account is al gekoppeld aan {other.username}", user)
    uid = user.id
    user.oidc_issuer, user.oidc_sub, user.oidc_name = iss, sub, name or None
    await _seen_issuer(db, iss)
    await audit(db, request, user, "oidc_linked", name=name, sub=sub[:64], issuer=iss)
    notify(db, "Authentik-account gekoppeld",
           f"{user.username} kan nu ook inloggen via Authentik, als {name or 'een account zonder naam'}. Was jij dit "
           "niet? Ontkoppel het onder ⚿ → authentik en wijzig je wachtwoord.", level="warn", source="auth")
    try:
        await db.commit()
    except IntegrityError:
        # Net tegelijk door een andere gebruiker gekoppeld.
        await db.rollback()
        return await _fail(db, request, saved, "Dit Authentik-account is al aan een andere gebruiker gekoppeld",
                           await db.get(User, uid))
    return _done(LINK_TARGET)
