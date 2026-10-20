"""Inloggen met Authentik (OpenID Connect). Instellingen staan in de database, aan te passen in het dashboard."""

import json
import secrets
import time
from datetime import datetime, timezone
from html import escape
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, client_country, client_ip, current_user, notify, recent_auth, secure_cookie
from ..models import AppState, User
from ..oidc import OidcError, check_claims, discovery, has_mfa, jwks, pkce_pair, verify_signature
from ..security import decrypt, encrypt
from .auth import _start_session

router = APIRouter(prefix="/api/auth/oidc", tags=["oidc"])

KEY = "oidc"
STATE_COOKIE = "hp_oidc"
STATE_TTL = 600
_clients: dict[bool, httpx.AsyncClient] = {}


def client(insecure: bool = False) -> httpx.AsyncClient:
    if insecure not in _clients:
        _clients[insecure] = httpx.AsyncClient(verify=not insecure, follow_redirects=False, timeout=8)
    return _clients[insecure]


async def _settings(db: AsyncSession) -> dict:
    st = await db.get(AppState, KEY)
    return dict(st.value) if st else {}


def _redirect_uri(request: Request, cfg: dict) -> str:
    base = (cfg.get("redirect_base") or str(request.base_url)).rstrip("/")
    return base + "/api/auth/oidc/callback"


@router.get("")
async def public_config(db: AsyncSession = Depends(get_db)):
    """Voor het loginscherm: staat de knop aan, en met welk opschrift."""
    cfg = await _settings(db)
    enabled = bool(cfg.get("enabled") and cfg.get("issuer") and cfg.get("client_id"))
    return {"enabled": enabled, "label": cfg.get("label") or "Authentik"}


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
    return {"enabled": bool(cfg.get("enabled")), "issuer": cfg.get("issuer", ""), "client_id": cfg.get("client_id", ""),
            "has_secret": bool(cfg.get("client_secret")), "label": cfg.get("label") or "Authentik",
            "require_mfa": cfg.get("require_mfa", True), "username_claim": cfg.get("username_claim") or "preferred_username",
            "insecure": bool(cfg.get("insecure")), "redirect_base": cfg.get("redirect_base", ""),
            "redirect_uri": _redirect_uri(request, cfg)}


@router.put("/settings")
async def put_settings(data: SettingsIn, request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    cfg = await _settings(db)
    new = data.model_dump(exclude={"client_secret"})
    new["client_secret"] = cfg.get("client_secret")
    if data.client_secret is not None:
        new["client_secret"] = encrypt(data.client_secret) if data.client_secret else None
    if data.enabled:
        if not (data.issuer and data.client_id):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Vul issuer en client-id in")
        try:
            await discovery(client(data.insecure), data.issuer, fresh=True)
        except OidcError as e:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Issuer niet bruikbaar: {e}") from e
    st = await db.get(AppState, KEY)
    if st:
        st.value = new
    else:
        db.add(AppState(key=KEY, value=new))
    await audit(db, request, user, "oidc_settings_changed", enabled=data.enabled, issuer=data.issuer)
    await db.commit()
    return await read_settings(request, user, db)


@router.get("/start")
async def start(request: Request, db: AsyncSession = Depends(get_db)):
    cfg = await _settings(db)
    if not (cfg.get("enabled") and cfg.get("issuer") and cfg.get("client_id")):
        return RedirectResponse("/?" + urlencode({"login_error": "Inloggen via Authentik staat uit"}), status_code=303)
    try:
        disc = await discovery(client(bool(cfg.get("insecure"))), cfg["issuer"])
    except OidcError as e:
        return RedirectResponse("/?" + urlencode({"login_error": str(e)}), status_code=303)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    verifier, challenge = pkce_pair()
    params = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": _redirect_uri(request, cfg),
              "scope": "openid profile email", "state": state, "nonce": nonce,
              "code_challenge": challenge, "code_challenge_method": "S256"}
    resp = RedirectResponse(disc["authorization_endpoint"] + "?" + urlencode(params), status_code=303)
    # Lax: de terugkeer van Authentik is een gewone navigatie, die mag dit cookie meesturen.
    resp.set_cookie(STATE_COOKIE, encrypt(json.dumps({"s": state, "n": nonce, "v": verifier, "t": time.time()})),
                    max_age=STATE_TTL, httponly=True, secure=secure_cookie(request), samesite="lax",
                    path="/api/auth/oidc")
    return resp


def _done(target: str) -> HTMLResponse:
    # Via een eigen pagina doorsturen: zo is de volgende navigatie "same-site" en stuurt de browser
    # het (strikte) sessiecookie meteen mee.
    t = escape(target, quote=True)
    # (Een meta-refresh; inline scripts mogen niet van de Content-Security-Policy.)
    resp = HTMLResponse(f'<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="0;url={t}">'
                        f'<a href="{t}">verder</a>')
    resp.delete_cookie(STATE_COOKIE, path="/api/auth/oidc")
    return resp


async def _fail(db: AsyncSession, request: Request, reason: str, user: User | None = None, **detail) -> HTMLResponse:
    await audit(db, request, user, "login_failed_oidc", reason=reason, **detail)
    await db.commit()
    return _done("/?" + urlencode({"login_error": reason}))


@router.get("/callback")
async def callback(request: Request, code: str | None = None, state: str | None = None, error: str | None = None,
                   db: AsyncSession = Depends(get_db)):
    cfg = await _settings(db)
    if error:
        return await _fail(db, request, f"Authentik weigerde: {error[:80]}")
    try:
        saved = json.loads(decrypt(request.cookies.get(STATE_COOKIE) or ""))
    except Exception:
        saved = None
    if not saved or not state or not secrets.compare_digest(saved.get("s", ""), state) \
            or time.time() - saved.get("t", 0) > STATE_TTL:
        return await _fail(db, request, "Login verlopen of ongeldig, probeer opnieuw")
    if not (cfg.get("enabled") and cfg.get("issuer") and cfg.get("client_id")) or not code:
        return await _fail(db, request, "Inloggen via Authentik staat uit")
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
        id_token = (r.json() or {}).get("id_token")
        if not id_token:
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
        return await _fail(db, request, str(e))

    name = str(claims.get(cfg.get("username_claim") or "preferred_username") or "")
    user = (await db.execute(select(User).where(func.lower(User.username) == name.lower()))).scalar_one_or_none() \
        if name else None
    if user is None or not user.totp_enabled:
        return await _fail(db, request, f"Geen gebruiker '{name[:64]}' in het dashboard", username=name[:64])
    if cfg.get("require_mfa", True) and not has_mfa(claims):
        return await _fail(db, request, "Authentik meldt geen 2FA voor deze login (amr-claim). Zet 2FA aan in je "
                                        "Authentik-flow, of zet 'Authentik moet 2FA melden' uit.", user)

    ip = client_ip(request) or "?"
    if user.last_login_ip and user.last_login_ip != ip:
        cc = client_country(request)
        notify(db, "Login vanaf nieuw IP", f"{user.username} logde in via Authentik vanaf {ip}{f' ({cc})' if cc else ''}.",
               level="warn", source="auth")
    user.last_login_at = datetime.now(timezone.utc)
    user.last_login_ip = ip
    resp = _done("/")
    await _start_session(db, request, resp, user, mfa_ok=True)
    await audit(db, request, user, "login", method="oidc", amr=claims.get("amr"))
    await db.commit()
    return resp
