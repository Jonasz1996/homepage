import pyotp

from .conftest import PASSWORD, SETUP_TOKEN, do_setup


async def test_state_requires_setup(client):
    r = await client.get("/api/auth/state")
    assert r.json()["setup_required"] is True
    assert r.json()["user"] is None


async def test_setup_needs_valid_token(client):
    r = await client.post("/api/auth/setup", json={"token": "fout", "username": "jonas", "password": PASSWORD})
    assert r.status_code == 403


async def test_setup_rejects_short_password(client):
    r = await client.post("/api/auth/setup", json={"token": SETUP_TOKEN, "username": "jonas", "password": "kort"})
    assert r.status_code == 422


async def test_full_setup_and_second_setup_refused(client):
    await do_setup(client)
    r = await client.get("/api/auth/state")
    assert r.json()["mfa_ok"] is True
    r = await client.post("/api/auth/setup", json={"token": SETUP_TOKEN, "username": "xy", "password": PASSWORD})
    assert r.status_code == 409


async def test_layout_blocked_until_totp_enabled(client):
    await client.post("/api/auth/setup", json={"token": SETUP_TOKEN, "username": "jonas", "password": PASSWORD})
    r = await client.get("/api/layout")
    assert r.status_code == 401
    r = await client.post("/api/auth/totp/enable", json={"code": "000000"})
    assert r.status_code == 400


async def test_csrf_header_required(client):
    r = await client.post("/api/auth/login", json={"username": "a", "password": "b"},
                          headers={"X-Requested-With": ""})
    assert r.status_code == 403


async def test_login_with_totp(authed):
    secret = authed.totp_secret
    await authed.post("/api/auth/logout")
    assert (await authed.get("/api/layout")).status_code == 401

    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD})
    assert r.json() == {"ok": False, "code_required": True}
    assert (await authed.get("/api/layout")).status_code == 401

    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD, "code": "123456"})
    assert r.status_code == 401

    code = pyotp.TOTP(secret).now()
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD, "code": code})
    assert r.status_code == 200 and r.json()["mfa_ok"] is True
    assert (await authed.get("/api/layout")).status_code == 200


async def test_login_rate_limited(authed):
    await authed.post("/api/auth/logout")
    for _ in range(5):
        r = await authed.post("/api/auth/login", json={"username": "jonas", "password": "fout-wachtwoord"})
        assert r.status_code == 401
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD})
    assert r.status_code == 429


async def test_unknown_user_same_error(client):
    await do_setup(client)
    r = await client.post("/api/auth/login", json={"username": "niemand", "password": PASSWORD})
    assert r.status_code == 401
    assert r.json()["detail"] == "Onjuiste gebruikersnaam of wachtwoord"


async def test_password_change(authed):
    r = await authed.post("/api/auth/password", json={"current": PASSWORD, "new": "nog-een-lang-wachtwoord"})
    assert r.status_code == 200
    await authed.post("/api/auth/logout")
    code = pyotp.TOTP(authed.totp_secret).now()
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD, "code": code})
    assert r.status_code == 401


async def test_session_slides_when_half_expired(authed):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import select, update

    from app.db import get_db
    from app.main import app
    from app.models import Session

    agen = app.dependency_overrides[get_db]()
    db = await agen.__anext__()
    soon = datetime.now(timezone.utc) + timedelta(days=2)
    await db.execute(update(Session).values(expires_at=soon))
    await db.commit()
    r = await authed.get("/api/layout")
    assert r.status_code == 200
    assert "hp_session" in r.headers.get("set-cookie", "")
    db.expire_all()
    exp = (await db.execute(select(Session.expires_at))).scalar_one()
    exp = exp if exp.tzinfo else exp.replace(tzinfo=timezone.utc)
    assert exp > datetime.now(timezone.utc) + timedelta(days=13)
    await agen.aclose()


async def test_cookie_secure_auto_follows_scheme(client, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "cookie_secure", "auto")
    r = await client.post("https://test/api/auth/setup",
                          json={"token": SETUP_TOKEN, "username": "jonas", "password": PASSWORD})
    assert r.status_code == 200 and "secure" in r.headers["set-cookie"].lower()
    r = await client.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD})
    assert r.status_code == 200 and "secure" not in r.headers["set-cookie"].lower()
