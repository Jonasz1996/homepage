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
