"""Beveiliging: recente 2FA voor gevoelige wijzigingen, rate limits, maskeren en TOTP-hergebruik."""

from datetime import datetime, timedelta, timezone

import pyotp
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select, update

from app.db import get_db
from app.main import app
from app.models import AppState, AuditLog, ConfigVersion, Session, SshHost
from app.monitoring import configs, upgrade
from app.security import encrypt, limiter

from .conftest import H, PASSWORD
from .test_integrations import _group, _svc


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _age_auth(db) -> None:
    """2FA-bevestiging een uur oud maken: gevoelige acties vragen dan opnieuw bevestigen."""
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()


async def _reauth(authed) -> None:
    r = await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})
    assert r.status_code == 200, r.text


# --- 1. service met secrets naar een ander adres --------------------------------------

async def test_service_target_change_with_secrets_needs_reauth(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "portainer", "https://portainer.lan", secrets={"key": "geheim"}, name="Portainer")
    agen, db = await _db()
    await _age_auth(db)
    base = {"group_id": g, "name": "Portainer", "type": "portainer", "url": "https://portainer.lan"}

    # Naam wijzigen mag gewoon.
    assert (await authed.patch(f"/api/services/{sid}", json={**base, "name": "Docker"})).status_code == 200
    base["name"] = "Docker"
    for change in ({"url": "https://evil.example"}, {"type": "npm"}, {"config": {"url": "https://evil.example"}}):
        r = await authed.patch(f"/api/services/{sid}", json={**base, **change})
        assert r.status_code == 403 and r.json()["detail"] == "reauth_required", change
    # Alle secrets opnieuw ingeven: dan lekt er niets weg.
    r = await authed.patch(f"/api/services/{sid}", json={**base, "url": "https://nieuw.lan", "secrets": {"key": "nieuw"}})
    assert r.status_code == 200
    # Eén ander geheim toevoegen is niet genoeg.
    r = await authed.patch(f"/api/services/{sid}", json={**base, "url": "https://x.lan", "secrets": {"extra": "y"}})
    assert r.status_code == 403

    await _reauth(authed)
    r = await authed.patch(f"/api/services/{sid}", json={**base, "url": "https://x.lan"})
    assert r.status_code == 200
    actions = [a.action for a in (await db.execute(select(AuditLog))).scalars()]
    assert "service_target_changed" in actions
    await agen.aclose()


async def test_service_without_secrets_can_move_freely(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "link", "https://a.lan", name="Link")
    agen, db = await _db()
    await _age_auth(db)
    r = await authed.patch(f"/api/services/{sid}", json={"group_id": g, "name": "Link", "url": "https://b.lan"})
    assert r.status_code == 200
    await agen.aclose()


# --- 2. rate limit op reauth en wachtwoord wijzigen ------------------------------------

async def test_reauth_rate_limited(authed):
    for _ in range(5):
        assert (await authed.post("/api/auth/reauth", json={"password": "fout-wachtwoord"})).status_code == 401
    r = await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})
    assert r.status_code == 429 and "Te veel" in r.json()["detail"]
    r = await authed.post("/api/auth/password", json={"current": PASSWORD, "new": "nog-een-lang-wachtwoord"})
    assert r.status_code == 429
    limiter._fails.clear()
    await _reauth(authed)


async def test_password_change_rate_limited(authed):
    for _ in range(5):
        r = await authed.post("/api/auth/password", json={"current": "fout-wachtwoord", "new": "nog-een-lang-wachtwoord"})
        assert r.status_code == 401
    r = await authed.post("/api/auth/password", json={"current": PASSWORD, "new": "nog-een-lang-wachtwoord"})
    assert r.status_code == 429


# --- 3. maskeren van KEY=waarde-regels, en eigen bestanden vragen 2FA --------------------

def test_mask_key_value_lines():
    text = ("[Interface]\nPrivateKey = abc=\nAddress = 10.0.0.1/24\nDB_PASSWORD=geheim\nexport API_TOKEN=\"x\"\n"
            "  client_secret: zz\nname: root\n<password>x</password>\n")
    out = configs.mask(text)
    for leak in ("abc=", "geheim", '"x"', "zz"):
        assert leak not in out
    assert "PrivateKey = •••" in out and "DB_PASSWORD=•••" in out and "client_secret: •••" in out
    assert "Address = 10.0.0.1/24" in out and "name: root" in out and "<password>•••</password>" in out
    # Al gemaskeerde JSON blijft zoals ze was.
    assert configs.mask('{"password": "abc", "user": "x"}') == '{"password": "•••", "user": "x"}'


async def test_file_diff_needs_recent_2fa(authed):
    agen, db = await _db()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for kind, item in (("file", "file:1:/etc/wireguard/wg0.conf"), ("pve", "pve:1:100")):
        for i, body in enumerate(("PrivateKey = oud\nPort = 1\n", "PrivateKey = nieuw\nPort = 2\n")):
            db.add(ConfigVersion(item=item, name=item, kind=kind, ts=now + timedelta(minutes=i), sha=f"{kind}{i}",
                                 size=len(body), added=1, removed=1, content=encrypt(body)))
    await db.commit()
    ids = {v.kind: v.id for v in (await db.execute(select(ConfigVersion).order_by(ConfigVersion.ts))).scalars()}
    await _age_auth(db)
    assert (await authed.get(f"/api/configs/versions/{ids['pve']}/diff")).status_code == 200
    r = await authed.get(f"/api/configs/versions/{ids['file']}/diff")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    await _reauth(authed)
    d = (await authed.get(f"/api/configs/versions/{ids['file']}/diff")).json()["diff"]
    assert "+Port = 2" in d and "nieuw" not in d and "oud" not in d
    await agen.aclose()


# --- 4. per-gebruiker blokkeren sluit de eigenaar niet buiten ---------------------------

async def test_failed_logins_from_one_ip_do_not_lock_out_owner(authed):
    secret = authed.totp_secret
    attacker = AsyncClient(transport=ASGITransport(app=app, client=("203.0.113.9", 1234)), base_url="http://test",
                           headers=H)
    for _ in range(6):
        await attacker.post("/api/auth/login", json={"username": "jonas", "password": "fout-wachtwoord"})
    assert (await attacker.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD})).status_code == 429
    owner = AsyncClient(transport=ASGITransport(app=app, client=("192.168.0.10", 1234)), base_url="http://test",
                        headers=H)
    r = await owner.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD,
                                                  "code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    await attacker.aclose()
    await owner.aclose()


def test_limiter_prune_keeps_no_empty_entries():
    limiter._fails.clear()
    assert not limiter.blocked("ip:onbekend")
    assert limiter._fails == {}
    limiter.fail("ip:x")
    limiter._fails["ip:x"][0] -= 10 ** 6  # ver buiten het venster
    assert not limiter.blocked("ip:x") and "ip:x" not in limiter._fails


# --- 5. SSH-hosts en snippets vragen een recente 2FA ------------------------------------

async def test_ssh_host_and_snippet_changes_need_reauth(authed):
    agen, db = await _db()
    await _age_auth(db)
    host = {"name": "pve", "host": "192.168.0.50"}
    for method, path, body in (("POST", "/api/ssh/hosts", host), ("PUT", "/api/ssh/snippets", []),
                               ("POST", "/api/ssh/import", [])):
        r = await authed.request(method, path, json=body)
        assert r.status_code == 403 and r.json()["detail"] == "reauth_required", path
    await _reauth(authed)
    hid = (await authed.post("/api/ssh/hosts", json=host)).json()["id"]
    await _age_auth(db)
    assert (await authed.patch(f"/api/ssh/hosts/{hid}", json=host)).status_code == 403
    assert (await authed.delete(f"/api/ssh/hosts/{hid}")).status_code == 403
    await agen.aclose()


# --- 7. een TOTP-code dient maar één keer ------------------------------------------------

async def test_totp_code_cannot_be_reused(authed):
    code = pyotp.TOTP(authed.totp_secret).now()
    assert (await authed.post("/api/auth/reauth", json={"code": code})).status_code == 200
    assert (await authed.post("/api/auth/reauth", json={"code": code})).status_code == 401
    await authed.post("/api/auth/logout")
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD, "code": code})
    assert r.status_code == 401
    r = await authed.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD,
                                                   "code": pyotp.TOTP(authed.totp_secret).now()})
    assert r.status_code == 200


async def test_totp_older_step_refused(authed, totp_clock):
    totp = pyotp.TOTP(authed.totp_secret)
    totp_clock[0] += 30
    newer, older = totp.at(totp_clock[0] + 30), totp.at(totp_clock[0] - 30)
    assert (await authed.post("/api/auth/reauth", json={"code": newer})).status_code == 200
    # Binnen het venster, maar ouder dan de laatst gebruikte stap.
    assert (await authed.post("/api/auth/reauth", json={"code": older})).status_code == 401


# --- 11. updates alleen voor machines uit de scan, en exacte nodenaam -------------------

async def test_install_refuses_unknown_targets_and_wildcards(authed):
    agen, db = await _db()
    db.add(SshHost(name="pve50", host="192.168.0.50", port=22, username=""))
    db.add(AppState(key="updates", value={"targets": []}))
    await db.commit()
    r = await authed.post("/api/updates/install", json={"targets": ["pve:1:%"]})
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["runs"] == [] and body["refused"][0]["why"] == "Staat niet in de laatste updatescan"

    # Een % in de nodenaam is geen jokerteken meer; hoofdletters maken niet uit.
    assert (await upgrade.plan_for(db, "pve:1:pve%")).host is None
    assert (await upgrade.plan_for(db, "pve:1:PVE50")).host.name == "pve50"
    await agen.aclose()
