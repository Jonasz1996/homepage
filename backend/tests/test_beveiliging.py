"""Beveiliging: recente 2FA voor gevoelige wijzigingen, rate limits, maskeren en TOTP-hergebruik."""

import asyncio
import gc
import threading
import time
from datetime import datetime, timedelta, timezone

import pyotp
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select, update

from app import security
from app.db import get_db
from app.main import app
from app.models import AppState, AuditLog, ConfigVersion, Notification, Session, SshHost
from app.monitoring import configs, upgrade
from app.security import DEVICE_COOKIE, LoginLimiter, encrypt, limiter

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


def _client(ip: str, device: str | None = None) -> AsyncClient:
    """Een eigen browser op een eigen IP, eventueel met een toestelcookie."""
    c = AsyncClient(transport=ASGITransport(app=app, client=(ip, 1234)), base_url="http://test", headers=H)
    if device:
        c.cookies.set(DEVICE_COOKIE, device)
    return c


async def _login(c: AsyncClient, password: str = PASSWORD, code: str | None = None, username: str = "jonas"):
    body = {"username": username, "password": password}
    if code:
        body["code"] = code
    return await c.post("/api/auth/login", json=body)


async def _notes(title: str) -> list[Notification]:
    agen, db = await _db()
    try:
        return list((await db.execute(select(Notification).where(Notification.title == title)
                                      .order_by(Notification.id))).scalars())
    finally:
        await agen.aclose()


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


async def test_reauth_needs_totp_not_password(authed):
    """Een gestolen sessie plus een afgekeken wachtwoord mag de terminal niet openzetten."""
    agen, db = await _db()
    await _age_auth(db)
    assert (await authed.post("/api/auth/reauth", json={"password": PASSWORD})).status_code == 401
    r = await authed.get("/api/ssh/ready")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await authed.post("/api/auth/reauth", json={"password": PASSWORD, "code": "000000"})).status_code == 401
    failed = (await db.execute(select(func.count()).select_from(AuditLog)
                               .where(AuditLog.action == "reauth_failed"))).scalar_one()
    assert failed == 2
    await _reauth(authed)
    assert (await authed.get("/api/ssh/ready")).status_code == 200
    await agen.aclose()


async def test_password_change_needs_recent_2fa(authed):
    agen, db = await _db()
    await _age_auth(db)
    body = {"current": PASSWORD, "new": "nog-een-lang-wachtwoord"}
    r = await authed.post("/api/auth/password", json=body)
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    await _reauth(authed)
    r = await authed.post("/api/auth/password", json={**body, "current": "fout-wachtwoord"})
    assert r.status_code == 401
    assert (await authed.post("/api/auth/password", json=body)).status_code == 200
    actions = [a.action for a in (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars()]
    assert "password_change_failed" in actions and actions[-1] == "password_changed"
    [note] = await _notes("Wachtwoord gewijzigd")
    assert note.level == "warn" and note.source == "auth" and "afgemeld" in note.body
    await agen.aclose()


async def test_confirm_limit_per_session(authed):
    """Foute codes vanuit een (gestolen) sessie zetten het bevestigen op je andere toestellen niet dicht."""
    thief = _client("203.0.113.9")
    r = await _login(thief, code=pyotp.TOTP(authed.totp_secret).now())
    assert r.status_code == 200, r.text
    for _ in range(5):
        assert (await thief.post("/api/auth/reauth", json={"code": "000000"})).status_code == 401
    assert (await thief.post("/api/auth/reauth", json={"code": "000000"})).status_code == 429
    await _reauth(authed)
    await thief.aclose()


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


async def test_parallel_wrong_logins_count_before_check(authed):
    """Pogingen tegelijk tellen al vóór het wachten op de database en argon2: van 20 komen er maar 5 door."""
    attacker = _client("203.0.113.9")
    rs = await asyncio.gather(*(_login(attacker, "fout-wachtwoord") for _ in range(20)))
    assert sorted(r.status_code for r in rs) == [401] * 5 + [429] * 15
    assert len(limiter._fails["ip:203.0.113.9"]) == 5 and len(limiter._fails["user:jonas"]) == 5
    await attacker.aclose()


async def test_parallel_totp_guesses_limited(authed):
    """Wie het wachtwoord kent, kan ook met verzoeken tegelijk van veel IP's niet meer dan 5 codes proberen."""
    clients = [_client(f"203.0.113.{i}") for i in range(1, 21)]
    rs = await asyncio.gather(*(_login(c, code="000000") for c in clients))
    wrong = [r for r in rs if r.status_code == 401]
    assert 0 < len(wrong) <= 5 and all(r.json()["detail"] == "2FA-code klopt niet" for r in wrong)
    assert all(r.status_code == 429 for r in rs if r.status_code != 401)
    for c in clients:
        await c.aclose()


async def test_code_required_step_not_counted(authed):
    """Het juiste wachtwoord zonder code (de tussenstap naar het codeveld) telt niet als mislukte poging."""
    await authed.post("/api/auth/logout")
    for _ in range(10):
        assert (await _login(authed)).json() == {"ok": False, "code_required": True}
    assert limiter._fails == {}
    assert (await _login(authed, code=pyotp.TOTP(authed.totp_secret).now())).status_code == 200


async def test_burst_from_one_ip_cannot_lock_username(authed):
    attacker = _client("203.0.113.9")
    await asyncio.gather(*(_login(attacker, "fout-wachtwoord") for _ in range(30)))
    owner = _client("198.51.100.7")  # een toestel dat hier nog nooit inlogde
    r = await _login(owner, code=pyotp.TOTP(authed.totp_secret).now())
    assert r.status_code == 200, r.text
    await attacker.aclose()
    await owner.aclose()


class _SlowHasher:
    """argon2 dat 0,3 s langer duurt en onthoudt in welke thread het rekende."""

    def __init__(self, real):
        self.real, self.threads = real, []

    def verify(self, password_hash, password):
        self.threads.append(threading.current_thread().name)
        time.sleep(0.3)
        return self.real.verify(password_hash, password)

    def hash(self, password):
        return self.real.hash(password)


async def test_password_check_off_event_loop(authed, monkeypatch):
    """Tijdens een reeks logins blijft de API antwoorden: argon2 rekent in een eigen thread."""
    slow = _SlowHasher(security._hasher)
    monkeypatch.setattr(security, "_hasher", slow)
    clients = [_client(f"203.0.113.{i}") for i in range(1, 5)]
    done = []

    async def login(c):
        await _login(c, "fout-wachtwoord")
        done.append("login")

    async def ping():
        await asyncio.sleep(0.05)
        t = time.monotonic()
        assert (await authed.get("/api/ping")).status_code == 200
        done.append("ping")
        return time.monotonic() - t

    # Zonder opruimronde van Python ertussen (die legt alles even stil en maakt de meting onbetrouwbaar).
    gc.collect()
    gc.disable()
    try:
        *_, took = await asyncio.gather(*(login(c) for c in clients), ping())
    finally:
        gc.enable()
    assert done[0] == "ping" and took < 0.2, (done, took)
    assert len(slow.threads) == 4 and all(n.startswith("argon2") for n in slow.threads)
    for c in clients:
        await c.aclose()


async def test_password_checks_capped(authed, monkeypatch):
    """Hoogstens 8 wachtwoordcontroles wachten tegelijk. De rest krijgt meteen 429, en dat telt niet als poging."""
    monkeypatch.setattr(security, "_hasher", _SlowHasher(security._hasher))
    clients = [_client(f"203.0.113.{i}") for i in range(1, 13)]
    rs = await asyncio.gather(*(_login(c, "fout-wachtwoord") for c in clients))
    assert sorted(r.status_code for r in rs) == [401] * 8 + [429] * 4
    assert {r.json()["detail"] for r in rs if r.status_code == 429} == {"Even te druk, probeer zo opnieuw"}
    assert len([k for k in limiter._fails if k.startswith("ip:")]) == 8 and len(limiter._fails["user:jonas"]) == 8
    assert security._pending == 0
    for c in clients:
        await c.aclose()


# --- 4b. bekende toestellen ----------------------------------------------------------

async def test_known_device_not_locked_by_username_limit(authed):
    secret = authed.totp_secret
    owner = _client("192.168.0.10")
    assert (await _login(owner, code=pyotp.TOTP(secret).now())).status_code == 200
    device = owner.cookies.get(DEVICE_COOKIE)
    assert device
    await owner.post("/api/auth/logout")
    assert owner.cookies.get(DEVICE_COOKIE) == device  # afmelden vergeet het toestel niet

    # Zes IP's met elk vijf foute wachtwoorden: de teller per gebruikersnaam (30) is vol. Eén melding.
    for i in range(1, 7):
        async with _client(f"203.0.113.{i}") as a:
            for _ in range(5):
                assert (await _login(a, "fout-wachtwoord")).status_code == 401
    async with _client("203.0.113.7") as a:
        assert (await _login(a, "fout-wachtwoord")).status_code == 429
    [note] = await _notes("Inloggen dicht voor nieuwe toestellen")
    assert note.level == "warn" and "min" in note.body and "toestel waarop je al eens inlogde" in note.body

    # Een nieuw toestel komt er niet in, ook niet met het juiste wachtwoord en een goede code.
    async with _client("198.51.100.7") as new:
        r = await _login(new, code=pyotp.TOTP(secret).now())
        assert r.status_code == 429 and "nieuwe toestellen" in r.json()["detail"]
    # Het bekende toestel wel, ook vanaf een ander IP. Maar niet vanaf een IP dat zelf dicht is.
    async with _client("203.0.113.1", device) as blocked_ip:
        assert (await _login(blocked_ip, code=pyotp.TOTP(secret).now())).status_code == 429
    assert (await _login(owner, code=pyotp.TOTP(secret).now())).status_code == 200
    traveller = _client("198.51.100.8", device)
    assert (await _login(traveller, code=pyotp.TOTP(secret).now())).status_code == 200
    assert len(await _notes("Inloggen dicht voor nieuwe toestellen")) == 1

    # Een nieuw wachtwoord maakt de bekende toestellen weer onbekend, behalve het toestel dat het wijzigde.
    new_pw = "nog-een-lang-wachtwoord"
    r = await owner.post("/api/auth/password", json={"current": PASSWORD, "new": new_pw})
    assert r.status_code == 200, r.text
    await traveller.post("/api/auth/logout")
    r = await _login(traveller, new_pw, code=pyotp.TOTP(secret).now())
    assert r.status_code == 429 and "nieuwe toestellen" in r.json()["detail"]
    await owner.post("/api/auth/logout")
    assert (await _login(owner, new_pw, code=pyotp.TOTP(secret).now())).status_code == 200
    await owner.aclose()
    await traveller.aclose()


async def test_device_cookie_tampered_or_other_name_ignored(authed):
    secret = authed.totp_secret
    owner = _client("192.168.0.10")
    assert (await _login(owner, code=pyotp.TOTP(secret).now())).status_code == 200
    device = owner.cookies.get(DEVICE_COOKIE)
    i = len(device) // 2
    tampered = device[:i] + ("A" if device[i] != "A" else "B") + device[i + 1:]
    limiter.fail(*["user:jonas"] * 30, *["user:admin"] * 30)
    async with _client("198.51.100.7", tampered) as c:
        assert (await _login(c, code=pyotp.TOTP(secret).now())).status_code == 429
    async with _client("198.51.100.8", device) as c:
        r = await _login(c, code=pyotp.TOTP(secret).now(), username="admin")
        assert r.status_code == 429 and "nieuwe toestellen" in r.json()["detail"]
        assert (await _login(c, code=pyotp.TOTP(secret).now())).status_code == 200
    await owner.aclose()


async def test_known_device_has_own_limit(authed):
    """Een gekopieerd toestelcookie geeft geen eindeloze pogingen: 5 per toestel, over alle IP's samen."""
    secret = authed.totp_secret
    owner = _client("192.168.0.10")
    assert (await _login(owner, code=pyotp.TOTP(secret).now())).status_code == 200
    device = owner.cookies.get(DEVICE_COOKIE)
    for i, n in ((1, 3), (2, 2)):
        async with _client(f"203.0.113.{i}", device) as c:
            for _ in range(n):
                assert (await _login(c, "fout-wachtwoord")).status_code == 401
    async with _client("203.0.113.3", device) as c:
        r = await _login(c, code=pyotp.TOTP(secret).now())
        assert r.status_code == 429 and r.json()["detail"] == "Te veel pogingen, probeer later opnieuw"
    # Die pogingen telden niet per gebruikersnaam: een ander toestel kan gewoon inloggen.
    assert "user:jonas" not in limiter._fails
    async with _client("198.51.100.7") as c:
        assert (await _login(c, code=pyotp.TOTP(secret).now())).status_code == 200
    await owner.aclose()


async def test_state_sets_device_cookie_for_logged_in_session(authed):
    """Wie al ingelogd was (ook van vóór de toestelcookies), is meteen een bekend toestel."""
    r = await authed.get("/api/auth/state")
    cookie = r.headers.get("set-cookie", "")
    assert cookie.startswith(f"{DEVICE_COOKIE}=")
    assert all(p in cookie.lower() for p in ("httponly", "max-age=31536000", "path=/api/auth", "samesite=lax"))
    assert DEVICE_COOKIE not in (await authed.get("/api/auth/state")).headers.get("set-cookie", "")
    async with _client("198.51.100.7") as c:
        assert DEVICE_COOKIE not in (await c.get("/api/auth/state")).headers.get("set-cookie", "")
    limiter.fail(*["user:jonas"] * 30)
    await authed.post("/api/auth/logout")
    assert (await _login(authed, code=pyotp.TOTP(authed.totp_secret).now())).status_code == 200


async def test_new_ip_alert_mentions_known_device(authed):
    secret = authed.totp_secret
    home = _client("192.168.0.10")
    assert (await _login(home, code=pyotp.TOTP(secret).now())).status_code == 200
    async with _client("198.51.100.7", home.cookies.get(DEVICE_COOKIE)) as known:
        assert (await _login(known, code=pyotp.TOTP(secret).now())).status_code == 200
    async with _client("198.51.100.8") as unknown:
        assert (await _login(unknown, code=pyotp.TOTP(secret).now())).status_code == 200
    notes = await _notes("Login vanaf nieuw IP")
    assert [(n.level, n.body.endswith("(bekend toestel).")) for n in notes] == [("info", True), ("warn", False)]
    await home.aclose()


def test_limiter_memory_bounded(monkeypatch):
    monkeypatch.setattr(LoginLimiter, "MAX_KEYS", 100)
    lim = LoginLimiter()
    lim.fail(*["user:jonas"] * 5)
    for i in range(1000):
        lim.fail(f"ip:10.0.{i // 256}.{i % 256}")
    assert len(lim._fails) <= 101 and len(lim._fails["user:jonas"]) == 5
    # Wat buiten het venster valt, gaat als eerste weg.
    lim = LoginLimiter()
    for i in range(100):
        lim.fail(f"ip:a{i}")
    for q in lim._fails.values():
        q[0] -= 10 ** 6
    lim.fail("ip:nieuw")
    assert list(lim._fails) == ["ip:nieuw"]


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


async def test_totp_claim_is_atomic(authed):
    """Dezelfde code twee keer tegelijk (allebei lezen ze de gebruiker vóór de ander bewaart): er lukt er maar één,
    bij het bevestigen en bij het inloggen."""
    code = pyotp.TOTP(authed.totp_secret).now()
    rs = await asyncio.gather(*(authed.post("/api/auth/reauth", json={"code": code}) for _ in range(2)))
    assert sorted(r.status_code for r in rs) == [200, 401]
    code = pyotp.TOTP(authed.totp_secret).now()
    clients = [_client(f"198.51.100.{i}") for i in (1, 2)]
    rs = await asyncio.gather(*(_login(c, code=code) for c in clients))
    assert sorted(r.status_code for r in rs) == [200, 401], [r.text for r in rs]
    for c in clients:
        await c.aclose()


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
