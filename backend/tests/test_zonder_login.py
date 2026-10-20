"""Zonder login (zonderlogin.py): geen wachtwoord en geen 2FA-code, thuis en van buitenaf, tot Authentik ervoor staat.
Van buitenaf blijven terminal, updates, acties en downloads dicht; alleen op een bekend adres en alleen voor de
frontend zelf."""

import asyncio
import json
from pathlib import Path

import pyotp
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from app import zonderlogin
from app.integrations import calls as callmod
from app.db import ensure_state
from app.main import app
from app.monitoring import checks
from app.models import AppState, AuditLog, ConfigVersion, Notification, Session
from app.routers import ssh as ssh_router
from app.security import DEVICE_COOKIE, USER_FAILURE_FACTOR, encrypt

from .conftest import H, PASSWORD, SETUP_TOKEN, TEST_DB
from .test_buitenaf import CF, _db, _stale
from .test_ssh import sshd  # noqa: F401  (fixture)

LAN = "192.168.0.50"
WAN = "81.82.83.84"


def _client(ip: str, host: str = "192.168.10.156", headers: dict | None = None) -> AsyncClient:
    """Een browser zonder cookie, op een eigen IP en een eigen adres."""
    return AsyncClient(transport=ASGITransport(app=app, client=(ip, 1234)), base_url=f"http://{host}",
                       headers=H if headers is None else headers)


async def _mode(authed, mode: str) -> dict:
    """Thuis, met een echte login (de testclient is 127.0.0.1, dus nooit zonder login)."""
    r = await authed.put("/api/outside/aanmelden", json={"mode": mode})
    assert r.status_code == 200, r.text
    return r.json()


async def _state(key: str) -> dict:
    agen, db = await _db()
    try:
        st = await db.get(AppState, key)
        return dict(st.value or {}) if st else {}
    finally:
        await agen.aclose()


def test_standaard_overal():
    """Zonder keuze: geen login (Jonas, 2026-10-17). conftest zet het voor de andere tests op "uit"."""
    src = Path(zonderlogin.__file__).read_text()
    assert '\nDEFAULT = "overal"\n' in src
    assert zonderlogin.DEFAULT == "uit"


async def test_standaard_zonder_keuze_geen_login(authed, monkeypatch):
    monkeypatch.setattr(zonderlogin, "DEFAULT", "overal")
    async with _client(LAN) as c:
        s = (await c.get("/api/auth/state")).json()
        assert s["mfa_ok"] is True and s["zonder_login"] is True and s["sessie"] is False
        assert s["user"]["username"] == "jonas"
        assert (await c.get("/api/layout")).status_code == 200
    async with _client(WAN) as c:
        assert (await c.get("/api/auth/state")).json()["mfa_ok"] is True
    assert (await authed.get("/api/outside")).json()["aanmelden"]["mode"] == "overal"


async def test_uit_vraagt_login(authed):
    async with _client(LAN) as c:
        assert (await c.get("/api/layout")).status_code == 401
        assert (await c.get("/api/auth/state")).json()["mfa_ok"] is False


async def test_eerst_setup_en_2fa(client):
    """Geen gebruiker, of nog geen 2FA: dan eerst de setup, ook zonder login."""
    agen, db = await _db()
    db.add(AppState(key=zonderlogin.KEY, value={"mode": "overal"}))
    await db.commit()
    await agen.aclose()
    async with _client(LAN) as c:
        assert (await c.get("/api/auth/state")).json()["mfa_ok"] is False
        r = await c.post("/api/auth/setup", json={"token": SETUP_TOKEN, "username": "jonas", "password": PASSWORD})
        assert r.status_code == 200, r.text
    async with _client(LAN) as other:
        # Wachtwoord gezet, 2FA nog niet: een ander krijgt dat account niet zonder login.
        s = (await other.get("/api/auth/state")).json()
        assert s["mfa_ok"] is False and s["user"] is None
        assert (await other.get("/api/auth/totp/enroll")).status_code == 401


async def test_thuis_wel_buiten_niet(authed):
    a = await _mode(authed, "thuis")
    assert a["mode"] == "thuis" and a["label"] == "thuis zonder login"
    async with _client(LAN) as c:
        assert (await c.get("/api/layout")).status_code == 200
    async with _client(WAN) as c:
        assert (await c.get("/api/layout")).status_code == 401
    async with _client(LAN, headers={**H, **CF}) as c:
        assert (await c.get("/api/layout")).status_code == 401


async def test_overal_ook_buiten_maar_geen_vervalst_cf(authed):
    await _mode(authed, "overal")
    async with _client(WAN) as c:
        assert (await c.get("/api/layout")).status_code == 200
    async with _client(LAN, headers={**H, **CF}) as c:
        assert (await c.get("/api/layout")).status_code == 200
    async with _client(LAN, headers={**H, "X-Homepage-Cf-Forged": "1"}) as c:
        assert (await c.get("/api/layout")).status_code == 401


async def test_niet_vanaf_de_container_zelf(authed):
    await _mode(authed, "overal")
    async with _client("127.0.0.1") as c:
        assert (await c.get("/api/layout")).status_code == 401
    async with _client("::1") as c:
        assert (await c.get("/api/layout")).status_code == 401


async def test_alleen_een_bekend_adres(authed):
    """Een naam werkt pas zonder login als er al eens iemand met een echte login op binnenkwam (DNS-rebinding)."""
    await _mode(authed, "overal")
    for host in ("192.168.10.156", "192.168.10.156:8080", "[fd00::5]:80", "localhost:5173"):
        async with _client(LAN, host=host) as c:
            assert (await c.get("/api/layout")).status_code == 200, host
    async with _client(LAN, host="homepage.jbogaert.be") as c:
        assert (await c.get("/api/layout")).status_code == 401
        why = (await c.get("/api/auth/state")).json()
        assert why["mfa_ok"] is False
    # Met login op die naam: daarna onthouden.
    r = await authed.get("/api/layout", headers={"Host": "Homepage.Jbogaert.BE."})
    assert r.status_code == 200
    # "test": de naam van de testclient, die zich met login aanmeldde.
    assert (await _state(zonderlogin.NAMES_KEY))["names"] == ["test", "homepage.jbogaert.be"]
    async with _client(LAN, host="homepage.jbogaert.be") as c:
        assert (await c.get("/api/layout")).status_code == 200
    async with _client(LAN, host="evil.example") as c:
        assert (await c.get("/api/layout")).status_code == 401
    a = (await authed.get("/api/outside")).json()["aanmelden"]
    assert a["names"] == ["test", "homepage.jbogaert.be"]
    assert a["nu"] is False and "dashboard zelf" in a["why"]


async def test_hoogstens_twintig_namen(authed):
    for i in range(25):
        assert (await authed.get("/api/layout", headers={"Host": f"n{i}.jbogaert.be"})).status_code == 200
    # Geen naam: rare tekens, of een IP.
    for host in ("a_b.example", "10.0.0.1", "localhost"):
        await authed.get("/api/layout", headers={"Host": host})
    names = (await _state(zonderlogin.NAMES_KEY))["names"]
    assert names == [f"n{i}.jbogaert.be" for i in range(5, 25)]


async def test_alleen_voor_de_frontend(authed):
    """Een andere website kan met een <img> of een formulier niets laten doen: de header of Sec-Fetch-Site."""
    await _mode(authed, "overal")
    async with _client(LAN, headers={}) as c:
        assert (await c.get("/api/layout")).status_code == 401
        assert (await c.get("/api/layout", headers={"Sec-Fetch-Site": "cross-site"})).status_code == 401
        assert (await c.get("/api/layout", headers={"Sec-Fetch-Site": "same-site"})).status_code == 401
        assert (await c.get("/api/layout", headers={"Sec-Fetch-Site": "same-origin"})).status_code == 200
        assert (await c.get("/api/layout", headers={"Sec-Fetch-Site": "none"})).status_code == 200
        # Schrijven zonder de header: csrf_guard zoals altijd.
        r = await c.put("/api/outside/aanmelden", json={"mode": "uit"}, headers={"Sec-Fetch-Site": "same-origin"})
        assert r.status_code in (401, 403)
    assert (await authed.get("/api/outside")).json()["aanmelden"]["mode"] == "overal"


async def test_gevoelig_zonder_code_en_in_de_auditlog(authed):
    await _mode(authed, "thuis")
    async with _client(LAN) as c:
        r = await c.put("/api/outside/settings", json={"home_ip": False, "networks": []})
        assert r.status_code == 200, r.text
    agen, db = await _db()
    rows = list((await db.execute(select(AuditLog).where(AuditLog.action == "outside_settings"))).scalars())
    await agen.aclose()
    assert rows[-1].detail.get("zonder_login") is True and rows[-1].ip == LAN


async def test_van_buitenaf_blijft_gevaarlijk_dicht(authed):
    for f in ("terminal", "updates", "acties", "downloads"):
        r = await authed.put(f"/api/outside/features/{f}", json={"mode": "aan"})
        assert r.status_code == 200, r.text
    await _mode(authed, "overal")
    async with _client(WAN) as c:
        r = await c.get("/api/ssh/ready")
        assert r.status_code == 403 and r.json()["detail"] == "buiten:terminal"
        r = await c.post("/api/updates/install", json={})
        assert r.status_code == 403 and r.json()["detail"] == "buiten:updates"
        r = await c.get("/api/diagnose")
        assert r.status_code == 403 and r.json()["detail"] == "buiten:downloads"
        r = await c.post("/api/heal", json={})
        assert r.status_code == 403 and r.json()["detail"] == "buiten:acties"
        # En aanzetten gaat ook niet.
        r = await c.put("/api/outside/features/terminal", json={"mode": "uur"})
        assert r.status_code == 403 and "Zonder login" in r.json()["detail"]
        # Uitzetten mag wel.
        assert (await c.put("/api/outside/features/updates", json={"mode": "uit"})).status_code == 200
        out = (await c.get("/api/outside")).json()
        assert out["outside"] is True and out["aanmelden"]["nu"] is True and out["aanmelden"]["sessie"] is False
    # Thuis zonder login: wel.
    async with _client(LAN) as c:
        assert (await c.get("/api/ssh/ready")).status_code != 403
    # Van buitenaf met een echte login: zoals vroeger (de functie staat op altijd).
    r = await authed.get("/api/ssh/ready", headers=CF)
    assert r.status_code != 403, r.text


async def test_aanmelden_van_buitenaf_alleen_strenger(authed):
    """Van buitenaf kan de stand alleen strenger: losser zetten (en dus de terminal bereikbaarder) kan alleen thuis."""
    await _mode(authed, "overal")
    async with _client(WAN) as c:
        assert (await c.put("/api/outside/aanmelden", json={"mode": "overal"})).status_code == 200  # niets nieuws
        r = await c.put("/api/outside/aanmelden", json={"mode": "thuis"})
        assert r.status_code == 200 and r.json()["mode"] == "thuis" and r.json()["nu"] is False
        assert (await c.get("/api/layout")).status_code == 401
    await _mode(authed, "overal")
    async with _client(WAN) as c:
        r = await c.put("/api/outside/aanmelden", json={"mode": "uit"})
        assert r.status_code == 200 and r.json()["mode"] == "uit" and r.json()["nu"] is False
        assert (await c.get("/api/layout")).status_code == 401
    assert (await _state(zonderlogin.KEY))["mode"] == "uit"
    # Van buitenaf met een echte login en een verse 2FA: losser zetten gaat toch niet.
    for mode in ("thuis", "overal"):
        r = await authed.put("/api/outside/aanmelden", json={"mode": mode}, headers=CF)
        assert r.status_code == 403 and "losser" in r.json()["detail"], r.text
    await _mode(authed, "thuis")
    r = await authed.put("/api/outside/aanmelden", json={"mode": "overal"}, headers=CF)
    assert r.status_code == 403, r.text
    assert (await authed.put("/api/outside/aanmelden", json={"mode": "uit"}, headers=CF)).status_code == 200
    agen, db = await _db()
    notes = [n.title for n in (await db.execute(select(Notification).order_by(Notification.id))).scalars()]
    await agen.aclose()
    assert notes[-5:] == ["Aanmelden: thuis zonder login", "Aanmelden: overal zonder login", "Aanmelden: altijd met 2FA",
                          "Aanmelden: thuis zonder login", "Aanmelden: altijd met 2FA"]
    assert (await authed.put("/api/outside/aanmelden", json={"mode": "ergens"})).status_code == 422


async def test_strenger_van_buitenaf_overschrijft_thuis_niet(authed, monkeypatch):
    """Zet Jonas thuis net 'altijd met 2FA' terwijl een bezoeker van buitenaf 'thuis zonder' kiest, dan wint die lossere
    stand niet: de controle kijkt naar de stand die overschreven wordt."""
    from app.routers import outside as outside_router

    await _mode(authed, "overal")
    orig = outside_router.ensure_state

    async def thuis_eerst(db, key, value=None):  # Jonas' verzoek komt net ertussen
        st = await orig(db, zonderlogin.KEY, {})
        st.value = {"mode": "uit"}
        await db.commit()
        return await orig(db, key, value)

    monkeypatch.setattr(outside_router, "ensure_state", thuis_eerst)
    async with _client(WAN) as c:
        r = await c.put("/api/outside/aanmelden", json={"mode": "thuis"})
        assert r.status_code == 403 and "losser" in r.json()["detail"], r.text
    assert (await _state(zonderlogin.KEY))["mode"] == "uit"


async def test_authentik_van_buitenaf_alleen_met_login(authed):
    await _mode(authed, "overal")
    body = {"enabled": False, "issuer": "https://evil.example/", "client_id": "x"}
    async with _client(WAN) as c:
        r = await c.put("/api/auth/oidc/settings", json=body)
        assert r.status_code == 403, r.text
        assert (await c.delete("/api/auth/oidc/link")).status_code == 403
    async with _client(LAN) as c:
        assert (await c.put("/api/auth/oidc/settings", json=body)).status_code == 200
    agen, db = await _db()
    st = await db.get(AppState, "oidc")
    st.value = {**st.value, "enabled": True, "issuer": "https://auth.jbogaert.be/", "client_id": "homepage"}
    await db.commit()
    await agen.aclose()
    async with _client(LAN) as c:
        # Koppelen zoekt na Authentik de sessie weer op: zonder login is er geen.
        r = await c.post("/api/auth/oidc/link")
        assert r.status_code == 409 and "echte login" in r.json()["detail"]


async def test_uitloggen_en_sessies(authed):
    await _mode(authed, "overal")
    agen, db = await _db()
    before = len(list((await db.execute(select(Session))).scalars()))
    await agen.aclose()
    async with _client(LAN) as c:
        assert (await c.post("/api/auth/logout")).status_code == 200
        assert (await c.get("/api/auth/state")).json()["mfa_ok"] is True
        assert "hp_session" not in c.cookies and DEVICE_COOKIE not in c.cookies
        sessions = (await c.get("/api/auth/sessions")).json()
        assert len(sessions) == before and not any(s["current"] for s in sessions)
    agen, db = await _db()
    assert len(list((await db.execute(select(Session))).scalars())) == before
    assert not list((await db.execute(select(AuditLog).where(AuditLog.action == "logout"))).scalars())
    await agen.aclose()


async def test_echte_login_naast_zonder_login(authed):
    """Wie zich toch aanmeldt (bv. om Authentik te koppelen), heeft een echte sessie: geen 2FA-code meer nodig."""
    await _mode(authed, "overal")
    async with _client(LAN) as c:
        r = await c.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD,
                                                   "code": pyotp.TOTP(authed.totp_secret).now()})
        assert r.status_code == 200, r.text
        s = (await c.get("/api/auth/state")).json()
        assert s["zonder_login"] is True and s["sessie"] is True
        await _stale(authed)  # alle sessies: ook die van c
        assert (await c.put("/api/outside/settings", json={"home_ip": True, "networks": []})).status_code == 200


# --- het dashboard zelf ------------------------------------------------------------------------------------

SELF_LAN = "192.168.10.156"  # het eigen adres van de container: nginx geeft dat door als client (ook via NPM)


async def _tile(c, check: dict):
    page = (await c.post("/api/pages", json={"name": "P"})).json()["id"]
    g = (await c.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]
    return await c.post("/api/services", json={"group_id": g, "name": "onschuldig", "type": "link", "check": check})


ATTACK = {"type": "http", "target": f"http://{SELF_LAN}/api/ssh/keys", "method": "POST", "body": '{"name": "aanvaller"}',
          "body_type": "json", "accept": "201"}


async def test_check_doet_zich_niet_voor_als_browser(authed):
    """Wie van buitenaf zonder login een check maakt die naar het dashboard zelf wijst, met de header van de frontend:
    die check zou thuis zonder login tellen en de terminal mogen."""
    await _mode(authed, "overal")
    async with _client(WAN, headers={**H, **CF}) as atk:
        assert (await atk.post("/api/ssh/keys", json={"name": "rechtstreeks"})).status_code == 403
        for name in ("X-Requested-With", "x-requested-with", "Sec-Fetch-Site", "Sec-Fetch-Mode"):
            r = await _tile(atk, {**ATTACK, "headers": {name: "homepage"}})
            assert r.status_code == 422 and "herkent het dashboard je browser" in r.text, (name, r.text)
        r = await _tile(atk, {**ATTACK, "headers": {"Accept": "application/json"}})
        assert r.status_code == 201, r.text
    # Een check van vroeger met zo'n header: die gaat niet meer mee.
    stored = {**ATTACK, "headers": {"X-Requested-With": "homepage", "Sec-Fetch-Site": "same-origin", "Accept": "x"}}
    assert checks._request_parts(stored)[4] == {"User-Agent": "homepage-monitor/1.0", "Accept": "x",
                                                 "Content-Type": "application/json"}
    async with AsyncClient(transport=ASGITransport(app=app, client=("192.168.10.200", 40000))) as worker:
        out = await checks.check_http(checks.target_for(stored, None), stored, worker)
    assert out.status_code in (401, 403) and not out.ok  # zonder de header: niet aangemeld (of CSRF)
    assert (await authed.get("/api/ssh/keys")).json() == []


async def test_eigen_adres_is_geen_bezoeker(authed, monkeypatch):
    """Ook als een verzoek van het dashboard zelf de header toch heeft: vanaf een eigen adres nooit zonder login."""
    from app.monitoring import upgrade
    monkeypatch.setattr(upgrade, "me", lambda: upgrade.Me(ips=frozenset({SELF_LAN})))
    await _mode(authed, "overal")
    async with _client(SELF_LAN) as c:
        assert (await c.post("/api/ssh/keys", json={"name": "zelf"})).status_code == 401
        assert (await c.get("/api/layout")).status_code == 401
    async with _client(LAN) as c:
        assert (await c.get("/api/layout")).status_code == 200


async def test_api_stuurt_geen_browserheaders(authed):
    await _mode(authed, "overal")
    base = {"name": "x", "kind": "rest", "url": "http://192.168.10.156"}
    for config in ({"headers": {"X-Requested-With": "homepage"}}, {"auth": {"type": "header", "name": "Sec-Fetch-Site"}}):
        r = await authed.post("/api/apis", json={**base, "config": config})
        assert r.status_code == 422 and "herkent het dashboard je browser" in r.text, r.text
    r = await authed.post("/api/apis", json={**base, "config": {"headers": {"Accept": "application/json"}}})
    assert r.status_code in (200, 201), r.text
    api_id = r.json()["id"]
    r = await authed.post(f"/api/apis/{api_id}/calls", json={"name": "c", "headers": {"X-Requested-With": "homepage"}})
    assert r.status_code == 422, r.text
    # En bij het versturen: ook wat er al stond, gaat niet mee.
    sent = []
    import httpx

    from app.integrations.rest import RestApi

    def handler(req: httpx.Request) -> httpx.Response:
        sent.append(dict(req.headers))
        return httpx.Response(200, json={})
    integ = RestApi("http://192.168.10.156", {"headers": {"X-Requested-With": "homepage", "Accept": "a"},
                                           "auth": {"type": "header", "name": "Sec-Fetch-Site"}},
                 {"token": "same-origin"}, httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    await callmod.run(integ, {"method": "GET", "path": "/x", "headers": {"sec-fetch-mode": "cors"}})
    assert sent and not any(k.startswith("sec-fetch") or k == "x-requested-with" for k in sent[0])
    assert sent[0]["accept"] == "a"


async def test_van_buitenaf_met_echte_login_nog_2fa(authed):
    """Overal zonder login, van buitenaf met een echte (misschien gestolen) cookie: de vier gevaarlijke functies,
    Authentik en het wachtwoord vragen nog een verse 2FA, net als met aanmelden aan. Gewone dingen en wat in die
    functies niets bevestigt (kijken, een proef) niet, en thuis niets."""
    await _mode(authed, "overal")
    for f in ("terminal", "downloads"):
        assert (await authed.put(f"/api/outside/features/{f}", json={"mode": "aan"})).status_code == 200
    agen, db = await _db()
    st = await db.get(AppState, "oidc")
    if st is None:
        st = AppState(key="oidc", value={})
        db.add(st)
    st.value = {**(st.value or {}), "enabled": True, "issuer": "https://auth.jbogaert.be/", "client_id": "homepage"}
    body = "PrivateKey = geheim\n"
    v = ConfigVersion(item="file:1:/etc/wireguard/wg0.conf", name="wg0.conf", kind="file", sha="f", size=len(body),
                      content=encrypt(body))
    db.add(v)
    await db.commit()
    vid = v.id
    await agen.aclose()
    await _stale(authed)
    cookie = authed.cookies.get("hp_session")
    oidc_off = {"enabled": False, "issuer": "https://evil.example/", "client_id": "x"}
    async with _client(WAN) as c:  # met de cookie, van buitenaf, op een vertrouwd adres
        c.cookies.set("hp_session", cookie)
        assert (await c.get("/api/auth/state")).json()["zonder_login"] is True
        for method, url, kw in (
                ("GET", "/api/ssh/ready", {}),
                ("POST", "/api/ssh/keys", {"json": {"name": "aanvaller"}}),
                ("PUT", "/api/outside/features/updates", {"json": {"mode": "uur"}}),
                ("GET", f"/api/configs/versions/{vid}/diff", {}),
                ("PUT", "/api/auth/oidc/settings", {"json": oidc_off}),
                ("POST", "/api/auth/oidc/link", {}),
                ("DELETE", "/api/auth/oidc/link", {}),
                ("POST", "/api/auth/password", {"json": {"current": PASSWORD, "new": "een-nieuw-lang-wachtwoord"}})):
            r = await c.request(method, url, **kw)
            assert r.status_code == 403 and r.json()["detail"] == "reauth_required", (url, r.text)
        # In een gevaarlijke functie, maar zonder bevestiging (nakijken): geen code, zoals met aanmelden aan.
        assert (await c.post("/api/ssh/pin/check")).status_code == 200
        # Gewone gevoelige dingen: zonder code, zoals zonder cookie.
        assert (await c.put("/api/outside/features/updates", json={"mode": "uit"})).status_code == 200
    async with _client(LAN) as c:  # thuis met dezelfde cookie: niets
        c.cookies.set("hp_session", cookie)
        assert (await c.get("/api/ssh/ready")).status_code == 200
        assert (await c.get(f"/api/configs/versions/{vid}/diff")).status_code == 200
        r = await c.put("/api/auth/oidc/settings", json=oidc_off)
        assert r.status_code == 200, r.text
    agen, db = await _db()
    assert (await db.get(AppState, "oidc")).value["issuer"] == "https://evil.example/"  # pas thuis
    await agen.aclose()
    async with _client(WAN) as c:
        c.cookies.set("hp_session", cookie)
        assert (await c.put("/api/outside/aanmelden", json={"mode": "uit"})).status_code == 200


async def test_strenger_zetten_tijdens_je_eigen_verzoek(authed, monkeypatch):
    """Van buitenaf mag iedereen aanmelden strenger zetten. Gebeurt dat terwijl een eigen verzoek zonder login nog
    loopt, dan blijft dat verzoek zonder login: de stand opnieuw lezen mag het niet langs de controles laten."""
    for f in ("terminal", "acties"):
        assert (await authed.put(f"/api/outside/features/{f}", json={"mode": "aan"})).status_code == 200
    await _mode(authed, "overal")
    orig = zonderlogin.home_user

    async def tighten(db):  # net nadat optional_session besliste dat dit verzoek zonder login mag
        st = await ensure_state(db, zonderlogin.KEY, {})
        st.value = {"mode": "thuis"}
        await db.commit()
        return await orig(db)

    monkeypatch.setattr(zonderlogin, "home_user", tighten)
    async with _client(WAN) as c:
        for method, url, kw, detail in (
                ("POST", "/api/ssh/keys", {"json": {"name": "aanvaller"}}, "buiten:terminal"),
                ("POST", "/api/apis", {"json": {"name": "x", "type": "rest", "url": "https://example.com"}},
                 "buiten:acties"),
                ("PUT", "/api/outside/features/terminal", {"json": {"mode": "uur"}}, "Zonder login"),
                ("POST", "/api/auth/password", {"json": {"current": PASSWORD, "new": "een-nieuw-lang-wachtwoord"}},
                 "Zonder login"),
                ("PUT", "/api/auth/oidc/settings", {"json": {"enabled": False, "issuer": "https://evil.example/",
                                                             "client_id": "x"}}, "Zonder login")):
            await _mode(authed, "overal")
            r = await c.request(method, url, **kw)
            assert r.status_code == 403 and r.json()["detail"].startswith(detail), (url, r.text)


async def test_wachtwoord_raden(authed):
    """Zonder login delen alle bezoekers één vluchtige sessie. Van buitenaf kan die je wachtwoord niet wijzigen (en dus
    ook niet raden); thuis telt elke poging per IP en alle samen hoogstens zoveel als het inloggen per gebruikersnaam.
    Een echte login telt apart: de eigenaar blijft er zo niet buiten."""
    await _mode(authed, "overal")
    wrong = {"current": "fout-fout-fout", "new": "x" * 14}
    async with _client(WAN) as c:
        r = await c.post("/api/auth/password", json={"current": PASSWORD, "new": "een-nieuw-lang-wachtwoord"})
        assert r.status_code == 403 and "Zonder login" in r.json()["detail"], r.text
        # Bevestigen valt er zonder login niet: geen 2FA-code om te raden.
        assert (await c.post("/api/auth/reauth", json={"code": "000000"})).json() == {"ok": True}
    limit = 5 * USER_FAILURE_FACTOR
    async with _client(LAN) as c:  # één IP: na 5 dicht
        codes = [(await c.post("/api/auth/password", json=wrong)).status_code for _ in range(6)]
        assert codes == [401] * 5 + [429], codes
    for i in range(limit - 5):  # andere IP's thuis: samen tot de limiet per gebruikersnaam
        async with _client(f"192.168.0.{60 + i}") as c:
            assert (await c.post("/api/auth/password", json=wrong)).status_code == 401
    async with _client("192.168.0.200") as c:
        r = await c.post("/api/auth/password", json={"current": PASSWORD, "new": "een-nieuw-lang-wachtwoord"})
        assert r.status_code == 429, r.text
    # Met een echte login gaat het nog.
    r = await authed.post("/api/auth/password", json={"current": PASSWORD, "new": "een-nieuw-lang-wachtwoord"})
    assert r.status_code == 200, r.text


async def test_namen_overschrijven_de_stand_niet(authed):
    """De namen staan apart: een eerste verzoek op een nieuwe naam schrijft de stand niet terug."""
    await _mode(authed, "thuis")
    agen, db = await _db()
    cfg = await zonderlogin.settings(db)
    await authed.put("/api/outside/aanmelden", json={"mode": "uit"})

    class C:
        headers = {"host": "nieuw.jbogaert.be"}
    assert await zonderlogin.learn(C(), db, cfg)
    await db.commit()
    await agen.aclose()
    assert (await _state(zonderlogin.KEY)) == {"mode": "uit"}
    assert "nieuw.jbogaert.be" in (await _state(zonderlogin.NAMES_KEY))["names"]


# --- WebSockets --------------------------------------------------------------------------------------------

class WS:
    """Een websocket zonder cookie, op een eigen IP en adres."""

    def __init__(self, path: str, ip: str = LAN, host: str = "192.168.10.156", origin: str | None = None):
        self.to_app: asyncio.Queue = asyncio.Queue()
        self.from_app: asyncio.Queue = asyncio.Queue()
        headers = [(b"host", host.encode()), (b"origin", (origin or f"http://{host}").encode())]
        scope = {"type": "websocket", "path": path, "raw_path": path.encode(), "query_string": b"cols=80&rows=24",
                 "headers": headers, "scheme": "ws", "server": (host, 80), "client": (ip, 5000),
                 "subprotocols": [], "asgi": {"version": "3.0"}}
        self.task = asyncio.create_task(app(scope, self.to_app.get, self.from_app.put))

    async def open(self):
        await self.to_app.put({"type": "websocket.connect"})
        assert (await asyncio.wait_for(self.from_app.get(), 10))["type"] == "websocket.accept"

    async def json(self):
        while True:
            m = await asyncio.wait_for(self.from_app.get(), 10)
            if m["type"] == "websocket.send" and m.get("text"):
                return json.loads(m["text"])
            if m["type"] == "websocket.close":
                return {"t": "socket-closed", "code": m.get("code")}

    async def close(self):
        await self.to_app.put({"type": "websocket.disconnect", "code": 1000})
        await asyncio.wait_for(self.task, 10)


async def _host(authed, sshd) -> int:  # noqa: F811
    r = await authed.post("/api/ssh/hosts", json={"name": "pve", "host": "127.0.0.1", "port": sshd["port"],
                                                  "username": "root", "password": "goed"})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_terminal_zonder_cookie(authed, sshd, monkeypatch):  # noqa: F811
    hid = await _host(authed, sshd)
    await _mode(authed, "overal")
    ws = WS(f"/api/ssh/ws/{hid}")
    await ws.open()
    assert (await ws.json())["t"] == "status"
    assert (await ws.json())["t"] == "hostkey"
    await ws.close()
    # Een website op een andere naam (DNS-rebinding): Origin en Host kloppen samen, de naam is onbekend.
    ws = WS(f"/api/ssh/ws/{hid}", host="evil.example")
    await ws.open()
    assert await ws.json() == {"t": "error", "m": "Niet ingelogd"}
    await ws.close()
    # Van buitenaf zonder login: dicht, ook als de terminal altijd aan staat.
    assert (await authed.put("/api/outside/features/terminal", json={"mode": "aan"})).status_code == 200
    ws = WS(f"/api/ssh/ws/{hid}", ip=WAN)
    await ws.open()
    assert await ws.json() == {"t": "error", "m": "buiten:terminal"}
    await ws.close()


async def test_terminal_sluit_als_aanmelden_terug_aan_gaat(authed, sshd, monkeypatch):  # noqa: F811
    hid = await _host(authed, sshd)
    await _mode(authed, "overal")
    monkeypatch.setattr(ssh_router, "SESSION_CHECK", 0.2)
    ws = WS(f"/api/ssh/ws/{hid}")
    await ws.open()
    assert (await ws.json())["t"] == "status"
    assert (await ws.json())["t"] == "hostkey"
    await ws.to_app.put({"type": "websocket.receive", "text": json.dumps({"t": "accept"})})
    while (m := await ws.json())["t"] != "ready":
        assert m["t"] == "status", m
    await asyncio.sleep(0.6)  # drie controles later: nog open
    while not ws.from_app.empty():
        m = ws.from_app.get_nowait()
        assert m["type"] == "websocket.send" and not m.get("text"), m  # alleen uitvoer van de shell
    await _mode(authed, "uit")
    while (m := await ws.json())["t"] not in ("error", "socket-closed"):
        pass
    assert m == {"t": "error", "m": ssh_router.LOGIN_BACK}
    # En de afsluiter zegt hetzelfde, niet "elders uitgelogd".
    assert await ws.json() == {"t": "closed", "m": ssh_router.LOGIN_BACK}
    await ws.close()
    agen, db = await _db()
    rows = {a.action: a.detail for a in (await db.execute(select(AuditLog))).scalars()}
    await agen.aclose()
    assert rows["ssh_open"]["zonder_login"] is True and rows["ssh_hostkey_accepted"]["zonder_login"] is True
    # SQLite in het geheugen deelt één verbinding tussen alle sessies: het afsluiten van een ander verzoek kan de
    # laatste regel nog terugdraaien. Op PostgreSQL (zoals in productie) staat ze er altijd.
    if not TEST_DB.startswith("sqlite"):
        assert rows["ssh_close"]["zonder_login"] is True


async def test_terminal_sluit_als_je_niet_meer_thuis_bent(authed, sshd, monkeypatch):  # noqa: F811
    """Overal zonder login: een terminal van een netwerk dat thuis telt, sluit als dat niet meer zo is."""
    hid = await _host(authed, sshd)
    r = await authed.put("/api/outside/settings", json={"home_ip": True, "networks": ["81.82.83.0/24"]})
    assert r.status_code == 200, r.text
    await _mode(authed, "overal")
    monkeypatch.setattr(ssh_router, "SESSION_CHECK", 0.2)
    ws = WS(f"/api/ssh/ws/{hid}", ip=WAN)
    await ws.open()
    assert (await ws.json())["t"] == "status"
    assert (await ws.json())["t"] == "hostkey"
    await ws.to_app.put({"type": "websocket.receive", "text": json.dumps({"t": "accept"})})
    while (m := await ws.json())["t"] != "ready":
        assert m["t"] == "status", m
    r = await authed.put("/api/outside/settings", json={"home_ip": True, "networks": []})
    assert r.status_code == 200, r.text
    while (m := await ws.json())["t"] not in ("error", "socket-closed"):
        pass
    assert m == {"t": "error", "m": ssh_router.LOGIN_BACK}
    await ws.close()


@pytest.mark.parametrize("raw,name", [("Test:80", "test"), ("[::1]:8080", "::1"), ("[]", None), ("[::1", None),
                                      ("a.b.", "a.b"), ("", None), ("fd00::1", "fd00::1")])
def test_host_of(raw, name):
    class C:
        headers = {"host": raw}
    assert zonderlogin.host_of(C()) == name
