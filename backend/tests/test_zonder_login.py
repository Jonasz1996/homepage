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
from app.main import app
from app.models import AppState, AuditLog, Notification, Session
from app.routers import ssh as ssh_router
from app.security import DEVICE_COOKIE

from .conftest import H, PASSWORD, SETUP_TOKEN
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
    assert (await _state(zonderlogin.KEY))["names"] == ["test", "homepage.jbogaert.be"]
    async with _client(LAN, host="homepage.jbogaert.be") as c:
        assert (await c.get("/api/layout")).status_code == 200
    async with _client(LAN, host="evil.example") as c:
        assert (await c.get("/api/layout")).status_code == 401
    a = (await authed.get("/api/outside")).json()["aanmelden"]
    assert a["names"] == ["test", "homepage.jbogaert.be"]
    assert a["nu"] is False and "container zelf" in a["why"]


async def test_hoogstens_twintig_namen(authed):
    for i in range(25):
        assert (await authed.get("/api/layout", headers={"Host": f"n{i}.jbogaert.be"})).status_code == 200
    # Geen naam: rare tekens, of een IP.
    for host in ("a_b.example", "10.0.0.1", "localhost"):
        await authed.get("/api/layout", headers={"Host": host})
    names = (await _state(zonderlogin.KEY))["names"]
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


async def test_aanmelden_uitzetten_alleen_thuis(authed):
    await _mode(authed, "overal")
    async with _client(WAN) as c:
        for mode in ("thuis", "overal"):
            r = await c.put("/api/outside/aanmelden", json={"mode": mode})
            assert r.status_code == 403, r.text
        r = await c.put("/api/outside/aanmelden", json={"mode": "uit"})
        assert r.status_code == 200 and r.json()["mode"] == "uit" and r.json()["nu"] is False
        assert (await c.get("/api/layout")).status_code == 401
    assert (await _state(zonderlogin.KEY))["mode"] == "uit"
    agen, db = await _db()
    notes = [n.title for n in (await db.execute(select(Notification).order_by(Notification.id))).scalars()]
    await agen.aclose()
    assert notes[-2:] == ["Aanmelden: overal zonder login", "Aanmelden: altijd aanmelden met 2FA"]
    assert (await authed.put("/api/outside/aanmelden", json={"mode": "ergens"})).status_code == 422


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
    await ws.close()


@pytest.mark.parametrize("raw,name", [("Test:80", "test"), ("[::1]:8080", "::1"), ("[]", None), ("[::1", None),
                                      ("a.b.", "a.b"), ("", None), ("fd00::1", "fd00::1")])
def test_host_of(raw, name):
    class C:
        headers = {"host": raw}
    assert zonderlogin.host_of(C()) == name
