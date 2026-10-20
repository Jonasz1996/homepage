"""Stap 2 van het verbeterplan: buitenmodus, twee Proxmox-tokens, SSH-sleutel vastzetten, poortlijst en de
veiligheidscheck."""

import asyncio
import os
from datetime import datetime, timedelta, timezone

import asyncssh
import httpx
import pytest
from sqlalchemy import update
from starlette.routing import Route, WebSocketRoute

from app import outside, ssh_pin
from app.db import get_db
from app.integrations import calls as callmod
from app.integrations.proxmox import Proxmox
from app.main import app
from app.models import AppState, Notification, Session, SshHost
from app.monitoring import ports
from app.monitoring.checks import HttpClients
from app.routers import integrations as integrations_router

from .test_ssh import WS, _cookie

CF = {"X-Homepage-Via-Cf": "1"}


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _stale(authed) -> None:
    """Herbevestiging verlopen laten (zoals 15 minuten later)."""
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    await agen.aclose()


# --- buitenmodus ---------------------------------------------------------------------------------------------

def _routes():
    for r in app.router.routes:
        for sub in getattr(getattr(r, "original_router", None), "routes", None) or [r]:
            yield sub


def _guarded() -> dict[str, str]:
    out = {}
    for r in _routes():
        if not isinstance(r, Route):
            continue
        for d in r.dependant.dependencies:
            if feat := getattr(d.call, "outside_feature", None):
                for m in r.methods - {"HEAD"}:
                    out[f"{m} {r.path}"] = feat
    return out


def test_welke_routes_van_buitenaf_uit_staan():
    """Bewust: een nieuwe gevaarlijke route hoort hier bij te komen."""
    assert _guarded() == {
        "POST /api/updates/install": "updates", "POST /api/updates/runs/{run_id}/rollback": "updates",
        "PUT /api/updates/settings": "updates",
        "POST /api/services/{service_id}/integration/action": "acties", "POST /api/services/{service_id}/wol": "acties",
        "POST /api/heal": "acties", "PUT /api/heal/{rule_id}": "acties", "POST /api/heal/{rule_id}/test": "acties",
        "POST /api/health/snapshots/delete": "acties",
        "PUT /api/restoretest/settings": "acties", "POST /api/restoretest/run": "acties",
        "POST /api/devices/{mac}/scan": "acties",
        "GET /api/configs/versions/{vid}/download": "downloads",
        "POST /api/cron/jobs/{job_id}/monitor": "terminal", "POST /api/logs/rollout": "terminal",
        "GET /api/ssh/ready": "terminal", "POST /api/ssh/pin/check": "terminal", "POST /api/ssh/pin": "terminal",
        # De instellingen van de terminal: een host naar een ander adres zetten kan een wachtwoord laten weglekken.
        "POST /api/ssh/keys": "terminal", "DELETE /api/ssh/keys/{key_id}": "terminal", "POST /api/ssh/hosts": "terminal",
        "PATCH /api/ssh/hosts/{host_id}": "terminal", "DELETE /api/ssh/hosts/{host_id}": "terminal",
        "POST /api/ssh/hosts/{host_id}/forget-hostkey": "terminal", "PUT /api/ssh/defaults": "terminal",
        "PUT /api/ssh/snippets": "terminal", "POST /api/ssh/import": "terminal",
    }
    ws = {r.path for r in _routes() if isinstance(r, WebSocketRoute)}
    assert ws == {"/api/ssh/ws/{host_id}", "/api/cron/ws/run/{job_id}", "/api/cron/ws/tail/{target}"}


async def test_thuis_en_buiten(authed):
    r = (await authed.get("/api/outside")).json()
    assert r["outside"] is False and r["why"] == "thuisnetwerk"
    assert [f["key"] for f in r["features"]] == list(outside.FEATURES)
    assert all(not f["allowed"] and f["mode"] == "uit" for f in r["features"])

    r = (await authed.get("/api/outside", headers=CF)).json()
    assert r["outside"] is True and r["why"] == "via Cloudflare" and r["access"] is None
    # Thuis gaat het verder dan de buitenmodus (hier: de herbevestiging), van buitenaf niet.
    await _stale(authed)
    assert (await authed.get("/api/ssh/ready")).json()["detail"] == "reauth_required"
    r = await authed.get("/api/ssh/ready", headers=CF)
    assert r.status_code == 403 and r.json()["detail"] == "buiten:terminal"
    for path, body in (("/api/updates/install", {"targets": []}), ("/api/health/snapshots/delete", {}),
                       ("/api/restoretest/run", None)):
        r = await authed.post(path, json=body, headers=CF)
        assert r.status_code == 403 and r.json()["detail"].startswith("buiten:"), (path, r.text)
    # Kijken kan wel.
    assert (await authed.get("/api/health", headers=CF)).status_code == 200
    assert (await authed.get("/api/export", headers=CF)).status_code == 200

    # Het bezoek is bewaard (voor de veiligheidscheck), met het slot dat ervoor stond.
    r = (await authed.get("/api/outside", headers={**CF, "X-Homepage-Access": "cloudflare-access"})).json()
    assert r["access"] == "cloudflare-access"
    assert r["seen"]["last"]["access"] == "cloudflare-access" and r["seen"]["visits"] == 2


async def test_een_uur_aanzetten_van_buitenaf(authed):
    r = await authed.put("/api/outside/features/terminal", json={"mode": "aan"}, headers=CF)
    assert r.status_code == 403 and "alleen thuis" in r.json()["detail"]
    r = await authed.put("/api/outside/features/terminal", json={"mode": "uur"}, headers=CF)
    assert r.status_code == 200, r.text
    t = next(f for f in r.json()["features"] if f["key"] == "terminal")
    assert t["allowed"] and t["mode"] == "uur"
    assert (await authed.get("/api/ssh/ready", headers=CF)).status_code == 200
    r = await authed.post("/api/updates/install", json={"targets": []}, headers=CF)
    assert r.json()["detail"] == "buiten:updates"  # de rest blijft uit

    agen, db = await _db()
    n = (await db.execute(Notification.__table__.select())).all()
    assert any("terminal één uur aan" in row.title for row in n)
    # Na het uur staat het weer uit.
    st = await db.get(AppState, outside.STATE_KEY)
    st.value = {**st.value, "features": {"terminal": {"mode": "uur", "until": "2020-01-01T00:00:00+00:00"}}}
    await db.commit()
    await agen.aclose()
    assert (await authed.get("/api/ssh/ready", headers=CF)).json()["detail"] == "buiten:terminal"

    # Wat als thuis telt, kan alleen thuis gewijzigd worden.
    r = await authed.put("/api/outside/settings", json={"home_ip": True, "networks": ["203.0.113.0/24"]}, headers=CF)
    assert r.status_code == 403
    r = await authed.put("/api/outside/settings", json={"home_ip": True, "networks": ["10.8.0.0/24", "x"]})
    assert r.status_code == 422
    r = await authed.put("/api/outside/settings", json={"home_ip": False, "networks": ["10.8.0.0/24"]})
    assert r.status_code == 200 and r.json()["networks"] == ["10.8.0.0/24"]


class _Conn:
    def __init__(self, ip, headers=None):
        self.client = type("C", (), {"host": ip})()
        self.headers = headers or {}


async def test_waar_komt_een_bezoek_vandaan(authed):
    agen, db = await _db()
    db.add(AppState(key="public_ip", value={"ip": "94.224.1.7"}))
    await db.commit()
    w = lambda ip, h=None: outside.where(_Conn(ip, h), db)  # noqa: E731
    assert (await w("192.168.0.20"))["outside"] is False
    assert (await w("100.101.1.2"))["outside"] is False  # Tailscale
    assert (await w("81.82.83.84"))["outside"] is True
    assert (await w("94.224.1.7", {"x-homepage-via-cf": "1"}))["why"] == "je eigen publieke IP"
    st = await db.get(AppState, outside.STATE_KEY) or AppState(key=outside.STATE_KEY, value={})
    st.value = {"home_ip": False, "networks": ["2a02:1810::/32"]}
    db.add(st)
    await db.commit()
    assert (await w("94.224.1.7", {"x-homepage-via-cf": "1"}))["outside"] is True
    assert (await w("2a02:1810:1::5", {"x-homepage-via-cf": "1"}))["outside"] is False
    await agen.aclose()


async def test_terminal_websocket_van_buitenaf(authed, monkeypatch):
    agen, db = await _db()
    db.add(SshHost(name="pve", host="127.0.0.1", port=22, username="root"))
    await db.commit()
    await agen.aclose()
    ws = WS("/api/ssh/ws/1", _cookie(authed))
    real = outside.where

    async def via_cf(conn, db, cfg=None):
        return {**await real(conn, db, cfg), "outside": True, "why": "via Cloudflare"}
    monkeypatch.setattr(outside, "where", via_cf)
    await ws.open()
    assert (await ws.json()) == {"t": "error", "m": "buiten:terminal"}
    await ws.close()


async def test_api_proberen_van_buitenaf(authed):
    r = await authed.post("/api/apis", json={"name": "Radarr", "kind": "rest", "url": "http://radarr.lan"})
    aid = r.json()["id"]
    r = await authed.post(f"/api/apis/{aid}/try", json={"call": {"name": "x", "method": "POST", "path": "/api/x"}},
                          headers=CF)
    assert r.status_code == 403 and r.json()["detail"] == "buiten:acties"


# --- twee Proxmox-tokens -------------------------------------------------------------------------------------

async def test_proxmox_leestoken_en_actietoken():
    seen = []

    def handler(req: httpx.Request):
        seen.append((req.method, req.url.path, req.headers["authorization"]))
        return httpx.Response(200, json={"data": "UPID:x"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        one = Proxmox("https://pve:8006", {}, {"username": "lees@pve!d", "password": "a"}, c)
        two = Proxmox("https://pve:8006", {}, {"username": "lees@pve!d", "password": "a",
                                                "action_username": "doe@pve!a", "action_password": "b"}, c)
        params = {"node": "pve1", "type": "lxc", "vmid": 105}
        await one.action("reboot", params)
        await two.action("reboot", params)
        await two.get("/cluster/resources")
        await callmod.run(two, {"method": "POST", "path": "/nodes/pve1/lxc/105/status/start"})
        await callmod.run(two, {"method": "GET", "path": "/version"})
    assert [a for *_, a in seen] == ["PVEAPIToken=lees@pve!d=a", "PVEAPIToken=doe@pve!a=b", "PVEAPIToken=lees@pve!d=a",
                                     "PVEAPIToken=doe@pve!a=b", "PVEAPIToken=lees@pve!d=a"]
    assert not one.split and two.split


# --- SSH-sleutel vastzetten ----------------------------------------------------------------------------------

BLOB = "AAAAC3NzaC1lZDI1NTE5AAAAIGtest"


def test_regels_herschrijven():
    text = (f"# commentaar met {BLOB}\n"
            f"ssh-ed25519 {BLOB} homepage-homepage\n"
            f'command="echo hi there",no-pty ssh-ed25519 {BLOB} met opties\n'
            f'from="10.0.0.1",no-pty ssh-ed25519 {BLOB}\n'
            "ssh-ed25519 AAAAandere jonas@pc\n")
    new, n = ssh_pin.rewrite(text, BLOB, "192.168.10.156")
    assert n == 3
    lines = new.splitlines()
    assert lines[0].startswith("# commentaar") and lines[4] == "ssh-ed25519 AAAAandere jonas@pc"
    assert lines[1] == f'from="192.168.10.156" ssh-ed25519 {BLOB} homepage-homepage'
    assert lines[2] == f'from="192.168.10.156",command="echo hi there",no-pty ssh-ed25519 {BLOB} met opties'
    assert lines[3] == f'from="192.168.10.156",no-pty ssh-ed25519 {BLOB}'
    assert ssh_pin.pinned_from(new, BLOB) == ["192.168.10.156"] * 3
    back, _ = ssh_pin.rewrite(new, BLOB, None)
    assert back.splitlines()[1] == f"ssh-ed25519 {BLOB} homepage-homepage"
    assert back.splitlines()[2] == f'command="echo hi there",no-pty ssh-ed25519 {BLOB} met opties'
    assert new.endswith("\n")


class PinServer(asyncssh.SSHServer):
    """Leest authorized_keys bij elke verbinding opnieuw, en asyncssh past from= toe zoals sshd."""

    def __init__(self, home):
        self.home = home

    def connection_made(self, conn):
        self.conn = conn

    def begin_auth(self, username):
        self.conn.set_authorized_keys(os.path.join(self.home, ".ssh", "authorized_keys"))
        return True


@pytest.fixture
async def pin_sshd(tmp_path):
    home = tmp_path / "root"
    (home / ".ssh").mkdir(parents=True)
    key = asyncssh.generate_private_key("ssh-ed25519", comment="homepage-test")
    ak = home / ".ssh" / "authorized_keys"
    ak.write_text("ssh-ed25519 AAAAandere jonas@pc\n" + key.export_public_key().decode())
    state = {"client": "127.0.0.1"}

    async def handle(process):
        # Zoals sshd: een shell met HOME en SSH_CLIENT van de verbinding.
        env = {"HOME": str(home), "PATH": os.environ["PATH"], "SSH_CLIENT": f"{state['client']} 40000 22"}
        p = await asyncio.create_subprocess_shell(process.command, env=env, stdin=asyncio.subprocess.PIPE,
                                                  stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        async def feed():
            try:
                while data := await process.stdin.read(65536):
                    p.stdin.write(data.encode())
                    await p.stdin.drain()
            finally:
                p.stdin.close()

        t = asyncio.create_task(feed())
        out, err = await asyncio.gather(p.stdout.read(), p.stderr.read())
        await p.wait()
        t.cancel()
        process.stdout.write(out.decode())
        process.stderr.write(err.decode())
        process.exit(p.returncode)

    host_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(lambda: PinServer(str(home)), "127.0.0.1", 0, server_host_keys=[host_key],
                                          process_factory=handle)
    port = server.sockets[0].getsockname()[1]
    yield {"port": port, "host_key": host_key, "key": key, "ak": ak, "state": state}
    server.close()
    await server.wait_closed()


async def _pin_host(authed, pin_sshd) -> int:
    r = await authed.post("/api/ssh/keys", json={"name": "test", "private_key": pin_sshd["key"].export_private_key().decode()})
    kid = r.json()["id"]
    r = await authed.post("/api/ssh/hosts", json={"name": "pve50", "host": "127.0.0.1", "port": pin_sshd["port"],
                                                  "username": "root", "key_id": kid})
    hid = r.json()["id"]
    agen, db = await _db()
    h = await db.get(SshHost, hid)
    h.host_key = pin_sshd["host_key"].export_public_key().decode()
    await db.commit()
    await agen.aclose()
    return hid


async def test_sleutel_vastzetten_en_losmaken(authed, pin_sshd):
    hid = await _pin_host(authed, pin_sshd)
    r = await authed.post("/api/ssh/pin/check")
    assert r.status_code == 200, r.text
    assert r.json()["hosts"][str(hid)]["state"] == "los", r.json()

    r = await authed.post("/api/ssh/pin", json={"host_ids": [hid]})
    assert r.status_code == 200, r.text
    res = r.json()["results"][str(hid)]
    assert res["state"] == "vast" and res["changed"] == 1, res
    text = pin_sshd["ak"].read_text()
    assert 'from="127.0.0.1" ssh-ed25519' in text and text.startswith("ssh-ed25519 AAAAandere jonas@pc\n")
    assert (pin_sshd["ak"].parent / "authorized_keys.homepage-bak").exists()
    # Het dashboard kan er nog in (de controle na het vastzetten deed dat al; hier nog eens via de status).
    assert (await authed.post("/api/ssh/pin/check")).json()["hosts"][str(hid)]["state"] == "vast"

    r = await authed.post("/api/ssh/pin", json={"host_ids": [hid], "pin": False})
    assert r.json()["results"][str(hid)]["state"] == "los"
    assert "from=" not in pin_sshd["ak"].read_text()


async def test_vastzetten_zet_terug_als_het_dashboard_er_niet_meer_in_kan(authed, pin_sshd):
    hid = await _pin_host(authed, pin_sshd)
    before = pin_sshd["ak"].read_text()
    # De machine meldt een ander afzender-IP dan waarmee de verbinding echt binnenkomt.
    pin_sshd["state"]["client"] = "10.9.9.9"
    r = await authed.post("/api/ssh/pin", json={"host_ids": [hid]})
    res = r.json()["results"][str(hid)]
    assert res["error"].startswith("Teruggezet"), res
    assert pin_sshd["ak"].read_text() == before


async def test_vastzetten_vraagt_herbevestiging_en_mag_niet_van_buitenaf(authed, pin_sshd):
    hid = await _pin_host(authed, pin_sshd)
    r = await authed.post("/api/ssh/pin", json={"host_ids": [hid]}, headers=CF)
    assert r.json()["detail"] == "buiten:terminal"
    await _stale(authed)
    r = await authed.post("/api/ssh/pin", json={"host_ids": [hid]})
    assert r.json()["detail"] == "reauth_required"


# --- poortlijst ----------------------------------------------------------------------------------------------

async def test_poortlijst(authed, monkeypatch):
    from app.config import get_settings
    monkeypatch.setattr(get_settings(), "syslog_target", "192.168.10.156")
    monkeypatch.setattr(get_settings(), "npm_ip", "192.168.0.245")
    monkeypatch.setattr(ports, "nameservers", lambda: ["192.168.0.1"])

    async def fake_resolve(names):
        known = {"plex.jbogaert.be": ["192.168.0.245"], "pve50.lan": ["192.168.0.50"]}
        return {n: known.get(n, [n] if n[0].isdigit() else []) for n in names}
    monkeypatch.setattr(ports, "resolve", fake_resolve)

    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    g = (await authed.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]
    await authed.post("/api/services", json={"group_id": g, "name": "Plex", "url": "https://plex.jbogaert.be",
                                             "type": "link", "check": {"type": "http", "interval": 60}})
    await authed.post("/api/services", json={"group_id": g, "name": "pve50", "url": "https://192.168.0.50:8006",
                                             "type": "proxmox", "check": {"type": "ping", "interval": 60}})
    await authed.post("/api/services", json={"group_id": g, "name": "nas", "url": "http://nas.onbekend",
                                             "type": "link", "check": {"type": "tcp", "interval": 60}})
    await authed.post("/api/ssh/hosts", json={"name": "pve50", "host": "pve50.lan", "port": 22, "username": "root"})
    await authed.post("/api/ssh/hosts", json={"name": "ct", "host": "192.168.10.20", "port": 2222, "username": "root"})

    r = (await authed.get("/api/network/ports")).json()
    rows = {x["ip"]: x for x in r["rows"]}
    assert rows["192.168.0.50"]["ports"] == ["ping", "22/tcp", "8006/tcp"]
    assert rows["192.168.0.50"]["scope"] == "ander netwerk" and rows["192.168.0.50"]["names"] == ["pve50.lan"]
    assert rows["192.168.0.245"]["ports"] == ["443/tcp"] and "Plex (check)" in rows["192.168.0.245"]["used_by"]
    assert rows["192.168.10.20"]["scope"] == "zelfde netwerk"
    assert rows["192.168.0.1"]["ports"] == ["53/udp"]
    assert r["unresolved"] == [{"name": "nas.onbekend", "used_by": ["nas (check)"]}]
    assert r["opnsense"] == {"hosts": ["192.168.0.1", "192.168.0.50", "192.168.0.245"], "tcp": [22, 443, 8006],
                             "udp": [53], "ping": True}
    assert r["inbound"][0]["from"] == "192.168.0.245"


# --- veiligheidscheck ----------------------------------------------------------------------------------------

async def test_veiligheidscheck(authed, monkeypatch):
    def handler(req: httpx.Request):
        if req.url.path == "/api2/json/access/permissions":
            if "doe@pve" in req.headers["authorization"]:
                return httpx.Response(200, json={"data": {"/vms": {"VM.PowerMgmt": 1, "VM.Snapshot": 1}}})
            return httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1, "VM.Audit": 1, "VM.PowerMgmt": 1}}})
        return httpx.Response(404)
    monkeypatch.setattr(integrations_router, "clients", HttpClients(httpx.MockTransport(handler)))

    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    g = (await authed.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]
    sid = (await authed.post("/api/services", json={"group_id": g, "name": "pve", "url": "https://192.168.0.50:8006",
                                                    "type": "proxmox", "secrets": {"username": "lees@pve!d", "password": "a"}})).json()["id"]
    r = (await authed.get("/api/security/check")).json()
    c = {x["key"]: x for x in r["checks"]}
    assert set(c) == {"2fa", "secret", "offsite", "sessions", "outside", "access", "sshpin", "tokens"}
    assert c["2fa"]["level"] == "ok" and c["outside"]["level"] == "ok"
    assert c["secret"]["level"] == "warn" and c["secret"]["fix"] == {"action": "secret_saved"}
    assert c["access"]["level"] == "info"
    assert c["tokens"]["level"] == "warn" and "één token voor alles" in c["tokens"]["items"][0]["text"]

    # Met een actietoken: het leestoken mag nog VM.PowerMgmt → nog altijd oranje, met een andere uitleg.
    r = await authed.patch(f"/api/services/{sid}", json={"group_id": g, "name": "pve", "url": "https://192.168.0.50:8006",
                                                         "type": "proxmox", "secrets": {"action_username": "doe@pve!a",
                                                                                        "action_password": "b"}})
    assert r.status_code == 200, r.text
    c = {x["key"]: x for x in (await authed.get("/api/security/check")).json()["checks"]}
    assert "het leestoken mag ook VM.PowerMgmt" in c["tokens"]["items"][0]["text"]

    # secret.key bevestigd, een bezoek van buitenaf zonder slot, de terminal altijd aan.
    assert (await authed.post("/api/security/secret-key-saved")).status_code == 200
    await authed.get("/api/outside", headers=CF)
    await authed.put("/api/outside/features/terminal", json={"mode": "aan"})
    c = {x["key"]: x for x in (await authed.get("/api/security/check")).json()["checks"]}
    assert c["secret"]["level"] == "ok"
    assert c["access"]["level"] == "warn"
    assert c["outside"]["level"] == "warn" and "terminal" in c["outside"]["text"]
