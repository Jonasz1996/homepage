import json
from datetime import datetime, timedelta, timezone

import httpx
import pyotp
import pytest
from sqlalchemy import update

from app.db import get_db
from app.main import app
from app.models import Session
from app.monitoring.checks import HttpClients
from app.routers import integrations as router

PVE = {"data": [
    {"type": "node", "node": "pve50", "status": "online", "cpu": 0.25, "maxcpu": 4, "mem": 4e9, "maxmem": 16e9, "uptime": 3600},
    {"type": "node", "node": "pve51", "status": "offline", "maxcpu": 4, "maxmem": 16e9},
    {"type": "qemu", "vmid": 100, "name": "opnsense", "node": "pve50", "status": "running", "cpu": 0.1, "mem": 1e9, "maxmem": 2e9},
    {"type": "lxc", "vmid": 101, "name": "homepage", "node": "pve50", "status": "stopped", "maxmem": 4e9},
    {"type": "qemu", "vmid": 9000, "name": "tpl", "node": "pve50", "status": "stopped", "template": 1},
    {"type": "storage", "storage": "local-lvm", "node": "pve50", "disk": 50e9, "maxdisk": 100e9},
]}


class Fake:
    def __init__(self):
        self.calls: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        p = req.url.path
        if p == "/api2/json/cluster/resources":
            assert req.headers["authorization"] == "PVEAPIToken=homepage@pve!dash=geheim"
            return httpx.Response(200, json=PVE)
        if p.startswith("/api2/json/nodes/pve50/lxc/101/status/"):
            return httpx.Response(200, json={"data": "UPID:pve50:..."})
        if p == "/control/stats":
            return httpx.Response(200, json={"num_dns_queries": 1000, "num_blocked_filtering": 125,
                                             "avg_processing_time": 0.004,
                                             "top_blocked_domains": [{"ads.example": 50}], "top_clients": []})
        if p == "/control/protection":
            return httpx.Response(200)
        if p == "/control/status":
            return httpx.Response(200, json={"protection_enabled": True})
        if p == "/api/tokens":
            return httpx.Response(200, json={"token": "jwt"})
        if p == "/api/nginx/proxy-hosts":
            assert req.headers["authorization"] == "Bearer jwt"
            return httpx.Response(200, json=[
                {"domain_names": ["jellyfin.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.20",
                 "forward_port": 8096, "certificate_id": 3, "enabled": 1},
                {"domain_names": ["adguard.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.2",
                 "forward_port": 80, "certificate_id": 3, "enabled": 1},
                {"domain_names": ["*.wild.jbogaert.be"], "certificate_id": 3, "enabled": 1},
            ])
        if p == "/api/nginx/certificates":
            soon = (datetime.now(timezone.utc) + timedelta(days=5)).strftime("%Y-%m-%d %H:%M:%S")
            return httpx.Response(200, json=[{"nice_name": "*.jbogaert.be", "provider": "letsencrypt", "expires_on": soon}])
        if p == "/api2/json/status/datastore-usage":
            assert req.headers["authorization"] == "PBSAPIToken=homepage@pbs!dash:geheim"
            return httpx.Response(200, json={"data": [{"store": "hdd", "used": 900, "total": 1000,
                                                       "estimated-full-date": 1900000000}]})
        if p == "/api2/json/admin/datastore/hdd/groups":
            now = datetime.now(timezone.utc).timestamp()
            return httpx.Response(200, json={"data": [
                {"backup-type": "vm", "backup-id": "100", "last-backup": now - 3600, "backup-count": 7},
                {"backup-type": "ct", "backup-id": "101", "last-backup": now - 5 * 86400, "backup-count": 3}]})
        if p == "/api2/json/nodes/localhost/tasks":
            return httpx.Response(200, json={"data": [{"worker_type": "backup", "worker_id": "hdd:ct/101",
                                                       "starttime": 1, "status": "error: no space"},
                                                      {"worker_type": "gc", "status": "OK"}]})
        if p == "/status.json":
            return httpx.Response(200, json={"sensors": [{"value": 21.456}], "ok": True})
        return httpx.Response(404)


@pytest.fixture
def fake(monkeypatch):
    f = Fake()
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(f)))
    router._cache.clear()
    from app.integrations import npm
    npm._tokens.clear()
    return f


async def _group(authed):
    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    return (await authed.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]


async def _svc(authed, group, type_, url, config=None, secrets=None, name="X"):
    r = await authed.post("/api/services", json={"group_id": group, "name": name, "url": url, "type": type_,
                                                 "config": config or {}, "secrets": secrets})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def test_proxmox_summary_detail_and_action(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"})
    w = (await authed.get("/api/widgets")).json()[str(sid)]["fields"]
    vals = {f["label"]: f for f in w}
    assert vals["VM"]["value"] == "1/1" and vals["LXC"]["value"] == "0/1"  # template telt niet mee
    assert vals["nodes"]["value"] == "1/2" and vals["nodes"]["level"] == "err"
    assert vals["CPU"]["value"] == "25%" and vals["RAM"]["value"] == "25%"

    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    assert d["label"] == "Proxmox VE"
    guests = next(s for s in d["sections"] if s["title"] == "vm's en containers")
    assert [r["cells"][0]["v"] for r in guests["rows"]] == [100, 101]
    start = guests["rows"][1]["actions"][0]
    assert start["id"] == "start"

    r = await authed.post(f"/api/services/{sid}/integration/action", json={"action": "start", "params": start["params"]})
    assert r.status_code == 200, r.text
    assert fake.calls[-1].method == "POST" and fake.calls[-1].url.path.endswith("/lxc/101/status/start")

    bad = await authed.post(f"/api/services/{sid}/integration/action",
                            json={"action": "start", "params": {"node": "../x", "type": "lxc", "vmid": 1}})
    assert bad.status_code == 502
    unknown = await authed.post(f"/api/services/{sid}/integration/action", json={"action": "delete", "params": {}})
    assert unknown.status_code == 502


async def test_action_needs_recent_2fa(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"})
    agen = app.dependency_overrides[get_db]()
    db = await agen.__anext__()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    body = {"action": "start", "params": {"node": "pve50", "type": "lxc", "vmid": 101}}
    r = await authed.post(f"/api/services/{sid}/integration/action", json=body)
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})).status_code == 200
    assert (await authed.post(f"/api/services/{sid}/integration/action", json=body)).status_code == 200


async def test_missing_secret_and_unreachable_show_error(authed, fake, monkeypatch):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be")
    assert "Geheim ontbreekt" in (await authed.get("/api/widgets")).json()[str(sid)]["error"]

    def boom(req):
        raise httpx.ConnectError("nope")
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(boom)))
    router._cache.clear()
    sid2 = await _svc(authed, g, "adguard", "https://adguard.jbogaert.be", secrets={"username": "a", "password": "b"})
    assert "Niet bereikbaar" in (await authed.get("/api/widgets")).json()[str(sid2)]["error"]


async def test_summary_is_cached_until_service_changes(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "adguard", "https://adguard.jbogaert.be", secrets={"username": "a", "password": "b"})
    await authed.get("/api/widgets")
    n = len(fake.calls)
    await authed.get("/api/widgets")
    assert len(fake.calls) == n
    await authed.patch(f"/api/services/{sid}", json={"group_id": g, "name": "AdGuard 2", "type": "adguard",
                                                      "url": "https://adguard2.jbogaert.be"})
    w = (await authed.get("/api/widgets")).json()[str(sid)]["fields"]
    assert len(fake.calls) > n
    assert {f["label"]: f["value"] for f in w}["geblokkeerd"] == "12.5%"


async def test_adguard_toggle(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "adguard", "https://adguard.jbogaert.be", secrets={"username": "a", "password": "b"})
    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    act = d["sections"][0]["actions"][0]
    assert act["params"] == {"enabled": False}
    r = await authed.post(f"/api/services/{sid}/integration/action", json={"action": "protection", "params": act["params"]})
    assert r.status_code == 200
    assert json.loads(fake.calls[-1].content) == {"enabled": False}
    notes = (await authed.get("/api/notifications")).json()
    assert any("Bescherming uitgezet" in n["title"] for n in notes["items"])


async def test_npm_summary_and_import(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "npm", "http://192.168.0.245:81", secrets={"username": "a@b.be", "password": "x"})
    await _svc(authed, g, "link", "https://adguard.jbogaert.be/", name="AdGuard")
    w = {f["label"]: f for f in (await authed.get("/api/widgets")).json()[str(sid)]["fields"]}
    assert w["hosts"]["value"] == 3 and w["cert"]["level"] == "err"

    hosts = (await authed.get(f"/api/services/{sid}/npm/hosts")).json()
    assert [(h["name"], h["exists"]) for h in hosts] == [("adguard", True), ("jellyfin", False)]
    r = await authed.post(f"/api/services/{sid}/npm/import", json={"group_id": g, "hosts": hosts})
    assert r.json() == {"added": 1}
    again = await authed.post(f"/api/services/{sid}/npm/import", json={"group_id": g, "hosts": hosts})
    assert again.json() == {"added": 0}
    layout = (await authed.get("/api/layout")).json()
    names = [s["name"] for s in layout["pages"][0]["groups"][0]["services"]]
    assert names[-1] == "jellyfin"
    jf = layout["pages"][0]["groups"][0]["services"][-1]
    assert jf["url"] == "https://jellyfin.jbogaert.be" and jf["check"]["type"] == "http"


async def test_json_fields(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "json", "https://api.jbogaert.be/status.json", config={"fields": [
        {"label": "temp", "path": "sensors.0.value", "suffix": " °C"}, {"label": "ok", "path": "ok"},
        {"label": "weg", "path": "nope.x"}]})
    w = (await authed.get("/api/widgets")).json()[str(sid)]["fields"]
    assert [f["value"] for f in w] == ["21.46 °C", True, "—"]
    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    assert d["sections"][-1]["kind"] == "code"


async def test_integration_list_and_link_has_none(authed, fake):
    names = {i["name"] for i in (await authed.get("/api/integrations")).json()}
    assert {"proxmox", "proxmoxbackupserver", "adguard", "npm", "json"} <= names
    g = await _group(authed)
    sid = await _svc(authed, g, "link", "https://x.jbogaert.be")
    assert (await authed.get(f"/api/services/{sid}/integration")).status_code == 404
    assert str(sid) not in (await authed.get("/api/widgets")).json()


async def test_pbs(authed, fake):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmoxbackupserver", "https://pbs.jbogaert.be",
                     secrets={"username": "homepage@pbs!dash", "password": "geheim"})
    w = {f["label"]: f for f in (await authed.get("/api/widgets")).json()[str(sid)]["fields"]}
    assert w["opslag"]["value"] == "90%" and w["opslag"]["level"] == "warn"
    assert w["fouten 24u"]["value"] == 1 and w["oudste"]["level"] == "err"
    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    backups = d["sections"][1]["rows"]
    assert [r[1]["v"] for r in backups] == ["ct/101", "vm/100"]
    assert [r[3]["level"] for r in backups] == ["err", "ok"]
    assert d["sections"][0]["items"][0]["note"] == {"full_at": 1900000000}
