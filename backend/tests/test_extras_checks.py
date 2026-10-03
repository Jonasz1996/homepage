import asyncio
import datetime as dt
import ssl
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import dns.message
import dns.rrset
import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import select

from app.db import get_db
from app.main import app
from app.models import AppState, CheckResult, Notification, Service, ServiceState
from app.monitoring import checks
from app.monitoring.checks import HttpClients, Outcome, check_dns, check_http
from app.monitoring.engine import record
from app.monitoring.watchers import watch_npm

_open = []


async def _db():
    agen = app.dependency_overrides[get_db]()
    _open.append(agen)
    return await agen.__anext__()


# --- Inhoud controleren -----------------------------------------------------------

def _client(body: bytes, status=200, ctype="text/html"):
    return httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(status, content=body, headers={"content-type": ctype})))


async def test_keyword_and_json_checks():
    page = b"<html><h1>Jellyfin</h1> Server is running</html>"
    async with _client(page) as c:
        assert (await check_http("http://x/", {"keyword": "server IS running"}, c)).ok
        out = await check_http("http://x/", {"keyword": "Welkom"}, c)
        assert not out.ok and "niet gevonden" in out.error
        out = await check_http("http://x/", {"keyword": "running", "keyword_absent": True}, c)
        assert not out.ok and "staat op de pagina" in out.error
    async with _client(b'{"status": {"health": "OK", "nodes": [1, 2]}}', ctype="application/json") as c:
        assert (await check_http("http://x/", {"json_path": "status.health", "json_value": "ok"}, c)).ok
        assert (await check_http("http://x/", {"json_path": "status.nodes.1"}, c)).ok
        out = await check_http("http://x/", {"json_path": "status.health", "json_value": "degraded"}, c)
        assert not out.ok and "verwacht degraded" in out.error
        assert "ontbreekt" in (await check_http("http://x/", {"json_path": "status.x"}, c)).error
    async with _client(b"geen json") as c:
        assert (await check_http("http://x/", {"json_path": "a"}, c)).error == "Antwoord is geen JSON"
    async with _client(b"Server is running", status=503) as c:
        assert (await check_http("http://x/", {"keyword": "running"}, c)).error == "HTTP 503"


# --- Certificaat ------------------------------------------------------------------

@pytest.fixture
async def https_server():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    not_after = datetime(2026, 12, 24, 12, 0, tzinfo=timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc)).not_valid_after(not_after)
            .sign(key, hashes.SHA256()))
    d = Path(tempfile.mkdtemp())
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")

    async def handle(r, w):
        await r.readuntil(b"\r\n\r\n")
        w.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok")
        await w.drain()
        w.close()

    srv = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    yield srv.sockets[0].getsockname()[1], not_after
    srv.close()


async def test_http_check_reads_certificate_expiry(https_server):
    port, not_after = https_server
    clients = HttpClients()
    out = await checks.run_check({"type": "http", "insecure": True}, f"https://127.0.0.1:{port}/", clients)
    assert out.ok and out.cert_expires == not_after
    # Zonder 'insecure' faalt een zelfondertekend certificaat gewoon.
    assert not (await checks.run_check({"type": "http"}, f"https://127.0.0.1:{port}/", clients)).ok
    await clients.aclose()


# --- DNS --------------------------------------------------------------------------

@pytest.fixture
async def dns_server():
    class P(asyncio.DatagramProtocol):
        def connection_made(self, t):
            self.t = t

        def datagram_received(self, data, addr):
            q = dns.message.from_wire(data)
            resp = dns.message.make_response(q)
            name = q.question[0].name.to_text()
            if name == "jellyfin.jbogaert.be.":
                resp.answer.append(dns.rrset.from_text(name, 60, "IN", "A", "192.168.0.245"))
            else:
                resp.set_rcode(dns.rcode.NXDOMAIN)
            self.t.sendto(resp.to_wire(), addr)

    loop = asyncio.get_running_loop()
    t, _ = await loop.create_datagram_endpoint(P, local_addr=("127.0.0.1", 0))
    yield t.get_extra_info("sockname")[1]
    t.close()


async def test_dns_check(dns_server):
    base = {"type": "dns", "dns_server": "127.0.0.1", "dns_port": dns_server}
    assert (await check_dns("jellyfin.jbogaert.be", {**base, "expect": "192.168.0.245"})).ok
    out = await check_dns("jellyfin.jbogaert.be", {**base, "expect": "192.168.0.9"})
    assert not out.ok and "verwacht 192.168.0.9" in out.error
    assert "NXDOMAIN" in (await check_dns("weg.jbogaert.be", base)).error
    assert (await check_dns("-x", base)).error == "Ongeldige naam"
    assert "IP-adres" in (await check_dns("a.be", {"dns_server": "adguard"})).error
    assert checks.target_for({"type": "dns"}, "https://jellyfin.jbogaert.be/web") == "jellyfin.jbogaert.be"


# --- Onderhoud, afhankelijkheden, certificaatmeldingen ----------------------------

async def _layout(authed):
    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    group = (await authed.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]

    async def svc(name, parent=None):
        return (await authed.post("/api/services", json={"group_id": group, "name": name, "url": f"https://{name}.be",
                                                         "check": {"type": "http"}, "parent_id": parent})).json()["id"]
    node = await svc("pve50")
    ct = await svc("ct101", node)
    app_ = await svc("jellyfin", ct)
    return group, node, ct, app_


async def _fail(db, sid, n=3, now=None):
    s = await db.get(Service, sid)
    for i in range(n):
        await record(db, s, Outcome(False, error="Time-out"), now=(now or datetime.now(timezone.utc)) + timedelta(seconds=i))
    await db.commit()


async def _titles(db):
    return [n for n in (await db.execute(select(Notification.title).where(Notification.source == "monitor")
                                         .order_by(Notification.id))).scalars()]


async def test_dependency_gives_one_notification(authed):
    group, node, ct, app_ = await _layout(authed)
    db = await _db()
    await _fail(db, node)
    await _fail(db, ct)
    await _fail(db, app_)
    assert await _titles(db) == ["pve50 is down (2 services getroffen)"]
    status = (await authed.get("/api/status")).json()
    assert status[str(app_)]["cause"] == "pve50" and status[str(node)]["cause"] is None
    s = await db.get(Service, app_)
    await record(db, s, Outcome(True, 5.0))
    await db.commit()
    assert len(await _titles(db)) == 1  # stil terug, want stil down gegaan


async def test_maintenance_silences_and_is_not_counted(authed):
    group, node, ct, app_ = await _layout(authed)
    r = await authed.post(f"/api/services/{node}/maintenance", json={"minutes": 30})
    assert r.status_code == 200 and r.json()["maintenance_until"]
    db = await _db()
    await _fail(db, app_)  # erft onderhoud van de node
    assert await _titles(db) == []
    st = await db.get(ServiceState, app_)
    assert st.status == "unknown" and st.fail_count == 0
    rows = (await db.execute(select(CheckResult.maintenance).where(CheckResult.service_id == app_))).scalars().all()
    assert rows == [True, True, True]
    status = (await authed.get("/api/status")).json()
    assert status[str(app_)]["maintenance_until"] and status[str(node)]["maintenance_until"]
    assert status[str(app_)]["uptime_24h"] is None
    hist = (await authed.get(f"/api/services/{app_}/history?range=1h")).json()
    assert hist["uptime"] is None and hist["recent"][0]["maintenance"] is True

    await authed.post(f"/api/services/{node}/maintenance", json={"minutes": 0})
    await authed.post(f"/api/groups/{group}/maintenance", json={"minutes": 60})
    assert all(v.get("maintenance_until") for v in (await authed.get("/api/status")).json().values())
    await authed.post(f"/api/groups/{group}/maintenance", json={"minutes": 0})
    db2 = await _db()
    await _fail(db2, app_)
    assert await _titles(db2) == ["jellyfin is down"]


async def test_certificate_notifications(authed):
    _, node, _, _ = await _layout(authed)
    db = await _db()
    s = await db.get(Service, node)
    now = datetime.now(timezone.utc)
    for days in (40, 13, 12, 2, 1, 60, 10):
        await record(db, s, Outcome(True, 3.0, cert_expires=now + timedelta(days=days)))
    await db.commit()
    titles = await _titles(db)
    assert titles == ["Certificaat van pve50 vervalt over 12 dagen", "Certificaat van pve50 vervalt over 1 dagen",
                      "Certificaat van pve50 vervalt over 9 dagen"]
    assert (await authed.get("/api/status")).json()[str(node)]["cert_expires_at"]


async def test_parent_validation_and_restore(authed):
    group, node, ct, app_ = await _layout(authed)
    body = {"group_id": group, "name": "pve50", "url": "https://pve50.be", "parent_id": app_}
    assert (await authed.patch(f"/api/services/{node}", json=body)).status_code == 400
    body["parent_id"] = 999
    assert (await authed.patch(f"/api/services/{node}", json=body)).status_code == 400
    revs = (await authed.get("/api/revisions")).json()
    # Terug naar de versie met alle drie de services: afhankelijkheden komen mee terug.
    await authed.delete(f"/api/services/{ct}")
    target = next(r for r in revs if "jellyfin" in r["summary"])
    assert (await authed.post(f"/api/revisions/{target['id']}/restore")).status_code == 200
    layout = (await authed.get("/api/layout")).json()
    by_name = {s["name"]: s for s in layout["pages"][0]["groups"][0]["services"]}
    assert by_name["jellyfin"]["parent_id"] == by_name["ct101"]["id"] and by_name["ct101"]["parent_id"] == node


# --- Nieuwe NPM-hosts ---------------------------------------------------------------

async def test_watch_npm_notifies_new_hosts_once(authed):
    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    group = (await authed.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]
    await authed.post("/api/services", json={"group_id": group, "name": "NPM", "url": "http://192.168.0.245:81",
                                             "type": "npm", "secrets": {"username": "a", "password": "b"}})
    await authed.post("/api/services", json={"group_id": group, "name": "AdGuard", "url": "https://adguard.jbogaert.be"})
    hosts = [{"domain_names": ["adguard.jbogaert.be"], "certificate_id": 1}]

    def handler(req):
        if req.url.path == "/api/tokens":
            return httpx.Response(200, json={"token": "t"})
        return httpx.Response(200, json=hosts)
    clients = HttpClients(httpx.MockTransport(handler))
    from app.integrations import npm
    npm._tokens.clear()
    db = await _db()
    await watch_npm(db, clients)       # eerste keer: alleen onthouden
    await db.commit()
    hosts.append({"domain_names": ["jellyfin.jbogaert.be"], "certificate_id": 1})
    hosts.append({"domain_names": ["plex.jbogaert.be"], "certificate_id": 1})
    await watch_npm(db, clients)
    await db.commit()
    await watch_npm(db, clients)       # geen tweede melding
    await db.commit()
    notes = (await db.execute(select(Notification).where(Notification.source == "npm"))).scalars().all()
    assert [n.title for n in notes] == ["2 nieuwe hosts in NPM"]
    assert "jellyfin.jbogaert.be, plex.jbogaert.be" in notes[0].body
    assert (await db.get(AppState, "npm_seen:1")).value["hosts"][0] == "adguard.jbogaert.be"
