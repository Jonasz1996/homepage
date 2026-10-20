import asyncio
import json
from datetime import datetime, timedelta, timezone

import asyncssh
import pyotp
import pytest
from sqlalchemy import select, update

from app.db import get_db
from app.main import app
from app.models import AuditLog, Session, SshHost


class WS:
    """Minimale ASGI-websocketclient, in dezelfde event loop als de tests."""

    def __init__(self, path: str, cookie: str, origin: str = "http://test", query: str = "cols=80&rows=24"):
        self.to_app: asyncio.Queue = asyncio.Queue()
        self.from_app: asyncio.Queue = asyncio.Queue()
        headers = [(b"host", b"test"), (b"cookie", f"hp_session={cookie}".encode())]
        if origin:
            headers.append((b"origin", origin.encode()))
        scope = {"type": "websocket", "path": path, "raw_path": path.encode(), "query_string": query.encode(),
                 "headers": headers, "scheme": "ws", "server": ("test", 80), "client": ("127.0.0.1", 5000),
                 "subprotocols": [], "asgi": {"version": "3.0"}}
        self.task = asyncio.create_task(app(scope, self.to_app.get, self.from_app.put))

    async def open(self):
        await self.to_app.put({"type": "websocket.connect"})
        assert (await self.recv())["type"] == "websocket.accept"

    async def recv(self, timeout=10):
        return await asyncio.wait_for(self.from_app.get(), timeout)

    async def json(self):
        while True:
            m = await self.recv()
            if m["type"] == "websocket.send" and m.get("text"):
                return json.loads(m["text"])
            if m["type"] == "websocket.close":
                return {"t": "socket-closed"}

    async def read_until(self, needle: bytes, timeout=10) -> bytes:
        buf = b""
        while needle not in buf:
            m = await self.recv(timeout)
            if m["type"] == "websocket.send" and m.get("bytes"):
                buf += m["bytes"]
        return buf

    async def send_text(self, obj):
        await self.to_app.put({"type": "websocket.receive", "text": json.dumps(obj)})

    async def send_bytes(self, b: bytes):
        await self.to_app.put({"type": "websocket.receive", "bytes": b})

    async def close(self):
        await self.to_app.put({"type": "websocket.disconnect", "code": 1000})
        await asyncio.wait_for(self.task, 10)


class Server(asyncssh.SSHServer):
    def begin_auth(self, username):
        return True

    def password_auth_supported(self):
        return True

    def validate_password(self, username, password):
        return username == "root" and password == "goed"


async def handle(process: asyncssh.SSHServerProcess):
    cols, rows, *_ = process.term_size
    process.stdout.write(f"welkom {process.get_extra_info('username')} {cols}x{rows}\r\n")
    try:
        async for line in process.stdin:
            if line.strip() == "size":
                c, r, *_ = process.term_size
                process.stdout.write(f"size {c}x{r}\r\n")
            elif line.strip() == "exit":
                break
            else:
                process.stdout.write(f"echo:{line.strip()}\r\n")
    except asyncssh.TerminalSizeChanged:
        pass
    process.exit(0)


@pytest.fixture
async def sshd():
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(
        Server, "127.0.0.1", 0, server_host_keys=[host_key], process_factory=handle,
        authorized_client_keys=asyncssh.import_authorized_keys(client_key.export_public_key().decode()),
        line_editor=False,
    )
    port = server.sockets[0].getsockname()[1]
    yield {"port": port, "host_key": host_key, "client_key": client_key}
    server.close()
    await server.wait_closed()


def _cookie(client) -> str:
    return client.cookies.get("hp_session")


_open = []


async def _db():
    # Generator bewaren: als hij opgeruimd wordt, sluit hij de sessie (en draait alles terug).
    agen = app.dependency_overrides[get_db]()
    _open.append(agen)
    return await agen.__anext__()


async def test_password_login_hostkey_and_shell(authed, sshd):
    r = await authed.post("/api/ssh/hosts", json={"name": "pve", "host": "127.0.0.1", "port": sshd["port"],
                                                  "username": "root", "password": "goed"})
    assert r.status_code == 201, r.text
    hid = r.json()["id"]
    assert r.json()["has_password"] and "password" not in r.json()

    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    assert (await ws.json())["t"] == "status"
    hk = await ws.json()
    assert hk["t"] == "hostkey" and hk["fp"] == sshd["host_key"].get_fingerprint("sha256")
    await ws.send_text({"t": "accept"})
    assert (await ws.json())["t"] == "status"
    assert (await ws.json())["t"] == "ready"
    assert b"welkom root 80x24" in await ws.read_until(b"80x24")
    await ws.send_bytes(b"hallo\n")
    assert b"echo:hallo" in await ws.read_until(b"echo:hallo")
    await ws.send_text({"t": "r", "c": 120, "r": 40})
    await asyncio.sleep(0.1)
    await ws.close()

    hosts = (await authed.get("/api/ssh/hosts")).json()
    assert hosts[0]["host_key_fingerprint"] == hk["fp"]
    db = await _db()
    actions = [a.action for a in (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars()]
    assert "ssh_hostkey_accepted" in actions and "ssh_open" in actions


async def test_key_login_and_changed_hostkey_refused(authed, sshd):
    r = await authed.post("/api/ssh/keys", json={"name": "test", "private_key": sshd["client_key"].export_private_key().decode()})
    assert r.status_code == 201, r.text
    key = r.json()
    assert key["public_key"].startswith("ssh-ed25519 ") and "private" not in json.dumps(key)
    hid = (await authed.post("/api/ssh/hosts", json={"name": "ct", "host": "127.0.0.1", "port": sshd["port"],
                                                     "username": "jonas", "key_id": key["id"]})).json()["id"]
    # Hostsleutel van een andere machine vooraf opslaan: verbinding moet geweigerd worden.
    db = await _db()
    other = asyncssh.generate_private_key("ssh-ed25519").export_public_key().decode()
    await db.execute(update(SshHost).values(host_key=other))
    await db.commit()
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    msgs = [await ws.json(), await ws.json()]
    assert msgs[-1]["t"] == "error" and "veranderd" in msgs[-1]["m"]

    assert (await authed.post(f"/api/ssh/hosts/{hid}/forget-hostkey")).status_code == 200
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    await ws.json()
    assert (await ws.json())["t"] == "hostkey"
    await ws.send_text({"t": "accept"})
    await ws.json()
    assert (await ws.json())["t"] == "ready"
    assert b"welkom jonas" in await ws.read_until(b"welkom jonas")
    await ws.close()


async def test_generated_key_and_wrong_password(authed, sshd):
    key = (await authed.post("/api/ssh/keys", json={"name": "nieuw"})).json()
    assert key["fingerprint"].startswith("SHA256:")
    hid = (await authed.post("/api/ssh/hosts", json={"name": "x", "host": "127.0.0.1", "port": sshd["port"],
                                                     "password": "fout"})).json()["id"]
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    await ws.json()
    await ws.json()
    await ws.send_text({"t": "accept"})
    await ws.json()
    err = await ws.json()
    assert err["t"] == "error" and "geweigerd" in err["m"]


async def test_ws_requires_origin_login_and_recent_2fa(authed, sshd):
    hid = (await authed.post("/api/ssh/hosts", json={"name": "x", "host": "127.0.0.1", "port": sshd["port"]})).json()["id"]
    for origin, cookie, why in [("https://evil.example", _cookie(authed), "Verkeerde origin"),
                                (None, _cookie(authed), "Verkeerde origin"),
                                ("http://test", "nep", "Niet ingelogd")]:
        ws = WS(f"/api/ssh/ws/{hid}", cookie, origin=origin)
        await ws.open()
        assert await ws.json() == {"t": "error", "m": why}
        # Eerst de handler laten afronden: zijn databasesessie deelt de SQLite-verbinding in het geheugen, en zijn
        # rollback bij het sluiten mag de update hieronder niet ongedaan maken (op Python 3.13 gebeurde dat).
        await asyncio.wait_for(ws.task, 5)

    db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    ws = WS(f"/api/ssh/ws/{hid}", _cookie(authed))
    await ws.open()
    assert await ws.json() == {"t": "error", "m": "reauth_required"}
    assert (await authed.get("/api/ssh/ready")).status_code == 403
    assert (await authed.post("/api/ssh/keys", json={"name": "x"})).status_code == 403
    await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})
    assert (await authed.get("/api/ssh/ready")).status_code == 200


async def test_host_validation_and_edit(authed):
    bad = await authed.post("/api/ssh/hosts", json={"name": "x", "host": "-oProxyCommand=boom"})
    assert bad.status_code == 422
    h = (await authed.post("/api/ssh/hosts", json={"name": "x", "host": "10.0.0.1", "password": "a"})).json()
    db = await _db()
    await db.execute(update(SshHost).values(host_key="ssh-ed25519 AAAA"))
    await db.commit()
    r = await authed.patch(f"/api/ssh/hosts/{h['id']}", json={"name": "y", "host": "10.0.0.2", "password": ""})
    assert r.status_code == 200 and r.json()["has_password"] is False and r.json()["host_key_fingerprint"] is None
    assert (await authed.post("/api/ssh/hosts", json={"name": "x", "host": "h", "key_id": 999})).status_code == 400
