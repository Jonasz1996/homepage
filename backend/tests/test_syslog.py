import asyncio
from datetime import datetime, timedelta, timezone

import asyncssh
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.config import get_settings
from app.db import get_db
from app.main import app
from app.models import LogEntry, LogRule, Notification
from app.syslog.parse import parse
from app.syslog.server import Receiver, handle_tcp

NOW = datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc)


def test_parse_rfc3164_with_tag_and_pid():
    p = parse(b"<30>Oct  3 19:59:01 pve50 systemd[1]: Started Daily apt upgrade.\n", "192.168.0.50", NOW)
    assert (p.host, p.app, p.facility, p.severity) == ("pve50", "systemd", 3, 6)
    assert p.msg == "Started Daily apt upgrade." and p.ts == NOW


def test_parse_rfc5424():
    raw = b'<11>1 2026-10-03T17:59:58.123Z ct101 nginx 4242 - [meta x="1"] upstream timed out'
    p = parse(raw, "192.168.0.101", NOW)
    assert (p.host, p.app, p.severity) == ("ct101", "nginx", 3)
    assert p.msg == "upstream timed out" and p.ts.minute == 59


def test_parse_garbage_and_control_chars():
    p = parse(b"zomaar\x00tekst\x1b[31m", "10.0.0.9", NOW)
    assert p.host == "10.0.0.9" and "\x00" not in p.msg and p.severity == 5
    assert parse(b"<999>x", None, NOW).facility == 23
    far = parse(b'<14>1 2031-01-01T00:00:00Z h a - - - m', None, NOW)
    assert far.ts == NOW  # klok van de bron staat verkeerd


@pytest.fixture
async def receiver(authed):
    agen = app.dependency_overrides[get_db]()
    db = await agen.__anext__()
    maker = async_sessionmaker(db.bind, expire_on_commit=False)
    rx = Receiver(maker)
    yield rx, db
    await agen.aclose()


async def test_receiver_stores_and_rules_notify(receiver, authed):
    rx, db = receiver
    db.add(LogRule(name="OOM", pattern="out of memory", max_severity=7, level="err", cooldown_minutes=10))
    # Zoals de migratie ze aanmaakt.
    db.add(LogRule(name="Kritieke meldingen", max_severity=2, level="err", cooldown_minutes=10))
    await db.commit()
    rx.accept(b"<14>Oct  3 20:00:01 pve50 kernel: Out of memory: Killed process 1234 (java)", "192.168.0.50")
    rx.accept(b"<14>Oct  3 20:00:02 pve50 kernel: Out of memory: Killed process 99 (x)", "192.168.0.50")   # cooldown
    rx.accept(b"<10>Oct  3 20:00:03 pve51 smartd[3]: Device /dev/sda failed", "192.168.0.51")             # standaardregel crit
    rx.accept(b"<14>internet zegt hallo", "8.8.8.8")                                       # niet toegelaten
    items = []
    while not rx.queue.empty():
        items.append(rx.queue.get_nowait())
    assert len(items) == 3
    await rx.flush(items)
    rows = (await db.execute(select(LogEntry).order_by(LogEntry.id))).scalars().all()
    assert [r.host for r in rows] == ["pve50", "pve50", "pve51"]
    notes = (await db.execute(select(Notification.title).where(Notification.source == "syslog"))).scalars().all()
    assert sorted(notes) == ["pve50: OOM", "pve51: Kritieke meldingen"]


async def test_tcp_octet_counting_and_lines(receiver):
    rx, _ = receiver
    srv = await asyncio.start_server(lambda r, w: handle_tcp(rx, r, w), "127.0.0.1", 0)
    port = srv.sockets[0].getsockname()[1]
    _, w = await asyncio.open_connection("127.0.0.1", port)
    m1 = b"<13>1 2026-10-03T18:00:00Z h1 app - - - een"
    w.write(str(len(m1)).encode() + b" " + m1 + b"<13>h2 app: twee\n")
    await w.drain()
    w.close()
    for _ in range(50):
        if rx.queue.qsize() == 2:
            break
        await asyncio.sleep(0.02)
    got = [rx.queue.get_nowait()[0] for _ in range(rx.queue.qsize())]
    assert got == [m1, b"<13>h2 app: twee\n"]
    srv.close()


async def _seed(db):
    now = datetime.now(timezone.utc)
    rows = [LogEntry(ts=now - timedelta(minutes=i), host="pve50" if i % 2 else "ct101", app="sshd" if i % 3 else "cron",
                     severity=3 if i == 4 else 6, msg=f"bericht {i}" + (" Failed password" if i == 4 else ""))
            for i in range(30)]
    rows.append(LogEntry(ts=now - timedelta(days=3), host="oud", severity=6, msg="oud"))
    db.add_all(rows)
    await db.commit()


async def test_search_pagination_hosts_histogram(receiver, authed):
    _, db = receiver
    await _seed(db)
    r = (await authed.get("/api/logs", params={"limit": 10})).json()
    assert len(r["items"]) == 10 and r["more"] and r["items"][0]["msg"] == "bericht 0"
    last = r["items"][-1]
    r2 = (await authed.get("/api/logs", params={"limit": 10, "before_ts": last["ts"], "before_id": last["id"]})).json()
    assert r2["items"][0]["msg"] == "bericht 10"
    assert (await authed.get("/api/logs", params={"q": "failed PASSWORD"})).json()["items"][0]["severity"] == 3
    assert len((await authed.get("/api/logs", params={"sev": 3})).json()["items"]) == 1
    assert {i["host"] for i in (await authed.get("/api/logs", params={"host": "ct101"})).json()["items"]} == {"ct101"}
    assert len((await authed.get("/api/logs", params={"range": "7d"})).json()["items"]) == 31
    assert (await authed.get("/api/logs", params={"q": "100%_"})).json()["items"] == []

    hosts = {h["host"]: h for h in (await authed.get("/api/logs/hosts")).json()}
    assert set(hosts) == {"pve50", "ct101"} and hosts["ct101"]["errors"] == 1
    hist = (await authed.get("/api/logs/histogram", params={"range": "1h"})).json()
    assert sum(p["total"] for p in hist["points"]) == 30 and sum(p["err"] for p in hist["points"]) == 1

    newest = r["items"][0]["id"]
    db.add(LogEntry(host="pve50", severity=6, msg="live"))
    await db.commit()
    live = (await authed.get("/api/logs", params={"after_id": max(newest, 31)})).json()["items"]
    assert [i["msg"] for i in live] == ["live"]


async def test_rules_crud(authed):
    rules = (await authed.get("/api/logs/rules")).json()
    assert rules == [] or rules[0]["name"] == "Kritieke meldingen"
    bad = await authed.post("/api/logs/rules", json={"name": "x", "pattern": "("})
    assert bad.status_code == 422
    r = (await authed.post("/api/logs/rules", json={"name": "ssh", "pattern": "Failed password", "host": " "})).json()
    assert r["host"] is None
    r = (await authed.patch(f"/api/logs/rules/{r['id']}", json={**r, "enabled": False})).json()
    assert r["enabled"] is False
    assert (await authed.delete(f"/api/logs/rules/{r['id']}")).status_code == 200


async def test_rollout_over_ssh(authed, monkeypatch):
    got = {}

    class S(asyncssh.SSHServer):
        def begin_auth(self, u):
            return True

        def password_auth_supported(self):
            return True

        def validate_password(self, u, p):
            return p == "pw"

    async def handle(proc):
        got["command"] = proc.command
        got["script"] = await proc.stdin.read()
        proc.stdout.write("ok pve50\n--- CT 101\nok ct101\n")
        proc.exit(0)

    hk = asyncssh.generate_private_key("ssh-ed25519")
    server = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[hk], process_factory=handle)
    port = server.sockets[0].getsockname()[1]
    hid = (await authed.post("/api/ssh/hosts", json={"name": "pve50", "host": "127.0.0.1", "port": port,
                                                     "password": "pw"})).json()["id"]
    body = {"host_id": hid, "containers": True}
    assert "HOMEPAGE_SYSLOG_TARGET" in (await authed.post("/api/logs/rollout", json=body)).json()["detail"]
    monkeypatch.setattr(get_settings(), "syslog_target", "192.168.0.80")
    assert "hostsleutel" in (await authed.post("/api/logs/rollout", json=body)).json()["detail"]

    agen = app.dependency_overrides[get_db]()
    db = await agen.__anext__()
    from app.models import SshHost
    h = await db.get(SshHost, hid)
    h.host_key = hk.export_public_key().decode()
    await db.commit()
    r = await authed.post("/api/logs/rollout", json=body)
    assert r.status_code == 200, r.text
    assert r.json() == {"exit_status": 0, "output": "ok pve50\n--- CT 101\nok ct101\n"}
    assert got["command"] == "sh -s"
    assert "sh /tmp/hp-rsyslog.sh 192.168.0.80 514" in got["script"]
    assert 'if [ "1" = 1 ]' in got["script"]
    setup = (await authed.get("/api/logs/setup")).json()
    assert setup["target"] == "192.168.0.80" and "omfwd" in setup["manual"]
    server.close()
