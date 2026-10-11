import asyncio
import os
import signal
import socket
import sys
import time
from datetime import datetime, timedelta, timezone

import asyncssh
import pytest
from sqlalchemy import event, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import get_settings
from app.db import get_db
from app.main import app
from app.models import AppState, Base, LogEntry, LogRule, Notification
from app.syslog import server
from app.syslog.parse import parse
from app.syslog.server import Receiver, handle_tcp

from .conftest import BACKEND, TEST_DB

NOW = datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc)
PG = TEST_DB.startswith("postgresql")
# Een database die er niet is: verbinden mislukt meteen, zoals bij een PostgreSQL die herstart.
DEAD = "postgresql+asyncpg://postgres@127.0.0.1:1/weg" if PG else "sqlite+aiosqlite:////niet-bestaande-map/weg.db"
OOM = b"<14>Oct  3 20:00:01 pve50 kernel: Out of memory: Killed process 1234 (java)"


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


# --- database weg, wachtrij, stoppen en starten ---------------------------------------------------------------

class Flaky:
    """Een sessionmaker waarvan de eerste `fails` sessies geen database vinden, daarna wel."""

    def __init__(self, real: async_sessionmaker, fails: int) -> None:
        self.engine = create_async_engine(DEAD)
        self.dead = async_sessionmaker(self.engine)
        self.real, self.fails, self.calls = real, fails, 0

    def __call__(self):
        self.calls += 1
        return self.dead() if self.calls <= self.fails else self.real()


async def _count(maker, model=LogEntry) -> int:
    async with maker() as s:
        return (await s.execute(select(func.count()).select_from(model))).scalar()


async def _titles(maker) -> list[str]:
    async with maker() as s:
        return list((await s.execute(select(Notification.title).where(Notification.source == "syslog"))).scalars())


async def _until(cond, seconds: float = 10) -> None:
    """Wachten op cond(). Op de tellers van de ontvanger, niet op de database: in de SQLite-tests delen alle sessies
    één verbinding, en een sessie die tussendoor leest en sluit, rolt de transactie van de schrijver terug."""
    end = time.monotonic() + seconds
    while not cond():
        assert time.monotonic() < end, "duurde te lang"
        await asyncio.sleep(0.02)


async def test_writer_keeps_every_line_while_the_database_is_away(receiver, monkeypatch):
    rx, db = receiver
    db.add(LogRule(name="OOM", pattern="out of memory", max_severity=7, level="err", cooldown_minutes=10))
    await db.commit()
    monkeypatch.setattr(server, "RETRY_FIRST", 0.01)
    monkeypatch.setattr(server, "FLUSH_SECONDS", 0.05)
    real = rx.maker
    await rx.reload_rules()
    rx.maker = flaky = Flaky(real, 4)
    rx.accept(OOM, "192.168.0.50")
    rx.accept(b"<14>Oct  3 20:00:02 pve50 cron[1]: twee", "192.168.0.50")
    rx.accept(b"<14>Oct  3 20:00:03 pve51 cron[1]: drie", "192.168.0.51")
    task = asyncio.create_task(rx.writer())
    try:
        await _until(lambda: rx.stored == 3)
    finally:
        task.cancel()
        await flaky.engine.dispose()
    # Elke regel precies één keer, de melding één keer, en de storing is voorbij.
    assert flaky.calls > 4 and await _count(real) == 3 and rx.stored == 3 and rx.lost == 0
    assert await _titles(real) == ["pve50: OOM"]
    assert rx.down_since is None and rx.last_error["until"] and rx.last_error["error"]
    # Nu pas telt de cooldown: een nieuwe OOM-regel geeft geen tweede melding.
    assert (await rx.prepare([(OOM, "192.168.0.50", time.time())])).notes == []


async def test_cooldown_only_after_the_batch_is_stored(receiver):
    rx, db = receiver
    db.add(LogRule(name="OOM", pattern="out of memory", max_severity=7, level="err", cooldown_minutes=10))
    await db.commit()
    await rx.reload_rules()
    real = rx.maker
    line = (OOM, "192.168.0.50", time.time())
    first = await rx.prepare([line])
    assert [n["title"] for n in first.notes] == ["pve50: OOM"]
    rx.maker = flaky = Flaky(real, 1)
    with pytest.raises(Exception):
        await rx.store(first)
    await flaky.engine.dispose()
    # Mislukt: geen cooldown, de melding is niet verloren en wordt ook niet onderdrukt.
    assert rx.rules.last_fire == {}
    assert len((await rx.prepare([line])).notes) == 1
    await rx.store(first)
    assert rx.rules.last_fire and (await rx.prepare([line])).notes == []
    assert await _titles(real) == ["pve50: OOM"]


async def test_receive_time_is_kept_until_written(receiver):
    rx, _ = receiver
    before = time.time()
    rx.accept(b"<14>Oct  3 20:00:01 pve50 cron[1]: zonder jaar of tijdzone", "192.168.0.50")
    data, ip, at = rx.queue.get_nowait()
    assert before <= at <= time.time()
    # Pas tien minuten later weggeschreven (na een storing): de regel houdt zijn ontvangsttijd.
    await rx.flush([(data, ip, at - 600)])
    async with rx.maker() as s:
        ts = (await s.execute(select(LogEntry.ts))).scalar()
    assert abs(ts.replace(tzinfo=ts.tzinfo or timezone.utc).timestamp() - (at - 600)) < 1


async def test_long_host_and_rule_name_cut_to_the_title_column(receiver):
    """notifications.title is varchar(200): op PostgreSQL gaf een lange hostnaam een fout, en verloor de batch."""
    rx, db = receiver
    db.add(LogRule(name="r" * 80, max_severity=7, level="warn", cooldown_minutes=0))
    await db.commit()
    host = "h" * 255
    await rx.flush([(f"<14>1 2026-10-03T18:00:00Z {host} app - - - hallo".encode(), "192.168.0.9", time.time())])
    [title] = await _titles(rx.maker)
    assert len(title) == 200 and title.startswith(host[:100])
    async with rx.maker() as s:
        assert (await s.execute(select(LogEntry.host))).scalar() == host


async def test_rejected_row_does_not_block_the_rest(receiver, monkeypatch):
    rx, db = receiver
    monkeypatch.setattr(server, "FLUSH_SECONDS", 0.05)
    dbapi = db.bind.dialect.loaded_dbapi

    def refuse(conn, cursor, statement, params, context, executemany):
        # De database weigert één regel (SQLSTATE 22001, zoals een te lange waarde).
        if statement.lstrip().startswith("INSERT INTO log_entries") and "gif" in repr(params):
            e = (getattr(dbapi, "DataError", None) or dbapi.DatabaseError)("value too long for type varchar(255)")
            e.sqlstate = "22001"
            raise e
    event.listen(db.bind.sync_engine, "before_cursor_execute", refuse)
    try:
        for word in ("een", "gif", "drie"):
            rx.accept(f"<14>app: {word}".encode(), "192.168.0.9")
        task = asyncio.create_task(rx.writer())
        await _until(lambda: rx.stored == 2 and rx.lost == 1)
        # Niet opnieuw geprobeerd: de schrijver neemt gewoon de volgende batch.
        rx.accept(b"<14>app: vier", "192.168.0.9")
        await _until(lambda: rx.stored == 3)
        task.cancel()
    finally:
        event.remove(db.bind.sync_engine, "before_cursor_execute", refuse)
    async with rx.maker() as s:
        assert sorted((await s.execute(select(LogEntry.msg))).scalars()) == ["drie", "een", "vier"]
    assert rx.lost == 1 and rx._loss["why"] == server.REJECTED and rx.down_since is None


async def test_udp_drops_the_oldest_and_tcp_waits(authed, monkeypatch):
    monkeypatch.setattr(server, "QUEUE_MAX", 4)
    rx = Receiver(None)
    for i in range(6):
        rx.accept(f"<14>udp {i}".encode(), "192.168.0.9")
    assert (rx.received, rx.lost, rx.queue.qsize()) == (6, 2, 4)
    assert [rx.queue.get_nowait()[0] for _ in range(4)] == [f"<14>udp {i}".encode() for i in range(2, 6)]

    # TCP: bij een volle wachtrij leest de verbinding niet verder, en er valt niets weg.
    srv = await asyncio.start_server(lambda r, w: handle_tcp(rx, r, w), "127.0.0.1", 0)
    _, w = await asyncio.open_connection("127.0.0.1", srv.sockets[0].getsockname()[1])
    w.write(b"".join(f"<14>tcp {i}\n".encode() for i in range(6)))
    await w.drain()

    await _until(lambda: rx.queue.qsize() == 4)
    await asyncio.sleep(0.2)
    # De vijfde regel is gelezen en wacht op plaats; de zesde blijft ongelezen.
    assert rx.queue.qsize() == 4 and len(rx.clients) == 1 and rx.received == 6 + 5
    got = [rx.queue.get_nowait()[0] for _ in range(4)]
    await _until(lambda: rx.queue.qsize() == 2)
    got += [rx.queue.get_nowait()[0] for _ in range(2)]
    assert got == [f"<14>tcp {i}\n".encode() for i in range(6)] and rx.lost == 2
    # Hoe lang een regel ook is: in de wachtrij hoogstens MAX_RAW bytes.
    rx.accept(b"<14>x " + b"a" * 100_000, "192.168.0.9")
    assert len(rx.queue.get_nowait()[0]) == server.MAX_RAW
    w.close()
    srv.close()


async def test_status_with_counters_and_loss(receiver, authed, monkeypatch):
    rx, _ = receiver
    monkeypatch.setattr(server, "QUEUE_MAX", 2)
    first = Receiver(rx.maker)
    for i in range(5):
        first.accept(f"<14>udp {i}".encode(), "192.168.0.9")
    assert await first.save_status()
    async with rx.maker() as s:
        v = (await s.get(AppState, server.STATE_KEY)).value
    assert (v["received"], v["lost"], v["backlog"], v["stored"]) == (5, 3, 2, 0)
    assert v["loss"]["n"] == 3 and v["loss"]["why"] == server.FULL and v["at"] and v["pid"] == os.getpid()
    assert first._loss["n"] == 0  # bewaard

    # Na een herstart: het verlies van daarnet blijft staan en telt op.
    second = Receiver(rx.maker)
    for i in range(3):
        second.accept(f"<14>udp {i}".encode(), "192.168.0.9")
    assert await second.save_status()
    async with rx.maker() as s:
        v2 = (await s.get(AppState, server.STATE_KEY)).value
    assert v2["lost"] == 1 and v2["loss"]["n"] == 4 and v2["loss"]["since"] == v["loss"]["since"]
    items = {i["key"]: i for i in (await authed.get("/api/attention")).json()["items"]}
    assert items["syslog:verlies"]["title"] == "4 logregels niet bewaard"
    assert items["syslog:verlies"]["level"] == "warn" and "syslog" not in items
    # Geen push, alleen onder Aandacht en Gezondheid.
    assert await _titles(rx.maker) == []
    health = (await authed.get("/api/health")).json()["syslog"]
    assert health["ok"] is True and health["loss"]["n"] == 4 and health["lost"] == 1


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


async def test_start_without_database(receiver, monkeypatch, tmp_path):
    """De luisteraars gaan eerst open; zonder database stopt het proces niet, gokt het niet dat het geen TimescaleDB
    is, en wacht wat binnenkomt tot de database er is."""
    rx0, _ = receiver
    real, own = rx0.maker, None
    if not PG:
        # Hier werken de schrijver, het opstarten en de toestand tegelijk: dat kan niet op één gedeelde verbinding
        # (SQLite in het geheugen), wel op een bestand met een verbinding per sessie, zoals PostgreSQL.
        own = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'syslog.db'}")
        async with own.begin() as c:
            await c.run_sync(Base.metadata.create_all)
        real = async_sessionmaker(own, expire_on_commit=False)
    for k, v in (("RETRY_FIRST", 0.01), ("RETRY_MAX", 0.05), ("FLUSH_SECONDS", 0.05)):
        monkeypatch.setattr(server, k, v)
    dead = create_async_engine(DEAD)
    rx = Receiver(async_sessionmaker(dead))
    stop = asyncio.Event()
    port = _free_port()
    task = asyncio.create_task(server.serve(rx, "127.0.0.1", port, stop))
    try:
        for _ in range(100):
            try:
                _, w = await asyncio.open_connection("127.0.0.1", port)
                break
            except OSError:
                await asyncio.sleep(0.02)
        w.write(b"<14>h1 app: via tcp\n")
        await w.drain()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            u.sendto(b"<14>h2 app: via udp", ("127.0.0.1", port))
        await _until(lambda: rx.received == 2)
        await asyncio.sleep(0.2)
        assert not task.done() and rx.down_since is not None and rx.backlog() == 2
        # Niet gegokt (vroeger: True, en dan op TimescaleDB zelf opruimen). SQLite is nooit TimescaleDB: dat weet de
        # ontvanger zonder verbinding.
        assert rx.self_cleanup is (None if PG else True)

        rx.maker = real  # de database is er weer
        await _until(lambda: rx.stored == 2 and rx.self_cleanup is not None and rx.down_since is None)
        w.close()
    finally:
        stop.set()
        await asyncio.wait_for(task, 15)
        await dead.dispose()
    # Op TimescaleDB (de migraties-suite) ruimt het retentiebeleid op, anders de ontvanger zelf.
    assert rx.self_cleanup is not await _hypertable(real)
    assert await _count(real) == 2
    async with real() as s:
        v = (await s.get(AppState, server.STATE_KEY)).value
    assert v["stored"] == 2 and v["lost"] == 0 and v["last_error"]["until"]
    if own:
        await own.dispose()


async def _hypertable(maker) -> bool:
    if not PG:
        return False
    async with maker() as s:
        if not (await s.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))).scalar():
            return False
        return bool((await s.execute(text(
            "SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'log_entries'"))).scalar())


async def test_sigterm_writes_the_queue_before_stopping(tmp_path):
    """systemctl stop/restart (ook bij elke update) stuurt SIGTERM. Vroeger stierf het proces dan meteen, met wat nog
    in de wachtrij of de batch zat."""
    url = f"sqlite+aiosqlite:///{tmp_path / 'syslog.db'}"
    engine = create_async_engine(url)
    async with engine.begin() as c:
        await c.run_sync(Base.metadata.create_all)
    port = _free_port()
    env = {**os.environ, "HOMEPAGE_DATABASE_URL": url, "HOMEPAGE_SYSLOG_BIND": "127.0.0.1",
           "HOMEPAGE_SYSLOG_PORT": str(port)}
    maker = async_sessionmaker(engine)
    proc = await asyncio.create_subprocess_exec(sys.executable, "-m", "app.syslog.server", cwd=BACKEND, env=env,
                                                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.PIPE)
    try:
        # Helemaal opgestart: luistert, en heeft zijn eerste teken van leven in de database gezet.
        for _ in range(600):
            async with maker() as s:
                if await s.get(AppState, server.STATE_KEY):
                    break
            assert proc.returncode is None
            await asyncio.sleep(0.05)
        _, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"<14>h1 app: een\n<14>h1 app: twee\n<14>h1 app: drie\n")
        await w.drain()
        # Ontvangen, maar nog niet weggeschreven: de schrijver wacht tot FLUSH_SECONDS (1 s) op meer regels.
        await asyncio.sleep(0.4)
        proc.send_signal(signal.SIGTERM)
        _, err = await asyncio.wait_for(proc.communicate(), 30)
        w.close()
    finally:
        if proc.returncode is None:
            proc.kill()
            await proc.wait()
    assert proc.returncode == 0, err.decode()[-2000:]
    assert await _count(maker) == 3
    async with maker() as s:
        assert (await s.get(AppState, server.STATE_KEY)).value["stored"] == 3
    await engine.dispose()


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
