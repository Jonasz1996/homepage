"""Databaseverbindingen: het slot voor trage taken, geen transactie open tijdens SSH, time-outs en de pool."""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app import db as dbmod
from app.config import get_settings
from app.cron import scan
from app.db import delete_before, get_db, job_lock, make_engine, pool_max, timed_out
from app.health import scan as hw
from app.main import app
from app.models import AppState, CheckResult, LogEntry, SshHost
from app.monitoring import configs, healing, updates as upd
from app.monitoring.checks import HttpClients

from .conftest import TEST_DB
from .test_integrations import _group, _svc

PG = TEST_DB.startswith("postgresql")
needs_pg = pytest.mark.skipif(not PG, reason="advisory locks en time-outs bestaan alleen op PostgreSQL")


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _idle_in_transaction() -> int:
    """Hoeveel verbindingen naar deze database staan "idle in transaction" (alleen PostgreSQL)."""
    if not PG:
        return 0
    # Autocommit: de controles lopen soms tegelijk en mogen elkaar niet meetellen.
    probe = create_async_engine(TEST_DB, isolation_level="AUTOCOMMIT")
    try:
        async with probe.connect() as c:
            return (await c.execute(text(
                "SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() "
                "AND backend_type = 'client backend' AND state LIKE 'idle in transaction%'"))).scalar()
    finally:
        await probe.dispose()


# --- job_lock ------------------------------------------------------------------------------------------------

@needs_pg
async def test_job_lock_on_postgres(client):
    a1, s1 = await _db()
    a2, s2 = await _db()
    async with job_lock(s1, "proef") as ok:
        assert ok
        # Het slot staat los van de transactie van het werk: geen transactie geopend, en committen laat het staan.
        assert not s1.in_transaction()
        await s1.execute(select(AppState))
        await s1.commit()
        async with job_lock(s2, "proef") as other:
            assert other is False
        # Een ander slot is gewoon vrij.
        async with job_lock(s2, "iets-anders") as other:
            assert other
        # De verbinding met het slot is niet "idle in transaction" (autocommit).
        assert await _idle_in_transaction() == 0
    async with job_lock(s2, "proef") as ok:
        assert ok

    # Ook na een fout gaat het slot vrij.
    with pytest.raises(RuntimeError):
        async with job_lock(s1, "proef") as ok:
            assert ok
            raise RuntimeError("mislukt")
    async with job_lock(s2, "proef") as ok:
        assert ok

    # En als de taak afgebroken wordt (bv. de worker stopt).
    holding = asyncio.Event()

    async def hold():
        async with job_lock(s1, "proef"):
            holding.set()
            await asyncio.sleep(60)
    task = asyncio.create_task(hold())
    await holding.wait()
    async with job_lock(s2, "proef") as ok:
        assert ok is False
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    async with job_lock(s2, "proef") as ok:
        assert ok
    await a1.aclose()
    await a2.aclose()


def _locked(monkeypatch):
    """Het slot is bezet: op PostgreSQL echt (zie test hieronder), op SQLite nagebootst."""
    @asynccontextmanager
    async def busy(db, name):
        yield False
    for mod in (scan, hw, upd):
        monkeypatch.setattr(mod, "job_lock", busy)


async def _hosts(db) -> list[SshHost]:
    hosts = [SshHost(name=f"m{i}", host=f"10.0.0.{i}", host_key=f"ssh-ed25519 AAAA{i}", updates="host") for i in (1, 2)]
    db.add_all(hosts)
    await db.commit()
    return hosts


async def test_locked_jobs_return_previous_state(client, monkeypatch):
    agen, db = await _db()
    for key in ("cron", "health", "updates"):
        db.add(AppState(key=key, value={"vorige": key}))
    await db.commit()

    async def never(*a, **kw):
        raise AssertionError("mag niet scannen terwijl een andere ronde loopt")
    monkeypatch.setattr(scan, "collect", never)
    monkeypatch.setattr(hw, "collect", never)
    monkeypatch.setattr(upd, "collect", never)

    async def check():
        assert await scan.run_scan(db) == {"vorige": "cron"}
        assert await hw.run_health(db) == {"vorige": "health"}
        assert await upd.run_updates(db, HttpClients()) == {"vorige": "updates"}

    if PG:
        holder_gen, holder = await _db()
        async with job_lock(holder, "cron"), job_lock(holder, "health"), job_lock(holder, "updates"):
            await check()
        await holder_gen.aclose()
    else:
        _locked(monkeypatch)
        await check()
    await agen.aclose()


# --- geen transactie open tijdens SSH --------------------------------------------------------------------------

async def test_scans_release_the_connection_during_ssh(client, monkeypatch):
    agen, db = await _db()
    hosts = await _hosts(db)
    seen = []

    async def note(what):
        seen.append((what, db.in_transaction(), await _idle_in_transaction()))

    async def scan_host(h, login, skip):
        await note("cron")
        return [scan._machine(f"ssh:{h.id}", h.name, h)]

    async def probe_host(h, login):
        await note("gezondheid")
        return {"key": f"ssh:{h.id}", "name": h.name, "host_id": h.id, "host": h.host, "error": None,
                "virt": "none", "disks": [], "pools": []}

    async def from_ssh(h, login):
        await note("updates")
        return [upd.target(f"ssh:{h.id}", h.name, "host", None, [{"n": "openssl", "from": "1", "to": "2"}])]

    monkeypatch.setattr(scan, "scan_host", scan_host)
    monkeypatch.setattr(hw, "probe_host", probe_host)
    monkeypatch.setattr(upd, "from_ssh", from_ssh)

    results = {"cron": await scan.run_scan(db), "health": await hw.run_health(db),
               "updates": await upd.run_updates(db, HttpClients())}
    # Tijdens elke SSH-stap: de sessie zonder transactie, en nergens een verbinding "idle in transaction".
    assert sorted(w for w, *_ in seen) == ["cron", "cron", "gezondheid", "gezondheid", "updates", "updates"]
    assert all(not in_tx and idle == 0 for _, in_tx, idle in seen), seen
    assert [t["key"] for t in results["cron"]["targets"]] == [f"ssh:{h.id}" for h in hosts]
    assert len(results["health"]["hosts"]) == 2 and results["updates"]["targets"][0]["count"] == 1
    # Bewaard voor het slot vrijkwam: een andere sessie ziet de nieuwe stand meteen, zonder commit van de aanroeper.
    assert not db.in_transaction()
    other_gen, other = await _db()
    for key, value in results.items():
        assert (await other.get(AppState, key)).value["checked_at" if key != "cron" else "scanned_at"] == \
            value["checked_at" if key != "cron" else "scanned_at"]
    await other_gen.aclose()
    await agen.aclose()


async def test_config_copy_and_heal_test_without_open_transaction(authed, monkeypatch):
    agen, db = await _db()
    h = SshHost(name="nas", host="10.0.0.9", host_key="ssh-ed25519 AAAA")
    db.add(h)
    await db.commit()
    seen = []

    async def from_files(host, login, paths):
        seen.append(("config", db.in_transaction(), await _idle_in_transaction()))
        return [(f"file:{host.id}:{p}", f"{host.name}:{p}", "file", "inhoud\n") for p in paths]
    monkeypatch.setattr(configs, "from_files", from_files)
    cfg = {"opnsense": False, "npm": False, "pve": False, "files": [{"host_id": h.id, "path": "/etc/fstab"}]}
    items, errors = await configs.gather(db, HttpClients(), cfg)
    assert [i[1] for i in items] == ["nas:/etc/fstab"] and errors == []

    async def prepare(session, action, http):
        async def go():
            seen.append(("herstel", session.in_transaction(), await _idle_in_transaction()))
            return "herstart"

        async def probe():
            seen.append(("proef", session.in_transaction(), await _idle_in_transaction()))
            return [], None
        return healing.Prepared([], [], go, probe)
    monkeypatch.setattr(healing, "prepare", prepare)
    g = await _group(authed)
    sid = await _svc(authed, g, "", "http://a", name="A")
    from app.models import HealRule
    rule = HealRule(service_id=sid, enabled=True, after=3, max_per_hour=2, fired=[],
                    action={"kind": "ssh", "host_id": h.id, "op": "systemctl", "name": "nginx"})
    db.add(rule)
    await db.commit()
    assert await healing.test_rule(db, rule, HttpClients()) == "herstart"
    # De proef kijkt via SSH op de machine: ook dan geen transactie open.
    assert (await healing.plan_rule(db, rule, HttpClients()))["proef"] is True
    assert seen == [("config", False, 0), ("herstel", False, 0), ("proef", False, 0)]
    await agen.aclose()


# --- time-outs en pool ---------------------------------------------------------------------------------------

def test_pool_sizes_leave_room():
    s = get_settings()
    # Samen ruim onder max_connections 100: psql, pg_dump en de hersteltest moeten er nog bij kunnen.
    assert sum(pool_max(r) for r in ("api", "worker", "syslog")) <= 65
    assert pool_max("worker") == s.db_pool_worker and pool_max("syslog") == s.db_pool_syslog
    assert pool_max("api") == pool_max("iets") == s.db_pool_api
    e = make_engine("postgresql+asyncpg://homepage@/homepage", "syslog")
    assert e.pool.size() + e.pool._max_overflow == s.db_pool_syslog
    e = make_engine("postgresql+asyncpg://homepage@/homepage", "worker")
    assert (e.pool.size(), e.pool._max_overflow) == (20, 20)


async def test_databasefout_in_de_logs_zonder_de_waarden():
    """Een databasefout komt in de logs, en die gaan mee in de diagnose: zonder de waarden (een cronregel, een header
    of syslogtekst kan een wachtwoord bevatten)."""
    e = make_engine("postgresql+asyncpg://u:p@localhost/x")
    assert e.sync_engine.hide_parameters is True
    e = make_engine(TEST_DB)
    try:
        async with e.connect() as c:
            with pytest.raises(Exception) as err:
                await c.execute(text("SELECT :pw FROM bestaat_niet"), {"pw": "geheim-in-een-cronregel"})
    finally:
        await e.dispose()
    assert "bestaat_niet" in str(err.value) and "geheim-in-een-cronregel" not in str(err.value)


@needs_pg
async def test_statement_timeout_on_app_connections(monkeypatch):
    e = make_engine(TEST_DB, "worker")
    try:
        async with e.connect() as c:
            assert (await c.execute(text("SHOW statement_timeout"))).scalar() == "1min"
            assert (await c.execute(text("SHOW idle_in_transaction_session_timeout"))).scalar() == "15min"
    finally:
        await e.dispose()
    monkeypatch.setattr(get_settings(), "db_statement_timeout", 1)
    monkeypatch.setattr(get_settings(), "db_idle_in_transaction_timeout", 0)
    e = make_engine(TEST_DB)
    try:
        async with e.connect() as c:
            assert (await c.execute(text("SHOW statement_timeout"))).scalar() == "1s"
            assert (await c.execute(text("SHOW idle_in_transaction_session_timeout"))).scalar() == "0"
            # Een te trage query wordt afgebroken, en timed_out herkent dat.
            with pytest.raises(Exception) as err:
                await c.execute(text("SELECT pg_sleep(3)"))
            assert timed_out(err.value)
            await c.rollback()
            with pytest.raises(Exception) as err:
                await c.execute(text("SELECT 1/0"))
            assert not timed_out(err.value)
    finally:
        await e.dispose()


async def test_log_search_timeout_gives_clear_error(authed, monkeypatch):
    agen, db = await _db()
    db.add(LogEntry(ts=datetime.now(timezone.utc), host="nas", severity=3, msg="schijf vol"))
    await db.commit()
    assert len((await authed.get("/api/logs", params={"range": "30d", "q": "schijf"})).json()["items"]) == 1
    if PG:
        # Echt: een app-verbinding met statement_timeout 1 s, en een slot op de tabel zodat het zoeken blijft wachten.
        monkeypatch.setattr(get_settings(), "db_statement_timeout", 1)
        slow = make_engine(TEST_DB)
        maker = async_sessionmaker(slow, expire_on_commit=False)
        normal = app.dependency_overrides[get_db]

        async def _slow_db():
            async with maker() as s:
                yield s
        app.dependency_overrides[get_db] = _slow_db
        try:
            async with db.bind.connect() as locker:
                await locker.execute(text("LOCK TABLE log_entries IN ACCESS EXCLUSIVE MODE"))
                r = await authed.get("/api/logs", params={"range": "30d", "q": "schijf"})
                h = await authed.get("/api/logs/histogram", params={"range": "30d", "q": "schijf"})
                await locker.rollback()
        finally:
            app.dependency_overrides[get_db] = normal
            await slow.dispose()
    else:
        # SQLite kent geen statement_timeout: de fout van de driver nabootsen zoals asyncpg ze geeft.
        dbapi = db.bind.dialect.loaded_dbapi

        def cancel(conn, cursor, statement, params, context, executemany):
            if "FROM log_entries" in statement:
                e = dbapi.OperationalError("canceling statement due to statement timeout")
                e.sqlstate = "57014"
                raise e
        event.listen(db.bind.sync_engine, "before_cursor_execute", cancel)
        try:
            r = await authed.get("/api/logs", params={"range": "30d", "q": "schijf"})
            h = await authed.get("/api/logs/histogram", params={"range": "30d", "q": "schijf"})
        finally:
            event.remove(db.bind.sync_engine, "before_cursor_execute", cancel)
    for resp in (r, h):
        assert resp.status_code == 503, resp.text
        detail = resp.json()["detail"]
        assert detail.startswith("Zoeken duurde te lang; kies een kortere periode, één machine of een niveau")
        # Alleen filters die de logviewer echt heeft, in zijn eigen woorden (geen app-filter, geen "host").
        assert "app" not in detail and "host" not in detail
    # Daarna werkt zoeken gewoon weer.
    assert (await authed.get("/api/logs", params={"range": "30d", "q": "schijf"})).status_code == 200
    await agen.aclose()


# --- grote DELETE's in stukken -------------------------------------------------------------------------------

async def test_delete_before_in_steps(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "", "http://a", name="A")
    agen, db = await _db()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for days in (400, 399.5, 380, 370, 10):
        db.add(CheckResult(service_id=sid, ts=now - timedelta(days=days), ok=True))
    await db.commit()
    deletes = []

    def count(conn, cursor, statement, params, context, executemany):
        if statement.lstrip().upper().startswith("DELETE"):
            deletes.append(statement)
    event.listen(db.bind.sync_engine, "before_cursor_execute", count)
    try:
        n = await delete_before(db, CheckResult.ts, now - timedelta(days=365), timedelta(days=1))
    finally:
        event.remove(db.bind.sync_engine, "before_cursor_execute", count)
    # 400 en 399,5 dagen in één stap, dan 380 en 370 elk apart; de lege dagen ertussen worden overgeslagen.
    assert n == 4 and len(deletes) == 3
    # Elke stap gecommit: een andere sessie ziet het al.
    other_gen, other = await _db()
    assert len((await other.execute(select(CheckResult.ts))).scalars().all()) == 1
    await other_gen.aclose()
    assert await delete_before(db, CheckResult.ts, now - timedelta(days=365), timedelta(days=1)) == 0
    await agen.aclose()


def test_alembic_uses_its_own_engine():
    """Migraties lopen zonder statement_timeout: alembic/env.py maakt een eigen engine, niet die van app.db."""
    from pathlib import Path
    env = (Path(dbmod.__file__).resolve().parent.parent / "alembic" / "env.py").read_text()
    assert "create_async_engine(get_settings().database_url)" in env and "app.db" not in env


async def test_selfcheck_copies_offsite_without_open_transaction(client, tmp_path, monkeypatch):
    """De kopie buiten de container kan minuten duren: geen transactie open, ook niet als er al een melding klaarstaat
    (geen back-up, schijf vol) of de schijfbewaker bezig is."""
    from app.health import selfcheck as sc
    s = get_settings()
    monkeypatch.setattr(s, "backup_dir", tmp_path / "leeg")
    monkeypatch.setattr(s, "offsite_dir", tmp_path)
    monkeypatch.setattr(sc, "disk", lambda p: {"path": str(p), "total": 100, "used": 80, "free": 20, "pct": 80.0})
    seen = []

    def copy(src, dst, blob, now):
        seen.append(asyncio.run_coroutine_threadsafe(_idle_in_transaction(), loop).result(10))
        return {"copied": [], "latest": None, "count": 0, "key": False}
    loop = asyncio.get_running_loop()
    monkeypatch.setattr(sc, "offsite_copy", copy)
    agen, db = await _db()
    db.add(AppState(key=sc.GUARD_KEY, value={"since": datetime.now(timezone.utc).isoformat()}))
    await db.commit()
    real_copy = asyncio.to_thread

    async def to_thread(fn, *a):
        # Een klaargezette melding begint wel een transactie in de sessie, maar zonder verbinding: dat mag.
        tx = db.sync_session.get_transaction()
        seen.append(bool(tx and tx._connections))
        return await real_copy(fn, *a)
    monkeypatch.setattr(sc.asyncio, "to_thread", to_thread)
    v = await sc.run_selfcheck(db, offsite_on=True)
    await db.commit()
    assert v["stale"] and v["offsite"]["count"] == 0
    assert seen == [False, 0]
    await agen.aclose()
