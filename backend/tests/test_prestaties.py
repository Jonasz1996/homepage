import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import event, select

from app import main
from app.db import ensure_state, get_db, job_lock
from app.main import app
from app.models import AppState, CheckResult, Device, Metric, Notification, UpdateRun
from app.monitoring import devices, engine, network, worker as worker_mod
from app.monitoring.checks import HttpClients
from app.monitoring.engine import cleanup, housekeeping
from app.monitoring.upgrade import mark_interrupted
from app.monitoring.worker import Worker

from .test_integrations import _group, _svc


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


def _maker():
    @asynccontextmanager
    async def maker():
        agen, db = await _db()
        try:
            yield db
        finally:
            await agen.aclose()
    return maker


# --- worker: geen overlap en losse deelstappen ------------------------------------------------------------

async def test_worker_skips_job_that_is_still_running():
    w = Worker(_maker())
    gate = asyncio.Event()
    starts = []

    async def slow():
        starts.append(1)
        await gate.wait()

    assert w.job("cron", slow)
    await asyncio.sleep(0)
    assert not w.job("cron", slow)  # vorige ronde loopt nog
    assert w.job("health:hardware", slow)  # andere naam: mag wel
    gate.set()
    await asyncio.sleep(0.01)
    assert w.job("cron", slow)  # klaar: volgende ronde mag
    await asyncio.sleep(0.01)
    assert len(starts) == 3


async def test_worker_step_failure_does_not_skip_the_rest(authed, monkeypatch):
    calls = []

    async def broken(db, http):
        db.add(AppState(key="half", value={}))
        raise RuntimeError("Proxmox stuk")

    async def power(db, http):
        calls.append("power")
        db.add(AppState(key="power", value={"ok": True}))

    async def forecasts(db):
        calls.append("forecasts")

    monkeypatch.setattr(worker_mod, "sample", broken)
    monkeypatch.setattr(worker_mod, "sample_power", power)
    monkeypatch.setattr(worker_mod, "check_forecasts", forecasts)
    await Worker(_maker()).capacity()
    assert calls == ["power", "forecasts"]
    agen, db = await _db()
    assert await db.get(AppState, "power") is not None  # bewaard
    assert await db.get(AppState, "half") is None  # alleen de mislukte stap teruggedraaid
    await agen.aclose()


async def test_sample_power_survives_broken_integration(authed, monkeypatch):
    g = await _group(authed)
    bad = await _svc(authed, g, "homeassistant", "http://ha1", name="HA kapot")
    good = await _svc(authed, g, "homeassistant", "http://ha2", name="HA")

    class Fake:
        def mapping(self):
            return [("pve50", "sensor.pve50", None)]

        async def state(self, entity):
            return 42.0, "W"

    def build(svc, clients):
        if svc.id == bad:
            raise ValueError("kapotte configuratie")
        return Fake()

    monkeypatch.setattr(network, "build", build)
    agen, db = await _db()
    assert await network.sample_power(db, HttpClients()) == 1
    await db.commit()
    rows = (await db.execute(select(Metric.service_id, Metric.watts))).all()
    assert rows == [(good, 42.0)]
    await agen.aclose()


# --- apparaten: één query voor de bekende apparaten ----------------------------------------------------------

async def test_devices_refresh_loads_known_devices_once(authed, monkeypatch):
    g = await _group(authed)
    await _svc(authed, g, "opnsense", "https://192.168.0.1", name="OPNsense")
    seen = [{"mac": f"aa:bb:cc:00:00:{i:02x}", "ip": f"192.168.0.{i}", "vendor": "x", "hostname": f"h{i}"}
            for i in range(1, 9)]

    class Fake:
        async def neighbours(self):
            return list(seen)

    monkeypatch.setattr(devices, "build", lambda svc, http: Fake())
    agen, db = await _db()
    v = await devices.refresh(db, HttpClients())
    await db.commit()
    assert v["seen"] == 8 and v["new"] == 0
    await db.close()  # lege identity map: anders komt db.get() niet eens bij de database

    queries = []
    eng = db.bind.sync_engine

    def count(conn, cursor, statement, *a):
        if "FROM devices" in statement:
            queries.append(statement)
    event.listen(eng, "before_cursor_execute", count)
    try:
        seen.append({"mac": "de:ad:be:ef:00:01", "ip": "192.168.0.77", "vendor": "Espressif", "hostname": None})
        v = await devices.refresh(db, HttpClients())
        await db.commit()
    finally:
        event.remove(eng, "before_cursor_execute", count)
    assert v["new"] == 1 and len(queries) == 1
    assert len((await db.execute(select(Device))).scalars().all()) == 9
    await agen.aclose()


# --- opruimen ----------------------------------------------------------------------------------------------

async def test_retention_and_pruning(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "", "http://a", name="A")
    now = datetime.now(timezone.utc)
    agen, db = await _db()
    for days in (200, 400):
        db.add(CheckResult(service_id=sid, ts=now - timedelta(days=days), ok=True))
        db.add(Metric(service_id=sid, kind="power", name=f"m{days}", ts=now - timedelta(days=days), watts=1.0))
    db.add(Notification(title="ongelezen, oud", ts=now - timedelta(days=200)))
    db.add(Notification(title="ongelezen, recent", ts=now - timedelta(days=100)))
    db.add(UpdateRun(target="ssh:1", target_name="oud klaar", status="ok", created_at=now - timedelta(days=400)))
    db.add(UpdateRun(target="ssh:2", target_name="oud bezig", status="installeren", created_at=now - timedelta(days=400)))
    db.add(UpdateRun(target="ssh:3", target_name="recent", status="fout", created_at=now - timedelta(days=10)))
    await db.commit()
    await cleanup(db)
    await housekeeping(db)
    await db.commit()
    # Checks een jaar, metingen een half jaar.
    assert len((await db.execute(select(CheckResult))).scalars().all()) == 1
    assert (await db.execute(select(Metric.name))).scalars().all() == []
    assert engine.KEEP_CHECKS_DAYS == 365 and engine.KEEP_METRICS_DAYS == 180
    titles = (await db.execute(select(Notification.title))).scalars().all()
    assert "ongelezen, recent" in titles and "ongelezen, oud" not in titles
    assert sorted((await db.execute(select(UpdateRun.target_name))).scalars().all()) == ["oud bezig", "recent"]
    await agen.aclose()


# --- onderbroken update-runs ---------------------------------------------------------------------------------

async def test_interrupted_update_runs_marked_on_startup(authed, monkeypatch):
    agen, db = await _db()
    db.add(UpdateRun(target="ssh:1", target_name="a", status="installeren", trigger="manueel"))
    db.add(UpdateRun(target="ssh:2", target_name="b", status="terugdraaien", trigger="manueel"))
    db.add(UpdateRun(target="ssh:3", target_name="c", status="installeren", trigger="auto"))
    db.add(UpdateRun(target="ssh:4", target_name="d", status="ok", trigger="manueel"))
    await db.commit()

    class Maker:  # get_maker() geeft een sessionmaker terug
        def __call__(self):
            return _maker()()

    monkeypatch.setattr(main, "get_maker", lambda: Maker())
    await main._startup()  # de API: alleen manuele runs
    await db.close()
    runs = {r.target_name: r for r in (await db.execute(select(UpdateRun))).scalars()}
    assert runs["a"].status == "fout" and runs["a"].error == "onderbroken door herstart" and runs["a"].finished_at
    assert runs["b"].status == "terugdraaien_mislukt"
    assert runs["c"].status == "installeren"  # van de worker
    assert runs["d"].status == "ok" and runs["d"].error is None
    assert await mark_interrupted(db, ("auto",)) == 1
    await db.commit()
    assert (await db.get(UpdateRun, runs["c"].id)).status == "fout"
    await agen.aclose()


# --- hulpjes voor gelijktijdigheid ---------------------------------------------------------------------------

async def test_ensure_state_and_job_lock(authed):
    agen, db = await _db()
    assert await job_lock(db, "cron")  # SQLite: altijd toegelaten
    st = await ensure_state(db, "net_gw:1")
    st.value = {"x": 1}
    await db.commit()
    assert (await ensure_state(db, "net_gw:1")).value == {"x": 1}
    assert (await ensure_state(db, "nieuw", {"a": 2})).value == {"a": 2}
    await db.commit()
    await agen.aclose()


async def test_run_check_has_overall_timeout(monkeypatch):
    from app.monitoring import checks

    async def hang(*a, **kw):
        await asyncio.sleep(10)

    monkeypatch.setattr(checks, "check_tcp", hang)
    monkeypatch.setattr(checks, "CHECK_TIMEOUT", 0.05)
    out = await checks.run_check({"type": "tcp", "target": "x:1"}, None)
    assert not out.ok and out.error == "Time-out"

