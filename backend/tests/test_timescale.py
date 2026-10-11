"""Productie draait op TimescaleDB: hypertables met compressie. Deze tests draaien alleen met een schema uit de
migraties (HOMEPAGE_TEST_SCHEMA=migraties) op PostgreSQL met TimescaleDB, zoals de CI doet. Ze zetten oude
metingen in gecomprimeerde chunks en kijken of lezen, bijschrijven en verwijderen daar nog werkt."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app.config import get_settings
from app.db import get_db
from app.health.scan import KEEP_READINGS
from app.main import app
from app.models import CheckHourly, CheckResult, LogEntry, Metric, Reading
from app.monitoring import engine, rollup
from app.routers import monitoring

from .conftest import MIGRATED, alembic

pytestmark = pytest.mark.skipif(not MIGRATED, reason="alleen met HOMEPAGE_TEST_SCHEMA=migraties op PostgreSQL")

HYPERTABLES = {"check_results", "check_hourly", "log_entries", "metrics", "readings"}


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _timescale(db) -> bool:
    return bool((await db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))).scalar())


async def _compress(db, table: str) -> int:
    """Alle chunks ouder dan een dag comprimeren, zoals het compressiebeleid na 3 of 7 dagen doet."""
    rows = (await db.execute(text(
        f"SELECT compress_chunk(c, if_not_compressed => true) FROM show_chunks('{table}', older_than => INTERVAL '1 day') c"
    ))).all()
    await db.commit()
    return len(rows)


async def test_hypertables_en_beleid(authed):
    agen, db = await _db()
    if not await _timescale(db):
        pytest.skip("TimescaleDB niet beschikbaar")
    hyper = {r[0] for r in (await db.execute(text("SELECT hypertable_name FROM timescaledb_information.hypertables")))}
    assert hyper == HYPERTABLES
    jobs = {(r[0].split(" [")[0], r[1]) for r in (await db.execute(text(
        "SELECT application_name, hypertable_name FROM timescaledb_information.jobs WHERE hypertable_name IS NOT NULL")))}
    for t in HYPERTABLES:
        assert ("Retention Policy", t) in jobs
    for t in HYPERTABLES - {"readings"}:  # nieuwere TimescaleDB noemt de compressietaak "Columnstore Policy"
        assert ("Compression Policy", t) in jobs or ("Columnstore Policy", t) in jobs, t


async def test_bewaartermijnen_zoals_zonder_timescaledb(authed):
    """Met en zonder TimescaleDB even lang bewaard: het bewaarbeleid van de migraties en wat de worker zelf opruimt
    (engine.cleanup, de syslog-ontvanger, health/scan) zeggen hetzelfde."""
    agen, db = await _db()
    if not await _timescale(db):
        pytest.skip("TimescaleDB niet beschikbaar")
    keep = dict((await db.execute(text(
        "SELECT hypertable_name, (config->>'drop_after')::interval FROM timescaledb_information.jobs "
        "WHERE proc_name = 'policy_retention'"))).all())
    assert keep == {
        "check_results": timedelta(days=engine.KEEP_CHECKS_DAYS),
        "check_hourly": timedelta(days=engine.KEEP_HOURLY_DAYS),
        "metrics": timedelta(days=engine.KEEP_METRICS_DAYS),
        "log_entries": timedelta(days=get_settings().syslog_keep_days),
        "readings": KEEP_READINGS,
    }
    assert engine.KEEP_CHECKS_DAYS == 90 and engine.KEEP_HOURLY_DAYS == 400
    await agen.aclose()


async def test_gecomprimeerde_metingen(authed):
    agen, db = await _db()
    if not await _timescale(db):
        pytest.skip("TimescaleDB niet beschikbaar")
    page = (await authed.post("/api/pages", json={"name": "Thuis"})).json()["id"]
    g = (await authed.post("/api/groups", json={"page_id": page, "name": "Infra"})).json()["id"]
    sid = (await authed.post("/api/services", json={"group_id": g, "name": "pve50", "url": "https://192.168.0.50:8006",
                                                    "type": "link"})).json()["id"]
    keep = (await authed.post("/api/services", json={"group_id": g, "name": "nas", "url": "https://192.168.0.60",
                                                     "type": "link"})).json()["id"]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for d in range(30):
        ts = now - timedelta(days=d, minutes=1)
        for s in (sid, keep):
            db.add(CheckResult(service_id=s, ts=ts, ok=d % 7 != 3, latency_ms=10 + d, maintenance=False))
            db.add(Metric(service_id=s, kind="storage", name="pve50/local", ts=ts, disk=50 + d, disk_total=1000))
        db.add(Reading(target="pve50", sensor="cpu", ts=ts, value=40 + d))
        db.add(LogEntry(ts=ts, host="pve50", app="sshd", severity=6, msg=f"regel {d}"))
    await db.commit()
    # readings heeft geen compressie, alleen een bewaartermijn; check_hourly vult de worker pas hieronder.
    for t in HYPERTABLES - {"readings", "check_hourly"}:
        assert await _compress(db, t) > 0, t

    # Lezen over gecomprimeerde chunks heen, en optellen per uur: dezelfde cijfers.
    r = await authed.get(f"/api/services/{sid}/history", params={"range": "30d"})
    assert r.status_code == 200, r.text
    raw = await monitoring._series(db, sid, now - timedelta(days=30), 4 * 3600)
    assert await rollup.roll_up(db) == 58
    # Ook de uurtotalen gecomprimeerd (hier allemaal, ook het lopende stuk), en dan opnieuw optellen alsof de
    # watermark weg was: bijschrijven in gecomprimeerde chunks.
    assert (await db.execute(text(
        "SELECT count(compress_chunk(c, if_not_compressed => true)) FROM show_chunks('check_hourly') c"))).scalar() > 0
    await db.commit()
    hourly = await monitoring._series(db, sid, now - timedelta(days=30), 4 * 3600)
    assert hourly == raw and hourly["checks"] == 30
    await db.execute(text("DELETE FROM app_state WHERE key = :k"), {"k": rollup.KEY})
    await db.commit()
    assert await rollup.roll_up(db) == 58
    assert await monitoring._series(db, sid, now - timedelta(days=30), 4 * 3600) == raw
    assert (await authed.get("/api/capacity")).status_code == 200
    logs = (await authed.get("/api/logs", params={"range": "30d", "limit": 100})).json()["items"]
    assert len(logs) == 30
    assert (await authed.get("/api/logs/histogram", params={"range": "30d"})).status_code == 200

    # Een late meting in een oude, gecomprimeerde chunk.
    db.add(CheckResult(service_id=sid, ts=now - timedelta(days=20, minutes=30), ok=True, latency_ms=5, maintenance=False))
    await db.commit()

    # Een service verwijderen haalt ook zijn metingen uit de gecomprimeerde chunks (ON DELETE CASCADE).
    r = await authed.delete(f"/api/services/{sid}")
    assert r.status_code in (200, 204), r.text
    left = lambda tbl, s: db.execute(text(f"SELECT count(*) FROM {tbl} WHERE service_id = :s"), {"s": s})  # noqa: E731
    assert (await left("check_results", sid)).scalar() == 0
    assert (await left("check_hourly", sid)).scalar() == 0
    assert (await left("metrics", sid)).scalar() == 0
    assert (await left("check_results", keep)).scalar() == 30
    assert (await left("check_hourly", keep)).scalar() == 29  # het lopende uur telt de worker pas later op
    await agen.aclose()


async def test_migratie_telt_bestaande_checks_op(authed):
    """Migratie 0025 telt de checks die er al zijn per uur op (ook in gecomprimeerde chunks, ook van meer dan 90
    dagen geleden: die wist het nieuwe bewaarbeleid) en zet de watermark: dezelfde uurtotalen als de worker maakt."""
    agen, db = await _db()
    page = (await authed.post("/api/pages", json={"name": "Thuis"})).json()["id"]
    g = (await authed.post("/api/groups", json={"page_id": page, "name": "Infra"})).json()["id"]
    sid = (await authed.post("/api/services", json={"group_id": g, "name": "nas", "url": "https://192.168.0.60",
                                                    "type": "link"})).json()["id"]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    for i in range(0, 200 * 24, 5):  # 200 dagen, om de 5 uur een paar checks
        ts = now - timedelta(hours=i, minutes=7)
        db.add(CheckResult(service_id=sid, ts=ts, ok=i % 3 != 0, latency_ms=None if i % 4 == 0 else 5.0 + i % 9,
                           maintenance=i % 11 == 0))
        db.add(CheckResult(service_id=sid, ts=ts + timedelta(minutes=2), ok=True, latency_ms=7.5, maintenance=None))
    await db.commit()
    if await _timescale(db):
        assert await _compress(db, "check_results") > 0
    # Wat de worker ervan maakt, als vergelijking.
    await rollup.roll_up(db, now)
    want = {(r.service_id, r.hour): r for r in (await db.execute(select(CheckHourly))).scalars()}
    assert sum(r.checks for r in want.values()) == (await db.execute(text(
        "SELECT count(*) FROM check_results WHERE maintenance IS NOT TRUE AND ts < :t"),
        {"t": rollup.floor_hour(now - rollup.LATE)})).scalar()
    engine_ = db.bind
    await agen.aclose()
    # Geen verbindingen die nog iets van de oude tabel weten (asyncpg onthoudt voorbereide queries).
    await engine_.dispose()

    # Zonder de tabel terug naar voor 0025, dan weer op: de migratie telt alles op.
    alembic("downgrade", "0025-1")
    alembic("upgrade", "head")
    agen, db = await _db()
    until = await rollup.watermark(db)
    assert until is not None and until >= rollup.floor_hour(now)
    got = {(r.service_id, r.hour): r for r in (await db.execute(select(CheckHourly))).scalars()}
    assert got.keys() >= want.keys() and min(h for _, h in got) < now - timedelta(days=150)
    for k, w in want.items():
        r = got[k]
        assert (r.checks, r.ok, r.latency_n, r.maint_latency_n) == (w.checks, w.ok, w.latency_n, w.maint_latency_n), k
        for f in ("latency_sum", "latency_min", "latency_max", "maint_latency_sum", "maint_latency_min",
                  "maint_latency_max"):
            assert getattr(r, f) == pytest.approx(getattr(w, f)), (k, f)
    if await _timescale(db):
        drop = (await db.execute(text(
            "SELECT config->>'drop_after' FROM timescaledb_information.jobs "
            "WHERE proc_name = 'policy_retention' AND hypertable_name = 'check_results'"))).scalar()
        assert drop == "90 days"
    await agen.aclose()
