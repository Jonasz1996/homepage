"""Productie draait op TimescaleDB: hypertables met compressie. Deze tests draaien alleen met een schema uit de
migraties (HOMEPAGE_TEST_SCHEMA=migraties) op PostgreSQL met TimescaleDB, zoals de CI doet. Ze zetten oude
metingen in gecomprimeerde chunks en kijken of lezen, bijschrijven en verwijderen daar nog werkt."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.db import get_db
from app.main import app
from app.models import CheckResult, LogEntry, Metric, Reading

from .conftest import MIGRATED

pytestmark = pytest.mark.skipif(not MIGRATED, reason="alleen met HOMEPAGE_TEST_SCHEMA=migraties op PostgreSQL")

HYPERTABLES = {"check_results", "log_entries", "metrics", "readings"}


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
    for t in HYPERTABLES - {"readings"}:
        assert ("Compression Policy", t) in jobs


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
    for t in HYPERTABLES - {"readings"}:  # readings heeft geen compressie, alleen een bewaartermijn
        assert await _compress(db, t) > 0, t

    # Lezen over gecomprimeerde chunks heen.
    r = await authed.get(f"/api/services/{sid}/history", params={"range": "30d"})
    assert r.status_code == 200, r.text
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
    assert (await left("metrics", sid)).scalar() == 0
    assert (await left("check_results", keep)).scalar() == 30
    await agen.aclose()
