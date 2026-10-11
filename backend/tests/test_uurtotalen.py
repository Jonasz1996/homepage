"""Uurtotalen van de checks (monitoring/rollup.py): de grafiek, de uptime over 7 dagen tot een jaar en het
weekrapport lezen de hele uren uit check_hourly. De cijfers moeten dezelfde blijven als uit de losse checks: dat
rekenen we hier na zoals het vroeger ging (alles uit check_results), op SQLite en PostgreSQL."""

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import Integer, and_, case, cast, func, insert, select

from app.models import AppState, CheckHourly, CheckResult
from app.monitoring import engine, rollup
from app.monitoring.engine import cleanup
from app.monitoring.report import build_report
from app.monitoring.rollup import NOT_MAINT
from app.routers import monitoring

from .conftest import BACKEND
from .test_kuma_vervangen import _db, _group, _svc

DAYS = 40
STEP = timedelta(minutes=10)
SPANS = {"7d": (timedelta(days=7), 3600), "30d": (timedelta(days=30), 4 * 3600), "1y": (timedelta(days=365), 86400)}


def _row(sid: int, k: int, i: int, now: datetime) -> dict:
    """Om de 10 minuten een check: mislukte, zonder latency, tijdens onderhoud (ook uren met alleen onderhoud) en
    zonder onderhoudsvlag (NULL, zoals rijen van voor die kolom bestond)."""
    maint = True if i % 23 == 0 or 500 <= i < 548 or (k and 3000 <= i < 3048) else None if i % 29 == 0 else False
    ok = not (i % 17 == 0 or (k == 0 and 2000 <= i < 2012) or (maint and i % 3 == 0))
    latency = None if i % 13 == 0 or (not ok and i % 2 == 0) else 3 + k + (i % 40) * 0.5
    return {"service_id": sid, "ts": now - timedelta(minutes=1) - i * STEP, "ok": ok, "latency_ms": latency,
            "maintenance": maint}


async def _seed(authed, now: datetime) -> tuple[list[int], object, object]:
    g = await _group(authed)
    sids = [await _svc(authed, g, "alfa"), await _svc(authed, g, "beta")]
    agen, db = await _db()
    await db.execute(insert(CheckResult), [_row(sid, k, i, now) for k, sid in enumerate(sids)
                                           for i in range(DAYS * 144)])
    await db.commit()
    return sids, agen, db


# --- zoals het vroeger rekende: alles uit de losse checks -----------------------------------------------------------

async def _old_series(db, sid: int, start: datetime, size: int) -> dict:
    b = rollup.bucket(db, CheckResult.ts, size).label("b")
    rows = (await db.execute(
        select(b, func.avg(CheckResult.latency_ms), func.min(CheckResult.latency_ms), func.max(CheckResult.latency_ms),
               func.sum(case((and_(CheckResult.ok, NOT_MAINT), 1), else_=0)), func.sum(case((NOT_MAINT, 1), else_=0)))
        .where(CheckResult.service_id == sid, CheckResult.ts >= start).group_by(b).order_by(b))).all()
    ok, n = sum(r[4] or 0 for r in rows), sum(r[5] or 0 for r in rows)
    return {"uptime": ok / n if n else None, "checks": n,
            "points": [{"t": datetime.fromtimestamp(int(x) * size, timezone.utc), "avg": avg, "min": lo, "max": hi,
                        "up": o / c if c else None} for x, avg, lo, hi, o, c in rows]}


async def _old_uptime(db, sid: int, start: datetime) -> float | None:
    ok, n = (await db.execute(select(func.sum(case((and_(CheckResult.ok, NOT_MAINT), 1), else_=0)),
                                     func.sum(case((NOT_MAINT, 1), else_=0)))
                              .where(CheckResult.service_id == sid, CheckResult.ts >= start))).one()
    return ok / n if n else None


async def _old_report(db, start: datetime, end: datetime) -> dict:
    rows = (await db.execute(
        select(CheckResult.service_id, func.count(), func.sum(cast(CheckResult.ok, Integer)),
               func.avg(CheckResult.latency_ms), func.max(CheckResult.latency_ms))
        .where(CheckResult.ts >= start, CheckResult.ts < end, CheckResult.maintenance.is_not(True))
        .group_by(CheckResult.service_id))).all()
    return {sid: {"checks": n, "uptime": round(int(ok) / n * 100, 3), "avg_ms": round(avg, 1) if avg is not None else None,
                  "max_ms": round(mx, 1) if mx is not None else None} for sid, n, ok, avg, mx in rows}


def _same(new: dict, old: dict) -> None:
    assert (new["uptime"], new["checks"]) == (old["uptime"], old["checks"])
    assert len(new["points"]) == len(old["points"])
    for p, q in zip(new["points"], old["points"]):
        assert (p["t"], p["up"], p["min"], p["max"]) == (q["t"], q["up"], q["min"], q["max"]), p["t"]
        assert p["avg"] == (None if q["avg"] is None else pytest.approx(q["avg"])), p["t"]


async def _compare(db, sids: list[int], now: datetime) -> None:
    for sid in sids:
        for span, size in SPANS.values():
            for start in (now - span, now - span + timedelta(minutes=37)):
                _same(await monitoring._series(db, sid, start, size), await _old_series(db, sid, start, size))
        monitoring._uptime_all_cache.clear()
        up = await monitoring._uptime_all(db, sid, now)
        for name, span in monitoring.UPTIME_ALL.items():
            assert up[name] == await _old_uptime(db, sid, now - span), name
    for start, end in ((now - timedelta(days=7), now),
                       (now - timedelta(days=20, minutes=17), now - timedelta(days=3, minutes=-5)),
                       (now - timedelta(days=90), now - timedelta(hours=2))):
        report = {r["service_id"]: {k: r[k] for k in ("checks", "uptime", "avg_ms", "max_ms")}
                  for r in (await build_report(db, start, end))["services"]}
        assert report == await _old_report(db, start, end)


async def test_zelfde_cijfers_uit_losse_checks_en_uurtotalen(authed):
    now = datetime.now(timezone.utc)
    sids, agen, db = await _seed(authed, now)
    # Nog niets opgeteld: alles uit de losse checks.
    assert await rollup.watermark(db) is None
    await _compare(db, sids, now)
    # Half opgeteld (de worker stond drie dagen stil): de rest uit de losse checks.
    assert await rollup.roll_up(db, now - timedelta(days=3)) > 0
    assert await rollup.watermark(db) == rollup.floor_hour(now - timedelta(days=3) - rollup.LATE)
    await _compare(db, sids, now)
    # Helemaal bij.
    await rollup.roll_up(db, now)
    assert await rollup.watermark(db) == rollup.floor_hour(now - rollup.LATE)
    await _compare(db, sids, now)
    # Ook de uren zonder losse checks meer (na 90 dagen weg): de uurtotalen blijven tellen, en de cijfers van
    # daarvoor kloppen nog. Hier: alles wat opgeteld is, weg uit de losse checks.
    start = rollup.ceil_hour(now - timedelta(days=30))
    before = {sid: await monitoring._series(db, sid, start, 4 * 3600) for sid in sids}
    await db.execute(CheckResult.__table__.delete().where(CheckResult.ts < rollup.floor_hour(now - rollup.LATE)))
    await db.commit()
    for sid in sids:
        _same(await monitoring._series(db, sid, start, 4 * 3600), before[sid])
    await agen.aclose()


async def test_de_api_geeft_hetzelfde_voor_en_na_het_optellen(authed, monkeypatch):
    now = datetime.now(timezone.utc)
    sids, agen, db = await _seed(authed, now)

    class Clock(datetime):  # de klok van de API stil: anders schuift het begin van elke periode mee
        @classmethod
        def now(cls, tz=None):
            return now

    monkeypatch.setattr(monitoring, "datetime", Clock)

    async def get(sid, range_):
        monitoring._uptime_all_cache.clear()
        r = await authed.get(f"/api/services/{sid}/history", params={"range": range_})
        assert r.status_code == 200, r.text
        return r.json()

    before = {(sid, r): await get(sid, r) for sid in sids for r in ("1h", "24h", "7d", "30d", "1y")}
    assert all(h["checks"] and h["points"] for h in before.values())
    await rollup.roll_up(db)
    for (sid, r), old in before.items():
        assert await get(sid, r) == old, r
    report = (await authed.get("/api/report", params={"days": 30})).json()
    assert {s["name"] for s in report["services"]} == {"alfa", "beta"}
    await agen.aclose()


async def _hourly(db) -> list[tuple]:
    h = CheckHourly
    rows = (await db.execute(select(h.service_id, h.hour, h.checks, h.ok, h.latency_n, h.latency_sum, h.latency_max,
                                    h.maint_latency_n))).all()
    return sorted((sid, rollup._aware(hour), *rest) for sid, hour, *rest in rows)


async def test_optellen_is_herhaalbaar_en_telt_late_checks_mee(authed):
    now = datetime.now(timezone.utc)
    sids, agen, db = await _seed(authed, now)
    n = await rollup.roll_up(db, now)
    first = await _hourly(db)
    assert len(first) == n and await rollup.roll_up(db, now) > 0
    assert await _hourly(db) == first
    end = rollup.floor_hour(now - rollup.LATE)
    raw = (await db.execute(select(func.count()).where(CheckResult.ts < end, NOT_MAINT))).scalar()
    assert sum(r[2] for r in first) == raw

    # Een check die later binnenkomt in een uur dat al opgeteld is (een push-signaal na een herstart): de volgende
    # ronde telt hem mee.
    late = now - timedelta(minutes=90)
    assert rollup.floor_hour(late) < await rollup.watermark(db)
    db.add(CheckResult(service_id=sids[0], ts=late + timedelta(seconds=7), ok=False, latency_ms=99.0, maintenance=False))
    await db.commit()
    await rollup.roll_up(db, now)
    key = (sids[0], rollup.floor_hour(late))
    old = next(r for r in first if r[:2] == key)
    new = next(r for r in await _hourly(db) if r[:2] == key)
    assert (new[2], new[3], new[6]) == (old[2] + 1, old[3], 99.0)
    await agen.aclose()


async def test_uurtotalen_tellen_ook_zonder_losse_checks(authed):
    """Na 90 dagen zijn de losse checks weg; de 1j-grafiek en de uptime over een jaar tellen dan op de uurtotalen."""
    g = await _group(authed)
    sid = await _svc(authed, g, "nas")
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    old = rollup.floor_hour(now - timedelta(days=200)).replace(hour=10)
    db.add_all([CheckHourly(service_id=sid, hour=old, checks=60, ok=30, latency_n=60, latency_sum=600.0,
                            latency_min=5.0, latency_max=20.0, maint_latency_n=0),
                CheckHourly(service_id=sid, hour=old + timedelta(hours=1), checks=0, ok=0, latency_n=0,
                            maint_latency_n=2, maint_latency_sum=100.0, maint_latency_min=40.0, maint_latency_max=60.0),
                AppState(key=rollup.KEY, value={"until": (rollup.floor_hour(now) - timedelta(hours=1)).isoformat()})])
    db.add(CheckResult(service_id=sid, ts=now - timedelta(minutes=5), ok=True, latency_ms=1.0, maintenance=False))
    await db.commit()
    h = (await authed.get(f"/api/services/{sid}/history", params={"range": "1y"})).json()
    day = [p for p in h["points"] if p["t"].startswith(old.strftime("%Y-%m-%d"))]
    assert len(day) == 1 and day[0]["up"] == 0.5 and day[0]["min"] == 5.0 and day[0]["max"] == 60.0
    assert day[0]["avg"] == pytest.approx(700 / 62)
    assert h["checks"] == 61 and h["uptime"] == pytest.approx(31 / 61)
    assert h["uptime_all"]["1y"] == pytest.approx(31 / 61) and h["uptime_all"]["30d"] == 1.0
    h30 = (await authed.get(f"/api/services/{sid}/history", params={"range": "30d"})).json()
    assert h30["checks"] == 1
    r = await build_report(db, now - timedelta(days=250), now)
    assert [(s["checks"], s["uptime"], s["avg_ms"], s["max_ms"]) for s in r["services"]] == \
        [(61, round(31 / 61 * 100, 3), round(601 / 61, 1), 20.0)]

    # Een service weg: zijn uurtotalen ook.
    assert (await authed.delete(f"/api/services/{sid}")).status_code in (200, 204)
    assert (await db.execute(select(func.count()).select_from(CheckHourly))).scalar() == 0
    await agen.aclose()


async def test_opruimen_wacht_op_de_uurtotalen(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "nas")
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    for days in (60, 95, 120):
        db.add(CheckResult(service_id=sid, ts=now - timedelta(days=days), ok=True, maintenance=False))
    for days in (380, 420):
        db.add(CheckHourly(service_id=sid, hour=rollup.floor_hour(now - timedelta(days=days)), checks=1, ok=1))
    await db.commit()

    async def left() -> list[int]:
        rows = (await db.execute(select(CheckResult.ts))).scalars().all()
        return sorted(round((now - rollup._aware(ts)).total_seconds() / 86400) for ts in rows)

    # Nog nooit opgeteld: geen enkele losse check weg (anders een gat in de jaargrafiek). De uurtotalen wel na 400 dagen.
    await cleanup(db)
    assert await left() == [60, 95, 120]
    assert len((await db.execute(select(CheckHourly))).scalars().all()) == 1
    # De worker stond lang stil: opgeteld tot 100 dagen geleden. Wat daarna kwam, blijft.
    db.add(AppState(key=rollup.KEY, value={"until": rollup.floor_hour(now - timedelta(days=100)).isoformat()}))
    await db.commit()
    await cleanup(db)
    assert await left() == [60, 95]
    # Bij: alles na 90 dagen weg.
    await rollup.roll_up(db, now)
    await cleanup(db)
    assert await left() == [60]
    assert engine.KEEP_CHECKS_DAYS == 90 and engine.KEEP_HOURLY_DAYS == 400
    await agen.aclose()


async def test_eerste_keer_zonder_checks(authed):
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    assert await rollup.roll_up(db, now) == 0
    # Toch een watermark: wie leest, weet dat er voor die uren niets in de losse checks te zoeken valt.
    assert await rollup.watermark(db) == rollup.floor_hour(now - rollup.LATE)
    await agen.aclose()


def test_installatie_noemt_dezelfde_bewaartermijnen():
    """Zonder TimescaleDB zegt install.sh hoelang alles blijft: dezelfde getallen als de worker gebruikt."""
    text = (BACKEND.parent / "deploy" / "install.sh").read_text()
    line = next(x for x in text.splitlines() if "TimescaleDB kon niet" in x)
    assert f"losse checks {engine.KEEP_CHECKS_DAYS} dagen" in line
    assert f"per uur opgeteld {engine.KEEP_HOURLY_DAYS} dagen" in line
    assert f"metingen {engine.KEEP_METRICS_DAYS} dagen" in line
