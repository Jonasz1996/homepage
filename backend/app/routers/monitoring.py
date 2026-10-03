from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import Integer, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import current_user
from ..models import CheckResult, Service, ServiceState, User

router = APIRouter(prefix="/api", tags=["monitoring"])

# range -> (lengte, bucketgrootte in seconden)
RANGES = {
    "1h": (timedelta(hours=1), 60),
    "24h": (timedelta(hours=24), 300),
    "7d": (timedelta(days=7), 3600),
    "30d": (timedelta(days=30), 4 * 3600),
    "1y": (timedelta(days=365), 86400),
}
SPARK_POINTS = 30


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt and dt.tzinfo is None else dt


def _bucket(db: AsyncSession, seconds: int):
    """Tijdvak-nummer per rij: epoch / bucketgrootte, afgerond naar beneden."""
    if db.bind.dialect.name == "sqlite":
        epoch = cast(func.strftime("%s", CheckResult.ts), Integer)
        return cast(epoch / seconds, Integer)
    return func.floor(func.extract("epoch", CheckResult.ts) / seconds)


def _ok_count():
    return func.sum(case((CheckResult.ok, 1), else_=0))


@router.get("/status")
async def all_status(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    states = (await db.execute(select(ServiceState))).scalars().all()
    uptime = {
        sid: (ok / total if total else None)
        for sid, ok, total in (await db.execute(
            select(CheckResult.service_id, _ok_count(), func.count())
            .where(CheckResult.ts >= now - timedelta(hours=24))
            .group_by(CheckResult.service_id)
        )).all()
    }
    spark: dict[int, list] = defaultdict(list)
    rows = (await db.execute(
        select(CheckResult.service_id, CheckResult.latency_ms, CheckResult.ok)
        .where(CheckResult.ts >= now - timedelta(hours=1))
        .order_by(CheckResult.service_id, CheckResult.ts)
    )).all()
    for sid, latency, ok in rows:
        spark[sid].append(latency if ok else None)
    return {
        str(s.service_id): {
            "status": s.status,
            "since": _aware(s.since),
            "last_check": _aware(s.last_check),
            "latency_ms": s.latency_ms,
            "last_error": s.last_error,
            "uptime_24h": uptime.get(s.service_id),
            "spark": spark[s.service_id][-SPARK_POINTS:],
        }
        for s in states
    }


@router.get("/services/{service_id}/history")
async def history(service_id: int, range: str = Query("24h", pattern="^(1h|24h|7d|30d|1y)$"),
                  user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    if await db.get(Service, service_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service niet gevonden")
    span, size = RANGES[range]
    now = datetime.now(timezone.utc)
    bucket = _bucket(db, size).label("b")
    rows = (await db.execute(
        select(
            bucket,
            func.avg(CheckResult.latency_ms),
            func.min(CheckResult.latency_ms),
            func.max(CheckResult.latency_ms),
            _ok_count(),
            func.count(),
        )
        .where(CheckResult.service_id == service_id, CheckResult.ts >= now - span)
        .group_by(bucket)
        .order_by(bucket)
    )).all()

    points, outages = [], []
    total_ok = total = 0
    for b, avg, lo, hi, ok, n in rows:
        t = datetime.fromtimestamp(int(b) * size, timezone.utc)
        up = ok / n if n else None
        points.append({"t": t, "avg": avg, "min": lo, "max": hi, "up": up})
        total_ok += ok or 0
        total += n
        # Opeenvolgende tijdvakken met mislukte checks samenvoegen tot één verstoring.
        if up is not None and up < 1:
            end = t + timedelta(seconds=size)
            if outages and outages[-1]["end"] >= t:
                outages[-1]["end"] = end
                outages[-1]["worst"] = min(outages[-1]["worst"], up)
            else:
                outages.append({"start": t, "end": end, "worst": up})

    state = await db.get(ServiceState, service_id)
    last = (await db.execute(
        select(CheckResult).where(CheckResult.service_id == service_id).order_by(CheckResult.ts.desc()).limit(10)
    )).scalars().all()
    return {
        "range": range,
        "bucket_seconds": size,
        "uptime": total_ok / total if total else None,
        "checks": total,
        "points": points,
        "outages": outages[::-1][:50],
        "state": {
            "status": state.status, "since": _aware(state.since), "latency_ms": state.latency_ms,
            "last_error": state.last_error, "last_check": _aware(state.last_check),
        } if state else None,
        "recent": [
            {"ts": _aware(r.ts), "ok": r.ok, "latency_ms": r.latency_ms, "status_code": r.status_code, "error": r.error}
            for r in last
        ],
    }
