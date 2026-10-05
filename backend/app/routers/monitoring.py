import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import Integer, and_, case, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_user
from ..models import CheckResult, Group, Service, ServiceState, User

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


# Checks tijdens onderhoud tellen niet mee voor de uptime.
NOT_MAINT = CheckResult.maintenance.is_not(True)


# De uptime over 24 uur verandert nauwelijks per minuut, maar telt wel alle checks van een dag op. Het dashboard
# vraagt /status elke paar seconden: één keer per minuut rekenen is genoeg. (engine, verloopt, uptime per service)
UPTIME_TTL = 60
_uptime_cache: tuple[object, float, dict[int, float | None]] | None = None


async def _uptime_24h(db: AsyncSession, now: datetime) -> dict[int, float | None]:
    global _uptime_cache
    hit = _uptime_cache
    # Per database-engine (de tests maken er per test een nieuwe).
    if hit and hit[0] is db.bind and hit[1] > time.monotonic():
        return hit[2]
    uptime = {
        sid: (ok / total if total else None)
        for sid, ok, total in (await db.execute(
            select(CheckResult.service_id, _ok_count(), func.count())
            .where(CheckResult.ts >= now - timedelta(hours=24), NOT_MAINT)
            .group_by(CheckResult.service_id)
        )).all()
    }
    _uptime_cache = (db.bind, time.monotonic() + UPTIME_TTL, uptime)
    return uptime


@router.get("/status")
async def all_status(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    states = (await db.execute(select(ServiceState))).scalars().all()
    uptime = await _uptime_24h(db, now)
    spark: dict[int, list] = defaultdict(list)
    rows = (await db.execute(
        select(CheckResult.service_id, CheckResult.latency_ms, CheckResult.ok)
        .where(CheckResult.ts >= now - timedelta(hours=1))
        .order_by(CheckResult.service_id, CheckResult.ts)
    )).all()
    for sid, latency, ok in rows:
        spark[sid].append(latency if ok else None)

    services = {sid: (name, parent, _aware(until)) for sid, name, parent, until in (await db.execute(
        select(Service.id, Service.name, Service.parent_id, Service.maintenance_until))).all()}
    by_id = {s.service_id: s for s in states}

    def chain(sid: int):
        seen = {sid}
        parent = services.get(sid, (None, None, None))[1]
        while parent and parent not in seen and parent in services:
            seen.add(parent)
            yield parent
            parent = services[parent][1]

    def maintenance(sid: int):
        ends = [services[x][2] for x in [sid, *chain(sid)] if services.get(x) and services[x][2] and services[x][2] > now]
        return max(ends) if ends else None

    def cause(sid: int):
        # De verste ouder die down is: de echte oorzaak (node), niet de CT ertussen.
        root = None
        for a in chain(sid):
            if by_id.get(a) and by_id[a].status == "down":
                root = services[a][0]
        return root

    out = {
        str(s.service_id): {
            "status": s.status,
            "since": _aware(s.since),
            "last_check": _aware(s.last_check),
            "latency_ms": s.latency_ms,
            "last_error": s.last_error,
            "uptime_24h": uptime.get(s.service_id),
            "spark": spark[s.service_id][-SPARK_POINTS:],
            "maintenance_until": maintenance(s.service_id),
            "cause": cause(s.service_id) if s.status == "down" else None,
            "cert_expires_at": _aware(s.cert_expires_at),
        }
        for s in states
    }
    # Services zonder check maar wel in onderhoud (bv. een node waarvan alleen de kinderen gecheckt worden).
    for sid in services:
        if str(sid) not in out and maintenance(sid):
            out[str(sid)] = {"status": None, "maintenance_until": maintenance(sid)}
    return out


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
            func.sum(case((and_(CheckResult.ok, NOT_MAINT), 1), else_=0)),
            func.sum(case((NOT_MAINT, 1), else_=0)),
        )
        .where(CheckResult.service_id == service_id, CheckResult.ts >= now - span)
        .group_by(bucket)
        .order_by(bucket)
    )).all()

    points, outages = [], []
    total_ok = total = 0
    for b, avg, lo, hi, ok, n in rows:
        t = datetime.fromtimestamp(int(b) * size, timezone.utc)
        ok, n = ok or 0, n or 0
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
            "cert_expires_at": _aware(state.cert_expires_at),
        } if state else None,
        "recent": [
            {"ts": _aware(r.ts), "ok": r.ok, "latency_ms": r.latency_ms, "status_code": r.status_code, "error": r.error,
             "maintenance": bool(r.maintenance)}
            for r in last
        ],
    }


# --- Onderhoud ------------------------------------------------------------------

class MaintenanceIn(BaseModel):
    # 0 = onderhoud stoppen.
    minutes: int = Field(ge=0, le=7 * 24 * 60)


def _until(minutes: int) -> datetime | None:
    return datetime.now(timezone.utc) + timedelta(minutes=minutes) if minutes else None


@router.post("/services/{service_id}/maintenance")
async def service_maintenance(service_id: int, data: MaintenanceIn, request: Request,
                              user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s = await db.get(Service, service_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service niet gevonden")
    s.maintenance_until = _until(data.minutes)
    await audit(db, request, user, "maintenance", service=s.name, minutes=data.minutes)
    await db.commit()
    return {"maintenance_until": s.maintenance_until}


@router.post("/groups/{group_id}/maintenance")
async def group_maintenance(group_id: int, data: MaintenanceIn, request: Request,
                            user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    g = await db.get(Group, group_id)
    if g is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groep niet gevonden")
    until = _until(data.minutes)
    await db.execute(update(Service).where(Service.group_id == group_id).values(maintenance_until=until))
    await audit(db, request, user, "maintenance", group=g.name, minutes=data.minutes)
    await db.commit()
    return {"maintenance_until": until}
