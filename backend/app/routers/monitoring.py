import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import Integer, and_, case, cast, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_session, current_user, notify, recent_auth
from ..layout import record_revision
from ..models import CheckResult, Group, Service, ServiceState, Session, User
from ..monitoring import routes
from ..monitoring.engine import active, down_after, reset_state

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

    rows = (await db.execute(
        select(Service.id, Service.name, Service.parent_id, Service.maintenance_until, Service.check))).all()
    services = {sid: (name, parent, _aware(until)) for sid, name, parent, until, _ in rows}
    checks = {sid: check or {} for sid, *_, check in rows}
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
            # Twijfel: mislukt, maar nog niet down (zoveel keer op rij nodig).
            "fail_count": s.fail_count,
            "down_after": down_after(checks.get(s.service_id)),
            "redirected_to": s.redirected_to,
            "stale": s.stale,
        }
        for s in states if active(checks.get(s.service_id))
    }
    # Services zonder (lopende) check maar wel in onderhoud (bv. een node waarvan alleen de kinderen gecheckt
    # worden), of met een gepauzeerde check.
    for sid in services:
        paused = bool(checks.get(sid, {}).get("type") and checks[sid].get("paused"))
        if str(sid) not in out and (paused or maintenance(sid)):
            out[str(sid)] = {"status": None, "maintenance_until": maintenance(sid), "paused": paused,
                             "uptime_24h": uptime.get(sid)}
    return out


# Uptime over 24 uur, 7 en 30 dagen en een jaar naast elkaar (zoals Kuma), per service vijf minuten onthouden.
UPTIME_ALL = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30), "1y": timedelta(days=365)}
_uptime_all_cache: dict[tuple[int, int], tuple[float, dict]] = {}


async def _uptime_all(db: AsyncSession, service_id: int, now: datetime) -> dict:
    key = (id(db.bind), service_id)
    hit = _uptime_all_cache.get(key)
    if hit and hit[0] > time.monotonic():
        return hit[1]
    cols = []
    for name, span in UPTIME_ALL.items():
        recent = CheckResult.ts >= now - span
        cols += [func.sum(case((and_(recent, CheckResult.ok, NOT_MAINT), 1), else_=0)),
                 func.sum(case((and_(recent, NOT_MAINT), 1), else_=0))]
    row = (await db.execute(select(*cols).where(CheckResult.service_id == service_id,
                                                  CheckResult.ts >= now - UPTIME_ALL["1y"]))).one()
    out = {}
    for i, name in enumerate(UPTIME_ALL):
        ok, total = row[2 * i] or 0, row[2 * i + 1] or 0
        out[name] = ok / total if total else None
    if len(_uptime_all_cache) > 1000:
        _uptime_all_cache.clear()
    _uptime_all_cache[key] = (time.monotonic() + 300, out)
    return out


@router.get("/services/{service_id}/history")
async def history(service_id: int, range: str = Query("24h", pattern="^(1h|24h|7d|30d|1y)$"),
                  user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    svc = await db.get(Service, service_id)
    if svc is None:
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
        # Gaat de check rechtstreeks naar de server achter NPM (zonder DNS), en zo niet, waarom niet.
        "route": routes.describe(svc.check, svc.url, await routes.load(db)),
        "uptime": total_ok / total if total else None,
        "uptime_all": await _uptime_all(db, service_id, now),
        "checks": total,
        "points": points,
        "outages": outages[::-1][:50],
        "state": {
            "status": state.status, "since": _aware(state.since), "latency_ms": state.latency_ms,
            "last_error": state.last_error, "last_check": _aware(state.last_check),
            "cert_expires_at": _aware(state.cert_expires_at), "fail_count": state.fail_count,
            "redirected_to": state.redirected_to, "stale": state.stale,
            "down_after": down_after(svc.check),
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


# --- Pauzeren ---------------------------------------------------------------------------------------------------

class PauseIn(BaseModel):
    paused: bool


@router.post("/services/{service_id}/pause")
async def pause_check(service_id: int, data: PauseIn, request: Request, sess: Session = Depends(current_session),
                      user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Check pauzeren (instellingen blijven bewaard) of hervatten. Pauzeren vraagt een recente 2FA en geeft een
    melding: een gestolen sessie zou anders als eerste de bewaking stilleggen."""
    s = await db.get(Service, service_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service niet gevonden")
    check = dict(s.check or {})
    if not check.get("type"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Deze tegel heeft geen check")
    if bool(check.get("paused")) == data.paused:
        return {"paused": data.paused}
    if data.paused:
        await recent_auth(sess, user)
        check["paused"] = True
        notify(db, f"Check gepauzeerd: {s.name}", "Was jij dit niet, kijk dan in ⚿ naar de sessies.", level="warn",
               source="auth", service_id=s.id)
    else:
        check.pop("paused", None)
    s.check, s.check_changed_at = check, datetime.now(timezone.utc)
    # Bij pauzeren en hervatten begint de status opnieuw: geen oude "down" die zijn kinderen stil houdt.
    await reset_state(db, s.id)
    await audit(db, request, user, "check_paused" if data.paused else "check_resumed", service=s.name)
    await record_revision(db, user, f"Check van '{s.name}' {'gepauzeerd' if data.paused else 'hervat'}")
    await db.commit()
    return {"paused": data.paused}
