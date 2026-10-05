"""Verwerkt check-resultaten: opslaan, status bijhouden en meldingen sturen."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..models import AuditLog, CheckResult, Event, Metric, Notification, Service, ServiceState, Session, UpdateRun
from .checks import Outcome
from .upgrade import DONE

# Pas na zoveel mislukte checks op rij is een service "down" (vermijdt valse meldingen).
DOWN_AFTER = 3
# Zonder TimescaleDB ruimt de worker zelf op: checks een jaar (de 1j-grafiek), metingen een half jaar.
KEEP_CHECKS_DAYS = 365
KEEP_METRICS_DAYS = 180
# Ongelezen meldingen die na een half jaar nog openstaan, leest niemand meer.
KEEP_UNREAD_DAYS = 180
KEEP_UPDATE_RUNS_DAYS = 365


def _fmt_duration(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return f"{max(minutes, 1)} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} u {minutes} min"
    return f"{hours // 24} dagen"


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt and dt.tzinfo is None else dt


async def ancestors(db: AsyncSession, service: Service, limit: int = 6) -> list[Service]:
    """Waar deze service van afhangt, van dichtbij naar ver (bv. CT → node)."""
    out, seen, cur = [], {service.id}, service
    while cur.parent_id and cur.parent_id not in seen and len(out) < limit:
        cur = await db.get(Service, cur.parent_id)
        if cur is None:
            break
        seen.add(cur.id)
        out.append(cur)
    return out


async def in_maintenance(db: AsyncSession, service: Service, now: datetime) -> bool:
    for s in [service, *await ancestors(db, service)]:
        until = _aware(s.maintenance_until)
        if until and until > now:
            return True
    return False


async def dependents_count(db: AsyncSession, service_id: int) -> int:
    """Hoeveel services (direct of verder) van deze service afhangen."""
    rows = (await db.execute(select(Service.id, Service.parent_id))).all()
    children: dict[int, list[int]] = {}
    for sid, parent in rows:
        if parent:
            children.setdefault(parent, []).append(sid)
    seen, todo = set(), [service_id]
    while todo:
        for c in children.get(todo.pop(), []):
            if c not in seen and c != service_id:
                seen.add(c)
                todo.append(c)
    return len(seen)


async def _parent_failing(db: AsyncSession, service: Service) -> Service | None:
    for a in await ancestors(db, service):
        st = await db.get(ServiceState, a.id)
        if st and (st.status == "down" or st.fail_count > 0):
            return a
    return None


def _cert_notes(db: AsyncSession, service: Service, state: ServiceState, expires: datetime, now: datetime) -> None:
    state.cert_expires_at = expires
    days = (expires - now).total_seconds() / 86400
    if days > 14:
        state.cert_notified = 0  # vernieuwd
        return
    threshold = 3 if days <= 3 else 14
    if state.cert_notified and state.cert_notified <= threshold:
        return
    state.cert_notified = threshold
    when = "verlopen" if days < 0 else f"vervalt over {max(0, int(days))} dagen"
    notify(db, f"Certificaat van {service.name} {when}", f"Geldig tot {expires:%d/%m/%Y %H:%M} UTC.",
           level="err" if threshold == 3 else "warn", source="monitor", service_id=service.id)


async def record(db: AsyncSession, service: Service, outcome: Outcome, now: datetime | None = None) -> ServiceState:
    now = now or datetime.now(timezone.utc)
    maint = await in_maintenance(db, service, now)
    db.add(CheckResult(service_id=service.id, ts=now, ok=outcome.ok, latency_ms=outcome.latency_ms,
                       status_code=outcome.status_code, error=outcome.error, maintenance=maint))
    state = await db.get(ServiceState, service.id)
    if state is None:
        state = ServiceState(service_id=service.id, status="unknown", since=now, fail_count=0, quiet=False,
                             cert_notified=0)
        db.add(state)
    state.last_check = now
    state.latency_ms = outcome.latency_ms
    if outcome.cert_expires:
        _cert_notes(db, service, state, outcome.cert_expires, now)
    if maint:
        # Onderhoud: niets beslissen en niets melden. Na het onderhoud telt het gewoon weer.
        state.last_error = outcome.error
        return state
    since = _aware(state.since)

    if outcome.ok:
        state.fail_count = 0
        state.last_error = None
        if state.status != "up":
            if state.status == "down" and not state.quiet:
                notify(db, f"{service.name} is weer bereikbaar", f"Was {_fmt_duration(now - since)} down.",
                       level="ok", source="monitor", service_id=service.id,
                       data={"down_s": int((now - since).total_seconds()), "down_at": since.isoformat()})
            state.status, state.since, state.quiet = "up", now, False
    else:
        state.fail_count += 1
        state.last_error = outcome.error
        if state.fail_count >= DOWN_AFTER and state.status != "down":
            cause = await _parent_failing(db, service)
            state.quiet = cause is not None
            if cause is None:
                affected = await dependents_count(db, service.id)
                body = outcome.error or ""
                if affected:
                    body = f"{body}\n{affected} services hangen hiervan af.".strip()
                notify(db, f"{service.name} is down" + (f" ({affected} services getroffen)" if affected else ""),
                       body, level="err", source="monitor", service_id=service.id, data={"down": True})
            state.status, state.since = "down", now
    return state


async def cleanup(db: AsyncSession) -> None:
    now = datetime.now(timezone.utc)
    await db.execute(delete(CheckResult).where(CheckResult.ts < now - timedelta(days=KEEP_CHECKS_DAYS)))
    await db.execute(delete(Metric).where(Metric.ts < now - timedelta(days=KEEP_METRICS_DAYS)))


async def housekeeping(db: AsyncSession) -> None:
    """Verlopen sessies, oude auditlog, oude tijdlijn, oude meldingen en oude update-runs opruimen."""
    now = datetime.now(timezone.utc)
    await db.execute(delete(Session).where(Session.expires_at < now))
    await db.execute(delete(AuditLog).where(AuditLog.ts < now - timedelta(days=365)))
    await db.execute(delete(Event).where(Event.ts < now - timedelta(days=365)))
    await db.execute(delete(Notification).where(Notification.read_at.is_not(None),
                                                Notification.ts < now - timedelta(days=30)))
    await db.execute(delete(Notification).where(Notification.read_at.is_(None),
                                                Notification.ts < now - timedelta(days=KEEP_UNREAD_DAYS)))
    # Alleen afgeronde runs: een run die (nog) loopt blijft staan, hoe oud ook.
    await db.execute(delete(UpdateRun).where(UpdateRun.status.in_(DONE),
                                             UpdateRun.created_at < now - timedelta(days=KEEP_UPDATE_RUNS_DAYS)))
