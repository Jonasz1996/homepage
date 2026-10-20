"""Verwerkt check-resultaten: opslaan, status bijhouden en meldingen sturen."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..models import CheckResult, Service, ServiceState
from .checks import Outcome

# Pas na zoveel mislukte checks op rij is een service "down" (vermijdt valse meldingen).
DOWN_AFTER = 3
# Zonder TimescaleDB ruimt de worker zelf op.
KEEP_DAYS = 90


def _fmt_duration(delta: timedelta) -> str:
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return f"{max(minutes, 1)} min"
    hours, minutes = divmod(minutes, 60)
    if hours < 48:
        return f"{hours} u {minutes} min"
    return f"{hours // 24} dagen"


async def record(db: AsyncSession, service: Service, outcome: Outcome, now: datetime | None = None) -> ServiceState:
    now = now or datetime.now(timezone.utc)
    db.add(CheckResult(service_id=service.id, ts=now, ok=outcome.ok, latency_ms=outcome.latency_ms,
                       status_code=outcome.status_code, error=outcome.error))
    state = await db.get(ServiceState, service.id)
    if state is None:
        state = ServiceState(service_id=service.id, status="unknown", since=now, fail_count=0)
        db.add(state)
    state.last_check = now
    state.latency_ms = outcome.latency_ms
    since = state.since if state.since.tzinfo else state.since.replace(tzinfo=timezone.utc)

    if outcome.ok:
        state.fail_count = 0
        state.last_error = None
        if state.status != "up":
            if state.status == "down":
                notify(db, f"{service.name} is weer bereikbaar", f"Was {_fmt_duration(now - since)} down.",
                       level="ok", source="monitor", service_id=service.id)
            state.status, state.since = "up", now
    else:
        state.fail_count += 1
        state.last_error = outcome.error
        if state.fail_count >= DOWN_AFTER and state.status != "down":
            notify(db, f"{service.name} is down", outcome.error, level="err",
                   source="monitor", service_id=service.id)
            state.status, state.since = "down", now
    return state


async def cleanup(db: AsyncSession) -> None:
    cutoff = datetime.now(timezone.utc) - timedelta(days=KEEP_DAYS)
    await db.execute(delete(CheckResult).where(CheckResult.ts < cutoff))
