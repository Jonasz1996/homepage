"""Capaciteit: CPU, RAM en schijf van alle nodes en VM's/CT's, en wanneer opslag vol loopt."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import current_user
from ..integrations import IntegrationError
from ..models import Metric, Service, User
from ..monitoring import consolidate
from ..monitoring.capacity import storage_trends
from .integrations import clients

router = APIRouter(prefix="/api", tags=["capacity"])


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@router.get("/capacity")
async def capacity(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    names = {s.id: s.name for s in (await db.execute(select(Service))).scalars()}
    # Laatste meting per node/guest (de worker meet elke 10 minuten).
    latest: dict[tuple, Metric] = {}
    stmt = select(Metric).where(Metric.kind.in_(("node", "guest")), Metric.ts >= now - timedelta(minutes=30))
    for m in (await db.execute(stmt)).scalars():
        key = (m.service_id, m.kind, m.name)
        if key not in latest or _aware(m.ts) > _aware(latest[key].ts):
            latest[key] = m
    peaks = {(sid, kind, name): (cpu, mem)
             for sid, kind, name, cpu, mem in (await db.execute(
                 select(Metric.service_id, Metric.kind, Metric.name, func.max(Metric.cpu), func.max(Metric.mem))
                 .where(Metric.kind.in_(("node", "guest")), Metric.ts >= now - timedelta(hours=24))
                 .group_by(Metric.service_id, Metric.kind, Metric.name))).all()}

    def row(m: Metric) -> dict:
        peak = peaks.get((m.service_id, m.kind, m.name), (None, None))
        return {"service_id": m.service_id, "service": names.get(m.service_id), "name": m.name, "label": m.label,
                "node": m.name.split("/")[0], "cpu": m.cpu, "cpu_max_24h": peak[0], "mem": m.mem,
                "mem_max_24h": peak[1], "mem_total": m.mem_total, "disk": m.disk, "disk_total": m.disk_total}

    rows = sorted(latest.values(), key=lambda m: m.name)
    storage = await storage_trends(db, now)
    for s in storage:
        s["service"] = names.get(s["service_id"])
    sampled = max((_aware(m.ts) for m in latest.values()), default=None)
    return {"sampled_at": sampled, "storage": storage,
            "nodes": [row(m) for m in rows if m.kind == "node"],
            "guests": [row(m) for m in rows if m.kind == "guest"]}


@router.get("/capacity/nightly")
async def nightly(hours: int = Query(8, ge=1, le=16), user: User = Depends(current_user),
                  db: AsyncSession = Depends(get_db)):
    """Welke node 's nachts uit kan als zijn VM's en CT's naar de andere verhuizen (alleen advies)."""
    try:
        return await consolidate.propose(db, clients, hours)
    except IntegrationError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
