"""Tijdlijn (alles wat er gebeurde, in volgorde), het weekrapport en het updates-overzicht."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import current_user
from ..models import AppState, AuditLog, Event, Revision, Service, User
from ..monitoring.report import build_report, week_bounds
from ..monitoring.updates import KEY as UPDATES_KEY, run_updates
from .integrations import clients

router = APIRouter(prefix="/api", tags=["timeline"])
log = logging.getLogger("homepage.api")

# Beheeracties uit de auditlog die op de tijdlijn horen (logins en dergelijke staan in de auditlog zelf).
AUDIT_TITLES = {
    "maintenance": lambda d: f"Onderhoud {d.get('service') or d.get('group') or ''}: "
                             + (f"{d.get('minutes')} min" if d.get("minutes") else "gestopt"),
    "syslog_rollout": lambda d: f"rsyslog uitgerold op {d.get('host')}",
    "oidc_settings_changed": lambda d: "Authentik-instellingen gewijzigd",
    "password_changed": lambda d: "Wachtwoord gewijzigd",
    "service_secrets_changed": lambda d: f"Geheimen van {d.get('service')} gewijzigd",
    "ssh_host_added": lambda d: f"SSH-host {d.get('name')} toegevoegd",
    "ssh_host_deleted": lambda d: f"SSH-host {d.get('name')} verwijderd",
    "log_rule_added": lambda d: f"Logregel {d.get('name')} toegevoegd",
    "log_rule_deleted": lambda d: f"Logregel {d.get('name')} verwijderd",
    "integration_action_failed": lambda d: f"{d.get('service')}: {d.get('op')} mislukt",
}
KINDS = ("storing", "herstart", "backup", "updates", "wijziging", "actie", "capaciteit", "netwerk", "toegang", "log",
         "melding")


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


@router.get("/timeline")
async def timeline(before: datetime | None = None, kind: list[str] | None = Query(default=None),
                   service_id: int | None = None, limit: int = 100,
                   user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    limit = min(max(limit, 1), 300)
    kinds = set(kind or KINDS)
    items: list[dict] = []

    q = select(Event).order_by(Event.ts.desc(), Event.id.desc()).limit(limit)
    if before:
        q = q.where(Event.ts < before)
    if service_id:
        q = q.where(Event.service_id == service_id)
    if kind:
        q = q.where(Event.kind.in_(kinds))
    for e in (await db.execute(q)).scalars():
        items.append({"id": f"e{e.id}", "ts": _aware(e.ts), "kind": e.kind, "level": e.level, "title": e.title,
                      "body": e.body, "service_id": e.service_id, "data": e.data or {}})

    if "wijziging" in kinds and not service_id:
        q = select(Revision.id, Revision.created_at, Revision.summary).order_by(Revision.id.desc()).limit(limit)
        if before:
            q = q.where(Revision.created_at < before)
        for rid, ts, summary in (await db.execute(q)).all():
            items.append({"id": f"r{rid}", "ts": _aware(ts), "kind": "wijziging", "level": "info", "title": summary,
                          "body": None, "service_id": None, "data": {"revision": rid}})
        q = select(AuditLog).where(AuditLog.action.in_(AUDIT_TITLES)).order_by(AuditLog.id.desc()).limit(limit)
        if before:
            q = q.where(AuditLog.ts < before)
        for a in (await db.execute(q)).scalars():
            items.append({"id": f"a{a.id}", "ts": _aware(a.ts), "kind": "wijziging",
                          "level": "err" if a.action.endswith("failed") else "info",
                          "title": AUDIT_TITLES[a.action](a.detail or {}), "body": None, "service_id": None,
                          "data": {"ip": a.ip}})

    items.sort(key=lambda i: i["ts"], reverse=True)
    items = items[:limit]
    return {"items": items, "more": len(items) == limit, "kinds": KINDS}


@router.get("/report")
async def report(days: int = 7, week: bool = False, user: User = Depends(current_user),
                 db: AsyncSession = Depends(get_db)):
    """days=7: de laatste 7 dagen tot nu. week=true: de vorige volledige week (zoals de maandagmelding)."""
    now = datetime.now(timezone.utc)
    if week:
        start, end = week_bounds(now.astimezone())
        start, end = start.astimezone(timezone.utc), end.astimezone(timezone.utc)
    else:
        start, end = now - timedelta(days=min(max(days, 1), 90)), now
    return await build_report(db, start, end)


# --- Updates -------------------------------------------------------------------

_refresh: asyncio.Task | None = None


def _matches(service: Service, name: str) -> bool:
    n = name.lower()
    if service.name.lower() == n:
        return True
    host = (service.url or "").split("//")[-1].split("/")[0].split(":")[0].lower()
    return bool(host) and host.split(".")[0] == n


@router.get("/updates")
async def updates(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    state = await db.get(AppState, UPDATES_KEY)
    value = state.value if state else {}
    targets = value.get("targets", [])
    # Teller per tegel: eigen service, of een container met dezelfde naam als de tegel.
    services = (await db.execute(select(Service))).scalars().all()
    by_service: dict[int, dict] = {}

    def add(sid: int, t: dict) -> None:
        b = by_service.setdefault(sid, {"count": 0, "security": 0})
        b["count"] += t["count"]
        b["security"] += t.get("security") or 0

    for t in targets:
        if not t.get("count"):
            continue
        if t.get("service_id"):
            add(t["service_id"], t)
        if t["kind"] in ("ct", "host"):
            for s in services:
                if s.id != t.get("service_id") and _matches(s, t["name"]):
                    add(s.id, t)
    return {"checked_at": value.get("checked_at"), "running": bool(_refresh and not _refresh.done()),
            "targets": sorted(targets, key=lambda t: (-(t.get("security") or 0), -t["count"], t["name"])),
            "total": sum(t["count"] for t in targets), "security": sum(t.get("security") or 0 for t in targets),
            "by_service": by_service}


async def _run_refresh(session_factory) -> None:
    # Eigen sessie: het verzoek zelf is dan al lang beantwoord.
    gen = session_factory()
    try:
        db = await anext(gen)
        await run_updates(db, clients)
        await db.commit()
    except Exception:
        log.exception("updates controleren mislukt")
    finally:
        await gen.aclose()


@router.post("/updates/refresh", status_code=status.HTTP_202_ACCEPTED)
async def refresh_updates(request: Request, user: User = Depends(current_user)):
    global _refresh
    if _refresh and not _refresh.done():
        raise HTTPException(status.HTTP_409_CONFLICT, "Er loopt al een controle")
    _refresh = asyncio.create_task(_run_refresh(request.app.dependency_overrides.get(get_db, get_db)))
    return {"ok": True}
