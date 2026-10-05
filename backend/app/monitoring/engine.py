"""Verwerkt check-resultaten: opslaan, status bijhouden en meldingen sturen."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..deps import event, notify
from ..models import (AppState, AuditLog, CheckResult, Event, Metric, Notification, Service, ServiceState, Session,
                      UpdateRun)
from .checks import Outcome, target_for
from .upgrade import DONE

# Standaard pas na zoveel mislukte checks op rij "down" (vermijdt valse meldingen); per check in te stellen.
DOWN_AFTER = 3
# Faalt het grootste deel van alle checks tegelijk, dan ligt het aan het dashboard zelf (netwerk, DNS van de
# container): één melding in plaats van honderd.
MASS_SHARE = 0.6
MASS_END_SHARE = 0.3
MASS_MIN = 5
MASS_KEY = "massastoring"
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


def active(check: dict | None) -> bool:
    """Een check die echt loopt: ingesteld en niet gepauzeerd."""
    return bool(isinstance(check, dict) and check.get("type") and not check.get("paused"))


def down_after(check: dict | None) -> int:
    """Na zoveel mislukte checks op rij down. Een push-check meldt een uitgebleven signaal hoogstens één keer per
    interval: daar is één keer al genoeg (zoals in Kuma)."""
    default = 1 if (check or {}).get("type") == "push" else DOWN_AFTER
    try:
        n = int((check or {}).get("down_after") or default)
    except (TypeError, ValueError):
        n = default
    return min(max(n, 1), 10)


def _remind_every(check: dict | None) -> timedelta | None:
    try:
        hours = int((check or {}).get("remind_hours") or 0)
    except (TypeError, ValueError):
        return None
    return timedelta(hours=hours) if hours > 0 else None


def identity(check: dict | None, url: str | None) -> tuple | None:
    """Wat er gecheckt wordt. Verandert dit, dan hoort de oude status (down, twijfel) niet meer bij de tegel."""
    if not active(check):
        return None
    return (check.get("type"), target_for(check, url), check.get("portainer_id"), check.get("env"),
            check.get("container"), check.get("path"))


def silencing(old: dict | None, new: dict | None) -> str | None:
    """Zet deze wijziging een lopende check stil? Dan wat er gebeurt, anders None."""
    old, new = old or {}, new or {}
    if active(old) and new.get("type") and new.get("paused"):
        return "check gepauzeerd"
    if old.get("type") and new.get("type") and new.get("notify") == "uit" and old.get("notify") != "uit":
        return "meldingen uitgezet"
    return None


async def reset_state(db: AsyncSession, service_id: int) -> None:
    """Oude status weg: een down-status zonder check zou anders voor altijd blijven staan, en alles wat ervan
    afhangt voor altijd stil houden."""
    await db.execute(delete(ServiceState).where(ServiceState.service_id == service_id))


def alert(db: AsyncSession, service: Service, title: str, body: str | None, level: str,
          data: dict | None = None) -> None:
    """Melding voor een service, zoals ingesteld op de check: hier en op de gsm, alleen hier, of alleen tijdlijn."""
    mode = (service.check or {}).get("notify") or "push"
    if mode == "uit":
        event(db, "storing", title, body, level, service.id, data)
        return
    notify(db, title, body, level=level, source="monitor", service_id=service.id, data=data, push=mode != "centrum")


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
        # Een ouder zonder (lopende) check zegt niets, ook al staat er nog een oude status.
        if not active(a.check):
            continue
        st = await db.get(ServiceState, a.id)
        if st and (st.status == "down" or st.fail_count > 0):
            return a
    return None


async def failing_share(db: AsyncSession) -> tuple[int, int]:
    """(aantal checks dat nu faalt, aantal lopende checks)."""
    ids = [sid for sid, check in (await db.execute(select(Service.id, Service.check))).all() if active(check)]
    if not ids:
        return 0, 0
    failing = (await db.execute(select(func.count()).select_from(ServiceState).where(
        ServiceState.service_id.in_(ids), ServiceState.fail_count > 0))).scalar_one()
    return failing, len(ids)


async def in_mass_outage(db: AsyncSession) -> bool:
    st = await db.get(AppState, MASS_KEY)
    return bool(st and (st.value or {}).get("since"))


async def _mass_start(db: AsyncSession, now: datetime) -> bool:
    """Faalt nu het grootste deel van de checks? Dan één melding en geen aparte per service."""
    if await in_mass_outage(db):
        return True
    failing, total = await failing_share(db)
    if total < MASS_MIN or failing < MASS_SHARE * total:
        return False
    st = await ensure_state(db, MASS_KEY, {})
    st.value = {"since": now.isoformat(), "failing": failing, "total": total}
    notify(db, "Het dashboard bereikt bijna niets",
           f"{failing} van de {total} checks mislukken tegelijk. Meestal ligt het aan het netwerk of de DNS van de "
           "container van het dashboard, of is er een node of switch uitgevallen. Zolang dit duurt, komt er geen "
           "melding per service; wat daarna nog down is, meldt het apart.",
           level="err", source="homepage")
    return True


async def mass_check(db: AsyncSession) -> None:
    """Elke minuut (worker): is de massastoring voorbij?"""
    if not await in_mass_outage(db):
        return
    failing, total = await failing_share(db)
    if total < MASS_MIN or failing < MASS_END_SHARE * total:
        st = await db.get(AppState, MASS_KEY)
        since = _aware(datetime.fromisoformat(st.value["since"])) if st.value.get("since") else None
        st.value = {}
        took = f" na {_fmt_duration(datetime.now(timezone.utc) - since)}" if since else ""
        event(db, "gezondheid", f"Het dashboard bereikt weer bijna alles{took}", level="ok")


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
    if (service.check or {}).get("cert_notify") is False:
        return
    when = "verlopen" if days < 0 else f"vervalt over {max(0, int(days))} dagen"
    alert(db, service, f"Certificaat van {service.name} {when}", f"Geldig tot {expires:%d/%m/%Y %H:%M} UTC.",
          "err" if threshold == 3 else "warn")


async def _still_down(db: AsyncSession, service: Service, state: ServiceState, outcome: Outcome,
                      now: datetime) -> None:
    since = _aware(state.since)
    if state.quiet:
        # Stil gebleven omdat een ouder (of alles) down was. Is dat voorbij en deze nog niet, dan nu wel melden.
        if await _parent_failing(db, service) is None and not await in_mass_outage(db):
            state.quiet = False
            state.reminded_at = now
            alert(db, service, f"{service.name} is nog down",
                  f"Waar het van afhing is weer in orde, deze service niet. {outcome.error or ''}".strip(), "err",
                  {"down": True})
        return
    every = _remind_every(service.check)
    if every and now - (_aware(state.reminded_at) or since) >= every:
        state.reminded_at = now
        alert(db, service, f"{service.name} is nog altijd down",
              f"Al {_fmt_duration(now - since)}. {outcome.error or ''}".strip(), "err", {"down": True, "reminder": True})


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
    state.stale = False
    if outcome.status_code is not None:
        state.redirected_to = outcome.redirected_to
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
                alert(db, service, f"{service.name} is weer bereikbaar", f"Was {_fmt_duration(now - since)} down.",
                      "ok", {"down_s": int((now - since).total_seconds()), "down_at": since.isoformat()})
            state.status, state.since, state.quiet, state.reminded_at = "up", now, False, None
    else:
        state.fail_count += 1
        state.last_error = outcome.error
        if state.status == "down":
            await _still_down(db, service, state, outcome, now)
        elif state.fail_count >= down_after(service.check):
            cause = await _parent_failing(db, service)
            state.quiet = cause is not None or await _mass_start(db, now)
            if not state.quiet:
                affected = await dependents_count(db, service.id)
                body = outcome.error or ""
                if affected:
                    body = f"{body}\n{affected} services hangen hiervan af.".strip()
                alert(db, service, f"{service.name} is down" + (f" ({affected} services getroffen)" if affected else ""),
                      body, "err", {"down": True})
            state.status, state.since, state.reminded_at = "down", now, None
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
