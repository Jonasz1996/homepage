"""Weekrapport: uptime per service, traagste services, langste storing, back-ups, herstarts en updates.

Wordt berekend uit de check-resultaten en de tijdlijn. Elke maandagochtend komt er een samenvatting in
het meldingencentrum; het volledige rapport staat in het dashboard (history → weekrapport).
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import Integer, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..models import AppState, CheckResult, Event, Service, ServiceState
from .capacity import storage_trends
from .engine import _fmt_duration

REPORT_KEY = "weekly_report"
REPORT_HOUR = 8


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def build_report(db: AsyncSession, start: datetime, end: datetime) -> dict:
    services = {s.id: s for s in (await db.execute(select(Service))).scalars()}

    # Uptime en snelheid per service (onderhoud telt niet mee).
    stmt = (select(CheckResult.service_id, func.count(),
                   func.sum(cast(CheckResult.ok, Integer)), func.avg(CheckResult.latency_ms), func.max(CheckResult.latency_ms))
            .where(CheckResult.ts >= start, CheckResult.ts < end, CheckResult.maintenance.is_not(True))
            .group_by(CheckResult.service_id))
    rows = []
    total = ok_total = 0
    for sid, n, ok, avg, mx in (await db.execute(stmt)).all():
        if sid not in services or not n:
            continue
        ok = int(ok or 0)
        total += n
        ok_total += ok
        rows.append({"service_id": sid, "name": services[sid].name, "checks": n, "uptime": round(ok / n * 100, 3),
                     "avg_ms": round(avg, 1) if avg is not None else None, "max_ms": round(mx, 1) if mx is not None else None})
    rows.sort(key=lambda r: (r["uptime"], r["name"].lower()))
    slowest = sorted((r for r in rows if r["avg_ms"] is not None), key=lambda r: -r["avg_ms"])[:5]

    # Storingen uit de tijdlijn: "down"-regels tellen, de duur staat bij het herstel.
    events = (await db.execute(select(Event).where(Event.ts >= start, Event.ts < end)
                               .order_by(Event.ts))).scalars().all()
    outages = [e for e in events if e.kind == "storing" and (e.data or {}).get("down_s")]
    downs = [e for e in events if e.kind == "storing" and (e.data or {}).get("down")]
    per_service: dict[int, int] = {}
    for e in downs:
        if e.service_id:
            per_service[e.service_id] = per_service.get(e.service_id, 0) + 1
    longest = max(outages, key=lambda e: e.data["down_s"], default=None)
    # Wat nu nog down is, telt ook mee voor de langste storing.
    now = datetime.now(timezone.utc)
    ongoing = []
    for st in (await db.execute(select(ServiceState).where(ServiceState.status == "down"))).scalars():
        if st.service_id in services and not st.quiet:
            since = _aware(st.since)
            ongoing.append({"service_id": st.service_id, "name": services[st.service_id].name,
                            "since": since, "seconds": int((min(end, now) - max(since, start)).total_seconds())})
    longest_out = None
    if longest:
        longest_out = {"service_id": longest.service_id,
                       "name": services[longest.service_id].name if longest.service_id in services else longest.title,
                       "seconds": longest.data["down_s"], "at": longest.data.get("down_at") or longest.ts,
                       "ongoing": False}
    for o in ongoing:
        if o["seconds"] > 0 and (longest_out is None or o["seconds"] > longest_out["seconds"]):
            longest_out = {"service_id": o["service_id"], "name": o["name"], "seconds": o["seconds"],
                           "at": o["since"], "ongoing": True}

    backups_made = sum(int((e.data or {}).get("count") or 0) for e in events if e.kind == "backup" and e.level == "ok")
    backup_problems = [{"ts": e.ts, "title": e.title, "body": e.body, "level": e.level}
                       for e in events if e.kind == "backup" and e.level in ("warn", "err")]
    # Wat nu nog misloopt (zelfde bron als de meldingen van de PBS-watcher).
    open_backups = []
    for st in (await db.execute(select(AppState).where(AppState.key.like("pbs_problems:%")))).scalars():
        sid = int(st.key.split(":", 1)[1])
        for k in st.value.get("keys", []):
            store, group, what = k.rsplit(":", 2)
            open_backups.append({"service": services[sid].name if sid in services else "?", "store": store,
                                 "group": group, "problem": {"task": "mislukt", "verify": "verify mislukt",
                                                             "late": "te oud"}.get(what, what)})

    restarts = [{"ts": e.ts, "title": e.title} for e in events if e.kind == "herstart" and "gestopt" not in e.title]
    updates_installed = sum(int((e.data or {}).get("count") or 0) for e in events if e.kind == "updates")
    upd = await db.get(AppState, "updates")
    pending = [t for t in (upd.value.get("targets", []) if upd else []) if t.get("count")]
    disks = [{"name": t["name"], "days_left": t["days_left"]} for t in await storage_trends(db, now)
             if t["days_left"] is not None and t["days_left"] <= 30]

    return {
        "start": start, "end": end,
        "uptime": round(ok_total / total * 100, 3) if total else None,
        "services": rows,
        "slowest": slowest,
        "outages": {"count": len(downs), "longest": longest_out,
                    "per_service": sorted(({"service_id": k, "name": services[k].name, "count": v}
                                           for k, v in per_service.items() if k in services),
                                          key=lambda x: -x["count"])[:10]},
        "backups": {"made": backups_made, "problems": backup_problems, "open": open_backups},
        "restarts": restarts,
        "updates": {"installed": updates_installed, "pending": sum(t["count"] for t in pending),
                    "security": sum(t.get("security") or 0 for t in pending),
                    "machines": sorted(({"name": t["name"], "count": t["count"], "security": t.get("security") or 0}
                                        for t in pending), key=lambda x: (-x["security"], -x["count"]))[:10]},
        "disks": disks,
    }


def _pct(v: float | None) -> str:
    if v is None:
        return "—"
    return f"{v:.2f}%" if v < 99.995 else "100%"


def summary_text(r: dict) -> str:
    lines = [f"Uptime: {_pct(r['uptime'])} over {len(r['services'])} services."]
    worst = [s for s in r["services"] if s["uptime"] < 99.9][:3]
    if worst:
        lines.append("Minst bereikbaar: " + ", ".join(f"{s['name']} {_pct(s['uptime'])}" for s in worst) + ".")
    o = r["outages"]
    if o["count"] or o["longest"]:
        line = f"Storingen: {o['count']}."
        if o["longest"]:
            line += (f" Langste: {o['longest']['name']}, {_fmt_duration(timedelta(seconds=o['longest']['seconds']))}"
                     + (" (nog bezig)" if o["longest"]["ongoing"] else "") + ".")
        lines.append(line)
    else:
        lines.append("Geen storingen.")
    if r["slowest"]:
        lines.append("Traagst: " + ", ".join(f"{s['name']} {s['avg_ms']:.0f} ms" for s in r["slowest"][:3]) + ".")
    b = r["backups"]
    line = f"Back-ups: {b['made']} gemaakt"
    line += f", {len(b['open'])} met een probleem." if b["open"] else ", geen gemiste."
    lines.append(line)
    if r["restarts"]:
        lines.append(f"Herstarts: {len(r['restarts'])}.")
    u = r["updates"]
    if u["pending"] or u["installed"]:
        lines.append(f"Updates: {u['installed']} geïnstalleerd, {u['pending']} open"
                     + (f" waarvan {u['security']} beveiliging" if u["security"] else "") + ".")
    for d in r["disks"][:3]:
        lines.append(f"Opslag {d['name']} vol over {max(0, round(d['days_left']))} dagen.")
    return "\n".join(lines)


def week_bounds(now_local: datetime) -> tuple[datetime, datetime]:
    """De afgelopen volledige week: maandag 00:00 tot maandag 00:00 (lokale tijd)."""
    monday = (now_local - timedelta(days=now_local.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    return monday - timedelta(days=7), monday


async def weekly_notification(db: AsyncSession, now: datetime | None = None) -> bool:
    """Maandag vanaf 8 uur: één keer per week de samenvatting als melding."""
    local = (now or datetime.now(timezone.utc)).astimezone()
    if local.weekday() != 0 or local.hour < REPORT_HOUR:
        return False
    start, end = week_bounds(local)
    week = f"{start.isocalendar().year}-W{start.isocalendar().week:02d}"
    state = await db.get(AppState, REPORT_KEY)
    if state and state.value.get("week") == week:
        return False
    r = await build_report(db, start.astimezone(timezone.utc), end.astimezone(timezone.utc))
    if r["services"] or r["backups"]["made"] or r["updates"]["pending"]:
        level = "warn" if (r["uptime"] is not None and r["uptime"] < 99) or r["backups"]["open"] else "info"
        notify(db, f"Weekrapport week {start.isocalendar().week}", summary_text(r), level=level, source="rapport")
    if state:
        state.value = {"week": week}
    else:
        db.add(AppState(key=REPORT_KEY, value={"week": week}))
    return True
