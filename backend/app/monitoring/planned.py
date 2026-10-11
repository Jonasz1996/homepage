"""Gepland onderhoud: vooraf vastgelegde vensters (eenmalig, elke dag of op vaste weekdagen) zetten de services
op "in onderhoud" zolang het venster loopt. Zo geen valse meldingen en klopt de uptime.

Een herhalend venster gebruikt het uur en de minuut van `start` in de lokale tijd van de container.
"""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import event
from ..models import AppState, MaintenanceWindow, Service
from .engine import _aware

# De worker kijkt elke minuut: een venster gaat een minuut vroeger in, zodat de eerste check al meetelt.
LEAD = timedelta(seconds=60)
STARTED_KEY = "maintenance_started"
# Een herhalend venster loopt hoogstens zo lang per keer (anders is elke dag 24 uur gewoon altijd onderhoud); ook een
# ouder venster dat langer bewaard is, telt maar zo lang. Eenmalig mag tot 7 dagen.
REPEAT_MAX = 12 * 60
WEEKDAYS = ("ma", "di", "wo", "do", "vr", "za", "zo")


def _local(dt: datetime) -> datetime:
    return _aware(dt).astimezone()


def run_minutes(w) -> int:
    """Hoe lang het venster per keer loopt (een MaintenanceWindow of wat de API binnenkrijgt)."""
    return w.minutes if w.repeat == "once" else min(w.minutes, REPEAT_MAX)


def occurrences(w: MaintenanceWindow, around: datetime, days: int = 1) -> list[tuple[datetime, datetime]]:
    """Begin en einde van de keren dat het venster loopt, van gisteren tot `days` dagen na `around`."""
    if w.repeat == "once":
        st = _aware(w.start)
        return [(st, st + timedelta(minutes=w.minutes))]
    length = timedelta(minutes=run_minutes(w))
    t = _local(w.start).timetz()
    base = around.astimezone().date()
    out = []
    for off in range(-1, days + 1):
        d = base + timedelta(days=off)
        if w.repeat == "weekly" and d.weekday() not in (w.weekdays or []):
            continue
        # Lokale tijd van die dag (zomer- en wintertijd juist).
        st = datetime.combine(d, t.replace(tzinfo=None)).astimezone().astimezone(timezone.utc)
        out.append((st, st + length))
    return out


def active(w: MaintenanceWindow, now: datetime) -> tuple[datetime, datetime] | None:
    if not w.enabled:
        return None
    for st, en in occurrences(w, now):
        if st - LEAD <= now < en:
            return st, en
    return None


def next_run(w: MaintenanceWindow, now: datetime) -> datetime | None:
    if not w.enabled:
        return None
    later = [st for st, en in occurrences(w, now, days=8) if en > now]
    return min(later) if later else None


def describe(w: MaintenanceWindow) -> str:
    st = _local(w.start)
    m = run_minutes(w)
    dur = f"{m // 60} u {m % 60:02d}" if m >= 60 else f"{m} min"
    if w.repeat == "once":
        return f"{st.strftime('%d/%m/%Y %H:%M')}, {dur}"
    when = "elke dag" if w.repeat == "daily" else "elke " + ", ".join(WEEKDAYS[d] for d in sorted(w.weekdays or []))
    return f"{when} om {st.strftime('%H:%M')}, {dur}"


async def targets(db: AsyncSession, w: MaintenanceWindow) -> list[Service]:
    if w.service_id:
        s = await db.get(Service, w.service_id)
        return [s] if s else []
    return list((await db.execute(select(Service).where(Service.group_id == w.group_id))).scalars())


async def apply(db: AsyncSession, now: datetime | None = None) -> int:
    """Elke minuut: lopende vensters zetten maintenance_until van hun services (verlengen, nooit inkorten)."""
    now = now or datetime.now(timezone.utc)
    st = await db.get(AppState, STARTED_KEY)
    started = dict(st.value) if st else {}
    n = 0
    for w in (await db.execute(select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True)))).scalars().all():
        run = active(w, now)
        if not run:
            continue
        begin, end = run
        for s in await targets(db, w):
            until = _aware(s.maintenance_until)
            if until is None or until < end:
                s.maintenance_until = end
                n += 1
        key = f"{w.id}:{begin.isoformat()}"
        if key not in started:
            started[key] = end.isoformat()
            event(db, "actie", f"Gepland onderhoud: {w.name}", f"tot {end.astimezone().strftime('%H:%M')}")
    # Oude vermeldingen weg.
    started = {k: v for k, v in started.items() if datetime.fromisoformat(v) > now - timedelta(days=2)}
    if st:
        st.value = started
    elif started:
        db.add(AppState(key=STARTED_KEY, value=started))
    # Eenmalige vensters die voorbij zijn, uitzetten.
    for w in (await db.execute(select(MaintenanceWindow).where(MaintenanceWindow.repeat == "once",
                                                              MaintenanceWindow.enabled.is_(True)))).scalars():
        if _aware(w.start) + timedelta(minutes=w.minutes) < now - timedelta(days=1):
            w.enabled = False
    return n


async def stop(db: AsyncSession, w: MaintenanceWindow, now: datetime | None = None) -> None:
    """Venster verwijderd of uitgezet terwijl het loopt: het onderhoud dat het zette, meteen beëindigen. Een ouder
    herhalend venster van meer dan REPEAT_MAX kan dat nog met zijn volle lengte gezet hebben (tot begin + w.minutes,
    van vóór de grens): ook dat stopt, tot die volle lengte voorbij is."""
    now = now or datetime.now(timezone.utc)
    if not w.enabled:
        return
    for st, en in occurrences(w, now):
        full = max(en, st + timedelta(minutes=w.minutes))
        if not st - LEAD <= now < full:
            continue
        for s in await targets(db, w):
            until = _aware(s.maintenance_until)
            if until is not None and en <= until <= full:
                s.maintenance_until = now
