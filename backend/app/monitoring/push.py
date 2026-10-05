"""Push-monitors beoordelen. De API schrijft alleen de laatste slag weg (routers/push.py); hier wordt dat een
check-resultaat via engine.record. Zo blijft de worker de enige die ServiceState bijwerkt.

Een slag met status=down telt meteen als mislukte check. Blijft het stil langer dan het interval plus wat speling,
dan ook ("Geen signaal sinds ..."), maar hoogstens één keer per interval: missed_at staat in de database, dus na
een herstart van de worker volgt geen vloed.
"""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..models import PushMonitor, Service, ServiceState
from .checks import Outcome
from .engine import _aware, record

MIN_INTERVAL = 60
MAX_INTERVAL = 86400
TZ = ZoneInfo("Europe/Brussels")
NO_ADDRESS = "Geen push-adres: maak er een aan"


def interval_of(check: dict) -> timedelta:
    try:
        s = int(check.get("interval") or 60)
    except (TypeError, ValueError):
        s = 60
    return timedelta(seconds=min(max(s, MIN_INTERVAL), MAX_INTERVAL))


def grace_of(interval: timedelta) -> timedelta:
    # Een script dat elke 5 minuten loopt en zelf even duurt, mag niet telkens net te laat zijn.
    return max(timedelta(seconds=30), interval / 10)


def _local(dt: datetime) -> str:
    return dt.astimezone(TZ).strftime("%d/%m %H:%M")


def _later(a: datetime | None, b: datetime | None) -> datetime | None:
    return max(a, b) if a and b else a or b


async def evaluate(db: AsyncSession, now: datetime | None = None) -> list[int]:
    """Nieuwe slagen en uitgebleven signalen van alle push-monitors wegschrijven met engine.record.

    Geeft de services terug waarvoor iets weggeschreven werd (voor de zelfherstelregels). Commit niet: dat doet de
    aanroeper, zoals bij de andere stappen van de worker."""
    now = now or datetime.now(timezone.utc)
    rows = [(sid, check, _aware(updated)) for sid, check, updated in
            (await db.execute(select(Service.id, Service.check, Service.updated_at))).all()
            if isinstance(check, dict) and check.get("type") == "push"]
    if not rows:
        return []
    monitors = {m.service_id: m for m in (await db.execute(
        select(PushMonitor).where(PushMonitor.service_id.in_([r[0] for r in rows])))).scalars()}
    done: list[int] = []
    for sid, check, updated in rows:
        mon = monitors.get(sid)
        if check.get("paused"):
            # Slagen tijdens de pauze tellen niet, ook niet achteraf als de pauze voorbij is.
            if mon and mon.last_at and (mon.seen_at is None or _aware(mon.last_at) > _aware(mon.seen_at)):
                mon.seen_at = mon.last_at
            continue
        interval = interval_of(check)
        # Na een wijziging van de tegel (nieuw, van type veranderd, pauze voorbij) begint het interval opnieuw.
        if mon is None:
            state = await db.get(ServiceState, sid)
            ref = _later(_aware(state.last_check) if state else None, updated)
            if ref is None or now - ref >= interval:
                await record(db, await db.get(Service, sid), Outcome(False, error=NO_ADDRESS), now)
                done.append(sid)
            continue

        seen = _aware(mon.seen_at)
        last_at, down_at = _aware(mon.last_at), _aware(mon.last_down_at)
        if last_at and (seen is None or last_at > seen):
            service = await db.get(Service, sid)
            # Eerst een mislukte slag die er sinds de vorige ronde tussen zat, dan de nieuwste (als die goed is).
            # Elk op het moment dat hij binnenkwam: zo blijft de volgorde juist in de geschiedenis.
            if down_at and (seen is None or down_at > seen):
                await record(db, service, Outcome(False, latency_ms=mon.last_ping,
                                                  error=mon.last_down_msg or "status=down"), min(down_at, now))
            if mon.last_ok:
                at = min(last_at, now)
                if down_at and at <= down_at:
                    at = down_at + timedelta(microseconds=1)
                await record(db, service, Outcome(True, latency_ms=mon.last_ping), at)
            mon.seen_at = mon.last_at
            done.append(sid)
            continue

        since = seen or _aware(mon.created_at)
        missed = _aware(mon.missed_at)
        if (now - _later(since, updated) > interval + grace_of(interval)
                and (missed is None or now - missed >= interval)):
            await record(db, await db.get(Service, sid), Outcome(False, error=f"Geen signaal sinds {_local(since)}"),
                         now)
            mon.missed_at = now
            done.append(sid)
    return done
