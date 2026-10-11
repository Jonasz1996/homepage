"""Schijfbewaker: de container heeft een kleine schijf, en als die volloopt, stopt PostgreSQL.

Elke 10 minuten kijken hoe vol de schijf is. Vanaf 75% gaan de oudste logregels weg, dag per dag, tot de schijf weer
onder 75% zit of alleen de laatste 3 dagen nog over zijn. Daarover één melding per keer dat het gebeurt. Zit de schijf
daarna nog boven 75%, dan zijn het de logregels niet: een melding zegt wat de schijf wel vult.
"""

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..deps import notify
from ..models import AppState, LogEntry
from . import selfcheck as sc

log = logging.getLogger("homepage.health")

GUARD_EVERY = 600
STATE_KEY = sc.GUARD_KEY
LIMIT = sc.DISK_WARN
# Pas onder 70% is het voorbij. Anders komt er elke dag een melding als de bewaker de schijf net onder 75% houdt.
CALM = LIMIT - 5
KEEP_DAYS = 3
BATCH = 10_000


def fullest() -> dict | None:
    return max(sc.measure_disks(get_settings().backup_dir), key=lambda d: d["pct"], default=None)


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _day(dt: datetime) -> datetime:
    return _aware(dt).astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _local(dt: datetime) -> str:
    return dt.astimezone().strftime("%d/%m %H:%M")


def _size(n: int) -> str:
    return f"{n / 2**30:.1f} GB" if n >= 2**30 else f"{n // 2**20} MB"


async def _hypertable(db: AsyncSession) -> bool:
    if db.bind.dialect.name != "postgresql":
        return False
    if not (await db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))).scalar():
        return False
    return bool((await db.execute(text(
        "SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'log_entries'"))).scalar())


async def _oldest(db: AsyncSession, hyper: bool) -> tuple[datetime, datetime] | None:
    """Begin en einde van de oudste dag met logregels. Met TimescaleDB is dat de oudste chunk (een dag per chunk)."""
    if hyper:
        row = (await db.execute(text(
            "SELECT range_start, range_end FROM timescaledb_information.chunks WHERE hypertable_name = 'log_entries' "
            "ORDER BY range_start LIMIT 1"))).first()
        return (_aware(row[0]), _aware(row[1])) if row else None
    first = (await db.execute(select(func.min(LogEntry.ts)))).scalar()
    return (_aware(first), _day(first) + timedelta(days=1)) if first else None


async def _drop(db: AsyncSession, hyper: bool, cut: datetime) -> None:
    """Alle logregels van voor cut weg."""
    if hyper:
        # Hele chunks weggooien (ook gecomprimeerde): de plaats komt meteen terug op de schijf.
        await db.execute(text("SELECT drop_chunks('log_entries', older_than => CAST(:cut AS timestamptz))"),
                         {"cut": cut})
        await db.commit()
        return
    # Zonder TimescaleDB in stukken, zodat de syslog-ontvanger niet lang op een slot wacht.
    while True:
        ids = select(LogEntry.id).where(LogEntry.ts < cut).limit(BATCH)
        n = (await db.execute(delete(LogEntry).where(LogEntry.id.in_(ids))
                              .execution_options(synchronize_session=False))).rowcount
        await db.commit()
        if n < BATCH:
            return


async def _consumers(db: AsyncSession, hyper: bool) -> str:
    """Wat de schijf vult: de grootste tabellen en de map met back-ups."""
    s = get_settings()
    size = await sc.db_size(db)
    parts = []
    if size["total"]:
        tables = ", ".join(f"{t['name']} {_size(t['size'])}" for t in size["tables"][:3])
        parts.append(f"database {_size(size['total'])} (grootste tabellen: {tables})")
    try:
        backups = sum(p.stat().st_size for p in s.backup_dir.iterdir() if p.is_file())
        parts.append(f"back-ups in {s.backup_dir} {_size(backups)}")
    except OSError:
        pass
    out = f"Wat de schijf vult: {'; '.join(parts) or 'onbekend'}. Ruim op of maak de schijf van de CT groter."
    if db.bind.dialect.name == "postgresql" and not hyper:
        out += ("\nZonder TimescaleDB geeft PostgreSQL de plaats van verwijderde logregels niet terug aan de schijf; "
                "hij gebruikt ze wel opnieuw voor nieuwe regels.")
    return out


async def run_diskguard(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    st = await db.get(AppState, STATE_KEY)
    prev = dict(st.value) if st else {}
    d = fullest()
    if d is None:
        return prev
    value = {**prev, "checked_at": now.isoformat(), "pct": d["pct"]}
    if d["pct"] < LIMIT:
        if prev.get("since") and d["pct"] < CALM:
            value = {"checked_at": now.isoformat(), "pct": d["pct"]}
            log.info("Schijf weer %s%% vol", d["pct"])
        return _save(db, st, value)

    # Dag per dag de oudste logregels weg, nooit iets van de laatste KEEP_DAYS dagen.
    hyper = await _hypertable(db)
    floor = _day(now - timedelta(days=KEEP_DAYS))
    before, removed, last = d["pct"], None, None
    while d["pct"] >= LIMIT:
        day = await _oldest(db, hyper)
        # Ook stoppen als de vorige stap niets weghaalde (een chunk die over de grens loopt): niet blijven proberen.
        if day is None or day[1] > floor or (last and day[0] <= last):
            break
        last = day[0]
        await _drop(db, hyper, day[1])
        removed = day[1]
        d = fullest() or d
    if removed:
        log.warning("Schijf %s%% vol: logregels van voor %s verwijderd, nu %s%%", before, removed.isoformat(), d["pct"])
        value["removed"] = removed.isoformat()

    value.update(pct=d["pct"], since=prev.get("since") or now.isoformat())
    lines = []
    if removed and not prev.get("noted"):
        lines.append(f"Logregels van voor {_local(removed)} verwijderd (de laatste {KEEP_DAYS} dagen blijven). "
                     f"De schijf was {before:.0f}% vol, nu {d['pct']:.0f}%.")
        value["noted"] = True
    if d["pct"] >= LIMIT and not prev.get("warned"):
        lines.append(f"Oude logregels opruimen helpt niet genoeg: de schijf zit nog boven {LIMIT}%.")
        lines.append(await _consumers(db, hyper))
        value["warned"] = True
    if lines:
        title = (f"Schijf van de homepage is {d['pct']:.0f}% vol" if d["pct"] >= LIMIT else
                 f"Schijf van de homepage was {before:.0f}% vol: oude logregels opgeruimd")
        notify(db, title, "\n".join(lines), level="warn", source="homepage")
    return _save(db, st, value)


def _save(db: AsyncSession, st: AppState | None, value: dict) -> dict:
    if st:
        st.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value
