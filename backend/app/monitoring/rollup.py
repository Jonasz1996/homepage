"""Uurtotalen van de checks (tabel check_hourly).

Losse checks blijven 90 dagen, per service per uur opgeteld blijven ze 400 dagen (engine.KEEP_CHECKS_DAYS en
KEEP_HOURLY_DAYS). De grafiek en de uptime over 7 dagen, 30 dagen en een jaar en het weekrapport lezen de hele uren
uit de uurtotalen, en alleen wat er nog niet in zit (het lopende uur, en het stukje voor het eerste hele uur) uit de
losse checks. Een jaar is zo hoogstens 8760 rijen per service in plaats van een half miljoen checks.

De cijfers blijven dezelfde als uit de losse checks: per uur staan aantallen en sommen, geen gemiddelden. Onderhoud
telt niet mee voor de uptime en het weekrapport; de latency-grafiek telt het wel mee, daarom apart opgeteld.

De worker telt op (roll_up, elke 10 minuten). Tot waar staat in app_state 'check_hourly': elk uur voor `until` zit
in de uurtotalen. Migratie 0026 telde op wat er al was.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import Integer, and_, case, cast, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..models import AppState, CheckHourly, CheckResult

KEY = "check_hourly"
HOUR = 3600
# Een uur pas wat na afloop optellen: een check die net voor het uur begon, staat er iets later in.
LATE = timedelta(minutes=10)
# Elke ronde de laatste uren opnieuw: wat daar nog bijkwam (een push-signaal dat de worker na een herstart pas
# verwerkt), telt dan mee. Losse checks uit die uren ruimt de worker ook niet op (engine.cleanup).
REDO = timedelta(hours=2)
# Per dag één transactie: de eerste keer of na een lange stilstand blijft elke stap kort.
STEP = timedelta(days=1)
ROLLUP_EVERY = 600
# Normaal loopt de watermark hoogstens iets meer dan een uur achter. Meer dan een dag: het optellen lukt niet meer
# (zelfcontrole en het !-venster zeggen het).
BEHIND = timedelta(days=1)

# Checks tijdens onderhoud tellen niet mee voor de uptime.
NOT_MAINT = CheckResult.maintenance.is_not(True)
MAINT = CheckResult.maintenance.is_(True)
FIELDS = ("checks", "ok", "latency_n", "latency_sum", "latency_min", "latency_max",
          "maint_latency_n", "maint_latency_sum", "maint_latency_min", "maint_latency_max")


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=timezone.utc) if dt and dt.tzinfo is None else dt


def floor_hour(dt: datetime) -> datetime:
    return _aware(dt).astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)


def ceil_hour(dt: datetime) -> datetime:
    down = floor_hour(dt)
    return down if down == dt else down + timedelta(hours=1)


def bucket(db: AsyncSession, column, seconds: int):
    """Tijdvak-nummer per rij: epoch / bucketgrootte, afgerond naar beneden."""
    if db.bind.dialect.name == "sqlite":
        epoch = cast(func.strftime("%s", column), Integer)
        return cast(epoch / seconds, Integer)
    return func.floor(func.extract("epoch", column) / seconds)


def _min(a, b):
    return b if a is None else a if b is None else min(a, b)


def _max(a, b):
    return b if a is None else a if b is None else max(a, b)


@dataclass
class Totals:
    """Opgetelde checks: van één uur, of van een heel tijdvak (uren en losse checks samen)."""

    checks: int = 0
    ok: int = 0
    latency_n: int = 0
    latency_sum: float = 0.0
    latency_min: float | None = None
    latency_max: float | None = None
    maint_latency_n: int = 0
    maint_latency_sum: float = 0.0
    maint_latency_min: float | None = None
    maint_latency_max: float | None = None

    def add(self, checks, ok, n, total, lo, hi, m_n, m_total, m_lo, m_hi) -> None:
        self.checks += int(checks or 0)
        self.ok += int(ok or 0)
        self.latency_n += int(n or 0)
        self.latency_sum += total or 0.0
        self.latency_min, self.latency_max = _min(self.latency_min, lo), _max(self.latency_max, hi)
        self.maint_latency_n += int(m_n or 0)
        self.maint_latency_sum += m_total or 0.0
        self.maint_latency_min, self.maint_latency_max = _min(self.maint_latency_min, m_lo), _max(self.maint_latency_max, m_hi)

    @property
    def uptime(self) -> float | None:
        return self.ok / self.checks if self.checks else None

    @property
    def avg(self) -> float | None:
        """Gemiddelde latency buiten onderhoud (het weekrapport)."""
        return self.latency_sum / self.latency_n if self.latency_n else None

    @property
    def chart_avg(self) -> float | None:
        """Gemiddelde latency van alle checks, ook tijdens onderhoud (de grafiek)."""
        n = self.latency_n + self.maint_latency_n
        return (self.latency_sum + self.maint_latency_sum) / n if n else None

    @property
    def chart_min(self) -> float | None:
        return _min(self.latency_min, self.maint_latency_min)

    @property
    def chart_max(self) -> float | None:
        return _max(self.latency_max, self.maint_latency_max)


def _raw_cols() -> tuple:
    """Wat Totals.add verwacht, uit de losse checks."""
    lat = CheckResult.latency_ms
    out, inside = case((NOT_MAINT, lat)), case((MAINT, lat))
    return (func.sum(case((NOT_MAINT, 1), else_=0)), func.sum(case((and_(CheckResult.ok, NOT_MAINT), 1), else_=0)),
            func.count(out), func.sum(out), func.min(out), func.max(out),
            func.count(inside), func.sum(inside), func.min(inside), func.max(inside))


def _hourly_cols() -> tuple:
    """Hetzelfde, uit de uurtotalen."""
    h = CheckHourly
    return (func.sum(h.checks), func.sum(h.ok),
            func.sum(h.latency_n), func.sum(h.latency_sum), func.min(h.latency_min), func.max(h.latency_max),
            func.sum(h.maint_latency_n), func.sum(h.maint_latency_sum), func.min(h.maint_latency_min),
            func.max(h.maint_latency_max))


async def watermark(db: AsyncSession) -> datetime | None:
    """Tot waar de uurtotalen gaan: elk uur hiervoor is opgeteld. None: nog nooit opgeteld."""
    value = (await db.execute(select(AppState.value).where(AppState.key == KEY))).scalar()
    until = (value or {}).get("until")
    return _aware(datetime.fromisoformat(until)) if until else None


async def lag(db: AsyncSession, now: datetime | None = None) -> dict:
    """Hoe ver de uurtotalen achterlopen. until: de watermark (None: nog nooit opgeteld); behind_h: hoeveel uur
    er nog niet opgeteld is (zonder watermark: sinds de oudste losse check); late: meer dan BEHIND."""
    now = now or datetime.now(timezone.utc)
    until = await watermark(db)
    ref = until
    if ref is None:
        oldest = (await db.execute(select(func.min(CheckResult.ts)))).scalar()
        ref = floor_hour(oldest) if oldest else None
    behind = max(now - ref, timedelta(0)) if ref else timedelta(0)
    return {"until": until.isoformat() if until else None, "behind_h": int(behind.total_seconds() // 3600),
            "late": behind > BEHIND}


async def _rows(db: AsyncSession, raw: bool, start: datetime, end: datetime | None, size: int | None,
                service_id: int | None) -> list:
    """(service, tijdvak, wat Totals.add verwacht) per service en tijdvak."""
    table, ts, cols = ((CheckResult, CheckResult.ts, _raw_cols()) if raw
                       else (CheckHourly, CheckHourly.hour, _hourly_cols()))
    # Voor één service niet op service_id groeperen: TimescaleDB (2.17) struikelt over GROUP BY service_id, tijdvak
    # met WHERE service_id = ... op gecomprimeerde chunks ("aggregated compressed column not found").
    keys = [] if service_id is not None else [table.service_id]
    if size:
        keys.append(bucket(db, ts, size).label("b"))
    stmt = select(*keys, *cols).where(ts >= start)
    if end is not None:
        stmt = stmt.where(ts < end)
    if service_id is not None:
        stmt = stmt.where(table.service_id == service_id)
    if keys:
        stmt = stmt.group_by(*keys)
    rows = (await db.execute(stmt)).all()
    if service_id is not None:
        rows = [(service_id, *row) for row in rows]
    if not size:
        rows = [(sid, 0, *vals) for sid, *vals in rows]
    # Zonder GROUP BY komt er ook een rij als er niets is (alles NULL).
    return [row for row in rows if row[2] is not None]


async def totals(db: AsyncSession, start: datetime, end: datetime | None = None, size: int | None = None,
                 service_id: int | None = None, hourly: bool = True) -> dict[tuple[int, int], Totals]:
    """De checks van start tot end (None: tot nu) opgeteld per (service, tijdvak). size: het tijdvak in seconden,
    None voor één totaal per service (tijdvak 0).

    De hele uren uit de uurtotalen, de rest uit de losse checks: van start tot het eerste hele uur, en wat nog niet
    opgeteld is (vanaf de watermark). Een tijdvak dat geen veelvoud van een uur is (1 u, 24 u), of hourly=False:
    alles uit de losse checks. Zolang de losse checks er nog zijn, geeft dat precies hetzelfde."""
    start = _aware(start)
    end = _aware(end)
    out: dict[tuple[int, int], Totals] = {}

    async def add(raw: bool, a: datetime, b: datetime | None) -> None:
        if b is not None and b <= a:
            return
        for sid, bk, *vals in await _rows(db, raw, a, b, size, service_id):
            out.setdefault((sid, int(bk)), Totals()).add(*vals)

    until = await watermark(db) if hourly and (not size or size % HOUR == 0) else None
    first = ceil_hour(start)
    last = None if until is None else until if end is None else min(until, floor_hour(end))
    if last is None or last <= first:
        await add(True, start, end)
    else:
        await add(True, start, first)
        await add(False, first, last)
        await add(True, last, end)
    return out


async def _roll(db: AsyncSession, start: datetime, end: datetime) -> int:
    """De uren van start tot end opnieuw optellen uit de losse checks. Een uur zonder losse checks blijft zoals het
    was (die kunnen al opgeruimd zijn); een uur met losse checks krijgt de nieuwe totalen."""
    b = bucket(db, CheckResult.ts, HOUR).label("b")
    rows = (await db.execute(
        select(CheckResult.service_id, b, *_raw_cols())
        .where(CheckResult.ts >= start, CheckResult.ts < end)
        .group_by(CheckResult.service_id, b)
    )).all()
    if not rows:
        return 0
    values = [{"service_id": sid, "hour": datetime.fromtimestamp(int(h) * HOUR, timezone.utc), **dict(zip(FIELDS, vals))}
              for sid, h, *vals in rows]
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    stmt = insert(CheckHourly)
    stmt = stmt.on_conflict_do_update(index_elements=["service_id", "hour"],
                                      set_={f: getattr(stmt.excluded, f) for f in FIELDS})
    await db.execute(stmt, values)
    return len(values)


async def _advance(db: AsyncSession, until: datetime) -> None:
    st = await ensure_state(db, KEY, {})
    old = (st.value or {}).get("until")
    if not old or _aware(datetime.fromisoformat(old)) < until:
        st.value = {"until": until.isoformat()}


async def roll_up(db: AsyncSession, now: datetime | None = None) -> int:
    """De hele uren van de losse checks optellen in check_hourly, vanaf waar de vorige ronde stopte (en REDO terug).
    De eerste keer zonder watermark (geen migratie, zoals op SQLite): alles wat er is.

    Per dag een commit, samen met de watermark: elke stap blijft kort en houdt niets lang vast, na een onderbreking
    gaat het verder waar het was, en wie leest neemt een uur altijd helemaal uit de uurtotalen of helemaal uit de
    losse checks. Geeft het aantal geschreven uurrijen terug."""
    now = now or datetime.now(timezone.utc)
    end = floor_hour(now - LATE)
    until = await watermark(db)
    if until is None:
        oldest = (await db.execute(select(func.min(CheckResult.ts)))).scalar()
        start = floor_hour(oldest) if oldest else end
    else:
        start = until - REDO
    if start >= end:
        # Niets op te tellen (nog geen enkele check): de watermark toch zetten, anders blijft wie leest alles uit de
        # losse checks halen.
        await _advance(db, end)
        await db.commit()
        return 0
    n = 0
    while start < end:
        stop = min(start + STEP, end)
        n += await _roll(db, start, stop)
        await _advance(db, stop)
        await db.commit()
        start = stop
    return n
