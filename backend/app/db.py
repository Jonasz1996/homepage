import logging
import zlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from .config import get_settings

log = logging.getLogger("homepage.db")

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def pool_max(role: str) -> int:
    """Hoeveel databaseverbindingen dit proces maximaal opent (api, worker of syslog).

    Samen blijven de drie processen ruim onder max_connections (100) van PostgreSQL, zodat psql, pg_dump,
    terugzetten.sh en een migratie er altijd nog bij kunnen. Standaard 20 + 40 + 5 = 65:
    - worker 40: tot 20 checks tegelijk (PARALLEL in worker.py; een API- of containercheck houdt zijn sessie vast
      tijdens de check, en als de routetabel verlopen is leest elke lopende check ze opnieuw), daarna kort een
      sessie om het resultaat te bewaren, een twintigtal periodieke taken met elk één sessie, en één verbinding per
      job_lock (cron, gezondheid, updates). Gemeten met 150 checks en alle periodieke taken tegelijk: meestal
      minder dan 10 verbindingen, pieken tot 26. De rest is marge, zodat de worker niet op de pool wacht.
    - api 20: een pagina laadt een tiental dingen tegelijk, plus de taken die je met een knop start.
    - syslog 5: één schrijver, het opruimen en het herladen van de regels (hoogstens 2 tegelijk).
    """
    s = get_settings()
    return max(1, {"worker": s.db_pool_worker, "syslog": s.db_pool_syslog}.get(role, s.db_pool_api))


def make_engine(url: str | None = None, role: str = "api"):
    url = url or get_settings().database_url
    extra = {}
    if url.startswith("postgresql"):
        s = get_settings()
        n = pool_max(role)
        # De helft blijft open; bij een piek komen er tijdelijk verbindingen bij tot het maximum.
        extra["pool_size"] = max(1, n // 2)
        extra["max_overflow"] = n - extra["pool_size"]
        # Vangnetten op de server (in ms, 0 = uit): een query die blijft lopen wordt afgebroken, en een transactie
        # die blijft openstaan (een sessie die vergeten werd of hangt) wordt gesloten. Alleen voor de app zelf:
        # alembic, pg_dump en psql maken hun eigen verbindingen.
        if "asyncpg" in url:
            extra["connect_args"] = {"server_settings": {
                "statement_timeout": str(max(0, s.db_statement_timeout) * 1000),
                "idle_in_transaction_session_timeout": str(max(0, s.db_idle_in_transaction_timeout) * 1000),
            }}
    # hide_parameters: een databasefout in de logs zonder de waarden (een cronregel, een header of syslogtekst kan
    # een wachtwoord bevatten, en de logs gaan mee in de diagnose).
    return create_async_engine(url, pool_pre_ping=True, hide_parameters=True, **extra)


def init_engine(url: str | None = None, role: str = "api") -> None:
    global _engine, _sessionmaker
    _engine = make_engine(url, role)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)


def get_engine(role: str = "api"):
    """role: welk proces (api, worker, syslog) de verbindingen opent, voor de grootte van de pool."""
    if _engine is None:
        init_engine(role=role)
    return _engine


def get_maker() -> async_sessionmaker[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    return _sessionmaker


async def get_db() -> AsyncIterator[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    async with _sessionmaker() as session:
        yield session


@asynccontextmanager
async def job_lock(db: AsyncSession, name: str) -> AsyncIterator[bool]:
    """Eén taak tegelijk over API en worker heen (bv. de knop "nu scannen" terwijl de worker al scant).

        async with job_lock(db, "cron") as ok:
            if not ok:
                ...  # loopt al elders

    PostgreSQL: een advisory lock op sessieniveau, op een eigen verbinding (autocommit) naast de sessie. Het slot
    hangt zo niet aan de transactie van het werk: die mag tussendoor committen (geen transactie open tijdens SSH),
    en na het blok gaat het slot altijd vrij, ook na een fout. SQLite (tests, één proces): altijd True."""
    if db.bind.dialect.name != "postgresql":
        yield True
        return
    key = zlib.crc32(f"homepage:{name}".encode())
    engine = db.bind if isinstance(db.bind, AsyncEngine) else db.bind.engine
    async with engine.connect() as conn:
        await conn.execution_options(isolation_level="AUTOCOMMIT")
        ok = None  # None: afgebroken terwijl we het slot vroegen, misschien hebben we het
        try:
            ok = bool((await conn.execute(text("SELECT pg_try_advisory_lock(:k)"), {"k": key})).scalar())
            yield ok
        finally:
            if ok is not False:
                try:
                    await conn.execute(text("SELECT pg_advisory_unlock(:k)"), {"k": key})
                except BaseException:
                    # Het slot hoort bij deze verbinding: weggooien in plaats van terug naar de pool, anders blijft
                    # het vastzitten tot die verbinding ooit sluit. PostgreSQL geeft het dan zelf vrij.
                    log.warning("slot %s niet vrijgegeven: verbinding gesloten", name)
                    await conn.invalidate()
                    raise


async def delete_before(db: AsyncSession, column, cutoff: datetime, step: timedelta) -> int:
    """DELETE ... WHERE column < cutoff, in stukken van `step` met een commit na elk stuk. Na een lange stilstand of
    een kortere bewaartermijn staan er soms miljoenen oude rijen: zo blijft elke query ruim onder de
    statement_timeout, en wat al weg is blijft weg. Geeft het aantal gewiste rijen terug."""
    n = 0
    while True:
        first = (await db.execute(select(func.min(column)).where(column < cutoff))).scalar()
        if first is None:
            break
        # SQLite geeft tijden zonder tijdzone terug.
        upto = min(first.replace(tzinfo=first.tzinfo or timezone.utc) + step, cutoff)
        n += (await db.execute(delete(column.class_).where(column < upto))).rowcount or 0
        await db.commit()
    return n


def sqlstate(e: BaseException) -> str | None:
    """De SQLSTATE van een databasefout (van asyncpg, ook als SQLAlchemy ze inpakt), anders None."""
    orig = getattr(e, "orig", None) if isinstance(e, DBAPIError) else None
    return next((x.sqlstate for x in (orig, getattr(orig, "__cause__", None)) if getattr(x, "sqlstate", None)), None)


def timed_out(e: BaseException) -> bool:
    """Brak PostgreSQL de query af (statement_timeout, SQLSTATE 57014)?"""
    return sqlstate(e) == "57014"


async def ensure_state(db: AsyncSession, key: str, value: dict | None = None):
    """De AppState-rij met deze sleutel, desnoods eerst aangemaakt. Met INSERT ... ON CONFLICT DO NOTHING, zodat
    twee taken die tegelijk dezelfde nieuwe sleutel aanmaken niet op een dubbele primaire sleutel botsen."""
    from .models import AppState

    st = await db.get(AppState, key)
    if st is not None:
        return st
    if db.bind.dialect.name == "postgresql":
        from sqlalchemy.dialects.postgresql import insert
    else:
        from sqlalchemy.dialects.sqlite import insert
    await db.execute(insert(AppState).values(key=key, value=value or {}).on_conflict_do_nothing(index_elements=["key"]))
    return await db.get(AppState, key, populate_existing=True)
