import zlib
from collections.abc import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import get_settings

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(url: str | None = None) -> None:
    global _engine, _sessionmaker
    url = url or get_settings().database_url
    # Trage taken (SSH, externe API's) houden soms een verbinding vast: wat meer ruimte dan de standaard 5 + 10.
    extra = {"pool_size": 10, "max_overflow": 20} if url.startswith("postgresql") else {}
    _engine = create_async_engine(url, pool_pre_ping=True, **extra)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)


def get_engine():
    if _engine is None:
        init_engine()
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


async def job_lock(db: AsyncSession, name: str) -> bool:
    """Eén taak tegelijk over API en worker heen (bv. de knop "nu scannen" terwijl de worker al scant).
    PostgreSQL: advisory lock tot het einde van de transactie. SQLite (tests, één proces): altijd True."""
    if db.bind.dialect.name != "postgresql":
        return True
    key = zlib.crc32(f"homepage:{name}".encode())
    return bool((await db.execute(text("SELECT pg_try_advisory_xact_lock(:k)"), {"k": key})).scalar())


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
