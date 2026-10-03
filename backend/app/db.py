from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import get_settings

_engine = None
_sessionmaker: async_sessionmaker[AsyncSession] | None = None


def init_engine(url: str | None = None) -> None:
    global _engine, _sessionmaker
    _engine = create_async_engine(url or get_settings().database_url, pool_pre_ping=True)
    _sessionmaker = async_sessionmaker(_engine, expire_on_commit=False)


def get_engine():
    if _engine is None:
        init_engine()
    return _engine


async def get_db() -> AsyncIterator[AsyncSession]:
    if _sessionmaker is None:
        init_engine()
    async with _sessionmaker() as session:
        yield session
