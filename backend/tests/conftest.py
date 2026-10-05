import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pyotp
import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

_tmp = Path(tempfile.mkdtemp())
(_tmp / "secret.key").write_bytes(Fernet.generate_key())
(_tmp / "setup-token").write_text("test-setup-token\n")
os.environ.update(
    HOMEPAGE_SECRET_KEY_FILE=str(_tmp / "secret.key"),
    HOMEPAGE_SETUP_TOKEN_FILE=str(_tmp / "setup-token"),
    HOMEPAGE_COOKIE_SECURE="false",
)

from app.db import get_db  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402
from app.security import limiter  # noqa: E402

# Standaard SQLite; zet HOMEPAGE_TEST_DATABASE_URL om tegen PostgreSQL te testen.
TEST_DB = os.environ.get("HOMEPAGE_TEST_DATABASE_URL", "sqlite+aiosqlite://")
# HOMEPAGE_TEST_SCHEMA=migraties: het schema komt uit de migraties, zoals in productie (met TimescaleDB als die
# er is: hypertables, compressie). Eén keer per testrun; tussen de tests worden de tabellen leeggemaakt.
MIGRATED = os.environ.get("HOMEPAGE_TEST_SCHEMA") == "migraties" and not TEST_DB.startswith("sqlite")
BACKEND = Path(__file__).resolve().parent.parent


def alembic(*args: str) -> None:
    env = {**os.environ, "HOMEPAGE_DATABASE_URL": TEST_DB}
    subprocess.run([sys.executable, "-m", "alembic", *args], cwd=BACKEND, env=env, check=True,
                   stdout=subprocess.DEVNULL)


async def _empty_schema() -> None:
    engine = create_async_engine(TEST_DB)
    async with engine.begin() as conn:
        await conn.execute(text("DROP SCHEMA public CASCADE"))
        await conn.execute(text("CREATE SCHEMA public"))
    await engine.dispose()


@pytest.fixture(scope="session")
def migrated():
    if MIGRATED:
        # Van een lege database: alle migraties op, helemaal terug (test de downgrades) en weer op.
        import asyncio
        asyncio.run(_empty_schema())
        alembic("upgrade", "head")
        alembic("downgrade", "base")
        alembic("upgrade", "head")
    return MIGRATED

SETUP_TOKEN = "test-setup-token"
PASSWORD = "een-lang-wachtwoord"
H = {"X-Requested-With": "homepage"}


@pytest.fixture(autouse=True)
def totp_clock(monkeypatch):
    """Elke nieuwe TOTP-code in een test hoort bij de volgende stap van 30 s (en de server telt mee):
    de server weigert een code die al gebruikt is, ook binnen hetzelfde venster."""
    import time

    from app.routers import auth
    clock = [time.time()]

    def now(self):
        clock[0] += 30
        return self.at(clock[0])
    monkeypatch.setattr(pyotp.TOTP, "now", now)
    monkeypatch.setattr(auth, "_clock", lambda: clock[0])
    return clock


@pytest.fixture
async def client(migrated):
    engine = create_async_engine(TEST_DB)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine.sync_engine, "connect")
        def _fk(conn, _):
            conn.execute("PRAGMA foreign_keys=ON")
    async with engine.begin() as conn:
        if migrated:
            tables = ", ".join(f'"{t.name}"' for t in Base.metadata.sorted_tables)
            await conn.execute(text(f"TRUNCATE {tables} RESTART IDENTITY CASCADE"))
        else:
            await conn.run_sync(Base.metadata.drop_all)
            await conn.run_sync(Base.metadata.create_all)
    maker = async_sessionmaker(engine, expire_on_commit=False)

    async def _db():
        async with maker() as s:
            yield s

    app.dependency_overrides[get_db] = _db
    limiter._fails.clear()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=H) as c:
        yield c
    app.dependency_overrides.clear()
    await engine.dispose()


async def do_setup(c: AsyncClient) -> str:
    r = await c.post("/api/auth/setup", json={"token": SETUP_TOKEN, "username": "jonas", "password": PASSWORD})
    assert r.status_code == 200, r.text
    r = await c.get("/api/auth/totp/enroll")
    secret = r.json()["secret"]
    r = await c.post("/api/auth/totp/enable", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200, r.text
    return secret


@pytest.fixture
async def authed(client):
    client.totp_secret = await do_setup(client)
    return client
