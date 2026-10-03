import os
import tempfile
from pathlib import Path

import pyotp
import pytest
from cryptography.fernet import Fernet
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
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

SETUP_TOKEN = "test-setup-token"
PASSWORD = "een-lang-wachtwoord"
H = {"X-Requested-With": "homepage"}


@pytest.fixture
async def client():
    engine = create_async_engine(TEST_DB)
    if engine.dialect.name == "sqlite":
        @event.listens_for(engine.sync_engine, "connect")
        def _fk(conn, _):
            conn.execute("PRAGMA foreign_keys=ON")
    async with engine.begin() as conn:
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
