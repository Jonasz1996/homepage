"""Waar install.sh op rekent om een update netjes af te breken: vaste versies in requirements.lock die bij
pyproject.toml passen, en migraties die samen in één transactie lopen (mislukt er één, dan is de database niet
veranderd en kan de vorige versie gewoon verder)."""

import os
import re
import shutil
import subprocess
import sys
import tomllib

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine

from .conftest import BACKEND, TEST_DB

PIN = re.compile(r"^([A-Za-z0-9._-]+)==([A-Za-z0-9.!+_-]+)$")


def _lock(name: str) -> tuple[dict[str, str], list[str]]:
    pins, other = {}, []
    for line in (BACKEND / name).read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        m = PIN.match(line)
        if m:
            assert canonicalize_name(m[1]) not in pins, f"{name}: {m[1]} staat er twee keer in"
            pins[canonicalize_name(m[1])] = m[2]
        else:
            other.append(line)
    return pins, other


def test_lock_vast_en_volgens_pyproject():
    project = tomllib.loads((BACKEND / "pyproject.toml").read_text())["project"]
    run, other = _lock("requirements.lock")
    dev, dev_other = _lock("requirements-dev.lock")
    # Alleen vaste versies; de backend zelf staat er niet in (de diensten lezen de code uit backend/).
    assert other == [] and dev_other == ["-r requirements.lock"]
    assert "homepage" not in run and "homepage" not in dev
    assert not set(run) & set(dev), "requirements-dev.lock voegt alleen toe"
    for reqs, pins in ((project["dependencies"], run), (project["optional-dependencies"]["dev"], {**run, **dev})):
        for r in map(Requirement, reqs):
            v = pins.get(canonicalize_name(r.name))
            assert v, f"{r.name} staat niet in de lock"
            assert r.specifier.contains(v, prereleases=True), f"{r.name}=={v} past niet bij {r} uit pyproject.toml"


def test_migraties_niet_in_aparte_transacties():
    env = (BACKEND / "alembic" / "env.py").read_text()
    assert "begin_transaction()" in env and "transaction_per_migration" not in env
    for f in sorted((BACKEND / "alembic" / "versions").glob("*.py")):
        code = f.read_text()
        for bad in ("autocommit_block", "CONCURRENTLY", ".commit("):
            assert bad not in code, f"{f.name}: {bad} breekt de ene transactie van alembic upgrade"


# Een update met twee nieuwe migraties: de eerste lukt, de tweede faalt nadat ze zelf al iets veranderde.
MIGRATIE = '''from alembic import op
import sqlalchemy as sa

revision = "{rev}"
down_revision = "{down}"
branch_labels = None
depends_on = None


def upgrade() -> None:
{body}


def downgrade() -> None:
    pass
'''
LUKT = '''    op.create_table("probeer", sa.Column("id", sa.Integer(), primary_key=True))
    op.add_column("users", sa.Column("probeer", sa.Integer(), nullable=True))'''
FAALT = '''    op.execute("DELETE FROM alembic_version")
    op.drop_table("probeer")
    raise RuntimeError("migratie faalt met opzet")'''


@pytest.mark.skipif(TEST_DB.startswith("sqlite"), reason="productie draait op PostgreSQL")
async def test_mislukte_migratie_laat_database_ongemoeid(tmp_path):
    # Een aparte database: het schema van de andere tests blijft zoals het is.
    url = make_url(TEST_DB)
    name = f"{url.database}_update"
    admin = create_async_engine(TEST_DB, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    db_url = url.set(database=name).render_as_string(hide_password=False)
    try:
        cfg = Config()
        cfg.set_main_option("script_location", str(BACKEND / "alembic"))
        head = ScriptDirectory.from_config(cfg).get_current_head()
        shutil.copytree(BACKEND / "alembic", tmp_path / "alembic", ignore=shutil.ignore_patterns("__pycache__"))
        versions = tmp_path / "alembic" / "versions"
        (versions / "9998_lukt.py").write_text(MIGRATIE.format(rev="9998", down=head, body=LUKT))
        (versions / "9999_faalt.py").write_text(MIGRATIE.format(rev="9999", down="9998", body=FAALT))
        ini = (BACKEND / "alembic.ini").read_text().replace("script_location = alembic",
                                                            f"script_location = {tmp_path / 'alembic'}")
        (tmp_path / "alembic.ini").write_text(ini)

        def alembic(*args: str) -> subprocess.CompletedProcess:
            return subprocess.run([sys.executable, "-m", "alembic", "-c", str(tmp_path / "alembic.ini"), *args],
                                  cwd=BACKEND, env={**os.environ, "HOMEPAGE_DATABASE_URL": db_url},
                                  capture_output=True, text=True)

        # Zoals bij een update: de database staat op de laatste versie, van de twee nieuwe migraties faalt de tweede.
        assert alembic("upgrade", head).returncode == 0
        r = alembic("upgrade", "head")
        assert r.returncode != 0 and "migratie faalt met opzet" in r.stderr

        engine = create_async_engine(db_url)
        async with engine.connect() as conn:
            assert (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar_one() == head
            assert (await conn.execute(text("SELECT to_regclass('probeer')"))).scalar() is None
            cols = (await conn.execute(text(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'"))).scalars().all()
            assert "probeer" not in cols and "username" in cols
        await engine.dispose()
    finally:
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()
