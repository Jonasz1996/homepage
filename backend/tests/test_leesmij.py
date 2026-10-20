"""LEESMIJ.txt bij de kopie buiten de container (en sectie 8 van het noodplan): de database terugzetten op een nieuwe
container, met dezelfde opdrachten als homepage-terugzetten, en daarna de migraties zoals install.sh ze draait.

Met PostgreSQL lopen de opdrachten hier echt, zoals ze in de tekst staan: tegen een eigen database, met een
nep-runuser (zonder van gebruiker te wisselen, de database homepage wordt de testdatabase) en een nep-systemctl.
"""

import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from app.health import selfcheck as sc

from .conftest import BACKEND, TEST_DB

DEPLOY = BACKEND.parent / "deploy"
DIENSTEN = "homepage-api homepage-worker homepage-syslog"
DUMP = "/pad/naar/homepage-JJJJ-MM-DD.dump"


def _stappen(t: str) -> list[str]:
    """De opdrachten van het terugzetten, zonder de uitleg ertussen."""
    rest = t.split("Terugzetten op een nieuwe container")[1]
    return [line[2:] for line in rest.splitlines() if line.startswith("  ") and not line.startswith("  #")]


def _herstel_uitleg(tmp_path: Path, ts: str) -> list[str]:
    """Wat homepage-terugzetten afdrukt om zijn eigen kopie terug te zetten (herstel_uitleg), voor dezelfde dump."""
    script = (DEPLOY / "terugzetten.sh").read_text().splitlines()
    start = script.index("herstel_uitleg() {")
    safe = tmp_path / "kopie.dump"
    Path(f"{safe}.versie").write_text(f"commit=\nversie=v1\ntimescaledb={ts}\n")
    bash = "\n".join([f"DB=homepage EIGENAAR=homepage APP_DIR={shlex.quote(str(tmp_path))} "
                      f"SAFE={shlex.quote(str(safe))}", *script[start:script.index("}", start) + 1], "herstel_uitleg"])
    r = subprocess.run(["bash", "-c", bash], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return [line[2:] for line in r.stdout.replace(str(safe), DUMP).splitlines()]


@pytest.mark.parametrize("ts", ["2.17.2", ""])
def test_leesmij_zoals_terugzetten_en_install_sh(tmp_path, ts):
    t = sc.readme({"postgresql": "16.4", "timescaledb": ts or None})
    stappen = _stappen(t)
    # Als root in de container: runuser, sudo staat er niet in.
    assert "sudo" not in t and all(s.startswith("runuser -u postgres -- ") for s in stappen if "postgres" in s)
    # Dezelfde opdrachten als homepage-terugzetten, in dezelfde volgorde.
    uitleg = _herstel_uitleg(tmp_path, ts)
    assert [s for s in stappen if s in uitleg] == uitleg, (stappen, uitleg)
    assert ("CREATE EXTENSION timescaledb VERSION '2.17.2'" in t) == bool(ts)
    # De migraties zoals install.sh ze draait: homepage.env ingelezen, als homepage, vanuit backend/.
    install = (DEPLOY / "install.sh").read_text().replace("\\\n  ", "")
    assert re.search(r'^set -a\n# shellcheck source=/dev/null\n\. "\$CONF_DIR/homepage\.env"$', install, re.M)
    assert "\nAPP_DIR=/opt/homepage\nCONF_DIR=/etc/homepage\n" in install
    assert ('(cd "$APP_DIR/backend" && runuser -u homepage -- env HOMEPAGE_DATABASE_URL="$HOMEPAGE_DATABASE_URL" '
            '"$APP_DIR/.venv/bin/alembic" upgrade head)') in install
    i = stappen.index("set -a; . /etc/homepage/homepage.env; set +a")
    assert stappen[0] == "cd /opt/homepage/backend" and stappen[i + 1:] == [
        'runuser -u homepage -- env HOMEPAGE_DATABASE_URL="$HOMEPAGE_DATABASE_URL" ../.venv/bin/alembic upgrade head',
        f"systemctl start {DIENSTEN}"]
    # Eerst alles terug, dan pas de migraties.
    assert stappen.index(uitleg[-2]) < i


def test_leesmij_zonder_versies():
    t = sc.readme({})
    assert "VERSION '<versie>'" in t and "homepage-dumpinfo /pad/naar/homepage-JJJJ-MM-DD.dump" in t
    assert "alembic upgrade head" in t and "sudo" not in t


@pytest.mark.skipif(TEST_DB.startswith("sqlite"), reason="met PostgreSQL")
async def test_leesmij_op_een_nieuwe_container(tmp_path):
    """De kopie van een oudere versie, met gegevens; de code is de nieuwste. Na de opdrachten uit LEESMIJ.txt is
    alles terug en staat de database op de nieuwste migratie, met TimescaleDB in de versie van de kopie."""
    from .test_backuptest import _env, _run
    from .test_migraties_met_gegevens import aparte_database, bouw, timescale

    async with aparte_database("leesmij") as url:
        counts, _ = await bouw(url)
        env = await _env(tmp_path / "bk", url)
        _run("homepage-backup.sh", env)
        dump = next((tmp_path / "bk").glob("homepage-*.dump"))
        engine = create_async_engine(url)
        async with AsyncSession(engine) as s:
            versions = await sc.db_versions(s)
        await engine.dispose()
        t = sc.readme(versions)

        fake = tmp_path / "bin"
        fake.mkdir()
        calls = tmp_path / "systemctl.log"
        # runuser -u X -- opdracht: zonder van gebruiker te wisselen, met de testdatabase en zijn eigenaar.
        (fake / "runuser").write_text('#!/usr/bin/env bash\n[ "$1" = -u ] && shift 2\n[ "$1" = -- ] && shift\na=()\n'
                                      'while [ $# -gt 0 ]; do\n  case "$1" in\n'
                                      '    -O) a+=(-O "$RUNUSER_OWNER"); shift ;;\n'
                                      '    homepage) a+=("$RUNUSER_DB") ;;\n    *) a+=("$1") ;;\n  esac\n  shift\n'
                                      'done\nexec "${a[@]}"\n')
        (fake / "systemctl").write_text(f'#!/bin/sh\necho "$*" >> "{calls}"\n')
        for f in fake.iterdir():
            f.chmod(0o755)
        conf = tmp_path / "homepage.env"
        conf.write_text(f"HOMEPAGE_DATABASE_URL={url.render_as_string(hide_password=False)}\n")
        alembic = Path(sys.executable).parent / "alembic"
        log = tmp_path / "pg_restore.log"
        stappen = _stappen(t)
        assert "app.health.selfcheck decrypt" in stappen[1] and stappen[2].startswith("chown root:homepage")
        hier = {"/opt/homepage/backend": str(BACKEND), DUMP: str(dump), "/root/pg_restore.log": str(log),
                "/etc/homepage/homepage.env": str(conf),
                "../.venv/bin/alembic": shlex.quote(str(alembic)) if alembic.exists()
                else f"{shlex.quote(sys.executable)} -m alembic",
                "homepage-herstelfouten ": f"sh {DEPLOY / 'herstelfouten.sh'} "}
        cmds = []
        for s in stappen[:1] + stappen[3:]:
            for oud, nieuw in hier.items():
                s = s.replace(oud, nieuw)
            cmds.append(s)
        r = subprocess.run(["bash", "-c", "set -e\n" + "\n".join(cmds)], capture_output=True, text=True, timeout=600,
                           env={**env, "PATH": f"{fake}:{env['PATH']}", "RUNUSER_DB": url.database,
                                "RUNUSER_OWNER": url.username or "postgres"})
        assert r.returncode == 0, r.stdout + r.stderr + (log.read_text() if log.exists() else "")
        assert calls.read_text().splitlines() == [f"stop {DIENSTEN}", f"start {DIENSTEN}"]

        head = ScriptDirectory.from_config(Config(str(BACKEND / "alembic.ini"))).get_current_head()
        engine = create_async_engine(url)
        try:
            async with engine.connect() as conn:
                assert (await conn.execute(text("SELECT version_num FROM alembic_version"))).scalar() == head
                for name in ("users", "services", "notifications", "cron_jobs", "app_state", "check_results"):
                    n = (await conn.execute(text(f'SELECT count(*) FROM "{name}"'))).scalar()
                    assert n >= counts[name] > 0, name
                if await timescale(conn):
                    assert versions["timescaledb"]
                    assert (await conn.execute(text("SELECT extversion FROM pg_extension "
                                                    "WHERE extname = 'timescaledb'"))).scalar() == versions["timescaledb"]
                    assert (await conn.execute(text("SELECT current_setting('timescaledb.restoring')"))).scalar() == "off"
                else:
                    assert not versions["timescaledb"] and "timescaledb" not in "\n".join(cmds)
        finally:
            await engine.dispose()
