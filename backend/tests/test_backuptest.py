"""De maandelijkse test van de eigen back-up (deploy/homepage-backuptest.sh) en welke fouten van pg_restore tellen
(deploy/herstelfouten.sh, dat homepage-terugzetten ook gebruikt).

De scripts lopen hier echt: de dump komt van homepage-backup.sh (zo is dit ook de test van het weglaten van de
logregels, met TimescaleDB in de chunks), het terugzetten gebeurt in een eigen testdatabase, met pg_dump en co. van
dezelfde of een nieuwere versie dan de server. In de CI ontbreken die nooit (HOMEPAGE_TEST_PG_CLIENT=verplicht);
elders slaan de tests zonder hen over.
"""

import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import create_async_engine

from app.health import selfcheck as sc

from .conftest import BACKEND, TEST_DB
from .test_migraties_met_gegevens import aparte_database, alembic, bouw, timescale

DEPLOY = BACKEND.parent / "deploy"
TOOLS = ("pg_dump", "pg_restore", "psql", "createdb", "dropdb")
pg = pytest.mark.skipif(TEST_DB.startswith("sqlite"), reason="productie draait op PostgreSQL")


def herstelfouten(tmp_path: Path, log: str) -> tuple[int, list[str]]:
    p = tmp_path / "pg_restore.log"
    p.write_text(log)
    r = subprocess.run(["sh", str(DEPLOY / "herstelfouten.sh"), str(p)], capture_output=True, text=True)
    return r.returncode, r.stdout.splitlines()


EXTENSIE = ('pg_restore: error: could not execute query: ERROR:  extension "timescaledb" already exists\n'
            "Command was: CREATE EXTENSION IF NOT EXISTS timescaledb WITH SCHEMA public;\n\n\n"
            "pg_restore: error: could not execute query: ERROR:  must be owner of extension timescaledb\n"
            "Command was: COMMENT ON EXTENSION timescaledb IS 'Enables scalable inserts and complex queries';\n\n\n"
            "pg_restore: warning: errors ignored on restore: 2\n")


def test_welke_fouten_van_pg_restore_tellen(tmp_path):
    assert herstelfouten(tmp_path, "") == (0, [])
    # Over de extensie zelf: die maakt het terugzetten eerst zelf aan, dus normaal.
    assert herstelfouten(tmp_path, EXTENSIE) == (0, [])
    # De gegevens van een tabel niet teruggezet: telt altijd, ook naast de normale meldingen.
    copy = 'pg_restore: error: COPY failed for table "users": ERROR:  invalid input syntax for type integer\n'
    assert herstelfouten(tmp_path, EXTENSIE + copy) == (1, ['COPY failed for table "users": ERROR:  invalid input '
                                                            'syntax for type integer'])
    assert herstelfouten(tmp_path, 'pg_restore: error: COPY failed for table "hypertable": ERROR:  extension '
                                   '"timescaledb" kapot\n')[0] == 1
    # Iets anders dan de extensie: telt, ook als de fout over timescaledb gaat.
    idx = ('pg_restore: error: could not execute query: ERROR:  relation "ix_users" already exists\n'
           "Command was: CREATE INDEX ix_users ON public.users USING btree (username);\n")
    assert herstelfouten(tmp_path, idx) == (1, ['could not execute query: ERROR:  relation "ix_users" already exists'])
    pre = ('pg_restore: error: could not execute query: ERROR:  extension "timescaledb" must be preloaded\n'
           "Command was: SELECT public.create_hypertable('public.readings', 'ts');\n")
    assert herstelfouten(tmp_path, pre)[0] == 1
    # Een afgebroken dump, en hoe pg_restore van voor PostgreSQL 12 het schreef.
    assert herstelfouten(tmp_path, "pg_restore: error: could not read from input file: end of file\n") == (
        1, ["could not read from input file: end of file"])
    assert herstelfouten(tmp_path, "pg_restore: [archiver (db)] could not execute query: ERROR:  kapot\n"
                                   "Command was: CREATE TABLE x ();\n")[0] == 1
    # Veel fouten: de eerste 20, en hoeveel er nog zijn.
    many = "".join(f'pg_restore: error: could not execute query: ERROR:  relation "t{i}" already exists\n'
                   f"Command was: CREATE TABLE public.t{i} ();\n\n" for i in range(25))
    rc, lines = herstelfouten(tmp_path, many)
    assert rc == 1 and len(lines) == 21 and lines[-1] == "… en nog 5 fouten"


def test_terugzetten_en_installatie_gebruiken_het():
    # homepage-terugzetten keurt het terugzetten af zoals de test van de back-up, niet meer alleen op alembic_version.
    t = (DEPLOY / "terugzetten.sh").read_text()
    assert re.search(r"if ! FOUTEN=\$\(/usr/local/sbin/homepage-herstelfouten /tmp/homepage-terugzetten\.log\)", t)
    # Bij elke installatie en update: het script, de dienst en de timer (op de 1e van de maand om 04:15).
    i = (DEPLOY / "install.sh").read_text()
    assert '"$APP_DIR/deploy/herstelfouten.sh" /usr/local/sbin/homepage-herstelfouten' in i
    assert '"$APP_DIR/deploy/homepage-backuptest.sh" /usr/local/sbin/homepage-backuptest' in i
    assert re.search(r"systemctl enable --now .*homepage-backuptest\.timer", i)
    assert "OnCalendar=*-*-01 04:15:00" in (DEPLOY / "homepage-backuptest.timer").read_text()
    unit = (DEPLOY / "homepage-backuptest.service").read_text()
    assert "User=postgres" in unit and "ReadWritePaths=/var/backups/homepage\n" in unit


def test_weigert_de_echte_database(tmp_path):
    r = subprocess.run(["sh", str(DEPLOY / "homepage-backuptest.sh")], capture_output=True, text=True,
                       env={**os.environ, "BACKUP_DIR": str(tmp_path), "PGDATABASE": "homepage",
                            "BACKUPTEST_DB": "homepage"})
    assert r.returncode == 2 and "andere" in r.stderr and not (tmp_path / sc.RESTORE_FILE).exists()


# --- met PostgreSQL ---------------------------------------------------------------------------------------------

def _major(exe: Path | str) -> int:
    out = subprocess.run([str(exe), "--version"], capture_output=True, text=True).stdout
    m = re.search(r"\) (\d+)", out)
    return int(m[1]) if m else 0


def _bin(server: int) -> str | None:
    """Map met pg_dump en co. van dezelfde versie als de server (zoals in productie), anders een nieuwere."""
    found = {int(p.parent.parent.name): p.parent for p in Path("/usr/lib/postgresql").glob("*/bin/pg_restore")
             if p.parent.parent.name.isdigit() and all((p.parent / t).exists() for t in TOOLS)}
    for v in sorted(found, key=lambda v: (v != server, v)):
        if v >= server:
            return str(found[v])
    exe = shutil.which("pg_restore")
    if exe and all(shutil.which(t) for t in TOOLS) and _major(exe) >= server:
        return str(Path(exe).parent)
    return None


async def _env(tmp_path: Path, url: URL) -> dict:
    engine = create_async_engine(TEST_DB)
    async with engine.connect() as conn:
        server = int((await conn.execute(text("SHOW server_version_num"))).scalar()) // 10000
    await engine.dispose()
    path = _bin(server)
    if path is None:
        msg = f"pg_dump, pg_restore en co. van PostgreSQL {server} of nieuwer niet gevonden"
        if os.environ.get("HOMEPAGE_TEST_PG_CLIENT") == "verplicht":
            pytest.fail(msg)
        pytest.skip(msg)
    tmp_path.mkdir(exist_ok=True)
    return {**os.environ, "PATH": f"{path}:{os.environ['PATH']}", "PGHOST": url.host or "", "PGPORT": str(url.port or 5432),
            "PGUSER": url.username or "", "PGPASSWORD": url.password or "", "PGDATABASE": url.database,
            "BACKUP_DIR": str(tmp_path), "BACKUPTEST_DB": f"{url.database}_backuptest",
            "HERSTELFOUTEN": str(DEPLOY / "herstelfouten.sh"),
            # De schijf van tmp_path, en niet die van de server (in de CI staat die in een container). Hoe vol de
            # schijf van de testmachine al is, doet hier niet ter zake: de grens zelf komt verderop aan bod.
            "BACKUPTEST_DF_PATH": str(tmp_path), "BACKUPTEST_MAX_PCT": "100"}


def _run(script: str, env: dict) -> dict:
    r = subprocess.run(["sh", str(DEPLOY / script)], env=env, capture_output=True, text=True, timeout=600)
    assert r.returncode == 0, r.stderr
    return sc.read_restore(Path(env["BACKUP_DIR"])) if script == "homepage-backuptest.sh" else {}


async def _databases(url: URL) -> set[str]:
    engine = create_async_engine(TEST_DB)
    async with engine.connect() as conn:
        names = set((await conn.execute(text("SELECT datname FROM pg_database WHERE datname LIKE :p"),
                                        {"p": f"{url.database}%"})).scalars())
    await engine.dispose()
    return names


@pg
async def test_back_up_terugzetten_in_een_testdatabase(tmp_path):
    async with aparte_database("bron") as url:
        # Een echte database: op een oudere versie gevuld (met TimescaleDB gecomprimeerd), dan bijgewerkt.
        counts, _ = await bouw(url)
        alembic(url, "upgrade", "head")
        env = await _env(tmp_path / "bk", url)
        _run("homepage-backup.sh", env)
        dump = next((tmp_path / "bk").glob("homepage-*.dump"))

        r = _run("homepage-backuptest.sh", env)
        log = (tmp_path / "bk" / "backuptest.log").read_text()
        assert r["status"] == "ok", (r, log)
        assert r["dump"] == dump.name and r["why"] is None and r["seconds"] is not None
        assert r["alembic"] and r["postgresql"]
        # Alles kwam terug, de logregels niet (ze gaan niet mee in de nachtelijke dump, ook niet uit de chunks).
        t = r["tables"]
        assert t["log_entries"] == 0 and counts["log_entries"] > 0
        for name in ("users", "services", "notifications", "cron_jobs", "app_state", "check_results", "metrics"):
            assert t[name] >= counts[name] > 0, name
        assert t["alembic_version"] == 1
        # De testdatabase is weer weg; de echte staat niet in "restoring" (pre_restore geldt per database).
        assert f"{url.database}_backuptest" not in await _databases(url)
        engine = create_async_engine(url)
        async with engine.connect() as conn:
            if await timescale(conn):
                assert r["timescaledb"]
                assert (await conn.execute(text("SELECT current_setting('timescaledb.restoring')"))).scalar() == "off"
            assert (await conn.execute(text("SELECT count(*) FROM log_entries"))).scalar() > 0
        await engine.dispose()

        # De worker leest het resultaat: in hw → homepage zelf.
        state = sc.restore_state(sc.read_restore(tmp_path / "bk"), {}, datetime.now(timezone.utc))
        assert state["status"] == "ok" and state["last_ok"] == r["at"]


@pg
async def test_back_up_test_mislukt_netjes(tmp_path):
    async with aparte_database("bron2") as url:
        alembic(url, "upgrade", "head")
        bk = tmp_path / "bk"
        env = await _env(bk, url)
        scratch = f"{url.database}_backuptest"

        # Nog geen dump: overgeslagen.
        r = _run("homepage-backuptest.sh", env)
        assert r["status"] == "overgeslagen" and "nog geen nachtelijke dump" in r["why"]

        _run("homepage-backup.sh", env)
        dump = next(bk.glob("homepage-*.dump"))

        # De schijf zou te vol worden (meer dan BACKUPTEST_MAX_PCT): overgeslagen, er wordt niets aangemaakt.
        r = _run("homepage-backuptest.sh", {**env, "BACKUPTEST_MAX_PCT": "0"})
        assert r["status"] == "overgeslagen" and "te weinig plaats" in r["why"] and "MB nodig" in r["why"]
        assert not (bk / "backuptest.log").exists()

        # Afgebroken dump: mislukt, met de reden, en de testdatabase is toch weer weg.
        good = dump.read_bytes()
        dump.write_bytes(good[: len(good) * 2 // 3])
        r = _run("homepage-backuptest.sh", env)
        assert r["status"] == "fout" and r["why"].startswith("pg_restore: "), r
        assert scratch not in await _databases(url)

        # Duurt het te lang (hier een pg_restore die blijft hangen): afgebroken na BACKUPTEST_TIMEOUT, weer opgeruimd.
        dump.write_bytes(good)
        fake = tmp_path / "bin"
        fake.mkdir()
        real = Path(env["PATH"].split(":")[0]) / "pg_restore"
        (fake / "pg_restore").write_text(f'#!/bin/sh\n[ "$1" = -l ] && exec "{real}" "$@"\nexec sleep 30\n')
        (fake / "pg_restore").chmod(0o755)
        r = _run("homepage-backuptest.sh", {**env, "PATH": f"{fake}:{env['PATH']}", "BACKUPTEST_TIMEOUT": "2"})
        assert r["status"] == "fout" and r["why"] == "terugzetten duurde langer dan 2 s"
        assert scratch not in await _databases(url)

        # Een testdatabase van een vorige keer die bleef staan: eerst weg, daarna lukt het gewoon.
        admin = create_async_engine(TEST_DB, isolation_level="AUTOCOMMIT")
        async with admin.connect() as conn:
            await conn.execute(text(f'CREATE DATABASE "{scratch}"'))
        await admin.dispose()
        r = _run("homepage-backuptest.sh", env)
        assert r["status"] == "ok", (r, (bk / "backuptest.log").read_text())
        assert scratch not in await _databases(url)
