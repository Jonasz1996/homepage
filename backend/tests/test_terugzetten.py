"""homepage-terugzetten (deploy/terugzetten.sh): eerst alles nakijken terwijl alles nog draait (voorbereiden), dan
terugzetten, en bij een fout zeggen hoe het erbij staat (bij_fout).

De functies van het script lopen hier echt, in bash met set -euo pipefail zoals in het script, tegen een eigen
database: met een nep-runuser (zonder van gebruiker te wisselen), een nep-systemctl (schrijft op wat er gevraagd werd)
en een eigen git-repository met een nep-install.sh als /opt/homepage. De dumps zijn echt (pg_dump), met TimescaleDB
ook een met een inhoudstafel van ruim meer dan 64 kB, zoals een database met duizenden chunks.
"""

import os
import re
import shlex
import subprocess
from pathlib import Path

import pytest

from .conftest import BACKEND, TEST_DB
from .test_backuptest import _bin
from .test_migraties_met_gegevens import aparte_database

DEPLOY = BACKEND.parent / "deploy"
SCRIPT = (DEPLOY / "terugzetten.sh").read_text().splitlines()
pytestmark = pytest.mark.skipif(TEST_DB.startswith("sqlite"), reason="productie draait op PostgreSQL")

FUNCTIES = ("say", "warn", "pg", "q", "qp", "afbreken", "onderbroken", "plaats", "voorbereiden", "kopie_maken", "bewaren",
            "db_terugzetten", "herstel_uitleg", "bij_fout", "uitvoeren")
DIENSTEN = "homepage-api homepage-worker homepage-syslog"


def _functie(naam: str) -> str:
    start = next(i for i, line in enumerate(SCRIPT) if line.startswith(f"{naam}() {{"))
    if SCRIPT[start].rstrip().endswith("}"):
        return SCRIPT[start]
    return "\n".join(SCRIPT[start:SCRIPT.index("}", start) + 1])


def _regels(begin: str, eind: str) -> str:
    start = next(i for i, line in enumerate(SCRIPT) if line.startswith(begin))
    stop = next(i for i in range(start, len(SCRIPT)) if SCRIPT[i].startswith(eind))
    return "\n".join(SCRIPT[start:stop + 1])


# Zoals in het script, na het kiezen van de kopie: de kopie van een vorige poging, dan voorbereiden.
VOORAF = _regels("SAFE=$(cat", "voorbereiden")


def test_stukken_zoals_in_terugzetten_sh():
    text = "\n".join(SCRIPT)
    assert text.index(VOORAF) < text.index("\nuitvoeren\n") and "set -euo pipefail" in text
    # De volgorde: alles nakijken, dan pas vragen en stoppen; en nergens nog een pipe naar grep -q achter pg_restore.
    assert text.index("\nvoorbereiden\n") < text.index("read -r -p") < text.index("\nuitvoeren\n")
    assert not re.search(r"pg_restore[^\n|]*\|\s*grep -q", text)
    assert "sudo -u" not in text


def _psql(env: dict, db: str, *sql: str) -> str:
    args = ["psql", "-XAtq", "-v", "ON_ERROR_STOP=1", "-d", db]
    for s in sql:
        args += ["-c", s]
    r = subprocess.run(args, env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _git(app: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(app), "-c", "user.name=t", "-c", "user.email=t@t", "-c",
                           "commit.gpgsign=false", *args], check=True, capture_output=True, text=True).stdout.strip()


class Omgeving:
    """Een container in het klein: de map met back-ups, /opt/homepage als git-repository met twee versies, en een
    eigen database als die van homepage."""

    def __init__(self, tmp: Path, url, pgbin: str):
        self.tmp, self.db, self.user = tmp, url.database, url.username or "postgres"
        self.bk = tmp / "bk"
        self.bk.mkdir()
        fake = tmp / "bin"
        fake.mkdir()
        (fake / "runuser").write_text('#!/bin/sh\n[ "$1" = -u ] && shift 2\n[ "$1" = -- ] && shift\nexec "$@"\n')
        (fake / "systemctl").write_text('#!/bin/sh\necho "$*" >> "$SYSTEMCTL_LOG"\n')
        for f in fake.iterdir():
            f.chmod(0o755)
        self.fake = fake
        self.env = {**os.environ, "PATH": f"{fake}:{pgbin}:{os.environ['PATH']}", "PGHOST": url.host or "",
                    "PGPORT": str(url.port or 5432), "PGUSER": self.user, "PGPASSWORD": url.password or "",
                    "SYSTEMCTL_LOG": str(tmp / "systemctl.log"), "INSTALL_LOG": str(tmp / "install.log")}
        self.env.pop("PGDATABASE", None)
        # /opt/homepage: de oude versie (waar het naartoe gaat) en de nieuwe die nu draait.
        self.app = tmp / "app"
        (self.app / "deploy").mkdir(parents=True)
        (self.app / "backend").mkdir()
        (self.app / "backend" / "requirements.lock").write_text("")
        (self.app / "deploy" / "install.sh").write_text(
            '#!/bin/sh\necho "install.sh van de oude versie (HOMEPAGE_TERUGZETTEN=$HOMEPAGE_TERUGZETTEN)" >> '
            '"$INSTALL_LOG"\nexit "${INSTALL_RC:-0}"\n')
        _git(self.app, "init", "-q")
        _git(self.app, "add", "-A")
        _git(self.app, "commit", "-qm", "oud")
        self.oud = _git(self.app, "rev-parse", "HEAD")
        (self.app / "deploy" / "install.sh").write_text("#!/bin/sh\necho nieuw\n")
        _git(self.app, "commit", "-qam", "nieuw")
        self.nieuw = _git(self.app, "rev-parse", "HEAD")
        self.dump = self.bk / "voor-update-20261010-120000.dump"

    def sql(self, *sql: str, db: str | None = None) -> str:
        return _psql(self.env, db or self.db, *sql)

    def ts_beschikbaar(self) -> str | None:
        """De versie van TimescaleDB als de server ze laadt (anders kan CREATE EXTENSION de verbinding laten crashen)."""
        if "timescaledb" not in self.sql("SHOW shared_preload_libraries"):
            return None
        return self.sql("SELECT default_version FROM pg_available_extensions WHERE name = 'timescaledb'") or None

    def maak_dump(self, versie: dict | None = None):
        r = subprocess.run(["pg_dump", "-Fc", "-f", str(self.dump), self.db], env=self.env, capture_output=True,
                           text=True)
        assert r.returncode == 0, r.stderr
        lines = {"commit": self.oud, "versie": "v1.0.0", **(versie or {})}
        self.dump.with_name(self.dump.name + ".versie").write_text("".join(f"{k}={v}\n" for k, v in lines.items()))

    def run(self, stappen: str = "uitvoeren", **extra: str) -> subprocess.CompletedProcess:
        # Zoals het script ze zet; datamap (SHOW data_directory) is hier de map met back-ups: in de CI staat de
        # server in een container.
        var = {"APP_DIR": self.app, "CONF_DIR": self.tmp / "conf", "BK": self.bk, "DB": self.db,
               "EIGENAAR": self.user, "LOG": self.tmp / "pg_restore.log", "HERSTELFOUTEN": DEPLOY / "herstelfouten.sh",
               "DUMPINFO": DEPLOY / "dumpinfo.sh", "DUMP": self.dump, "COMMIT": self.oud, "VERSIE": "v1.0.0",
               "NU": "v1.1.0", "NU_COMMIT": self.nieuw, "KANAAL": "stabiel", **extra}
        script = "\n".join(["set -euo pipefail", *map(_functie, FUNCTIES), 'datamap() { echo "$BK"; }',
                            'STAP="" REDEN=""', *(f"{k}={shlex.quote(str(v))}" for k, v in var.items()), VOORAF,
                            'echo "TS=$TS"', stappen, "exit"])
        return subprocess.run(["bash", "-c", script], env=self.env, capture_output=True, text=True, timeout=300)

    def systemctl(self) -> list[str]:
        p = self.tmp / "systemctl.log"
        return p.read_text().splitlines() if p.exists() else []

    def safe(self) -> Path | None:
        return next(self.bk.glob("voor-terugzetten-*.dump"), None)


def _pgbin(url) -> str:
    """pg_dump en co. van dezelfde of een nieuwere versie dan de server (zoals in test_backuptest)."""
    env = {**os.environ, "PGHOST": url.host or "", "PGPORT": str(url.port or 5432), "PGUSER": url.username or "",
           "PGPASSWORD": url.password or ""}
    server = int(_psql(env, url.database, "SHOW server_version_num")) // 10000
    path = _bin(server)
    if path is None:
        msg = f"pg_dump, pg_restore en co. van PostgreSQL {server} of nieuwer niet gevonden"
        if os.environ.get("HOMEPAGE_TEST_PG_CLIENT") == "verplicht":
            pytest.fail(msg)
        pytest.skip(msg)
    return path


VOOR = ["CREATE TABLE alembic_version (version_num varchar(32) PRIMARY KEY)",
        "INSERT INTO alembic_version VALUES ('oud')",
        "CREATE TABLE gegevens (id int PRIMARY KEY)", "INSERT INTO gegevens SELECT generate_series(1, 3)"]
NA = ["UPDATE alembic_version SET version_num = 'nieuw'", "INSERT INTO gegevens VALUES (4)"]


async def test_terugzetten_met_timescaledb_en_een_grote_dump(tmp_path):
    async with aparte_database("tz_groot") as url:
        o = Omgeving(tmp_path, url, _pgbin(url))
        ts = o.ts_beschikbaar()
        if not ts:
            pytest.skip("TimescaleDB staat niet op deze server")
        # Zoals een echte database: een hypertable met chunks, en zoveel tabellen dat de inhoudstafel ruim groter is
        # dan de buffer van een pipe (64 kB).
        o.sql("CREATE EXTENSION IF NOT EXISTS timescaledb", *VOOR,
              "CREATE TABLE metingen (ts timestamptz NOT NULL, v int)",
              "SELECT create_hypertable('metingen', 'ts', chunk_time_interval => INTERVAL '1 day')",
              "INSERT INTO metingen SELECT now() - n * INTERVAL '1 day', n FROM generate_series(1, 10) n",
              "DO $$ BEGIN FOR i IN 1..2500 LOOP EXECUTE format('CREATE TABLE t%s (id int)', i); END LOOP; END $$")
        o.maak_dump()
        toc = subprocess.run(["pg_restore", "-l", str(o.dump)], env=o.env, capture_output=True, text=True).stdout
        assert len(toc) > 128 * 1024
        # Zo zocht het vroeger: grep -q stopt bij de eerste regel, pg_restore krijgt SIGPIPE, en met pipefail lijkt
        # het alsof de dump geen TimescaleDB heeft.
        oud = subprocess.run(["bash", "-c", 'set -euo pipefail; if pg_restore -l "$1" | grep -q '
                              '"EXTENSION.*timescaledb"; then echo ja; else echo nee; fi', "_", str(o.dump)],
                             env=o.env, capture_output=True, text=True)
        assert oud.stdout.strip() == "nee"
        assert subprocess.run(["sh", str(DEPLOY / "dumpinfo.sh"), str(o.dump)], env=o.env, capture_output=True,
                              text=True).stdout.strip() == "timescaledb"
        o.sql(*NA)

        # Een kopie zonder timescaledb= ernaast (van voor deze versie): de versie van de database van nu.
        r = o.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert f"TS={ts}" in r.stdout
        assert o.sql("SELECT version_num FROM alembic_version") == "oud"
        assert o.sql("SELECT count(*) FROM gegevens") == "3" and o.sql("SELECT count(*) FROM metingen") == "10"
        assert o.sql("SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'") == ts
        assert o.sql("SELECT current_setting('timescaledb.restoring')") == "off"
        assert o.sql("SELECT count(*) FROM pg_tables WHERE tablename LIKE 't%' AND schemaname = 'public'") == "2500"
        # De versie staat nu naast de kopie, de database van daarvoor is bewaard met haar versies.
        assert not o.dump.with_name(o.dump.name + ".versie").exists()
        assert f"timescaledb={ts}\n" in o.dump.with_name(o.dump.name + ".teruggezet").read_text()
        assert not o.dump.with_name(o.dump.name + ".bezig").exists()
        safe = o.safe()
        assert safe and Path(f"{safe}.versie").read_text() == f"commit={o.nieuw}\nversie=v1.1.0\ntimescaledb={ts}\n"
        assert o.systemctl() == [f"stop {DIENSTEN}"]
        assert (tmp_path / "install.log").read_text() == "install.sh van de oude versie (HOMEPAGE_TERUGZETTEN=1)\n"
        assert _git(o.app, "rev-parse", "HEAD") == o.oud
        assert not o.sql(f"SELECT 1 FROM pg_database WHERE datname = '{o.db}_terugzetten_proef'", db="postgres")


async def test_voorbereiden_weigert_voor_er_iets_stilvalt(tmp_path):
    async with aparte_database("tz_weiger") as url:
        o = Omgeving(tmp_path, url, _pgbin(url))
        ts = o.ts_beschikbaar()
        o.sql(*(["CREATE EXTENSION IF NOT EXISTS timescaledb"] if ts else []), *VOOR)
        o.maak_dump()
        o.sql(*NA)
        good = o.dump.read_bytes()

        # Afgebroken: de inhoudstafel is er nog, de gegevens niet helemaal.
        o.dump.write_bytes(good[: len(good) * 2 // 3])
        r = o.run()
        assert r.returncode != 0 and "De kopie is onleesbaar" in r.stdout and "Er is niets veranderd" in r.stdout
        o.dump.write_bytes(good)

        # PostgreSQL draait niet (de kopie heeft geen timescaledb= ernaast): dat zeggen, en niet dat de database van
        # nu geen TimescaleDB heeft of dat ze niet bereikbaar is voor een kopie.
        host = o.env["PGHOST"]
        o.env["PGHOST"] = str(tmp_path / "geen-socket")
        try:
            r = o.run()
        finally:
            o.env["PGHOST"] = host
        assert r.returncode != 0 and "PostgreSQL is niet bereikbaar" in r.stdout, r.stdout + r.stderr
        assert "Er is niets" in r.stdout and "TimescaleDB" not in r.stdout and "TS=" not in r.stdout

        # Te weinig plaats voor de kopie van nu en de teruggezette database.
        o.maak_dump({"grootte": 10 ** 18})
        r = o.run()
        assert r.returncode != 0 and "Te weinig plaats in" in r.stdout and "MB nodig" in r.stdout, r.stdout

        if ts:
            # Die versie van TimescaleDB is hier niet geïnstalleerd: zeggen welke wel, en welk pakket.
            o.maak_dump({"timescaledb": "0.0.1"})
            r = o.run()
            assert r.returncode != 0, r.stdout
            assert "TimescaleDB 0.0.1 nodig" in r.stdout and "wel: " in r.stdout and ts in r.stdout, r.stdout
            assert "timescaledb-2-0.0.1-postgresql-" in r.stdout and "Er is niets veranderd" in r.stdout
            assert not o.sql(f"SELECT 1 FROM pg_database WHERE datname = '{o.db}_terugzetten_proef'", db="postgres")
            # Iets wat geen versie is, komt niet in SQL terecht.
            o.maak_dump({"timescaledb": "2.17'; DROP TABLE gegevens; --"})
            r = o.run()
            assert r.returncode != 0 and "Geen geldige versie" in r.stdout

        # Niets gestopt, niets veranderd.
        assert o.systemctl() == [] and o.safe() is None
        assert o.sql("SELECT version_num FROM alembic_version") == "nieuw"
        assert not o.dump.with_name(o.dump.name + ".bezig").exists()


async def test_fout_na_het_weggooien_zegt_hoe_het_terug_moet(tmp_path):
    """De database van nu is al weg: de diensten blijven stil, en de uitleg (met runuser) zet haar echt terug.
    Daarna gaat een tweede poging verder met dezelfde kopie."""
    async with aparte_database("tz_weg") as url:
        o = Omgeving(tmp_path, url, _pgbin(url))
        ts = o.ts_beschikbaar()
        o.sql(*(["CREATE EXTENSION IF NOT EXISTS timescaledb"] if ts else []), *VOOR)
        o.maak_dump({"timescaledb": ts} if ts else None)
        o.sql(*NA)
        kapot = tmp_path / "kapot.sh"
        kapot.write_text("#!/bin/sh\necho 'COPY failed for table \"gegevens\"'\nexit 1\n")
        kapot.chmod(0o755)

        r = o.run(HERSTELFOUTEN=kapot)
        out = r.stdout + r.stderr
        assert r.returncode == 1, out
        assert "De database kon niet (volledig) teruggezet worden" in out and 'COPY failed for table "gegevens"' in out
        safe = o.safe()
        assert safe and f"De database {o.db} is weg of maar half teruggezet" in out and str(safe) in out
        assert "homepage-terugzetten (het gaat verder met die kopie)" in out and "sudo" not in out
        assert o.systemctl() == [f"stop {DIENSTEN}"]
        assert o.dump.with_name(o.dump.name + ".bezig").read_text() == f"{safe}\n"
        # De uitleg uitvoeren, zoals ze er staat (de log van pg_restore in een eigen map), ook wat erachter staat.
        uitleg = [line.strip() for line in out.splitlines() if line.startswith("  runuser ")
                  or line.startswith("  homepage-herstelfouten ")]
        assert uitleg[-1].startswith("homepage-herstelfouten /root/pg_restore.log")
        assert f"  runuser -u postgres -- pg_restore -d {o.db} {safe} 2> /root/pg_restore.log" in out
        if ts:
            assert f"CREATE EXTENSION timescaledb VERSION '{ts}'" in out and "timescaledb_post_restore" in out
        assert "  systemctl start homepage-api homepage-worker homepage-syslog" in out
        log = tmp_path / "herstel.log"
        cmds = [c.replace("/root/pg_restore.log", str(log)).replace("homepage-herstelfouten ",
                                                                      f"sh {DEPLOY / 'herstelfouten.sh'} ")
                for c in uitleg]
        h = subprocess.run(["bash", "-c", "set -e\n" + "\n".join(cmds)], env=o.env, capture_output=True, text=True)
        assert h.returncode == 0, h.stdout + h.stderr
        assert o.sql("SELECT version_num FROM alembic_version") == "nieuw"
        assert o.sql("SELECT count(*) FROM gegevens") == "4"

        # Opnieuw: gaat verder met de kopie van de eerste poging, zonder een nieuwe.
        r = o.run()
        assert r.returncode == 0, r.stdout + r.stderr
        assert f"Al bewaard bij een vorige poging: {safe}" in r.stdout
        assert list(o.bk.glob("voor-terugzetten-*.dump")) == [safe]
        assert o.sql("SELECT version_num FROM alembic_version") == "oud"
        assert not o.dump.with_name(o.dump.name + ".bezig").exists()


async def test_fout_voor_het_weggooien_start_de_diensten_weer(tmp_path):
    async with aparte_database("tz_gestopt") as url:
        o = Omgeving(tmp_path, url, _pgbin(url))
        o.sql(*VOOR)
        o.maak_dump()
        o.sql(*NA)
        # De kopie van de database van nu mislukt (bv. de schijf loopt toch vol).
        (o.fake / "pg_dump").write_text("#!/bin/sh\necho 'pg_dump: error: schijf vol' >&2\nexit 1\n")
        (o.fake / "pg_dump").chmod(0o755)
        r = o.run()
        out = r.stdout + r.stderr
        assert r.returncode == 1, out
        assert "Er is niets veranderd: de database en de code zijn nog die van v1.1.0, de diensten draaien weer." in out
        assert o.systemctl() == [f"stop {DIENSTEN}", f"start {DIENSTEN}"]
        assert o.sql("SELECT version_num FROM alembic_version") == "nieuw"
        assert not list(o.bk.glob("voor-terugzetten-*")) and not o.dump.with_name(o.dump.name + ".bezig").exists()
        assert _git(o.app, "rev-parse", "HEAD") == o.nieuw


async def test_install_sh_van_de_oude_versie_mislukt(tmp_path):
    """De database en de code staan dan al op de oude versie: zeggen wat er nu moet, de diensten niet starten."""
    async with aparte_database("tz_install") as url:
        o = Omgeving(tmp_path, url, _pgbin(url))
        o.sql(*VOOR)
        o.maak_dump()
        o.sql(*NA)
        o.env["INSTALL_RC"] = "1"
        r = o.run()
        out = r.stdout + r.stderr
        assert r.returncode == 1, out
        assert "Terugzetten niet afgewerkt: install.sh van v1.0.0 mislukte." in out
        assert "De database staat al op v1.0.0, de code ook." in out and "homepage-diagnose" in out
        assert o.systemctl() == [f"stop {DIENSTEN}"]
        assert o.dump.with_name(o.dump.name + ".versie").exists()
        assert o.dump.with_name(o.dump.name + ".bezig").exists()
