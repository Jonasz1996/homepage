"""De vangnetten van install.sh: een log van elke keer, de versie van TimescaleDB en de grootte naast elke kopie van
voor een update, genoeg verbindingen in PostgreSQL voor de pools van de diensten, en nakijken of de drie diensten na
het herstarten ook draaien.

Zoals test_install_lan: de echte stukken uit deploy/install.sh in bash, met nep-systemctl, -psql, -curl en -sleep waar
het om root of systemd gaat, en tegen een echte database waar het om de kopie gaat.
"""

import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest
from sqlalchemy.engine import make_url

from .conftest import TEST_DB
from .test_install_lan import SCRIPT, _functie

pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("python3") is None,
                                reason="bash of python3 ontbreekt")
TEXT = "\n".join(SCRIPT)


def _blok(begin: str, eind: str) -> str:
    """Van de eerste regel die met begin start tot en met de eerste regel daarna die precies eind is."""
    start = next(i for i, line in enumerate(SCRIPT) if line.startswith(begin))
    return "\n".join(SCRIPT[start:SCRIPT.index(eind, start) + 1])


def _fake(d: Path, **scripts: str) -> Path:
    d.mkdir(exist_ok=True)
    for name, body in scripts.items():
        (d / name).write_text(body)
        (d / name).chmod(0o755)
    return d


def _bash(script: str, env: dict, stdin: str = "") -> subprocess.CompletedProcess:
    return subprocess.run(["bash", "-c", script], env=env, input=stdin, capture_output=True, text=True, timeout=60)


# --- het log ------------------------------------------------------------------------------------------------------

LOG_BLOK = _blok("if install -d -m 750 \"$LOG_DIR\"", "fi")


def test_log_van_elke_keer(tmp_path):
    logs = tmp_path / "log"
    logs.mkdir()
    for i in range(12):
        (logs / f"install-202610{i + 1:02d}-120000.log").write_text("oud\n")
    script = "\n".join(["set -euo pipefail", f"LOG_DIR={shlex.quote(str(logs))}", 'INSTALL_LOG="" TEE_PID=""',
                        _functie("log_dicht"), LOG_BLOK,
                        'echo "stap 1"', 'read -r -p "Vraag: " x', 'echo "gelezen: $x"', 'echo "naar stderr" >&2',
                        "exit 3"])
    r = _bash(script, os.environ, stdin="ja\n")
    # De exitcode van het script, een vraag leest nog van stdin, en alles staat ook in het log.
    assert r.returncode == 3, r.stderr
    assert "stap 1" in r.stdout and "gelezen: ja" in r.stdout and "naar stderr" in r.stdout
    new = sorted(logs.glob("install-*.log"))
    assert len(new) == 10 and new[0].name == "install-20261004-120000.log"
    log = new[-1].read_text()
    assert new[-1].name.startswith("install-2") and "oud" not in log and new[-1].stat().st_mode & 0o777 == 0o600
    assert "stap 1\n" in log and "gelezen: ja\n" in log and "naar stderr\n" in log


def test_log_bij_een_fout(tmp_path):
    """Wat bij_fout nog schrijft (de reden, waar het log staat), komt ook in het log, voor het afgesloten wordt."""
    logs = tmp_path / "log"
    script = "\n".join(["set -euo pipefail", f"LOG_DIR={shlex.quote(str(logs))}", f"APP_DIR={shlex.quote(str(tmp_path))}",
                        'TERUG_NAAR="" GESTOPT="" GEWISSELD="" KLAAR="" REDEN="" VENV_OUD="" VERSIE="" DUMP=""',
                        'INSTALL_LOG="" TEE_PID=""', 'afbreken() { REDEN=$1; exit 1; }',
                        *map(_functie, ("warn", "log_dicht", "bij_fout")), LOG_BLOK, "trap bij_fout EXIT",
                        'echo "bezig"', 'afbreken "Kapot met opzet."'])
    r = _bash(script, os.environ)
    assert r.returncode == 1 and "Kapot met opzet." in r.stdout
    log = next(logs.glob("install-*.log"))
    text = log.read_text()
    assert "bezig" in text and "Kapot met opzet." in text and f"Alles van deze keer staat ook in {log}." in text
    assert "Afgebroken, de database is niet veranderd." in text


def test_log_vooraan_en_terugzetten_roept_het_aan():
    # Na de controle op root en de map, voor er iets gebeurt; bij_fout sluit het af bij elke exit.
    assert TEXT.index('[ -d "$APP_DIR/backend" ]') < TEXT.index(LOG_BLOK) < TEXT.index("trap bij_fout EXIT")
    bij_fout = _functie("bij_fout")
    assert bij_fout.count("log_dicht") == 3 and bij_fout.count("exit") == 3
    # homepage-terugzetten roept install.sh gewoon aan: de exitcode komt erdoor.
    t = (Path(SCRIPT_PATH()).parent / "terugzetten.sh").read_text()
    assert 'bash "$APP_DIR/deploy/install.sh" || afbreken' in t


def SCRIPT_PATH() -> str:
    return str(Path(__file__).resolve().parents[2] / "deploy" / "install.sh")


# --- de versie van TimescaleDB en de grootte naast de kopie ---------------------------------------------------------

VERSIE_BLOK = _blok("    # Naast de kopie: welke versie erbij hoort", "    fi")


@pytest.mark.skipif(TEST_DB.startswith("sqlite"), reason="met PostgreSQL")
def test_versie_naast_de_kopie(tmp_path):
    url = make_url(TEST_DB)
    # runuser als postgres, met de testdatabase in plaats van homepage.
    fake = _fake(tmp_path / "bin", runuser='#!/usr/bin/env bash\n[ "$1" = -u ] && shift 2\n[ "$1" = -- ] && shift\n'
                 'a=()\nwhile [ $# -gt 0 ]; do\n  if [ "$1" = -d ] && [ "${2:-}" = homepage ]; then a+=(-d "$RUNUSER_DB")'
                 '; shift 2\n  else a+=("$1"); shift; fi\ndone\nexec "${a[@]}"\n')
    env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "PGHOST": url.host or "",
           "PGPORT": str(url.port or 5432), "PGUSER": url.username or "", "PGPASSWORD": url.password or "",
           "RUNUSER_DB": url.database}
    dump = tmp_path / "voor-update-20261017-120000.dump"
    script = "\n".join(["set -euo pipefail", f"DUMP={shlex.quote(str(dump))}", "PREV_COMMIT=abc1234def",
                        "PREV_VERSIE=v1.2.3", VERSIE_BLOK])
    r = _bash(script, env)
    assert r.returncode == 0, r.stderr
    ts = subprocess.run(["psql", "-XAtqd", url.database, "-c",
                         "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"], env=env,
                        capture_output=True, text=True).stdout.strip()
    lines = Path(f"{dump}.versie").read_text().splitlines()
    assert lines[:3] == ["commit=abc1234def", "versie=v1.2.3", f"timescaledb={ts}"]
    assert re.fullmatch(r"grootte=\d{6,}", lines[3]) and len(lines) == 4
    # homepage-terugzetten leest net die regels.
    t = (Path(SCRIPT_PATH()).parent / "terugzetten.sh").read_text()
    assert "s/^timescaledb=//p" in t and "s/^grootte=//p" in t


# --- max_connections ----------------------------------------------------------------------------------------------

PSQL = """#!/bin/sh
echo "$*" >> "$PSQL_LOG"
case "$*" in
  *"ALTER SYSTEM"*) echo "$*" | sed -n "s/.*max_connections = \\([0-9]*\\).*/max_connections = '\\1'/p" \\
                      >> "$PG_DATA/postgresql.auto.conf" ;;
  *"SHOW port"*) echo "${PG_POORT:-5432}" ;;
  *"SHOW data_directory"*) echo "$PG_DATA" ;;
  *superuser_reserved_connections*) echo "${PG_MAX:-100} 3" ;;
  *"SELECT 1"*) [ -z "$PG_KAPOT" ] || exit 2 ;;
esac
"""
VERBINDINGEN = "\n".join([*map(_functie, ("warn", "db_lokaal", "db_verbindingen", "pg_klaar")),
                          next(line for line in SCRIPT if line.startswith("VERBINDINGEN_MARGE="))])


def _verbindingen(tmp_path: Path, **env: str) -> tuple[subprocess.CompletedProcess, list[str], list[str], str]:
    data = tmp_path / "data"
    data.mkdir(exist_ok=True)
    (data / "postgresql.auto.conf").write_text("# Do not edit this file manually!\n")
    for f in ("psql.log", "systemctl.log"):
        (tmp_path / f).unlink(missing_ok=True)
    fake = _fake(tmp_path / "bin", psql=PSQL, runuser='#!/bin/sh\nshift 3\nexec "$@"\n',
                 systemctl='#!/bin/sh\necho "$*" >> "$SYSTEMCTL_LOG"\n[ "$*" != "restart postgresql" ] || '
                           '[ -z "$PG_START_KAPOT" ] || { rm -f "$PG_START_KAPOT"; exit 1; }\n',
                 sleep="#!/bin/sh\n")
    base = {k: v for k, v in os.environ.items() if not k.startswith("HOMEPAGE_")}
    r = _bash("set -euo pipefail\nCONF_DIR=/etc/homepage\n" + VERBINDINGEN + "\ndb_verbindingen",
              {**base, "PATH": f"{fake}:{os.environ['PATH']}", "PSQL_LOG": str(tmp_path / "psql.log"),
               "SYSTEMCTL_LOG": str(tmp_path / "systemctl.log"), "PG_DATA": str(data),
               "HOMEPAGE_DATABASE_URL": "postgresql+asyncpg://homepage@/homepage?host=/var/run/postgresql", **env})
    read = lambda f: (tmp_path / f).read_text().splitlines() if (tmp_path / f).exists() else []  # noqa: E731
    return r, read("psql.log"), read("systemctl.log"), (data / "postgresql.auto.conf").read_text()


def test_max_connections_genoeg(tmp_path):
    # Standaard 20 + 40 + 5 met 10 extra en 3 voor superusers: 78, ruim onder 100.
    r, psql, systemctl, _ = _verbindingen(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "max_connections 100: genoeg voor de diensten (65) en 10 extra." in r.stdout
    assert not [c for c in psql if "ALTER SYSTEM" in c] and systemctl == []


def test_max_connections_hoger_op_de_eigen_postgresql(tmp_path):
    r, psql, systemctl, auto = _verbindingen(tmp_path, HOMEPAGE_DB_POOL_WORKER="100", HOMEPAGE_DB_POOL_SYSLOG="0")
    # 20 + 100 + 1 (minstens één) + 10 + 3 = 134: naar boven afgerond op een tiental.
    assert r.returncode == 0, r.stderr
    assert "max_connections van 100 naar 140: de diensten openen samen tot 121 verbindingen" in r.stdout
    assert "-XAtq -c ALTER SYSTEM SET max_connections = 140" in psql
    assert systemctl == ["restart postgresql"] and "max_connections = '140'" in auto
    assert not (tmp_path / "data" / "postgresql.auto.conf.homepage-vorige").exists()


def test_max_connections_niet_op_een_andere_server(tmp_path):
    for url, poort in (("postgresql+asyncpg://homepage:pw@192.168.0.5/homepage", "5432"),
                       ("postgresql+asyncpg://homepage@localhost:5433/homepage", "5432"),
                       ("postgresql+asyncpg://homepage@/homepage?host=/var/run/postgresql&port=5433", "5432")):
        r, psql, systemctl, _ = _verbindingen(tmp_path, HOMEPAGE_DB_POOL_WORKER="100", HOMEPAGE_DATABASE_URL=url,
                                              PG_POORT=poort)
        assert r.returncode == 0, r.stderr
        assert "zet het op die server op minstens 140, of verklein de pools." in r.stdout, url
        assert not [c for c in psql if "ALTER SYSTEM" in c] and systemctl == [], url
    # Dezelfde poort op localhost: wel de eigen.
    r, psql, systemctl, _ = _verbindingen(tmp_path, HOMEPAGE_DB_POOL_WORKER="100", PG_POORT="5433",
                                          HOMEPAGE_DATABASE_URL="postgresql+asyncpg://homepage@127.0.0.1:5433/homepage")
    assert systemctl == ["restart postgresql"], r.stdout + r.stderr


def test_max_connections_terug_als_postgresql_niet_start(tmp_path):
    flag = tmp_path / "kapot"
    flag.write_text("")
    r, psql, systemctl, auto = _verbindingen(tmp_path, HOMEPAGE_DB_POOL_WORKER="100", PG_START_KAPOT=str(flag))
    assert r.returncode == 0, r.stderr
    assert "PostgreSQL startte niet met max_connections = 140 en staat weer op 100." in r.stdout
    assert systemctl == ["restart postgresql", "restart postgresql"] and "140" not in auto


def test_max_connections_onleesbare_pool(tmp_path):
    r, psql, systemctl, _ = _verbindingen(tmp_path, HOMEPAGE_DB_POOL_API="veel")
    assert r.returncode == 0 and "HOMEPAGE_DB_POOL_*=veel" in r.stdout and psql == [] and systemctl == []


def test_max_connections_zoals_db_py():
    """Dezelfde standaarden en namen als de pools zelf (config.py), en voor het herstarten van de diensten."""
    from app.config import Settings
    s = Settings()
    f = _functie("db_verbindingen")
    assert (f'"${{HOMEPAGE_DB_POOL_API:-{s.db_pool_api}}}" "${{HOMEPAGE_DB_POOL_WORKER:-{s.db_pool_worker}}}" '
            f'"${{HOMEPAGE_DB_POOL_SYSLOG:-{s.db_pool_syslog}}}"') in f
    assert "(n > 0 ? n : 1)" in f  # pool_max: minstens 1
    assert TEXT.index("\ndb_verbindingen\n") < TEXT.index("\nsystemctl restart homepage-api homepage-worker "
                                                          "homepage-syslog\ndiensten_nakijken\n")


# --- de diensten na het herstarten -------------------------------------------------------------------------------

SYSTEMCTL = """#!/bin/sh
case "$1" in
  show) unit=$5; n=$(cat "$STATE/$unit.n" 2>/dev/null || echo 0); echo "$n"
        [ ! -f "$STATE/$unit.lus" ] || echo $((n + 1)) > "$STATE/$unit.n" ;;
  is-active) cat "$STATE/$2.state" 2>/dev/null || echo active ;;
esac
"""


def _diensten(tmp_path: Path, curl_rc: int = 0, **staat: str) -> subprocess.CompletedProcess:
    state = tmp_path / "state"
    shutil.rmtree(state, ignore_errors=True)
    state.mkdir()
    for unit, s in staat.items():
        unit = unit.replace("_", "-")
        if s == "lus":
            (state / f"{unit}.lus").write_text("")
        else:
            (state / f"{unit}.state").write_text(s + "\n")
    (tmp_path / "curl.log").unlink(missing_ok=True)
    fake = _fake(tmp_path / "bin", systemctl=SYSTEMCTL, sleep="#!/bin/sh\n",
                 curl=f'#!/bin/sh\necho "$*" >> "{tmp_path / "curl.log"}"\nexit {curl_rc}\n')
    script = "\n".join(["set -euo pipefail", _functie("warn"), 'afbreken() { echo "AFBREKEN: $1"; exit 1; }',
                        _functie("diensten_nakijken"), "diensten_nakijken"])
    return _bash(script, {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "STATE": str(state)})


def test_diensten_draaien(tmp_path):
    r = _diensten(tmp_path)
    assert r.returncode == 0, r.stderr
    assert "homepage-worker draait.\nhomepage-syslog draait.\nAPI draait." in r.stdout and "!!" not in r.stdout


def test_worker_die_telkens_herstart(tmp_path):
    # Telkens even "active" tussen twee crashes: NRestarts telt op.
    r = _diensten(tmp_path, homepage_worker="lus", homepage_syslog="activating")
    assert r.returncode == 0, r.stderr
    assert "homepage-worker draait niet (of herstart telkens opnieuw): journalctl -u homepage-worker -n 100 --no-pager" \
        in r.stdout
    assert "homepage-syslog draait niet (of herstart telkens opnieuw): journalctl -u homepage-syslog -n 100" in r.stdout
    assert "API draait." in r.stdout


def test_api_die_niet_antwoordt_is_een_fout(tmp_path):
    r = _diensten(tmp_path, curl_rc=7, homepage_api="activating")
    assert r.returncode == 1
    assert "AFBREKEN: De API reageert niet (activating): journalctl -u homepage-api -n 100 --no-pager" in r.stdout
    assert (tmp_path / "curl.log").read_text().count("http://127.0.0.1/api/ping") == 20


def test_installatie_installeert_de_nieuwe_commandos():
    assert 'install -m 755 "$APP_DIR/deploy/dumpinfo.sh" /usr/local/sbin/homepage-dumpinfo' in TEXT
    assert 'install -m 755 "$APP_DIR/deploy/diagnose.sh" /usr/local/sbin/homepage-diagnose' in TEXT
    assert "Wat er misloopt, in één bestand om te delen: homepage-diagnose." in TEXT


def test_herstelcommandos_meteen_na_het_bijwerken_van_de_database():
    """Mislukt er na het bijwerken van de database nog iets (nginx, de diensten), dan raadt bij_fout
    homepage-terugzetten aan: dat moet dan al dat van deze versie zijn, met homepage-dumpinfo en -herstelfouten erbij,
    en niet nog dat van de vorige (bij de eerste update naar deze versie: met de pipe naar grep -q)."""
    klaar = TEXT.index("\nKLAAR=1\n")
    for script, naam in (("terugzetten", "terugzetten"), ("herstelfouten", "herstelfouten"),
                         ("dumpinfo", "dumpinfo"), ("diagnose", "diagnose")):
        regel = f'\ninstall -m 755 "$APP_DIR/deploy/{script}.sh" /usr/local/sbin/homepage-{naam}\n'
        assert TEXT.count(regel) == 1, regel
        assert klaar < TEXT.index(regel) < TEXT.index('\nsay "nginx"\n'), regel
    # Daarvoor gaat een mislukte update helemaal terug, en is homepage-terugzetten niet nodig.
    assert "homepage-terugzetten." in _functie("bij_fout").split('if [ -n "$KLAAR" ]; then')[1].split("elif")[0]


def test_api_niet_na_een_update_zegt_hoe_terug(tmp_path):
    """Na het bijwerken van de database blijft de nieuwe versie staan; de kopie van voor de update is er nog."""
    dump = tmp_path / "voor-update-20261017-120000.dump"
    dump.write_text("")
    Path(f"{dump}.versie").write_text("commit=abc\nversie=v1\n")
    fake = _fake(tmp_path / "bin", systemctl=f'#!/bin/sh\necho "$*" >> "{tmp_path / "systemctl.log"}"\n'
                 'case "$1" in show) echo 0 ;; is-active) echo failed ;; esac\n',
                 sleep="#!/bin/sh\n", curl="#!/bin/sh\nexit 7\n")
    script = "\n".join(["set -euo pipefail", f"APP_DIR={shlex.quote(str(tmp_path))}",
                        'TERUG_NAAR="abc" GESTOPT=1 GEWISSELD=1 KLAAR=1 REDEN="" VENV_OUD="" VERSIE="v2"',
                        f"DUMP={shlex.quote(str(dump))}", 'INSTALL_LOG="" TEE_PID=""',
                        'afbreken() { REDEN=$1; exit 1; }', *map(_functie, ("warn", "log_dicht", "bij_fout")),
                        _functie("diensten_nakijken"), "trap bij_fout EXIT", "diensten_nakijken"])
    r = _bash(script, {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}"})
    assert r.returncode == 1
    assert "De API reageert niet (failed)" in r.stdout and "versie v2 blijft staan" in r.stdout
    assert "Of terug naar de vorige versie: homepage-terugzetten." in r.stdout
    # De kopie en haar versie blijven, de code ook.
    assert dump.exists() and Path(f"{dump}.versie").exists()
