"""homepage-diagnose (deploy/diagnose.sh): één tekstbestand over de installatie, ook als het dashboard zelf niet start,
en zonder geheimen.

Het script loopt hier echt, met eigen mappen als /etc/homepage, /var/backups/homepage en /var/log/homepage, en een
nep-systemctl, -journalctl, -curl, -nginx en -runuser die tonen wat er in een container zou staan, met geheimen in de
logregels zoals ze daar kunnen opduiken.
"""

import os
import re
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy.engine import make_url

from .conftest import BACKEND, TEST_DB

DEPLOY = BACKEND.parent / "deploy"
pytestmark = pytest.mark.skipif(subprocess.run(["bash", "-c", "sed --version"], capture_output=True).returncode != 0,
                                reason="GNU sed ontbreekt")

SECRET_KEY = Fernet.generate_key().decode()
SETUP = "a1b2c3d4e5f6a7b8c9d0e1f2"
DB_PW = "db-wachtwoord-geheim"
ENV_TOKEN = "env-token-0123456789"
PEM_BODY = ("b3BlbnNzaC1rZXktdjEAAAAABG5vbmU", "QUJDREVGR0hJSktMTU5PUFFSU1RVVldY")
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJlMTIz"
FERNET = "gAAAAABmZXJuZXQtdG9rZW4tZGF0YS0xMjM0NTY3"
# Wat er in journald kan staan: de bekende geheimen zelf, en wat er alleen op een geheim lijkt.
JOURNAL = f"""2026-10-17T12:00:00+0200 ct uvicorn[123]: Started homepage worker
2026-10-17T12:00:01+0200 ct python[123]: sleutel {SECRET_KEY} gelezen
2026-10-17T12:00:02+0200 ct python[123]: setup-code {SETUP}
2026-10-17T12:00:03+0200 ct python[123]: header Authorization: Bearer abcdefghijklmnopqrstuvwxyz
2026-10-17T12:00:04+0200 ct python[123]: GET /api/push/AbCdEfGhIjKlMnOpQrSt?status=up 200
2026-10-17T12:00:05+0200 ct python[123]: fout bij https://jonas:pw-in-url@example.com/x
2026-10-17T12:00:06+0200 ct python[123]: login met password=hunter2hunter2 mislukt
2026-10-17T12:00:07+0200 ct python[123]: PVEAPIToken=homepage@pve!dash=11111111-2222-3333-4444-555555555555
2026-10-17T12:00:08+0200 ct python[123]: sleutel -----BEGIN OPENSSH PRIVATE KEY-----
{PEM_BODY[0]}
{PEM_BODY[1]}
-----END OPENSSH PRIVATE KEY----- en verder
2026-10-17T12:00:09+0200 ct python[123]: jwt {JWT} en {FERNET}
2026-10-17T12:00:10+0200 ct python[123]: cookie hp_session=sessie-geheim-123; verbinding postgresql+asyncpg://homepage:{DB_PW}@db/homepage
2026-10-17T12:00:11+0200 ct python[123]: GET /api/x?token=urltoken123456&n=1 en {{"api_key": "json-sleutel-geheim"}}
2026-10-17T12:00:12+0200 ct python[123]: env {ENV_TOKEN}
"""
SECRETS = (SECRET_KEY, SETUP, DB_PW, ENV_TOKEN, "abcdefghijklmnopqrstuvwxyz", "AbCdEfGhIjKlMnOpQrSt", "pw-in-url",
           "hunter2hunter2", "11111111-2222-3333-4444-555555555555", *PEM_BODY, JWT, FERNET, "sessie-geheim-123",
           "urltoken123456", "json-sleutel-geheim", "commentaar-geheim")


def _omgeving(tmp: Path) -> dict:
    conf, bk, logs, fake, uit = (tmp / n for n in ("conf", "bk", "logs", "bin", "uit"))
    for d in (conf, bk, logs, fake, uit):
        d.mkdir()
    (conf / "secret.key").write_text(SECRET_KEY)
    (conf / "setup-token").write_text(SETUP + "\n")
    (conf / "versie").write_text("versie=v1.2.3\ncommit=abc123\nkanaal=stabiel\ndatum=2026-10-17T12:00:00+02:00\n")
    (conf / "nginx").write_text("lan=dicht\nreden=\nnpm=192.168.0.245\n")
    (conf / "homepage.env").write_text(
        f"# HOMEPAGE_OUD_PASSWORD=commentaar-geheim\n"
        f"HOMEPAGE_DATABASE_URL=postgresql+asyncpg://homepage:{DB_PW}@/homepage?host=/var/run/postgresql\n"
        f"HOMEPAGE_SITE_NAME=thuis-dashboard\nHOMEPAGE_PBS_TOKEN=\"{ENV_TOKEN}\"\n"
        f"HOMEPAGE_SECRET_KEY_FILE=/etc/homepage/secret.key\nHOMEPAGE_SMTP_PASSWORD=\nHOMEPAGE_DB_POOL_WORKER=40\n")
    (bk / "homepage-2026-10-17.dump").write_bytes(b"PGDMP")
    (bk / "voor-update-20261010-120000.dump").write_bytes(b"PGDMP")
    (bk / "voor-update-20261010-120000.dump.versie").write_text("commit=abc\nversie=v1.2.2\ntimescaledb=2.17.2\n")
    (bk / "backuptest").write_text("at=2026-10-01T04:15:00+00:00\nok=1\n")
    (logs / "install-20261001-100000.log").write_text("OUD-LOG\n")
    (logs / "install-20261017-120000.log").write_text(
        f"\x1b[1;37m==> Klaar (versie v1.2.3)\x1b[0m\nSetup-code voor het eerste account: {SETUP}\n")
    (tmp / "journal.txt").write_text(JOURNAL)
    scripts = {
        "runuser": '#!/bin/sh\n[ "$1" = -u ] && shift 2\n[ "$1" = -- ] && shift\nexec "$@"\n',
        "systemctl": '#!/bin/sh\ncase "$1" in\n  status) echo "● $3 - dienst"; echo "     Active: active (running)";;\n'
                     '  show) echo "ActiveState=active"; echo "NRestarts=0";;\n  *) echo "systemctl $*";;\nesac\n',
        "journalctl": f'#!/bin/sh\ncat "{tmp / "journal.txt"}"\n',
        "curl": '#!/bin/sh\nprintf \'{"ok":true} (HTTP 200)\\n\'\n',
        "nginx": '#!/bin/sh\necho "nginx: configuration file /etc/nginx/nginx.conf test is successful" >&2\n',
    }
    for name, body in scripts.items():
        (fake / name).write_text(body)
        (fake / name).chmod(0o755)
    env = {**os.environ, "PATH": f"{fake}:{os.environ['PATH']}", "DIAGNOSE_DIR": str(uit), "DIAGNOSE_CONF": str(conf),
           "DIAGNOSE_BK": str(bk), "DIAGNOSE_LOGS": str(logs), "DIAGNOSE_APP": str(tmp / "app"),
           # Geen PostgreSQL: een socket die er niet is (de test met PostgreSQL staat hieronder).
           "PGHOST": str(tmp / "geen-socket"), "PGDATABASE": "homepage"}
    return env


def _diagnose(env: dict) -> tuple[Path, str, str]:
    r = subprocess.run(["bash", str(DEPLOY / "diagnose.sh")], env=env, capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    out = Path(r.stdout.splitlines()[0])
    return out, out.read_text(), r.stdout


def test_diagnose_zonder_geheimen(tmp_path):
    env = _omgeving(tmp_path)
    out, text, stdout = _diagnose(env)
    # Eén bestand, alleen voor wie het maakte, en het pad op de terminal.
    assert out.parent == Path(env["DIAGNOSE_DIR"]) and re.fullmatch(r"homepage-diagnose-\d{8}-\d{6}\.txt", out.name)
    assert stat.S_IMODE(out.stat().st_mode) == 0o600 and "Kijk het na voor je het deelt" in stdout
    for s in SECRETS:
        assert s not in text, s
    # Wat er in moet staan.
    for kop in ("Versies", "Diensten", "API", "Schijf en geheugen", "PostgreSQL", "Back-ups", "Configuratie",
                "Laatste install-log", "journald: homepage-api", "journald: homepage-worker", "journald: homepage-syslog",
                "journald: postgresql", "journald: nginx"):
        assert f"===== {kop}" in text, kop
    assert "versie=v1.2.3" in text and '{"ok":true} (HTTP 200)' in text and "test is successful" in text
    assert "Started homepage worker" in text and "timescaledb=2.17.2" in text and "homepage-2026-10-17.dump" in text
    # homepage.env: de waarde van wat op een geheim lijkt nooit, de rest wel (met een wachtwoord in de url gemaskeerd).
    assert "HOMEPAGE_SITE_NAME=thuis-dashboard" in text and "HOMEPAGE_DB_POOL_WORKER=40" in text
    assert "HOMEPAGE_PBS_TOKEN=***" in text and "HOMEPAGE_SMTP_PASSWORD (leeg)" in text
    assert "HOMEPAGE_SECRET_KEY_FILE=***" in text and "HOMEPAGE_DATABASE_URL=postgresql+asyncpg://homepage:***@" in text
    # Het nieuwste install-log, zonder kleurcodes; het setup-token erin is gemaskeerd.
    assert "==> Klaar (versie v1.2.3)" in text and "\x1b[" not in text and "OUD-LOG" not in text
    assert "Setup-code voor het eerste account: ***" in text
    # Wat van de geheimen overblijft: de namen en wat errond staat.
    assert "-----BEGIN PRIVATE KEY----- ***" in text and "-----END PRIVATE KEY----- en verder" in text
    assert "PVEAPIToken=" in text and "/api/push/***" in text and "https://jonas:***@example.com" in text
    # PostgreSQL is er niet: dat staat erin, en de rest is er toch.
    assert "SHOW max_connections" in text and "(code " in text


def test_een_sleutel_zonder_einde_laat_de_rest_weg(tmp_path):
    env = _omgeving(tmp_path)
    (tmp_path / "journal.txt").write_text("begin\n-----BEGIN RSA PRIVATE KEY-----\n" + "QUJD" * 10 + "\n"
                                          + "".join(f"regel {i}\n" for i in range(250)))
    _, text, _ = _diagnose(env)
    assert "QUJD" not in text and "privésleutel zonder einde" in text and "regel 199" not in text


@pytest.mark.skipif(TEST_DB.startswith("sqlite"), reason="met PostgreSQL")
def test_diagnose_met_postgresql(tmp_path):
    url = make_url(TEST_DB)
    env = {**_omgeving(tmp_path), "PGHOST": url.host or "", "PGPORT": str(url.port or 5432),
           "PGUSER": url.username or "", "PGPASSWORD": url.password or "", "PGDATABASE": url.database}
    max_conn = subprocess.run(["psql", "-XAtqc", "SHOW max_connections"], env=env, capture_output=True,
                              text=True).stdout.strip()
    assert max_conn
    _, text, _ = _diagnose(env)
    blok = text.split("===== PostgreSQL =====\n")[1].split("\n===== ")[0]
    assert re.search(rf"\$ runuser -u postgres -- psql -X -d {url.database} -c SHOW max_connections\n"
                     rf" max_connections \n-+\n +{max_conn}\n", blok), blok
    assert "verbindingen" in blok and "alembic_version" in blok
    if url.password:
        assert url.password not in text
