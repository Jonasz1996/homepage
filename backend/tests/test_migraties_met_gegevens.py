"""Een update met gegevens erin. De database staat op een oudere migratie (VAN) en heeft iets in elke tabel van toen,
met TimescaleDB ook oude metingen in gecomprimeerde chunks. Dan alle migraties tot de nieuwste, zoals install.sh bij
een update doet. Daarna moet alles er nog zijn, en moet het dashboard het kunnen lezen, ook de versleutelde geheimen.

Draait op PostgreSQL in een eigen database; in de CI ook op PostgreSQL met TimescaleDB (op die server maken de
migraties de hypertables zelf, zoals in productie). VAN hoger zetten (bv. op een release): vul() aanpassen aan het
schema van die migratie; de test zegt welke tabel er nog niets in heeft.
"""

import contextlib
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timedelta, timezone

import asyncssh
import pyotp
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.engine import URL, make_url
from sqlalchemy.ext.asyncio import AsyncConnection, async_sessionmaker, create_async_engine

from app.db import get_db
from app.main import app
from app.security import decrypt, encrypt, encrypt_json, hash_password, limiter

from .conftest import BACKEND, H, PASSWORD, TEST_DB

pytestmark = pytest.mark.skipif(TEST_DB.startswith("sqlite"), reason="productie draait op PostgreSQL")

# De migratie van "afronden": de eerste versie met de bootstrap-kanalen en homepage-terugzetten.
VAN = "0018"
TOTP = pyotp.random_base32()
PVE = {"password": "pve-geheim-wachtwoord", "username": "lees@pve!dashboard"}
WEBHOOK = "webhook-token-dat-geheim-blijft"
SSH_KEY = asyncssh.generate_private_key("ssh-ed25519", comment="homepage")
HYPERTABLES = ("check_results", "metrics", "log_entries", "readings")
# Metingen tellen vanaf hier: wat ouder is, mag een bewaarbeleid van TimescaleDB intussen opgeruimd hebben.
WINDOW = timedelta(days=80)


def alembic(url: URL, *args: str) -> None:
    r = subprocess.run([sys.executable, "-m", "alembic", *args], cwd=BACKEND, capture_output=True, text=True,
                       env={**os.environ, "HOMEPAGE_DATABASE_URL": url.render_as_string(hide_password=False)})
    assert r.returncode == 0, f"alembic {' '.join(args)}:\n{r.stderr[-4000:]}"


@contextlib.asynccontextmanager
async def aparte_database(suffix: str):
    """Een eigen database naast die van de andere tests (zoals in test_update_terugdraaien), na afloop weer weg."""
    url = make_url(TEST_DB)
    name = f"{url.database}_{suffix}"
    admin = create_async_engine(TEST_DB, isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield url.set(database=name)
    finally:
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        await admin.dispose()


async def _ins(conn: AsyncConnection, table: str, *rows: dict) -> None:
    cols = list(rows[0])
    names = ", ".join(f'"{c}"' for c in cols)
    await conn.execute(text(f'INSERT INTO "{table}" ({names}) VALUES ({", ".join(f":{c}" for c in cols)})'),
                       [{c: json.dumps(v) if isinstance(v, (dict, list)) else v for c, v in r.items()} for r in rows])


async def timescale(conn: AsyncConnection) -> bool:
    return bool((await conn.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))).scalar())


async def vul(conn: AsyncConnection, now: datetime) -> dict[str, int]:
    """Iets in elke tabel die er op VAN is, met alleen de kolommen van toen. Geeft de ids van de tegels terug."""
    d = lambda **kw: now - timedelta(**kw)  # noqa: E731
    await _ins(conn, "users", dict(id=1, username="jonas", password_hash=hash_password(PASSWORD),
                                   totp_secret=encrypt(TOTP), totp_enabled=True, created_at=d(days=200),
                                   last_login_at=d(days=1), last_login_ip="192.168.0.10", totp_last_step=None))
    await _ins(conn, "pages", dict(id=1, name="Thuis", icon=None, position=0), dict(id=2, name="Media", icon="mdi-tv",
                                                                                     position=1))
    await _ins(conn, "groups", dict(id=1, page_id=1, name="Infra", icon=None, position=0, collapsed=False),
               dict(id=2, page_id=2, name="Films", icon=None, position=0, collapsed=True))
    await _ins(conn, "api_connections", dict(
        id=1, name="NAS", category="opslag", kind="rest", template=None, url="https://nas.lan:5001", config={},
        secrets=encrypt_json({"password": "nas-geheim", "username": "dashboard"}), created_at=d(days=30),
        updated_at=d(days=30)))
    svc = dict(description=None, icon=None, config={}, secrets=None, created_at=d(days=100), updated_at=d(days=2),
               parent_id=None, maintenance_until=None, notes=None, api_id=None)
    http = {"type": "http", "interval": 60}
    await _ins(conn, "services",
               {**svc, "id": 1, "group_id": 1, "name": "pve50", "url": "https://192.168.0.50:8006", "position": 0,
                "type": "proxmox", "check": http, "config": {"node": "pve50"}, "secrets": encrypt_json(PVE),
                "notes": "de hoofdnode"},
               {**svc, "id": 2, "group_id": 1, "name": "plex", "url": "http://192.168.0.60:32400", "position": 1,
                "type": "link", "check": http, "parent_id": 1},
               {**svc, "id": 3, "group_id": 1, "name": "nas", "url": "https://nas.lan:5001", "position": 2,
                "type": "link", "check": {"type": "ping", "interval": 120}, "api_id": 1},
               {**svc, "id": 4, "group_id": 2, "name": "wiki", "url": "https://wiki.lan", "position": 0, "type": "link",
                "check": {}, "maintenance_until": d(hours=-1)})
    st = dict(latency_ms=12.0, fail_count=0, last_error=None, quiet=False, cert_expires_at=None, cert_notified=0)
    await _ins(conn, "service_state", {**st, "service_id": 1, "status": "up", "since": d(days=3), "last_check": d(minutes=1)},
               {**st, "service_id": 2, "status": "down", "since": d(minutes=20), "last_check": d(minutes=1),
                "fail_count": 3, "last_error": "Timeout", "latency_ms": None},
               {**st, "service_id": 3, "status": "up", "since": d(days=9), "last_check": d(minutes=2),
                "cert_expires_at": d(days=-20)})
    # 120 dagen checks van 3 tegels, om de 20 minuten: oude chunks, die met TimescaleDB gecomprimeerd worden.
    await conn.execute(text(
        "INSERT INTO check_results (service_id, ts, ok, latency_ms, status_code, error, maintenance) "
        "SELECT s, g, extract(epoch FROM g)::bigint % 17 <> 0, 10 + s, 200, NULL, false "
        "FROM unnest(ARRAY[1, 2, 3]) s, generate_series(CAST(:now AS timestamptz) - INTERVAL '120 days', "
        "CAST(:now AS timestamptz), INTERVAL '20 minutes') g"), {"now": now})
    await conn.execute(text(
        "INSERT INTO metrics (service_id, kind, name, ts, label, cpu, mem, mem_total, disk, disk_total, watts) "
        "SELECT 1, 'node', 'pve50', g, 'pve50', 0.25, 8000000000, 32000000000, 500000000000, 1000000000000, 35.5 "
        "FROM generate_series(CAST(:now AS timestamptz) - INTERVAL '10 days', CAST(:now AS timestamptz), "
        "INTERVAL '1 hour') g"), {"now": now})
    await conn.execute(text(
        "INSERT INTO log_entries (ts, host, source_ip, facility, severity, app, msg) "
        "SELECT g, 'pve50', '192.168.0.50', 4, 6, 'sshd', 'Accepted publickey for root' "
        "FROM generate_series(CAST(:now AS timestamptz) - INTERVAL '3 days', CAST(:now AS timestamptz), "
        "INTERVAL '10 minutes') g"), {"now": now})
    await conn.execute(text(
        "INSERT INTO readings (target, sensor, ts, value) SELECT 'ssh:1', 'cpu', g, 48.5 "
        "FROM generate_series(CAST(:now AS timestamptz) - INTERVAL '2 days', CAST(:now AS timestamptz), "
        "INTERVAL '1 hour') g"), {"now": now})
    await _ins(conn, "log_rules", dict(name="Schijffouten", pattern="I/O error", host=None, max_severity=3,
                                       level="warn", cooldown_minutes=30, enabled=True, created_at=d(days=40)))
    await _ins(conn, "app_state",
               dict(key="health_settings", updated_at=d(days=5),
                    value={"cpu_warn": 85, "disk_warn": 55, "snapshot_days": 14, "domains": [], "offsite": False}),
               dict(key="attention_ack", updated_at=d(days=1), value={"items": {}}),
               dict(key="selfcheck", updated_at=d(hours=1),
                    value={"checked_at": d(hours=1).isoformat(), "stale": False, "backups": []}))
    note = dict(body=None, service_id=None, read_at=None)
    await _ins(conn, "notifications",
               {**note, "ts": d(minutes=20), "level": "err", "title": "plex is down", "body": "Timeout",
                "source": "monitor", "service_id": 2},
               {**note, "ts": d(days=2), "level": "warn", "title": "Schijf van de homepage is 80% vol",
                "source": "homepage", "read_at": d(days=1)},
               {**note, "ts": d(days=3), "level": "info", "title": "Weekrapport", "source": "rapport"})
    await _ins(conn, "events", dict(ts=d(minutes=20), kind="storing", level="err", title="plex is down", body="Timeout",
                                    service_id=2, data={}, note="router herstart", note_at=d(minutes=5)),
               dict(ts=d(days=4), kind="backup", level="ok", title="Back-up gelukt", body=None, service_id=None,
                    data={"vmid": 101}, note=None, note_at=None))
    await _ins(conn, "audit_log", dict(ts=d(days=1), user_id=1, action="login", detail={}, ip="192.168.0.10"),
               dict(ts=d(hours=5), user_id=1, action="service_update", detail={"id": 2}, ip="192.168.0.10"))
    await _ins(conn, "revisions", dict(created_at=d(days=2), user_id=1, summary="Tegel plex gewijzigd",
                                       snapshot={"pages": [], "groups": [], "services": []}))
    await _ins(conn, "sessions", dict(id=hashlib.sha256(b"oude-sessie").hexdigest(), user_id=1, mfa_ok=True,
                                      created_at=d(days=30), expires_at=d(days=16), auth_at=d(days=30),
                                      ip="192.168.0.10", user_agent="Firefox", country=None, last_seen_at=d(days=20)))
    await _ins(conn, "ssh_keys", dict(id=1, name="homepage", public_key=SSH_KEY.export_public_key().decode(),
                                      private_key=encrypt(SSH_KEY.export_private_key().decode()),
                                      created_at=d(days=90)))
    await _ins(conn, "ssh_hosts", dict(id=1, name="pve50", host="192.168.0.50", port=22, username="root", key_id=1,
                                       password=None, host_key=None, service_id=1, position=0, created_at=d(days=90),
                                       last_used_at=d(days=1), updates="", folder="", source=None))
    await _ins(conn, "cron_jobs", dict(
        id=1, key="ssh:1:cron:root:backup", target="ssh:1", target_name="pve50", host_id=1, vmid=None, kind="cron",
        source="/var/spool/cron/crontabs/root", user="root", schedule="0 3 * * *", sched_type="cron",
        command="/usr/local/bin/backup.sh", raw="0 3 * * * /usr/local/bin/backup.sh", name="backup.sh", alias=None,
        enabled=True, system=False, wid=None, monitored=False, muted=False, targets=[], extra={}, tz="Europe/Brussels",
        next_run_at=d(hours=-10), last_run_at=d(hours=14), last_status="ok", last_exit=0, last_duration=12.5,
        runs_24h=1, first_seen=d(days=60), last_seen=d(minutes=10), removed_at=None))
    await _ins(conn, "cron_runs", *(dict(job_id=1, started_at=d(days=i, hours=14), ended_at=d(days=i, hours=14),
                                         exit_code=0, status="ok", trigger="schedule", output="klaar")
                                    for i in range(2)))
    await _ins(conn, "update_runs", dict(
        target="node:pve50", target_name="pve50", trigger="manual", security_only=False, status="ok", snapshot=None,
        exit_code=0, reboot_needed=False, checks=None, output="0 upgraded", error=None, user_id=1,
        created_at=d(days=3), started_at=d(days=3), finished_at=d(days=3), rolled_back_at=None))
    await _ins(conn, "heal_rules", dict(service_id=2, enabled=True, after=3, max_per_hour=2,
                                        action={"kind": "ssh", "host_id": 1, "op": "systemctl", "name": "plexmediaserver"},
                                        fired=[], last_at=None, last_result=None, created_at=d(days=10)))
    await _ins(conn, "config_versions", dict(item="opnsense:1", name="config.xml", kind="opnsense", ts=d(days=1),
                                             sha="a" * 64, size=11, added=1, removed=0, content=encrypt("<opnsense/>")))
    dev = dict(name=None, vendor="Raspberry Pi", hostname=None, ip="192.168.0.80", intf="lan", note=None, known=True,
               scan=False, ports=None, ports_at=None, first_seen=d(days=50), last_seen=d(minutes=5))
    await _ins(conn, "devices", {**dev, "mac": "dc:a6:32:00:00:01", "name": "pi"},
               {**dev, "mac": "aa:bb:cc:dd:ee:ff", "known": False, "vendor": None, "ip": "192.168.0.99"})
    await _ins(conn, "maintenance_windows", dict(name="Back-up venster", service_id=1, group_id=None, repeat="weekly",
                                                 start=d(days=7), minutes=60, weekdays=[6], enabled=True,
                                                 created_at=d(days=7)))
    await _ins(conn, "webhook_sources", dict(name="Proxmox", kind="proxmox",
                                             token_hash=hashlib.sha256(WEBHOOK.encode()).hexdigest(),
                                             token=encrypt(WEBHOOK), service_id=1, enabled=True, created_at=d(days=5),
                                             last_at=None, count=0, last_error=None))
    await _ins(conn, "api_calls", dict(connection_id=1, name="Info", method="GET", path="/webapi/query.cgi", query={},
                                       headers={}, body=None, show="tile", fields=[], table={}, confirm=False,
                                       position=0))
    # Ids hierboven zelf gekozen: de reeksen erachter mee, zoals na echt gebruik.
    for t in (await conn.execute(text("SELECT table_name FROM information_schema.columns "
                                      "WHERE table_schema = 'public' AND column_name = 'id'"))).scalars().all():
        seq = (await conn.execute(text("SELECT pg_get_serial_sequence(:t, 'id')"), {"t": f'"{t}"'})).scalar()
        if seq:
            await conn.execute(text(f'SELECT setval(CAST(:seq AS regclass), (SELECT max(id) FROM "{t}"))'),
                               {"seq": seq})


async def tel(conn: AsyncConnection, since: datetime) -> dict[str, int]:
    """Aantal rijen per tabel; van de metingen alleen die na `since`."""
    out = {}
    for t in (await conn.execute(text("SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' "
                                      "AND table_type = 'BASE TABLE' AND table_name <> 'alembic_version'"))).scalars():
        where = " WHERE ts >= :since" if t in HYPERTABLES else ""
        out[t] = (await conn.execute(text(f'SELECT count(*) FROM "{t}"{where}'), {"since": since} if where else {})
                  ).scalar_one()
    return out


async def bouw(url: URL, compress: bool = True) -> tuple[dict[str, int], datetime]:
    """Database op VAN met gegevens; met TimescaleDB de chunks van meer dan een dag oud gecomprimeerd, zoals het
    compressiebeleid doet. Geeft de aantallen per tabel van toen, en vanaf wanneer de metingen geteld zijn."""
    alembic(url, "upgrade", VAN)
    engine = create_async_engine(url)
    now = datetime.now(timezone.utc).replace(microsecond=0)
    try:
        async with engine.begin() as conn:
            await vul(conn, now)
        async with engine.begin() as conn:
            if compress and await timescale(conn):
                for t in ("check_results", "metrics", "log_entries"):
                    n = (await conn.execute(text(
                        f"SELECT count(compress_chunk(c, if_not_compressed => true)) "
                        f"FROM show_chunks('{t}', older_than => INTERVAL '1 day') c"))).scalar()
                    assert n > 0, t
            counts = await tel(conn, now - WINDOW)
    finally:
        await engine.dispose()
    empty = sorted(t for t, n in counts.items() if not n)
    assert not empty, f"vul() zet niets in {empty}: elke tabel van {VAN} hoort gegevens te hebben"
    return counts, now - WINDOW


async def test_update_met_gegevens():
    async with aparte_database("gegevens") as url:
        before, since = await bouw(url)
        alembic(url, "upgrade", "head")

        engine = create_async_engine(url)
        try:
            async with engine.connect() as conn:
                ts = await timescale(conn)
                if ts:  # de metingen zitten echt in gecomprimeerde chunks
                    assert (await conn.execute(text(
                        "SELECT count(*) FROM timescaledb_information.chunks WHERE hypertable_name = 'check_results' "
                        "AND is_compressed"))).scalar() > 0
                after = await tel(conn, since)
                # Tabellen van na VAN zijn nieuw (en leeg); wat er al was, is er nog, rij voor rij geteld.
                assert {t: after[t] for t in before} == before
                # 0019: oude meldingen gaan nooit meer naar de gsm.
                assert (await conn.execute(text(
                    "SELECT count(*) FROM notifications WHERE pushed_at IS NULL"))).scalar() == 0
                # De geheimen zijn nog te ontcijferen met dezelfde sleutel.
                secret = (await conn.execute(text("SELECT secrets FROM services WHERE id = 1"))).scalar()
                assert json.loads(decrypt(secret)) == PVE
                assert decrypt((await conn.execute(text("SELECT token FROM webhook_sources"))).scalar()) == WEBHOOK
        finally:
            await engine.dispose()
        # Modellen en database komen overeen, ook na een update met gegevens.
        alembic(url, "check")

        # Het dashboard op die database: inloggen met het wachtwoord en de 2FA van toen, en elk venster openen.
        engine = create_async_engine(url)
        maker = async_sessionmaker(engine, expire_on_commit=False)

        async def _db():
            async with maker() as s:
                yield s

        app.dependency_overrides[get_db] = _db
        limiter._fails.clear()
        try:
            async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test", headers=H) as c:
                r = await c.post("/api/auth/login", json={"username": "jonas", "password": PASSWORD,
                                                          "code": pyotp.TOTP(TOTP).now()})
                assert r.status_code == 200 and r.json()["mfa_ok"], r.text
                layout = (await c.get("/api/layout")).json()
                services = {s["name"]: s for p in layout["pages"] for g in p["groups"] for s in g["services"]}
                assert set(services) == {"pve50", "plex", "nas", "wiki"}
                assert services["pve50"]["secret_keys"] == ["password", "username"]
                assert services["plex"]["parent_id"] == 1 and services["nas"]["api_id"] == 1
                status = (await c.get("/api/status")).json()
                assert status["2"]["status"] == "down"
                for path in ("/api/services/1/history?range=30d", "/api/services/1/history?range=1y",
                             "/api/attention", "/api/attention/setup", "/api/health", "/api/logs?range=7d",
                             "/api/notifications", "/api/cron", "/api/apis", "/api/ssh/hosts", "/api/ssh/keys",
                             "/api/heal", "/api/maintenance/windows", "/api/webhooks", "/api/timeline",
                             "/api/configs/versions?item=opnsense:1", "/api/devices", "/api/updates/runs", "/api/capacity"):
                    r = await c.get(path)
                    assert r.status_code == 200, f"{path}: {r.status_code} {r.text[:300]}"
                hist = (await c.get("/api/services/1/history", params={"range": "30d"})).json()
                assert hist["uptime"] is not None
        finally:
            app.dependency_overrides.clear()
            await engine.dispose()
