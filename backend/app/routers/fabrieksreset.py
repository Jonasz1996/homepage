"""Fabrieksreset: het hele dashboard wissen en opnieuw beginnen bij de eerste start (account aanmaken, 2FA, dan een
leeg dashboard met de welkomstappen).

Wat weg gaat: alles in de database. Tegels, pagina's, groepen, checks en hun geschiedenis, meldingen, logs, API's en
hun geheimen, SSH-hosts en -sleutels, cronjobs, webhooks, gsm's, instellingen (ook van buitenaf en aanmelden), de
achtergrond, sessies en het account zelf.

Wat blijft: de bestanden op de container. /etc/homepage (secret.key, setup-token, homepage.env), de dagelijkse
back-ups in /var/backups/homepage en de kopie buiten de container. Met een back-up van voor de reset en dezelfde
secret.key kan je dus alles terugzetten.

Bewaakt: alleen thuis (nooit van buitenaf, ook niet met een echte login), met een recente 2FA als aanmelden aan
staat, en alleen met de zin WIS ALLES in het verzoek. Vooraf kan je een volledige back-up downloaden."""

import asyncio
import contextlib
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.background import BackgroundTask

from .. import outside
from ..config import get_settings
from ..db import get_db
from ..deps import COOKIE, audit, current_user, recent_auth
from ..health.selfcheck import list_dumps
from ..models import (ApiConnection, AppState, Base, CheckResult, LogEntry, LogRule, Notification, Page, Service,
                      SshHost, User)

router = APIRouter(prefix="/api/fabrieksreset", tags=["fabrieksreset"])

ZIN = "WIS ALLES"
# Boekhouding die een leeg dashboard ook nodig heeft: tot waar de uurtotalen opgeteld zijn (de losse checks zijn
# toch weg, dus er valt niets dubbel te tellen).
KEEP_STATE = {"check_hourly"}
# Vanaf hier staan oude auditregels niet meer los op de tijdlijn (routers/timeline.py, migratie 0024).
LEGACY_KEY = "tijdlijn_audit_tot"
# Hoelang pg_dump mag duren.
DUMP_TIMEOUT = 600


class ResetIn(BaseModel):
    zin: str = Field(max_length=40)


async def _thuis(request: Request, db: AsyncSession) -> None:
    w = await outside.where(request, db)
    if w["outside"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "Een fabrieksreset (en de back-up ervoor) kan alleen thuis, nooit van buitenaf.")


async def _count(db: AsyncSession, model) -> int:
    return (await db.execute(select(func.count()).select_from(model))).scalar_one()


@router.get("")
async def preview(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Wat er weg zou gaan, of het van hier mag, en de laatste dagelijkse back-up."""
    w = await outside.where(request, db)
    dumps = list_dumps(get_settings().backup_dir)
    return {
        "thuis": not w["outside"],
        "zin": ZIN,
        "telling": {
            "paginas": await _count(db, Page),
            "tegels": await _count(db, Service),
            "apis": await _count(db, ApiConnection),
            "ssh_hosts": await _count(db, SshHost),
            "meldingen": await _count(db, Notification),
            "checks": await _count(db, CheckResult),
            "logregels": await _count(db, LogEntry),
        },
        "laatste_backup": dumps[0] if dumps else None,
        "backup_dir": str(get_settings().backup_dir),
        "backup_download": db.bind.dialect.name == "postgresql",
    }


# --- back-up vooraf --------------------------------------------------------------------------------------------------

# Zoals deploy/homepage-backup.sh: de logregels (en met TimescaleDB hun chunks) zonder inhoud, de rest volledig.
LOG_CHUNKS = """
WITH ch AS (
  SELECT show_chunks(format('%I.%I', hypertable_schema, hypertable_name)::regclass) AS rel
    FROM timescaledb_information.hypertables
   WHERE hypertable_schema = 'public' AND hypertable_name = 'log_entries'
), cat AS (
  SELECT to_jsonb(x) AS j FROM _timescaledb_catalog.chunk x
), rels AS (
  SELECT rel FROM ch
  UNION
  SELECT to_regclass(s.j ->> 'compress_relid')
    FROM (SELECT to_jsonb(x) AS j FROM _timescaledb_catalog.compression_settings x) s
    JOIN ch ON to_regclass(s.j ->> 'relid') = ch.rel
  UNION
  SELECT to_regclass(quote_ident(cc.j ->> 'schema_name') || '.' || quote_ident(cc.j ->> 'table_name'))
    FROM cat c JOIN cat cc ON cc.j -> 'id' = c.j -> 'compressed_chunk_id'
    JOIN ch ON to_regclass(quote_ident(c.j ->> 'schema_name') || '.' || quote_ident(c.j ->> 'table_name')) = ch.rel
)
SELECT format('%I.%I', n.nspname, r.relname)
  FROM rels JOIN pg_class r ON r.oid = rels.rel JOIN pg_namespace n ON n.oid = r.relnamespace
"""

# Pech met het moment (TimescaleDB verving een chunk tijdens de dump): nog eens proberen.
RETRY = ('does not exist', 'could not open relation with OID', 'cache lookup failed for relation')


def dump_command(url: str, out: str, exclude: list[str]) -> tuple[list[str], dict]:
    """pg_dump met de verbinding van de API zelf (meestal de socket, als gebruiker homepage)."""
    u = make_url(url)
    args = ["pg_dump", "-Fc", "-f", out]
    # De host kan ook als ?host=/pad/naar/socket in de URL staan (asyncpg).
    host = u.host or u.query.get("host")
    if isinstance(host, tuple):
        host = host[0]
    if host:
        args += ["-h", host]
    if u.port:
        args += ["-p", str(u.port)]
    if u.username:
        args += ["-U", u.username]
    args += [f"--exclude-table-data={t}" for t in ["public.log_entries", *exclude]]
    args.append(u.database or "homepage")
    env = {**os.environ}
    if u.password:
        env["PGPASSWORD"] = str(u.password)
    return args, env


async def _log_chunks(db: AsyncSession) -> list[str]:
    has = (await db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))).first()
    if not has:
        return []
    return [r[0] for r in (await db.execute(text(LOG_CHUNKS))).all() if r[0]]


@router.get("/backup", dependencies=[Depends(recent_auth)])
async def backup(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Een volledige back-up (pg_dump, zonder de logregels) om te downloaden, vlak voor de reset. Geheimen zitten er
    versleuteld in: terugzetten werkt met dezelfde /etc/homepage/secret.key."""
    await _thuis(request, db)
    if db.bind.dialect.name != "postgresql":
        raise HTTPException(status.HTTP_409_CONFLICT, "Alleen met PostgreSQL")
    exclude = await _log_chunks(db)
    await audit(db, request, user, "fabrieksreset-backup")
    await db.commit()
    fd, out = tempfile.mkstemp(prefix="homepage-voor-reset-", suffix=".dump")
    os.close(fd)
    args, env = dump_command(get_settings().database_url, out, exclude)
    for attempt in range(3):
        try:
            proc = await asyncio.create_subprocess_exec(*args, env=env, stdout=asyncio.subprocess.DEVNULL,
                                                        stderr=asyncio.subprocess.PIPE)
        except FileNotFoundError:
            Path(out).unlink(missing_ok=True)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "pg_dump staat niet op deze container") from None
        try:
            _, raw = await asyncio.wait_for(proc.communicate(), DUMP_TIMEOUT)
        except asyncio.TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                proc.kill()
            Path(out).unlink(missing_ok=True)
            raise HTTPException(status.HTTP_504_GATEWAY_TIMEOUT, "De back-up duurde te lang") from None
        if proc.returncode == 0:
            break
        err = raw.decode(errors="replace").strip()
        if attempt == 2 or not any(r in err for r in RETRY):
            Path(out).unlink(missing_ok=True)
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, f"pg_dump mislukte: {err[-300:]}")
        await asyncio.sleep(2)
    name = f"homepage-voor-reset-{datetime.now(timezone.utc):%Y-%m-%d-%H%M}.dump"
    return FileResponse(out, media_type="application/octet-stream", filename=name,
                        background=BackgroundTask(lambda: Path(out).unlink(missing_ok=True)))


# --- de reset zelf ----------------------------------------------------------------------------------------------------

def _clear_caches() -> None:
    """Wat de API in het geheugen bijhoudt over tegels en API's: na de reset hoort daar niets meer van te bestaan."""
    from ..integrations import cloudflare, npm, zabbix as zbx_integration
    from ..routers import integrations, monitoring as monitoring_router, netmap, search, zabbix
    from ..monitoring import integrationchecks
    from .. import nieuweservice, oidc

    for d in (integrations._cache, integrations._since, monitoring_router._uptime_all_cache, netmap._cache,
              search._cache, zabbix._cache, integrationchecks._cache, nieuweservice._guest_cache, oidc._cache,
              npm._tokens, cloudflare._zones, zbx_integration._auth_in_body):
        d.clear()


async def wipe(db: AsyncSession) -> None:
    """Alle tabellen leeg, en wat een verse installatie in de migraties meekrijgt opnieuw. Eén transactie."""
    tables = [t for t in reversed(Base.metadata.sorted_tables)]
    keep = [(s.key, s.value) for s in (await db.execute(select(AppState).where(AppState.key.in_(KEEP_STATE))))
            .scalars()]
    if db.bind.dialect.name == "postgresql":
        # TRUNCATE: meteen, ook voor miljoenen checks en logregels (en hypertables van TimescaleDB). Zonder RESTART
        # IDENTITY: nieuwe tegels krijgen nooit het nummer van een oude, zodat niets in het geheugen van de worker
        # (die per nummer onthoudt) aan een nieuwe tegel blijft hangen.
        for t in tables:
            await db.execute(text(f'TRUNCATE TABLE "{t.name}" CASCADE'))
    else:
        for t in tables:
            await db.execute(delete(t))
    now = datetime.now(timezone.utc)
    for key, value in keep:
        db.add(AppState(key=key, value=value))
    db.add(AppState(key=LEGACY_KEY, value={"tot": now.isoformat()}))
    # Zoals migratie 0004: alles vanaf 'crit' wordt een melding.
    db.add(LogRule(name="Kritieke meldingen", pattern=None, host=None, max_severity=2, level="err",
                   cooldown_minutes=10, enabled=True))


@router.post("", dependencies=[Depends(recent_auth)])
async def reset(data: ResetIn, request: Request, response: Response, user: User = Depends(current_user),
                db: AsyncSession = Depends(get_db)):
    await _thuis(request, db)
    if data.zin.strip().upper() != ZIN:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Typ {ZIN} om te bevestigen")
    who = user.username
    for attempt in range(3):
        try:
            await wipe(db)
            # Het enige spoor van daarvoor: wie het deed (zonder account erachter, dat is ook weg).
            await audit(db, request, None, "fabrieksreset", door=who)
            await db.commit()
            break
        except Exception as e:  # noqa: BLE001 - een deadlock met de worker: nog eens
            await db.rollback()
            if attempt == 2 or "deadlock" not in str(e).lower():
                raise
            await asyncio.sleep(1)
    _clear_caches()
    response.delete_cookie(COOKIE, path="/")
    # De setup-code staat in /etc/homepage/setup-token (de API mag die lezen). Wie de reset deed, krijgt hem meteen:
    # anders moet hij eerst in de container gaan kijken.
    try:
        code = get_settings().setup_token_file.read_text().strip() or None
    except OSError:
        code = None
    return {"ok": True, "setup_code": code}
