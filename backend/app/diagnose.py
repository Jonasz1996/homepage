"""Diagnose-export (knop "diagnose ↓" onder !): één JSON-bestand om bij een foutmelding te voegen.

Erin: versies, de processen, het aandacht-overzicht, de instellingen-checklist, de fouten per integratie en per
achtergrondtaak, de laatste meldingen, tijdlijn en audit, wat de proefmodus zou doen, en de laatste 200 logregels
van de API, de worker en de syslog-ontvanger.

Alleen lezen: geen ensure_state, geen nieuwe VAPID-sleutels, en genegeerde punten worden hier niet opgeruimd (dat
doet routers/attention.overview wel). Geheimen komen er niet in. Versleutelde kolommen en AppState met geheimen
worden niet eens opgevraagd, behalve door known_secrets, dat ze alleen ontsleutelt om ze overal te maskeren. Wat
overblijft gaat door masking.mask_tree: de bekende geheimen (ook url-gecodeerd en als base64 van
gebruiker:wachtwoord) en alles wat op een token, sleutel of wachtwoord lijkt. IP-adressen en namen blijven staan.
"""

import asyncio
import contextlib
import importlib.metadata
import json
import logging
import os
import platform
import re
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi.encoders import jsonable_encoder
from sqlalchemy import or_, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession

from . import attention, logring, proef
from .config import get_settings
from .health import selfcheck as sc
from .integrations import REGISTRY
from .masking import basic, mask_tree, variants
from .models import (ApiConnection, AppState, AuditLog, CronJob, Event, HealRule, Notification, PushMonitor,
                     PushSubscription, Service, ServiceState, SshHost, SshKey, UpdateRun, User, WebhookSource)
from .monitoring import restoretest, upgrade, watchdog
from .routers import attention as attention_router, integrations as integ, versie
from .security import decrypt

log = logging.getLogger("homepage.api")

FORMAAT = 1
# De checklist vraagt de API van elke tegel en de rechten van de Proxmox-tokens: hoogstens zo lang.
SETUP_TIMEOUT = 25
LAST = 50
PROEF_EVENTS = 20
UPDATE_DAYS = 7
OUTPUT_TAIL = 2048
MAX_ERRORS = 30
# Elke tekst in de export hoogstens zo lang (begin en einde), zodat het maskeren snel blijft.
MAX_TEXT = 8000
PACKAGES = ("fastapi", "starlette", "uvicorn", "pydantic", "sqlalchemy", "alembic", "asyncpg", "httpx", "asyncssh",
            "cryptography")

# AppState die mee mag, telkens teruggebracht tot tijdstippen, fouten en aantallen: in de ruwe waarde staan soms
# megabytes aan hosts of pakketten.
BACKGROUND = ("containerlogs", "zabbix", "npm_routes", "cluster", "coverage", "config_last", "devices", "health",
              "snapshots", "domains", "selfcheck", "diskguard", "updates", "cron", "restoretest", "massastoring",
              "update_auto_last")
BACKGROUND_PREFIX = ("net_gw:", "net_tunnel:", "pbs_problems:")
# Nooit mee, ook niet verkort: daar staan geheimen in (of wie wanneer van waar keek).
DENY = ("offsite_key", "webpush", "oidc", "ssh_defaults", "ssh_snippets", "ssh_pin", "attention_ack", "outside_seen")

# Wat van een AppState-waarde overblijft.
SCALARS = {"at", "checked_at", "scanned_at", "last_at", "since", "date", "started", "count", "items", "lines", "seen",
           "new", "changed", "failing", "total", "pct", "stale", "ok", "enabled", "down", "step"}
ERRORS = {"error", "errors", "cleanup_error"}
NAMES = ("key", "name", "service", "service_id", "vmid", "node")

# Sleutels in de geheimen van een tegel of API die geen geheim zijn: zo blijven token-ID's leesbaar.
USER_KEYS = ("username", "user", "action_username")
PAIRS = (("username", "password"), ("user", "password"), ("action_username", "action_password"))


def filename(at: datetime) -> str:
    return f"homepage-diagnose-{at.astimezone(timezone.utc).strftime('%Y%m%d-%H%M')}.json"


def _tail(t: str | None, n: int) -> str | None:
    """De laatste n tekens, zonder een half woord vooraan (een afgekapt token herkent het maskeren niet meer)."""
    if not t or len(t) <= n:
        return t
    return "… " + re.sub(r"^\S*", "", t[-n:])


async def _value(db: AsyncSession, key: str) -> dict:
    st = await db.get(AppState, key)
    return dict(st.value) if st and isinstance(st.value, dict) else {}


async def _rows(db: AsyncSession, stmt) -> list[dict]:
    return [dict(r._mapping) for r in (await db.execute(stmt)).all()]


# --- geheimen ---------------------------------------------------------------------------------------------------

def _bounded(x):
    if isinstance(x, str):
        return logring.bound(x, MAX_TEXT)
    if isinstance(x, dict):
        return {k: _bounded(v) for k, v in x.items()}
    if isinstance(x, list):
        return [_bounded(v) for v in x]
    return x


def _leaves(x) -> list[str]:
    if isinstance(x, str):
        return [x]
    if isinstance(x, dict):
        return [s for v in x.values() for s in _leaves(v)]
    if isinstance(x, list):
        return [s for v in x for s in _leaves(v)]
    return []


async def known_secrets(db: AsyncSession, counts: Counter | None = None) -> list[str]:
    """Elk geheim dat het dashboard bewaart, ontsleuteld: alleen om het in de export te maskeren, het gaat nergens
    anders heen. Wat niet te ontsleutelen is (bv. na een nieuwe secret.key) telt als "onleesbaar"."""
    out: list[str] = []
    bad = 0

    def dec(v) -> str | None:
        nonlocal bad
        if not v:
            return None
        try:
            return decrypt(v)
        except Exception:  # noqa: BLE001 - een andere sleutel of een kapotte waarde
            bad += 1
            return None

    def dec_json(v) -> dict:
        nonlocal bad
        s = dec(v)
        try:
            d = json.loads(s) if s else {}
        except ValueError:
            bad += 1
            return {}
        return d if isinstance(d, dict) else {}

    def pair(user, password) -> None:
        if isinstance(password, str) and password:
            out.append(password)
            if isinstance(user, str):
                out.append(basic(user, password) or "")

    def from_secrets(d: dict) -> None:
        for k, v in d.items():
            if k not in USER_KEYS:
                out.extend(_leaves(v))
        for u, p in PAIRS:
            pair(d.get(u), d.get(p))

    for col in (Service.secrets, ApiConnection.secrets):
        for v in (await db.execute(select(col).where(col.is_not(None)))).scalars():
            from_secrets(dec_json(v))
    for user, pw in (await db.execute(select(SshHost.username, SshHost.password)
                                      .where(SshHost.password.is_not(None)))).all():
        pair(user or "root", dec(pw))
    for v in (await db.execute(select(SshKey.private_key))).scalars():
        if pem := dec(v):
            # De hele sleutel, en elke regel apart (voor als hij ergens anders afgebroken staat).
            out.append(pem.strip())
            out.extend(s.strip() for s in pem.splitlines() if len(s.strip()) >= 16 and not s.startswith("-----"))
    for col in (WebhookSource.token, PushMonitor.token, User.totp_secret):
        for v in (await db.execute(select(col).where(col.is_not(None)))).scalars():
            out.append(dec(v) or "")
    for v in (await db.execute(select(PushSubscription.data))).scalars():
        d = dec_json(v)
        out.extend(_leaves(d))
        if isinstance(d.get("endpoint"), str):
            # Het laatste stuk van het pushadres is het eigenlijke geheim.
            out.append(d["endpoint"].rstrip("/").rsplit("/", 1)[-1])
    ssh = await _value(db, "ssh_defaults")
    pair(ssh.get("username") or "root", dec(ssh.get("password")))
    out.append(dec((await _value(db, "oidc")).get("client_secret")) or "")
    out.append(dec((await _value(db, "webpush")).get("private")) or "")
    s = get_settings()
    for f in (s.secret_key_file, s.setup_token_file):
        try:
            out.append(f.read_text().strip())
        except OSError:
            pass
    try:
        url = make_url(s.database_url)
        pair(url.username, url.password)
    except Exception:  # noqa: BLE001 - een vreemde url: dan niets om te maskeren
        pass
    if counts is not None and bad:
        counts["onleesbaar"] += bad
    return [v for v in out if isinstance(v, str) and v]


# --- onderdelen -------------------------------------------------------------------------------------------------

async def _database(db: AsyncSession) -> dict:
    out = {"soort": db.bind.dialect.name, "server_version": None, "timescaledb": None, "alembic": None,
           "hypertables": None, "grootte": None}
    if out["soort"] != "postgresql":
        return out
    out["server_version"] = (await db.execute(text("SHOW server_version"))).scalar()
    out["timescaledb"] = (await db.execute(text(
        "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'"))).scalar()
    # Een fout zou de hele transactie afbreken: elke vraag die kan mislukken in een savepoint.
    with contextlib.suppress(Exception):
        async with db.begin_nested():
            out["alembic"] = (await db.execute(text("SELECT version_num FROM alembic_version"))).scalar()
    if out["timescaledb"]:
        with contextlib.suppress(Exception):
            async with db.begin_nested():
                out["hypertables"] = sorted((await db.execute(text(
                    "SELECT hypertable_name FROM timescaledb_information.hypertables"))).scalars())
    out["grootte"] = await sc.db_size(db)
    return out


async def _versie(db: AsyncSession, user: User, frontend_nr: int | None) -> dict:
    packages = {}
    for name in PACKAGES:
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    return {**versie.installed(), "frontend_nieuws": frontend_nr,
            "gezien": (await _value(db, versie.STATE_KEY)).get(str(user.id)),
            "python": platform.python_version(), "systeem": platform.platform(terse=True), "venv": sys.prefix,
            "pakketten": packages, "database": await _database(db)}


async def _processen(db: AsyncSession, now: datetime) -> dict:
    hb = await _value(db, sc.HEARTBEAT_KEY)
    syslog = await _value(db, logring.state_key("syslog"))
    return {"api": {"pid": os.getpid(), "started": logring.started()},
            "worker": {**sc.worker_status(hb, now), "pid": hb.get("pid")},
            # De syslog-ontvanger meldt zich alleen via zijn logregels.
            "syslog": {k: syslog.get(k) for k in ("at", "pid", "started")},
            "worker_alert": await _value(db, "worker_alert"), "api_alert": await _value(db, watchdog.API_KEY),
            "healthz_seen": await _value(db, watchdog.SEEN_KEY)}


async def _instellingen(db: AsyncSession, user: User) -> dict:
    """Dezelfde stappen als GET /api/attention/setup, met een eigen sessie en een tijdslimiet: een API die blijft
    hangen mag de rest van de export niet tegenhouden (en een afgebroken vraag de sessie van het verzoek niet)."""
    s = AsyncSession(db.bind, expire_on_commit=False)
    try:
        return await asyncio.wait_for(attention_router.setup(user=user, db=s), SETUP_TIMEOUT)
    except asyncio.TimeoutError:
        return {"fout": "time-out"}
    except Exception as e:  # noqa: BLE001 - de rest van de export moet er toch komen
        log.exception("instellingen-checklist voor de diagnose mislukt")
        return {"fout": type(e).__name__}
    finally:
        with contextlib.suppress(Exception):
            await s.close()


async def _integraties(db: AsyncSession) -> list[dict]:
    """Per tegel met een API: de toestand van de check en de laatste fout van de API (zonder adres of sleutels)."""
    errors = integ.last_errors()
    rows = await _rows(db, select(
        Service.id, Service.name, Service.type, ApiConnection.kind.label("api_kind"),
        ApiConnection.name.label("api_name"), ServiceState.status, ServiceState.since, ServiceState.last_check,
        ServiceState.fail_count, ServiceState.last_error, ServiceState.stale)
        .outerjoin(ApiConnection, ApiConnection.id == Service.api_id)
        .outerjoin(ServiceState, ServiceState.service_id == Service.id)
        .where(or_(Service.type.in_(list(REGISTRY)), Service.api_id.is_not(None)))
        .order_by(Service.name, Service.id))
    for r in rows:
        kind, name = r.pop("api_kind"), r.pop("api_name")
        r["api"] = {"kind": kind, "name": name} if kind else None
        r["tegel_fout"] = errors.get(r["id"])
    return rows


def _errors(x):
    """Fouten zoals ze bewaard zijn (tekst, lijst of per naam), ingekort."""
    if isinstance(x, str):
        return logring.cut(x, 1000)
    if isinstance(x, list):
        return [_errors(i) for i in x[:MAX_ERRORS]]
    if isinstance(x, dict):
        return {str(k): _errors(v) for k, v in list(x.items())[:MAX_ERRORS]}
    return x


def brief(value: dict, depth: int = 0) -> dict:
    """Een AppState-waarde teruggebracht tot tijdstippen, fouten en aantallen. Een lijst wordt een aantal, plus de
    rijen met een fout (alleen hun naam en de fout)."""
    out = {}
    for k, x in value.items():
        if k in ERRORS:
            out[k] = _errors(x)
        elif x is None or isinstance(x, (str, int, float, bool)):
            if k in SCALARS:
                out[k] = logring.cut(x, 200) if isinstance(x, str) else x
        elif isinstance(x, list) and depth == 0:
            bad = [{**{n: i[n] for n in NAMES if n in i}, "error": _errors(i["error"])}
                   for i in x if isinstance(i, dict) and i.get("error")]
            out[k] = {"aantal": len(x), **({"fouten": bad[:MAX_ERRORS]} if bad else {})}
        elif isinstance(x, dict) and depth == 0:
            if sub := brief(x, 1):
                out[k] = sub
    return out


def _selfcheck(v: dict) -> dict:
    off, size = v.get("offsite") or {}, v.get("db") or {}
    return {"checked_at": v.get("checked_at"), "stale": v.get("stale"), "backup_dir": v.get("backup_dir"),
            "backups": (v.get("backups") or [])[:3], "verified": v.get("verified"), "disks": v.get("disks"),
            "db": {"total": size.get("total"), "tables": (size.get("tables") or [])[:5]},
            "offsite": {k: off.get(k) for k in ("enabled", "dir", "at", "count", "error")}, "alerts": v.get("alerts")}


def _restoretest(v: dict) -> dict:
    history = [h for h in v.get("history") or [] if isinstance(h, dict)]
    out = brief({k: x for k, x in v.items() if k not in ("history", "dry_history", "settings")})
    out["tests"] = len(history)
    if history:
        out["laatste"] = {k: history[0].get(k) for k in ("at", "ok", "manual", "step", "error", "cleanup_error",
                                                          "seconds", "name", "source_vmid", "vmid", "node")}
    return out


def _pbs(v: dict) -> dict:
    items = v.get("items") or {}
    return {"aantal": len(v.get("keys") or items), "problemen": _errors(list(items.values()))}


async def _achtergrond(db: AsyncSession) -> dict:
    """Wat de achtergrondtaken laatst vonden (alleen de sleutels uit BACKGROUND, nooit iets uit DENY)."""
    rows = (await db.execute(select(AppState).where(or_(
        AppState.key.in_(BACKGROUND), *[AppState.key.startswith(p, autoescape=True) for p in BACKGROUND_PREFIX]))
        .order_by(AppState.key))).scalars()
    out = {}
    for st in rows:
        v = st.value if isinstance(st.value, dict) else {}
        if st.key == "selfcheck":
            out[st.key] = _selfcheck(v)
        elif st.key == restoretest.STATE_KEY:
            out[st.key] = _restoretest(v)
        elif st.key.startswith("pbs_problems:"):
            out[st.key] = _pbs(v)
        else:
            out[st.key] = brief(v)
    return out


async def _updates(db: AsyncSession, now: datetime) -> list[dict]:
    rows = await _rows(db, select(
        UpdateRun.id, UpdateRun.target, UpdateRun.target_name, UpdateRun.trigger, UpdateRun.security_only,
        UpdateRun.status, UpdateRun.exit_code, UpdateRun.reboot_needed, UpdateRun.checks, UpdateRun.error,
        UpdateRun.output, UpdateRun.created_at, UpdateRun.started_at, UpdateRun.finished_at, UpdateRun.rolled_back_at)
        .where(UpdateRun.created_at >= now - timedelta(days=UPDATE_DAYS))
        .order_by(UpdateRun.created_at.desc(), UpdateRun.id.desc()).limit(100))
    for r in rows:
        r["error"] = _tail(r["error"], OUTPUT_TAIL)
        r["output"] = _tail(r["output"], OUTPUT_TAIL)
    return rows


def _heal(rules: list[HealRule]) -> list[dict]:
    # De parameters van een actie niet: alleen wat de regel doet.
    return [{"id": r.id, "service_id": r.service_id, "enabled": r.enabled, "after": r.after,
             "max_per_hour": r.max_per_hour,
             "actie": {k: (r.action or {}).get(k) for k in ("kind", "action", "op", "name", "label", "service_id",
                                                             "host_id") if (r.action or {}).get(k) is not None},
             "last_at": r.last_at, "last_result": r.last_result, "dry_run": bool(getattr(r, "dry_run", False))}
            for r in rules]


async def _proef(db: AsyncSession, rules: list[HealRule]) -> dict:
    """Welke automatische runs alleen als proef lopen, en wat ze laatst zouden gedaan hebben. Elke vlag met een
    standaardwaarde: wie ze nog niet kent (een oudere stand), heeft ze uit."""
    upd = await _value(db, upgrade.SETTINGS_KEY)
    rt = await _value(db, restoretest.STATE_KEY)
    dry = [h for h in rt.get("dry_history") or [] if isinstance(h, dict)]
    dry.sort(key=lambda h: str(h.get("at") or ""), reverse=True)
    events = await _rows(db, select(Event.id, Event.ts, Event.kind, Event.level, Event.title, Event.service_id,
                                    Event.body, Event.data)
                         .where(Event.title.startswith(proef.EVENT_PREFIX, autoescape=True))
                         .order_by(Event.ts.desc(), Event.id.desc()).limit(PROEF_EVENTS))
    for e in events:
        plan = (e.pop("data") or {}).get("plan")
        if plan:
            e["plan"] = plan
            del e["body"]  # dezelfde inhoud als tekst
    return {"vlaggen": {"update_settings.proef": bool(upd.get("proef", False)),
                        "update_settings.cleanup_proef": bool(upd.get("cleanup_proef", False)),
                        "heal_rules.dry_run": sum(1 for r in rules if getattr(r, "dry_run", False)),
                        "restoretest.dry": bool(restoretest.settings(rt).get("dry", False))},
            "update_auto_proef": await _value(db, "update_auto_proef") or None,
            "update_cleanup_proef": await _value(db, "update_cleanup_proef") or None,
            "restoretest_dry_history": dry[:3], "tijdlijn": events}


async def _logs(db: AsyncSession) -> dict:
    out = {"api": {"pid": os.getpid(), "started": logring.started(), "regels": logring.lines(logring.EXPORT)}}
    for role in ("worker", "syslog"):
        v = await _value(db, logring.state_key(role))
        out[role] = {"at": v.get("at"), "pid": v.get("pid"), "started": v.get("started"),
                     "regels": (v.get("lines") or [])[-logring.EXPORT:]}
    out["tip"] = ("De worker en de syslog-ontvanger bewaren hun regels elke minuut. Wat vlak voor een crash kwam, "
                  "staat in journald: journalctl -u homepage-worker -n 200 (of homepage-api, homepage-syslog), als "
                  "root op de container.")
    return out


# --- samen ------------------------------------------------------------------------------------------------------

async def build(db: AsyncSession, user: User, frontend_nr: int | None = None) -> dict:
    """De hele export, gemaskeerd en klaar voor JSON. Schrijft niets."""
    now = datetime.now(timezone.utc)
    # Eerst de checklist: die vraagt de API's van de tegels (en vult zo ook de fouten per tegel aan). De sessie van
    # het verzoek houdt intussen geen transactie open.
    await db.close()
    setup = await _instellingen(db, user)
    rules = list((await db.execute(select(HealRule).order_by(HealRule.id))).scalars())
    aandacht = await attention.collect(db, integ.last_errors())
    aandacht.pop("stale", None)
    export = {
        "formaat": FORMAAT,
        "gemaakt": now.isoformat(),
        "bestand": filename(now),
        "versie": await _versie(db, user, frontend_nr),
        "processen": await _processen(db, now),
        "aandacht": aandacht,
        "instellingen": setup,
        "integraties": await _integraties(db),
        "achtergrond": await _achtergrond(db),
        "webhooks": await _rows(db, select(
            WebhookSource.id, WebhookSource.name, WebhookSource.kind, WebhookSource.enabled, WebhookSource.service_id,
            WebhookSource.created_at, WebhookSource.last_at, WebhookSource.count, WebhookSource.last_error)
            .order_by(WebhookSource.id)),
        "pushtoestellen": await _rows(db, select(
            PushSubscription.id, PushSubscription.label, PushSubscription.min_level, PushSubscription.created_at,
            PushSubscription.last_ok_at, PushSubscription.fail_count, PushSubscription.last_error,
            PushSubscription.warned, PushSubscription.gone_at).order_by(PushSubscription.id)),
        "zelfherstel": _heal(rules),
        "updates": await _updates(db, now),
        # Zonder het commando zelf: daar staat soms een wachtwoord in.
        "cron": await _rows(db, select(
            CronJob.id, CronJob.target_name, CronJob.name, CronJob.alias, CronJob.kind, CronJob.schedule,
            CronJob.last_status, CronJob.last_exit, CronJob.last_run_at, CronJob.monitored, CronJob.muted)
            .where(CronJob.removed_at.is_(None), CronJob.last_status.in_(("fout", "gemist")))
            .order_by(CronJob.target_name, CronJob.id)),
        "meldingen": await _rows(db, select(
            Notification.id, Notification.ts, Notification.level, Notification.source, Notification.title,
            Notification.body, Notification.service_id, Notification.read_at)
            .order_by(Notification.ts.desc(), Notification.id.desc()).limit(LAST)),
        "tijdlijn": await _rows(db, select(Event.id, Event.ts, Event.kind, Event.level, Event.title, Event.body,
                                           Event.service_id).order_by(Event.ts.desc(), Event.id.desc()).limit(LAST)),
        "audit": await _rows(db, select(AuditLog.id, AuditLog.ts, AuditLog.user_id, AuditLog.action, AuditLog.detail,
                                        AuditLog.ip).order_by(AuditLog.ts.desc(), AuditLog.id.desc()).limit(LAST)),
        "proef": await _proef(db, rules),
        "logs": await _logs(db),
    }
    counts: Counter = Counter()
    known = variants(await known_secrets(db, counts))
    # Eerst alles tekst (tijdstippen ook), dan maskeren: zo ontsnapt er niets via de JSON-codering.
    out = mask_tree(_bounded(jsonable_encoder(export)), known, counts)
    out["gemaskeerd"] = dict(sorted(counts.items()))
    return out
