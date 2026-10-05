"""Wie bewaakt de bewaker: nu Uptime Kuma weg is, is het dashboard de enige die storingen ziet.

- De worker kijkt elke minuut of er checks zijn die niet meer lopen, en of de API nog antwoordt.
- De API kijkt elke minuut of de worker leeft, en stuurt als die dood is zelf de meldingen naar de gsm.
- /api/healthz (zonder login, alleen thuis) zegt in één antwoord of database, worker en checks lopen: daarop zet
  je een HTTP-item in Zabbix, het enige dat ziet dat de hele container weg is.
- Na een herstart zegt de worker hoe lang het dashboard stil was.
"""

import asyncio
import ipaddress
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from starlette.requests import HTTPConnection

from ..config import get_settings
from ..db import ensure_state
from ..deps import event, notify
from ..health.selfcheck import HEARTBEAT_KEY, WORKER_STALE, check_worker, worker_status
from ..models import AppState, CheckResult, Service, ServiceState
from .engine import _aware, _fmt_duration, active

log = logging.getLogger("homepage.watchdog")

STALE_MIN = timedelta(minutes=5)
API_FAILS = 3
API_KEY = "api_alert"
SEEN_KEY = "healthz_seen"
WATCH_EVERY = 60
HEALTHZ_TTL = 5
_api_fails = 0
_healthz: tuple[float, bool, object] | None = None
_seen_saved = 0.0


def _local(dt: datetime) -> str:
    try:
        from zoneinfo import ZoneInfo
        return dt.astimezone(ZoneInfo("Europe/Brussels")).strftime("%d/%m %H:%M")
    except Exception:  # noqa: BLE001 - zonder tijdzonedata dan maar UTC
        return dt.strftime("%d/%m %H:%M UTC")


def _interval(check: dict) -> int:
    try:
        return max(int(check.get("interval") or 60), 15)
    except (TypeError, ValueError):
        return 60


async def stale_checks(db: AsyncSession, now: datetime | None = None) -> list[str]:
    """Lopende checks zonder recent resultaat: de tegel zou anders op zijn laatste kleur blijven staan (vals groen).
    Eén melding per check, of één samen als het er veel tegelijk zijn."""
    now = now or datetime.now(timezone.utc)
    svcs = {s.id: s for s in (await db.execute(select(Service))).scalars() if active(s.check)}
    if not svcs:
        return []
    states = (await db.execute(select(ServiceState).where(ServiceState.service_id.in_(list(svcs))))).scalars()
    names = []
    for st in states:
        last = _aware(st.last_check)
        if st.stale or last is None:
            continue
        limit = max(timedelta(seconds=3 * _interval(svcs[st.service_id].check)), STALE_MIN)
        if now - last > limit:
            st.stale = True
            st.status = "unknown"
            names.append(svcs[st.service_id].name)
    if len(names) == 1:
        notify(db, f"De check van {names[0]} loopt niet meer",
               "Er komt geen resultaat meer binnen, dus de tegel toont grijs in plaats van zijn laatste kleur. Op de "
               "container: journalctl -u homepage-worker -n 50", level="warn", source="homepage")
    elif names:
        shown = ", ".join(sorted(names)[:8]) + (" …" if len(names) > 8 else "")
        notify(db, f"{len(names)} checks lopen niet meer", f"{shown}. Op de container: journalctl -u homepage-worker "
               "-n 50", level="warn", source="homepage")
    return names


async def check_api(db: AsyncSession, client: httpx.AsyncClient) -> bool:
    """Vanuit de worker: antwoordt de API nog? Na drie keer niet één melding (de worker stuurt hem ook naar de gsm)."""
    global _api_fails
    try:
        r = await client.get(get_settings().api_url.rstrip("/") + "/api/ping", timeout=5, follow_redirects=False)
        ok = r.status_code == 200
    except httpx.HTTPError:
        ok = False
    _api_fails = 0 if ok else _api_fails + 1
    flag = await db.get(AppState, API_KEY)
    alerted = bool(flag and (flag.value or {}).get("down"))
    if _api_fails >= API_FAILS and not alerted:
        notify(db, "De API van de homepage antwoordt niet",
               "Het dashboard is niet te openen; de checks lopen wel door. Op de container: systemctl status "
               "homepage-api; journalctl -u homepage-api -n 50", level="err", source="homepage")
        (flag or await ensure_state(db, API_KEY)).value = {"down": True}
    elif ok and alerted:
        event(db, "gezondheid", "De API van de homepage antwoordt weer", level="ok")
        flag.value = {"down": False}
    return ok


async def report_gap(db: AsyncSession, started: datetime) -> None:
    """Bij het starten van de worker: hoe lang was het dashboard stil (geen hartslag)?"""
    hb = await db.get(AppState, HEARTBEAT_KEY)
    at = (hb.value or {}).get("at") if hb else None
    if not at:
        return
    last = _aware(datetime.fromisoformat(at))
    if started - last <= WORKER_STALE:
        return
    notify(db, f"Het dashboard was {_fmt_duration(started - last)} stil",
           f"Geen checks van {_local(last)} tot {_local(started)}. Wat in die tijd uitviel, heeft het dashboard niet "
           "gezien; die periode telt niet mee in de uptime.", level="warn", source="homepage")


# --- vanuit de API ------------------------------------------------------------------------------------------------

async def api_loop(maker: async_sessionmaker) -> None:
    """Elke minuut: leeft de worker? Zo niet, dan meldt de API dat (één keer) en stuurt hij de meldingen naar de
    gsm, want dat doet normaal de worker."""
    async with httpx.AsyncClient(timeout=10, follow_redirects=False) as client:
        while True:
            await asyncio.sleep(WATCH_EVERY)
            try:
                async with maker() as db:
                    status = await check_worker(db)
                    await db.commit()
                    if not status["ok"] and status["at"]:
                        from . import webpush
                        await webpush.run_webpush(db, client)
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("bewaking van de worker mislukt")


def is_outside(conn: HTTPConnection) -> bool:
    """Zonder database: via Cloudflare of vanaf een publiek IP. (healthz moet ook antwoorden als de database weg is.)"""
    if conn.headers.get("x-homepage-via-cf") == "1":
        return True
    try:
        return bool(conn.client) and ipaddress.ip_address(conn.client.host).is_global
    except ValueError:
        return False


async def healthy(db: AsyncSession, now: datetime | None = None) -> bool:
    """Database bereikbaar, worker leeft, en als er checks zijn: er kwam de laatste 5 minuten een resultaat binnen."""
    now = now or datetime.now(timezone.utc)
    await db.execute(text("SELECT 1"))
    hb = await db.get(AppState, HEARTBEAT_KEY)
    if not worker_status(hb.value if hb else None, now)["ok"]:
        return False
    polled = [s for s, c in (await db.execute(select(Service.id, Service.check))).all()
              if active(c) and c.get("type") != "push"]
    if not polled:
        return True
    newest = (await db.execute(select(func.max(CheckResult.ts)))).scalar()
    return newest is not None and now - _aware(newest) < STALE_MIN


async def healthz(conn: HTTPConnection, db: AsyncSession) -> bool | None:
    """None = van buitenaf (404), anders gezond of niet. Vijf seconden in het geheugen, zodat een poller niet elke
    keer de database vraagt. De sessie maakt pas verbinding bij het eerste verzoek: van buitenaf raakt dit de
    database dus niet."""
    global _healthz, _seen_saved
    if is_outside(conn):
        return None
    hit = _healthz
    if hit and hit[0] > time.monotonic() and hit[2] is db.bind:
        return hit[1]
    try:
        ok = await healthy(db)
        # Onthouden dat iets (Zabbix) dit opvraagt: de instellingen-checklist toont dat. Hoogstens elke 5 min.
        if time.monotonic() - _seen_saved > 300:
            _seen_saved = time.monotonic()
            st = await ensure_state(db, SEEN_KEY, {})
            st.value = {"at": datetime.now(timezone.utc).isoformat(), "ip": conn.client.host if conn.client else None}
            await db.commit()
    except Exception:  # noqa: BLE001 - database weg = niet gezond
        log.exception("healthz: database niet bereikbaar")
        ok = False
    _healthz = (time.monotonic() + HEALTHZ_TTL, ok, db.bind)
    return ok
