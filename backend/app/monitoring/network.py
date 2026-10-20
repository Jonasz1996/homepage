"""Internet en stroom: WAN-gateways (OPNsense), Cloudflare-tunnels, het publieke IP en het verbruik per node.

De worker draait watch_network() elke 2 minuten en bewaart de laatste stand in AppState, zodat het
netwerkoverzicht in het dashboard meteen laadt. Een gateway of tunnel die van toestand verandert, geeft pas
een melding als de nieuwe toestand twee rondes na elkaar gezien wordt (geen meldingen bij één haperende ping).
"""

import logging
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import ensure_state
from ..deps import notify
from ..integrations import IntegrationError, build
from ..integrations.homeassistant import month_start
from ..models import AppState, Metric, Service
from .checks import HttpClients

log = logging.getLogger("homepage.worker")

NETWORK_EVERY = 120
PUBLIC_IP_EVERY = 300
# Volgorde: eerst Cloudflare zelf, dan een tweede bron als die niet antwoordt.
IP_SOURCES = ("https://1.1.1.1/cdn-cgi/trace", "https://api.ipify.org")
HISTORY = 20


async def _state(db: AsyncSession, key: str) -> AppState:
    # Worker en API (knop "vernieuwen") kunnen tegelijk dezelfde nieuwe sleutel aanmaken.
    return await ensure_state(db, key)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def debounce(prev: dict, items: dict[str, str]) -> tuple[dict, list[tuple[str, str | None, str]]]:
    """prev: {naam: {"status": bevestigd, "seen": kandidaat}}. Geeft de nieuwe toestand en de bevestigde
    wijzigingen (naam, oud, nieuw). De eerste keer is alles meteen bevestigd zonder wijziging."""
    out, changes = {}, []
    for name, status in items.items():
        p = prev.get(name)
        if p is None:
            out[name] = {"status": status, "seen": status}
        elif status == p["status"]:
            out[name] = {"status": status, "seen": status}
        elif status == p.get("seen"):
            changes.append((name, p["status"], status))
            out[name] = {"status": status, "seen": status}
        else:
            out[name] = {"status": p["status"], "seen": status}
    return out, changes


async def watch_gateways(db: AsyncSession, clients: HttpClients) -> None:
    for svc in (await db.execute(select(Service).where(Service.type == "opnsense"))).scalars().all():
        st = await _state(db, f"net_gw:{svc.id}")
        try:
            gws = await build(svc, clients).gateways()
        except IntegrationError as e:
            st.value = {**st.value, "error": str(e), "checked_at": _now()}
            continue
        track, changes = debounce(st.value.get("track", {}), {g["name"]: g["level"] for g in gws})
        for name, old, new in changes:
            g = next(x for x in gws if x["name"] == name)
            if new == "ok":
                notify(db, f"{name} is weer online", f"Latency {g['delay_ms'] or 0:.0f} ms.", level="ok",
                       source="netwerk", service_id=svc.id)
            else:
                detail = f"{g['label']}" + (f", {g['loss_pct']:.0f}% verlies" if g["loss_pct"] else "") \
                    + (f", {g['delay_ms']:.0f} ms" if g["delay_ms"] else "")
                notify(db, f"{name}: {'down' if new == 'err' else 'problemen'}", f"{detail} ({svc.name}).",
                       level=new if new in ("err", "warn") else "warn", source="netwerk", service_id=svc.id)
        st.value = {"track": track, "items": gws, "checked_at": _now(), "error": None}


async def watch_tunnels(db: AsyncSession, clients: HttpClients) -> None:
    for svc in (await db.execute(select(Service).where(Service.type == "cloudflared"))).scalars().all():
        st = await _state(db, f"net_tunnel:{svc.id}")
        try:
            tunnels = await build(svc, clients).tunnels()
        except IntegrationError as e:
            st.value = {**st.value, "error": str(e), "checked_at": _now()}
            continue
        track, changes = debounce(st.value.get("track", {}), {t["name"]: t["status"] for t in tunnels})
        for name, old, new in changes:
            if new == "healthy":
                notify(db, f"Tunnel {name} is weer gezond", None, level="ok", source="netwerk", service_id=svc.id)
            else:
                notify(db, f"Tunnel {name}: {new}", f"Was {old}. Van buitenaf is het dashboard misschien niet bereikbaar.",
                       level="err" if new in ("down", "inactive") else "warn", source="netwerk", service_id=svc.id)
        st.value = {"track": track, "items": tunnels, "checked_at": _now(), "error": None}


async def fetch_public_ip(client: httpx.AsyncClient) -> str | None:
    for url in IP_SOURCES:
        try:
            r = await client.get(url, timeout=6)
            if r.status_code != 200:
                continue
            text = r.text.strip()
            if "ip=" in text:
                text = next((ln[3:] for ln in text.splitlines() if ln.startswith("ip=")), "")
            if text and len(text) <= 45 and all(c in "0123456789abcdef.:" for c in text.lower()):
                return text
        except httpx.HTTPError:
            continue
    return None


async def watch_public_ip(db: AsyncSession, clients: HttpClients) -> None:
    if not get_settings().public_ip_check:
        return
    ip = await fetch_public_ip(clients.get(False))
    st = await _state(db, "public_ip")
    v = dict(st.value)
    v["checked_at"] = _now()
    if ip is None:
        v["error"] = "Geen antwoord van 1.1.1.1 of ipify (geen internet?)"
        st.value = v
        return
    v["error"] = None
    if v.get("ip") and v["ip"] != ip:
        hist = [{"ip": v["ip"], "since": v.get("since"), "until": v["checked_at"]}, *v.get("history", [])][:HISTORY]
        v["history"] = hist
        notify(db, "Publiek IP gewijzigd", f"{v['ip']} → {ip}\nControleer DNS-records of firewallregels die het oude IP gebruiken.",
               level="warn", source="netwerk", data={"old": v["ip"], "new": ip})
        v["since"] = v["checked_at"]
    elif not v.get("ip"):
        v["since"] = v["checked_at"]
    v["ip"] = ip
    st.value = v


# --- Stroom ----------------------------------------------------------------------

async def sample_power(db: AsyncSession, clients: HttpClients, now: datetime | None = None) -> int:
    """Elke 10 minuten het verbruik per node bewaren (voor kWh zonder energy-sensor, en de grafiek)."""
    now = now or datetime.now(timezone.utc)
    n = 0
    for svc in (await db.execute(select(Service).where(Service.type == "homeassistant"))).scalars().all():
        try:
            # build() hoort in de try: één Home Assistant met een kapotte configuratie mag de rest niet tegenhouden.
            integ = build(svc, clients)
            for label, power, _ in integ.mapping():
                w, unit = await integ.state(power)
                if w is None:
                    continue
                db.add(Metric(service_id=svc.id, kind="power", name=label[:120], ts=now,
                              watts=w * 1000 if (unit or "").lower() == "kw" else w))
                n += 1
        except IntegrationError as e:
            log.info("Home Assistant %s niet bereikbaar: %s", svc.name, e)
        except Exception:
            log.exception("verbruik van %s ophalen mislukt", svc.name)
    return n


def integrate(points: list[tuple[datetime, float]], max_gap: timedelta = timedelta(minutes=30)) -> tuple[float, float]:
    """(kWh, gemeten uren) uit metingen (tijd, watt): trapezium; gaten langer dan max_gap tellen niet mee
    (het dashboard stond uit)."""
    wh = hours = 0.0
    for (t0, w0), (t1, w1) in zip(points, points[1:]):
        dt = t1 - t0
        if timedelta(0) < dt <= max_gap:
            h = dt.total_seconds() / 3600
            wh += (w0 + w1) / 2 * h
            hours += h
    return wh / 1000, hours


def integrate_kwh(points: list[tuple[datetime, float]]) -> float:
    return integrate(points)[0]


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def power_overview(db: AsyncSession, clients: HttpClients) -> list[dict]:
    """Per Home Assistant-service en node: watt nu, kWh en kost deze maand, prognose voor de hele maand,
    en het verbruik per dag over de laatste 30 dagen (uit de eigen metingen)."""
    now = datetime.now(timezone.utc)
    start = month_start(now)
    # Dagen in deze maand, voor de prognose.
    nxt = (start.replace(day=28) + timedelta(days=4)).replace(day=1)
    month_hours = (nxt - start).total_seconds() / 3600
    elapsed_hours = max((now - start).total_seconds() / 3600, 1)
    since = min(start, now - timedelta(days=30))
    out = []
    for svc in (await db.execute(select(Service).where(Service.type == "homeassistant"))).scalars().all():
        integ = build(svc, clients)
        entry = {"service_id": svc.id, "service": svc.name, "price": integ.price, "nodes": [], "error": None}
        try:
            readings = await integ.readings()
        except IntegrationError as e:
            entry["error"] = str(e)
            readings = []
        rows = (await db.execute(select(Metric.name, Metric.ts, Metric.watts).where(
            Metric.service_id == svc.id, Metric.kind == "power", Metric.ts >= since).order_by(Metric.ts))).all()
        series: dict[str, list[tuple[datetime, float]]] = {}
        for name, ts, w in rows:
            if w is not None:
                series.setdefault(name, []).append((_aware(ts), w))
        names = [r["name"] for r in readings] or sorted(series)
        for name in names:
            r = next((x for x in readings if x["name"] == name), {"watts": None, "month_kwh": None, "energy": False})
            pts = series.get(name, [])
            month = r["month_kwh"]
            measured = month is None
            covered = elapsed_hours
            if measured:
                # Eigen metingen: de prognose rekent alleen met de uren die echt gemeten zijn.
                month, covered = integrate([p for p in pts if p[0] >= start])
                month = month if covered else None
            days = {}
            for d in range(30, -1, -1):
                day0 = (now.astimezone() - timedelta(days=d)).replace(hour=0, minute=0, second=0, microsecond=0)
                day1 = day0 + timedelta(days=1)
                days[day0.date().isoformat()] = round(integrate_kwh([p for p in pts if day0 <= p[0] < day1]), 3)
            avg_w = sum(w for _, w in pts[-144:]) / len(pts[-144:]) if pts else None
            price = integ.price
            out_row = {"name": name, "watts": r["watts"], "avg_24h": avg_w, "month_kwh": month,
                       "month_cost": month * price if price is not None and month is not None else None,
                       "forecast_kwh": month / covered * month_hours if month is not None and covered else None,
                       "measured": measured, "days": days}
            out_row["forecast_cost"] = (out_row["forecast_kwh"] * price
                                        if price is not None and out_row["forecast_kwh"] is not None else None)
            entry["nodes"].append(out_row)
        out.append(entry)
    return out
