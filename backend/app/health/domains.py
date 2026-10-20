"""Domeinen: vervaldatum, registrar en nameservers via RDAP (rdap.org stuurt door naar het juiste register).

Niet elk register geeft een vervaldatum (DNS Belgium voor .be bijvoorbeeld niet); dan kan je ze zelf invullen.
Meldingen 30, 7 en 1 dag(en) op voorhand, en als de nameservers veranderen (dat zou je zelf moeten weten).
"""

import logging
import re
from datetime import date, datetime, timezone

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..models import AppState

log = logging.getLogger("homepage.health")

DOMAINS_EVERY = 24 * 3600
STATE_KEY = "domains"
RDAP = "https://rdap.org/domain/{}"
WARN_DAYS = (30, 7, 1)
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def clean(name: str) -> str | None:
    n = (name or "").strip().lower().rstrip(".")
    n = re.sub(r"^https?://", "", n).split("/")[0]
    try:
        n = n.encode("idna").decode()
    except UnicodeError:
        return None
    return n if DOMAIN_RE.match(n) else None


def _date(s: str | None) -> str | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return None


def _vcard_name(entity: dict) -> str | None:
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if isinstance(item, list) and len(item) >= 4 and item[0] in ("fn", "org") and item[3]:
            return str(item[3])
    return None


def parse_rdap(d: dict) -> dict:
    ev = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) if isinstance(e, dict)}
    registrar = None
    for ent in d.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard_name(ent) or ent.get("handle")
    return {
        "expires": _date(ev.get("expiration")),
        "registered": _date(ev.get("registration")),
        "changed": _date(ev.get("last changed")),
        "registrar": registrar,
        "status": [s for s in d.get("status", []) if isinstance(s, str)],
        "nameservers": sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in d.get("nameservers", [])
                               if n.get("ldhName")}),
    }


async def lookup(client: httpx.AsyncClient, name: str) -> dict:
    try:
        r = await client.get(RDAP.format(name), headers={"Accept": "application/rdap+json"}, timeout=20)
    except httpx.HTTPError as e:
        return {"error": f"RDAP niet bereikbaar: {type(e).__name__}"}
    if r.status_code == 404:
        return {"error": "Het register kent dit domein niet (of heeft geen RDAP)"}
    if r.status_code >= 400:
        return {"error": f"RDAP gaf HTTP {r.status_code}"}
    try:
        return parse_rdap(r.json())
    except ValueError:
        return {"error": "RDAP gaf geen geldig antwoord"}


def days_left(expires: str | None, today: date) -> int | None:
    return (date.fromisoformat(expires) - today).days if expires else None


async def run_domains(db: AsyncSession, http, domains: list[dict]) -> dict:
    """domains: [{"name": "jbogaert.be", "expires": "2027-05-01" (optioneel, zelf ingevuld)}]."""
    now = datetime.now(timezone.utc).replace(microsecond=0)
    state = await db.get(AppState, STATE_KEY)
    prev = {d["name"]: d for d in (state.value.get("items", []) if state else [])}
    client = http.get(False)
    items = []
    for cfg in domains:
        name = cfg["name"]
        info = await lookup(client, name)
        p = prev.get(name, {})
        item = {"name": name, **info, "manual": cfg.get("expires")}
        if info.get("error"):
            # Laatste gekende gegevens houden als RDAP even niet antwoordt.
            for k in ("registrar", "nameservers", "registered", "status"):
                item.setdefault(k, p.get(k))
            item.setdefault("expires", p.get("expires"))
        item["source"] = "rdap" if info.get("expires") else ("manueel" if cfg.get("expires") else None)
        item["expires"] = info.get("expires") or cfg.get("expires") or item.get("expires")
        item["days_left"] = days_left(item["expires"], now.date())
        item["warned"] = p.get("warned") if p.get("expires") == item["expires"] else None
        dl = item["days_left"]
        if dl is not None:
            step = next((w for w in sorted(WARN_DAYS) if dl <= w), None)
            if step is not None and (item["warned"] is None or step < item["warned"]):
                item["warned"] = step
                notify(db, f"Domein {name} {'is verlopen' if dl < 0 else f'verloopt over {dl} dag' + ('en' if dl != 1 else '')}",
                       f"Vervaldatum {item['expires']}" + (f" bij {item['registrar']}" if item.get("registrar") else ""),
                       level="err" if dl <= 7 else "warn", source="domein")
        ns, ons = item.get("nameservers") or [], p.get("nameservers") or []
        if not info.get("error") and ons and ns and ns != ons:
            notify(db, f"Nameservers van {name} gewijzigd", f"was: {', '.join(ons)}\nnu: {', '.join(ns)}",
                   level="warn", source="domein")
        items.append(item)
    value = {"checked_at": now.isoformat(), "items": items}
    if state:
        state.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value
