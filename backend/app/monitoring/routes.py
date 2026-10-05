"""Checks rechtstreeks naar de server achter Nginx Proxy Manager, zonder DNS.

Bijna elke tegel heet <naam>.jbogaert.be, en die naam wijst via DNS naar NPM. Een check op de naam vraagt dus elke
keer DNS (A en AAAA) en gaat door NPM. Met de proxy hosts van NPM gaat de check rechtstreeks naar het doel dat NPM zelf
gebruikt (bv. http://192.168.0.27:8096), met dezelfde Host- en X-Forwarded-headers als NPM stuurt: voor de app ziet
het eruit alsof het via NPM komt. De link van de tegel blijft de naam.

- Elke 5 minuten (worker) de proxy hosts en certificaten uit NPM: naam → doel, plus de vervaldatum van het
  certificaat (dat ziet een check op het IP niet meer).
- Alleen een doel dat een IP-adres is en dat het dashboard echt bereikt (een TCP-verbinding lukt). Anders gaat de
  check naar het IP van NPM zelf (het adres van de NPM-tegel), met de naam in Host en SNI: zoals vroeger door NPM,
  maar zonder DNS. De reden staat erbij (meestal de firewall tussen de VLAN's). Zodra de server bereikbaar is,
  schakelt de tegel vanzelf over; er gaat geen status verloren.
- Per tegel uit te zetten (check "direct": false: via de naam, met DNS, zoals vroeger), en voor alles samen op de
  NPM-tegel.
"""

import asyncio
import ipaddress
import logging
import socket
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..integrations import IntegrationError, build
from ..models import AppState, Service
from .checks import endpoint_of as endpoint
from .checks import target_for

log = logging.getLogger("homepage.routes")

KEY = "npm_routes"
REFRESH_EVERY = 300
# Een doel dat werkte, af en toe opnieuw proberen; een doel dat niet werkte, bij elke ronde.
PROBE_OK_EVERY = 3600
PROBE_TIMEOUT = 3.0
PROBE_PARALLEL = 20
# Zo lang houden de checks de tabel in het geheugen (de worker zet hem meteen na een ronde).
CACHE_TTL = 30
# Waar NPM zelf op luistert voor de proxy hosts.
NPM_PORTS = {"http": 80, "https": 443}


def _is_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


@dataclass(frozen=True)
class Route:
    """Waar een check op een naam heen gaat: de server achter NPM, of (npm=True) NPM zelf, op zijn IP."""
    scheme: str
    host: str
    port: int
    cert: datetime | None = None
    npm: bool = False

    @property
    def where(self) -> str:
        return endpoint(self.host, self.port)

    @property
    def label(self) -> str:
        return f"via NPM op {self.host}" if self.npm else f"rechtstreeks naar {self.where}"

    def url(self, logical: httpx.URL) -> httpx.URL:
        """Het echte adres voor een adres met de naam: zelfde pad en query, ander schema, host en poort."""
        return logical.copy_with(scheme=self.scheme, host=self.host, port=self.port)


def _forward(item: dict) -> tuple[str, str, int] | None:
    scheme = str(item.get("forward_scheme") or "http").lower()
    host = str(item.get("forward_host") or "").strip()
    try:
        port = int(item.get("forward_port") or (443 if scheme == "https" else 80))
    except (TypeError, ValueError):
        return None
    if scheme not in ("http", "https") or not host or not 0 < port < 65536:
        return None
    return scheme, host, port


def _why_not(scheme_host_port: tuple[str, str, int] | None) -> str | None:
    """Waarom dit doel niet rechtstreeks kan (None = kan)."""
    if scheme_host_port is None:
        return "geen geldig doel in NPM"
    host = scheme_host_port[1]
    ip = _is_ip(host)
    if ip is None:
        # Een containernaam of een naam: daar is opnieuw DNS voor nodig, of het dashboard kent hem niet.
        return f"het doel ({host}) is geen IP-adres"
    if ip.is_loopback or ip.is_unspecified:
        return "het doel is NPM zelf (localhost)"
    return None


def _expiry(value) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def build_hosts(proxy_hosts: list[dict], certs: list[dict], npm_id: int, via: str | None = None) -> dict[str, dict]:
    """Naam (kleine letters, ook *.domein) → wat NPM ermee doet. via: het IP van NPM zelf."""
    expires = {c.get("id"): _expiry(c.get("expires_on")) for c in certs if isinstance(c, dict)}
    out: dict[str, dict] = {}
    for h in proxy_hosts:
        if not isinstance(h, dict):
            continue
        fwd = _forward(h)
        why = _why_not(fwd)
        if not h.get("enabled", True):
            why = "staat uit in NPM"
        elif "proxy_pass" in str(h.get("advanced_config") or ""):
            why = "eigen nginx-configuratie in NPM (proxy_pass)"
        locations = []
        for loc in h.get("locations") or []:
            if not isinstance(loc, dict) or not str(loc.get("path") or "").startswith("/"):
                continue
            lf = _forward(loc)
            lwhy = "het doel heeft een pad" if lf and "/" in lf[1] else _why_not(lf)
            if "proxy_pass" in str(loc.get("advanced_config") or ""):
                lwhy = "eigen nginx-configuratie in NPM (proxy_pass)"
            locations.append({"path": str(loc["path"]), "scheme": lf[0] if lf else None, "host": lf[1] if lf else None,
                              "port": lf[2] if lf else None, "why": lwhy})
        entry = {"npm": npm_id, "via": via, "id": h.get("id"), "scheme": fwd[0] if fwd else None, "host": fwd[1] if fwd else None,
                 "port": fwd[2] if fwd else None, "cert": expires.get(h.get("certificate_id")) if h.get("certificate_id")
                 else None, "why": why,
                 "locations": sorted(locations, key=lambda x: len(x["path"]), reverse=True)}
        for name in h.get("domain_names") or []:
            name = str(name).strip().lower().rstrip(".")
            if name:
                out.setdefault(name, entry)
    return out


class Table:
    """De routes zoals de checks ze gebruiken."""

    def __init__(self, value: dict | None) -> None:
        value = value or {}
        self.enabled = value.get("enabled", True) is not False
        self.hosts: dict[str, dict] = value.get("hosts") or {}
        self.probes: dict[str, dict] = value.get("probes") or {}

    def entry(self, name: str | None) -> dict | None:
        if not name:
            return None
        name = name.lower().rstrip(".")
        if name in self.hosts:
            return self.hosts[name]
        # Een wildcard in NPM (*.lab.jbogaert.be): de langste die past.
        parts = name.split(".")
        for i in range(1, len(parts) - 1):
            hit = self.hosts.get("*." + ".".join(parts[i:]))
            if hit:
                return hit
        return None

    def _pick(self, name: str | None, path: str) -> tuple[dict | None, dict | None, str | None]:
        """(wat NPM met de naam doet, het doel voor dit pad, waarom het niet rechtstreeks kan)."""
        e = self.entry(name)
        if e is None:
            return None, None, None
        if e.get("why"):
            return e, None, e["why"]
        # Zoals nginx: de langste locatie waarmee het pad begint.
        for loc in e.get("locations") or []:
            if path.startswith(loc["path"]):
                if loc.get("why"):
                    return e, None, f"aparte locatie {loc['path']} in NPM: {loc['why']}"
                return e, loc, None
        return e, e, None

    @staticmethod
    def _cert(e: dict) -> datetime | None:
        try:
            return datetime.fromisoformat(e["cert"]) if e.get("cert") else None
        except ValueError:
            return None

    def _via_npm(self, e: dict, scheme: str | None) -> Route | None:
        """NPM zelf, op zijn IP: voor een naam die niet rechtstreeks kan. scheme None (tcp, ping): 80 of 443 volstaat."""
        via = e.get("via")
        if not via:
            return None
        for sch in (scheme,) if scheme else ("https", "http"):
            port = NPM_PORTS.get(sch)
            if port and (self.probes.get(endpoint(via, port)) or {}).get("ok"):
                return Route(sch, via, port, self._cert(e), npm=True)
        return None

    def forward(self, name: str | None, path: str = "/") -> tuple[str, int] | None:
        """Het IP en de poort waar een check op deze naam heen zou gaan, ook als dat nu niet lukt (voor de firewall)."""
        if not self.enabled:
            return None
        _, target, _ = self._pick(name, path)
        return (target["host"], int(target["port"])) if target else None

    def explain(self, name: str | None, path: str = "/", scheme: str | None = None, port: int | None = None
                ) -> tuple[Route | None, str | None, str | None]:
        """(route, waarom niet rechtstreeks, onbereikbaar ip:poort). De route is de server zelf (reden None), NPM op
        zijn IP (npm=True), of None: via de naam, met DNS (ook als NPM de naam niet kent: dan alles None).
        scheme en port: van het adres van een http-check (port None = de standaardpoort); tcp en ping geven niets."""
        if not self.enabled:
            return None, None, None
        e, target, why = self._pick(name, path)
        if e is None:
            return None, None, None
        if port is not None and port != NPM_PORTS.get(scheme or ""):
            # NPM luistert alleen op 80 en 443: een naam met een eigen poort gaat niet door NPM.
            return None, f"het adres heeft een eigen poort (:{port})", None
        blocked = None
        if target is not None:
            where = endpoint(target["host"], target["port"])
            probe = self.probes.get(where)
            if not probe:
                why = "nog niet geprobeerd"
            elif not probe.get("ok"):
                why = f"{where} niet bereikbaar vanaf het dashboard" + (
                    f" ({probe['error']})" if probe.get("error") else "") + ", firewall?"
                blocked = where
            else:
                return Route(target["scheme"], target["host"], int(target["port"]), self._cert(e)), None, None
        return self._via_npm(e, scheme), why, blocked

    def find(self, name: str | None, path: str = "/", scheme: str | None = None, port: int | None = None
             ) -> Route | None:
        return self.explain(name, path, scheme, port)[0]


# --- de tabel in het geheugen (voor de checks) ---------------------------------------------------------------------

_cache: tuple[float, Table] | None = None


def remember(value: dict | None) -> Table:
    global _cache
    table = Table(value)
    _cache = (time.monotonic() + CACHE_TTL, table)
    return table


async def table(maker) -> Table:
    """De routes, hoogstens 30 seconden oud. Zonder database (of een fout): geen routes, de check gaat via de naam."""
    hit = _cache
    if hit and hit[0] > time.monotonic():
        return hit[1]
    try:
        async with maker() as db:
            st = await db.get(AppState, KEY)
            return remember(st.value if st else None)
    except Exception:  # noqa: BLE001 - liever via de naam checken dan helemaal niet
        log.exception("routes niet te lezen")
        return remember(None)


def forget() -> None:
    global _cache
    _cache = None


# --- vernieuwen (worker, of de knop op de NPM-tegel) ---------------------------------------------------------------

async def _probe(where: tuple[str, int]) -> tuple[bool, str | None]:
    host, port = where
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), PROBE_TIMEOUT)
    except (TimeoutError, asyncio.TimeoutError):
        return False, "time-out"
    except ConnectionRefusedError:
        return False, "geweigerd"
    except OSError as e:
        return False, (e.strerror or type(e).__name__).lower()
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 1)
    except Exception:  # noqa: BLE001
        pass
    return True, None


def _endpoints(hosts: dict[str, dict]) -> set[tuple[str, int]]:
    out = set()
    for e in hosts.values():
        if e.get("via"):
            out.update((e["via"], p) for p in NPM_PORTS.values())
        if e.get("why"):
            continue
        for t in [e, *(e.get("locations") or [])]:
            if not t.get("why") and t.get("host") and t.get("port"):
                out.add((t["host"], int(t["port"])))
    return out


async def refresh(db: AsyncSession, clients, now: datetime | None = None, force_probe: bool = False) -> dict:
    """Proxy hosts en certificaten uit elke NPM-tegel, en de doelen proberen die nog niet (of lang niet) lukten.
    force_probe: alle doelen opnieuw (de knop "nu vernieuwen")."""
    now = now or datetime.now(timezone.utc)
    st = await ensure_state(db, KEY, {})
    prev = dict(st.value or {})
    old_hosts: dict[str, dict] = prev.get("hosts") or {}
    hosts: dict[str, dict] = {}
    errors: dict[str, str] = {}
    for svc in (await db.execute(select(Service).where(Service.type == "npm").order_by(Service.id))).scalars().all():
        try:
            integ = build(svc, clients)
            via = await _npm_ip(integ.base)
            proxy_hosts = await integ.proxy_hosts()
            try:
                certs = await integ.certificates()
            except IntegrationError:
                certs = []
        except IntegrationError as e:
            # NPM even niet bereikbaar: de routes van die tegel blijven zoals ze waren.
            errors[str(svc.id)] = str(e)[:200]
            for name, entry in old_hosts.items():
                if entry.get("npm") == svc.id:
                    hosts.setdefault(name, entry)
            continue
        for name, entry in build_hosts(proxy_hosts if isinstance(proxy_hosts, list) else [], certs
                                       if isinstance(certs, list) else [], svc.id, via).items():
            hosts.setdefault(name, entry)
    old_probes: dict[str, dict] = prev.get("probes") or {}
    wanted = _endpoints(hosts)
    todo = []
    for host, port in wanted:
        p = old_probes.get(endpoint(host, port))
        at = _at(p.get("at")) if p else None
        if force_probe or not p or not p.get("ok") or at is None or (now - at).total_seconds() > PROBE_OK_EVERY:
            todo.append((host, port))
    sem = asyncio.Semaphore(PROBE_PARALLEL)

    async def one(where):
        async with sem:
            return where, await _probe(where)

    results = await asyncio.gather(*(one(w) for w in todo))
    probes = {k: v for k, v in old_probes.items() if k in {endpoint(h, p) for h, p in wanted}}
    for (host, port), (ok, error) in results:
        probes[endpoint(host, port)] = {"ok": ok, "error": error, "at": now.isoformat()}
    value = {"enabled": prev.get("enabled", True) is not False, "at": now.isoformat(), "hosts": hosts,
             "probes": probes, "errors": errors}
    st.value = value
    remember(value)
    return value


async def _npm_ip(base: str) -> str | None:
    """Het IP van NPM: de host van de NPM-tegel (meestal al een IP; een naam één keer per ronde opzoeken)."""
    host = urlsplit(base).hostname or ""
    if ip := _is_ip(host):
        return None if ip.is_loopback or ip.is_unspecified else str(ip)
    try:
        infos = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(host, None, family=socket.AF_INET), 3)
    except (OSError, TimeoutError, asyncio.TimeoutError, UnicodeError):
        return None
    return infos[0][4][0] if infos else None


def _at(value) -> datetime | None:
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


# --- voor de schermen ----------------------------------------------------------------------------------------------

def name_and_path(check: dict, url: str | None) -> tuple[str | None, str, bool]:
    """(naam, pad, uit de URL afgeleid) van wat deze check zou proberen."""
    kind = check.get("type")
    try:
        target = target_for(check, url)
    except ValueError:
        return None, "/", False
    if not target:
        return None, "/", False
    if kind == "http":
        try:
            u = httpx.URL(target)
        except (httpx.InvalidURL, ValueError):
            return None, "/", False
        return u.host or None, u.path or "/", not (check.get("target") or "").strip()
    if kind == "tcp":
        host = target.rpartition(":")[0].strip("[]")
        return host or None, "/", not (check.get("target") or "").strip()
    if kind == "ping":
        return target, "/", not (check.get("target") or "").strip()
    return None, "/", False


def tcp_port(route: Route, port: int) -> int:
    """De poort voor een tcp-check op een naam: 80 of 443 (de poorten van NPM) wordt de poort van de server erachter;
    een andere poort blijft, op het IP van de server. Via NPM blijft de poort altijd: zoals de naam vroeger."""
    return route.port if not route.npm and port in NPM_PORTS.values() else port


def describe(check: dict | None, url: str | None, tab: Table) -> dict | None:
    """Voor het mini dashboard: rechtstreeks naar de server, via NPM op zijn IP, of via de naam, en waarom.
    None = NPM kent de naam niet (of de check gaat niet op een naam)."""
    check = check or {}
    kind = check.get("type")
    if kind not in ("http", "tcp", "ping"):
        return None
    name, path, _ = name_and_path(check, url)
    if not name or _is_ip(name) or tab.entry(name) is None:
        return None
    if check.get("direct") is False:
        return {"direct": False, "why": "uitgezet voor deze tegel"}
    if not tab.enabled:
        return {"direct": False, "why": "uitgezet op de NPM-tegel"}
    target = target_for(check, url) or ""
    scheme = port = None
    if kind == "http":
        u = httpx.URL(target)
        scheme, port = u.scheme, u.port
    route, why, blocked = tab.explain(name, path, scheme, port)
    out = {"direct": route is not None and not route.npm}
    if route is None:
        return {**out, "why": why, "blocked": blocked}
    if kind == "http":
        to = f"{route.scheme}://{route.where}"
    elif kind == "tcp":
        own = target.rpartition(":")[2]
        to = endpoint(route.host, tcp_port(route, int(own))) if own.isdigit() else route.where
    else:
        to = route.host
    if route.npm:
        return {**out, "npm": route.host, "to": to, "why": why, "blocked": blocked}
    return {**out, "to": to}


async def overview(db: AsyncSession) -> dict:
    """Per tegel met een check: rechtstreeks of via de naam (en waarom), plus de doelen die de firewall tegenhoudt."""
    from .engine import active

    st = await db.get(AppState, KEY)
    value = st.value if st else {}
    tab = Table(value)
    rows, blocked = [], {}
    for s in (await db.execute(select(Service).order_by(Service.name))).scalars():
        if not active(s.check):
            continue
        d = describe(s.check, s.url, tab)
        if d is None:
            continue
        rows.append({"service_id": s.id, "name": s.name, "host": name_and_path(s.check, s.url)[0], **d})
        if d.get("blocked"):
            blocked.setdefault(d["blocked"], []).append(s.name)
    return {
        "enabled": tab.enabled, "at": value.get("at"), "errors": list((value.get("errors") or {}).values()),
        "known": len(tab.hosts), "rows": rows,
        "counts": {"direct": sum(1 for r in rows if r["direct"]), "npm": sum(1 for r in rows if r.get("npm")),
                   "naam": sum(1 for r in rows if not r["direct"] and not r.get("npm"))},
        "blocked": [{"endpoint": k, "tiles": v} for k, v in sorted(blocked.items())],
    }
