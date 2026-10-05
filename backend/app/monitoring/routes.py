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
import re
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
# De schakelaar op de NPM-tegel: {"enabled": bool}.
KEY_ON = "npm_routes_aan"
REFRESH_EVERY = 300
# Een doel dat werkte, af en toe opnieuw proberen; een doel dat niet werkte, bij elke ronde.
PROBE_OK_EVERY = 3600
PROBE_TIMEOUT = 3.0
REFUSED = "geweigerd"  # de server antwoordt, maar op die poort luistert niets
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
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]  # IPv6 zoals NPM het wil; endpoint() en de URL zetten de haken zelf
    try:
        port = int(item.get("forward_port") or (443 if scheme == "https" else 80))
    except (TypeError, ValueError):
        return None
    if scheme not in ("http", "https") or not host or not 0 < port < 65536:
        return None
    return scheme, host, port


# Waar Docker zijn netwerken legt (172.17.0.1 is de server van NPM, gezien vanuit zijn container).
_DOCKER = ipaddress.ip_network("172.16.0.0/12")


def _why_not(scheme_host_port: tuple[str, str, int] | None, via: str | None = None) -> str | None:
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
    v = _is_ip(via or "")
    if ip in _DOCKER and not (v is not None and v in _DOCKER):
        # Een Docker-netwerk op de server van NPM: alleen NPM zelf kan daar.
        return f"het doel ({host}) is een Docker-netwerk bij NPM"
    return None


def _norm(name) -> str:
    """Een naam zoals we hem vergelijken: kleine letters, zonder punt op het einde, IDN als punycode."""
    name = str(name).strip().lower().rstrip(".")
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


_COMMENT = re.compile(r"#[^\n]*")


def _own_config(item: dict) -> bool:
    """Eigen nginx-configuratie in NPM (een login zoals Authentik, include, allow/deny, return, proxy_pass ...): wat
    die doet, raden we niet. Zo'n naam gaat via NPM."""
    return bool(_COMMENT.sub("", str(item.get("advanced_config") or "")).strip())


def _expiry(value) -> str | None:
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def _names(item: dict) -> list[str]:
    return [n for n in (_norm(x) for x in item.get("domain_names") or []) if n]


def build_hosts(proxy_hosts: list[dict], certs: list[dict] | None, npm_id: int, via: str | None = None,
                others: list[tuple[list[dict], str]] = ()) -> dict[str, dict]:
    """Naam (kleine letters, ook *.domein) → wat NPM ermee doet. via: het IP van NPM zelf. certs None: niet op te
    halen. others: redirection- en 404-hosts, met de reden: die naam beantwoordt NPM zelf."""
    known = {c.get("id"): c for c in certs or [] if isinstance(c, dict)}
    out: dict[str, dict] = {}

    def cert_of(h: dict) -> dict:
        cid = h.get("certificate_id")
        if not cid:
            return {"cert": None, "cert_names": []}
        c = known.get(cid)
        # Niet op te halen: we gaan ervan uit dat het certificaat past (NPM hangt het zelf aan de host).
        return {"cert": _expiry(c.get("expires_on")) if c else None,
                "cert_names": (_names(c) or None) if c else None}

    for h in proxy_hosts:
        if not isinstance(h, dict):
            continue
        fwd = _forward(h)
        why = _why_not(fwd, via)
        if not h.get("enabled", True):
            why = "staat uit in NPM"
        elif (h.get("meta") or {}).get("nginx_online") is False:
            why = "offline in NPM (fout in de configuratie)"
        elif _own_config(h):
            why = "eigen nginx-configuratie in NPM"
        elif h.get("access_list_id"):
            # Een login of IP-lijst van NPM ervoor: rechtstreeks zou de check die overslaan.
            why = "toegangslijst in NPM"
        locations = []
        for loc in h.get("locations") or []:
            if not isinstance(loc, dict):
                continue
            if not str(loc.get("path") or "").startswith("/"):
                # Een regex (~), = of ^~: welke locatie nginx kiest, raden we niet.
                why = why or "aparte locatie met een regex of = in NPM"
                continue
            lf = _forward(loc)
            lwhy = "het doel heeft een pad" if lf and "/" in lf[1] else _why_not(lf, via)
            if _own_config(loc):
                lwhy = "eigen nginx-configuratie in NPM"
            locations.append({"path": str(loc["path"]), "scheme": lf[0] if lf else None, "host": lf[1] if lf else None,
                              "port": lf[2] if lf else None, "why": lwhy})
        entry = {"npm": npm_id, "via": via, "id": h.get("id"), "scheme": fwd[0] if fwd else None,
                 "host": fwd[1] if fwd else None, "port": fwd[2] if fwd else None, **cert_of(h), "why": why,
                 "ssl_forced": bool(h.get("ssl_forced") and h.get("certificate_id")),
                 "locations": sorted(locations, key=lambda x: len(x["path"]), reverse=True)}
        for name in _names(h):
            out.setdefault(name, entry)
    for items, why in others:
        for h in items:
            if isinstance(h, dict) and h.get("enabled", True):
                entry = {"npm": npm_id, "via": via, "id": h.get("id"), "scheme": None, "host": None, "port": None,
                         **cert_of(h), "why": why, "locations": []}
                for name in _names(h):
                    out.setdefault(name, entry)
    return out


def _covers(names: list[str] | None, name: str) -> bool:
    """Past het certificaat (zijn namen) op deze naam? Een wildcard telt voor precies één label, zoals in TLS."""
    if names is None:
        return True
    return name in names or ("." in name and f"*.{name.split('.', 1)[1]}" in names)


@dataclass(frozen=True)
class Plan:
    """Hoe een check op een naam loopt: route None = via de naam (DNS). firewall: de server die de check zou
    gebruiken als het dashboard hem bereikt (voor de firewallregel)."""
    route: Route | None
    target: str | None = None
    why: str | None = None
    blocked: str | None = None
    firewall: tuple[str, int] | None = None
    firewall_npm: bool = False  # de firewallregel is voor NPM zelf, niet voor de server erachter


class Table:
    """De routes zoals de checks ze gebruiken (load() leest ze uit de database)."""

    def __init__(self, value: dict | None, enabled: bool = True) -> None:
        value = value or {}
        self.enabled = enabled
        self.hosts: dict[str, dict] = value.get("hosts") or {}
        self.probes: dict[str, dict] = value.get("probes") or {}

    def entry(self, name: str | None) -> dict | None:
        if not name:
            return None
        name = _norm(name)
        if name in self.hosts:
            return self.hosts[name]
        # Een wildcard in NPM (*.lab.jbogaert.be): de langste die past, zoals nginx.
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

    def npm_for(self, name: str | None, scheme: str | None = None) -> Route | None:
        """NPM op zijn IP voor deze naam (ook als de server rechtstreeks kan): om op terug te vallen."""
        e = self.entry(name) if self.enabled else None
        return self._via_npm(e, scheme) if e else None

    def explain(self, name: str | None, path: str = "/", scheme: str | None = None, port: int | None = None
                ) -> tuple[Route | None, str | None, str | None, tuple[str, int] | None]:
        """(route, waarom niet rechtstreeks, onbereikbaar ip:poort, server voor de firewall). De route is de server
        zelf (reden None), NPM op zijn IP (npm=True), of None: via de naam, met DNS (ook als NPM de naam niet kent:
        dan alles None). scheme en port: van het adres (port None = de standaardpoort); "https" vraagt een
        certificaat in NPM dat op de naam past."""
        if not self.enabled:
            return None, None, None, None
        e, target, why = self._pick(name, path)
        if e is None:
            return None, None, None, None
        if port is not None and port != NPM_PORTS.get(scheme or ""):
            # NPM luistert alleen op 80 en 443: een naam met een eigen poort gaat niet door NPM.
            return None, f"het adres heeft een eigen poort (:{port})", None, None
        if target is not None and scheme == "https" and not _covers_entry(e, name):
            # Zonder passend certificaat beantwoordt NPM https voor deze naam niet (of met een fout certificaat):
            # via NPM ziet de check dat zoals vroeger.
            target, why = None, "NPM heeft voor deze naam geen passend certificaat"
        elif target is not None and scheme == "https" and self._cert(e) is None:
            # Niet te lezen in NPM (rechten, of nog niet opgehaald): rechtstreeks zagen we een verlopen certificaat
            # niet, via NPM wel (en dan met de echte vervaldatum).
            target, why = None, "de vervaldatum van het certificaat is niet te lezen in NPM"
        if target is not None and scheme == "http" and e.get("ssl_forced"):
            # NPM stuurt http door naar https: via NPM krijgt de check die doorverwijzing, en gaat daarna (https)
            # rechtstreeks, met het certificaat.
            target, why = None, "NPM stuurt http door naar https"
        blocked = fw = None
        if target is not None:
            fw = (target["host"], int(target["port"]))
            where = endpoint(*fw)
            probe = self.probes.get(where)
            if not probe:
                why = "nog niet geprobeerd"
            elif not probe.get("ok"):
                if probe.get("error") == REFUSED:
                    # De server antwoordt, maar niets luistert: de service staat uit (of een firewall weigert actief).
                    why = f"{where} weigert de verbinding: draait de service (of weigert een firewall)?"
                else:
                    why = f"{where} niet bereikbaar vanaf het dashboard" + (
                        f" ({probe['error']})" if probe.get("error") else "") + ", firewall?"
                blocked = where
            else:
                return Route(target["scheme"], target["host"], int(target["port"]), self._cert(e)), None, None, fw
        return self._via_npm(e, scheme), why, blocked, fw

    def find(self, name: str | None, path: str = "/", scheme: str | None = None, port: int | None = None
             ) -> Route | None:
        return self.explain(name, path, scheme, port)[0]

    def plan(self, check: dict, url: str | None) -> Plan | None:
        """Hoe deze check loopt. None: gewoon via de naam (NPM kent hem niet, een IP, per tegel of overal uit)."""
        kind = check.get("type")
        if not self.enabled or check.get("direct") is False or kind not in ("http", "tcp", "ping"):
            return None
        name, path, _ = name_and_path(check, url)
        if not name or _is_ip(name) or self.entry(name) is None:
            return None
        target = target_for(check, url) or ""
        if kind == "http":
            u = httpx.URL(target)
            route, why, blocked, fw = self.explain(name, path, u.scheme, u.port)
            return Plan(route, None, why, blocked, fw)
        if kind == "tcp":
            port = target.rpartition(":")[2]
            if not port.isdigit():
                return None
            # Een tcp-check op een naam opende altijd een verbinding met NPM, en dat blijft zo (zonder DNS). Naar de
            # server erachter zou hij down gaan als die uitvalt, en na de volgende ronde weer "up" via NPM.
            route = self.npm_for(name)
            if route is None:
                return Plan(None, None, "NPM niet bereikbaar vanaf het dashboard")
            return Plan(route, endpoint(route.host, int(port)), "een tcp-check op een naam test NPM, zoals altijd",
                        firewall=(route.host, int(port)), firewall_npm=True)
        # Een ping op een naam pingt NPM (zo was het altijd): of de server erachter ping toelaat, weten we niet.
        route = self.npm_for(name)
        return Plan(route, route.host if route else None, "een ping op een naam pingt NPM, zoals altijd (vul het IP "
                    "van de server in als doel om die zelf te pingen)" if route else "NPM niet bereikbaar vanaf het "
                    "dashboard")


def _covers_entry(e: dict, name: str | None) -> bool:
    """[] = geen certificaat aan de host; None = niet op te halen (dan gaan we ervan uit dat het past)."""
    names = e.get("cert_names")
    return names is None or bool(names) and _covers(names, _norm(name or ""))


# --- de tabel in het geheugen (voor de checks) ---------------------------------------------------------------------

_cache: tuple[float, Table] | None = None
# Doelen waar een check net niet bij kon (de route kan verouderd zijn): de volgende ronde opnieuw proberen.
_suspect: set[str] = set()


async def load(db: AsyncSession) -> Table:
    """De tabel uit de database, met de schakelaar op de NPM-tegel (apart bewaard: een ronde overschrijft hem niet)."""
    st, on = await db.get(AppState, KEY), await db.get(AppState, KEY_ON)
    return Table(st.value if st else None, (on.value or {}).get("enabled", True) is not False if on else True)


def remember(table: Table) -> Table:
    global _cache
    _cache = (time.monotonic() + CACHE_TTL, table)
    return table


async def table(maker) -> Table:
    """De routes, hoogstens 30 seconden oud. Zonder database (of een fout): geen routes, de check gaat via de naam."""
    hit = _cache
    if hit and hit[0] > time.monotonic():
        return hit[1]
    try:
        async with maker() as db:
            return remember(await load(db))
    except Exception:  # noqa: BLE001 - liever via de naam checken dan helemaal niet
        log.exception("routes niet te lezen")
        return remember(Table(None))


def forget() -> None:
    global _cache
    _cache = None


def suspect(where: str) -> None:
    _suspect.add(where)


# --- vernieuwen (worker, of de knop op de NPM-tegel) ---------------------------------------------------------------

async def _probe(where: tuple[str, int]) -> tuple[bool, str | None]:
    host, port = where
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), PROBE_TIMEOUT)
    except (TimeoutError, asyncio.TimeoutError):
        return False, "time-out"
    except ConnectionRefusedError:
        return False, REFUSED
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


async def _list(integ, path: str) -> list[dict] | None:
    try:
        items = await integ.get(path)
    except IntegrationError:
        return None
    return items if isinstance(items, list) else None


async def refresh(db: AsyncSession, clients, now: datetime | None = None, force_probe: bool = False) -> dict:
    """Proxy hosts en certificaten uit elke NPM-tegel, en de doelen proberen die nog niet (of lang niet) lukten.
    force_probe: alle doelen opnieuw (de knop "nu vernieuwen")."""
    now = now or datetime.now(timezone.utc)
    st = await ensure_state(db, KEY, {})
    prev = dict(st.value or {})
    old_hosts: dict[str, dict] = prev.get("hosts") or {}
    per_npm: list[dict[str, dict]] = []
    errors: dict[str, str] = {}

    def kept(sid: int) -> dict[str, dict]:
        """De routes van deze NPM uit de vorige ronde (ook namen die in meer dan één NPM staan)."""
        return {n: e_ for n, e_ in old_hosts.items() if sid in (e_.get("npms") or [e_.get("npm")])}

    for svc in (await db.execute(select(Service).where(Service.type == "npm").order_by(Service.id))).scalars().all():
        try:
            integ = build(svc, clients)
            via = await _npm_ip(integ.base)
            proxy_hosts = await integ.proxy_hosts()
        except IntegrationError as e:
            # NPM even niet bereikbaar: de routes van die tegel blijven zoals ze waren.
            errors[str(svc.id)] = str(e)[:200]
            per_npm.append(kept(svc.id))
            continue
        certs = await _list(integ, "/nginx/certificates")
        redirects = await _list(integ, "/nginx/redirection-hosts")
        dead = await _list(integ, "/nginx/dead-hosts")
        if (certs is None or redirects is None or dead is None) and (old := kept(svc.id)):
            # Half gelukt: liever de vorige ronde dan certificaten of doorverwijzingen die plots "weg" zijn.
            errors[str(svc.id)] = "certificaten, redirection- of 404-hosts niet op te halen"
            per_npm.append(old)
            continue
        others = [(redirects or [], "NPM stuurt deze naam door (redirection host)"), (dead or [], "404-host in NPM")]
        per_npm.append(build_hosts(proxy_hosts if isinstance(proxy_hosts, list) else [], certs, svc.id, via, others))
    hosts: dict[str, dict] = {}
    owners: dict[str, set[int]] = {}
    for found in per_npm:
        for name, entry in found.items():
            owners.setdefault(name, set()).update(entry.get("npms") or [entry.get("npm")])
            hosts.setdefault(name, entry)
    for name, ids in owners.items():
        if len(ids) > 1:
            # Welke NPM de naam in DNS krijgt, weten we niet: via de naam, zoals vroeger.
            hosts[name] = {**hosts[name], "why": "staat in meer dan één NPM", "via": None, "locations": [],
                           "npms": sorted(ids)}
    old_probes: dict[str, dict] = prev.get("probes") or {}
    wanted = _endpoints(hosts)
    recheck = set(_suspect)
    _suspect.difference_update(recheck)
    todo = []
    for host, port in wanted:
        p = old_probes.get(endpoint(host, port))
        at = _at(p.get("at")) if p else None
        if (force_probe or not p or not p.get("ok") or at is None or (now - at).total_seconds() > PROBE_OK_EVERY
                or endpoint(host, port) in recheck):
            todo.append((host, port))
    sem = asyncio.Semaphore(PROBE_PARALLEL)

    async def one(where):
        async with sem:
            return where, await _probe(where)

    results = await asyncio.gather(*(one(w) for w in todo))
    probes = {k: v for k, v in old_probes.items() if k in {endpoint(h, p) for h, p in wanted}}
    for (host, port), (ok, error) in results:
        probes[endpoint(host, port)] = {"ok": ok, "error": error, "at": now.isoformat()}
    value = {"at": now.isoformat(), "hosts": hosts, "probes": probes, "errors": errors}
    st.value = value
    on = await db.get(AppState, KEY_ON)
    remember(Table(value, (on.value or {}).get("enabled", True) is not False if on else True))
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


def describe(check: dict | None, url: str | None, tab: Table) -> dict | None:
    """Voor het mini dashboard: rechtstreeks naar de server, via NPM op zijn IP, of via de naam, en waarom.
    None = NPM kent de naam niet (of de check gaat niet op een naam)."""
    check = check or {}
    if check.get("type") not in ("http", "tcp", "ping"):
        return None
    name = name_and_path(check, url)[0]
    if not name or _is_ip(name) or tab.entry(name) is None:
        return None
    if check.get("direct") is False:
        return {"direct": False, "why": "uitgezet voor deze tegel"}
    if not tab.enabled:
        return {"direct": False, "why": "uitgezet op de NPM-tegel"}
    p = tab.plan(check, url)
    if p is None or p.route is None:
        return {"direct": False, "why": p.why if p else None, "blocked": p.blocked if p else None}
    to = f"{p.route.scheme}://{p.route.where}" if check.get("type") == "http" else p.target
    if p.route.npm:
        return {"direct": False, "npm": p.route.host, "to": to, "why": p.why, "blocked": p.blocked}
    return {"direct": True, "to": to}


async def overview(db: AsyncSession) -> dict:
    """Per tegel met een check: rechtstreeks of via de naam (en waarom), plus de doelen die de firewall tegenhoudt."""
    from .engine import active

    st = await db.get(AppState, KEY)
    value = st.value if st else {}
    tab = await load(db)
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
        "blocked": [{"endpoint": k, "tiles": v, "refused": (tab.probes.get(k) or {}).get("error") == REFUSED}
                    for k, v in sorted(blocked.items())],
    }
