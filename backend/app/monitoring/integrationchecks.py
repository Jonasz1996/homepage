"""Checks via de integraties, ter vervanging van Uptime Kuma:

- container: draait een container (en is hij niet unhealthy), gevraagd aan de Portainer-tegel. Geen Docker-socket
  en geen nieuw geheim nodig.
- api: antwoordt de API van een tegel, met de sleutels die het dashboard er al voor bewaart (API-beheer,
  geheimen van de tegel of de ingebouwde integratie).

De check zelf (Service.check) bevat nooit een geheim: die gaat naar de browser en naar de YAML-export.
Beide checks gooien nooit: elke fout wordt een Outcome.
"""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable

from .. import integrations
from ..integrations import REGISTRY, Integration, IntegrationError, calls
from ..integrations.jsonapi import JsonApi
from ..integrations.portainer import Portainer
from ..integrations.rest import RestApi
from ..models import ApiConnection, Service
from .checks import CHECK_TIMEOUT, HttpClients, Outcome, _content_error, _short

# Zo lang delen alle container-checks op dezelfde Portainer (en omgeving) één lijst van containers:
# 30 checks kosten zo één API-call per 20 s.
CONTAINER_TTL = 20.0
# Herkenbaar begin van de fout als Portainer zelf niet antwoordt (de UI zet de Portainer-tegel als afhankelijkheid,
# zodat een storing van Portainer één melding blijft).
UNREACHABLE = "Portainer onbereikbaar: "
GONE = "Portainer-tegel bestaat niet meer"
NO_API = "Deze tegel heeft geen API of integratie: koppel er een via bewerken → Integratie en API"

# Klok van de cache (tests zetten hun eigen).
_clock: Callable[[], float] = time.monotonic


# --- Gemeenschappelijk ------------------------------------------------------------

_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]*@")
_QUERY = re.compile(r"\?[^\s)\"']+")


def _clean(text: str, secrets: dict | None) -> str:
    """Nooit een geheim in een foutmelding: geen sleutels, geen user:pass@ in een url en geen ?query (apikey=...)."""
    for v in (secrets or {}).values():
        if isinstance(v, str) and len(v) >= 4:
            text = text.replace(v, "***")
    text = _USERINFO.sub(r"\1", text)
    return _QUERY.sub("", text)


def _reason(e: Exception, secrets: dict | None) -> str:
    return _short(IntegrationError(_clean(str(e) or type(e).__name__, secrets)))


def _internal(e: Exception) -> Outcome:
    return Outcome(False, error=f"Interne fout in de check: {type(e).__name__}")


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


# --- Container (via Portainer) ------------------------------------------------------

@dataclass
class _Snapshot:
    """Containers van één Portainer (en omgeving) op één moment, of de fout van Portainer."""
    containers: list[dict] = field(default_factory=list)  # [{"names", "env", "state", "status"}]
    # Omgevingen die niet meededen (offline, of hun Docker-API antwoordde niet).
    missing: list[str] = field(default_factory=list)
    error: str | None = None
    at: float = 0.0


_cache: dict[tuple[int, int | None], _Snapshot] = {}
_locks: dict[tuple[int, int | None], tuple[asyncio.AbstractEventLoop, asyncio.Lock]] = {}


def clear_cache() -> None:
    _cache.clear()
    _locks.clear()


def _lock(key: tuple[int, int | None]) -> asyncio.Lock:
    loop = asyncio.get_running_loop()
    held = _locks.get(key)
    if held is None or held[0] is not loop:  # een lock hoort bij één event loop
        held = _locks[key] = (loop, asyncio.Lock())
    return held[1]


def _fresh(key: tuple[int, int | None]) -> _Snapshot | None:
    snap = _cache.get(key)
    return snap if snap is not None and _clock() - snap.at < CONTAINER_TTL else None


def is_portainer(svc: Service) -> bool:
    """Is dit een Portainer-tegel (zelf, of gekoppeld aan een Portainer-API uit API-beheer)?"""
    api = svc.__dict__.get("api") if getattr(svc, "api_id", None) else None
    return (api.kind if api is not None else svc.type) == "portainer"


async def _portainer(db, portainer_id) -> Service | None:
    try:
        pid = int(portainer_id)
    except (TypeError, ValueError):
        return None
    svc = await db.get(Service, pid)
    return svc if svc is not None and is_portainer(svc) else None


def _env(value) -> int | None:
    if value in (None, ""):
        return None
    if isinstance(value, bool):
        raise ValueError
    return int(str(value).strip())


def _rows(env_id, data) -> list[dict]:
    out = []
    for c in data if isinstance(data, list) else []:
        if not isinstance(c, dict):
            continue
        names = [n.lstrip("/") for n in c.get("Names") or [] if isinstance(n, str)]
        out.append({"names": names, "env": env_id, "state": str(c.get("State") or ""), "status": str(c.get("Status") or "")})
    return out


async def _fetch(svc: Service, env: int | None, http: HttpClients) -> _Snapshot:
    integ = None
    try:
        integ = integrations.build(svc, http)
        if not isinstance(integ, Portainer):
            raise IntegrationError("geen Portainer-integratie")
        if env is not None:
            return _Snapshot(_rows(env, await integ.containers(env)))
        # Geen omgeving gekozen: zoals de Portainer-tegel zelf (alle omgevingen, of die uit zijn instellingen).
        envs = [e for e in await integ.envs() if isinstance(e, dict)]
        up = [e for e in envs if e.get("Status") == 1]
        missing = [f"omgeving {e.get('Name') or e.get('Id')} offline" for e in envs if e.get("Status") != 1]
        results = await asyncio.gather(*(integ.containers(e["Id"]) for e in up), return_exceptions=True)
        rows: list[dict] = []
        for e, res in zip(up, results):
            if isinstance(res, IntegrationError):
                missing.append(f"omgeving {e.get('Name') or e.get('Id')} onbereikbaar: {_reason(res, integ.secrets)}")
            elif isinstance(res, BaseException):
                raise res
            else:
                rows += _rows(e["Id"], res)
        return _Snapshot(rows, missing)
    except IntegrationError as e:
        return _Snapshot(error=_reason(e, getattr(integ, "secrets", None)))


async def _snapshot(svc: Service, env: int | None, http: HttpClients) -> tuple[_Snapshot, float | None]:
    """De containers (uit de cache, of opgehaald). Tweede waarde: duur van de API-call als déze aanroep hem deed.
    Gelijktijdige checks wachten op hetzelfde lock en delen zo één verzoek, ook als dat een fout gaf."""
    key = (svc.id, env)
    snap = _fresh(key)
    if snap is not None:
        return snap, None
    async with _lock(key):
        snap = _fresh(key)
        if snap is not None:
            return snap, None
        start = time.perf_counter()
        snap = await _fetch(svc, env, http)
        ms = _ms(start)
        snap.at = _clock()
        _cache[key] = snap
        return snap, (None if snap.error else ms)


def _rank(c: dict) -> int:
    if c["state"] != "running":
        return 2
    return 1 if "(unhealthy)" in c["status"] else 0


def _verdict(snap: _Snapshot, name: str, ms: float | None) -> Outcome:
    found = [c for c in snap.containers if name in c["names"]]
    if not found:
        extra = f" ({'; '.join(snap.missing)})" if snap.missing else ""
        return Outcome(False, ms, error=f"container {name} niet gevonden{extra}"[:300])
    # Dezelfde naam in meerdere omgevingen: één gezonde volstaat (kies "env" in de check om er één te volgen).
    c = min(found, key=_rank)
    if c["state"] != "running":
        return Outcome(False, ms, error=f"gestopt ({c['status'] or c['state'] or '?'})"[:300])
    if "(unhealthy)" in c["status"]:
        return Outcome(False, ms, error=f"unhealthy ({c['status']})"[:300])
    return Outcome(True, ms)


async def check_container(db, check: dict, http: HttpClients) -> Outcome:
    """check = {"type": "container", "portainer_id": id van de Portainer-tegel, "env": optioneel id van de
    Portainer-omgeving, "container": "naam"}. In orde als de container draait en niet unhealthy is."""
    try:
        async with asyncio.timeout(CHECK_TIMEOUT):
            return await _check_container(db, check, http)
    except TimeoutError:
        return Outcome(False, error="Time-out")
    except Exception as e:  # een check gooit nooit
        return _internal(e)


async def _check_container(db, check: dict, http: HttpClients) -> Outcome:
    name = str(check.get("container") or "").strip().lstrip("/")
    if not name:
        return Outcome(False, error="Geen container ingesteld")
    try:
        env = _env(check.get("env"))
    except ValueError:
        return Outcome(False, error="Ongeldige omgeving (env): het id van een Portainer-omgeving")
    svc = await _portainer(db, check.get("portainer_id"))
    if svc is None:
        return Outcome(False, error=GONE)
    snap, ms = await _snapshot(svc, env, http)
    if snap.error:
        return Outcome(False, error=(UNREACHABLE + snap.error)[:300])
    return _verdict(snap, name, ms)


async def list_containers(db, portainer_id: int, http: HttpClients) -> list[dict]:
    """Alle containers van een Portainer-tegel (alle omgevingen), voor de keuzelijst in het formulier:
    [{"name", "env", "state"}]. Gooit IntegrationError als de tegel geen Portainer is of Portainer niet antwoordt."""
    svc = await _portainer(db, portainer_id)
    if svc is None:
        raise IntegrationError(GONE)
    snap, _ = await _snapshot(svc, None, http)
    if snap.error:
        raise IntegrationError((UNREACHABLE + snap.error)[:300])
    out = [{"name": c["names"][0], "env": c["env"], "state": c["state"]} for c in snap.containers if c["names"]]
    return sorted(out, key=lambda c: (c["name"].lower(), str(c["env"])))


# --- API van de tegel -------------------------------------------------------------

# Zonder pad: per soort integratie de lichtste call die toch de sleutels nodig heeft. Een tekst is een pad achter
# het API-pad van de integratie (call_prefix, bv. /api2/json); anders een functie. Niet in de lijst: summary().
HEALTH: dict[str, str | Callable[[Any], Awaitable[Any]]] = {
    "proxmox": "/version",
    "pbs": "/version",
    "homeassistant": "/",
    "adguard": "/status",
    "portainer": "/endpoints",
    "npm": "/nginx/proxy-hosts",
    "opnsense": "/routes/gateway/status",
    "cloudflared": lambda i: i.tunnels(),
    "zabbix": lambda i: i.rpc("host.get", {"countOutput": True}),
}


class _Client:
    """De gedeelde HTTP-client, met de time-out van de check; onthoudt de HTTP-status van het laatste verzoek."""

    def __init__(self, inner, timeout: float | None) -> None:
        self._inner = inner
        self._timeout = timeout
        self.status: int | None = None

    async def request(self, method: str, url, **kw):
        self.status = None
        if self._timeout:
            kw["timeout"] = self._timeout
        r = await self._inner.request(method, url, **kw)
        self.status = r.status_code
        return r

    def __getattr__(self, name: str):
        return getattr(self._inner, name)


def _timeout(check: dict) -> int | None:
    try:
        t = int(check.get("timeout") or 0)
    except (TypeError, ValueError):
        return None
    return min(max(t, 1), 60) if t else None


async def _build(db, svc: Service, http: HttpClients) -> Integration:
    api_id = getattr(svc, "api_id", None)
    if api_id and svc.__dict__.get("api") is None and db is not None:
        # De API was niet mee geladen: zelf ophalen in plaats van een fout.
        api = await db.get(ApiConnection, api_id)
        if api is not None:
            return integrations.from_api(api, svc.config, http)
    return integrations.build(svc, http)


def _relative(integ: Integration, path: str) -> str:
    """Pad achter het API-pad van de integratie, zoals bij eigen calls; met dat API-pad ervoor mag ook."""
    p = integ.call_prefix
    if p and (path == p or path.startswith((p + "/", p + "?"))):
        return path[len(p):]
    return path


async def _health(integ: Integration) -> Any:
    if isinstance(integ, RestApi):
        # Eigen API: de eerste GET-call uit API-beheer, anders het adres van de API zelf (met de aanmelding).
        call = next((c for c in integ.calls if c["method"] == "GET" and c["show"] != "action"), None)
        return await calls.run(integ, call or {"method": "GET", "path": ""})
    if isinstance(integ, JsonApi):  # ook customapi: de url van de tegel zelf
        return await integ.fetch()
    how = HEALTH.get(integ.name)
    if isinstance(how, str):
        return await calls.run(integ, {"method": "GET", "path": how})
    if how is not None:
        return await how(integ)
    return {str(f.get("label")): f.get("value") for f in await integ.summary()}


def _json_error(check: dict, data: Any) -> str | None:
    path = str(check.get("json_path") or "").strip()
    if not path:
        return None
    if isinstance(data, str):
        return "Antwoord is geen JSON"
    return _content_error({"json_path": path, "json_value": check.get("json_value")},
                          json.dumps(data, default=str).encode())


async def check_api(db, svc: Service, check: dict, http: HttpClients) -> Outcome:
    """check = {"type": "api", "path": optioneel (bv. /api/v3/system/status), "json_path": optioneel,
    "json_value": optioneel, "timeout": optioneel 1..60 s}. Vraagt de API van de tegel met de eigen aanmelding."""
    try:
        limit = _timeout(check)
        async with asyncio.timeout(limit or CHECK_TIMEOUT):
            return await _check_api(db, svc, check, http, limit)
    except TimeoutError:
        return Outcome(False, error="Time-out")
    except Exception as e:  # een check gooit nooit
        return _internal(e)


async def _check_api(db, svc: Service, check: dict, http: HttpClients, limit: int | None) -> Outcome:
    if not getattr(svc, "api_id", None) and svc.type not in REGISTRY:
        return Outcome(False, error=NO_API)
    try:
        integ = await _build(db, svc, http)
    except IntegrationError as e:
        return Outcome(False, error=_reason(e, None))
    client = integ.client = _Client(integ.client, limit)
    path = str(check.get("path") or "").strip()
    start = time.perf_counter()
    try:
        data = await (calls.run(integ, {"method": "GET", "path": _relative(integ, path)}) if path else _health(integ))
    except IntegrationError as e:
        return Outcome(False, _ms(start) if client.status else None, client.status, _reason(e, integ.secrets))
    ms = _ms(start)
    error = _json_error(check, data)
    return Outcome(error is None, ms, client.status, _clean(error, integ.secrets) if error else None)
