"""De checks zelf: HTTP(S), ping, TCP en DNS. Elke check geeft een Outcome terug en gooit nooit."""

import asyncio
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from cryptography import x509

TIMEOUT = 10.0
# Bovengrens voor één check in zijn geheel (DNS, verbinden, trage body): een hangende check blokkeert anders
# een plaats in de worker.
CHECK_TIMEOUT = 25.0
# Zoveel van de pagina lezen voor een woord- of JSON-controle.
MAX_BODY = 1_000_000
_PING_TIME = re.compile(r"time[=<]([\d.]+)\s*ms")


@dataclass
class Outcome:
    ok: bool
    latency_ms: float | None = None
    status_code: int | None = None
    error: str | None = None
    cert_expires: datetime | None = None
    # http: de host waar de pagina na doorverwijzingen eindigde, als dat een andere is (bv. de loginpagina).
    redirected_to: str | None = None


def target_for(check: dict, url: str | None) -> str | None:
    """Het doel van de check; leeg = afgeleid van de URL van de service."""
    target = (check.get("target") or "").strip()
    if target:
        return target
    if not url:
        return None
    if check.get("type") == "http":
        return url
    parts = urlsplit(url)
    if check.get("type") == "dns":
        return parts.hostname
    if check.get("type") == "tcp":
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return f"{parts.hostname}:{port}"
    return parts.hostname


def _cert_expiry(response: httpx.Response) -> datetime | None:
    """Vervaldatum van het TLS-certificaat van de server die geantwoord heeft."""
    stream = response.extensions.get("network_stream")
    ssl_object = stream.get_extra_info("ssl_object") if stream else None
    if ssl_object is None:
        return None
    try:
        der = ssl_object.getpeercert(binary_form=True)
        return x509.load_der_x509_certificate(der).not_valid_after_utc if der else None
    except (ValueError, AttributeError):
        return None


def _lookup(data, path: str):
    for part in str(path).split("."):
        if isinstance(data, list):
            try:
                data = data[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(data, dict):
            data = data.get(part)
        else:
            return None
    return data


def _content_error(check: dict, body: bytes) -> str | None:
    """Woord- en JSON-controle op de inhoud. None = in orde."""
    keyword = (check.get("keyword") or "").strip()
    if keyword:
        found = keyword.lower() in body.decode("utf-8", errors="replace").lower()
        if check.get("keyword_absent") and found:
            return f"'{keyword}' staat op de pagina"[:300]
        if not check.get("keyword_absent") and not found:
            return f"'{keyword}' niet gevonden"[:300]
    path = (check.get("json_path") or "").strip()
    if path:
        try:
            value = _lookup(json.loads(body), path)
        except ValueError:
            return "Antwoord is geen JSON"
        expected = check.get("json_value")
        if value is None:
            return f"{path} ontbreekt"[:300]
        if expected not in (None, "") and str(value).lower() != str(expected).lower():
            return f"{path} = {value} (verwacht {expected})"[:300]
    return None


def _accept_rule(check: dict) -> str | None:
    """Geldige statuscodes als tekst (200-299,401); oude checks hadden één code in expect_status."""
    rule = str(check.get("accept") or check.get("expect_status") or "").replace(" ", "")
    return rule or None


def accepted(code: int, check: dict) -> bool:
    rule = _accept_rule(check)
    if not rule:
        return code < 400
    for part in rule.split(","):
        lo, _, hi = part.partition("-")
        try:
            if int(lo) <= code <= int(hi or lo):
                return True
        except ValueError:
            continue
    return False


BODY_TYPES = {"json": "application/json", "form": "application/x-www-form-urlencoded", "text": "text/plain"}


async def check_http(target: str, check: dict, client: httpx.AsyncClient | None = None) -> Outcome:
    need_body = bool((check.get("keyword") or "").strip() or (check.get("json_path") or "").strip())
    method = check.get("method") if check.get("method") in ("GET", "HEAD", "POST") else "GET"
    follow = check.get("follow_redirects") is not False
    timeout = _seconds(check.get("timeout"), TIMEOUT)
    headers = {"User-Agent": "homepage-monitor/1.0", **{str(k): str(v) for k, v in (check.get("headers") or {}).items()}}
    body = check.get("body") if method == "POST" else None
    if body is not None:
        headers.setdefault("Content-Type", BODY_TYPES.get(check.get("body_type") or "", "application/json"))
    own = client is None
    client = client or httpx.AsyncClient(verify=not check.get("insecure"), timeout=TIMEOUT, follow_redirects=True)
    start = time.perf_counter()
    try:
        async with client.stream(method, target, headers=headers, content=body, timeout=timeout,
                                 follow_redirects=follow) as r:
            ms = (time.perf_counter() - start) * 1000
            cert = _cert_expiry(r) if r.url.scheme == "https" else None
            data = b""
            if need_body and method != "HEAD":
                async for chunk in r.aiter_bytes():
                    data += chunk
                    if len(data) >= MAX_BODY:
                        break
        # Doorverwezen naar een andere host: meestal de loginpagina van Authentik of Cloudflare Access. Die antwoordt
        # 200, ook als de app erachter dood is.
        start_host = (urlsplit(target).hostname or "").lower()
        end_host = (r.url.host or "").lower()
        if not follow and r.is_redirect:
            end_host = (urlsplit(str(r.url.join(r.headers.get("location", "")))).hostname or "").lower()
        moved = end_host if end_host and end_host != start_host else None
        ok = accepted(r.status_code, check)
        rule = _accept_rule(check)
        error = None if ok else f"HTTP {r.status_code}" + (f" (verwacht {rule})" if rule else "")
        if ok and moved and check.get("same_host"):
            ok, error = False, f"Doorverwezen naar {moved} (loginpagina?)"
        if ok and need_body and method != "HEAD":
            error = _content_error(check, data)
            ok = error is None
        return Outcome(ok, round(ms, 1), r.status_code, error, cert, moved)
    except httpx.TimeoutException:
        return Outcome(False, error="Time-out")
    except httpx.HTTPError as e:
        return Outcome(False, error=_short(e))
    finally:
        if own:
            await client.aclose()


def _seconds(value, default: float) -> float:
    try:
        v = float(value)
    except (TypeError, ValueError):
        return default
    return min(max(v, 1.0), 60.0)


async def check_dns(target: str, check: dict) -> Outcome:
    """Lost de naam op (via een gekozen DNS-server, bv. AdGuard) en vergelijkt eventueel met het verwachte IP."""
    name = target.strip().rstrip(".")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*", name):
        return Outcome(False, error="Ongeldige naam")
    resolver = dns.asyncresolver.Resolver(configure=not check.get("dns_server"))
    if check.get("dns_server"):
        try:
            resolver.nameservers = [str(ipaddress.ip_address(str(check["dns_server"]).strip()))]
        except ValueError:
            return Outcome(False, error="DNS-server moet een IP-adres zijn")
    resolver.lifetime = _seconds(check.get("timeout"), 5)
    try:
        resolver.port = int(check.get("dns_port") or 53)
    except (TypeError, ValueError):
        return Outcome(False, error="DNS-poort klopt niet")
    start = time.perf_counter()
    try:
        answer = await resolver.resolve(name, "AAAA" if check.get("record") == "AAAA" else "A")
    except dns.resolver.NXDOMAIN:
        return Outcome(False, error="Naam bestaat niet (NXDOMAIN)")
    except dns.exception.Timeout:
        return Outcome(False, error="Time-out")
    except dns.exception.DNSException as e:
        return Outcome(False, error=_short(e))
    ms = round((time.perf_counter() - start) * 1000, 1)
    ips = sorted(r.to_text() for r in answer)
    expect = (check.get("expect") or "").strip()
    if expect and expect not in ips:
        return Outcome(False, ms, error=f"{name} → {', '.join(ips)} (verwacht {expect})"[:300])
    return Outcome(True, ms)


async def check_tcp(target: str, timeout: float = 5) -> Outcome:
    host, _, port = target.rpartition(":")
    if not host or not port.isdigit():
        return Outcome(False, error="Doel moet host:poort zijn")
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host.strip("[]"), int(port)), timeout=timeout)
        ms = (time.perf_counter() - start) * 1000
        writer.close()
        return Outcome(True, round(ms, 1))
    except asyncio.TimeoutError:
        return Outcome(False, error="Time-out")
    except OSError as e:
        return Outcome(False, error=_short(e))


async def kill(proc: asyncio.subprocess.Process) -> None:
    """Kindproces stoppen en opruimen, zodat er na een time-out geen ping (of pg_restore) blijft hangen."""
    if proc.returncode is None:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(proc.wait(), 2)
    except asyncio.TimeoutError:
        pass


async def check_ping(target: str) -> Outcome:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:_-]*", target):
        return Outcome(False, error="Ongeldig doel")
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "2", "-n", target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return Outcome(False, error="ping niet geïnstalleerd")
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
    except (asyncio.TimeoutError, asyncio.CancelledError) as e:
        await kill(proc)
        if isinstance(e, asyncio.CancelledError):
            raise
        return Outcome(False, error="Time-out")
    m = _PING_TIME.search(out.decode(errors="replace"))
    if proc.returncode == 0 and m:
        return Outcome(True, float(m.group(1)))
    return Outcome(False, error=(err.decode(errors="replace").strip() or "Geen antwoord")[:300])


class HttpClients:
    """Twee gedeelde clients (met en zonder certificaatcontrole), zodat verbindingen hergebruikt worden."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._clients: dict[bool, httpx.AsyncClient] = {}
        self.transport = transport  # alleen voor tests

    def get(self, insecure: bool) -> httpx.AsyncClient:
        if insecure not in self._clients:
            self._clients[insecure] = httpx.AsyncClient(
                verify=not insecure, timeout=TIMEOUT, follow_redirects=True,
                limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
                transport=self.transport,
            )
        return self._clients[insecure]

    async def aclose(self) -> None:
        for c in self._clients.values():
            await c.aclose()
        self._clients.clear()


# Deze soorten draaien niet hier: push wacht op een signaal (monitoring/push.py), container en api hebben de
# database nodig voor de Portainer-tegel of de sleutels (monitoring/integrationchecks.py, via de worker).
NOT_HERE = ("push", "container", "api")


async def run_check(check: dict, url: str | None, clients: HttpClients | None = None) -> Outcome:
    try:
        async with asyncio.timeout(max(CHECK_TIMEOUT, _seconds(check.get("timeout"), 0) + 5)):
            return await _run_check(check, url, clients)
    except TimeoutError:
        return Outcome(False, error="Time-out")
    except Exception as e:  # noqa: BLE001 - een fout in een check is een mislukte check, geen bevroren tegel
        return Outcome(False, error=f"Interne fout in de check: {type(e).__name__}")


async def check_service(maker, sid: int, check: dict, url: str | None, clients: HttpClients) -> Outcome:
    """Eender welke check van tegel sid, ook de containercheck en de API van de tegel (die hebben de database nodig
    voor de sleutels). Een push-check heeft niets om na te kijken: die wacht op signalen."""
    if check.get("type") not in NOT_HERE:
        return await run_check(check, url, clients)
    if check.get("type") == "push":
        return Outcome(False, error="Een push-check wacht op signalen")
    from ..models import Service
    from . import integrationchecks
    try:
        async with asyncio.timeout(CHECK_TIMEOUT + 35), maker() as db:
            if check.get("type") == "container":
                return await integrationchecks.check_container(db, check, clients)
            service = await db.get(Service, sid)
            if service is None:
                return Outcome(False, error="Tegel bestaat niet meer")
            return await integrationchecks.check_api(db, service, check, clients)
    except TimeoutError:
        return Outcome(False, error="Time-out")


async def _run_check(check: dict, url: str | None, clients: HttpClients | None = None) -> Outcome:
    kind = check.get("type")
    if kind in NOT_HERE:
        return Outcome(False, error=f"Check {kind} loopt via de worker")
    target = target_for(check, url)
    if not target:
        return Outcome(False, error="Geen doel ingesteld")
    if kind == "http":
        client = clients.get(bool(check.get("insecure"))) if clients else None
        return await check_http(target, check, client)
    if kind == "tcp":
        return await check_tcp(target, _seconds(check.get("timeout"), 5))
    if kind == "ping":
        return await check_ping(target)
    if kind == "dns":
        return await check_dns(target, check)
    return Outcome(False, error=f"Onbekend check-type {kind!r}")


# Veelvoorkomende netwerkfouten in gewone taal (de originele tekst staat erachter).
_FRIENDLY = (
    ("Name or service not known", "DNS: naam onbekend"),
    ("Temporary failure in name resolution", "DNS: geen antwoord"),
    ("nodename nor servname", "DNS: naam onbekend"),
    ("Connection refused", "Verbinding geweigerd"),
    ("No route to host", "Geen route naar host"),
    ("Network is unreachable", "Netwerk onbereikbaar"),
    ("CERTIFICATE_VERIFY_FAILED", "Certificaat niet vertrouwd"),
)


def _short(e: Exception) -> str:
    text = str(e) or type(e).__name__
    for needle, label in _FRIENDLY:
        if needle in text:
            return f"{label} ({text})"[:300]
    return text[:300]
