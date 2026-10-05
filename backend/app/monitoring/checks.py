"""De checks zelf: HTTP(S), ping, TCP en DNS. Elke check geeft een Outcome terug en gooit nooit."""

import asyncio
import ipaddress
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from http.cookiejar import CookieJar, DefaultCookiePolicy
from http.cookies import CookieError, SimpleCookie
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
# Zelf doorverwijzingen volgen (rechtstreekse checks): hoogstens zoveel, zoals httpx.
MAX_REDIRECTS = 20
# Rechtstreeks naar een server op het LAN: lukt verbinden niet zo snel, dan via NPM (de route kan verouderd zijn).
DIRECT_CONNECT = 3.0


def endpoint_of(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


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
    need_body, method, follow, timeout, headers, body = _request_parts(check)
    own = client is None
    client = client or httpx.AsyncClient(verify=not check.get("insecure"), timeout=TIMEOUT, follow_redirects=True)
    start = time.perf_counter()
    try:
        async with client.stream(method, target, headers=headers, content=body, timeout=timeout,
                                 follow_redirects=follow) as r:
            ms = (time.perf_counter() - start) * 1000
            cert = _cert_expiry(r) if r.url.scheme == "https" else None
            data = await _read(r, need_body and method != "HEAD")
        start_host = (urlsplit(target).hostname or "").lower()
        end_host = (r.url.host or "").lower()
        if not follow and r.is_redirect:
            end_host = (urlsplit(str(r.url.join(r.headers.get("location", "")))).hostname or "").lower()
        ok, error, moved = _verdict(check, r.status_code, start_host, end_host, data, need_body and method != "HEAD")
        return Outcome(ok, round(ms, 1), r.status_code, error, cert, moved)
    except httpx.TimeoutException:
        return Outcome(False, error="Time-out")
    except httpx.HTTPError as e:
        return Outcome(False, error=_short(e))
    finally:
        if own:
            await client.aclose()


def _verdict(check: dict, code: int, start_host: str, end_host: str, data: bytes, content: bool
             ) -> tuple[bool, str | None, str | None]:
    """(ok, fout, doorverwezen naar) voor een antwoord."""
    # Doorverwezen naar een andere host: meestal de loginpagina van Authentik of Cloudflare Access. Die antwoordt
    # 200, ook als de app erachter dood is.
    moved = end_host if end_host and end_host != start_host else None
    ok = accepted(code, check)
    rule = _accept_rule(check)
    error = None if ok else f"HTTP {code}" + (f" (verwacht {rule})" if rule else "")
    if ok and moved and check.get("same_host"):
        ok, error = False, f"Doorverwezen naar {moved} (loginpagina?)"
    if ok and content:
        error = _content_error(check, data)
        ok = error is None
    return ok, error, moved


def _request_parts(check: dict) -> tuple[bool, str, bool, float, dict, str | None]:
    need_body = bool((check.get("keyword") or "").strip() or (check.get("json_path") or "").strip())
    method = check.get("method") if check.get("method") in ("GET", "HEAD", "POST") else "GET"
    follow = check.get("follow_redirects") is not False
    timeout = _seconds(check.get("timeout"), TIMEOUT)
    headers = {"User-Agent": "homepage-monitor/1.0", **{str(k): str(v) for k, v in (check.get("headers") or {}).items()}}
    body = check.get("body") if method == "POST" else None
    if body is not None:
        headers.setdefault("Content-Type", BODY_TYPES.get(check.get("body_type") or "", "application/json"))
    return need_body, method, follow, timeout, headers, body


async def _read(r: httpx.Response, need: bool) -> bytes:
    data = b""
    if need:
        async for chunk in r.aiter_bytes():
            data += chunk
            if len(data) >= MAX_BODY:
                break
    return data


def _host_header(u: httpx.URL) -> str:
    host = u.host or ""
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{u.port}" if u.port else host


def _redirected(method: str, body: str | None, code: int) -> tuple[str, str | None]:
    """Zoals een browser (en httpx): na 303, en na 301/302 op een POST, wordt het een GET zonder body."""
    if (code == 303 and method != "HEAD") or (code in (301, 302) and method == "POST"):
        return "GET", None
    return method, body


def _logical_next(logical: httpx.URL, route, location: str) -> httpx.URL:
    """Waar een doorverwijzing van de server heen gaat, in namen: een Location met het IP en de poort van de server
    zelf (sommige apps kennen alleen hun eigen adres) is dezelfde naam."""
    nxt = logical.join(location)
    port = nxt.port or (443 if nxt.scheme == "https" else 80)
    if (nxt.host or "").lower() == route.host.lower().strip("[]") and port == route.port:
        nxt = nxt.copy_with(scheme=logical.scheme, host=logical.host, port=logical.port)
    return nxt


class _ChainCookies:
    """Cookies binnen één check, per naam (een app die een cookie zet en dan doorverwijst). De clients voor checks
    zonder DNS bewaren er geen: daar is het IP de sleutel, en dan kregen alle apps achter NPM (of op dezelfde server)
    elkaars cookies."""

    def __init__(self) -> None:
        self._c: dict[tuple[str, str], str] = {}  # (domein, naam) -> waarde

    @staticmethod
    def _under(host: str, domain: str) -> bool:
        return host == domain or host.endswith("." + domain)

    def take(self, host: str, r: httpx.Response) -> None:
        host = host.lower()
        for raw in r.headers.get_list("set-cookie"):
            c = SimpleCookie()
            try:
                c.load(raw)
            except CookieError:
                continue
            for name, m in c.items():
                domain = (m["domain"] or "").lstrip(".").lower() or host
                if not self._under(host, domain):
                    continue  # zoals een browser: een cookie voor een ander domein telt niet
                if str(m["max-age"]).strip().lstrip("-").isdigit() and int(m["max-age"]) <= 0:
                    self._c.pop((domain, name), None)
                else:
                    self._c[(domain, name)] = m.coded_value

    def header(self, host: str) -> str | None:
        host = host.lower()
        return "; ".join(f"{n}={v}" for (d, n), v in self._c.items() if self._under(host, d)) or None


async def check_http_direct(logical: httpx.URL, check: dict, clients: "HttpClients | None", table, route) -> Outcome:
    """Zoals check_http, maar zonder DNS (monitoring/routes.py): rechtstreeks naar de server achter NPM, met de headers
    die NPM meestuurt, of (route.npm) naar het IP van NPM zelf, met de naam in Host en SNI. Doorverwijzingen volgen we
    zelf, in namen: zo blijft "doorverwezen naar een andere host" kloppen, en gaat een doorverwijzing naar een andere
    naam achter NPM ook zonder DNS. Een naam die NPM niet kent (een externe login): vanaf daar zoals vroeger."""
    need_body, method, follow, timeout, headers, body = _request_parts(check)
    start_host = (logical.host or "").lower()
    own: list[httpx.AsyncClient] = []

    def client_for(insecure: bool) -> httpx.AsyncClient:
        if clients is not None:
            return clients.get(insecure)
        c = httpx.AsyncClient(verify=not insecure, timeout=TIMEOUT)
        own.append(c)
        return c

    def bare_for(insecure: bool) -> httpx.AsyncClient:
        if clients is not None:
            return clients.bare(insecure)
        c = httpx.AsyncClient(verify=not insecure, timeout=TIMEOUT, cookies=_no_cookies())
        own.append(c)
        return c

    cookies = _ChainCookies()
    start = time.perf_counter()
    hops = 0
    try:
        while True:
            host = _host_header(logical)
            ext = {}
            if route.npm:
                # NPM kiest de proxy host op de naam: in SNI (het certificaat wordt gecontroleerd zoals vroeger) en
                # in Host. Geen verbinding hergebruiken: die hoort bij de naam van de vorige check.
                hdrs = {**headers, "Host": host, "Connection": "close"}
                if logical.scheme == "https":
                    ext["sni_hostname"] = logical.host
                client = bare_for(bool(check.get("insecure")))
            else:
                hdrs = {**headers, "Host": host, "X-Forwarded-Proto": logical.scheme,
                        "X-Forwarded-Scheme": logical.scheme, "X-Forwarded-Host": host}
                # Net als NPM: een https-server erachter heeft meestal een eigen certificaat, dat niemand controleert.
                client = bare_for(route.scheme == "https" or bool(check.get("insecure")))
            jar = cookies.header(logical.host or "")
            if jar and not any(k.lower() == "cookie" for k in hdrs):
                hdrs["Cookie"] = jar
            hop_timeout = timeout if route.npm else httpx.Timeout(timeout, connect=min(timeout, DIRECT_CONNECT))
            try:
                async with client.stream(method, route.url(logical), headers=hdrs, content=body, timeout=hop_timeout,
                                         follow_redirects=False, extensions=ext) as r:
                    cookies.take(logical.host or "", r)
                    if follow and r.is_redirect:
                        if hops >= MAX_REDIRECTS:
                            # Zoals httpx: een kringetje van doorverwijzingen is een fout, geen 302.
                            return Outcome(False, error="Exceeded maximum allowed redirects.")
                        nxt = _logical_next(logical, route, r.headers.get("location", ""))
                        code = r.status_code
                    else:
                        ms = (time.perf_counter() - start) * 1000
                        # Via NPM: het certificaat dat NPM voor de naam toont (zoals vroeger); rechtstreeks: dat uit NPM.
                        cert = None if logical.scheme != "https" else (route.npm and _cert_expiry(r)) or route.cert
                        data = await _read(r, need_body and method != "HEAD")
                        end_host = (logical.host or "").lower()
                        if r.is_redirect:
                            end_host = (_logical_next(logical, route, r.headers.get("location", "")).host or "").lower()
                        ok, error, moved = _verdict(check, r.status_code, start_host, end_host, data,
                                                    need_body and method != "HEAD")
                        if (ok and cert and not route.npm and not check.get("insecure")
                                and cert <= datetime.now(timezone.utc)):
                            # Via de naam weigert de check (en de browser) een verlopen certificaat; rechtstreeks
                            # zien we het alleen in NPM.
                            ok, error = False, f"Certificaat verlopen op {cert:%d/%m/%Y} (volgens NPM)"
                        return Outcome(ok, round(ms, 1), r.status_code, error, cert, moved)
            except (httpx.ConnectError, httpx.ConnectTimeout) as e:
                # De server niet te bereiken: misschien is hij verhuisd en is de route nog van voor de wijziging in
                # NPM. Dan via NPM, zoals de link: is de server echt weg, dan geeft NPM een 502.
                alt = None if route.npm else table.npm_for(logical.host, logical.scheme)
                if alt is None:
                    return Outcome(False, error=f"{'Time-out' if isinstance(e, httpx.TimeoutException) else _short(e)}"
                                                f" ({route.label})"[:300])
                from .routes import suspect
                suspect(route.where)
                route = alt
                continue
            except httpx.TimeoutException:
                return Outcome(False, error=f"Time-out ({route.label})")
            except httpx.HTTPError as e:
                return Outcome(False, error=f"{_short(e)} ({route.label})"[:300])
            hops += 1
            method, body = _redirected(method, body, code)
            nxt_route = (table.find(nxt.host, nxt.path or "/", nxt.scheme, nxt.port)
                         if nxt.scheme in ("http", "https") else None)
            if nxt_route is None:
                return await _rest_by_name(nxt, check, clients, client_for, method, body, headers, need_body, timeout,
                                           start, start_host)
            logical, route = nxt, nxt_route
    finally:
        for c in own:
            await c.aclose()


async def _rest_by_name(url: httpx.URL, check: dict, clients, client_for, method: str, body: str | None, headers: dict,
                        need_body: bool, timeout: float, start: float, start_host: str) -> Outcome:
    """Een doorverwijzing naar een naam die NPM niet kent: verder zoals een gewone check."""
    client = client_for(bool(check.get("insecure")))
    try:
        async with client.stream(method, url, headers=headers, content=body, timeout=timeout,
                                 follow_redirects=True) as r:
            ms = (time.perf_counter() - start) * 1000
            cert = _cert_expiry(r) if r.url.scheme == "https" else None
            data = await _read(r, need_body and method != "HEAD")
    except httpx.TimeoutException:
        return Outcome(False, error="Time-out")
    except httpx.HTTPError as e:
        return Outcome(False, error=_short(e))
    ok, error, moved = _verdict(check, r.status_code, start_host, (r.url.host or "").lower(), data,
                                need_body and method != "HEAD")
    return Outcome(ok, round(ms, 1), r.status_code, error, cert, moved)


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


def _no_cookies() -> CookieJar:
    """Een cookiejar die niets bewaart."""
    return CookieJar(policy=DefaultCookiePolicy(allowed_domains=[]))


class HttpClients:
    """Twee gedeelde clients (met en zonder certificaatcontrole), zodat verbindingen hergebruikt worden. Voor checks
    zonder DNS (op een IP) twee aparte, zonder cookies: één jar per IP zou cookies tussen apps delen."""

    def __init__(self, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._clients: dict[bool, httpx.AsyncClient] = {}
        self._bare: dict[bool, httpx.AsyncClient] = {}
        self.transport = transport  # alleen voor tests

    def _new(self, insecure: bool, **kw) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            verify=not insecure, timeout=TIMEOUT, follow_redirects=True,
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
            transport=self.transport, **kw,
        )

    def get(self, insecure: bool) -> httpx.AsyncClient:
        if insecure not in self._clients:
            self._clients[insecure] = self._new(insecure)
        return self._clients[insecure]

    def bare(self, insecure: bool) -> httpx.AsyncClient:
        if insecure not in self._bare:
            self._bare[insecure] = self._new(insecure, cookies=_no_cookies())
        return self._bare[insecure]

    async def aclose(self) -> None:
        for c in [*self._clients.values(), *self._bare.values()]:
            await c.aclose()
        self._clients.clear()
        self._bare.clear()


# Deze soorten draaien niet hier: push wacht op een signaal (monitoring/push.py), container en api hebben de
# database nodig voor de Portainer-tegel of de sleutels (monitoring/integrationchecks.py, via de worker).
NOT_HERE = ("push", "container", "api")


async def run_check(check: dict, url: str | None, clients: HttpClients | None = None, routes=None) -> Outcome:
    """routes: de tabel uit monitoring/routes.py; dan gaat een check op een naam achter NPM rechtstreeks."""
    try:
        async with asyncio.timeout(max(CHECK_TIMEOUT, _seconds(check.get("timeout"), 0) + 5)):
            return await _run_check(check, url, clients, routes)
    except TimeoutError:
        return Outcome(False, error="Time-out")
    except Exception as e:  # noqa: BLE001 - een fout in een check is een mislukte check, geen bevroren tegel
        return Outcome(False, error=f"Interne fout in de check: {type(e).__name__}")


async def check_service(maker, sid: int, check: dict, url: str | None, clients: HttpClients) -> Outcome:
    """Eender welke check van tegel sid, ook de containercheck en de API van de tegel (die hebben de database nodig
    voor de sleutels). Een push-check heeft niets om na te kijken: die wacht op signalen."""
    if check.get("type") not in NOT_HERE:
        from . import routes
        return await run_check(check, url, clients, await routes.table(maker))
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


async def _run_check(check: dict, url: str | None, clients: HttpClients | None = None, routes=None) -> Outcome:
    kind = check.get("type")
    if kind in NOT_HERE:
        return Outcome(False, error=f"Check {kind} loopt via de worker")
    target = target_for(check, url)
    if not target:
        return Outcome(False, error="Geen doel ingesteld")
    # Zonder DNS (monitoring/routes.py): rechtstreeks naar de server achter NPM, of naar NPM op zijn IP.
    plan = routes.plan(check, url) if routes is not None else None
    if kind == "http":
        if plan is not None and plan.route is not None:
            return await check_http_direct(httpx.URL(target), check, clients, routes, plan.route)
        client = clients.get(bool(check.get("insecure"))) if clients else None
        return await check_http(target, check, client)
    if kind == "tcp":
        if plan is not None and plan.target:
            target = plan.target
            if not plan.route.npm:
                outcome = await check_tcp(target, _seconds(check.get("timeout"), 5))
                if not outcome.ok:
                    from .routes import suspect
                    suspect(plan.route.where)
                return outcome
        return await check_tcp(target, _seconds(check.get("timeout"), 5))
    if kind == "ping":
        if plan is not None and plan.target:
            target = plan.target
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
