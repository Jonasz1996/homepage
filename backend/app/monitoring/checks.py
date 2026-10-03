"""De checks zelf: HTTP(S), ping en TCP. Elke check geeft een Outcome terug en gooit nooit."""

import asyncio
import re
import time
from dataclasses import dataclass
from urllib.parse import urlsplit

import httpx

TIMEOUT = 10.0
_PING_TIME = re.compile(r"time[=<]([\d.]+)\s*ms")


@dataclass
class Outcome:
    ok: bool
    latency_ms: float | None = None
    status_code: int | None = None
    error: str | None = None


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
    if check.get("type") == "tcp":
        port = parts.port or (443 if parts.scheme == "https" else 80)
        return f"{parts.hostname}:{port}"
    return parts.hostname


async def check_http(target: str, check: dict, client: httpx.AsyncClient | None = None) -> Outcome:
    expected = check.get("expect_status")
    own = client is None
    client = client or httpx.AsyncClient(verify=not check.get("insecure"), timeout=TIMEOUT, follow_redirects=True)
    start = time.perf_counter()
    try:
        r = await client.get(target, headers={"User-Agent": "homepage-monitor/1.0"})
        ms = (time.perf_counter() - start) * 1000
        ok = r.status_code == int(expected) if expected else r.status_code < 400
        return Outcome(ok, round(ms, 1), r.status_code, None if ok else f"HTTP {r.status_code}")
    except httpx.TimeoutException:
        return Outcome(False, error="Time-out")
    except httpx.HTTPError as e:
        return Outcome(False, error=_short(e))
    finally:
        if own:
            await client.aclose()


async def check_tcp(target: str) -> Outcome:
    host, _, port = target.rpartition(":")
    if not host or not port.isdigit():
        return Outcome(False, error="Doel moet host:poort zijn")
    start = time.perf_counter()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host.strip("[]"), int(port)), timeout=5)
        ms = (time.perf_counter() - start) * 1000
        writer.close()
        return Outcome(True, round(ms, 1))
    except asyncio.TimeoutError:
        return Outcome(False, error="Time-out")
    except OSError as e:
        return Outcome(False, error=_short(e))


async def check_ping(target: str) -> Outcome:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:_-]*", target):
        return Outcome(False, error="Ongeldig doel")
    try:
        proc = await asyncio.create_subprocess_exec(
            "ping", "-c", "1", "-W", "2", "-n", target,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        out, err = await asyncio.wait_for(proc.communicate(), timeout=5)
    except (asyncio.TimeoutError, FileNotFoundError) as e:
        return Outcome(False, error="Time-out" if isinstance(e, asyncio.TimeoutError) else "ping niet geïnstalleerd")
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


async def run_check(check: dict, url: str | None, clients: HttpClients | None = None) -> Outcome:
    target = target_for(check, url)
    if not target:
        return Outcome(False, error="Geen doel ingesteld")
    kind = check.get("type")
    if kind == "http":
        client = clients.get(bool(check.get("insecure"))) if clients else None
        return await check_http(target, check, client)
    if kind == "tcp":
        return await check_tcp(target)
    if kind == "ping":
        return await check_ping(target)
    return Outcome(False, error=f"Onbekend check-type {kind!r}")


def _short(e: Exception) -> str:
    return (str(e) or type(e).__name__)[:300]
