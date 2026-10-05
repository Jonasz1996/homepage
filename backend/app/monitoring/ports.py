"""Welke verbindingen het dashboard echt gebruikt, voor een strakke firewallregel tussen de VLAN's.

Uit de tegels (check en integratie), API-beheer, de SSH-hosts en web push: per doel-IP de poorten en wie ze gebruikt.
Namen worden opgezocht in DNS (zoals de container ze ziet). Daarnaast wat er binnenkomt (NPM, syslog, webhooks)
en een voorstel voor aliassen in OPNsense.
"""

import asyncio
import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..models import ApiConnection, Service, SshHost
from .checks import target_for
from .routes import Table
from .routes import load as load_routes
from .webpush import endpoint_hosts

RESOLVE_TIMEOUT = 3.0
RESOLV_CONF = Path("/etc/resolv.conf")


def _from_url(url: str | None) -> tuple[str, int] | None:
    if not url:
        return None
    try:
        p = urlsplit(url.strip())
        host, port = p.hostname, p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        return None
    return (host, port) if host and p.scheme in ("http", "https") else None


def _hostport(target: str) -> tuple[str, int] | None:
    host, _, port = target.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        return (host, int(port)) if host else None
    except ValueError:
        return None


def uses(services: list[Service], apis: list[ApiConnection], hosts: list[SshHost], table: Table | None = None
         ) -> list[tuple[str, str, int | None, str]]:
    """(host, protocol, poort, wie): alle uitgaande verbindingen. Poort None = ping. Met de routes van NPM: een check
    op een naam achter NPM gaat rechtstreeks naar de server (ook als de firewall dat nu nog tegenhoudt)."""
    api_url = {a.id: a.url for a in apis}
    out: list[tuple[str, str, int | None, str]] = []
    for s in services:
        check = s.check or {}
        kind = check.get("type")
        try:
            target = target_for(check, s.url) if kind else None
        except ValueError:
            target = None
        # De server achter NPM die de check gebruikt zodra het dashboard hem bereikt (zie Table.plan).
        fw = plan.firewall if table is not None and (plan := table.plan(check, s.url)) else None
        if target:
            if kind == "http" and (hp := _from_url(target)):
                out.append((fw[0], "tcp", fw[1], f"{s.name} (check, rechtstreeks)") if fw
                           else (hp[0], "tcp", hp[1], f"{s.name} (check)"))
            elif kind == "tcp" and (hp := _hostport(target)):
                out.append((fw[0], "tcp", fw[1], f"{s.name} (check, rechtstreeks)") if fw
                           else (hp[0], "tcp", hp[1], f"{s.name} (check)"))
            elif kind == "ping":
                out.append((target, "icmp", None, f"{s.name} (ping)"))
        if s.type and s.type != "link":
            url = api_url.get(s.api_id) if s.api_id else (s.config or {}).get("url") or s.url
            if hp := _from_url(url):
                out.append((hp[0], "tcp", hp[1], f"{s.name} ({s.type})"))
    for a in apis:
        if hp := _from_url(a.url):
            out.append((hp[0], "tcp", hp[1], f"API {a.name}"))
    for h in hosts:
        out.append((h.host, "tcp", h.port or 22, f"SSH {h.name}"))
    return out


def nameservers(path: Path = RESOLV_CONF) -> list[str]:
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    return [ln.split()[1] for ln in lines if ln.startswith("nameserver") and len(ln.split()) > 1]


async def resolve(names: set[str]) -> dict[str, list[str]]:
    """Naam → IPv4-adressen (een IP blijft zichzelf). Onbekend of te traag = []."""
    loop = asyncio.get_running_loop()
    sem = asyncio.Semaphore(10)

    async def one(name: str) -> tuple[str, list[str]]:
        try:
            return name, [str(ipaddress.ip_address(name))]
        except ValueError:
            pass
        async with sem:
            try:
                infos = await asyncio.wait_for(loop.getaddrinfo(name, None, family=socket.AF_INET,
                                                                type=socket.SOCK_STREAM), RESOLVE_TIMEOUT)
            except (OSError, asyncio.TimeoutError):
                return name, []
        return name, sorted({i[4][0] for i in infos})

    return dict(await asyncio.gather(*(one(n) for n in names)))


def _scope(ip: str, own: ipaddress.IPv4Network | None) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "onbekend"
    if a.is_loopback:
        return "zelf"
    if a.is_global:
        return "internet"
    if own and a in own:
        return "zelfde netwerk"
    return "ander netwerk"


def _port_label(proto: str, port: int | None) -> str:
    return "ping" if proto == "icmp" else f"{port}/{proto}"


async def overview(db: AsyncSession) -> dict:
    s = get_settings()
    services = list((await db.execute(select(Service))).scalars())
    apis = list((await db.execute(select(ApiConnection))).scalars())
    hosts = list((await db.execute(select(SshHost))).scalars())
    conns = uses(services, apis, hosts, await load_routes(db))
    # Web push naar je gsm('s): 443 naar de pushdienst (fcm.googleapis.com, *.push.apple.com, *.push.services.mozilla.com).
    conns += [(host, "tcp", 443, f"web push ({label})") for host, label in await endpoint_hosts(db)]
    dns = nameservers()
    conns += [(ns, "udp", 53, "DNS") for ns in dns]
    ips = await resolve({c[0] for c in conns})

    own_ip = s.syslog_target or None
    own = None
    if own_ip:
        try:
            own = ipaddress.ip_network(f"{own_ip}/24", strict=False)
        except ValueError:
            own = None

    rows: dict[str, dict] = {}
    unresolved: dict[str, set[str]] = {}
    for host, proto, port, who in conns:
        addrs = ips.get(host) or []
        if not addrs:
            unresolved.setdefault(host, set()).add(who)
            continue
        for ip in addrs:
            r = rows.setdefault(ip, {"ip": ip, "names": set(), "ports": set(), "used_by": set(), "scope": _scope(ip, own)})
            if host != ip:
                r["names"].add(host)
            r["ports"].add((proto, port))
            r["used_by"].add(who)
    order = {"ander netwerk": 0, "zelfde netwerk": 1, "internet": 2, "zelf": 3, "onbekend": 4}
    out_rows = []
    for r in sorted(rows.values(), key=lambda r: (order[r["scope"]], tuple(int(x) if x.isdigit() else 0 for x in r["ip"].split(".")))):
        ports = sorted(r["ports"], key=lambda p: (p[1] or 0, p[0]))
        out_rows.append({"ip": r["ip"], "scope": r["scope"], "names": sorted(r["names"])[:8], "names_total": len(r["names"]),
                         "ports": [_port_label(*p) for p in ports], "used_by": sorted(r["used_by"])[:8],
                         "used_total": len(r["used_by"])})

    cross = [r for r in out_rows if r["scope"] == "ander netwerk"]
    tcp = sorted({int(p.split("/")[0]) for r in cross for p in r["ports"] if p.endswith("/tcp")})
    udp = sorted({int(p.split("/")[0]) for r in cross for p in r["ports"] if p.endswith("/udp")})
    npm_ip = s.npm_ip or None
    inbound = [
        {"from": npm_ip or "Nginx Proxy Manager", "port": "80/tcp", "why": "het dashboard zelf (via NPM)"},
        {"from": "je machines (LAN)", "port": f"{s.syslog_port}/udp, {s.syslog_port}/tcp", "why": "logs (rsyslog)"},
        {"from": "Proxmox, PBS, Home Assistant", "port": "80/tcp", "why": "webhooks naar het meldingencentrum"},
    ]
    return {
        "own_ip": own_ip, "own_net": str(own) if own else None, "rows": out_rows, "inbound": inbound,
        "unresolved": [{"name": n, "used_by": sorted(w)[:5]} for n, w in sorted(unresolved.items())],
        "internet": any(r["scope"] == "internet" for r in out_rows),
        "opnsense": {
            "hosts": [r["ip"] for r in cross], "tcp": tcp, "udp": udp,
            "ping": any("ping" in r["ports"] for r in cross),
        },
    }
