"""Apparaten op het netwerk: ARP- en DHCP-tabel van OPNsense, een melding bij een onbekend apparaat, en een optionele
poortscan per apparaat die meldt wanneer er een nieuwe poort openstaat.
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..integrations import IntegrationError, build
from ..models import AppState, Device, Service
from .checks import HttpClients

log = logging.getLogger("homepage.devices")

DEVICES_EVERY = 300
SCAN_EVERY = 6 * 3600
ONLINE = timedelta(minutes=15)
STATE_KEY = "devices"
MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
# De gebruikelijke poorten in een thuisnetwerk; genoeg om "er staat ineens iets open" te zien.
PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 81: "npm", 110: "pop3", 111: "rpc",
    139: "netbios", 143: "imap", 443: "https", 445: "smb", 548: "afp", 554: "rtsp", 631: "ipp", 873: "rsync",
    993: "imaps", 1080: "socks", 1433: "mssql", 1883: "mqtt", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
    3000: "grafana", 3306: "mysql", 3389: "rdp", 5000: "upnp/synology", 5001: "synology", 5432: "postgres",
    5900: "vnc", 6379: "redis", 6443: "kubernetes", 7878: "radarr", 8006: "proxmox", 8007: "pbs", 8080: "http-alt",
    8081: "http-alt", 8096: "jellyfin", 8123: "home-assistant", 8443: "https-alt", 8888: "http-alt", 8989: "sonarr",
    9000: "portainer", 9090: "prometheus", 9100: "printer", 9443: "portainer", 10000: "webmin", 11211: "memcached",
    27017: "mongodb", 32400: "plex", 51820: "wireguard",
}
SCAN_TIMEOUT = 1.0
SCAN_PARALLEL = 64


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc) if dt else None


def device_out(d: Device, now: datetime) -> dict:
    return {"mac": d.mac, "name": d.name, "vendor": d.vendor, "hostname": d.hostname, "ip": d.ip, "intf": d.intf,
            "note": d.note, "known": d.known, "scan": d.scan, "ports": d.ports, "ports_at": d.ports_at,
            "first_seen": d.first_seen, "last_seen": d.last_seen, "online": now - _aware(d.last_seen) < ONLINE,
            "port_names": {str(p): PORTS.get(p, "") for p in (d.ports or [])}}


async def refresh(db: AsyncSession, http: HttpClients, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    seen: dict[str, dict] = {}
    errors = []
    for svc in (await db.execute(select(Service).where(Service.type == "opnsense"))).scalars():
        try:
            for n in await build(svc, http).neighbours():
                if MAC_RE.match(n["mac"]):
                    seen.setdefault(n["mac"], n)
        except IntegrationError as e:
            errors.append({"source": svc.name, "error": str(e)})
    # Alle bekende apparaten in één query, niet één per gezien MAC-adres.
    known = {d.mac: d for d in (await db.execute(select(Device))).scalars()}
    first_run = not known
    new = []
    for mac, n in seen.items():
        d = known.get(mac)
        if d is None:
            d = Device(mac=mac, first_seen=now, last_seen=now, known=first_run, scan=False)
            db.add(d)
            if not first_run:
                new.append(n)
        d.last_seen = now
        d.ip = n.get("ip") or d.ip
        d.vendor = n.get("vendor") or d.vendor
        d.hostname = n.get("hostname") or d.hostname
        d.intf = n.get("intf") or d.intf
    for n in new:
        label = n.get("hostname") or n.get("vendor") or "onbekend apparaat"
        notify(db, f"Nieuw apparaat op je netwerk: {label}",
               f"{n.get('ip') or '?'} · {n['mac']}" + (f" · {n['vendor']}" if n.get("vendor") else "")
               + (f" · {n['intf']}" if n.get("intf") else "") + "\nGeef het een naam onder net → apparaten.",
               level="warn", source="apparaat")
    value = {"at": now.isoformat(), "seen": len(seen), "new": len(new), "errors": errors}
    st = await db.get(AppState, STATE_KEY)
    if st:
        st.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value


async def _open(ip: str, port: int, sem: asyncio.Semaphore) -> bool:
    async with sem:
        try:
            _, w = await asyncio.wait_for(asyncio.open_connection(ip, port), SCAN_TIMEOUT)
        except (OSError, asyncio.TimeoutError):
            return False
        w.close()
        try:
            await w.wait_closed()
        except OSError:
            pass
        return True


async def scan_ports(ip: str, ports: list[int] | None = None) -> list[int]:
    ports = ports or list(PORTS)
    sem = asyncio.Semaphore(SCAN_PARALLEL)
    res = await asyncio.gather(*(_open(ip, p, sem) for p in ports))
    return [p for p, ok in zip(ports, res) if ok]


async def scan_device(db: AsyncSession, d: Device, now: datetime | None = None, ports: list[int] | None = None) -> list[int]:
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    if not d.ip:
        return d.ports or []
    found = await scan_ports(d.ip, ports)
    before = set(d.ports or [])
    added = [p for p in found if p not in before]
    if d.ports is not None and added:
        label = d.name or d.hostname or d.ip
        notify(db, f"Nieuwe poort open op {label}: " + ", ".join(f"{p} ({PORTS.get(p, '?')})" for p in added),
               f"{d.ip} · {d.mac}\nnu open: {', '.join(str(p) for p in found) or 'geen'}", level="warn", source="apparaat")
    d.ports, d.ports_at = found, now
    return found


async def scan_due(db: AsyncSession, now: datetime | None = None) -> int:
    """Elke 6 uur de apparaten met poortscan aan (en die online zijn)."""
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    n = 0
    for d in (await db.execute(select(Device).where(Device.scan.is_(True)))).scalars().all():
        if now - _aware(d.last_seen) > ONLINE:
            continue
        if d.ports_at and now - _aware(d.ports_at) < timedelta(seconds=SCAN_EVERY):
            continue
        await scan_device(db, d, now)
        n += 1
    return n
