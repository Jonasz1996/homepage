"""Apparaten op het netwerk: ARP- en DHCP-tabel van OPNsense, een melding bij een onbekend apparaat, en een optionele
poortscan per apparaat die meldt wanneer er een nieuwe poort openstaat.

Privé-adressen: een gsm of laptop gebruikt vaak een willekeurig MAC-adres (iOS "wisselend", Android, Windows) en neemt
af en toe een nieuw. Duikt zo'n adres op met dezelfde hostnaam op dezelfde interface als een gekend toestel met een
privé-adres en een naam, en staat dat oude adres niet meer in de ARP-tabel, dan is het dat toestel: het nieuwe adres
krijgt stil zijn naam (een melding in 🔔, niet op de gsm). Staat het oude adres er nog, dan is dat toestel online en is
dit een ander met dezelfde hostnaam (twee keer "iPhone"): een gewone melding, met de naam erbij als hint.
Opruimen: wat 30 dagen niet gezien is, verdwijnt als het onbekend is, of als het het oude adres is van zo'n toestel.
Wat een naam, een notitie of "volgen" heeft, en elk ander gekend apparaat, blijft staan tot je het zelf vergeet.
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
# Zo lang niet gezien: onbekende apparaten en de oude adressen van een toestel met een privé-adres verdwijnen uit de
# lijst (niet als ze een naam, een notitie of "volgen" hebben).
PRUNE_AFTER = timedelta(days=30)
# Zoveel nieuwe apparaten bij naam in één melding; de rest staat onder net → apparaten.
LIST_MAX = 20


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc) if dt else None


def private_mac(mac: str) -> bool:
    """Een lokaal beheerd MAC-adres (bit 0x02 van de eerste byte): het privé- of willekeurige adres van een gsm of
    laptop, of een VM/container. Er hoort geen fabrikant bij."""
    try:
        return bool(int(mac[:2], 16) & 0x02)
    except ValueError:
        return False


def device_out(d: Device, now: datetime) -> dict:
    return {"mac": d.mac, "name": d.name, "vendor": d.vendor, "hostname": d.hostname, "ip": d.ip, "intf": d.intf,
            "note": d.note, "known": d.known, "scan": d.scan, "ports": d.ports, "ports_at": d.ports_at,
            "first_seen": d.first_seen, "last_seen": d.last_seen, "online": now - _aware(d.last_seen) < ONLINE,
            "port_names": {str(p): PORTS.get(p, "") for p in (d.ports or [])}, "private": private_mac(d.mac)}


def _label(n: dict) -> str:
    return n.get("hostname") or n.get("vendor") or (
        "onbekend toestel met privé-adres" if private_mac(n["mac"]) else "onbekend apparaat")


def _line(n: dict, label: str | None = None) -> str:
    """IP, MAC, fabrikant en interface. label: staat er al voor (de fabrikant dan niet nog eens)."""
    vendor = n.get("vendor") if n.get("vendor") != label else None
    return f"{n.get('ip') or '?'} · {n['mac']}" + (f" · {vendor}" if vendor else "") + (
        f" · {n['intf']}" if n.get("intf") else "")


def _same_host(hostname: str | None, intf: str | None, n: dict) -> bool:
    """Zelfde hostnaam (hoofdletters tellen niet) en, als beide er een hebben, dezelfde interface."""
    return bool(hostname) and hostname.lower() == n["hostname"].lower() and not (
        intf and n.get("intf") and intf != n["intf"])


def _owner(rows: dict[str, Device], n: dict, fresh: list[dict], taken: set[str]) -> Device | None:
    """Is dit nieuwe privé-adres misschien een gekend toestel dat een ander adres nam? Dan de rij met de naam van dat
    toestel, anders None (en een gewone melding). Of het de naam echt overneemt, zegt _moved().

    Alleen als alle rijen met dezelfde hostnaam op dezelfde interface gekende privé-adressen zijn, en er precies één
    een naam heeft (die gaf jij): de andere zijn de oude adressen van hetzelfde toestel (hun naam verhuisde al eerder
    mee). Een gekend toestel zonder naam (zoals alles uit de eerste ronde) staat niet in voor zijn hostnaam. Een
    onbekende rij of een vast adres met die hostnaam, twee namen, of twee nieuwe adressen met die hostnaam in dezelfde
    ronde: niet te zeggen welk toestel het is, dus melden."""
    if not n.get("hostname") or not private_mac(n["mac"]):
        return None
    if any(o is not n and o.get("hostname") and _same_host(o["hostname"], o.get("intf"), n) for o in fresh):
        return None
    match = [d for d in rows.values() if _same_host(d.hostname, d.intf, n)]
    if not match or any(d.mac in taken or not d.known or not private_mac(d.mac) for d in match):
        return None
    named = [d for d in match if d.name]
    return named[0] if len(named) == 1 else None


def _moved(old: Device, n: dict, arp: set[str]) -> bool:
    """Neemt n de naam van old over? Niet als het oude adres in de ARP-tabel van deze ronde staat: dan is dat toestel
    online, en is n een ander (een lease alleen zegt dat niet, die loopt na een nieuw adres nog een tijd door). En
    alleen op dezelfde interface: zonder interface aan een van beide kanten is dat niet te zeggen."""
    return old.mac not in arp and bool(old.intf) and old.intf == n.get("intf")


async def refresh(db: AsyncSession, http: HttpClients, now: datetime | None = None) -> dict:
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    seen: dict[str, dict] = {}
    # Wat in de ARP-tabel staat (online), niet alleen in een lease.
    arp: set[str] = set()
    errors = []
    svcs = list((await db.execute(select(Service).where(Service.type == "opnsense"))).scalars())
    # Geen transactie open tijdens de calls naar OPNsense: de verbinding gaat terug naar de pool, de tegels blijven
    # bruikbaar (expire_on_commit=False; build() doet zelf geen query).
    await db.commit()
    for svc in svcs:
        try:
            for n in await build(svc, http).neighbours():
                if MAC_RE.match(n["mac"]):
                    seen.setdefault(n["mac"], n)
                    if n.get("arp"):
                        arp.add(n["mac"])
        except IntegrationError as e:
            errors.append({"source": svc.name, "error": str(e)})
    # Alle bekende apparaten in één query, niet één per gezien MAC-adres.
    rows = {d.mac: d for d in (await db.execute(select(Device))).scalars()}
    st = await db.get(AppState, STATE_KEY)
    prev = dict(st.value or {}) if st else {}
    # De eerste ronde: wat er al is, is gekend. Met een vlag, en niet "de tabel is leeg": wie de tabel leegmaakt,
    # krijgt bij de volgende ronde een melding over alles, niet stilletjes alles (ook wat er niet hoort) als gekend.
    first_run = not prev.get("baseline") and not rows
    # De oude adressen van toestellen die een nieuw privé-adres namen: van wat gekend is, mogen alleen die weg. Staat
    # zo'n adres weer in de ARP-tabel, dan is het niet meer verlaten.
    vacated = {m for m in prev.get("vacated") or [] if m in rows} - arp
    for mac, n in seen.items():
        if (d := rows.get(mac)) is not None:
            d.last_seen = now
            d.ip = n.get("ip") or d.ip
            d.vendor = n.get("vendor") or d.vendor
            d.hostname = n.get("hostname") or d.hostname
            d.intf = n.get("intf") or d.intf
    fresh = [n for mac, n in seen.items() if mac not in rows]
    new, taken, like = [], set(), {}
    for n in fresh:
        old = None if first_run else _owner(rows, n, fresh, taken)
        if old is not None and not _moved(old, n, arp):
            # Toch een nieuw apparaat; de naam van het toestel met dezelfde hostnaam staat er als hint bij.
            like[n["mac"]] = f" (zelfde hostnaam als {old.name}" + (
                ", maar dat toestel is nog online)" if old.mac in arp else ")")
            old = None
        d = Device(mac=n["mac"], first_seen=now, last_seen=now, known=first_run or old is not None, scan=False,
                   ip=n.get("ip"), vendor=n.get("vendor"), hostname=n.get("hostname"), intf=n.get("intf"))
        db.add(d)
        if old is not None:
            # Hetzelfde toestel met een nieuw adres: de naam, de notitie en de poortscan verhuizen mee (de eerste scan
            # van het nieuwe adres is weer een nulmeting). Het oude adres blijft gekend, zonder naam, en verdwijnt na
            # 30 dagen niet gezien.
            taken.add(old.mac)
            vacated.add(old.mac)
            d.name, d.note, d.scan = old.name, old.note, old.scan
            old.name, old.note, old.scan = None, None, False
            notify(db, f"{d.name}: nieuw privé-adres",
                   f"{_line(n)} (was {old.mac})\nZelfde hostnaam op dezelfde interface, en het oude adres staat niet "
                   "meer in de ARP-tabel: het toestel houdt zijn naam. Was het een ander toestel? Geef het onder net → "
                   "apparaten een eigen naam.", level="info", source="apparaat", push=False)
        elif not first_run:
            new.append(n)
    # Een melding voor alle nieuwe samen: een gsm die een paar keer van adres wisselt, of een hele reeks na een
    # nieuwe OPNsense-tegel, zijn zo één bericht. Zonder sleutel: een indringer vervangt de vorige melding niet.
    if len(new) == 1:
        notify(db, f"Nieuw apparaat op je netwerk: {_label(new[0])}",
               _line(new[0]) + like.get(new[0]["mac"], "") + "\nGeef het een naam onder net → apparaten.",
               level="warn", source="apparaat")
    elif new:
        lines = [f"{_label(n)}: {_line(n, _label(n))}{like.get(n['mac'], '')}" for n in new[:LIST_MAX]]
        if len(new) > LIST_MAX:
            lines.append(f"… en nog {len(new) - LIST_MAX}")
        notify(db, f"{len(new)} nieuwe apparaten op je netwerk", "\n".join(lines)
               + "\nGeef ze een naam onder net → apparaten.", level="warn", source="apparaat")
    pruned = 0
    # Opruimen alleen na een volledige ronde: ligt een OPNsense-tegel plat, dan is "niet gezien" niets waard. Wat een
    # naam, een notitie of "volgen" heeft, blijft; van wat gekend is, gaat alleen een verlaten oud adres weg.
    if seen and not errors:
        for d in rows.values():
            if (_aware(d.last_seen) < now - PRUNE_AFTER and not (d.name or d.note or d.scan)
                    and (not d.known or d.mac in vacated)):
                await db.delete(d)
                vacated.discard(d.mac)
                pruned += 1
    value = {"at": now.isoformat(), "seen": len(seen), "new": len(new), "moved": len(taken), "pruned": pruned,
             "errors": errors,
             # Sinds wanneer de lijst bijgehouden wordt (zie first_run).
             "baseline": prev.get("baseline") or (now.isoformat() if seen or rows else None),
             # Wanneer er voor het laatst een echt nieuw, onbekend apparaat bijkwam: een genegeerd aandachtspunt
             # komt alleen dan terug (niet als je er een als gekend markeert of er een opgeruimd wordt).
             "last_new": now.isoformat() if new else prev.get("last_new"),
             # Zie vacated hierboven.
             "vacated": sorted(vacated)}
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
    """Scant de poorten van één apparaat. Commit eerst wat er al was: geen transactie open tijdens de scan (tot een
    paar seconden per apparaat). Het resultaat bewaart de oproeper."""
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    if not d.ip:
        return d.ports or []
    await db.commit()
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
