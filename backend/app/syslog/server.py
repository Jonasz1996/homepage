"""Syslog-ontvanger op UDP en TCP (standaard poort 514). Start met: python -m app.syslog.server

Schrijft in batches naar de database en maakt meldingen volgens de regels uit log_rules.
"""

import asyncio
import ipaddress
import logging
import re
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, insert, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..config import get_settings
from ..db import get_engine
from ..models import LogEntry, LogRule, Notification
from .parse import SEVERITIES, Parsed, parse

log = logging.getLogger("homepage.syslog")

BATCH = 500
FLUSH_SECONDS = 1.0
QUEUE_MAX = 50_000
MAX_TCP_FRAME = 64 * 1024


class Rules:
    """Meldingsregels uit de database, elke 30 s herladen."""

    def __init__(self) -> None:
        self.rules: list[tuple[LogRule, re.Pattern | None]] = []
        self.last_fire: dict[tuple[int, str], float] = {}
        self.loaded = 0.0

    def set(self, rules: list[LogRule]) -> None:
        out = []
        for r in rules:
            try:
                out.append((r, re.compile(r.pattern, re.I) if r.pattern else None))
            except re.error:
                log.warning("Ongeldige regex in regel %s", r.name)
        self.rules = out
        self.loaded = time.monotonic()

    def match(self, p: Parsed) -> list[Notification]:
        notes = []
        now = time.monotonic()
        for r, rx in self.rules:
            if p.severity > r.max_severity or (r.host and r.host.lower() != p.host.lower()):
                continue
            if rx and not rx.search(p.msg):
                continue
            key = (r.id, p.host)
            if now - self.last_fire.get(key, -1e9) < r.cooldown_minutes * 60:
                continue
            self.last_fire[key] = now
            notes.append(Notification(
                title=f"{p.host}: {r.name}", body=f"[{SEVERITIES[p.severity]}] {p.app or ''} {p.msg}".strip()[:1000],
                level=r.level if r.level in ("info", "ok", "warn", "err") else "warn", source="syslog",
            ))
        return notes


def allowed_networks() -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(n.strip(), strict=False) for n in get_settings().syslog_allow.split(",") if n.strip()]


class Receiver:
    def __init__(self, maker: async_sessionmaker) -> None:
        self.maker = maker
        self.queue: asyncio.Queue[tuple[bytes, str]] = asyncio.Queue(QUEUE_MAX)
        self.rules = Rules()
        self.nets = allowed_networks()
        self.dropped = 0
        self.self_cleanup = True

    def accept(self, data: bytes, ip: str) -> None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        if not any(addr in n for n in self.nets):
            return
        try:
            self.queue.put_nowait((data, str(addr)))
        except asyncio.QueueFull:
            self.dropped += 1

    async def reload_rules(self) -> None:
        async with self.maker() as db:
            self.rules.set(list((await db.execute(select(LogRule).where(LogRule.enabled))).scalars()))

    async def flush(self, items: list[tuple[bytes, str]]) -> None:
        if time.monotonic() - self.rules.loaded > 30:
            await self.reload_rules()
        rows, notes = [], []
        for data, ip in items:
            p = parse(data, ip)
            rows.append({"ts": p.ts, "host": p.host, "source_ip": ip, "facility": p.facility,
                         "severity": p.severity, "app": p.app, "msg": p.msg})
            notes.extend(self.rules.match(p))
        async with self.maker() as db:
            await db.execute(insert(LogEntry), rows)
            db.add_all(notes)
            await db.commit()

    async def writer(self) -> None:
        while True:
            items = [await self.queue.get()]
            deadline = time.monotonic() + FLUSH_SECONDS
            while len(items) < BATCH:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                try:
                    items.append(await asyncio.wait_for(self.queue.get(), left))
                except asyncio.TimeoutError:
                    break
            try:
                await self.flush(items)
            except Exception:
                log.exception("Wegschrijven van %d logregels mislukt", len(items))
                await asyncio.sleep(2)

    async def cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(3600)
            if self.dropped:
                log.warning("%d logregels weggegooid (wachtrij vol)", self.dropped)
                self.dropped = 0
            if not self.self_cleanup:
                continue
            try:
                async with self.maker() as db:
                    keep = timedelta(days=get_settings().syslog_keep_days)
                    await db.execute(delete(LogEntry).where(LogEntry.ts < datetime.now(timezone.utc) - keep))
                    await db.commit()
            except Exception:
                log.exception("Opruimen mislukt")

    async def detect_timescale(self) -> None:
        async with self.maker() as db:
            try:
                hyper = (await db.execute(text(
                    "SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'log_entries'"
                ))).scalar()
            except Exception:
                hyper = None
        self.self_cleanup = not hyper


class Udp(asyncio.DatagramProtocol):
    def __init__(self, rx: Receiver) -> None:
        self.rx = rx

    def datagram_received(self, data: bytes, addr) -> None:
        self.rx.accept(data, addr[0])


async def handle_tcp(rx: Receiver, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """TCP-syslog: octet counting ("123 <34>1 ...") of één bericht per regel."""
    ip = writer.get_extra_info("peername")[0]
    try:
        while True:
            first = await reader.read(1)
            if not first:
                break
            if first.isdigit():
                digits = first + await reader.readuntil(b" ")
                length = int(digits[:-1])
                if length > MAX_TCP_FRAME:
                    break
                rx.accept(await reader.readexactly(length), ip)
            else:
                line = first + await reader.readuntil(b"\n")
                rx.accept(line, ip)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, ConnectionError):
        pass
    finally:
        writer.close()


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    s = get_settings()
    maker = async_sessionmaker(get_engine(), expire_on_commit=False)
    rx = Receiver(maker)
    await rx.detect_timescale()
    await rx.reload_rules()
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(lambda: Udp(rx), local_addr=(s.syslog_bind, s.syslog_port))
    server = await asyncio.start_server(lambda r, w: handle_tcp(rx, r, w), s.syslog_bind, s.syslog_port,
                                        limit=MAX_TCP_FRAME)
    log.info("Syslog luistert op %s:%d (udp+tcp), toegelaten: %s", s.syslog_bind, s.syslog_port, s.syslog_allow)
    async with server:
        await asyncio.gather(rx.writer(), rx.cleanup_loop(), server.serve_forever())


if __name__ == "__main__":
    asyncio.run(main())
