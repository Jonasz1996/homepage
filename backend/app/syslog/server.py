"""Syslog-ontvanger op UDP en TCP (standaard poort 514). Start met: python -m app.syslog.server

Schrijft in batches naar de database en maakt meldingen volgens de regels uit log_rules.

Is de database even weg (herstart van PostgreSQL, schijf vol), dan gaat er niets verloren zolang de wachtrij niet vol
is: de schrijver houdt zijn batch vast en probeert opnieuw, telkens iets later (tot 30 s). Zit de wachtrij vol
(QUEUE_MAX regels), dan leest de ontvanger niet verder op TCP: rsyslog op de afzender (uitgerold vanuit het dashboard)
houdt de regels dan in zijn eigen wachtrij. UDP kan niet wachten: daar valt de oudste regel weg. Wat verloren gaat,
wordt geteld en elke minuut met een teken van leven bewaard in AppState "syslog"; Aandacht en Gezondheid › homepage
tonen het.
"""

import asyncio
import contextlib
import ipaddress
import logging
import os
import re
import signal
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import insert, select, text
from sqlalchemy.exc import DBAPIError, TimeoutError as PoolTimeout
from sqlalchemy.ext.asyncio import async_sessionmaker

from .. import logring
from ..config import get_settings
from ..db import delete_before, ensure_state, get_engine, sqlstate
from ..masking import mask
from ..models import LogEntry, LogRule, Notification
from .parse import SEVERITIES, Parsed, parse

log = logging.getLogger("homepage.syslog")

BATCH = 500
FLUSH_SECONDS = 1.0
QUEUE_MAX = 50_000
MAX_TCP_FRAME = 64 * 1024
# Langer wordt een bericht toch niet bewaard (parse houdt 8192 tekens): zo neemt een volle wachtrij geen gigabytes in.
MAX_RAW = 16 * 1024
# Database weg: opnieuw na 1 s, dan telkens dubbel zo lang, hoogstens 30 s.
RETRY_FIRST = 1.0
RETRY_MAX = 30.0
STATE_KEY = "syslog"
STATUS_EVERY = 60
# Bij het stoppen (systemctl stop of restart, ook bij elke update): zo lang mag het wegschrijven van de wachtrij duren.
DRAIN_SECONDS = 10
# Verlies binnen een dag na het vorige telt op bij dezelfde reeks (en zo lang staat het onder Aandacht).
LOSS_HOURS = 24
# Waarom regels niet in de database kwamen (loss.why in AppState "syslog").
FULL, REJECTED, STOPPED = "vol", "geweigerd", "gestopt"


class Rules:
    """Meldingsregels uit de database, elke 30 s herladen."""

    def __init__(self) -> None:
        self.rules: list[tuple[LogRule, re.Pattern | None]] = []
        self.last_fire: dict[tuple[int, str], float] = {}
        self.loaded = -1e9
        # Ooit geladen? Zonder regels zouden meldingen ontbreken.
        self.ready = False

    def set(self, rules: list[LogRule]) -> None:
        out = []
        for r in rules:
            try:
                out.append((r, re.compile(r.pattern, re.I) if r.pattern else None))
            except re.error:
                log.warning("Ongeldige regex in regel %s", r.name)
        self.rules = out
        self.loaded = time.monotonic()
        self.ready = True

    def match(self, p: Parsed, fired: dict[tuple[int, str], float] | None = None) -> list[dict]:
        """De meldingen voor deze regel, als velden voor Notification(**n).

        fired: de cooldown van een batch die nog niet in de database staat. Die gaat pas na het wegschrijven naar
        last_fire (zie Receiver.store): een batch die niet weggeschreven raakt, mag de volgende melding niet
        onderdrukken. Zonder fired telt de cooldown meteen."""
        fired = self.last_fire if fired is None else fired
        notes = []
        now = time.monotonic()
        for r, rx in self.rules:
            if p.severity > r.max_severity or (r.host and r.host.lower() != p.host.lower()):
                continue
            if rx and not rx.search(p.msg):
                continue
            key = (r.id, p.host)
            if now - fired.get(key, self.last_fire.get(key, -1e9)) < r.cooldown_minutes * 60:
                continue
            fired[key] = now
            # notifications.title is varchar(200): een lange hostnaam mag de batch niet laten weigeren.
            notes.append({
                "title": f"{p.host}: {r.name}"[:200],
                "body": f"[{SEVERITIES[p.severity]}] {p.app or ''} {p.msg}".strip()[:1000],
                "level": r.level if r.level in ("info", "ok", "warn", "err") else "warn", "source": "syslog",
            })
        return notes


def allowed_networks() -> list[ipaddress._BaseNetwork]:
    return [ipaddress.ip_network(n.strip(), strict=False) for n in get_settings().syslog_allow.split(",") if n.strip()]


def _iso(t: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if t is None else t, timezone.utc).replace(microsecond=0).isoformat()


def _why(e: BaseException) -> str:
    """Kort en leesbaar wat er misging (de fout van asyncpg zelf, zonder de SQL), gemaskeerd: het komt in de logs, in
    AppState en op het scherm."""
    orig = getattr(e, "orig", None) if isinstance(e, DBAPIError) else None
    base = getattr(orig, "__cause__", None) or orig or e
    return mask(f"{type(base).__name__}: {str(base).strip()}"[:300])


def _bad_data(e: BaseException) -> bool:
    """Weigert de database de gegevens zelf (SQLSTATE-klasse 22: te lang of ongeldig, 23: een beperking)? Dan helpt
    opnieuw proberen niet."""
    return isinstance(e, DBAPIError) and (sqlstate(e) or "")[:2] in ("22", "23")


def _outage(e: BaseException) -> bool:
    """Een gewone storing (database weg of aan het herstarten, schijf vol, time-out): geen traceback nodig."""
    return isinstance(e, (DBAPIError, OSError, TimeoutError, PoolTimeout))


@dataclass
class Batch:
    """Ontleed en klaar om weg te schrijven. Blijft bestaan tot alles in de database staat: een nieuwe poging schrijft
    precies hetzelfde weg, zonder de meldingsregels opnieuw toe te passen."""

    rows: list[dict]
    notes: list[dict]
    # De cooldown van de meldingen hierin: pas na het wegschrijven naar Rules.last_fire.
    fired: dict
    # Na een geweigerde regel: één regel per transactie, zodat de rest er wel in komt.
    single: bool = False


class Receiver:
    def __init__(self, maker: async_sessionmaker) -> None:
        self.maker = maker
        # Ruwe regels met hun bron en ontvangsttijd. Begrensd: zie accept (UDP) en accept_wait (TCP).
        self.queue: asyncio.Queue[tuple[bytes, str, float]] = asyncio.Queue(QUEUE_MAX)
        self.rules = Rules()
        self.nets = allowed_networks()
        # Ruimt de ontvanger zelf oude regels op? Niet op TimescaleDB (die heeft een retentiebeleid). None: nog niet
        # geweten, want de database was onbereikbaar; dan ook niet opruimen.
        self.self_cleanup: bool | None = None
        self.started = _iso()
        # De batch die de schrijver in handen heeft: uit de wachtrij, nog niet in de database.
        self.current: list[tuple[bytes, str, float]] = []
        self.closing = False
        self._wake = asyncio.Event()
        self.clients: set[asyncio.Task] = set()
        # Tellers sinds de start; dropped: niet bewaard sinds de vorige uurlijkse logregel.
        self.received = 0
        self.stored = 0
        self.lost = 0
        self.dropped = 0
        # Verlies dat nog niet in AppState staat: aantal, eerste en laatste keer (time.time()), waarom.
        self._loss: dict = {"n": 0, "since": None, "at": None, "why": None}
        # Sinds wanneer (time.time()) het wegschrijven mislukt, en de laatste fout (ook na het herstel bewaard).
        self.down_since: float | None = None
        self.last_error: dict | None = None
        self._status_failed = False

    def _allowed(self, ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return str(addr) if any(addr in n for n in self.nets) else None

    def accept(self, data: bytes, ip: str) -> None:
        """UDP: kan niet wachten. Zit de wachtrij vol (de database is al lang weg), dan valt de oudste regel weg."""
        addr = self._allowed(ip)
        if addr is None:
            return
        self.received += 1
        if self.queue.full():
            self.queue.get_nowait()
            self.lose(1, FULL)
        self.queue.put_nowait((data[:MAX_RAW], addr, time.time()))

    async def accept_wait(self, data: bytes, ip: str) -> None:
        """TCP: zit de wachtrij vol, dan wachten tot er plaats is. Zolang leest deze verbinding niets: de afzender
        merkt dat (het TCP-venster gaat dicht) en houdt de regels in zijn eigen wachtrij."""
        addr = self._allowed(ip)
        if addr is None:
            return
        self.received += 1
        try:
            await self.queue.put((data[:MAX_RAW], addr, time.time()))
        except asyncio.CancelledError:
            # Bij het stoppen, terwijl deze regel nog op plaats wachtte.
            self.lose(1, STOPPED)
            raise

    def lose(self, n: int, why: str) -> None:
        """n regels komen niet in de database: tellen, voor Aandacht en Gezondheid."""
        if n <= 0:
            return
        now = time.time()
        self.lost += n
        self.dropped += n
        loss = self._loss
        loss.update(n=loss["n"] + n, since=loss["since"] or now, at=now, why=why)

    def backlog(self) -> int:
        return self.queue.qsize() + len(self.current)

    async def reload_rules(self) -> None:
        async with self.maker() as db:
            self.rules.set(list((await db.execute(select(LogRule).where(LogRule.enabled))).scalars()))

    async def prepare(self, items: list[tuple[bytes, str, float]]) -> Batch:
        """Ontleden en de meldingsregels toepassen. Met de ontvangsttijd: een regel zonder bruikbare eigen tijd die pas
        na een storing weggeschreven wordt, krijgt niet het tijdstip van dan."""
        if not self.rules.ready or time.monotonic() - self.rules.loaded > 30:
            try:
                await self.reload_rules()
            except Exception:
                if not self.rules.ready:
                    # Nog nooit geladen (de database was weg bij het starten): wachten zoals bij het wegschrijven,
                    # anders ontbreken de meldingen voor alles wat intussen binnenkwam.
                    raise
                # De vorige regels blijven gelden; over 30 s opnieuw proberen.
                self.rules.loaded = time.monotonic()
        rows, notes, fired = [], [], {}
        for data, ip, at in items:
            try:
                p = parse(data, ip, datetime.fromtimestamp(at, timezone.utc))
            except Exception:  # noqa: BLE001 - één vreemde regel mag de rest niet tegenhouden
                log.exception("Logregel van %s niet te ontleden", ip)
                self.lose(1, REJECTED)
                continue
            rows.append({"ts": p.ts, "host": p.host, "source_ip": ip, "facility": p.facility,
                         "severity": p.severity, "app": p.app, "msg": p.msg})
            notes.extend(self.rules.match(p, fired))
        return Batch(rows, notes, fired)

    async def store(self, b: Batch) -> None:
        """De hele batch in één transactie. Bij een storing gaat de fout naar de oproeper, die opnieuw probeert; wat
        al bewaard is, staat dan niet meer in de batch (geen dubbele regels). Weigert de database de gegevens zelf,
        dan regel per regel: één slechte regel mag de rest niet tegenhouden, en hem opnieuw proberen helpt niet."""
        if not b.single:
            try:
                async with self.maker() as db:
                    if b.rows:
                        await db.execute(insert(LogEntry), b.rows)
                    db.add_all([Notification(**n) for n in b.notes])
                    await db.commit()
            except DBAPIError as e:
                if not _bad_data(e):
                    raise
                log.warning("De database weigert een regel uit deze batch (%s): regel per regel verder", _why(e))
                b.single = True
            else:
                self.stored += len(b.rows)
                b.rows, b.notes = [], []
        while b.rows:
            try:
                async with self.maker() as db:
                    await db.execute(insert(LogEntry), b.rows[:1])
                    await db.commit()
                self.stored += 1
            except DBAPIError as e:
                if not _bad_data(e):
                    raise
                log.warning("Logregel van %s geweigerd door de database: %s", b.rows[0]["host"][:80], _why(e))
                self.lose(1, REJECTED)
            b.rows.pop(0)
        while b.notes:
            try:
                async with self.maker() as db:
                    db.add(Notification(**b.notes[0]))
                    await db.commit()
            except DBAPIError as e:
                if not _bad_data(e):
                    raise
                log.warning("Melding %r geweigerd door de database: %s", b.notes[0]["title"][:80], _why(e))
            b.notes.pop(0)
        self.rules.last_fire.update(b.fired)

    async def flush(self, items: list[tuple[bytes, str, float]]) -> None:
        """Eén poging, zonder opnieuw proberen (dat doet write)."""
        await self.store(await self.prepare(items))

    async def write(self, items: list[tuple[bytes, str, float]]) -> None:
        """Tot de batch in de database staat: bij een storing opnieuw, telkens iets later (tot RETRY_MAX). Zolang neemt
        de schrijver niets nieuws uit de wachtrij; die vangt op wat intussen binnenkomt."""
        batch, wait = None, RETRY_FIRST
        while True:
            try:
                if batch is None:
                    batch = await self.prepare(items)
                await self.store(batch)
                break
            except Exception as e:  # noqa: BLE001 - de ontvanger moet blijven draaien
                self._failed(e)
            await self._pause(wait)
            wait = min(wait * 2, RETRY_MAX)
        self._recovered()

    def _failed(self, e: BaseException) -> None:
        """Eén logregel per storing (niet per poging): de eigen logregels gaan ook naar de diagnose."""
        why = _why(e)
        first = self.down_since is None
        if first:
            self.down_since = time.time()
            self.last_error = {"since": _iso(self.down_since), "until": None, "error": why}
        else:
            self.last_error["error"] = why
        if not first:
            return
        if _outage(e):
            log.warning("Database onbereikbaar (%s): logregels wachten in het geheugen (%d in de wachtrij)", why,
                        self.backlog())
        else:
            log.exception("Wegschrijven van %d logregels mislukt; nieuwe poging tot het lukt", len(self.current))

    def _recovered(self) -> None:
        if self.down_since is None:
            return
        log.info("Database weer bereikbaar na %d s; %d logregels uit de wachtrij worden nu bijgeschreven",
                 time.time() - self.down_since, self.queue.qsize())
        self.last_error["until"] = _iso()
        self.down_since = None

    async def _pause(self, seconds: float) -> None:
        """Wachten voor een nieuwe poging. Bij het stoppen niet lang: dan telt elke seconde."""
        if self.closing:
            await asyncio.sleep(min(seconds, RETRY_FIRST))
            return
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._wake.wait(), seconds)

    async def take(self) -> list[tuple[bytes, str, float]]:
        """De volgende batch: tot BATCH regels, of wat er binnen FLUSH_SECONDS bijkomt."""
        self.current = [await self.queue.get()]
        deadline = time.monotonic() + FLUSH_SECONDS
        while len(self.current) < BATCH:
            if self.closing and self.queue.empty():
                break
            left = deadline - time.monotonic()
            if left <= 0:
                break
            try:
                self.current.append(await asyncio.wait_for(self.queue.get(), left))
            except asyncio.TimeoutError:
                break
        return self.current

    async def writer(self) -> None:
        while True:
            await self.write(await self.take())
            self.current = []

    def status(self, prev: dict) -> tuple[dict, int]:
        """De waarde voor AppState "syslog": teken van leven, tellers, de laatste databasefout en het verlies. Nieuw
        verlies telt op bij wat er al stond (ook van voor een herstart) als dat minder dan LOSS_HOURS oud is. Geeft ook
        terug hoeveel nieuw verlies erin zit: dat staat pas na de commit in de database."""
        loss = prev.get("loss") or None
        new = dict(self._loss)
        if new["n"]:
            since, at = _iso(new["since"]), _iso(new["at"])
            if loss and new["since"] - datetime.fromisoformat(loss["at"]).timestamp() < LOSS_HOURS * 3600:
                loss = {**loss, "at": at, "n": loss["n"] + new["n"], "why": new["why"]}
            else:
                loss = {"since": since, "at": at, "n": new["n"], "why": new["why"]}
        return {"at": _iso(), "started": self.started, "pid": os.getpid(), "received": self.received,
                "stored": self.stored, "lost": self.lost, "backlog": self.backlog(),
                "down_since": _iso(self.down_since) if self.down_since else None,
                "last_error": self.last_error, "loss": loss}, new["n"]

    async def save_status(self) -> bool:
        try:
            async with self.maker() as db:
                st = await ensure_state(db, STATE_KEY)
                st.value, n = self.status(dict(st.value or {}))
                await db.commit()
        except Exception:  # noqa: BLE001 - de ontvanger moet blijven draaien
            # Een storing meldt de schrijver al; iets anders één keer, met traceback.
            if self.down_since is None and not self._status_failed:
                log.exception("Toestand van de syslog-ontvanger bewaren mislukt")
            self._status_failed = True
            return False
        self._status_failed = False
        # Dat staat nu in de database. Intussen kan er nieuw verlies bijgekomen zijn: dat blijft staan.
        self._loss["n"] -= n
        if not self._loss["n"]:
            self._loss.update(since=None, at=None, why=None)
        return True

    async def status_loop(self) -> None:
        while True:
            await asyncio.sleep(STATUS_EVERY)
            await self.save_status()

    async def setup(self) -> None:
        """Bij het starten, terwijl de luisteraars al open staan: TimescaleDB of niet, de meldingsregels en een eerste
        teken van leven. Is de database (nog) niet bereikbaar, dan later opnieuw: het proces blijft draaien, en wat
        binnenkomt wacht in de wachtrij."""
        wait = RETRY_FIRST
        while True:
            try:
                await self.detect_timescale()
                if not self.rules.ready:
                    await self.reload_rules()
                break
            except Exception as e:  # noqa: BLE001
                if wait == RETRY_FIRST:
                    log.warning("Database niet bereikbaar bij het starten (%s); nieuwe poging op de achtergrond",
                                _why(e))
            await asyncio.sleep(wait)
            wait = min(wait * 2, RETRY_MAX)
        await self.save_status()

    async def cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(3600)
            if self.dropped:
                log.warning("%d logregels niet bewaard het afgelopen uur (zie Gezondheid › homepage)", self.dropped)
                self.dropped = 0
            # None: nog niet geweten of het TimescaleDB is (database onbereikbaar sinds het starten).
            if not self.self_cleanup:
                continue
            try:
                async with self.maker() as db:
                    keep = timedelta(days=get_settings().syslog_keep_days)
                    # Per uur met een commit ertussen: ook na een lange stilstand blijft elke DELETE kort.
                    await delete_before(db, LogEntry.ts, datetime.now(timezone.utc) - keep, timedelta(hours=1))
            except Exception:
                log.exception("Opruimen mislukt")

    async def detect_timescale(self) -> None:
        """Is log_entries een hypertable? Dan ruimt TimescaleDB zelf op (retentiebeleid) en de ontvanger niet. Een fout
        (database onbereikbaar) gaat naar de oproeper: niet gokken, self_cleanup blijft dan None."""
        async with self.maker() as db:
            hyper = False
            if db.bind.dialect.name == "postgresql":
                ext = (await db.execute(text("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"))).scalar()
                hyper = bool(ext and (await db.execute(text(
                    "SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'log_entries'"
                ))).scalar())
        self.self_cleanup = not hyper

    async def drain(self, seconds: float = DRAIN_SECONDS) -> None:
        """Bij het stoppen, als er niets meer binnenkomt: de schrijver de wachtrij laten leegmaken, hoogstens seconds
        lang (ook een wachtende nieuwe poging gaat dan sneller)."""
        self.closing = True
        self._wake.set()
        end = time.monotonic() + seconds
        while self.backlog() and time.monotonic() < end:
            await asyncio.sleep(0.05)


class Udp(asyncio.DatagramProtocol):
    def __init__(self, rx: Receiver) -> None:
        self.rx = rx

    def datagram_received(self, data: bytes, addr) -> None:
        self.rx.accept(data, addr[0])


async def handle_tcp(rx: Receiver, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """TCP-syslog: octet counting ("123 <34>1 ...") of één bericht per regel. Zit de wachtrij vol, dan leest deze
    verbinding niet verder tot er plaats is (zie Receiver.accept_wait)."""
    ip = writer.get_extra_info("peername")[0]
    task = asyncio.current_task()
    rx.clients.add(task)
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
                await rx.accept_wait(await reader.readexactly(length), ip)
            else:
                line = first + await reader.readuntil(b"\n")
                await rx.accept_wait(line, ip)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError, ConnectionError):
        pass
    finally:
        rx.clients.discard(task)
        writer.close()


async def serve(rx: Receiver, bind: str, port: int, stop: asyncio.Event) -> None:
    """Eerst luisteren, dan pas de database: een database die (nog) niet bereikbaar is, houdt het ontvangen niet tegen.
    Tot stop gezet wordt; dan geen nieuwe regels meer aannemen en de wachtrij wegschrijven (hoogstens DRAIN_SECONDS)."""
    loop = asyncio.get_running_loop()
    udp, _ = await loop.create_datagram_endpoint(lambda: Udp(rx), local_addr=(bind, port))
    server = await asyncio.start_server(lambda r, w: handle_tcp(rx, r, w), bind, port, limit=MAX_TCP_FRAME)
    log.info("Syslog luistert op %s:%d (udp+tcp), toegelaten: %s", bind, port, get_settings().syslog_allow)
    writer = asyncio.create_task(rx.writer())
    # De eigen logregels elke minuut in de database, voor de diagnose.
    forever = [writer, asyncio.create_task(rx.cleanup_loop()), asyncio.create_task(rx.status_loop()),
               asyncio.create_task(logring.flush_loop(rx.maker, "syslog"))]
    setup = asyncio.create_task(rx.setup())
    stopping = asyncio.create_task(stop.wait())
    try:
        done, _ = await asyncio.wait([stopping, *forever], return_when=asyncio.FIRST_COMPLETED)
        for t in done:
            if t is not stopping:
                t.result()  # een lus die stopt is een fout: die gaat naar systemd, dat herstart
                raise RuntimeError("achtergrondtaak van de syslog-ontvanger gestopt")
    finally:
        log.info("Stoppen: geen nieuwe regels meer aannemen, de wachtrij wegschrijven (%d regels)", rx.backlog())
        udp.close()
        server.close()
        for t in list(rx.clients):
            t.cancel()
        if not writer.done():
            await rx.drain(DRAIN_SECONDS)
        for t in (*forever, setup, stopping):
            t.cancel()
        await asyncio.gather(*forever, setup, stopping, return_exceptions=True)
        left = rx.backlog()
        if left:
            log.warning("%d logregels niet meer weggeschreven bij het stoppen", left)
            rx.lose(left, STOPPED)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(rx.save_status(), 3)


async def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logring.install("syslog")
    s = get_settings()
    rx = Receiver(async_sessionmaker(get_engine("syslog"), expire_on_commit=False))
    stop = asyncio.Event()
    # systemctl stop/restart (ook bij elke update) stuurt SIGTERM: eerst de wachtrij wegschrijven.
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await serve(rx, s.syslog_bind, s.syslog_port, stop)
    log.info("Syslog-ontvanger gestopt")


if __name__ == "__main__":
    asyncio.run(main())
