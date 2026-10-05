"""Achtergrondproces dat de checks uitvoert. Start met: python -m app.monitoring.worker"""

import asyncio
import logging
import random
import time
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..cron.scan import CRON_EVERY, run_scan as cron_scan
from ..db import get_engine
from ..health.domains import DOMAINS_EVERY, run_domains
from ..health.scan import HEALTH_EVERY, run_health, settings as health_settings
from ..health.selfcheck import HEARTBEAT_EVERY, SELFCHECK_EVERY, heartbeat, run_selfcheck
from ..health.snapshots import SNAPSHOTS_EVERY, run_snapshots
from ..models import AppState, Service
from ..ssh_discovery import SYNC_EVERY, auto_sync
from .checks import HttpClients, run_check
from .engine import cleanup, housekeeping, record
from .capacity import SAMPLE_EVERY, check_forecasts, sample
from .network import NETWORK_EVERY, PUBLIC_IP_EVERY, sample_power, watch_gateways, watch_public_ip, watch_tunnels
from .report import weekly_notification
from .updates import UPDATES_EVERY, run_updates
from .upgrade import auto_updates, cleanup_snapshots, mark_interrupted
from . import cluster, configs, containerlogs, devices, healing, planned, restoretest
from .watchers import watch_npm, watch_pbs

log = logging.getLogger("homepage.worker")

TICK = 5
MIN_INTERVAL = 15
PARALLEL = 20
PERIODIC = 1800


class Worker:
    def __init__(self, maker: async_sessionmaker) -> None:
        self.maker = maker
        self.next_due: dict[int, float] = {}
        self.running: set[int] = set()
        self.sem = asyncio.Semaphore(PARALLEL)
        self.tasks: set[asyncio.Task] = set()
        self.self_cleanup = True
        self.http = HttpClients()
        self.started = datetime.now(timezone.utc).replace(microsecond=0)
        # Periodieke taken per naam: een trage ronde (SSH die hangt) mag niet stapelen met de volgende.
        self.jobs: dict[str, asyncio.Task] = {}

    async def detect_timescale(self) -> None:
        async with self.maker() as db:
            try:
                hyper = (await db.execute(text(
                    "SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name = 'check_results'"
                ))).scalar()
            except Exception:
                hyper = None
        # TimescaleDB heeft een eigen bewaarbeleid; anders ruimen we zelf op.
        self.self_cleanup = not hyper
        log.info("TimescaleDB %s", "actief" if hyper else "niet actief, worker ruimt zelf op")

    async def due_services(self) -> list[tuple[int, dict, str | None]]:
        async with self.maker() as db:
            rows = (await db.execute(select(Service.id, Service.check, Service.url))).all()
        now = time.monotonic()
        due = []
        seen = set()
        for sid, check, url in rows:
            if not check or not check.get("type"):
                continue
            seen.add(sid)
            interval = max(int(check.get("interval") or 60), MIN_INTERVAL)
            if sid not in self.next_due:
                # Eerste keer: spreiden zodat niet alles tegelijk vertrekt.
                self.next_due[sid] = now + random.uniform(0, min(interval, 30))
            if self.next_due[sid] <= now and sid not in self.running:
                self.next_due[sid] = now + interval
                due.append((sid, check, url))
        for sid in list(self.next_due):
            if sid not in seen:
                del self.next_due[sid]
        return due

    async def run_one(self, sid: int, check: dict, url: str | None) -> None:
        self.running.add(sid)
        try:
            async with self.sem:
                outcome = await run_check(check, url, self.http)
            async with self.maker() as db:
                service = await db.get(Service, sid)
                if service is None:
                    return
                await record(db, service, outcome)
                await db.commit()
            if not outcome.ok:
                await healing.check(self.maker, sid, self.http)
        except Exception:
            log.exception("check voor service %s mislukt", sid)
        finally:
            self.running.discard(sid)

    async def step(self, name: str, fn) -> None:
        """Eén deelstap in een eigen sessie: een fout rolt alleen deze stap terug, de volgende stappen lopen gewoon."""
        try:
            async with self.maker() as db:
                await fn(db)
                await db.commit()
        except Exception:
            log.exception("%s mislukt", name)

    async def restoretest(self) -> None:
        """De maandelijkse hersteltest, als het zover is (loopt minutenlang, los van de andere taken)."""
        async with self.maker() as db:
            st = await db.get(AppState, restoretest.STATE_KEY)
            value = st.value if st else None
        if restoretest.due(value, datetime.now(timezone.utc)):
            await restoretest.run(self.maker, self.http)

    async def periodic(self) -> None:
        """Trage taken (externe API's) los van de checks, elk half uur."""
        await self.step("NPM bekijken", lambda db: watch_npm(db, self.http))
        await self.step("PBS bekijken", lambda db: watch_pbs(db, self.http))
        await self.step("weekoverzicht", weekly_notification)

    async def network(self, with_ip: bool) -> None:
        """Elke 2 minuten: WAN-gateways en tunnels; elke 5 minuten ook het publieke IP."""
        await self.step("WAN-gateways", lambda db: watch_gateways(db, self.http))
        await self.step("tunnels", lambda db: watch_tunnels(db, self.http))
        if with_ip:
            await self.step("publiek IP", lambda db: watch_public_ip(db, self.http))

    async def updates(self) -> None:
        """Elke 6 uur: openstaande updates op nodes, containers en Docker-images."""
        await self.step("updates bekijken", lambda db: run_updates(db, self.http))
        try:
            await cleanup_snapshots(self.maker, self.http)
        except Exception:
            log.exception("snapshots van updates opruimen mislukt")

    async def auto_updates(self) -> None:
        """Elke minuut kijken of het tijd is voor de nachtelijke beveiligingsupdates."""
        try:
            ran = await auto_updates(self.maker, self.http)
        except Exception:
            log.exception("nachtelijke updates mislukt")
            return
        if ran:
            async with self.maker() as db:
                await run_updates(db, self.http)
                await db.commit()

    async def capacity(self) -> None:
        """Elke 10 minuten: gebruik uit Proxmox bewaren en kijken of er opslag vol dreigt te lopen."""
        await self.step("capaciteit meten", lambda db: sample(db, self.http))
        await self.step("verbruik meten", lambda db: sample_power(db, self.http))
        await self.step("prognoses", check_forecasts)

    async def ssh_sync(self) -> None:
        """Elk half uur, als het aan staat: nieuwe machines uit Proxmox in de terminal en IP's bijwerken."""
        async with self.maker() as db:
            result = await auto_sync(db, self.http)
            await db.commit()
            if result and (result["added"] or result["updated"]):
                log.info("SSH-hosts uit Proxmox: %(added)s nieuw, %(updated)s bijgewerkt", result)

    async def cron(self) -> None:
        """Elk kwartier: cronjobs, timers en Proxmox/PBS-jobs van alle machines, met hun runs."""
        async with self.maker() as db:
            await cron_scan(db)
            await db.commit()

    async def health(self, what: str) -> None:
        """Schijven en temperaturen (10 min), snapshots (6 u), domeinen (dagelijks), de homepage zelf (elk uur)."""
        async with self.maker() as db:
            cfg = await health_settings(db)
            if what == "hardware":
                await run_health(db)
            elif what == "snapshots":
                await run_snapshots(db, self.http, cfg["snapshot_days"])
            elif what == "domains":
                if cfg["domains"]:
                    await run_domains(db, self.http, cfg["domains"])
            elif what == "selfcheck":
                await run_selfcheck(db, cfg["offsite"])
            await db.commit()

    async def lan(self) -> None:
        """Elke 5 minuten: apparaten uit OPNsense, en de poortscans die aan de beurt zijn."""
        await self.step("apparaten ophalen", lambda db: devices.refresh(db, self.http))
        await self.step("poortscans", devices.scan_due)

    async def config_copy(self) -> None:
        """Elke nacht op het ingestelde uur: kopie van de configuratie, met een melding als er iets veranderde."""
        async with self.maker() as db:
            if await configs.due(db):
                await configs.run_configs(db, self.http)
                await db.commit()

    async def beat(self) -> None:
        async with self.maker() as db:
            await heartbeat(db, self.started)
            await db.commit()

    async def tidy(self) -> None:
        async with self.maker() as db:
            if self.self_cleanup:
                await cleanup(db)
            await housekeeping(db)
            await db.commit()

    def spawn(self, coro) -> asyncio.Task:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        task.add_done_callback(lambda t: t.cancelled() or not t.exception() or
                               log.error("achtergrondtaak mislukt", exc_info=t.exception()))
        return task

    def job(self, name: str, make) -> bool:
        """Start make() als taak `name`, tenzij de vorige ronde van die taak nog loopt. Geeft terug of hij startte."""
        running = self.jobs.get(name)
        if running and not running.done():
            log.info("%s loopt nog van de vorige keer, deze ronde overgeslagen", name)
            return False
        self.jobs[name] = self.spawn(make())
        return True

    async def interrupted(self) -> None:
        """Nachtelijke update-runs die liepen toen de worker stopte, als mislukt markeren."""
        try:
            async with self.maker() as db:
                n = await mark_interrupted(db, ("auto",))
                await db.commit()
            if n:
                log.warning("%s nachtelijke update-run(s) onderbroken door herstart", n)
        except Exception:
            log.exception("onderbroken update-runs opruimen mislukt")

    async def run(self) -> None:
        await self.detect_timescale()
        await self.interrupted()
        last_cleanup = 0.0
        # Eerste ronde na een minuut, daarna elk half uur.
        last_periodic = time.monotonic() - PERIODIC + 60
        last_capacity = time.monotonic() - SAMPLE_EVERY + 30
        last_updates = time.monotonic() - UPDATES_EVERY + 300
        # Netwerk en publiek IP meteen bij de start.
        last_network = time.monotonic() - NETWORK_EVERY - 1
        last_ip = time.monotonic() - PUBLIC_IP_EVERY - 1
        last_ssh = time.monotonic() - SYNC_EVERY + 120
        last_cron = time.monotonic() - CRON_EVERY + 180
        start = time.monotonic()
        health = {"hardware": (HEALTH_EVERY, start - HEALTH_EVERY + 240),
                  "snapshots": (SNAPSHOTS_EVERY, start - SNAPSHOTS_EVERY + 300),
                  "domains": (DOMAINS_EVERY, start - DOMAINS_EVERY + 360),
                  "selfcheck": (SELFCHECK_EVERY, start - SELFCHECK_EVERY + 90)}
        last_beat = 0.0
        last_lan = start - devices.DEVICES_EVERY + 45
        last_cluster = start - cluster.CLUSTER_EVERY + 20
        last_docker = start - containerlogs.EVERY + 15
        while True:
            try:
                for sid, check, url in await self.due_services():
                    self.spawn(self.run_one(sid, check, url))
                if time.monotonic() - last_periodic > PERIODIC:
                    last_periodic = time.monotonic()
                    self.job("periodic", self.periodic)
                if time.monotonic() - last_capacity > SAMPLE_EVERY:
                    last_capacity = time.monotonic()
                    self.job("capacity", self.capacity)
                if time.monotonic() - last_network > NETWORK_EVERY:
                    last_network = time.monotonic()
                    with_ip = last_network - last_ip > PUBLIC_IP_EVERY
                    if with_ip:
                        last_ip = last_network
                    self.job("network", lambda: self.network(with_ip))
                if time.monotonic() - last_updates > UPDATES_EVERY:
                    last_updates = time.monotonic()
                    self.job("updates", self.updates)
                if time.monotonic() - last_ssh > SYNC_EVERY:
                    last_ssh = time.monotonic()
                    self.job("ssh_sync", self.ssh_sync)
                if time.monotonic() - last_cron > CRON_EVERY:
                    last_cron = time.monotonic()
                    self.job("cron", self.cron)
                for what, (every, last) in health.items():
                    if time.monotonic() - last > every:
                        health[what] = (every, time.monotonic())
                        self.job(f"health:{what}", lambda what=what: self.health(what))
                if time.monotonic() - last_cluster > cluster.CLUSTER_EVERY:
                    last_cluster = time.monotonic()
                    self.job("cluster", lambda: self.step("clusterstatus", lambda db: cluster.run_cluster(db, self.http)))
                if time.monotonic() - last_docker > containerlogs.EVERY:
                    last_docker = time.monotonic()
                    self.job("containerlogs", lambda: self.step(
                        "containerlogs", lambda db: containerlogs.run_containerlogs(db, self.http)))
                if time.monotonic() - last_lan > devices.DEVICES_EVERY:
                    last_lan = time.monotonic()
                    self.job("lan", self.lan)
                if time.monotonic() - last_beat > HEARTBEAT_EVERY:
                    last_beat = time.monotonic()
                    self.job("beat", self.beat)
                    self.job("planned", lambda: self.step("gepland onderhoud", planned.apply))
                    self.job("restoretest", self.restoretest)
                    self.job("config_copy", self.config_copy)
                    self.job("auto_updates", self.auto_updates)
                if time.monotonic() - last_cleanup > 3600:
                    last_cleanup = time.monotonic()
                    self.job("cleanup", self.tidy)
            except Exception:
                log.exception("fout in de worker-lus")
            await asyncio.sleep(TICK)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    maker = async_sessionmaker(get_engine(), expire_on_commit=False)
    asyncio.run(Worker(maker).run())


if __name__ == "__main__":
    main()
