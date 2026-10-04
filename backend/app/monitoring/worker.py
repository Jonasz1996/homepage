"""Achtergrondproces dat de checks uitvoert. Start met: python -m app.monitoring.worker"""

import asyncio
import logging
import random
import time

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..cron.scan import CRON_EVERY, run_scan as cron_scan
from ..db import get_engine
from ..models import Service
from ..ssh_discovery import SYNC_EVERY, auto_sync
from .checks import HttpClients, run_check
from .engine import cleanup, housekeeping, record
from .capacity import SAMPLE_EVERY, check_forecasts, sample
from .network import NETWORK_EVERY, PUBLIC_IP_EVERY, sample_power, watch_gateways, watch_public_ip, watch_tunnels
from .report import weekly_notification
from .updates import UPDATES_EVERY, run_updates
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
        except Exception:
            log.exception("check voor service %s mislukt", sid)
        finally:
            self.running.discard(sid)

    async def periodic(self) -> None:
        """Trage taken (externe API's) los van de checks, elk half uur."""
        async with self.maker() as db:
            await watch_npm(db, self.http)
            await db.commit()
        async with self.maker() as db:
            await watch_pbs(db, self.http)
            await db.commit()
        async with self.maker() as db:
            await weekly_notification(db)
            await db.commit()

    async def network(self, with_ip: bool) -> None:
        """Elke 2 minuten: WAN-gateways en tunnels; elke 5 minuten ook het publieke IP."""
        async with self.maker() as db:
            await watch_gateways(db, self.http)
            await watch_tunnels(db, self.http)
            if with_ip:
                await watch_public_ip(db, self.http)
            await db.commit()

    async def updates(self) -> None:
        """Elke 6 uur: openstaande updates op nodes, containers en Docker-images."""
        async with self.maker() as db:
            await run_updates(db, self.http)
            await db.commit()

    async def capacity(self) -> None:
        """Elke 10 minuten: gebruik uit Proxmox bewaren en kijken of er opslag vol dreigt te lopen."""
        async with self.maker() as db:
            await sample(db, self.http)
            await sample_power(db, self.http)
            await db.commit()
            await check_forecasts(db)
            await db.commit()

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

    def spawn(self, coro) -> None:
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        task.add_done_callback(lambda t: t.cancelled() or not t.exception() or
                               log.error("achtergrondtaak mislukt", exc_info=t.exception()))

    async def run(self) -> None:
        await self.detect_timescale()
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
        while True:
            try:
                for sid, check, url in await self.due_services():
                    self.spawn(self.run_one(sid, check, url))
                if time.monotonic() - last_periodic > PERIODIC:
                    last_periodic = time.monotonic()
                    self.spawn(self.periodic())
                if time.monotonic() - last_capacity > SAMPLE_EVERY:
                    last_capacity = time.monotonic()
                    self.spawn(self.capacity())
                if time.monotonic() - last_network > NETWORK_EVERY:
                    last_network = time.monotonic()
                    with_ip = last_network - last_ip > PUBLIC_IP_EVERY
                    if with_ip:
                        last_ip = last_network
                    self.spawn(self.network(with_ip))
                if time.monotonic() - last_updates > UPDATES_EVERY:
                    last_updates = time.monotonic()
                    self.spawn(self.updates())
                if time.monotonic() - last_ssh > SYNC_EVERY:
                    last_ssh = time.monotonic()
                    self.spawn(self.ssh_sync())
                if time.monotonic() - last_cron > CRON_EVERY:
                    last_cron = time.monotonic()
                    self.spawn(self.cron())
                if time.monotonic() - last_cleanup > 3600:
                    async with self.maker() as db:
                        if self.self_cleanup:
                            await cleanup(db)
                        await housekeeping(db)
                        await db.commit()
                    last_cleanup = time.monotonic()
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
