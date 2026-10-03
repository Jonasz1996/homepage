"""Achtergrondproces dat de checks uitvoert. Start met: python -m app.monitoring.worker"""

import asyncio
import logging
import random
import time

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker

from ..db import get_engine
from ..models import Service
from .checks import HttpClients, run_check
from .engine import cleanup, housekeeping, record
from .capacity import SAMPLE_EVERY, check_forecasts, sample
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

    async def capacity(self) -> None:
        """Elke 10 minuten: gebruik uit Proxmox bewaren en kijken of er opslag vol dreigt te lopen."""
        async with self.maker() as db:
            await sample(db, self.http)
            await db.commit()
            await check_forecasts(db)
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
