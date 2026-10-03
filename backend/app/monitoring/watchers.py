"""Periodieke taken naast de checks: nieuwe hosts in NPM opmerken."""

import logging
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..integrations import IntegrationError, build
from ..integrations.npm import host_url
from ..models import AppState, Service
from .checks import HttpClients

log = logging.getLogger("homepage.worker")


def _host(url: str | None) -> str | None:
    return (urlsplit(url).hostname or "").lower() or None if url else None


async def watch_npm(db: AsyncSession, clients: HttpClients) -> None:
    """Meldt proxy hosts die in NPM bijgekomen zijn en nog geen tegel hebben (één keer per host)."""
    known = {_host(u) for u in (await db.execute(select(Service.url))).scalars()}
    for svc in (await db.execute(select(Service).where(Service.type == "npm"))).scalars().all():
        try:
            hosts = await build(svc, clients).proxy_hosts()
        except IntegrationError as e:
            log.info("NPM %s niet bereikbaar: %s", svc.name, e)
            continue
        names = sorted({_host(host_url(h)) for h in hosts if host_url(h)})
        key = f"npm_seen:{svc.id}"
        state = await db.get(AppState, key)
        if state is None:
            # Eerste keer: alles wat er nu staat als gezien beschouwen, niets melden.
            db.add(AppState(key=key, value={"hosts": names}))
            continue
        seen = set(state.value.get("hosts", []))
        new = [n for n in names if n not in seen and n not in known]
        if new:
            shown = ", ".join(new[:5]) + (f" en {len(new) - 5} meer" if len(new) > 5 else "")
            notify(db, f"{len(new)} nieuwe host{'s' if len(new) > 1 else ''} in NPM", f"{shown}. Importeer ze via ▤ op de NPM-tegel.",
                   level="info", source="npm", service_id=svc.id)
        state.value = {"hosts": names}
