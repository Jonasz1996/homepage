"""Periodieke taken naast de checks: nieuwe hosts in NPM, back-ups in PBS."""

import logging
import time
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import event, notify
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


async def watch_pbs(db: AsyncSession, clients: HttpClients) -> None:
    """Meldt back-ups die te oud zijn, een mislukte taak of een mislukte verify hebben (één keer per probleem)."""
    for svc in (await db.execute(select(Service).where(Service.type == "proxmoxbackupserver"))).scalars().all():
        try:
            _, groups, _ = await build(svc, clients).backup_status()
        except IntegrationError as e:
            log.info("PBS %s niet bereikbaar: %s", svc.name, e)
            continue
        await _new_backups(db, svc, groups)
        problems = {}
        for g in groups:
            name = f"{g['store']}:{g['group']}" + (f" ({g['comment']})" if g.get("comment") else "")
            if g["task_failed"]:
                problems[f"{g['store']}:{g['group']}:task"] = f"{name}: laatste back-up mislukt"
            if g["verify"] == "failed":
                problems[f"{g['store']}:{g['group']}:verify"] = f"{name}: verify mislukt"
            if g["level"] != "ok" and not g["task_failed"] and g["verify"] != "failed":
                problems[f"{g['store']}:{g['group']}:late"] = f"{name}: geen back-up in meer dan 26 uur"
        key = f"pbs_problems:{svc.id}"
        state = await db.get(AppState, key)
        seen = set(state.value.get("keys", [])) if state else set()
        new = [problems[k] for k in sorted(problems) if k not in seen]
        if new:
            body = "\n".join(new[:8]) + (f"\n… en {len(new) - 8} meer" if len(new) > 8 else "")
            notify(db, f"{svc.name}: {len(new)} back-up{'s' if len(new) > 1 else ''} met een probleem", body,
                   level="err" if any("mislukt" in n for n in new) else "warn", source="backup", service_id=svc.id)
        # De teksten erbij voor het aandacht-overzicht.
        value = {"keys": sorted(problems), "items": problems}
        if state:
            state.value = value
        else:
            db.add(AppState(key=key, value=value))


async def _new_backups(db: AsyncSession, svc: Service, groups: list[dict]) -> None:
    """Gemaakte back-ups op de tijdlijn, gebundeld per ronde (anders honderden regels per nacht)."""
    now = time.time()
    last = {f"{g['store']}:{g['group']}": int(now - g["age"]) for g in groups if g.get("age") is not None}
    key = f"pbs_last:{svc.id}"
    state = await db.get(AppState, key)
    if state is None:
        db.add(AppState(key=key, value=last))
        return
    seen = state.value
    new = sorted((k for k, t in last.items() if t > seen.get(k, 0) + 60), key=lambda k: last[k])
    if new:
        names = {f"{g['store']}:{g['group']}": g.get("comment") or g["group"] for g in groups}
        shown = [names[k] for k in new[:20]] + ([f"… en {len(new) - 20} meer"] if len(new) > 20 else [])
        event(db, "backup", f"{svc.name}: {len(new)} back-up{'s' if len(new) > 1 else ''} gemaakt", ", ".join(shown),
              level="ok", service_id=svc.id, data={"count": len(new)})
    state.value = {**seen, **last}
