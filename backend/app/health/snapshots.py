"""Vergeten snapshots: alle snapshots van VM's en containers via de Proxmox-API, met hun leeftijd.

Een snapshot die blijft staan houdt oude blokken vast en laat de opslag stilletjes vollopen. Lezen kan met de
PVEAuditor-rol; verwijderen vraagt VM.Snapshot op het token.
"""

import asyncio
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..integrations import IntegrationError, build
from ..integrations.proxmox import NODE_RE
from ..models import AppState, Service

log = logging.getLogger("homepage.health")

SNAPSHOTS_EVERY = 6 * 3600
STATE_KEY = "snapshots"
SNAP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")


async def _guest_snaps(px, g: dict, sem: asyncio.Semaphore) -> list[dict]:
    path = f"/nodes/{g['node']}/{g['type']}/{g['vmid']}/snapshot"
    async with sem:
        rows = await px.get(path)
    out = []
    for s in rows or []:
        if s.get("name") == "current" or not s.get("name"):
            continue
        out.append({"name": s["name"], "description": (s.get("description") or "").strip()[:300] or None,
                    "snaptime": s.get("snaptime"), "vmstate": bool(s.get("vmstate")), "parent": s.get("parent")})
    return out


async def collect(db: AsyncSession, http, now: datetime) -> dict:
    items, errors, seen = [], [], set()
    sem = asyncio.Semaphore(8)
    for svc in (await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars():
        px = build(svc, http)
        try:
            res = await px.resources()
        except IntegrationError as e:
            errors.append({"service": svc.name, "error": str(e)})
            continue
        guests = [r for r in res if r.get("type") in ("qemu", "lxc") and not r.get("template")
                  and (r.get("node"), r.get("vmid")) not in seen]
        seen.update((g.get("node"), g.get("vmid")) for g in guests)
        results = await asyncio.gather(*(_guest_snaps(px, g, sem) for g in guests), return_exceptions=True)
        for g, r in zip(guests, results):
            if isinstance(r, BaseException):
                errors.append({"service": svc.name, "guest": g.get("vmid"), "error": str(r)[:200]})
                continue
            for s in r:
                age = None
                if s["snaptime"]:
                    age = (now - datetime.fromtimestamp(int(s["snaptime"]), timezone.utc)).total_seconds() / 86400
                items.append({**s, "service_id": svc.id, "service": svc.name, "node": g["node"], "type": g["type"],
                              "vmid": g["vmid"], "guest": g.get("name") or str(g["vmid"]),
                              "age_days": round(age, 1) if age is not None else None})
    items.sort(key=lambda s: -(s["age_days"] or 0))
    return {"items": items, "errors": errors}


def _key(s: dict) -> str:
    return f"{s['node']}/{s['vmid']}/{s['name']}"


async def run_snapshots(db: AsyncSession, http, days: int) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    data = await collect(db, http, now)
    state = await db.get(AppState, STATE_KEY)
    warned = set(state.value.get("warned", [])) if state else set()
    old = [s for s in data["items"] if (s["age_days"] or 0) >= days]
    new = [s for s in old if _key(s) not in warned]
    if new:
        lines = [f"{s['guest']} ({s['vmid']}) · {s['name']} · {int(s['age_days'])} dagen" for s in new[:15]]
        if len(new) > 15:
            lines.append(f"… en nog {len(new) - 15}")
        notify(db, f"{len(new)} snapshot{'s' if len(new) != 1 else ''} ouder dan {days} dagen",
               "\n".join(lines) + "\nOude snapshots houden schijfruimte vast.", level="warn", source="snapshots")
    # Alleen bijhouden wat nog bestaat, zodat een opnieuw gemaakte snapshot met dezelfde naam weer meldt.
    value = {"checked_at": now.isoformat(), **data, "warned": sorted(_key(s) for s in old)}
    if state:
        state.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value


async def delete_snapshot(svc: Service, http, node: str, kind: str, vmid: int, name: str) -> str:
    if not (isinstance(node, str) and NODE_RE.match(node)) or kind not in ("qemu", "lxc") or not SNAP_RE.match(name):
        raise IntegrationError("Ongeldige node, type of snapshotnaam")
    px = build(svc, http)
    upid = await px.request("DELETE", f"/api2/json/nodes/{node}/{kind}/{int(vmid)}/snapshot/{name}",
                            headers=px.headers())
    return (upid or {}).get("data") or ""
