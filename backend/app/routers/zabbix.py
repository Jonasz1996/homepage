"""Zabbix bij de tegels: rood of groen per service (uit de laatste ronde van de worker), en bij het openklikken
de hosts van die service met hun waarden, een grafiek van 24 u en de open problemen, rechtstreeks uit Zabbix."""

import time

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import current_user
from ..integrations import IntegrationError, build
from ..models import AppState, Service, User
from ..monitoring import zabbix as zmon
from . import integrations as integrations_router

router = APIRouter(prefix="/api", tags=["zabbix"])

DETAIL_TTL = 30
_cache: dict[int, tuple[float, dict]] = {}


async def _state(db: AsyncSession) -> dict:
    st = await db.get(AppState, zmon.STATE_KEY)
    return dict(st.value) if st and st.value else {}


@router.get("/zabbix")
async def zabbix_status(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    v = await _state(db)
    return {"configured": bool(v.get("service_id")), "at": v.get("at"), "error": v.get("error"), "url": v.get("url"),
            "services": zmon.status(v), "hosts": sorted({h["name"] for h in v.get("hosts") or []}, key=str.lower)}


@router.get("/services/{service_id}/zabbix")
async def service_zabbix(service_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    v = await _state(db)
    rows = (v.get("map") or {}).get(str(service_id)) or []
    if not v.get("service_id") or not rows:
        svc = await db.get(Service, service_id)
        off = svc is not None and str((svc.config or {}).get("zabbix") or "").strip() == "-"
        return {"configured": bool(v.get("service_id")) and not off, "hosts": []}
    hit = _cache.get(service_id)
    if hit and hit[0] > time.monotonic() and hit[1].get("_at") == v.get("at"):
        return hit[1]
    zsvc = (await db.execute(select(Service).where(Service.id == v["service_id"]))).scalar_one_or_none()
    await db.close()
    if zsvc is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Zabbix-tegel niet gevonden")
    known = {h["id"]: h for h in v.get("hosts") or []}
    role = {r["id"]: r["role"] for r in rows}
    ids = [r["id"] for r in rows if r["id"] in known]
    out = {"configured": True, "url": v.get("url"), "error": None, "hosts": [], "_at": v.get("at")}
    try:
        z = build(zsvc, integrations_router.clients)
        problems = await z.problems(ids)
        metrics = await z.metrics(ids)
    except IntegrationError as e:
        problems, metrics, out["error"] = [p for p in v.get("problems") or [] if p["host_id"] in ids], {}, str(e)
    for hid in ids:
        h = known[hid]
        ps = [p for p in problems if p["host_id"] == hid]
        out["hosts"].append({"id": hid, "name": h["name"], "host": h["host"], "role": role[hid], "down": h["down"],
                             "ips": h["ips"], "level": zmon.host_level(h, ps), "problems": ps, "metrics": metrics.get(hid, [])})
    _cache[service_id] = (time.monotonic() + DETAIL_TTL, out)
    return out
