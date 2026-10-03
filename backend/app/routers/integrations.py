"""API voor integraties: velden op de tegels, het mini dashboard, acties en de NPM-import."""

import asyncio
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_user, notify, recent_auth
from ..integrations import REGISTRY, Integration, IntegrationError
from ..integrations.npm import NginxProxyManager, host_url
from ..layout import record_revision
from ..models import Group, Service, User
from ..monitoring.checks import HttpClients
from ..security import decrypt_json

router = APIRouter(prefix="/api", tags=["integrations"])

clients = HttpClients()
SUMMARY_TTL = 30
DETAIL_TTL = 10
# (service_id, soort) -> (verloopt, vingerafdruk, resultaat)
_cache: dict[tuple[int, str], tuple[float, tuple, dict]] = {}


def _fingerprint(s: Service) -> tuple:
    return (s.type, s.url, repr(s.config), s.secrets)


def _integration(s: Service) -> Integration:
    cls = REGISTRY.get(s.type)
    if cls is None:
        raise IntegrationError(f"Geen integratie voor type '{s.type}'")
    client = clients.get(bool((s.config or {}).get("insecure")))
    return cls(s.url, s.config or {}, decrypt_json(s.secrets), client)


async def _cached(s: Service, kind: str, ttl: int, fn) -> dict:
    key = (s.id, kind)
    fp = _fingerprint(s)
    hit = _cache.get(key)
    if hit and hit[0] > time.monotonic() and hit[1] == fp:
        return hit[2]
    try:
        result = await fn(_integration(s))
    except IntegrationError as e:
        result = {"error": str(e)}
    except Exception as e:  # een kapotte API mag het dashboard niet breken
        result = {"error": f"Onverwacht antwoord ({type(e).__name__})"}
    # Fouten korter bewaren, zodat een herstelde service snel weer verschijnt.
    _cache[key] = (time.monotonic() + (ttl if "error" not in result else 10), fp, result)
    return result


async def _service(db: AsyncSession, service_id: int) -> Service:
    s = await db.get(Service, service_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service niet gevonden")
    return s


@router.get("/integrations")
async def list_integrations(user: User = Depends(current_user)):
    return [{"name": c.name, "label": c.label, "config": c.config_help, "secrets": c.secret_help,
             "actions": sorted(c.actions)} for c in REGISTRY.values()]


@router.get("/widgets")
async def widgets(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    services = (await db.execute(select(Service).where(Service.type.in_(list(REGISTRY))))).scalars().all()
    sem = asyncio.Semaphore(10)

    async def one(s: Service):
        async with sem:
            return s.id, await _cached(s, "summary", SUMMARY_TTL, lambda i: _fields(i))

    return {str(sid): data for sid, data in await asyncio.gather(*(one(s) for s in services))}


async def _fields(i: Integration) -> dict:
    return {"fields": await i.summary()}


@router.get("/services/{service_id}/integration")
async def integration_detail(service_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s = await _service(db, service_id)
    if s.type not in REGISTRY:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deze service heeft geen integratie")
    data = await _cached(s, "detail", DETAIL_TTL, lambda i: i.detail())
    return {"label": REGISTRY[s.type].label, **data}


class ActionIn(BaseModel):
    action: str = Field(max_length=40)
    params: dict = Field(default_factory=dict)


@router.post("/services/{service_id}/integration/action")
async def integration_action(service_id: int, data: ActionIn, request: Request,
                             user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    s = await _service(db, service_id)
    try:
        integ = _integration(s)
        if data.action not in integ.actions:
            raise IntegrationError("Onbekende actie")
        message = await integ.action(data.action, data.params)
    except IntegrationError as e:
        await audit(db, request, user, "integration_action_failed", service=s.name, op=data.action, error=str(e))
        await db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    await audit(db, request, user, "integration_action", service=s.name, op=data.action, params=data.params)
    notify(db, f"{s.name}: {message}", level="info", source="actie", service_id=s.id)
    await db.commit()
    _cache.pop((s.id, "detail"), None)
    _cache.pop((s.id, "summary"), None)
    return {"ok": True, "message": message}


# --- NPM: proxy hosts als tegels importeren ------------------------------------

def _norm(url: str | None) -> str | None:
    if not url:
        return None
    p = urlsplit(url)
    return (p.hostname or "").lower() or None


async def _npm(db: AsyncSession, service_id: int) -> NginxProxyManager:
    s = await _service(db, service_id)
    if s.type != "npm":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Dit is geen NPM-service")
    return _integration(s)


@router.get("/services/{service_id}/npm/hosts")
async def npm_hosts(service_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    try:
        hosts = await (await _npm(db, service_id)).proxy_hosts()
    except IntegrationError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    known = {_norm(u) for u in (await db.execute(select(Service.url))).scalars()}
    out = []
    for h in hosts:
        url = host_url(h)
        if not url:
            continue
        name = urlsplit(url).hostname.split(".")[0]
        out.append({"url": url, "name": name, "enabled": bool(h.get("enabled")), "exists": _norm(url) in known,
                    "forward": f"{h.get('forward_host')}:{h.get('forward_port')}"})
    return sorted(out, key=lambda x: x["name"])


class NpmImportIn(BaseModel):
    group_id: int
    hosts: list[dict] = Field(max_length=500)
    monitor: bool = True


@router.post("/services/{service_id}/npm/import")
async def npm_import(service_id: int, data: NpmImportIn, request: Request,
                     user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await _npm(db, service_id)
    if await db.get(Group, data.group_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Groep niet gevonden")
    known = {_norm(u) for u in (await db.execute(select(Service.url))).scalars()}
    pos = (await db.execute(select(func.coalesce(func.max(Service.position), -1))
                            .where(Service.group_id == data.group_id))).scalar_one() + 1
    added = 0
    for h in data.hosts:
        url, name = str(h.get("url") or ""), str(h.get("name") or "").strip()[:80]
        if not url.startswith(("http://", "https://")) or not name or _norm(url) in known:
            continue
        known.add(_norm(url))
        db.add(Service(group_id=data.group_id, name=name, url=url[:500], icon=f"{name.lower()}.png", position=pos,
                       type="link", config={},
                       check={"type": "http", "interval": 60} if data.monitor else {}))
        pos += 1
        added += 1
    if added:
        await record_revision(db, user, f"{added} services geïmporteerd uit NPM")
        await audit(db, request, user, "npm_import", added=added)
    await db.commit()
    return {"added": added}
