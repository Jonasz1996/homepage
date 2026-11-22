"""Tegels die ClusterForge beheert (homepage-API v2).

Elke minuut vraagt de worker bij elke API van soort clusterforge (API-beheer) de indeling op
(/api/dashboard/v2/homepage/layout, met ETag: als er niets veranderde kost dat niets). Elke app wordt een tegel
van type clusterforge in de groep met dezelfde naam (zo nodig nieuw, op de eerste pagina), met de check "api"
op /apps/<slug>?strict=1 (via ClusterForge.health): rood zodra ClusterForge de app niet gezond vindt.

Tegels die ClusterForge maakte staan herkenbaar in config.managed_by = "clusterforge" en config.cf_key. Alleen die
worden bijgewerkt en verwijderd; tegels die je zelf maakte blijft de sync uit de buurt. Wat je in ClusterForge
bijstuurt (naam, groep, icoon, verbergen) volgt hier vanzelf. Met "sync": false in de API staat dit uit.
"""

import logging
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..integrations import IntegrationError, from_api
from ..models import ApiConnection, Group, Page, Service
from .checks import HttpClients

log = logging.getLogger("homepage.clusterforge")

EVERY = 60
STATE_KEY = "clusterforge"
MANAGED = "clusterforge"


def is_managed(svc: Service, conn_id: int | None = None) -> bool:
    cfg = svc.config or {}
    return cfg.get("managed_by") == MANAGED and (conn_id is None or svc.api_id == conn_id)


def wanted(layout: dict) -> list[tuple[str, int, dict]]:
    """(groep, positie, tegel) in de volgorde van ClusterForge."""
    out = []
    for g in layout.get("groups") or []:
        for i, t in enumerate(g.get("tiles") or []):
            if t.get("key") and t.get("app"):
                out.append((str(g.get("name") or "ClusterForge")[:80], i, t))
    return out


async def fetch_layout(conn: ApiConnection, http: HttpClients, etag: str | None) -> tuple[dict | None, str | None]:
    """De indeling, of (None, etag) als er niets veranderde."""
    integ = from_api(conn, {}, http)
    headers = integ.headers()
    if etag:
        headers["If-None-Match"] = etag
    url = (conn.url or "").rstrip("/") + "/api/dashboard/v2/homepage/layout"
    try:
        r = await integ.client.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise IntegrationError(f"ClusterForge niet bereikbaar: {type(e).__name__}") from e
    if r.status_code == 304:
        return None, etag
    if r.status_code != 200:
        raise IntegrationError(f"ClusterForge antwoordt {r.status_code}")
    return r.json(), r.headers.get("ETag")


async def apply(db: AsyncSession, conn: ApiConnection, layout: dict) -> dict:
    """Maakt, wijzigt en verwijdert de beheerde tegels van deze verbinding. Geeft de aantallen terug."""
    services = (await db.execute(select(Service))).scalars().all()
    groups = (await db.execute(select(Group))).scalars().all()
    by_key = {(s.config or {}).get("cf_key"): s for s in services if is_managed(s, conn.id)}
    group_by_name = {g.name: g for g in groups}
    page = (await db.execute(select(Page).order_by(Page.position, Page.id).limit(1))).scalar_one_or_none()
    if page is None:
        page = Page(name="Home", position=0)
        db.add(page)
        await db.flush()
    stats = {"added": 0, "updated": 0, "removed": 0}
    seen = set()
    for gname, pos, t in wanted(layout):
        key = str(t["key"])
        seen.add(key)
        group = group_by_name.get(gname)
        if group is None:
            group = Group(page_id=page.id, name=gname, position=1000 + len(group_by_name))
            db.add(group)
            await db.flush()
            group_by_name[gname] = group
        slug = str(t["app"])
        values: dict[str, Any] = {
            "name": str(t.get("name") or slug)[:80],
            "description": (str(t.get("description") or "")[:255]) or None,
            "url": (str(t.get("href") or "")[:500]) or None,
            "icon": (str(t.get("icon") or "")[:500]) or None,
            "group_id": group.id,
        }
        config = {"managed_by": MANAGED, "cf_key": key, "app": slug}
        # De api-check van de tegel vraagt /apps/<slug>?strict=1 (ClusterForge.health): rood als de app niet gezond is.
        check = {"type": "api", "interval": 60}
        svc = by_key.get(key)
        if svc is None:
            db.add(Service(type="clusterforge", api_id=conn.id, position=1000 + pos, config=config, check=check, **values))
            stats["added"] += 1
            continue
        changed = False
        for k, v in values.items():
            if getattr(svc, k) != v:
                setattr(svc, k, v)
                changed = True
        cfg = {**(svc.config or {}), **config}
        if cfg != svc.config:
            svc.config = cfg
            changed = True
        # De check alleen zetten als hij nog de onze is (zelf aangepast = blijven).
        if not svc.check or ((svc.check or {}).get("type") == "api" and (svc.check or {}).get("path")):
            svc.check = check
            changed = True
        if changed:
            stats["updated"] += 1
    for key, svc in by_key.items():
        if key not in seen:
            await db.delete(svc)
            stats["removed"] += 1
    return stats


async def run_sync(db: AsyncSession, http: HttpClients) -> None:
    conns = (await db.execute(select(ApiConnection).where(ApiConnection.kind == "clusterforge"))).scalars().all()
    if not conns:
        return
    st = await ensure_state(db, STATE_KEY)
    state = dict(st.value or {})
    for conn in conns:
        if str((conn.config or {}).get("sync", True)).lower() in ("false", "0", "nee", "no"):
            continue
        cur = dict(state.get(str(conn.id)) or {})
        try:
            layout, etag = await fetch_layout(conn, http, cur.get("etag"))
        except IntegrationError as e:
            cur["error"] = str(e)
            state[str(conn.id)] = cur
            log.warning("ClusterForge %s: %s", conn.name, e)
            continue
        cur["error"] = None
        if layout is not None:
            stats = await apply(db, conn, layout)
            cur.update(etag=etag, version=layout.get("version"), last=stats)
            if any(stats.values()):
                log.info("ClusterForge %s: %s nieuw, %s bijgewerkt, %s weg", conn.name, stats["added"], stats["updated"],
                         stats["removed"])
        state[str(conn.id)] = cur
    st.value = state
