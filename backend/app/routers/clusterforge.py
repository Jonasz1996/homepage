"""ClusterForge beheert het dashboard: aan- en uitzetten, kiezen op welke pagina, en nu synchroniseren."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import clusterforge_sync as cfs
from ..db import ensure_state, get_db
from ..deps import audit, current_user
from ..models import Page, Service, User
from . import integrations as integ_router

router = APIRouter(prefix="/api/clusterforge", tags=["clusterforge"])


def _sources(services) -> list[dict]:
    """ClusterForge-tegels die als bron kunnen dienen: het overzicht (geen cluster, node of SOC, niet zelf beheerd)."""
    out = []
    for s in services:
        c = s.config or {}
        if s.type == "clusterforge" and not any(c.get(k) for k in ("cluster", "node", "soc", cfs.MARK)):
            out.append({"id": s.id, "name": s.name})
    return out


@router.get("/beheer")
async def get_beheer(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await ensure_state(db, cfs.STATE_KEY, {})
    v = st.value or {}
    services = list((await db.execute(select(Service).where(Service.type == "clusterforge"))).scalars())
    pages = list((await db.execute(select(Page).order_by(Page.position))).scalars())
    managed = sum(1 for s in services if (s.config or {}).get(cfs.MARK))
    await db.commit()
    return {"service_id": v.get("service_id"), "page_id": v.get("page_id"), "nodes": v.get("nodes", True),
            "last": v.get("last"), "managed": managed, "sources": _sources(services),
            "pages": [{"id": p.id, "name": p.name} for p in pages], "every": cfs.EVERY}


class BeheerIn(BaseModel):
    service_id: int | None = None
    page_id: int | None = None
    nodes: bool = True


@router.put("/beheer")
async def put_beheer(data: BeheerIn, request: Request, user: User = Depends(current_user),
                     db: AsyncSession = Depends(get_db)):
    if data.service_id is not None:
        s = await db.get(Service, data.service_id)
        if s is None or not _sources([s]):
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Kies een ClusterForge-tegel met het overzicht (zonder cluster, node of soc)")
    if data.page_id is not None and await db.get(Page, data.page_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Pagina niet gevonden")
    st = await ensure_state(db, cfs.STATE_KEY, {})
    v = dict(st.value or {})
    v.update(service_id=data.service_id, nodes=data.nodes)
    if data.page_id is not None or data.service_id is None:
        v["page_id"] = data.page_id
    st.value = v
    await audit(db, request, user, "clusterforge_beheer", service_id=data.service_id, page_id=data.page_id, nodes=data.nodes)
    await db.commit()
    result = None
    if data.service_id:
        # Meteen een eerste ronde, zodat je ziet wat er gebeurt.
        result = await cfs.sync(db, integ_router.clients)
        await db.commit()
    return {"ok": True, "result": result}


class SyncIn(BaseModel):
    force: bool = True


@router.post("/beheer/sync")
async def sync_now(data: SyncIn, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Nu synchroniseren. Met de hand mag het ook als het veel weghaalt (de worker houdt zich dan in)."""
    result = await cfs.sync(db, integ_router.clients, force=data.force)
    if result.get("skipped"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Het beheer door ClusterForge staat uit")
    await audit(db, request, user, "clusterforge_sync", **{k: v for k, v in result.items() if k != "error"})
    await db.commit()
    return result
