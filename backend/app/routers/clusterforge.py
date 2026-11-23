"""ClusterForge beheert het dashboard: aan- en uitzetten, kiezen op welke pagina, en nu synchroniseren."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import clusterforge_sync as cfs
from .. import outside
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


# --- in één stap koppelen (welkomstscherm) -------------------------------------------------------------------

class KoppelIn(BaseModel):
    url: str = Field(min_length=8, max_length=500)
    token: str = Field(min_length=4, max_length=500)


def _base(url: str) -> str:
    url = url.strip().rstrip("/")
    for tail in ("/api/dashboard/v2", "/api/dashboard/v1", "/api"):
        if url.lower().endswith(tail):
            url = url[: -len(tail)]
    if not url.lower().startswith(("http://", "https://")) or " " in url:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Een adres met http:// of https://, bv. https://clusterforge.voorbeeld.be")
    return url


@router.post("/koppelen", dependencies=[outside.guard("acties", fresh=True)])
async def koppelen(data: KoppelIn, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Adres + token van ClusterForge: de API maken (of het token van de bestaande vervangen) en meteen alle tegels
    ophalen die ClusterForge publiceert. Daarna houdt de worker ze elke minuut bij."""
    from ..integrations import IntegrationError
    from ..layout import record_revision
    from ..models import ApiConnection
    from ..monitoring import clusterforge as cfapps
    from ..security import encrypt_json

    url = _base(data.url)
    token = data.token.strip()
    probe = ApiConnection(name="ClusterForge", kind="clusterforge", url=url, config={}, secrets=encrypt_json({"token": token}))
    try:
        layout, _ = await cfapps.fetch_layout(probe, integ_router.clients, None)
    except IntegrationError as e:
        msg = str(e)
        if "401" in msg or "403" in msg:
            msg = "ClusterForge weigert dit token: maak een nieuw in ClusterForge (Instellingen → Dashboard-API)."
        raise HTTPException(status.HTTP_400_BAD_REQUEST, msg) from None
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Dat adres is geen ClusterForge (geen JSON)") from None
    conns = (await db.execute(select(ApiConnection).where(ApiConnection.kind == "clusterforge"))).scalars().all()
    conn = next((c for c in conns if (c.url or "").rstrip("/").lower() == url.lower()), None)
    if conn is None:
        conn = ApiConnection(name="ClusterForge", category="Monitoring", kind="clusterforge", template="clusterforge",
                             url=url, config={})
        db.add(conn)
    conn.secrets = probe.secrets
    await db.flush()
    pve = await cfapps.proxmox_nodes(db, integ_router.clients)
    stats = await cfapps.apply(db, conn, layout or {}, pve)
    # De worker past de indeling bij zijn volgende ronde opnieuw toe (zonder ETag): dan klopt ook zijn toestand.
    st = await ensure_state(db, cfapps.STATE_KEY)
    st.value = {**(st.value or {}), str(conn.id): {"error": None}}
    tiles = sum(1 for s in (await db.execute(select(Service))).scalars().all() if cfapps.is_managed(s, conn.id))
    await audit(db, request, user, "clusterforge_koppelen", url=url, **stats)
    if any(stats.values()):
        await record_revision(db, user, f"ClusterForge gekoppeld: {stats['added']} tegels nieuw")
    await db.commit()
    return {**stats, "tiles": tiles, "api_id": conn.id}


@router.post("/ordenen")
async def ordenen(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Alle tegels uit ClusterForge nu opnieuw ordenen volgens de regels van monitoring/clusterforge.py (naam, dubbels,
    groep, check, Proxmox), zonder op de volgende ronde van de worker te wachten. Eigen tegels blijven zoals ze zijn."""
    from ..integrations import IntegrationError
    from ..layout import record_revision
    from ..models import ApiConnection
    from ..monitoring import clusterforge as cfapps

    conns = (await db.execute(select(ApiConnection).where(ApiConnection.kind == "clusterforge"))).scalars().all()
    if not conns:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Nog geen ClusterForge-API: koppel eerst ClusterForge")
    pve = await cfapps.proxmox_nodes(db, integ_router.clients)
    total = {"added": 0, "updated": 0, "removed": 0}
    errors = []
    for conn in conns:
        try:
            layout, _ = await cfapps.fetch_layout(conn, integ_router.clients, None)
        except (IntegrationError, ValueError) as e:
            errors.append(f"{conn.name}: {e}")
            continue
        for k, v in (await cfapps.apply(db, conn, layout or {}, pve)).items():
            total[k] += v
    if errors and len(errors) == len(conns):
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "; ".join(errors)[:300])
    await audit(db, request, user, "clusterforge_ordenen", **total)
    if any(total.values()):
        await record_revision(db, user, f"ClusterForge-tegels opnieuw geordend: {total['updated']} bijgewerkt, "
                                        f"{total['removed']} dubbels weg")
    await db.commit()
    return {**total, "errors": errors}
