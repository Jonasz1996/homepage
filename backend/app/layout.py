"""Lezen, bewaren en terugzetten van de volledige layout (pagina's, groepen, services)."""

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from .config import get_settings
from .models import Group, Page, Revision, Service, User
from .schemas import PageOut, ServiceOut
from .security import decrypt_json

SERVICE_FIELDS = ("id", "name", "description", "url", "icon", "position", "type", "check", "config", "secrets",
                  "parent_id", "notes")


async def load_pages(db: AsyncSession) -> list[Page]:
    stmt = (
        select(Page)
        .options(selectinload(Page.groups).selectinload(Group.services))
        .order_by(Page.position, Page.id)
        .execution_options(populate_existing=True)
    )
    return list((await db.execute(stmt)).scalars())


def service_out(s: Service) -> ServiceOut:
    out = ServiceOut.model_validate(s)
    out.secret_keys = sorted(decrypt_json(s.secrets)) if s.secrets else []
    return out


def pages_out(pages: list[Page]) -> list[dict]:
    result = []
    for p in pages:
        page = PageOut.model_validate(p).model_dump()
        for g_out, g in zip(page["groups"], p.groups):
            g_out["services"] = [service_out(s).model_dump() for s in g.services]
        result.append(page)
    return result


def snapshot(pages: list[Page]) -> dict:
    """Volledige kopie inclusief (versleutelde) secrets, om te kunnen terugzetten."""
    return {
        "pages": [
            {
                "id": p.id, "name": p.name, "icon": p.icon, "position": p.position,
                "groups": [
                    {
                        "id": g.id, "name": g.name, "icon": g.icon, "position": g.position,
                        "collapsed": g.collapsed,
                        "services": [{f: getattr(s, f) for f in SERVICE_FIELDS} for s in g.services],
                    }
                    for g in p.groups
                ],
            }
            for p in pages
        ]
    }


async def record_revision(db: AsyncSession, user: User | None, summary: str) -> None:
    await db.flush()
    db.add(Revision(user_id=user.id if user else None, summary=summary[:255],
                    snapshot=snapshot(await load_pages(db))))
    await db.flush()
    keep = get_settings().revisions_keep
    old_ids = (await db.execute(
        select(Revision.id).order_by(Revision.id.desc()).offset(keep)
    )).scalars().all()
    if old_ids:
        await db.execute(delete(Revision).where(Revision.id.in_(old_ids)))


async def restore_snapshot(db: AsyncSession, snap: dict) -> None:
    """Zet de layout terug zonder services te verwijderen die blijven bestaan,
    zodat hun monitoring-historiek bewaard blijft."""
    page_ids, group_ids, service_ids = set(), set(), set()
    for p in snap["pages"]:
        page_ids.add(p["id"])
        await db.merge(Page(id=p["id"], name=p["name"], icon=p.get("icon"), position=p["position"]))
    await db.flush()
    for p in snap["pages"]:
        for g in p["groups"]:
            group_ids.add(g["id"])
            await db.merge(Group(id=g["id"], page_id=p["id"], name=g["name"], icon=g.get("icon"),
                                 position=g["position"], collapsed=g.get("collapsed", False)))
    await db.flush()
    parents = {}
    for p in snap["pages"]:
        for g in p["groups"]:
            for s in g["services"]:
                service_ids.add(s["id"])
                parents[s["id"]] = s.get("parent_id")
                fields = {f: s.get(f) for f in SERVICE_FIELDS if f != "parent_id"}
                await db.merge(Service(group_id=g["id"], parent_id=None, **fields))
    await db.flush()
    # Afhankelijkheden pas zetten als alle services bestaan.
    for sid, parent in parents.items():
        if parent in service_ids:
            (await db.get(Service, sid)).parent_id = parent
    await db.flush()
    # Eerst services, dan groepen, dan pagina's: wat verplaatst werd, hangt al onder de juiste ouder.
    await db.execute(delete(Service).where(Service.id.not_in(service_ids or {-1})))
    await db.execute(delete(Group).where(Group.id.not_in(group_ids or {-1})))
    await db.execute(delete(Page).where(Page.id.not_in(page_ids or {-1})))
    await db.flush()
