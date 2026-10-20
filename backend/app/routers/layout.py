from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_session, current_user, recent_auth
from ..layout import load_pages, pages_out, record_revision, restore_snapshot, service_out
from ..models import Group, Page, Revision, Service, Session, User
from ..schemas import GroupIn, OrderIn, PageIn, ServiceIn
from ..security import decrypt_json, encrypt_json

router = APIRouter(prefix="/api", tags=["layout"])


async def _get(db: AsyncSession, model, obj_id: int):
    obj = await db.get(model, obj_id)
    if obj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{model.__name__} {obj_id} niet gevonden")
    return obj


async def _next_position(db: AsyncSession, column, parent_col=None, parent_id=None) -> int:
    stmt = select(func.coalesce(func.max(column), -1))
    if parent_col is not None:
        stmt = stmt.where(parent_col == parent_id)
    return (await db.execute(stmt)).scalar_one() + 1


@router.get("/layout")
async def get_layout(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return {"pages": pages_out(await load_pages(db))}


# --- Pagina's ---------------------------------------------------------------

@router.post("/pages", status_code=201)
async def create_page(data: PageIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    page = Page(**data.model_dump(), position=await _next_position(db, Page.position))
    db.add(page)
    await record_revision(db, user, f"Pagina '{page.name}' toegevoegd")
    await db.commit()
    return {"id": page.id}


@router.patch("/pages/{page_id}")
async def update_page(page_id: int, data: PageIn, user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)):
    page = await _get(db, Page, page_id)
    for k, v in data.model_dump().items():
        setattr(page, k, v)
    await record_revision(db, user, f"Pagina '{page.name}' aangepast")
    await db.commit()
    return {"ok": True}


@router.delete("/pages/{page_id}")
async def delete_page(page_id: int, request: Request, user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)):
    page = await _get(db, Page, page_id)
    await db.delete(page)
    await audit(db, request, user, "page_deleted", name=page.name)
    await record_revision(db, user, f"Pagina '{page.name}' verwijderd")
    await db.commit()
    return {"ok": True}


# --- Groepen ----------------------------------------------------------------

@router.post("/groups", status_code=201)
async def create_group(data: GroupIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await _get(db, Page, data.page_id)
    group = Group(**data.model_dump(),
                  position=await _next_position(db, Group.position, Group.page_id, data.page_id))
    db.add(group)
    await record_revision(db, user, f"Groep '{group.name}' toegevoegd")
    await db.commit()
    return {"id": group.id}


@router.patch("/groups/{group_id}")
async def update_group(group_id: int, data: GroupIn, user: User = Depends(current_user),
                       db: AsyncSession = Depends(get_db)):
    group = await _get(db, Group, group_id)
    await _get(db, Page, data.page_id)
    for k, v in data.model_dump().items():
        setattr(group, k, v)
    await record_revision(db, user, f"Groep '{group.name}' aangepast")
    await db.commit()
    return {"ok": True}


@router.delete("/groups/{group_id}")
async def delete_group(group_id: int, request: Request, user: User = Depends(current_user),
                       db: AsyncSession = Depends(get_db)):
    group = await _get(db, Group, group_id)
    await db.delete(group)
    await audit(db, request, user, "group_deleted", name=group.name)
    await record_revision(db, user, f"Groep '{group.name}' verwijderd")
    await db.commit()
    return {"ok": True}


# --- Services ---------------------------------------------------------------

def _apply_secrets(service: Service, secrets: dict[str, str | None] | None) -> None:
    if secrets is None:
        return
    current = decrypt_json(service.secrets)
    for k, v in secrets.items():
        if v in (None, ""):
            current.pop(k, None)
        else:
            current[k] = v
    service.secrets = encrypt_json(current)


async def _check_parent(db: AsyncSession, service_id: int | None, parent_id: int | None) -> None:
    """Afhankelijkheid moet bestaan en mag geen kring vormen (A hangt af van B, B van A)."""
    seen = {service_id} if service_id else set()
    cur = parent_id
    while cur:
        if cur in seen:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Deze afhankelijkheid maakt een kring")
        seen.add(cur)
        parent = await db.get(Service, cur)
        if parent is None:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Service voor afhankelijkheid bestaat niet")
        cur = parent.parent_id


@router.post("/services", status_code=201)
async def create_service(data: ServiceIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await _get(db, Group, data.group_id)
    await _check_parent(db, None, data.parent_id)
    service = Service(**data.model_dump(exclude={"secrets"}),
                      position=await _next_position(db, Service.position, Service.group_id, data.group_id))
    _apply_secrets(service, data.secrets)
    db.add(service)
    await record_revision(db, user, f"Service '{service.name}' toegevoegd")
    await db.commit()
    return {"id": service.id}


@router.get("/services/{service_id}")
async def get_service(service_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return service_out(await _get(db, Service, service_id))


def _target(type_: str | None, url: str | None, config: dict | None) -> tuple:
    return type_, url, (config or {}).get("url")


@router.patch("/services/{service_id}")
async def update_service(service_id: int, data: ServiceIn, request: Request, sess: Session = Depends(current_session),
                         user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    service = await _get(db, Service, service_id)
    # Bewaarde secrets naar een ander adres of type sturen = ze kunnen weglekken: vraagt een recente 2FA,
    # tenzij alle secrets in hetzelfde verzoek opnieuw ingegeven (of gewist) worden.
    moved = _target(data.type, data.url, data.config) != _target(service.type, service.url, service.config)
    stored = set(decrypt_json(service.secrets)) if moved and service.secrets else set()
    if stored and not stored <= set(data.secrets or {}):
        await recent_auth(sess, user)
        await audit(db, request, user, "service_target_changed", service=service.name, url=data.url,
                    type=data.type, old_url=service.url, old_type=service.type)
    await _check_parent(db, service_id, data.parent_id)
    if data.group_id != service.group_id:
        await _get(db, Group, data.group_id)
        service.position = await _next_position(db, Service.position, Service.group_id, data.group_id)
    # Notities worden meestal apart bewaard (zie hieronder); zonder veld blijven ze staan.
    skip = {"secrets"} if "notes" in data.model_fields_set else {"secrets", "notes"}
    for k, v in data.model_dump(exclude=skip).items():
        setattr(service, k, v)
    if data.secrets is not None:
        _apply_secrets(service, data.secrets)
        await audit(db, request, user, "service_secrets_changed", service=service.name, keys=sorted(data.secrets))
    await record_revision(db, user, f"Service '{service.name}' aangepast")
    await db.commit()
    return {"ok": True}


class NotesIn(BaseModel):
    notes: str | None = Field(default=None, max_length=20000)


@router.put("/services/{service_id}/notes")
async def set_notes(service_id: int, data: NotesIn, user: User = Depends(current_user),
                    db: AsyncSession = Depends(get_db)):
    service = await _get(db, Service, service_id)
    service.notes = (data.notes or "").strip() or None
    await record_revision(db, user, f"Notities van '{service.name}' aangepast")
    await db.commit()
    return {"ok": True, "notes": service.notes}


@router.delete("/services/{service_id}")
async def delete_service(service_id: int, request: Request, user: User = Depends(current_user),
                         db: AsyncSession = Depends(get_db)):
    service = await _get(db, Service, service_id)
    await db.delete(service)
    await audit(db, request, user, "service_deleted", name=service.name)
    await record_revision(db, user, f"Service '{service.name}' verwijderd")
    await db.commit()
    return {"ok": True}


# --- Volgorde (slepen) ------------------------------------------------------

@router.put("/layout/order")
async def set_order(data: OrderIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    if data.pages is not None:
        for pos, pid in enumerate(data.pages):
            (await _get(db, Page, pid)).position = pos
    for page_id, group_ids in (data.groups or {}).items():
        await _get(db, Page, page_id)
        for pos, gid in enumerate(group_ids):
            g = await _get(db, Group, gid)
            g.page_id, g.position = page_id, pos
    for group_id, service_ids in (data.services or {}).items():
        await _get(db, Group, group_id)
        for pos, sid in enumerate(service_ids):
            s = await _get(db, Service, sid)
            s.group_id, s.position = group_id, pos
    await record_revision(db, user, "Volgorde aangepast")
    await db.commit()
    return {"ok": True}


# --- Revisies ---------------------------------------------------------------

@router.get("/revisions")
async def list_revisions(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(Revision.id, Revision.created_at, Revision.summary).order_by(Revision.id.desc()).limit(100)
    )).all()
    return [{"id": r.id, "created_at": r.created_at, "summary": r.summary} for r in rows]


@router.post("/revisions/{revision_id}/restore")
async def restore_revision(revision_id: int, request: Request, user: User = Depends(current_user),
                           db: AsyncSession = Depends(get_db)):
    rev = await _get(db, Revision, revision_id)
    label = f"Teruggezet naar versie van {rev.created_at:%d/%m %H:%M}"
    await restore_snapshot(db, rev.snapshot)
    await audit(db, request, user, "revision_restored", revision=revision_id)
    await record_revision(db, user, label)
    await db.commit()
    return {"ok": True}
