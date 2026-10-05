"""Import van homepage.dev services.yaml en import/export in ons eigen YAML-formaat."""

import re

import yaml
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_user
from ..layout import load_pages, record_revision
from ..models import Group, Page, Service, User
from ..schemas import ImportIn
from ..security import encrypt_json

router = APIRouter(prefix="/api", tags=["import"])

# Velden in een homepage.dev-widget die geheim zijn en dus versleuteld bewaard worden.
SECRET_FIELDS = {"key", "password", "token", "apikey", "api_key", "secret", "tokensecret", "username"}


_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


def _clean_url(v) -> str | None:
    """Zoals ServiceIn: alleen http(s)-links, anders niets (geen javascript: en dergelijke)."""
    v = str(v).strip()[:500] if v else ""
    return v if v.lower().startswith(("http://", "https://")) else None


def _clean_icon(v) -> str | None:
    """Een icoonnaam (mdi-…, jellyfin.png), een pad of een http(s)-adres; geen ander schema."""
    v = str(v).strip()[:500] if v else ""
    if not v or (_SCHEME.match(v) and not v.lower().startswith(("http://", "https://"))):
        return None
    return v


def _homepage_service(name: str, item: dict) -> dict:
    item = item or {}
    svc = {
        "name": str(name)[:80],
        "url": item.get("href"),
        "icon": item.get("icon"),
        "description": (item.get("description") or None),
        "type": "link",
        "check": {},
        "config": {},
        "secrets": {},
    }
    if item.get("siteMonitor"):
        svc["check"] = {"type": "http", "target": item["siteMonitor"], "interval": 60}
    elif item.get("ping"):
        svc["check"] = {"type": "ping", "target": item["ping"], "interval": 60}
    widget = item.get("widget")
    if isinstance(widget, dict) and widget.get("type"):
        svc["type"] = str(widget["type"])[:40]
        for k, v in widget.items():
            if k == "type":
                continue
            (svc["secrets"] if k.lower() in SECRET_FIELDS else svc["config"])[k] = v
    for k in ("server", "container", "namespace", "app"):
        if k in item:
            svc["config"].setdefault("homepage", {})[k] = item[k]
    return svc


def _walk_homepage(entries, prefix: str, groups: list[tuple[str, list[dict]]]) -> None:
    """homepage.dev: lijst van {Groep: [ {Service: {...}} | {Subgroep: [...]} ]}."""
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        for group_name, items in entry.items():
            full = f"{prefix} / {group_name}" if prefix else str(group_name)
            services: list[dict] = []
            groups.append((full[:80], services))
            for it in items or []:
                if not isinstance(it, dict):
                    continue
                for name, body in it.items():
                    if isinstance(body, list):
                        _walk_homepage([{name: body}], full, groups)
                    else:
                        services.append(_homepage_service(name, body))


def parse_import(text: str) -> list[tuple[str, list[tuple[str, list[dict]]]]]:
    """Geeft [(paginanaam of "", [(groepnaam, [service])])] terug."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Ongeldige YAML: {e}") from e
    if isinstance(data, dict) and "pages" in data:
        pages = []
        for p in data.get("pages") or []:
            groups = [
                (str(g.get("name", "Groep"))[:80],
                 [{**s, "secrets": {}} for s in (g.get("services") or []) if isinstance(s, dict) and s.get("name")])
                for g in (p.get("groups") or [])
            ]
            pages.append((str(p.get("name", "Import"))[:80], groups))
        return pages
    if isinstance(data, list):
        groups: list = []
        _walk_homepage(data, "", groups)
        return [("", groups)]
    raise HTTPException(status.HTTP_400_BAD_REQUEST, "Onbekend formaat: verwacht homepage.dev services.yaml of een eigen export")


@router.post("/import")
async def import_yaml(data: ImportIn, request: Request, user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)):
    parsed = parse_import(data.yaml)
    page_pos = (await db.execute(select(func.coalesce(func.max(Page.position), -1)))).scalar_one() + 1
    target = await db.get(Page, data.page_id) if data.page_id else None
    n_groups = n_services = 0
    for page_name, groups in parsed:
        page = target
        if page is None or page_name:
            page = Page(name=page_name or data.page_name or "Import", position=page_pos)
            page_pos += 1
            db.add(page)
            await db.flush()
        group_pos = (await db.execute(
            select(func.coalesce(func.max(Group.position), -1)).where(Group.page_id == page.id)
        )).scalar_one() + 1
        for group_name, services in groups:
            group = Group(page_id=page.id, name=group_name, position=group_pos)
            group_pos += 1
            db.add(group)
            await db.flush()
            n_groups += 1
            for pos, s in enumerate(services):
                db.add(Service(
                    group_id=group.id, position=pos, name=str(s["name"])[:80],
                    description=s.get("description"), url=_clean_url(s.get("url")), icon=_clean_icon(s.get("icon")),
                    type=s.get("type") or "link", check=s.get("check") or {}, config=s.get("config") or {},
                    notes=str(s["notes"])[:20000] if s.get("notes") else None,
                    secrets=encrypt_json(s.get("secrets") or {}),
                ))
                n_services += 1
    await audit(db, request, user, "import", groups=n_groups, services=n_services)
    await record_revision(db, user, f"Import: {n_groups} groepen, {n_services} services")
    await db.commit()
    return {"groups": n_groups, "services": n_services}


@router.get("/export", response_class=PlainTextResponse)
async def export_yaml(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Export zonder secrets: die blijven versleuteld in de database."""
    pages = await load_pages(db)
    doc = {
        "version": 1,
        "pages": [
            {
                "name": p.name,
                "groups": [
                    {
                        "name": g.name,
                        "services": [
                            {k: v for k, v in {
                                "name": s.name, "url": s.url, "icon": s.icon, "description": s.description,
                                "type": s.type, "check": s.check or None, "config": s.config or None,
                                "notes": s.notes,
                            }.items() if v not in (None, "")}
                            for s in g.services
                        ],
                    }
                    for g in p.groups
                ],
            }
            for p in pages
        ],
    }
    return PlainTextResponse(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True),
        headers={"Content-Disposition": 'attachment; filename="homepage-export.yaml"'},
    )
