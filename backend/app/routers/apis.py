"""API-beheer: API's per categorie (adres, aanmelding, versleutelde sleutels), eigen calls met velden voor de tegel,
en welke tegels welke API gebruiken. Met sjablonen voor bekende apps en het in één keer koppelen van veel tegels.
"""

import json
import time
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_session, current_user, recent_auth
from ..integrations import API_ONLY, REGISTRY, IntegrationError, from_api
from ..integrations import calls as callmod
from ..integrations import templates as tpl
from ..layout import record_revision
from ..models import ApiCall, ApiConnection, Service, Session, User, utcnow
from ..security import decrypt_json, encrypt_json
from . import integrations as integrations_router

router = APIRouter(prefix="/api/apis", tags=["apis"])

MAX_PREVIEW = 300_000


# --- schema's ------------------------------------------------------------------

class FieldIn(BaseModel):
    label: str = Field(default="", max_length=30)
    path: str = Field(default="", max_length=200)
    format: str = "auto"
    suffix: str = Field(default="", max_length=12)
    warn: float | None = None
    err: float | None = None
    equals: str | None = Field(default=None, max_length=60)

    @field_validator("format")
    @classmethod
    def _fmt(cls, v: str) -> str:
        if v not in callmod.FORMATS:
            raise ValueError("Onbekend formaat")
        return v


class TableIn(BaseModel):
    path: str = Field(default="", max_length=200)
    columns: list[FieldIn] = Field(default_factory=list, max_length=10)


class CallIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(default="", max_length=500)
    query: dict[str, str] = Field(default_factory=dict, max_length=20)
    headers: dict[str, str] = Field(default_factory=dict, max_length=20)
    body: str | None = Field(default=None, max_length=10000)
    show: Literal["tile", "detail", "action"] = "tile"
    fields: list[FieldIn] = Field(default_factory=list, max_length=12)
    table: TableIn | None = None
    confirm: bool = True

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        try:
            return callmod.check_path(v)
        except IntegrationError as e:
            raise ValueError(str(e)) from e

    def checked(self) -> "CallIn":
        # Alles behalve GET verandert iets: dat is altijd een knop (die een recente 2FA vraagt), nooit iets dat de
        # tegel elke minuut zelf zou uitvoeren.
        if self.method != "GET" and self.show != "action":
            raise HTTPException(422, f"Een {self.method}-call kan alleen een actieknop zijn")
        return self

    def values(self) -> dict:
        d = self.model_dump()
        d["table"] = d["table"] if d["table"] and d["table"]["columns"] else {}
        d["fields"] = [f for f in d["fields"] if f["path"] or f["format"] == "count"]
        return d


class ConnIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    category: str = Field(default="Overig", min_length=1, max_length=40)
    kind: str = Field(default="rest", max_length=40)
    url: str = Field(min_length=8, max_length=500)
    config: dict = Field(default_factory=dict)
    # None = ongewijzigd; een lege waarde wist die sleutel.
    secrets: dict[str, str | None] | None = None
    template: str | None = Field(default=None, max_length=40)

    @field_validator("url")
    @classmethod
    def _url(cls, v: str) -> str:
        v = v.strip()
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("Het adres begint met http:// of https://")
        return v

    @field_validator("kind")
    @classmethod
    def _kind(cls, v: str) -> str:
        if v not in REGISTRY:
            raise ValueError("Onbekende soort API")
        return v

    @field_validator("config")
    @classmethod
    def _config(cls, v: dict) -> dict:
        if len(json.dumps(v)) > 20000:
            raise ValueError("Instellingen te groot")
        auth = v.get("auth")
        if auth is not None and (not isinstance(auth, dict) or (auth.get("type") or "none") not in
                                 ("none", "bearer", "header", "query", "basic")):
            raise ValueError("Onbekende aanmelding")
        return v


class TilesIn(BaseModel):
    service_ids: list[int] = Field(max_length=500)
    attach: bool = True


class BulkItem(BaseModel):
    service_id: int
    template: str = Field(max_length=40)
    url: str | None = Field(default=None, max_length=500)
    secrets: dict[str, str] = Field(default_factory=dict)


class BulkIn(BaseModel):
    items: list[BulkItem] = Field(min_length=1, max_length=300)


class AdoptIn(BaseModel):
    service_ids: list[int] = Field(min_length=1, max_length=500)


class OrderIn(BaseModel):
    ids: list[int] = Field(max_length=200)


class TryIn(BaseModel):
    call: CallIn
    service_id: int | None = None


# --- hulpjes ---------------------------------------------------------------------

def _call_out(c: ApiCall) -> dict:
    return callmod.call_dict(c)


def _conn_out(a: ApiConnection, tiles: list[Service]) -> dict:
    cls = REGISTRY.get(a.kind)
    return {"id": a.id, "name": a.name, "category": a.category, "kind": a.kind, "kind_label": cls.label if cls else a.kind,
            "template": a.template, "url": a.url, "config": a.config or {},
            "secret_keys": sorted(decrypt_json(a.secrets)) if a.secrets else [],
            "calls": [_call_out(c) for c in a.calls], "updated_at": a.updated_at,
            "tiles": [{"id": s.id, "name": s.name} for s in tiles if s.api_id == a.id]}


async def _conn(db: AsyncSession, api_id: int) -> ApiConnection:
    a = await db.get(ApiConnection, api_id)
    if a is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "API niet gevonden")
    return a


def _apply_secrets(a: ApiConnection, secrets: dict[str, str | None] | None) -> None:
    if secrets is None:
        return
    cur = decrypt_json(a.secrets)
    for k, v in secrets.items():
        k = str(k).strip()[:40]
        if not k:
            continue
        if v in (None, ""):
            cur.pop(k, None)
        else:
            cur[k] = str(v)
    a.secrets = encrypt_json(cur) if cur else None


def _touch(a: ApiConnection) -> None:
    """Gewijzigde calls tellen als een gewijzigde API: de tegels halen hun velden dan opnieuw op."""
    a.updated_at = utcnow()


def _template_calls(key: str) -> list[ApiCall]:
    out = []
    for i, c in enumerate(tpl.TEMPLATES[key].get("calls") or []):
        d = CallIn(**c).checked().values()
        out.append(ApiCall(position=i, **d))
    return out


def _template_config(key: str) -> dict:
    t = tpl.TEMPLATES[key]
    config = {**(t.get("config") or {})}
    if t.get("auth"):
        config["auth"] = t["auth"]
    if t.get("headers"):
        config["headers"] = t["headers"]
    return config


def _new_conn(key: str, name: str, url: str, secrets: dict) -> ApiConnection:
    t = tpl.TEMPLATES[key]
    config = _template_config(key)
    a = ApiConnection(name=name[:80], category=t["category"], kind=t.get("kind", "rest"), template=key,
                      url=(t.get("url") or url)[:500], config=config, calls=_template_calls(key))
    _apply_secrets(a, secrets)
    return a


def _link(s: Service, a: ApiConnection | None) -> None:
    if a is None:
        if s.api_id is not None:
            s.type = "link"
        s.api_id = None
    else:
        s.api_id, s.type = a.id, a.kind


def _trim(data, depth: int = 0):
    """Voor het voorbeeld in de browser: lange lijsten en diepe nesting inkorten."""
    if depth > 12:
        return "…"
    if isinstance(data, list):
        return [_trim(x, depth + 1) for x in data[:50]] + ([f"… nog {len(data) - 50}"] if len(data) > 50 else [])
    if isinstance(data, dict):
        return {str(k): _trim(v, depth + 1) for k, v in list(data.items())[:200]}
    if isinstance(data, str) and len(data) > 2000:
        return data[:2000] + "…"
    return data


# --- lezen -------------------------------------------------------------------------

@router.get("")
async def list_apis(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    conns = (await db.execute(select(ApiConnection).order_by(ApiConnection.category, ApiConnection.name))).scalars().all()
    tiles = (await db.execute(select(Service).order_by(Service.name))).scalars().all()
    cats = list(tpl.CATEGORIES)
    for a in conns:
        if a.category not in cats:
            cats.append(a.category)
    kinds = [{"name": c.name, "label": c.label, "config": c.config_help, "secrets": c.secret_help, "prefix": c.call_prefix}
             for c in REGISTRY.values() if c.name not in ("json", "customapi")]
    return {"apis": [_conn_out(a, tiles) for a in conns], "categories": cats, "kinds": kinds,
            "templates": tpl.public(), "formats": callmod.FORMATS,
            "tiles": [{"id": s.id, "name": s.name, "url": s.url, "type": s.type, "api_id": s.api_id,
                       "own_keys": bool(s.secrets and decrypt_json(s.secrets))} for s in tiles]}


@router.get("/suggest")
async def suggest(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Tegels zonder API die een bekend sjabloon herkennen, en tegels met eigen sleutels die naar API-beheer kunnen."""
    tiles = (await db.execute(select(Service).where(Service.api_id.is_(None)).order_by(Service.name))).scalars().all()
    matches, adopt = [], []
    for s in tiles:
        own = bool(s.secrets and decrypt_json(s.secrets))
        if s.type in REGISTRY and (own or s.type not in ("rest", "json", "customapi")):
            adopt.append({"service_id": s.id, "name": s.name, "type": s.type, "url": (s.config or {}).get("url") or s.url})
            continue
        key = tpl.match(s) if s.url else None
        if key and key != "rest":
            t = tpl.TEMPLATES[key]
            matches.append({"service_id": s.id, "name": s.name, "url": s.url, "template": key, "label": t["label"],
                            "category": t["category"]})
    return {"matches": matches, "adopt": adopt}


# --- API's ---------------------------------------------------------------------------

@router.post("", status_code=201)
async def create_api(data: ConnIn, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    if data.template and data.template not in tpl.TEMPLATES:
        raise HTTPException(422, "Onbekend sjabloon")
    a = ApiConnection(name=data.name, category=data.category, kind=data.kind, url=data.url, config=data.config,
                      template=data.template)
    if data.template:
        # Aanmelding, vaste headers en calls van het sjabloon; wat de browser meestuurt gaat voor.
        a.config = {**_template_config(data.template), **data.config}
        a.calls = _template_calls(data.template)
    _apply_secrets(a, data.secrets)
    db.add(a)
    await db.flush()
    await audit(db, request, user, "api_created", name=a.name, url=a.url, keys=sorted(data.secrets or {}))
    await db.commit()
    return {"id": a.id}


@router.patch("/{api_id}")
async def update_api(api_id: int, data: ConnIn, request: Request, sess: Session = Depends(current_session),
                     user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    a = await _conn(db, api_id)
    # Bewaarde sleutels naar een ander adres, een andere soort of een andere aanmelding sturen kan ze laten
    # weglekken: dat vraagt een recente 2FA, tenzij alle sleutels in hetzelfde verzoek opnieuw ingegeven worden.
    old = (a.kind, a.url, json.dumps((a.config or {}).get("auth"), sort_keys=True))
    new = (data.kind, data.url, json.dumps(data.config.get("auth"), sort_keys=True))
    stored = set(decrypt_json(a.secrets)) if a.secrets and old != new else set()
    if stored and not stored <= set(data.secrets or {}):
        await recent_auth(sess, user)
        await audit(db, request, user, "api_target_changed", name=a.name, url=data.url, old_url=a.url, kind=data.kind)
    kind_changed = data.kind != a.kind
    a.name, a.category, a.kind, a.url, a.config = data.name, data.category, data.kind, data.url, data.config
    if data.secrets is not None:
        _apply_secrets(a, data.secrets)
        await audit(db, request, user, "api_secrets_changed", name=a.name, keys=sorted(data.secrets))
    _touch(a)
    if kind_changed:
        for s in (await db.execute(select(Service).where(Service.api_id == a.id))).scalars():
            s.type = a.kind
    await db.commit()
    return {"ok": True}


@router.delete("/{api_id}")
async def delete_api(api_id: int, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    a = await _conn(db, api_id)
    tiles = (await db.execute(select(Service).where(Service.api_id == a.id))).scalars().all()
    for s in tiles:
        _link(s, None)
    await db.delete(a)
    await audit(db, request, user, "api_deleted", name=a.name, tiles=len(tiles))
    if tiles:
        await record_revision(db, user, f"API '{a.name}' verwijderd ({len(tiles)} tegels losgekoppeld)")
    await db.commit()
    return {"ok": True}


@router.post("/{api_id}/tiles")
async def link_tiles(api_id: int, data: TilesIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Tegels (ook veel tegelijk) aan deze API koppelen, of ervan loskoppelen."""
    a = await _conn(db, api_id)
    n = 0
    for s in (await db.execute(select(Service).where(Service.id.in_(data.service_ids)))).scalars():
        if data.attach:
            _link(s, a)
            n += 1
        elif s.api_id == a.id:
            _link(s, None)
            n += 1
    if n:
        await record_revision(db, user, f"{n} tegels {'gekoppeld aan' if data.attach else 'losgekoppeld van'} API '{a.name}'")
    await db.commit()
    return {"changed": n}


# --- calls -----------------------------------------------------------------------------

@router.post("/{api_id}/calls", status_code=201)
async def create_call(api_id: int, data: CallIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    a = await _conn(db, api_id)
    c = ApiCall(position=len(a.calls), **data.checked().values())
    a.calls.append(c)
    _touch(a)
    await db.commit()
    return {"id": c.id}


async def _call(db: AsyncSession, call_id: int) -> ApiCall:
    c = await db.get(ApiCall, call_id)
    if c is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Call niet gevonden")
    return c


@router.patch("/calls/{call_id}")
async def update_call(call_id: int, data: CallIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    c = await _call(db, call_id)
    for k, v in data.checked().values().items():
        setattr(c, k, v)
    _touch(await _conn(db, c.connection_id))
    await db.commit()
    return {"ok": True}


@router.delete("/calls/{call_id}")
async def delete_call(call_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    c = await _call(db, call_id)
    a = await _conn(db, c.connection_id)
    a.calls.remove(c)
    _touch(a)
    await db.commit()
    return {"ok": True}


@router.post("/{api_id}/calls/order")
async def order_calls(api_id: int, data: OrderIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    a = await _conn(db, api_id)
    pos = {cid: i for i, cid in enumerate(data.ids)}
    for c in a.calls:
        c.position = pos.get(c.id, len(pos) + c.position)
    _touch(a)
    await db.commit()
    return {"ok": True}


@router.post("/{api_id}/try")
async def try_call(api_id: int, data: TryIn, sess: Session = Depends(current_session), user: User = Depends(current_user),
                   db: AsyncSession = Depends(get_db)):
    """Een (nog niet bewaarde) call uitproberen: het antwoord, en wat de velden en de tabel ervan maken."""
    a = await _conn(db, api_id)
    call = data.call
    if call.method != "GET":
        await recent_auth(sess, user)
    tile = {}
    if data.service_id:
        s = await db.get(Service, data.service_id)
        tile = (s.config or {}) if s else {}
    elif tiles := (await db.execute(select(Service).where(Service.api_id == a.id).limit(1))).scalars().all():
        tile = tiles[0].config or {}  # de variabelen van de eerste tegel die deze API gebruikt (bv. {node})
    await db.close()
    d = call.values()
    started = time.monotonic()
    try:
        integ = from_api(a, tile, integrations_router.clients)
        result = await callmod.run(integ, d)
    except IntegrationError as e:
        return {"ok": False, "error": str(e), "ms": round((time.monotonic() - started) * 1000)}
    ms = round((time.monotonic() - started) * 1000)
    preview = _trim(result)
    text = json.dumps(preview, ensure_ascii=False, default=str)
    if len(text) > MAX_PREVIEW:
        preview = text[:MAX_PREVIEW] + "…"
    return {"ok": True, "ms": ms, "data": preview, "fields": callmod.fields_of(result, d),
            "table": callmod.table_of(result, d)}


# --- veel tegels tegelijk ------------------------------------------------------------------

@router.post("/bulk")
async def bulk(data: BulkIn, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Per tegel een API uit een sjabloon maken (adres = dat van de tegel) en de tegel eraan koppelen."""
    made = []
    for it in data.items:
        if it.template not in tpl.TEMPLATES:
            raise HTTPException(422, f"Onbekend sjabloon: {it.template}")
        s = await db.get(Service, it.service_id)
        url = (it.url or (s.url if s else "") or "").strip()
        if s is None or not url.lower().startswith(("http://", "https://")):
            continue
        a = _new_conn(it.template, s.name, url, it.secrets)
        db.add(a)
        await db.flush()
        _link(s, a)
        made.append(s.name)
    if made:
        await audit(db, request, user, "api_bulk", count=len(made), tiles=made[:50])
        await record_revision(db, user, f"API voor {len(made)} tegels ingesteld")
    await db.commit()
    return {"created": len(made)}


@router.post("/adopt")
async def adopt(data: AdoptIn, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Tegels met hun eigen sleutels naar API-beheer verhuizen. Tegels met hetzelfde adres en dezelfde sleutels
    (bv. vier node-tegels op één Proxmox-cluster) delen daarna één API."""
    tiles = (await db.execute(select(Service).where(Service.id.in_(data.service_ids), Service.api_id.is_(None))
                              .order_by(Service.id))).scalars().all()
    by_key: dict[tuple, ApiConnection] = {}
    moved = 0
    for s in tiles:
        if s.type not in REGISTRY:
            continue
        cfg = s.config or {}
        url = str(cfg.get("url") or s.url or "").strip()
        if not url.lower().startswith(("http://", "https://")):
            continue
        secrets = decrypt_json(s.secrets)
        api_cfg = {k: v for k, v in cfg.items() if k in API_ONLY and k != "url"}
        key = (s.type, url, json.dumps(secrets, sort_keys=True), json.dumps(api_cfg, sort_keys=True))
        a = by_key.get(key)
        if a is None:
            t = next((k for k, t in tpl.TEMPLATES.items() if t.get("kind", "rest") == s.type), None)
            a = ApiConnection(name=s.name, category=tpl.TEMPLATES[t]["category"] if t else "Overig", kind=s.type,
                              template=t, url=url[:500], config=api_cfg, secrets=encrypt_json(secrets) if secrets else None)
            db.add(a)
            await db.flush()
            by_key[key] = a
        elif a.name != REGISTRY[s.type].label:
            a.name = REGISTRY[s.type].label  # gedeeld: de naam van de soort zegt meer dan die van één tegel
        s.api_id, s.secrets = a.id, None
        s.config = {k: v for k, v in cfg.items() if k not in API_ONLY}
        moved += 1
    if moved:
        await audit(db, request, user, "api_adopt", tiles=moved, apis=len(by_key))
        await record_revision(db, user, f"{moved} tegels naar API-beheer verhuisd")
    await db.commit()
    return {"moved": moved, "apis": len(by_key)}
