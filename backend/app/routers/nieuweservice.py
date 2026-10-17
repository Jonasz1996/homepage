"""Nieuwe service in één keer, en een service opruimen (het werk zelf staat in nieuweservice.py).

Elke actie heeft een proef (gewoon ingelogd) en een echte run (verse 2FA, de hash van de proef). De run loopt in de
achtergrond; de browser vraagt de stand op met GET /runs/{id}. Echte runs pas als "echt uitvoeren" aan staat (PUT
/echt, aanzetten vraagt een verse 2FA); tot dan werkt alleen de proef.
"""

import asyncio
import logging
import time
from contextlib import asynccontextmanager
from ipaddress import IPv4Address
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import nieuweservice as ns
from .. import outside
from ..db import get_db
from ..deps import audit, current_session, current_user, recent_auth
from ..integrations.proxmox import JOB_RE
from ..models import AppState, Service, Session, User
from . import integrations as integrations_router
from .layout import _guard_removal

router = APIRouter(prefix="/api/nieuweservice", tags=["nieuweservice"])
log = logging.getLogger("homepage.api")

HASH = r"^[0-9a-f]{16}$"

_tasks: set[asyncio.Task] = set()


def _maker(request: Request):
    factory = request.app.dependency_overrides.get(get_db, get_db)

    @asynccontextmanager
    async def maker():
        gen = factory()
        db = await anext(gen)
        try:
            yield db
        finally:
            await gen.aclose()
    return maker


def _spawn(coro) -> None:
    t = asyncio.create_task(coro)
    _tasks.add(t)
    t.add_done_callback(_tasks.discard)
    t.add_done_callback(lambda t: t.cancelled() or not t.exception() or
                        log.error("nieuwe service: run mislukt", exc_info=t.exception()))


# --- invoer --------------------------------------------------------------------------------------------------------

class TileIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    group_id: int
    label: str = Field(min_length=1, max_length=80)
    check: bool = True

    @field_validator("label")
    @classmethod
    def _label(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Geef de tegel een naam")
        return v.strip()


class NieuwIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=ns.LABEL_RE.pattern, max_length=63)
    ip: IPv4Address
    port: int = Field(ge=1, le=65535)
    scheme: Literal["http", "https"] = "http"
    exposure: Literal["publiek", "lan"] = "publiek"
    cert: Literal["auto", "letsencrypt", "geen"] = "auto"
    access_list_id: int | None = Field(default=None, ge=1)
    poort_443_dicht: bool = False
    bescherming_van: int | None = Field(default=None, ge=1)
    websockets: bool = True
    tile: TileIn | None = None
    zabbix: str | None = Field(default=None, max_length=120)
    backup: bool = True
    backup_job: str | None = Field(default=None, pattern=JOB_RE.pattern)

    @field_validator("ip")
    @classmethod
    def _ip(cls, v: IPv4Address) -> IPv4Address:
        if not v.is_private or v.is_loopback or v.is_link_local or v.is_unspecified or v.is_multicast:
            raise ValueError("Alleen een IP-adres op je eigen netwerk (bv. 192.168.0.27)")
        return v


class NieuwRun(NieuwIn):
    plan_hash: str = Field(pattern=HASH)


class OpruimIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    service_id: int | None = None
    fqdn: str | None = Field(default=None, max_length=253)
    backup: bool = False


class OpruimRun(OpruimIn):
    plan_hash: str = Field(pattern=HASH)


class HashIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plan_hash: str = Field(pattern=HASH)


class EchtIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    on: bool


# --- hulpjes -------------------------------------------------------------------------------------------------------

async def _runs(db: AsyncSession) -> list[dict]:
    st = await db.get(AppState, ns.STATE_KEY)
    return ns.runs_of(st.value if st else None)


async def _run(db: AsyncSession, run_id: str) -> dict:
    run = next((r for r in await _runs(db) if r.get("id") == run_id), None)
    if run is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Run niet gevonden")
    return ns.effective(run)


async def _real_on(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)) -> None:
    """Een echte run kan pas als "echt uitvoeren" aan staat. Vóór de 2FA-vraag: aanzetten gaat apart."""
    if not (await ns.real(db))["on"]:
        raise HTTPException(status.HTTP_409_CONFLICT, ns.REAL_OFF)


REAL = Depends(_real_on)


def _accept(plan: ns.Plan, plan_hash: str, empty: str) -> None:
    """Alleen het plan dat de proef toonde. Veranderde er intussen iets, dan eerst een nieuwe proef."""
    if plan.hash != plan_hash:
        raise HTTPException(status.HTTP_409_CONFLICT, "plan_veranderd")
    if plan.plan.get("waarom"):
        raise HTTPException(422, f"Kan niet: {plan.plan['waarom'][0]}")
    if not plan.ops or not plan.plan.get("kan"):
        raise HTTPException(422, empty)


async def _guard_tiles(db: AsyncSession, request: Request, sess: Session, user: User, ids: list[int]) -> None:
    """Een tegel met een lopende check weghalen legt de bewaking stil: auditlog en een melding (zoals in de layout)."""
    if ids:
        svcs = list((await db.execute(select(Service).where(Service.id.in_(ids)))).scalars())
        await _guard_removal(db, request, sess, user, svcs)


async def _launch(db: AsyncSession, request: Request, user: User, kind: str, plan: ns.Plan, data: dict,
                  of: str | None = None) -> dict:
    """Eén run tegelijk: nakijken en starten onder het slot, dan de stappen in de achtergrond."""
    async with ns._lock:
        st = await db.get(AppState, ns.STATE_KEY)
        if ns.busy(st.value if st else None):
            raise HTTPException(status.HTTP_409_CONFLICT, "bezig")
        await audit(db, request, user, f"nieuwe_service_{kind}", fqdn=plan.plan.get("fqdn"),
                    steps=[o.key for o in plan.ops], plan_hash=plan.hash, input=data)
        run = await ns.start(db, kind, plan, data, user, of=of)
        try:
            await db.commit()
        except Exception:
            ns._running.discard(run["id"])
            raise
    user_id = user.id
    # De verbinding teruggeven: de run werkt met eigen korte sessies (op SQLite in de tests delen ze er één).
    await db.close()
    _spawn(ns.execute(_maker(request), run["id"], plan.ops, integrations_router.clients, user_id))
    return {"run": ns.run_out(run)}


async def _proef_audit(db: AsyncSession, request: Request, user: User, kind: str, plan: ns.Plan, data: dict) -> dict:
    # De proef kijkt alleen, maar probeert wel een poort die je intikte: daarom staat ze in het auditlog.
    await audit(db, request, user, "nieuwe_service_proef", soort=kind, fqdn=plan.plan.get("fqdn"),
                steps=[o.key for o in plan.ops], plan_hash=plan.hash, input=data)
    await db.commit()
    return {"plan": plan.plan}


def _cleanup_plan(db: AsyncSession, body: OpruimIn, who: str):
    if body.service_id is None and not (body.fqdn or "").strip():
        raise HTTPException(422, "Kies een tegel of geef een naam")

    async def go() -> ns.Plan:
        try:
            return await ns.plan_cleanup(db, integrations_router.clients, body, who=who)
        except ns.Refused as e:
            raise HTTPException(422, str(e)) from None
    return go()


# --- lezen ---------------------------------------------------------------------------------------------------------

@router.get("/domein")
async def domein(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Het domein, zonder een call naar buiten (voor de knop "opruimen…" bij een tegel)."""
    return {"domain": await ns.zone_light(db)}


@router.get("/opties")
async def opties(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, ns.STATE_KEY)
    running = ns.busy(st.value if st else None)
    key = await ns.options_key(db)
    hit = ns._options
    if hit.get("key") == key and time.monotonic() - hit.get("at", 0) < ns.OPTIONS_TTL:
        value = hit["value"]
    else:
        value = await ns.options(db, integrations_router.clients)
        ns._options.clear()
        ns._options.update(key=key, at=time.monotonic(), value=value)
    return {**value, "busy": ns.run_out(running) if running else None}


@router.get("/runs")
async def runs(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    value = {"runs": await _runs(db)}
    running = ns.busy(value)
    return {"runs": [ns.run_out(r, calls=False) for r in value["runs"]], "busy": running["id"] if running else None}


@router.get("/runs/{run_id}")
async def get_run(run_id: str, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return ns.run_out(await _run(db, run_id))


@router.get("/echt")
async def echt(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await ns.real(db)


@router.put("/echt", dependencies=[outside.guard("acties")])
async def put_echt(body: EchtIn, request: Request, sess: Session = Depends(current_session),
                   user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Echt uitvoeren aan (verse 2FA, zoals een run zelf) of uit (altijd, zonder 2FA). Van buitenaf allebei uit, zoals
    de runs. In het auditlog."""
    was = (await ns.real(db))["on"]
    if body.on and not was:
        await recent_auth(sess, user)
    if body.on == was:
        return await ns.real(db)
    out = await ns.set_real(db, body.on, user)
    await audit(db, request, user, "nieuwe_service_echt", on=body.on)
    await db.commit()
    return out


@router.get("/losse-dns")
async def losse_dns(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Records die dit dashboard maakte en waarvan NPM de naam niet meer kent (als het tabblad opruimen opengaat)."""
    return await ns.orphans(db, integrations_router.clients)


# --- maken ---------------------------------------------------------------------------------------------------------

@router.post("/proef", dependencies=[outside.guard("acties")])
async def proef(body: NieuwIn, request: Request, user: User = Depends(current_user),
                db: AsyncSession = Depends(get_db)):
    plan = await ns.plan_create(db, integrations_router.clients, body, who=user.username)
    return await _proef_audit(db, request, user, "maken", plan, body.model_dump(mode="json"))


@router.post("/maken", status_code=status.HTTP_202_ACCEPTED, dependencies=[outside.guard("acties"), REAL])
async def maken(body: NieuwRun, request: Request, user: User = Depends(recent_auth),
                db: AsyncSession = Depends(get_db)):
    plan = await ns.plan_create(db, integrations_router.clients, body, at_run=True, who=user.username)
    _accept(plan, body.plan_hash, "Er zou niets gebeuren")
    return await _launch(db, request, user, "maken", plan, body.model_dump(mode="json", exclude={"plan_hash"}))


# --- opruimen ------------------------------------------------------------------------------------------------------

@router.post("/opruimen/proef", dependencies=[outside.guard("acties")])
async def opruimen_proef(body: OpruimIn, request: Request, user: User = Depends(current_user),
                         db: AsyncSession = Depends(get_db)):
    plan = await _cleanup_plan(db, body, user.username)
    return await _proef_audit(db, request, user, "opruimen", plan, body.model_dump(mode="json"))


@router.post("/opruimen", status_code=status.HTTP_202_ACCEPTED, dependencies=[outside.guard("acties"), REAL])
async def opruimen(body: OpruimRun, request: Request, sess: Session = Depends(current_session),
                   user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    plan = await _cleanup_plan(db, body, user.username)
    _accept(plan, body.plan_hash, "Niets op te ruimen")
    await _guard_tiles(db, request, sess, user, plan.services)
    return await _launch(db, request, user, "opruimen", plan, body.model_dump(mode="json", exclude={"plan_hash"}))


# --- ongedaan maken ------------------------------------------------------------------------------------------------

async def _undo_plan(db: AsyncSession, request: Request, run_id: str, who: str) -> tuple[dict, ns.Plan]:
    run = await _run(db, run_id)
    if not run["can_undo"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "Ongedaan maken kan niet (meer) voor deze run")
    return run, await ns.plan_undo(db, integrations_router.clients, run, who=who, maker=_maker(request))


@router.post("/runs/{run_id}/ongedaan/proef", dependencies=[outside.guard("acties")])
async def ongedaan_proef(run_id: str, request: Request, user: User = Depends(current_user),
                         db: AsyncSession = Depends(get_db)):
    run, plan = await _undo_plan(db, request, run_id, user.username)
    return await _proef_audit(db, request, user, "ongedaan", plan, {"run": run["id"]})


@router.post("/runs/{run_id}/ongedaan", status_code=status.HTTP_202_ACCEPTED,
             dependencies=[outside.guard("acties"), REAL])
async def ongedaan(run_id: str, body: HashIn, request: Request, sess: Session = Depends(current_session),
                   user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    run, plan = await _undo_plan(db, request, run_id, user.username)
    _accept(plan, body.plan_hash, "Niets ongedaan te maken")
    await _guard_tiles(db, request, sess, user, plan.services)
    return await _launch(db, request, user, "ongedaan", plan, {"run": run["id"]}, of=run["id"])
