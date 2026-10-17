"""Updates installeren (met snapshot vooraf), meekijken, terugdraaien, en de nachtelijke beveiligingsupdates."""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..db import get_db
from ..deps import audit, current_user, recent_auth
from ..models import AppState, UpdateRun, User
from ..monitoring import upgrade
from ..monitoring.updates import KEY as UPDATES_KEY, run_updates
from .integrations import clients

router = APIRouter(prefix="/api/updates", tags=["upgrade"])
log = logging.getLogger("homepage.api")

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
                        log.error("updates installeren mislukt", exc_info=t.exception()))


def run_out(r: UpdateRun, output: bool = False) -> dict:
    out = {"id": r.id, "target": r.target, "name": r.target_name, "trigger": r.trigger, "status": r.status,
           "security_only": r.security_only, "snapshot": r.snapshot, "exit_code": r.exit_code,
           "reboot_needed": r.reboot_needed, "checks": r.checks, "error": r.error, "created_at": r.created_at,
           "started_at": r.started_at, "finished_at": r.finished_at, "rolled_back_at": r.rolled_back_at,
           # Niet bij een run die niets installeerde (apt-get update mislukte): terug zou alleen weggooien wat de
           # machine sinds de snapshot schreef.
           "can_rollback": (upgrade.needs_snapshot(r.snapshot)
                            and r.status in ("ok", "fout", "services_down", "terugdraaien_mislukt"))}
    if output:
        out["output"] = r.output or ""
    return out


@router.get("/plans")
async def plans(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Per machine uit het overzicht: kan installeren, en kan er een snapshot vooraf?"""
    st = await db.get(AppState, UPDATES_KEY)
    plans_ = [await upgrade.plan_for(db, t["key"], t["name"]) for t in (st.value.get("targets", []) if st else [])]
    await upgrade.mark_self(db, plans_)
    return {p.key: upgrade.plan_out(p) for p in plans_}


@router.get("/runs")
async def runs(limit: int = 30, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(UpdateRun).order_by(UpdateRun.id.desc()).limit(min(max(limit, 1), 200)))).scalars()
    return [run_out(r) for r in rows]


@router.get("/runs/{run_id}")
async def get_run(run_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    r = await db.get(UpdateRun, run_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    return run_out(r, output=True)


class InstallIn(BaseModel):
    targets: list[str] = Field(min_length=1, max_length=100)
    security_only: bool = False
    snapshot: bool = True


async def _targets(db: AsyncSession, targets: list[str]) -> tuple[list[tuple[str, str | None]], list[dict]]:
    """(sleutel, naam) van wat mag, en wat geweigerd is. Alleen machines uit de laatste scan. Uitzondering: een eigen
    SSH-host (ssh:<id>…), die plan_for zelf opzoekt; na een installatie verdwijnt hij uit de scan maar opnieuw
    installeren mag."""
    st = await db.get(AppState, UPDATES_KEY)
    names = {t["key"]: t["name"] for t in (st.value.get("targets", []) if st else [])}
    wanted = list(dict.fromkeys(targets))
    known = [k for k in wanted if k in names or k.startswith("ssh:")]
    return ([(k, names.get(k)) for k in known],
            [{"key": k[:200], "name": None, "why": "Staat niet in de laatste updatescan"} for k in wanted if k not in known])


@router.post("/install", status_code=status.HTTP_202_ACCEPTED, dependencies=[outside.guard("updates")])
async def install(body: InstallIn, request: Request, user: User = Depends(recent_auth),
                  db: AsyncSession = Depends(get_db)):
    keys, unknown = await _targets(db, body.targets)
    # Het dashboard zelf alleen als het de enige gekozen machine is (zie upgrade.mark_self).
    runs, refused = await upgrade.create_runs(db, keys, body.security_only, body.snapshot, "manueel", user.id,
                                              alone=len(dict.fromkeys(body.targets)) == 1)
    refused += unknown
    if runs:
        await audit(db, request, user, "updates_install", targets=[r.target_name for r in runs],
                    security_only=body.security_only, snapshot=body.snapshot)
    await db.commit()
    if runs:
        maker = _maker(request)

        async def go():
            await upgrade.run_batch(maker, clients, [r.id for r in runs])
            async with maker() as db2:
                await run_updates(db2, clients)
                await db2.commit()
        _spawn(go())
    return {"runs": [run_out(r) for r in runs], "refused": refused}


# Proef: dezelfde keuze als installeren, maar alleen tonen wat er zou gebeuren. Geen SSH, geen runs, geen audit;
# daarom gewoon ingelogd volstaat (geen herbevestiging, ook van buitenaf).
@router.post("/install/proef")
async def install_proef(body: InstallIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    keys, unknown = await _targets(db, body.targets)
    return await upgrade.describe_batch(db, clients, keys, security_only=body.security_only, snapshot=body.snapshot,
                                        trigger="manueel", refused=unknown, alone=len(dict.fromkeys(body.targets)) == 1)


async def _rollback_run(db: AsyncSession, run_id: int) -> UpdateRun:
    r = await db.get(UpdateRun, run_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    if not run_out(r)["can_rollback"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "Terugdraaien kan niet (meer) voor deze run")
    return r


@router.post("/runs/{run_id}/rollback", status_code=status.HTTP_202_ACCEPTED, dependencies=[outside.guard("updates")])
async def rollback(run_id: int, request: Request, user: User = Depends(recent_auth),
                   db: AsyncSession = Depends(get_db)):
    r = await _rollback_run(db, run_id)
    r.status = "terugdraaien"
    await audit(db, request, user, "updates_rollback", target=r.target_name, snapshot=r.snapshot.get("name"))
    await db.commit()
    _spawn(upgrade.rollback(_maker(request), run_id, clients))
    return {"ok": True}


@router.post("/runs/{run_id}/rollback/proef")
async def rollback_proef(run_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await upgrade.describe_rollback(db, clients, await _rollback_run(db, run_id))


@router.get("/auto/proef")
async def auto_proef(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Wat de nachtelijke run vannacht zou doen, los van het uur."""
    return await upgrade.describe_auto(db, clients)


@router.get("/cleanup/proef")
async def cleanup_proef(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Welke eigen snapshots het volgende opruimen zou verwijderen."""
    return await upgrade.describe_cleanup(db, clients)


class SettingsIn(BaseModel):
    auto: bool = False
    hour: int = Field(default=4, ge=0, le=23)
    keep_days: int = Field(default=7, ge=1, le=90)
    # Alleen noteren wat de nachtelijke updates en het opruimen van snapshots zouden doen.
    proef: bool = False
    cleanup_proef: bool = False


@router.get("/settings")
async def get_settings_(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """De instellingen, met het laatste plan van de nachtelijke run en van het opruimen als die als proef liepen."""
    last = {}
    for k, key in (("auto", upgrade.AUTO_PROEF_KEY), ("cleanup", upgrade.CLEANUP_PROEF_KEY)):
        st = await db.get(AppState, key)
        last[k] = st.value if st else None
    return {**await upgrade.settings(db), "last_proef": last}


@router.put("/settings", dependencies=[outside.guard("updates")])
async def put_settings(body: SettingsIn, request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, upgrade.SETTINGS_KEY)
    value = body.model_dump()
    if st:
        st.value = value
    else:
        db.add(AppState(key=upgrade.SETTINGS_KEY, value=value))
    await audit(db, request, user, "updates_settings", **value)
    await db.commit()
    return value
