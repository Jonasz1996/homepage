"""Updates installeren (met snapshot vooraf), meekijken, terugdraaien, en de nachtelijke beveiligingsupdates."""

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

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
           "can_rollback": bool(r.snapshot and r.snapshot.get("name") and not r.snapshot.get("removed_at")
                                and r.status in ("ok", "fout", "services_down", "terugdraaien_mislukt"))}
    if output:
        out["output"] = r.output or ""
    return out


@router.get("/plans")
async def plans(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Per machine uit het overzicht: kan installeren, en kan er een snapshot vooraf?"""
    st = await db.get(AppState, UPDATES_KEY)
    out = {}
    for t in (st.value.get("targets", []) if st else []):
        out[t["key"]] = upgrade.plan_out(await upgrade.plan_for(db, t["key"], t["name"]))
    return out


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


@router.post("/install", status_code=status.HTTP_202_ACCEPTED)
async def install(body: InstallIn, request: Request, user: User = Depends(recent_auth),
                  db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, UPDATES_KEY)
    names = {t["key"]: t["name"] for t in (st.value.get("targets", []) if st else [])}
    # Alleen machines uit de laatste scan. Uitzondering: een eigen SSH-host (ssh:<id>…), die plan_for
    # zelf opzoekt; na een installatie verdwijnt hij uit de scan maar opnieuw installeren mag.
    wanted = list(dict.fromkeys(body.targets))
    known = [k for k in wanted if k in names or k.startswith("ssh:")]
    runs, refused = await upgrade.create_runs(db, [(k, names.get(k)) for k in known], body.security_only,
                                              body.snapshot, "manueel", user.id)
    refused += [{"key": k[:200], "name": None, "why": "Staat niet in de laatste updatescan"}
                for k in wanted if k not in known]
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


@router.post("/runs/{run_id}/rollback", status_code=status.HTTP_202_ACCEPTED)
async def rollback(run_id: int, request: Request, user: User = Depends(recent_auth),
                   db: AsyncSession = Depends(get_db)):
    r = await db.get(UpdateRun, run_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Niet gevonden")
    if not run_out(r)["can_rollback"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "Terugdraaien kan niet (meer) voor deze run")
    r.status = "terugdraaien"
    await audit(db, request, user, "updates_rollback", target=r.target_name, snapshot=r.snapshot.get("name"))
    await db.commit()
    _spawn(upgrade.rollback(_maker(request), run_id, clients))
    return {"ok": True}


class SettingsIn(BaseModel):
    auto: bool = False
    hour: int = Field(default=4, ge=0, le=23)
    keep_days: int = Field(default=7, ge=1, le=90)


@router.get("/settings")
async def get_settings_(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await upgrade.settings(db)


@router.put("/settings")
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
