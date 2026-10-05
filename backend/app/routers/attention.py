"""Aandacht: alles wat nu mis is (knop ! en de strook bovenaan) en de instellingen-checklist."""

import asyncio
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import attention, setupcheck
from ..db import ensure_state, get_db
from ..deps import current_user
from ..integrations import REGISTRY
from ..models import Service, User
from . import integrations as integ

router = APIRouter(prefix="/api/attention", tags=["aandacht"])
SETUP_TIMEOUT = 12


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    data = await attention.collect(db, integ.last_errors())
    stale = data.pop("stale")
    if stale:
        # Wat genegeerd was en intussen opgelost is: vergeten, zodat het terugkomt als het opnieuw misgaat.
        st = await ensure_state(db, attention.ACK_KEY, {})
        st.value = {**st.value, "items": {k: v for k, v in (st.value.get("items") or {}).items() if k not in stale}}
        await db.commit()
    return data


class IgnoreIn(BaseModel):
    key: str = Field(min_length=1, max_length=200)
    sig: str | None = Field(default=None, max_length=40)  # leeg = niet langer negeren


@router.put("/ignore")
async def ignore(body: IgnoreIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await ensure_state(db, attention.ACK_KEY, {})
    items = dict(st.value.get("items") or {})
    if body.sig:
        items[body.key] = {"sig": body.sig, "at": datetime.now(timezone.utc).isoformat(), "by": user.username}
    else:
        items.pop(body.key, None)
    st.value = {**st.value, "items": items}
    await db.commit()
    return await overview(user, db)


async def _widgets(svcs: list[Service]) -> dict[int, dict]:
    """Of de API van elke tegel antwoordt (uit de cache van de tegels, anders nu gevraagd, met een tijdslimiet)."""
    if not svcs:
        return {}
    sem = asyncio.Semaphore(10)

    async def one(s: Service):
        async with sem:
            return s.id, await integ._cached(s, "summary", integ.SUMMARY_TTL, integ._fields)

    tasks = [asyncio.create_task(one(s)) for s in svcs]
    done, pending = await asyncio.wait(tasks, timeout=SETUP_TIMEOUT)
    for t in pending:
        t.cancel()
    out = dict(t.result() for t in done if not t.cancelled() and t.exception() is None)
    errors = integ.last_errors()
    for s in svcs:
        if s.id not in out and s.id in errors:
            out[s.id] = {"error": errors[s.id]}
    return out


@router.get("/setup")
async def setup(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    svcs = list((await db.execute(select(Service).where(Service.type.in_(list(REGISTRY))))).scalars())
    await db.close()  # geen verbinding vasthouden terwijl de API's antwoorden
    results = await _widgets(svcs)
    return await setupcheck.run(db, integ.clients, results)
