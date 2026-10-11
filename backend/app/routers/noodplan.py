"""Noodplan: de stand, het document (HTML of Markdown), nu bijwerken en de proef daarvan. Zie monitoring/noodplan.py.

Het document is een kaart van namen, IP's, MAC's en waar de sleutels staan: zoals de diagnose vraagt het een recente
2FA, komt het in het auditlog en staat het van buitenaf uit (downloads). Nu bijwerken leest alleen (de leestokens van
de tegels) en schrijft alleen naar de eigen map van de kopie buiten de container: geen 2FA, wel in het auditlog.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..config import get_settings
from ..db import get_db
from ..deps import audit, current_user, recent_auth
from ..health import scan as hw
from ..models import AppState, User
from ..monitoring import noodplan
from .integrations import clients
from .upgrade import _maker

log = logging.getLogger("homepage.noodplan")

router = APIRouter(prefix="/api/noodplan", tags=["noodplan"])
_task: asyncio.Task | None = None
MEDIA = {"html": "text/html; charset=utf-8", "md": "text/markdown; charset=utf-8"}


def _running(value: dict | None, now: datetime) -> bool:
    """Loopt er een noodplan: de knop hier, of de worker (die zet een marker in de database)."""
    return bool(_task and not _task.done()) or noodplan.is_busy(value, now)


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Datums, bronnen, fouten en aantallen: nooit het document of de gegevens zelf."""
    st = await db.get(AppState, noodplan.STATE_KEY)
    value = st.value if st else None
    now = datetime.now(timezone.utc)
    return noodplan.status(value, _running(value, now), now, bool((await hw.settings(db)).get("offsite")),
                           str(get_settings().offsite_dir))


@router.get("/document", dependencies=[outside.guard("downloads")])
async def document(request: Request, formaat: Literal["html", "md"] = "html", user: User = Depends(recent_auth),
                   db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, noodplan.STATE_KEY)
    if not st or not (st.value or {}).get("at"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Nog geen noodplan")
    value = st.value
    text, masked, kinds = await noodplan.render(db, value, formaat)
    await audit(db, request, user, "noodplan_view", formaat=formaat, at=value["at"], masked=masked, kinds=kinds)
    await db.commit()
    name = f"noodplan-{datetime.fromisoformat(value['at']).astimezone():%Y-%m-%d}.{formaat}"
    # Altijd als bijlage: de URL rechtstreeks openen toont geen HTML-pagina op het adres van het dashboard.
    return Response(text, media_type=MEDIA[formaat],
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store"})


async def _run(maker, user: str) -> None:
    try:
        await noodplan.run(maker, clients, trigger="knop", user=user)
    except Exception:
        log.exception("noodplan: nu bijwerken mislukt")


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
async def run_now(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    global _task
    st = await db.get(AppState, noodplan.STATE_KEY)
    if _running(st.value if st else None, datetime.now(timezone.utc)):
        raise HTTPException(status.HTTP_409_CONFLICT, "Loopt al")
    await audit(db, request, user, "noodplan_run")
    await db.commit()
    _task = asyncio.create_task(_run(_maker(request), user.username))
    return {"ok": True}


@router.post("/proef")
async def proef_run(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Wat nu bijwerken zou doen, zonder het te doen: geen verzoek naar buiten, geen DNS, niets bewaard."""
    return await noodplan.proef_plan(db, clients)
