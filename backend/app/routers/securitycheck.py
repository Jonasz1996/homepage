"""Veiligheidscheck (hw → beveiliging)."""

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state, get_db
from ..deps import audit, current_user, recent_auth
from ..health import security
from ..models import User
from . import integrations as integrations_router

router = APIRouter(prefix="/api/security", tags=["beveiliging"])


@router.get("/check")
async def check(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await security.run(db, integrations_router.clients)


@router.post("/secret-key-saved")
async def secret_key_saved(request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """Jonas bevestigt dat hij /etc/homepage/secret.key zelf ergens veilig bewaard heeft."""
    st = await ensure_state(db, security.SECRET_SAVED, {})
    st.value = {"at": datetime.now(timezone.utc).isoformat(), "by": user.username}
    await audit(db, request, user, "secret_key_saved")
    await db.commit()
    return {"ok": True}
