"""Welke versie er draait (uit /etc/homepage/versie, geschreven door install.sh) en welke nieuwigheden de
gebruiker al gezien heeft: na een update toont het dashboard één keer wat er nieuw is."""

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import ensure_state, get_db
from ..deps import current_user
from ..models import AppState, User

router = APIRouter(prefix="/api/version", tags=["versie"])

STATE_KEY = "changelog_seen"


def installed() -> dict:
    out = {"versie": "dev", "commit": None, "kanaal": None, "datum": None}
    try:
        text = get_settings().version_file.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        k, _, v = line.partition("=")
        if k in out and v.strip():
            out[k] = v.strip()[:80]
    return out


@router.get("")
async def version(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, STATE_KEY)
    seen = (st.value or {}).get(str(user.id)) if st else None
    created = user.created_at if user.created_at.tzinfo else user.created_at.replace(tzinfo=timezone.utc)
    # Een nieuw account hoeft de geschiedenis niet te zien.
    return {**installed(), "gezien": seen, "nieuw_account": datetime.now(timezone.utc) - created < timedelta(days=1)}


class SeenIn(BaseModel):
    id: str = Field(min_length=1, max_length=80)


@router.post("/seen")
async def seen(body: SeenIn, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await ensure_state(db, STATE_KEY, {})
    st.value = {**(st.value or {}), str(user.id): body.id}
    await db.commit()
    return {"ok": True}
