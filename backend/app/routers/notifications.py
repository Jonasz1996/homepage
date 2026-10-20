from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import current_user
from ..models import Notification, PushQueue, User

router = APIRouter(prefix="/api/notifications", tags=["notifications"])


@router.get("")
async def list_notifications(limit: int = 50, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(
        select(Notification).order_by(Notification.id.desc()).limit(min(max(limit, 1), 200))
    )).scalars().all()
    unread = (await db.execute(
        select(func.count()).select_from(Notification).where(Notification.read_at.is_(None))
    )).scalar_one()
    return {
        "unread": unread,
        "items": [
            {"id": n.id, "ts": n.ts, "level": n.level, "title": n.title, "body": n.body,
             "source": n.source, "service_id": n.service_id, "read": n.read_at is not None}
            for n in rows
        ],
    }


@router.post("/read-all")
async def read_all(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await db.execute(update(Notification).where(Notification.read_at.is_(None))
                     .values(read_at=datetime.now(timezone.utc)))
    await db.commit()
    return {"ok": True}


@router.post("/{notification_id}/read")
async def read_one(notification_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await db.execute(update(Notification).where(Notification.id == notification_id)
                     .values(read_at=datetime.now(timezone.utc)))
    await db.commit()
    return {"ok": True}


@router.delete("")
async def clear_read(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Gelezen meldingen wissen, behalve wat nog naar je gsm moet: anders kan wie inlogt "Login vanaf nieuw IP" wissen
    voor de worker het verstuurt (elke 5 s), en krijg jij het nooit te zien. Die blijven staan tot ze verstuurd zijn."""
    read = Notification.read_at.is_not(None)
    waiting = or_(Notification.pushed_at.is_(None), Notification.id.in_(
        select(PushQueue.notification_id).where(PushQueue.notification_id.is_not(None))))
    kept = (await db.execute(select(func.count()).select_from(Notification).where(read, waiting))).scalar_one()
    await db.execute(delete(Notification).where(read, ~waiting))
    await db.commit()
    return {"ok": True, "kept": kept}


# Voor een tik op een pushbericht: /?open=melding&n=<id> opent dezelfde plek als in het meldingencentrum.
@router.get("/{notification_id}")
async def get_notification(notification_id: int, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    n = await db.get(Notification, notification_id)
    if n is None:
        raise HTTPException(404, "Melding niet gevonden (al gewist?)")
    return {"id": n.id, "ts": n.ts, "level": n.level, "title": n.title, "body": n.body,
            "source": n.source, "service_id": n.service_id, "read": n.read_at is not None}
