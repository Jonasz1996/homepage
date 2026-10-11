"""Zelfherstel-regels per service."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..db import get_db
from ..deps import audit, current_user, recent_auth
from ..integrations import IntegrationError
from ..models import HealRule, Service, User
from ..monitoring import healing
from ..ssh_exec import SshFail
from .integrations import clients

router = APIRouter(prefix="/api/heal", tags=["heal"])


def rule_out(r: HealRule, names: dict[int, str]) -> dict:
    # max_per_hour: de limiet die echt geldt. Een oudere regel op 6 komt zo als 5 terug, en aan/uit zetten (dat de
    # regel terugstuurt) lukt dan nog.
    return {"id": r.id, "service_id": r.service_id, "service": names.get(r.service_id), "enabled": r.enabled,
            "after": r.after, "max_per_hour": healing.per_hour(r), "action": r.action,
            "describe": healing.describe(r.action), "fired": r.fired or [], "last_at": r.last_at,
            "last_result": r.last_result, "dry_run": r.dry_run}


async def _names(db: AsyncSession) -> dict[int, str]:
    return {s.id: s.name for s in (await db.execute(select(Service))).scalars()}


@router.get("")
async def rules(service_id: int | None = None, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    stmt = select(HealRule).order_by(HealRule.id)
    if service_id:
        stmt = stmt.where(HealRule.service_id == service_id)
    names = await _names(db)
    return [rule_out(r, names) for r in (await db.execute(stmt)).scalars()]


class RuleIn(BaseModel):
    service_id: int
    enabled: bool = True
    after: int = Field(default=3, ge=1, le=60)
    max_per_hour: int = Field(default=2, ge=1, le=healing.MAX_PER_HOUR)
    action: dict
    # Alleen proef. None: bij een wijziging blijft het zoals het was (aan/uit zetten stuurt het niet altijd mee).
    dry_run: bool | None = None


async def _clean(db: AsyncSession, body: RuleIn) -> dict:
    if await db.get(Service, body.service_id) is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service niet gevonden")
    try:
        return await healing.validate(db, body.action)
    except (ValueError, TypeError) as e:
        raise HTTPException(422, str(e)) from e


@router.post("", status_code=status.HTTP_201_CREATED, dependencies=[outside.guard("acties")])
async def create(body: RuleIn, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    action = await _clean(db, body)
    r = HealRule(service_id=body.service_id, enabled=body.enabled, after=body.after, max_per_hour=body.max_per_hour,
                 action=action, fired=[], dry_run=bool(body.dry_run))
    db.add(r)
    await db.flush()
    await audit(db, request, user, "heal_rule_added", rule=r.id, what=healing.describe(action), dry_run=r.dry_run)
    await db.commit()
    return rule_out(r, await _names(db))


@router.post("/proef", dependencies=[outside.guard("acties")])
async def proef_new(body: RuleIn, request: Request, user: User = Depends(current_user),
                    db: AsyncSession = Depends(get_db)):
    """Proef van een regel die nog niet bewaard is (het formulier): wat zou ze doen? Voert niets uit en bewaart niets.
    Van buitenaf uit, zoals de regels zelf: de proef kan met de bewaarde login via SSH kijken."""
    action = await _clean(db, body)
    r = HealRule(service_id=body.service_id, enabled=body.enabled, after=body.after, max_per_hour=body.max_per_hour,
                 action=action, fired=[], last_at=None, last_result=None, dry_run=bool(body.dry_run))
    return await _proef(db, request, user, r)


async def _rule(db: AsyncSession, rule_id: int) -> HealRule:
    r = await db.get(HealRule, rule_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Regel niet gevonden")
    return r


@router.put("/{rule_id}", dependencies=[outside.guard("acties")])
async def update(rule_id: int, body: RuleIn, request: Request, user: User = Depends(recent_auth),
                 db: AsyncSession = Depends(get_db)):
    r = await _rule(db, rule_id)
    r.action = await _clean(db, body)
    r.service_id, r.enabled, r.after, r.max_per_hour = body.service_id, body.enabled, body.after, body.max_per_hour
    r.last_result = None if r.last_result and r.last_result.startswith("limiet") else r.last_result
    if body.dry_run is not None:
        if r.dry_run and not body.dry_run:
            # Van proef naar echt: de proefbeurten mogen de eerste echte herstart niet tegenhouden (wachttijd, limiet).
            r.fired, r.last_at, r.last_result = [], None, None
        r.dry_run = body.dry_run
    await audit(db, request, user, "heal_rule_changed", rule=r.id, enabled=r.enabled, dry_run=r.dry_run)
    await db.commit()
    return rule_out(r, await _names(db))


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[outside.guard("acties")])
async def remove(rule_id: int, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    r = await _rule(db, rule_id)
    await audit(db, request, user, "heal_rule_deleted", rule=r.id, what=healing.describe(r.action))
    await db.delete(r)
    await db.commit()


@router.post("/{rule_id}/test", dependencies=[outside.guard("acties")])
async def test(rule_id: int, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """De actie nu één keer uitvoeren, om te zien of ze werkt."""
    r = await _rule(db, rule_id)
    try:
        msg = await healing.test_rule(db, r, clients)
    except (IntegrationError, SshFail) as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    await audit(db, request, user, "heal_rule_tested", rule=r.id, what=healing.describe(r.action))
    await db.commit()
    return {"ok": True, "message": msg}


@router.post("/{rule_id}/proef", dependencies=[outside.guard("acties")])
async def proef(rule_id: int, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Proef: wat zou deze regel doen, en zou ze nu afgaan? Kijkt alleen (de stand via de API of via SSH), voert niets
    uit en verandert de regel niet."""
    return await _proef(db, request, user, await _rule(db, rule_id))


async def _proef(db: AsyncSession, request: Request, user: User, r: HealRule) -> dict:
    plan = await healing.plan_rule(db, r, clients)
    # Alleen dit wordt bewaard: wie keek er met de bewaarde login op de machine.
    await audit(db, request, user, "heal_rule_proef", rule=r.id, what=healing.describe(r.action))
    await db.commit()
    return plan
