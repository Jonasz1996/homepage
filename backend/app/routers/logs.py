"""Logviewer: zoeken in syslog-regels, live meekijken, meldingsregels en rsyslog uitrollen."""

import asyncio
import re
from datetime import datetime, timedelta, timezone

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import and_, case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import get_db
from ..deps import audit, current_user, recent_auth
from ..models import LogEntry, LogRule, SshHost, User
from ..ssh_login import login_for
from ..syslog import rollout
from .monitoring import _aware

router = APIRouter(prefix="/api/logs", tags=["logs"])

RANGES = {"1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}
BUCKETS = {"1h": 60, "24h": 1800, "7d": 6 * 3600, "30d": 86400}


def _row(e: LogEntry) -> dict:
    return {"id": e.id, "ts": e.ts, "host": e.host, "app": e.app, "severity": e.severity,
            "facility": e.facility, "msg": e.msg}


def _filters(host: list[str] | None, app: str | None, sev: int | None, q: str | None) -> list:
    conds = []
    if host:
        conds.append(LogEntry.host.in_(host))
    if app:
        conds.append(LogEntry.app == app)
    if sev is not None:
        conds.append(LogEntry.severity <= sev)
    if q:
        for word in q.split()[:5]:
            like = "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
            conds.append(or_(LogEntry.msg.ilike(like, escape="\\"), LogEntry.app.ilike(like, escape="\\")))
    return conds


@router.get("")
async def search(host: list[str] | None = Query(default=None), app: str | None = None,
                 sev: int | None = Query(default=None, ge=0, le=7), q: str | None = Query(default=None, max_length=200),
                 span_key: str = Query(default="24h", alias="range"), before_ts: datetime | None = None, before_id: int | None = None,
                 after_id: int | None = None, limit: int = Query(default=200, ge=1, le=1000),
                 user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    conds = _filters(host, app, sev, q)
    if after_id is not None:
        # Live meekijken: alles wat nieuw is sinds de laatste regel die de browser heeft.
        stmt = (select(LogEntry).where(LogEntry.id > after_id, *conds)
                .where(LogEntry.ts > datetime.now(timezone.utc) - timedelta(hours=1))
                .order_by(LogEntry.id).limit(limit))
        rows = (await db.execute(stmt)).scalars().all()
        return {"items": [_row(e) for e in reversed(rows)]}
    span = RANGES.get(span_key, RANGES["24h"])
    conds.append(LogEntry.ts >= datetime.now(timezone.utc) - span)
    if before_ts is not None and before_id is not None:
        conds.append(or_(LogEntry.ts < before_ts, and_(LogEntry.ts == before_ts, LogEntry.id < before_id)))
    stmt = select(LogEntry).where(*conds).order_by(LogEntry.ts.desc(), LogEntry.id.desc()).limit(limit)
    rows = (await db.execute(stmt)).scalars().all()
    return {"items": [_row(e) for e in rows], "more": len(rows) == limit}


@router.get("/hosts")
async def hosts(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    stmt = (select(LogEntry.host, func.count(), func.max(LogEntry.ts), func.min(LogEntry.severity),
                   func.sum(case((LogEntry.severity <= 3, 1), else_=0)),
                   func.max(case((LogEntry.app == "docker", 1), else_=0)))
            .where(LogEntry.ts >= since).group_by(LogEntry.host).order_by(LogEntry.host))
    return [{"host": h, "count": n, "last": _aware(last), "worst": worst, "errors": int(errs or 0), "docker": bool(dock)}
            for h, n, last, worst, errs, dock in (await db.execute(stmt)).all()]


@router.get("/histogram")
async def histogram(host: list[str] | None = Query(default=None), app: str | None = None,
                    sev: int | None = Query(default=None, ge=0, le=7), q: str | None = Query(default=None, max_length=200),
                    span_key: str = Query(default="24h", alias="range"), user: User = Depends(current_user),
                    db: AsyncSession = Depends(get_db)):
    span, size = RANGES.get(span_key, RANGES["24h"]), BUCKETS.get(span_key, 1800)
    start = datetime.now(timezone.utc) - span
    if db.bind.dialect.name == "sqlite":
        from sqlalchemy import Integer, cast
        bucket = cast(cast(func.strftime("%s", LogEntry.ts), Integer) / size, Integer)
    else:
        bucket = func.floor(func.extract("epoch", LogEntry.ts) / size)
    stmt = (select(bucket.label("b"), func.sum(case((LogEntry.severity <= 3, 1), else_=0)),
                   func.sum(case((LogEntry.severity == 4, 1), else_=0)), func.count())
            .where(LogEntry.ts >= start, *_filters(host, app, sev, q)).group_by("b").order_by("b"))
    rows = {int(b): (int(e or 0), int(w or 0), int(n)) for b, e, w, n in (await db.execute(stmt)).all()}
    first = int(start.timestamp()) // size
    last = int(datetime.now(timezone.utc).timestamp()) // size
    return {"bucket_seconds": size, "points": [
        {"t": datetime.fromtimestamp(b * size, timezone.utc), "err": rows.get(b, (0, 0, 0))[0],
         "warn": rows.get(b, (0, 0, 0))[1], "total": rows.get(b, (0, 0, 0))[2]}
        for b in range(first, last + 1)]}


# --- Meldingsregels -------------------------------------------------------------

class RuleIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    pattern: str | None = Field(default=None, max_length=500)
    host: str | None = Field(default=None, max_length=255)
    max_severity: int = Field(default=7, ge=0, le=7)
    level: str = Field(default="warn", pattern="^(info|warn|err)$")
    cooldown_minutes: int = Field(default=10, ge=0, le=1440)
    enabled: bool = True

    @field_validator("pattern")
    @classmethod
    def _regex(cls, v: str | None) -> str | None:
        if v:
            try:
                re.compile(v)
            except re.error as e:
                raise ValueError(f"Ongeldige regex: {e}") from e
        return v or None

    @field_validator("host")
    @classmethod
    def _host(cls, v: str | None) -> str | None:
        return v.strip() or None if v else None


def _rule_out(r: LogRule) -> dict:
    return {k: getattr(r, k) for k in ("id", "name", "pattern", "host", "max_severity", "level",
                                        "cooldown_minutes", "enabled")}


@router.get("/rules")
async def list_rules(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return [_rule_out(r) for r in (await db.execute(select(LogRule).order_by(LogRule.id))).scalars()]


@router.post("/rules", status_code=201)
async def create_rule(data: RuleIn, request: Request, user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)):
    r = LogRule(**data.model_dump())
    db.add(r)
    await audit(db, request, user, "log_rule_added", name=r.name)
    await db.commit()
    return _rule_out(r)


@router.patch("/rules/{rule_id}")
async def update_rule(rule_id: int, data: RuleIn, request: Request, user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)):
    r = await db.get(LogRule, rule_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Regel niet gevonden")
    for k, v in data.model_dump().items():
        setattr(r, k, v)
    await audit(db, request, user, "log_rule_changed", name=r.name)
    await db.commit()
    return _rule_out(r)


@router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: int, request: Request, user: User = Depends(current_user),
                      db: AsyncSession = Depends(get_db)):
    r = await db.get(LogRule, rule_id)
    if r is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Regel niet gevonden")
    await db.delete(r)
    await audit(db, request, user, "log_rule_deleted", name=r.name)
    await db.commit()
    return {"ok": True}


# --- rsyslog uitrollen ------------------------------------------------------------

@router.get("/setup")
async def setup(user: User = Depends(current_user)):
    s = get_settings()
    target = s.syslog_target or "<IP van de homepage-container>"
    return {"target": s.syslog_target, "port": s.syslog_port, "allow": s.syslog_allow,
            "manual": rollout.manual(target, s.syslog_port),
            "proxmox_hint": "Op een Proxmox-node met 'ook containers' worden alle draaiende CT's meegenomen (pct)."}


class RolloutIn(BaseModel):
    host_id: int
    containers: bool = False


@router.post("/rollout")
async def run_rollout(data: RolloutIn, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    s = get_settings()
    if not s.syslog_target:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "HOMEPAGE_SYSLOG_TARGET is niet ingesteld in /etc/homepage/homepage.env")
    h = await db.get(SshHost, data.host_id)
    if h is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Host niet gevonden")
    if not h.host_key:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "Open eerst één keer een terminal naar deze host om de hostsleutel te bevestigen")
    login = await login_for(db, h)
    script = rollout.build(s.syslog_target, s.syslog_port, data.containers)
    command = "sh -s" if login.username == "root" else "sudo -n sh -s"
    try:
        async with asyncio.timeout(600):
            async with asyncssh.connect(
                h.host, port=h.port, username=login.username,
                known_hosts=([asyncssh.import_public_key(h.host_key)], [], []),
                client_keys=[login.key] if login.key else None, password=login.password,
                agent_path=None, config=None, connect_timeout=10,
            ) as conn:
                result = await conn.run(command, input=script, check=False)
    except asyncssh.HostKeyNotVerifiable as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "Hostsleutel klopt niet meer, verbinding geweigerd") from e
    except (OSError, asyncssh.Error, TimeoutError) as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"SSH mislukt: {getattr(e, 'reason', None) or e}") from e
    output = (str(result.stdout or "") + str(result.stderr or ""))[-20000:]
    await audit(db, request, user, "syslog_rollout", host=h.name, containers=data.containers,
                exit_status=result.exit_status)
    await db.commit()
    return {"exit_status": result.exit_status, "output": output}
