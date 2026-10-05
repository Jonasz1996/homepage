"""Gezondheid: schijven en temperaturen, vergeten snapshots, domeinen en de homepage zelf."""

import asyncio
import logging
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..config import get_settings
from ..db import get_db
from ..deps import audit, current_user, recent_auth
from ..health import domains as dom, scan as hw, selfcheck as sc, snapshots as snap
from ..monitoring import cluster
from ..integrations import IntegrationError
from ..models import AppState, Reading, Service, User
from .integrations import clients

router = APIRouter(prefix="/api/health", tags=["health"])
log = logging.getLogger("homepage.api")

_tasks: dict[str, asyncio.Task] = {}
MAX_POINTS = 300


async def _value(db: AsyncSession, key: str) -> dict:
    st = await db.get(AppState, key)
    return dict(st.value) if st else {}


def _running(name: str) -> bool:
    t = _tasks.get(name)
    return bool(t and not t.done())


def _summary(hardware: dict, snaps: dict, domains: dict, selfc: dict, worker: dict, cfg: dict) -> dict:
    hosts = hardware.get("hosts", [])
    disks = [d for h in hosts for d in h.get("disks", [])]
    old = [s for s in snaps.get("items", []) if (s.get("age_days") or 0) >= cfg["snapshot_days"]]
    soon = [d for d in domains.get("items", []) if d.get("days_left") is not None and d["days_left"] <= 30]
    problems = []
    if not worker["ok"]:
        problems.append("worker draait niet")
    if selfc.get("stale"):
        problems.append("geen recente back-up")
    if (selfc.get("verified") or {}).get("ok") is False:
        problems.append("back-up onleesbaar")
    if (selfc.get("offsite") or {}).get("enabled") and (selfc.get("offsite") or {}).get("error"):
        problems.append("kopie buiten de container")
    if (selfc.get("alerts") or {}).get("disk"):
        problems.append("schijf bijna vol")
    err = sum(1 for d in disks if d.get("level") == "err") + sum(1 for h in hosts if h.get("error"))
    warn = sum(1 for d in disks if d.get("level") == "warn") + sum(
        1 for h in hosts for p in h.get("pools", []) if p.get("level") in ("warn", "err"))
    warn += sum(1 for h in hosts if (h.get("throttle") or {}).get("now"))
    hot = [h["name"] for h in hosts if h.get("cpu_temp") is not None and h["cpu_temp"] >= cfg["cpu_warn"]]
    return {"err": err + len(problems) + sum(1 for d in soon if d["days_left"] <= 7),
            "warn": warn + len(old) + len(hot) + sum(1 for d in soon if d["days_left"] > 7),
            "disks": len(disks), "hosts": len(hosts), "old_snapshots": len(old), "domains_soon": len(soon),
            "hot": hot, "problems": problems}


async def _with_cluster(db: AsyncSession, summ: dict) -> dict:
    """Problemen met de Proxmox-cluster tellen mee in de knop hw (tabblad cluster)."""
    c = cluster.summary(await _value(db, cluster.STATE_KEY))
    return {**summ, "err": summ["err"] + c["err"], "warn": summ["warn"] + c["warn"], "cluster": c}


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    cfg = await hw.settings(db)
    worker = await sc.check_worker(db)
    await db.commit()
    hardware, snaps = await _value(db, hw.STATE_KEY), await _value(db, snap.STATE_KEY)
    domains, selfc = await _value(db, dom.STATE_KEY), await _value(db, sc.STATE_KEY)
    key = await _value(db, sc.KEY_STATE)
    snaps.pop("warned", None)
    selfc.pop("alerts", None)
    return {"settings": cfg, "hardware": hardware, "snapshots": snaps, "domains": domains, "selfcheck": selfc,
            "worker": worker, "offsite_key": {"set": bool(key.get("blob")), "at": key.get("at")},
            "offsite_dir": str(get_settings().offsite_dir),
            "running": [k for k in _tasks if _running(k)],
            "summary": await _with_cluster(db, _summary(hardware, snaps, domains, selfc, worker, cfg))}


@router.get("/summary")
async def summary(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Voor de knop in de titelbalk. Kijkt ook of de worker nog leeft (en meldt het als hij stilviel)."""
    cfg = await hw.settings(db)
    worker = await sc.check_worker(db)
    await db.commit()
    return await _with_cluster(db, _summary(await _value(db, hw.STATE_KEY), await _value(db, snap.STATE_KEY),
                                            await _value(db, dom.STATE_KEY), await _value(db, sc.STATE_KEY), worker, cfg))


@router.get("/temps")
async def temps(hours: int = 24, target: str | None = None, user: User = Depends(current_user),
                db: AsyncSession = Depends(get_db)):
    hours = min(max(hours, 1), 24 * 30)
    since = datetime.now(timezone.utc) - timedelta(hours=hours)
    stmt = select(Reading).where(Reading.ts >= since).order_by(Reading.ts)
    if target:
        stmt = stmt.where(Reading.target == target)
    series: dict[tuple[str, str], list] = {}
    for r in (await db.execute(stmt)).scalars():
        ts = r.ts if r.ts.tzinfo else r.ts.replace(tzinfo=timezone.utc)
        series.setdefault((r.target, r.sensor), []).append((ts.timestamp(), r.value))
    # Uitdunnen tot hoogstens MAX_POINTS punten per lijn (maximum per vak, zodat pieken zichtbaar blijven).
    step = max(1, hours * 3600 // MAX_POINTS)
    out = []
    for (tgt, sensor), pts in series.items():
        buckets: dict[int, float] = {}
        for t, v in pts:
            b = int(t // step * step)
            buckets[b] = max(buckets.get(b, v), v)
        out.append({"target": tgt, "sensor": sensor, "points": sorted(buckets.items())})
    return {"hours": hours, "series": out}


async def _bg(name: str, factory, work) -> None:
    gen = factory()
    try:
        db = await anext(gen)
        await work(db)
        await db.commit()
    except Exception:
        log.exception("gezondheid: %s mislukt", name)
    finally:
        await gen.aclose()


async def _work(name: str, db: AsyncSession):
    cfg = await hw.settings(db)
    if name == "hardware":
        await hw.run_health(db)
    elif name == "snapshots":
        await snap.run_snapshots(db, clients, cfg["snapshot_days"])
    elif name == "domains":
        await dom.run_domains(db, clients, cfg["domains"])
    elif name == "selfcheck":
        await sc.run_selfcheck(db, cfg["offsite"])


@router.post("/scan/{what}", status_code=status.HTTP_202_ACCEPTED)
async def scan(what: str, request: Request, user: User = Depends(current_user)):
    if what not in ("hardware", "snapshots", "domains", "selfcheck"):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onbekend onderdeel")
    if _running(what):
        raise HTTPException(status.HTTP_409_CONFLICT, "Loopt al")
    factory = request.app.dependency_overrides.get(get_db, get_db)
    _tasks[what] = asyncio.create_task(_bg(what, factory, lambda db: _work(what, db)))
    return {"ok": True}


class Domain(BaseModel):
    name: str = Field(max_length=253)
    expires: str | None = Field(default=None, max_length=10)


class SettingsIn(BaseModel):
    cpu_warn: int = Field(ge=40, le=110)
    disk_warn: int = Field(ge=30, le=80)
    snapshot_days: int = Field(ge=1, le=365)
    domains: list[Domain] = Field(default_factory=list, max_length=50)
    offsite: bool = False


@router.put("/settings")
async def put_settings(body: SettingsIn, request: Request, user: User = Depends(current_user),
                       db: AsyncSession = Depends(get_db)):
    domains, seen = [], set()
    for d in body.domains:
        name = dom.clean(d.name)
        if not name:
            raise HTTPException(422, f"Geen geldig domein: {d.name}")
        if d.expires:
            try:
                datetime.strptime(d.expires, "%Y-%m-%d")
            except ValueError as e:
                raise HTTPException(422, f"Datum als JJJJ-MM-DD: {d.expires}") from e
        if name not in seen:
            seen.add(name)
            domains.append({"name": name, "expires": d.expires or None})
    value = {**body.model_dump(exclude={"domains"}), "domains": domains}
    st = await db.get(AppState, hw.SETTINGS_KEY)
    if st:
        st.value = value
    else:
        db.add(AppState(key=hw.SETTINGS_KEY, value=value))
    await audit(db, request, user, "health_settings", domains=[d["name"] for d in domains], offsite=body.offsite)
    await db.commit()
    return value


class Passphrase(BaseModel):
    passphrase: str = Field(min_length=sc.MIN_PASSPHRASE, max_length=500)


@router.put("/offsite-key")
async def offsite_key(body: Passphrase, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    """secret.key versleutelen met een wachtzin, voor de kopie buiten de container. De wachtzin bewaren we niet."""
    try:
        secret = get_settings().secret_key_file.read_bytes()
    except OSError as e:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "secret.key niet leesbaar") from e
    blob = await asyncio.to_thread(sc.encrypt_key, secret, body.passphrase)
    value = {"blob": blob, "at": datetime.now(timezone.utc).replace(microsecond=0).isoformat()}
    st = await db.get(AppState, sc.KEY_STATE)
    if st:
        st.value = value
    else:
        db.add(AppState(key=sc.KEY_STATE, value=value))
    await audit(db, request, user, "offsite_key_set")
    await db.commit()
    return {"set": True, "at": value["at"]}


class SnapshotRef(BaseModel):
    service_id: int
    node: str = Field(max_length=63)
    type: str = Field(pattern="^(qemu|lxc)$")
    vmid: int = Field(ge=100, le=999999999)
    name: str = Field(max_length=40)


@router.post("/snapshots/delete")
async def delete_snapshot(body: SnapshotRef, request: Request, user: User = Depends(recent_auth),
                          db: AsyncSession = Depends(get_db)):
    svc = await db.get(Service, body.service_id)
    if svc is None or svc.type != "proxmox":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Proxmox-tegel niet gevonden")
    try:
        upid = await snap.delete_snapshot(svc, clients, body.node, body.type, body.vmid, body.name)
    except IntegrationError as e:
        msg = str(e)
        if "te weinig rechten" in msg:
            msg += " — het token heeft VM.Snapshot nodig om snapshots te verwijderen"
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, msg) from e
    st = await db.get(AppState, snap.STATE_KEY)
    if st:
        v = dict(st.value)
        v["items"] = [s for s in v.get("items", []) if not (
            s["node"] == body.node and s["vmid"] == body.vmid and s["name"] == body.name)]
        st.value = v
    await audit(db, request, user, "snapshot_delete", guest=body.vmid, node=body.node, name=body.name)
    await db.commit()
    return {"ok": True, "task": upid}
