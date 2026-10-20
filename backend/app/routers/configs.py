"""Configuratiewijzigingen (versies, diff, downloaden) en apparaten op het netwerk."""

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import audit, current_session, current_user, recent_auth
from ..models import AppState, ConfigVersion, Device, Session, SshHost, User
from ..monitoring import configs, devices
from ..security import decrypt
from .integrations import clients

router = APIRouter(prefix="/api", tags=["configs"])
log = logging.getLogger("homepage.api")

_run: asyncio.Task | None = None


def _v(v: ConfigVersion) -> dict:
    return {"id": v.id, "item": v.item, "name": v.name, "kind": v.kind, "ts": v.ts, "size": v.size, "added": v.added,
            "removed": v.removed}


@router.get("/configs")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, configs.LAST_KEY)
    return {"items": await configs.overview(db), "settings": await configs.settings(db),
            "last": st.value if st else None, "running": bool(_run and not _run.done())}


@router.get("/configs/versions")
async def versions(item: str, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    rows = (await db.execute(select(ConfigVersion).where(ConfigVersion.item == item)
                             .order_by(ConfigVersion.ts.desc(), ConfigVersion.id.desc()))).scalars()
    return [_v(v) for v in rows]


async def _version(db: AsyncSession, vid: int) -> ConfigVersion:
    v = await db.get(ConfigVersion, vid)
    if v is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Versie niet gevonden")
    return v


@router.get("/configs/versions/{vid}/diff")
async def diff(vid: int, against: int | None = None, sess: Session = Depends(current_session),
               user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Verschil met de vorige versie (of met `against`). Wachtwoorden en sleutels gemaskeerd."""
    v = await _version(db, vid)
    if v.kind == "file":
        # Eigen bestanden kunnen van alles bevatten dat het maskeren mist: vraagt een recente 2FA.
        await recent_auth(sess, user)
    if against:
        old = await _version(db, against)
        if old.item != v.item:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Andere configuratie")
    else:
        old = (await db.execute(select(ConfigVersion).where(ConfigVersion.item == v.item, ConfigVersion.ts < v.ts)
                                .order_by(ConfigVersion.ts.desc()).limit(1))).scalar_one_or_none()
    when = lambda x: x.ts.strftime("%Y-%m-%d %H:%M")  # noqa: E731
    text = configs.diff(decrypt(old.content) if old else None, decrypt(v.content),
                        when(old) if old else "(niets)", when(v))
    return {"version": _v(v), "against": _v(old) if old else None, "diff": text}


@router.get("/configs/versions/{vid}/download")
async def download(vid: int, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """Volledige inhoud, ongemaskeerd (vraagt een recente 2FA)."""
    v = await _version(db, vid)
    await audit(db, request, user, "config_download", name=v.name, ts=v.ts.isoformat())
    await db.commit()
    base = v.name.split(" · ")[-1].split("/")[-1].replace(" ", "_") or "config"
    fname = f"{v.ts.strftime('%Y%m%d-%H%M')}-{base}"
    return PlainTextResponse(decrypt(v.content), headers={"Content-Disposition": f'attachment; filename="{fname}"'})


async def _bg(factory) -> None:
    gen = factory()
    try:
        db = await anext(gen)
        await configs.run_configs(db, clients)
        await db.commit()
    except Exception:
        log.exception("configuratie ophalen mislukt")
    finally:
        await gen.aclose()


@router.post("/configs/run", status_code=status.HTTP_202_ACCEPTED)
async def run_now(request: Request, user: User = Depends(current_user)):
    global _run
    if _run and not _run.done():
        raise HTTPException(status.HTTP_409_CONFLICT, "Loopt al")
    _run = asyncio.create_task(_bg(request.app.dependency_overrides.get(get_db, get_db)))
    return {"ok": True}


class FileIn(BaseModel):
    host_id: int
    path: str = Field(max_length=200)


class ConfigSettings(BaseModel):
    hour: int = Field(default=2, ge=0, le=23)
    opnsense: bool = True
    npm: bool = True
    pve: bool = True
    files: list[FileIn] = Field(default_factory=list, max_length=50)


@router.put("/configs/settings")
async def put_settings(body: ConfigSettings, request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    files = []
    for f in body.files:
        p = f.path.rstrip("/") or "/"
        if not configs.PATH_RE.match(p) or ".." in p.split("/") or p == "/":
            raise HTTPException(422, f"Geen geldig pad: {f.path}")
        if await db.get(SshHost, f.host_id) is None:
            raise HTTPException(422, "SSH-host niet gevonden")
        files.append({"host_id": f.host_id, "path": p})
    value = {**body.model_dump(exclude={"files"}), "files": files}
    st = await db.get(AppState, configs.SETTINGS_KEY)
    if st:
        st.value = value
    else:
        db.add(AppState(key=configs.SETTINGS_KEY, value=value))
    await audit(db, request, user, "config_settings", files=[f["path"] for f in files])
    await db.commit()
    return value


# --- apparaten -------------------------------------------------------------------------------

@router.get("/devices")
async def device_list(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    rows = [devices.device_out(d, now) for d in (await db.execute(select(Device))).scalars()]
    rows.sort(key=lambda d: (d["known"], not d["online"], tuple(int(x) if x.isdigit() else 0 for x in (d["ip"] or "").split("."))))
    st = await db.get(AppState, devices.STATE_KEY)
    return {"items": rows, "last": st.value if st else None,
            "summary": {"total": len(rows), "online": sum(1 for d in rows if d["online"]),
                        "unknown": sum(1 for d in rows if not d["known"])}}


class DeviceIn(BaseModel):
    name: str | None = Field(default=None, max_length=80)
    note: str | None = Field(default=None, max_length=300)
    known: bool | None = None
    scan: bool | None = None


async def _device(db: AsyncSession, mac: str) -> Device:
    d = await db.get(Device, mac.lower())
    if d is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Apparaat niet gevonden")
    return d


@router.patch("/devices/{mac}")
async def device_patch(mac: str, body: DeviceIn, request: Request, user: User = Depends(current_user),
                       db: AsyncSession = Depends(get_db)):
    d = await _device(db, mac)
    for k, v in body.model_dump(exclude_unset=True).items():
        setattr(d, k, (v.strip() or None) if isinstance(v, str) else v)
    if body.name:
        d.known = True if body.known is None else body.known
    await audit(db, request, user, "device_changed", mac=d.mac, name=d.name, scan=d.scan)
    await db.commit()
    return devices.device_out(d, datetime.now(timezone.utc))


@router.post("/devices/{mac}/scan")
async def device_scan(mac: str, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    d = await _device(db, mac)
    if not d.ip:
        raise HTTPException(status.HTTP_409_CONFLICT, "Geen IP-adres bekend")
    await devices.scan_device(db, d)
    await audit(db, request, user, "device_scan", mac=d.mac, ip=d.ip)
    await db.commit()
    return devices.device_out(d, datetime.now(timezone.utc))


@router.post("/devices/refresh")
async def device_refresh(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    v = await devices.refresh(db, clients)
    await db.commit()
    return v
