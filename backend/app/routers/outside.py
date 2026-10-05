"""Buitenmodus in het scherm: van waar dit bezoek komt, wat er van buitenaf mag, en aan- of uitzetten."""

import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..db import ensure_state, get_db
from ..deps import audit, client_country, current_user, notify, recent_auth
from ..models import AppState, User

router = APIRouter(prefix="/api/outside", tags=["buitenaf"])

ACCESS = {"cloudflare-access": "Cloudflare Access", "authentik": "Authentik (forward-auth in NPM)"}


def access_of(request: Request) -> str | None:
    """Welk slot er voor het dashboard stond (nginx zet dit alleen voor verzoeken via NPM)."""
    a = (request.headers.get("x-homepage-access") or "").strip()
    return a if a in ACCESS else None


def _features(cfg: dict) -> list[dict]:
    out = []
    for key, (label, help_) in outside.FEATURES.items():
        ok, mode, until = outside.allowed(cfg, key)
        out.append({"key": key, "label": label, "help": help_, "allowed": ok, "mode": mode, "until": until})
    return out


async def _record_visit(db: AsyncSession, request: Request, w: dict) -> None:
    """Laatste bezoek van buitenaf, voor de veiligheidscheck: stond er een slot (Access of Authentik) voor?"""
    st = await ensure_state(db, outside.SEEN_KEY, {})
    v = dict(st.value or {})
    acc = access_of(request)
    v["last"] = {"ts": datetime.now(timezone.utc).isoformat(), "ip": w["ip"], "country": client_country(request),
                 "via_cf": w["via_cf"], "access": acc}
    v["visits"] = int(v.get("visits") or 0) + 1
    if acc:
        v["with_access"] = int(v.get("with_access") or 0) + 1
        v["last_access"] = acc
    else:
        v["last_without"] = v["last"]["ts"]
    st.value = v


@router.get("")
async def state(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    cfg = await outside.settings(db)
    w = await outside.where(request, db, cfg)
    if w["outside"]:
        await _record_visit(db, request, w)
        await db.commit()
    seen = await db.get(AppState, outside.SEEN_KEY)
    return {**w, "country": client_country(request), "access": access_of(request),
            "features": _features(cfg), "home_ip": cfg["home_ip"], "networks": cfg["networks"],
            "seen": (seen.value if seen else {}) or {}}


class ModeIn(BaseModel):
    mode: str = Field(pattern="^(uit|uur|aan)$")


@router.put("/features/{key}")
async def set_mode(key: str, data: ModeIn, request: Request, user: User = Depends(recent_auth),
                   db: AsyncSession = Depends(get_db)):
    if key not in outside.FEATURES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onbekende functie")
    cfg = await outside.settings(db)
    w = await outside.where(request, db, cfg)
    if data.mode == "aan" and w["outside"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Altijd aanzetten kan alleen thuis. Onderweg kan het voor één uur.")
    entry = {"mode": data.mode}
    if data.mode == "uur":
        entry["until"] = (datetime.now(timezone.utc) + outside.TEMP).isoformat()
    st = await ensure_state(db, outside.STATE_KEY, {})
    v = dict(st.value or {})
    v["features"] = {**(v.get("features") or {}), key: entry}
    st.value = v
    label = outside.FEATURES[key][0]
    await audit(db, request, user, "outside_mode", feature=key, mode=data.mode, outside=w["outside"])
    if data.mode != "uit":
        where = f"vanaf {w['ip']}{f' ({c})' if (c := client_country(request)) else ''}, {w['why']}"
        notify(db, f"Van buitenaf: {label} {'één uur aan' if data.mode == 'uur' else 'altijd aan'}",
               f"{user.username} zette dit aan {where}.", level="warn" if w["outside"] or data.mode == "aan" else "info",
               source="auth")
    await db.commit()
    return {"features": _features(v)}


class SettingsIn(BaseModel):
    home_ip: bool = True
    networks: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("networks")
    @classmethod
    def _nets(cls, v: list[str]) -> list[str]:
        out = []
        for n in v:
            n = n.strip()
            if not n:
                continue
            try:
                net = ipaddress.ip_network(n, strict=False)
            except ValueError as e:
                raise ValueError(f"Geen geldig netwerk: {n}") from e
            if net.prefixlen < (8 if net.version == 4 else 32):
                raise ValueError(f"Te groot netwerk: {n}")
            out.append(str(net))
        return out


@router.put("/settings")
async def put_settings(data: SettingsIn, request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    """Wat telt als thuis. Alleen thuis te wijzigen: anders zet wie je login heeft zijn eigen IP erbij."""
    if (await outside.where(request, db))["outside"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Wat als thuis telt, kan je alleen thuis wijzigen")
    st = await ensure_state(db, outside.STATE_KEY, {})
    st.value = {**(st.value or {}), "home_ip": data.home_ip, "networks": data.networks}
    await audit(db, request, user, "outside_settings", home_ip=data.home_ip, networks=data.networks)
    await db.commit()
    return {"home_ip": data.home_ip, "networks": data.networks}
