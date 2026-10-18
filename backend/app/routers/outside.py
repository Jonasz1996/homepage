"""Buitenmodus in het scherm: van waar dit bezoek komt, wat er van buitenaf mag, en aan- of uitzetten."""

import ipaddress
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside, zonderlogin
from ..db import ensure_state, get_db
from ..deps import audit, client_country, current_session, current_user, fresh_auth, notify, recent_auth
from ..models import AppState, Session, User

router = APIRouter(prefix="/api/outside", tags=["buitenaf"])

ACCESS = {"cloudflare-access": "Cloudflare Access", "authentik": "Authentik (forward-auth in NPM)"}


def access_of(request: Request) -> str | None:
    """Welk slot er voor het dashboard stond. nginx zet dit alleen voor verzoeken via NPM, Cloudflare Access alleen als
    NPM het van Cloudflare of een tunnel kreeg, en nooit samen met een vervalste header van Cloudflare."""
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


async def _aanmelden(request: Request, db: AsyncSession) -> dict:
    """Stand van aanmelden, en of dit bezoek zonder login mag (en zo niet, waarom)."""
    cfg = await zonderlogin.settings(db)
    ok, why = await zonderlogin.check(request, db, cfg)
    return {"mode": cfg["mode"], "label": zonderlogin.LABELS[cfg["mode"]], "names": cfg["names"],
            "nu": ok, "why": why, "sessie": await zonderlogin.logged_in(request, db)}


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
            "seen": (seen.value if seen else {}) or {}, "aanmelden": await _aanmelden(request, db)}


class ModeIn(BaseModel):
    mode: str = Field(pattern="^(uit|uur|aan)$")


@router.put("/features/{key}")
async def set_mode(key: str, data: ModeIn, request: Request, user: User = Depends(recent_auth),
                   sess: Session = Depends(current_session), db: AsyncSession = Depends(get_db)):
    if key not in outside.FEATURES:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Onbekende functie")
    cfg = await outside.settings(db)
    w = await outside.where(request, db, cfg)
    if data.mode != "uit" and w["outside"] and await zonderlogin.outside_without_login(request, db):
        # Anders zet iedereen die het adres kent hier de terminal aan.
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Zonder login kan je dit van buitenaf niet aanzetten. Thuis wel.")
    if data.mode == "aan" and w["outside"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Altijd aanzetten kan alleen thuis. Onderweg kan het voor één uur.")
    if data.mode != "uit" and w["outside"]:
        await fresh_auth(sess, user)  # ook overal zonder login: met een gestolen cookie alleen gaat het niet
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
        who = f"Iemand zonder login (als {user.username})" if getattr(request.state, "zonder_login", False) \
            else user.username
        notify(db, f"Van buitenaf: {label} {'één uur aan' if data.mode == 'uur' else 'altijd aan'}",
               f"{who} zette dit aan {where}.", level="warn" if w["outside"] or data.mode == "aan" else "info",
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


class AanmeldenIn(BaseModel):
    mode: str = Field(pattern="^(uit|thuis|overal)$")


@router.put("/aanmelden")
async def put_aanmelden(data: AanmeldenIn, request: Request, user: User = Depends(recent_auth),
                        db: AsyncSession = Depends(get_db)):
    """Aanmelden aan of uit (zonderlogin.py). Losser zetten kan alleen thuis; strenger ook van buitenaf."""
    current = (await zonderlogin.settings(db))["mode"]
    if zonderlogin.LOOSE[data.mode] > zonderlogin.LOOSE[current] and (await outside.where(request, db))["outside"]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Aanmelden losser zetten kan alleen thuis; strenger kan overal.")
    if data.mode != current:
        st = await ensure_state(db, zonderlogin.KEY, {})
        st.value = {**(st.value or {}), "mode": data.mode}
        await audit(db, request, user, "aanmelden", mode=data.mode)
        notify(db, f"Aanmelden: {zonderlogin.LABELS[data.mode]}", {
            "uit": "Het dashboard vraagt weer overal je login met 2FA.",
            "thuis": "Thuis vraagt het dashboard geen login en geen 2FA-code meer; van buitenaf wel.",
            "overal": "Het dashboard vraagt nergens nog een login of 2FA-code, ook niet van buitenaf. Zonder echte "
                      "login blijven van buitenaf terminal, updates, acties en downloads dicht, net als Authentik en je "
                      "wachtwoord wijzigen.",
        }[data.mode], level="info" if data.mode == "uit" else "warn", source="auth")
        await db.commit()
    return await _aanmelden(request, db)
