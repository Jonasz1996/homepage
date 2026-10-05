"""Buitenmodus: wat mag er als het dashboard van buitenaf gebruikt wordt.

Van buitenaf = het verzoek kwam via Cloudflare (nginx zet X-Homepage-Via-Cf als NPM een CF-Connecting-IP doorgaf),
of vanaf een publiek IP. Thuis (LAN, VPN, Tailscale) en het eigen publieke IP (wie thuis via Cloudflare surft)
tellen als thuis. Van buitenaf staan de gevaarlijke functies standaard uit; kijken kan altijd. Per functie kan
Jonas ze aanzetten: één uur (ook onderweg, met een verse 2FA-code) of altijd (alleen thuis).

nginx overschrijft X-Homepage-Via-Cf en X-Homepage-Access bij elk verzoek, en uvicorn luistert alleen op
127.0.0.1, dus een bezoeker kan ze niet zelf meesturen.
"""

import ipaddress
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from .db import get_db
from .models import AppState

STATE_KEY = "outside"
SEEN_KEY = "outside_seen"
TEMP = timedelta(hours=1)
MODES = ("uit", "uur", "aan")

# Volgorde = volgorde in het scherm.
FEATURES = {
    "terminal": ("terminal", "SSH-terminal en zijn hosts, sleutels en snippets, cronjobs zelf starten of bewaken, "
                             "rsyslog uitrollen"),
    "updates": ("updates installeren", "updates installeren en terugdraaien, nachtelijke updates instellen"),
    "acties": ("acties", "VM's en containers aan of uit, Wake-on-LAN, zelfherstel, snapshots verwijderen, hersteltest, "
                         "API-calls die iets veranderen, poortscan"),
    "downloads": ("configuraties downloaden", "oude configuraties downloaden en eigen bestanden ongemaskeerd bekijken"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ip(conn: HTTPConnection) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(conn.client.host) if conn.client else None
    except ValueError:
        return None


async def settings(db: AsyncSession) -> dict:
    st = await db.get(AppState, STATE_KEY)
    v = dict(st.value) if st else {}
    v.setdefault("features", {})
    v.setdefault("home_ip", True)
    v.setdefault("networks", [])
    return v


async def _home_public_ip(db: AsyncSession) -> str | None:
    st = await db.get(AppState, "public_ip")
    return (st.value or {}).get("ip") if st else None


async def where(conn: HTTPConnection, db: AsyncSession, cfg: dict | None = None) -> dict:
    """{outside, via_cf, ip, why}: van waar dit verzoek komt."""
    cfg = cfg or await settings(db)
    via_cf = conn.headers.get("x-homepage-via-cf") == "1"
    ip = _ip(conn)
    out = {"outside": False, "via_cf": via_cf, "ip": str(ip) if ip else None, "why": "thuisnetwerk"}
    if ip is not None:
        for net in cfg.get("networks") or []:
            try:
                if ip in ipaddress.ip_network(net, strict=False):
                    return {**out, "why": f"thuisnetwerk {net}"}
            except ValueError:
                continue
        if cfg.get("home_ip", True) and str(ip) == await _home_public_ip(db):
            return {**out, "why": "je eigen publieke IP"}
    if via_cf:
        return {**out, "outside": True, "why": "via Cloudflare"}
    if ip is not None and ip.is_global:
        return {**out, "outside": True, "why": "publiek IP"}
    return out


def allowed(cfg: dict, feature: str) -> tuple[bool, str, str | None]:
    """(mag, stand, tot wanneer) voor een bezoek van buitenaf."""
    f = (cfg.get("features") or {}).get(feature) or {}
    mode = f.get("mode") or "uit"
    if mode == "aan":
        return True, "aan", None
    if mode == "uur" and f.get("until"):
        until = datetime.fromisoformat(f["until"])
        if until > _now():
            return True, "uur", f["until"]
    return False, "uit", None


async def blocked(conn: HTTPConnection, db: AsyncSession, feature: str) -> str | None:
    """None als het mag, anders de reden (voor WebSockets, die geen HTTPException kunnen geven)."""
    cfg = await settings(db)
    w = await where(conn, db, cfg)
    if not w["outside"] or allowed(cfg, feature)[0]:
        return None
    return f"buiten:{feature}"


def guard(feature: str):
    """Dependency: 403 "buiten:<functie>" als het verzoek van buitenaf komt en die functie daar uit staat."""
    assert feature in FEATURES

    async def dep(conn: HTTPConnection, db: AsyncSession = Depends(get_db)) -> None:
        if why := await blocked(conn, db, feature):
            raise HTTPException(status.HTTP_403_FORBIDDEN, why)

    dep.outside_feature = feature  # voor de test die nagaat welke routes bewaakt zijn
    return Depends(dep)
