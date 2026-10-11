"""Buitenmodus: wat mag er als het dashboard van buitenaf gebruikt wordt.

Van buitenaf = het verzoek kwam via Cloudflare (nginx zet X-Homepage-Via-Cf als NPM een CF-Connecting-IP doorgaf dat
het van Cloudflare of een tunnel kreeg), met een vervalste header van Cloudflare, of vanaf een publiek IP. Thuis (LAN,
VPN, Tailscale) en het eigen publieke IP (wie thuis via Cloudflare surft) tellen als thuis. Van buitenaf staan de
gevaarlijke functies standaard uit; kijken kan altijd. Per functie kan Jonas ze aanzetten: één uur (ook onderweg, met
een verse 2FA-code) of altijd (alleen thuis).

nginx overschrijft X-Homepage-Via-Cf, X-Homepage-Access en X-Homepage-Cf-Forged bij elk verzoek, en uvicorn luistert
alleen op 127.0.0.1, dus een bezoeker kan ze niet zelf meesturen. De headers van Cloudflare gelooft nginx alleen als NPM
het verzoek van Cloudflare of een tunnel kreeg (deploy/nginx-map.conf). Stuurt iemand anders ze mee (wie NPM
rechtstreeks bereikt en zo een ander IP voorwendt, bv. het eigen publieke IP), dan zet nginx X-Homepage-Cf-Forged: zo
iemand telt altijd als van buitenaf, en het dashboard meldt het. Het IP is dan het adres waarvan NPM het verzoek kreeg;
dat kan gekozen zijn (NPM gelooft X-Real-IP van het LAN), dus de limieten op pogingen delen dan één sleutel
(deps.limit_ip).
"""

import ipaddress
import zlib
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, status
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import HTTPConnection

from .db import get_db
from .deps import cf_forged, current_session, current_user, notify, recent_auth
from .models import AppState, Notification, Session, User

STATE_KEY = "outside"
SEEN_KEY = "outside_seen"
TEMP = timedelta(hours=1)
MODES = ("uit", "uur", "aan")
FORGED_WHY = "vervalste Cloudflare-header van een adres dat geen Cloudflare is"
# Een melding over vervalste headers: hoogstens één per uur, van welk adres ook (het adres kan gekozen zijn).
FORGED_KEY = "cf-vervalst"
FORGED_EVERY = timedelta(hours=1)

# Volgorde = volgorde in het scherm.
FEATURES = {
    "terminal": ("terminal", "SSH-terminal en zijn hosts, sleutels en snippets, cronjobs zelf starten of bewaken, "
                             "rsyslog uitrollen"),
    "updates": ("updates installeren", "updates installeren en terugdraaien, nachtelijke updates instellen"),
    "acties": ("acties", "VM's en containers aan of uit, Wake-on-LAN, zelfherstel, snapshots verwijderen, hersteltest, "
                         "API-calls die iets veranderen, API's instellen of calls uitproberen, een tegel met "
                         "integratie een ander adres geven, poortscan"),
    "downloads": ("configuraties, diagnose en noodplan downloaden",
                  "oude configuraties, de diagnose en het noodplan downloaden en eigen bestanden ongemaskeerd bekijken"),
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ip(conn: HTTPConnection) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        ip = ipaddress.ip_address(conn.client.host) if conn.client else None
    except ValueError:
        return None
    # Een IPv4-adres in IPv6-vorm (::ffff:a.b.c.d) is gewoon dat IPv4-adres.
    if ip is not None and ip.version == 6 and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


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


def forged(conn: HTTPConnection) -> bool:
    """Had het verzoek een header van Cloudflare die niet van Cloudflare kwam? (nginx zet dit, zie hierboven.)"""
    return cf_forged(conn)


async def _report_forged(db: AsyncSession, ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None) -> None:
    """Melding (en tijdlijn) over een vervalste header. Bewaart meteen: een geweigerd verzoek bewaart zelf niets.
    De aanroepers van where() hebben op dat moment nog niets gewijzigd."""
    if db.bind.dialect.name == "postgresql":
        # Gelijktijdige verzoeken na elkaar: anders zien ze allemaal nog geen melding en maakt elk er een. Het slot
        # gaat vrij bij de commit hieronder.
        key = zlib.crc32(f"homepage:{FORGED_KEY}".encode())
        await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": key})
    if (await db.execute(select(Notification.id).where(
            Notification.push_key == FORGED_KEY, Notification.ts >= _now() - FORGED_EVERY).limit(1))).first():
        await db.commit()
        return
    who = str(ip) if ip is not None else "?"
    notify(db, "Vervalste Cloudflare-header",
           f"Een verzoek van {who} had een header van Cloudflare (CF-Connecting-IP, CF-IPCountry of "
           "Cf-Access-Jwt-Assertion), maar NPM kreeg het niet van Cloudflare of een tunnel: zo kan wie NPM "
           "rechtstreeks bereikt een ander IP voorwenden. Het dashboard telt het als van buitenaf, met het adres "
           "waarvan NPM het verzoek kreeg (meestal het echte; van het LAN kan het gekozen zijn). Een uur lang komt "
           "er geen nieuwe melding over. Kwam je zelf via Cloudflare binnen? Dan mist deploy/nginx-map.conf "
           "misschien een nieuw blok van Cloudflare: zie de README (Installeren → Cloudflare).",
           level="warn", source="auth", key=FORGED_KEY, data={"ip": who})
    await db.commit()


async def where(conn: HTTPConnection, db: AsyncSession, cfg: dict | None = None) -> dict:
    """{outside, via_cf, ip, why}: van waar dit verzoek komt."""
    cfg = cfg or await settings(db)
    via_cf = conn.headers.get("x-homepage-via-cf") == "1"
    ip = _ip(conn)
    out = {"outside": False, "via_cf": via_cf, "ip": str(ip) if ip else None, "why": "thuisnetwerk"}
    # Eerst: wie headers van Cloudflare vervalst, is nooit thuis (ook niet met het IP van een thuisnetwerk).
    if forged(conn):
        await _report_forged(db, ip)
        return {**out, "outside": True, "via_cf": False, "why": FORGED_WHY}
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


async def require(conn: HTTPConnection, db: AsyncSession, feature: str, sess: Session, user: User) -> None:
    """Van buitenaf: de functie moet aan staan én je 2FA moet vers zijn (voor deze sessie). Thuis: niets.

    De stand van een functie geldt voor elke sessie van buitenaf (ze staat niet per sessie): zonder verse 2FA zou wie
    je sessie steelt in dat uur meeliften. Voor routes die het alleen in sommige gevallen vragen (een tegel die een
    nieuw adres krijgt); anders guard(feature, fresh=True)."""
    cfg = await settings(db)
    if not (await where(conn, db, cfg))["outside"]:
        return
    if not allowed(cfg, feature)[0]:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"buiten:{feature}")
    await recent_auth(sess, user)


def guard(feature: str, fresh: bool = False):
    """Dependency: 403 "buiten:<functie>" als het verzoek van buitenaf komt en die functie daar uit staat.
    fresh: van buitenaf ook een verse 2FA vragen (403 "reauth_required"), zie require()."""
    assert feature in FEATURES

    if fresh:
        async def dep(conn: HTTPConnection, db: AsyncSession = Depends(get_db),
                      sess: Session = Depends(current_session), user: User = Depends(current_user)) -> None:
            await require(conn, db, feature, sess, user)
    else:
        async def dep(conn: HTTPConnection, db: AsyncSession = Depends(get_db)) -> None:
            if why := await blocked(conn, db, feature):
                raise HTTPException(status.HTTP_403_FORBIDDEN, why)

    dep.outside_feature = feature  # voor de test die nagaat welke routes bewaakt zijn
    return Depends(dep)
