"""Zonder login: het dashboard zonder aanmelden en zonder 2FA-code gebruiken (Jonas, 2026-10-17: "haal er nu login en
mfa van, ga alles achter Authentik steken later").

De stand staat in AppState "aanmelden" (⚿ → van buitenaf): "uit" = altijd aanmelden met 2FA; "thuis" = thuis geen
login en geen 2FA-code; "overal" = ook van buitenaf niet, tot Authentik ervoor staat. Zonder login ben je de eerste
gebruiker (die 2FA al ingesteld heeft). Er wordt geen sessie bewaard en er is geen cookie om te stelen: elk verzoek
wordt opnieuw beoordeeld.

Wat ook zonder login blijft:
- Van buitenaf gaan terminal, updates, acties en downloads niet zonder echte login, ook niet als ze "altijd aan" staan,
  en zonder login kan je ze van buitenaf ook niet aanzetten (outside.blocked, routers/outside.set_mode).
- Alleen op een bekend adres: een IP, localhost, of een naam waarop al eens iemand mét login binnenkwam (het
  sessiecookie hoort bij precies die naam, een andere website krijgt het nooit). Anders kan een website die je thuis
  opent via DNS-rebinding het dashboard bedienen alsof jij het deed.
- Alleen verzoeken van de frontend zelf (X-Requested-With, of Sec-Fetch-Site same-origin/none; die laatste stuurt een
  browser alleen over https of naar localhost): anders kan een andere website met een <img> of een formulier iets laten
  doen. WebSockets controleren de Origin (routers/ssh._ws_user). Checks en API's van het dashboard sturen die headers
  nooit mee (schemas.FRONTEND_HEADER): anders doet een check die naar het dashboard wijst, zich voor als jouw browser.
- Niet vanaf de container zelf (127.0.0.1 of een eigen adres, ook via NPM): een check of API-call die naar het
  dashboard zelf wijst, is geen bezoeker.

De namen staan apart (AppState "aanmelden_namen"): learn() schrijft bij het eerste verzoek op een nieuwe naam, en mag
zo nooit een stand overschrijven die intussen gewijzigd is.
"""

import ipaddress
import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import set_committed_value
from starlette.requests import HTTPConnection

from . import outside
from .db import ensure_state
from .deps import COOKIE, CSRF_HEADER, fresh_auth
from .models import AppState, Session, User
from .security import token_id

KEY = "aanmelden"
NAMES_KEY = "aanmelden_namen"
MODES = ("uit", "thuis", "overal")
# Wat geldt zolang er niets gekozen is. De tests zetten dit op "uit" (conftest), zodat ze aanmelden blijven testen.
DEFAULT = "overal"
MAX_NAMES = 20
NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}\.)*[a-z0-9-]{1,63}$")
LABELS = {"uit": "altijd met 2FA", "thuis": "thuis zonder login", "overal": "overal zonder login"}
# Hoe los: van buitenaf mag de stand alleen strenger (routers/outside.put_aanmelden).
LOOSE = {"uit": 0, "thuis": 1, "overal": 2}
# De eigen adressen van het dashboard (monitoring/upgrade.me), een minuut onthouden.
OWN_TTL = 60.0
_own: tuple[float, frozenset[str]] = (float("-inf"), frozenset())


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def settings(db: AsyncSession) -> dict:
    rows = {st.key: st.value for st in (await db.execute(
        select(AppState).where(AppState.key.in_((KEY, NAMES_KEY))))).scalars()}
    mode = (rows.get(KEY) or {}).get("mode")
    return {"mode": mode if mode in MODES else DEFAULT, "names": list((rows.get(NAMES_KEY) or {}).get("names") or [])}


def host_of(conn: HTTPConnection) -> str | None:
    """De naam uit de Host-header, klein en zonder poort ("[::1]:8080" → "::1")."""
    raw = (conn.headers.get("host") or "").strip().lower()
    if raw.startswith("["):
        end = raw.find("]")
        return (raw[1:end] or None) if end > 0 else None
    if raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    return raw.rstrip(".") or None


def _is_ip(name: str) -> bool:
    try:
        ipaddress.ip_address(name)
    except ValueError:
        return False
    return True


def trusted(name: str | None, cfg: dict) -> bool:
    return bool(name) and (_is_ip(name) or name == "localhost" or name in cfg["names"])


async def learn(conn: HTTPConnection, db: AsyncSession, cfg: dict) -> bool:
    """De naam onthouden van een verzoek met een echte login (geldig sessiecookie met 2FA), in elke stand: zo werkt
    zonder login later ook op die naam. True als er iets veranderde: dan moet de aanroeper bewaren."""
    name = host_of(conn)
    if not name or name in cfg["names"] or _is_ip(name) or name == "localhost" or len(name) > 253 \
            or not NAME.match(name):
        return False
    st = await ensure_state(db, NAMES_KEY, {})
    names = [n for n in ((st.value or {}).get("names") or []) if n != name] + [name]
    st.value = {"names": names[-MAX_NAMES:]}
    cfg["names"] = st.value["names"]
    return True


def own_ips() -> frozenset[str]:
    global _own
    if time.monotonic() - _own[0] > OWN_TTL:
        from .monitoring import upgrade
        _own = (time.monotonic(), upgrade.me().ips)
    return _own[1]


def _from_frontend(conn: HTTPConnection) -> bool:
    if conn.scope["type"] != "http":
        return True  # WebSockets: de Origin moet het eigen adres zijn (routers/ssh._ws_user)
    if conn.headers.get(CSRF_HEADER) == "homepage":
        return True
    return conn.headers.get("sec-fetch-site") in ("same-origin", "none")


async def check(conn: HTTPConnection, db: AsyncSession, cfg: dict | None = None) -> tuple[bool, str]:
    """(mag dit verzoek zonder login, waarom niet of van waar)."""
    ok, why, _ = await check_full(conn, db, cfg)
    return ok, why


async def check_full(conn: HTTPConnection, db: AsyncSession, cfg: dict | None = None) -> tuple[bool, str, bool]:
    """Zoals check(), en of het verzoek van buitenaf komt (alleen geldig als het mag)."""
    cfg = cfg or await settings(db)
    if cfg["mode"] == "uit":
        return False, "aanmelden staat aan", False
    ip = outside._ip(conn)
    if ip is None or ip.is_loopback or str(ip) in own_ips():
        return False, "geen bezoeker (het dashboard zelf)", False
    if not _from_frontend(conn):
        return False, "niet van het dashboard zelf", False
    name = host_of(conn)
    if not trusted(name, cfg):
        return False, (f"onbekend adres {name or '?'}: zonder login werkt alleen op een IP of op een naam waarop je al "
                       "eens met login binnenkwam"), False
    w = await outside.where(conn, db)
    if w["outside"] and (cfg["mode"] != "overal" or outside.forged(conn)):
        return False, "van buitenaf", True
    return True, w["why"], w["outside"]


async def home_user(db: AsyncSession) -> User | None:
    """Wie je zonder login bent: de eerste gebruiker, als die 2FA al ingesteld heeft (anders eerst de setup)."""
    user = (await db.execute(select(User).order_by(User.id).limit(1))).scalars().first()
    return user if user is not None and user.totp_enabled else None


def transient(user: User, conn: HTTPConnection) -> Session:
    """Een sessie die alleen voor dit verzoek bestaat. Nooit db.add/delete/merge: ze staat niet in de database."""
    now = _now()
    s = Session(id=f"zonder-login:{user.id}", user_id=user.id, mfa_ok=True, created_at=now, auth_at=now,
                expires_at=now + timedelta(hours=1), ip=conn.client.host if conn.client else None,
                user_agent=(conn.headers.get("user-agent") or "")[:255] or None, country=None, last_seen_at=now)
    set_committed_value(s, "user", user)
    s.zonder_login = True
    s.vluchtig = True
    return s


async def logged_in(conn: HTTPConnection, db: AsyncSession) -> bool:
    """Heeft dit verzoek een echte login (een geldig sessiecookie met 2FA)?"""
    token = conn.cookies.get(COOKIE)
    if not token:
        return False
    s = await db.get(Session, token_id(token))
    if s is None or not (s.mfa_ok and s.user.totp_enabled):
        return False
    return s.expires_at.replace(tzinfo=s.expires_at.tzinfo or timezone.utc) > _now()


async def outside_without_login(conn: HTTPConnection, db: AsyncSession) -> bool:
    """Overal zonder login en zonder echte login: dan blijven van buitenaf de gevaarlijke functies dicht. (Of het
    verzoek van buitenaf komt, kijkt de aanroeper.)

    Loopt dit verzoek zonder login (deps.optional_session, routers/ssh._ws_user), dan altijd: de stand opnieuw lezen
    volstaat niet. Wie van buitenaf aanmelden strenger zet (dat mag zonder login), zou anders zijn eigen verzoeken die
    nog zonder login lopen langs deze controle krijgen."""
    if getattr(conn.state, "zonder_login", False) or getattr(conn.state, "zonder_cookie", False):
        return True
    return (await settings(db))["mode"] == "overal" and not await logged_in(conn, db)


async def need_login_outside(conn: HTTPConnection, db: AsyncSession, sess: Session | None = None) -> None:
    """Voor wat bepaalt wie er mag inloggen (Authentik, het wachtwoord): van buitenaf alleen met een echte login, en
    dan met een verse 2FA, zoals met aanmelden aan. Anders stelt wie het adres kent (of een gestolen cookie heeft) zijn
    eigen Authentik in, logt daarmee echt in en kan dan ook de terminal aanzetten."""
    if not (await outside.where(conn, db))["outside"]:
        return
    if await outside_without_login(conn, db):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Zonder login kan je dit van buitenaf niet wijzigen. Thuis wel.")
    if sess is not None and getattr(sess, "zonder_buiten", False):
        await fresh_auth(sess, sess.user)
