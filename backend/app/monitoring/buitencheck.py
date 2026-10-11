"""Check van buitenaf: een gratis Cloudflare Worker bekijkt de gekozen tegels vanuit het netwerk van Cloudflare, zoals
een bezoeker op het internet. De gewone checks lopen van binnenuit (meestal rechtstreeks naar de server, zonder DNS
en NPM): die zien een tunnel, port forward, NPM, DNS-record of certificaat dat van buitenaf stuk is niet.

Bewuste keuze: het dashboard roept de Worker aan (elke minuut een POST met een vijfde van de lijst, de tegels met het
oudste resultaat eerst), en de Worker antwoordt met de statuscodes. De Worker heeft geen planning (cron trigger), geen
lijst en geen opslag, en duwt niets naar het dashboard. Een Worker die zelf naar /api/push zou sturen, komt binnen
langs dezelfde weg (Cloudflare → tunnel of poort 443 → NPM) die hij moet testen: is die weg stuk, dan komt er niets
aan, en weet het dashboard niet waarom. Zo gaat de vraag naar buiten, en komt de precieze fout per tegel (1033 tunnel
weg, 521 NPM weigert, time-out) toch binnen. Er is dus ook geen ingang van buitenaf, en geen uitzondering in Cloudflare
Access of Authentik nodig.

Opslag (AppState, geen eigen tabel):
- buitencheck: de instellingen (lijst, adres van de Worker, het geheim versleuteld, een nieuw geheim dat wacht). De API
  schrijft ze; de worker zet alleen een wachtend geheim in gebruik als de Worker het al kent (promote).
- buitencheck_state: de toestand per tegel, de Worker, een massastoring en groepen. Alleen de worker schrijft ze. Los
  van ServiceState: zo kan een tegel thuis werken en van buitenaf niet ("thuis ok · buiten down").

Meldingen: alleen het meldingencentrum en web push (notify, engine.alert). Een tegel die thuis al stuk, gepauzeerd of
in onderhoud is, waarvan de ouder, NPM of de tunnel al gemeld is, of die bij een massastoring of groep hoort, blijft
stil. Is die reden voorbij, dan begint de tegel opnieuw: pas 2 nieuwe mislukte checks geven een melding. Vallen er
meerdere tegels om dezelfde reden uit (GROUP_MIN), dan één melding voor allemaal.
"""

import math
import re
import secrets
from collections import Counter
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit, urlunsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..deps import event, notify
from ..integrations.base import _net_reason
from ..models import AppState, Service, ServiceState
from ..security import decrypt
from . import engine, routes
from .checks import _accept_rule, _request_parts, accepted, target_for
from .push import TZ

CONFIG_KEY = "buitencheck"
STATE_KEY = "buitencheck_state"
NAME_PREFIX = "homepage-buitencheck-"   # + 8 hex, één keer per installatie (config.name)
SCRIPT_VERSION = 1                      # ook in buitencheck_worker.mjs; een test kijkt of ze gelijk zijn
SCRIPT = (Path(__file__).with_name("buitencheck_worker.mjs")).read_text()
COMPAT_DATE = "2025-06-01"              # vanaf 2024-11-11 kent fetch(..., {cache: "no-store"})
EVERY = 60                              # één vraag per minuut
ROUNDS = 5                              # elke tegel om de 5 rondes
PER_CALL = 45                           # gratis plan: 50 subrequests per verzoek
MAX_TILES = ROUNDS * PER_CALL           # 225
CALL_TIMEOUT = 90.0                     # ergste geval 45 adressen / 6 tegelijk × 8 s ≈ 64 s
DOWN_AFTER = 2
STALE = timedelta(minutes=16)           # 3 rondes geen resultaat: "wacht"
WORKER_FAIL_AFTER = 5                   # zoveel rondes na elkaar voor "werkt niet"
GROUP_MIN = 3                           # dezelfde oorzaak op zoveel tegels: één melding
GROUP_WAVE = timedelta(minutes=10)      # twee volle rondes: wat in die tijd faalde, hoort bij dezelfde golf
PASTE_GRACE = timedelta(hours=1)        # zolang een nieuw geheim zo lang wacht, is een 404 geen kapotte Worker
LOCK = "buitencheck-geheim"             # naam voor db.job_lock: geheim, zetten en in gebruik nemen nooit tegelijk
WORKERS_DEV = re.compile(r"^https://([a-z0-9-]{1,63})\.([a-z0-9-]{1,63})\.workers\.dev/?$")
TUNNEL_CAUSES = {"cfe:1033", "http:530"}
# Hoe recent een nieuw publiek IP moet zijn om het als hint te noemen.
IP_RECENT = timedelta(minutes=30)
# In een melding over een groep: zoveel namen, dan "en n meer".
NAMES_SHOWN = 8

CF_CODES = {
    1033: "de Cloudflare Tunnel is niet verbonden (1033)",
    1016: "Cloudflare vindt het doel achter de naam niet (1016)",
    1000: "de DNS-record wijst naar een verboden IP (1000)",
    1014: "CNAME naar een ander Cloudflare-account (1014)",
    1020: "een WAF-regel van Cloudflare blokkeert de check (1020)",
    1010: "Cloudflare blokkeert de check op zijn browserkenmerk (1010)",
}
CF_HTTP = {
    520: "NPM of de app gaf een leeg of vreemd antwoord (520)",
    521: "NPM weigert de verbinding (521)",
    522: "Cloudflare krijgt geen verbinding met je thuisnetwerk (522)",
    523: "je thuisnetwerk is onbereikbaar voor Cloudflare (523)",
    524: "de app antwoordt te traag (524)",
    525: "TLS tussen Cloudflare en NPM mislukt (525)",
    526: "ongeldig certificaat op NPM (526)",
    530: "Cloudflare bereikt je thuisnetwerk niet (530)",
}
NOT_ALLOWED = "valt buiten ALLOWED_SUFFIXES van de Worker: zet de Worker opnieuw"
TIMEOUT_WHY = ("geen antwoord binnen 8 s: Cloudflare bereikt je thuisnetwerk niet (poort 443, tunnel of NPM), of de "
               "app is erg traag")
CHALLENGE = "Cloudflare houdt de check tegen met een uitdaging (Bot Fight Mode, Under Attack of een WAF-regel)"
UNKNOWN_SECRET = ("De Worker kent het geheim niet, of het adres klopt niet: zet de Worker opnieuw of plak het geheim "
                  "opnieuw")
NOT_HOME = "Van thuis uit is bij deze tegels geen storing bekend."

CONFIG = {"enabled": False, "name": None, "worker_url": None, "token": None, "token_at": None, "token_next": None,
          "token_next_at": None, "suffixes": None, "api_id": None, "services": [], "how": None, "deployed": None}


class Target(NamedTuple):
    """Wat de Worker ophaalt en hoe het antwoord beoordeeld wordt. login_ok: het adres van de tegel (niet het doel van
    de check), dan telt 401/403 als "NPM bereikt"."""
    url: str
    rule: dict
    login_ok: bool


class Verdict(NamedTuple):
    """cause: een korte sleutel om tegels te groeperen die om dezelfde reden falen (bv. cfe:1033, time-out)."""
    ok: bool
    why: str | None
    note: str | None
    cause: str | None


class Reply(NamedTuple):
    data: dict | None
    err: str | None
    code: int | None


def iso(dt: datetime) -> str:
    """Altijd hetzelfde formaat in UTC: zo sorteren de tijden als tekst in de juiste volgorde (pick)."""
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")


def _dt(s) -> datetime | None:
    if not s:
        return None
    try:
        d = datetime.fromisoformat(str(s))
    except ValueError:
        return None
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def hhmm(dt) -> str:
    d = _dt(dt) if not isinstance(dt, datetime) else dt
    return d.astimezone(TZ).strftime("%H:%M") if d else "?"


def _cap(s: str | None) -> str:
    return (s[:1].upper() + s[1:]) if s else ""


# --- instellingen en toestand ----------------------------------------------------------------------------------

def _is_ip(host: str) -> bool:
    try:
        ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def host_of(url: str | None) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except ValueError:
        return ""


async def default_suffixes(db: AsyncSession) -> list[str]:
    """De laatste twee labels van de meest voorkomende https-naam op de tegels (bv. jbogaert.be)."""
    count = Counter()
    for url in (await db.execute(select(Service.url).where(Service.url.is_not(None)))).scalars():
        if not str(url).lower().startswith("https://"):
            continue
        host = host_of(url)
        if host and not _is_ip(host) and host.count(".") >= 1:
            count[".".join(host.split(".")[-2:])] += 1
    return [count.most_common(1)[0][0]] if count else []


async def config(db: AsyncSession) -> dict:
    st = await db.get(AppState, CONFIG_KEY)
    cfg = {**CONFIG, **(st.value if st and isinstance(st.value, dict) else {})}
    cfg["services"] = [int(x) for x in cfg.get("services") or []]
    if not cfg["suffixes"]:
        cfg["suffixes"] = await default_suffixes(db)
    return cfg


def _state_defaults(v: dict | None) -> dict:
    v = dict(v or {})
    v["tiles"] = dict(v.get("tiles") or {})
    v["worker"] = dict(v.get("worker") or {})
    v.setdefault("mass", None)
    v["groups"] = dict(v.get("groups") or {})
    v.setdefault("round_at", None)
    return v


async def state(db: AsyncSession) -> dict:
    st = await db.get(AppState, STATE_KEY)
    return _state_defaults(deepcopy(st.value) if st and isinstance(st.value, dict) else None)


async def config_for_update(db: AsyncSession) -> AppState:
    """De instellingen vergrendeld (SELECT ... FOR UPDATE) en vers gelezen, voor elke wijziging. Met een naam voor de
    Worker als die er nog niet is: willekeurig per installatie, zodat het publieke workers.dev-adres niet te raden is."""
    await ensure_state(db, CONFIG_KEY, {})
    st = (await db.execute(select(AppState).where(AppState.key == CONFIG_KEY).with_for_update()
                           .execution_options(populate_existing=True))).scalar_one()
    if not (st.value or {}).get("name"):
        st.value = {**(st.value or {}), "name": NAME_PREFIX + secrets.token_hex(4)}
    return st


def _decrypt(v: str | None) -> str | None:
    if not v:
        return None
    try:
        return decrypt(v)
    except Exception:  # noqa: BLE001 - een andere sleutel of een kapotte waarde: dan is er geen geheim
        return None


async def promote(db: AsyncSession, secret: str, now: datetime | None = None, **extra) -> bool:
    """Het wachtende geheim in gebruik nemen, alleen als het nog altijd het geheim is dat net werkte (vergelijken en
    wisselen onder het slot op de rij: een nieuw geheim dat intussen klaargezet werd, blijft wachten). extra komt
    alleen in de instellingen als het lukt (bv. enabled bij de eerste keer zelf plakken)."""
    now = now or datetime.now(timezone.utc)
    st = await config_for_update(db)
    v = dict(st.value)
    if not v.get("token_next") or _decrypt(v["token_next"]) != secret:
        return False
    v.update(token=v["token_next"], token_at=iso(now), token_next=None, token_next_at=None, **extra)
    st.value = v
    event(db, "wijziging", "Nieuw geheim voor de check van buitenaf in gebruik",
          "Cloudflare had het nieuwe geheim al; het vorige werkt niet meer.")
    return True


# --- wat er gecheckt wordt ---------------------------------------------------------------------------------------

def _https(url: str | None) -> str | None:
    """Het adres zoals de Worker het ophaalt: https met een naam (geen IP), zonder #, een leeg pad wordt /."""
    if not url:
        return None
    try:
        p = urlsplit(str(url).strip())
        host = p.hostname
    except ValueError:
        return None
    if p.scheme.lower() != "https" or not host or _is_ip(host):
        return None
    return urlunsplit(("https", p.netloc, p.path or "/", p.query, ""))


def target(service) -> Target | None:
    """Een gewone GET van binnenuit (zonder eigen headers of body) naar een https-naam: hetzelfde doel, met dezelfde
    goede statuscodes. Anders (POST of HEAD, een API-sleutel in een header, een body, een andere soort check, een IP
    of http als doel) het adres van de tegel, met de standaardregel (< 400) en 401/403 als "NPM bereikt"."""
    check = service.check or {}
    if check.get("type") == "http":
        _, method, _, _, _, body = _request_parts(check)
        if method == "GET" and not check.get("headers") and body is None:
            try:
                url = _https(target_for(check, service.url))
            except ValueError:
                url = None
            if url:
                return Target(url, check, False)
    url = _https(service.url)
    return Target(url, {}, True) if url else None


def under(host: str, suffixes: list[str]) -> bool:
    host = host.lower()
    return any(host == s or host.endswith("." + s) for s in suffixes)


def eligible(service, suffixes: list[str]) -> tuple[Target | None, str | None]:
    """(doel, None) als de tegel van buitenaf gecheckt kan worden, anders (None, waarom niet)."""
    t = target(service)
    if t is None:
        url = (service.url or "").strip()
        if not url:
            return None, "geen adres"
        if not url.lower().startswith("https://"):
            return None, "geen https-adres"
        return None, "IP-adres" if _is_ip(host_of(url)) else "geen https-adres"
    if not under(host_of(t.url), suffixes):
        return None, f"niet onder {' of '.join(suffixes)}" if suffixes else "geen domein ingesteld"
    return t, None


def pick(ids: list[int], tiles: dict) -> list[int]:
    """De tegels met het oudste resultaat (nog geen resultaat eerst), een vijfde van de lijst. Geen klok: een ronde die
    overgeslagen werd of mislukte (dan komt er geen nieuw resultaat), stuurt de volgende keer dezelfde tegels."""
    n = min(PER_CALL, math.ceil(len(ids) / ROUNDS))
    return sorted(ids, key=lambda sid: ((tiles.get(str(sid)) or {}).get("at") or "", sid))[:n]


def npm_access(table: routes.Table, host: str) -> bool:
    """Staat er in NPM een toegangslijst op deze naam? Van buitenaf geeft die 401 of 403."""
    e = table.entry(host)
    return bool(e and (e.get("access_list") or e.get("why") == "toegangslijst in NPM"))


def reset_text(now: datetime) -> str:
    """Wanneer de dagelijkse limiet van Cloudflare weer vrij is (00:00 UTC), in Belgische tijd."""
    midnight = (now.astimezone(timezone.utc) + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    return midnight.astimezone(TZ).strftime("%H:%M")


def judge(r: dict, t: Target, npm_access: bool) -> Verdict:
    """Eén antwoord van de Worker beoordelen. De volgorde telt: eerst wat Cloudflare zelf zegt."""
    c, e = r.get("c") or 0, r.get("e")
    if e == "niet toegelaten":
        return Verdict(False, NOT_ALLOWED, None, "suffix")
    if c == 0:
        if e == "time-out":
            return Verdict(False, TIMEOUT_WHY, None, "time-out")
        e = str(e or "onbekend")
        return Verdict(False, f"geen antwoord: {e}", None, f"net:{e[:40]}")
    if r.get("cfm") == "challenge":
        return Verdict(False, CHALLENGE, None, "challenge")
    cfe = r.get("cfe")
    if cfe in CF_CODES:
        return Verdict(False, CF_CODES[cfe], None, f"cfe:{cfe}")
    if 520 <= c <= 530:
        return Verdict(False, CF_HTTP.get(c, f"HTTP {c}"), None, f"http:{c}")
    if 300 <= c < 400:
        # Niet gevolgd: elke stap zou een subrequest kosten.
        to = host_of(r.get("loc"))
        if to == "cloudflareaccess.com" or to.endswith(".cloudflareaccess.com"):
            return Verdict(True, None, "achter Cloudflare Access: alleen tot Cloudflare getest", None)
        if to and to != host_of(t.url):
            if t.rule.get("same_host"):
                return Verdict(False, f"Doorverwezen naar {to} (loginpagina?)", None, f"redirect:{to}")
            return Verdict(True, None, f"verwijst door naar {to}", None)
        return Verdict(True, None, None, None)
    if c in (401, 403) and npm_access:
        return Verdict(True, None, "achter toegangslijst in NPM: alleen tot NPM getest", None)
    if c in (401, 403) and t.login_ok:
        return Verdict(True, None, f"NPM bereikt; de app vraagt een login ({c})", None)
    if accepted(c, t.rule):
        return Verdict(True, None, None, None)
    if c in (502, 504):
        if r.get("srv") == "nginx":
            return Verdict(False, f"NPM bereikt de app niet ({c})", None, f"http:{c}:npm")
        return Verdict(False, f"de tunnel of NPM bereikt het doel niet ({c})", None, f"http:{c}")
    rule = _accept_rule(t.rule)
    return Verdict(False, f"HTTP {c}" + (f" (verwacht {rule})" if rule else ""), None, f"http:{c}")


def tile_view(entry: dict | None, now: datetime | None = None) -> dict:
    """Wat de tegel toont: up, down, of wacht (nog geen of geen vers resultaat, of opnieuw begonnen)."""
    now = now or datetime.now(timezone.utc)
    e = entry or {}
    at = _dt(e.get("at"))
    status = e.get("status")
    if not status or not at or now - at > STALE:
        status = "wacht"
    return {"status": status, "since": e.get("since"), "at": e.get("at"), "why": e.get("why"), "note": e.get("note"),
            "colo": e.get("colo"), "ms": e.get("ms"), "code": e.get("code"), "quiet": e.get("quiet")}


async def tile_views(db: AsyncSession, now: datetime, existing) -> dict[int, dict]:
    """Voor /api/status: wat elke tegel uit de lijst van buitenaf ziet, alleen als de check draait (zoals run_round).
    existing: de ids van de tegels die nog bestaan."""
    st = await db.get(AppState, CONFIG_KEY)
    cfg = {**CONFIG, **(st.value if st and isinstance(st.value, dict) else {})}
    if not cfg["enabled"] or not cfg["worker_url"] or not cfg["token"]:
        return {}
    tiles = (await state(db))["tiles"]
    return {int(sid): tile_view(tiles.get(str(sid)), now) for sid in cfg["services"] or [] if int(sid) in existing}


def worker_calls(account: str, name: str, suffixes: list[str]) -> list[dict]:
    """De calls naar Cloudflare om de Worker te zetten, één keer gebouwd voor de proef en het echte werk. Het geheim
    staat er als plaatshouder in: run_worker_calls zet het echte alleen in de verzonden inhoud."""
    return [
        {"method": "PUT", "path": f"/accounts/{account}/workers/scripts/{name}", "kind": "upload",
         "data": {"main_module": "worker.js", "compatibility_date": COMPAT_DATE,
                  "bindings": [{"type": "secret_text", "name": "HOMEPAGE_TOKEN", "text": "(geheim, wordt niet getoond)"},
                               {"type": "plain_text", "name": "ALLOWED_SUFFIXES", "text": ",".join(suffixes)}]}},
        {"method": "POST", "path": f"/accounts/{account}/workers/scripts/{name}/subdomain", "kind": "subdomain",
         "data": {"enabled": True, "previews_enabled": False}},
    ]


# --- de Worker aanroepen -----------------------------------------------------------------------------------------

async def call_worker(client: httpx.AsyncClient, url: str, token: str, checks: list[dict],
                      now: datetime | None = None) -> Reply:
    """POST <worker>/check met de lijst. Nooit een uitzondering: een fout komt als Nederlandse tekst terug."""
    now = now or datetime.now(timezone.utc)
    try:
        r = await client.post(url.rstrip("/") + "/check", json={"v": 1, "checks": checks},
                              headers={"Authorization": f"Bearer {token}", "User-Agent": "homepage-buitencheck"},
                              timeout=CALL_TIMEOUT, follow_redirects=False)
    except httpx.TimeoutException:
        return Reply(None, "De Worker antwoordde niet binnen 90 s", None)
    except httpx.HTTPError as e:
        return Reply(None, f"Worker niet bereikbaar: {_net_reason(e)}", None)
    code = r.status_code
    if code == 404:
        return Reply(None, UNKNOWN_SECRET, code)
    if code >= 400:
        body = r.text[:4000].lower()
        if "error code: 1027" in body:
            return Reply(None, f"Dagelijkse limiet van het gratis plan op (1027): om {reset_text(now)} werkt het weer",
                         code)
        if "1102" in body:
            return Reply(None, "De Worker liep tegen de CPU-limiet van het gratis plan (1102)", code)
        if "1101" in body:
            return Reply(None, "De Worker liep vast (1101): zet hem opnieuw. Helpt dat niet: zet bij de Worker in "
                         "Cloudflare de logs aan en test opnieuw", code)
        if code == 429 or "1015" in body:
            return Reply(None, "Cloudflare: te veel verzoeken (1015)", code)
        return Reply(None, f"Worker gaf HTTP {code}", code)
    try:
        data = r.json()
    except ValueError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        return Reply(None, "Onverwacht antwoord van de Worker", code)
    return Reply(data, None, code)


# --- de toestand van thuis uit -----------------------------------------------------------------------------------

@dataclass
class Inside:
    """Wat het dashboard van binnenuit weet, voor de stille redenen. Eén keer per ronde gelezen."""
    reasons: dict[int, str] = field(default_factory=dict)
    up: set[int] = field(default_factory=set)
    npm_down: bool = False
    dashboard: bool = False
    tdown: list[tuple[str, str]] = field(default_factory=list)
    ip_error: str | None = None
    ip_since: datetime | None = None

    def reason(self, sid: int) -> str | None:
        return self.reasons.get(int(sid))


async def inside(db: AsyncSession, now: datetime) -> Inside:
    rows = (await db.execute(select(Service.id, Service.parent_id, Service.check, Service.maintenance_until,
                                    Service.type))).all()
    svcs = {r[0]: r for r in rows}
    states = {st.service_id: st for st in (await db.execute(select(ServiceState))).scalars()}

    def failing(sid: int) -> bool:
        st = states.get(sid)
        return bool(st and (st.status == "down" or st.fail_count > 0))

    def chain(sid: int):
        seen, p = {sid}, svcs[sid][1]
        while p and p not in seen and p in svcs:
            seen.add(p)
            yield p
            p = svcs[p][1]

    ctx = Inside()
    for sid, _, check, until, typ in rows:
        check = check if isinstance(check, dict) else {}
        on = engine.active(check)
        if any((engine._aware(svcs[x][3]) or now) > now for x in [sid, *chain(sid)]):
            ctx.reasons[sid] = "onderhoud"
        elif check.get("type") and check.get("paused"):
            ctx.reasons[sid] = "pauze"
        elif on and failing(sid):
            ctx.reasons[sid] = "thuis"
        # Zoals engine._failing: een ouder zonder lopende check of met meldingen uit zegt niets.
        elif any(engine.active(svcs[a][2]) and (svcs[a][2] or {}).get("notify") != "uit" and failing(a)
                 for a in chain(sid)):
            ctx.reasons[sid] = "ouder"
        if on and not failing(sid) and states.get(sid) and states[sid].status == "up":
            ctx.up.add(sid)
        if typ == "npm" and on and failing(sid):
            ctx.npm_down = True
    ctx.dashboard = await engine.in_mass_outage(db)
    for st in (await db.execute(select(AppState).where(AppState.key.like("net_tunnel:%")))).scalars():
        for t in (st.value or {}).get("items") or []:
            if isinstance(t, dict) and t.get("status") in ("down", "inactive"):
                ctx.tdown.append((str(t.get("name") or "?"), t["status"]))
    ip = await db.get(AppState, "public_ip")
    v = ip.value if ip and isinstance(ip.value, dict) else {}
    ctx.ip_error = v.get("error") or None
    since = _dt(v.get("since"))
    if since and now - since <= IP_RECENT and (v.get("history") or []):
        ctx.ip_since = since
    return ctx


def _hints(ctx: Inside) -> str:
    out = [f"Tunnel {name} is {status} (al gemeld)." for name, status in ctx.tdown]
    if ctx.ip_since:
        out.append(f"Je publieke IP veranderde om {hhmm(ctx.ip_since)}: kloppen de DNS-records nog?")
    return " ".join(out)


def _with_hints(body: str, ctx: Inside) -> str:
    h = _hints(ctx)
    return f"{body} {h}" if h else body


def quiet_reason(sid: int, entry: dict, s: dict, ctx: Inside) -> str | None:
    """Waarom deze tegel nu niets meldt (en wie het Jonas al zei), of None."""
    if ctx.dashboard:
        return "dashboard"
    if s.get("mass"):
        return "massa"
    if r := ctx.reason(sid):
        return r
    if ctx.npm_down:
        return "npm"
    if entry.get("cause") in TUNNEL_CAUSES and ctx.tdown:
        return "tunnel"
    if any(int(sid) in [int(x) for x in g.get("tiles") or []] for g in s["groups"].values()):
        return "groep"
    return None


def _fresh(e: dict, now: datetime) -> bool:
    at = _dt(e.get("at"))
    return bool(at and now - at <= STALE)


def _names(names: list[str]) -> str:
    out = ", ".join(names[:NAMES_SHOWN])
    return out + (f" en {len(names) - NAMES_SHOWN} meer" if len(names) > NAMES_SHOWN else "")


MODE_RANK = {"push": 2, "centrum": 1, "uit": 0}


# --- een ronde ---------------------------------------------------------------------------------------------------

async def run_round(maker, http, now: datetime | None = None) -> None:
    """De taak van de worker, elke minuut: de tegels met het oudste resultaat door de Worker laten bekijken."""
    start = now or datetime.now(timezone.utc)
    async with maker() as db:
        cfg = await config(db)
        # Een wachtend geheim alleen draait niet: niets kan mislukken voor het eerste geheim bevestigd is.
        if not cfg["enabled"] or not cfg["worker_url"] or not cfg["token"]:
            return
        tiles = (await state(db))["tiles"]
        ids = cfg["services"]
        svcs = {s.id: s for s in (await db.execute(select(Service).where(Service.id.in_(ids)))).scalars()} if ids else {}
        targets = {sid: t for sid in ids if sid in svcs and (t := eligible(svcs[sid], cfg["suffixes"])[0])}
        sent = [{"i": sid, "u": targets[sid].url} for sid in pick(list(targets), tiles)]
        token = _decrypt(cfg["token"])
        nxt = _decrypt(cfg["token_next"])
        token_at = cfg["token_at"]
    # De sessie is dicht: geen open transactie terwijl de Worker tot 90 s bezig is.
    reply, worked = Reply(None, None, None), None
    if sent and token:
        client = http.get(False)
        reply = await call_worker(client, cfg["worker_url"], token, sent, start)
        if reply.code == 404 and nxt:
            # Kent de Worker het nieuwe geheim al (zelf geplakt)? Eén verzoek extra, alleen zolang er een wacht.
            reply = await call_worker(client, cfg["worker_url"], nxt, sent, start)
            worked = nxt if reply.data is not None else None
    async with maker() as db:
        await apply_round(db, sent, start, reply, token_at=token_at, tried_next=worked, pending=bool(nxt), now=now)
        await db.commit()


async def apply_round(db: AsyncSession, sent: list[dict], at: datetime, reply: Reply, *, token_at: str | None,
                      tried_next: str | None, pending: bool, now: datetime | None = None) -> None:
    """De antwoorden van een ronde verwerken: toestand per tegel, stille redenen, massastoring, groepen en alle
    meldingen. at: wanneer de ronde begon (elk resultaat krijgt die tijd); now: nu. tried_next: het wachtende geheim,
    als de Worker dat aanvaardde."""
    now = now or datetime.now(timezone.utc)
    cfg = await config(db)
    st = await ensure_state(db, STATE_KEY, {})
    s = _state_defaults(deepcopy(st.value) if isinstance(st.value, dict) else None)
    tiles, groups, w = s["tiles"], s["groups"], s["worker"]
    ids = set(cfg["services"]) | {int(k) for k in tiles}
    svcs = {x.id: x for x in (await db.execute(select(Service).where(Service.id.in_(ids)))).scalars()} if ids else {}
    listed = {sid: svcs[sid] for sid in cfg["services"] if sid in svcs}
    ctx = await inside(db, now)
    table = await routes.load(db)

    # Weg uit de lijst, verwijderd, of een ander adres: de draad op de gsm sluiten als hij als down gemeld was, en de
    # tegel vergeten (een nieuw adres begint opnieuw). Vóór de resultaten: die van een nieuw adres horen bij een nieuwe.
    for key, e in list(tiles.items()):
        sid = int(key)
        svc = svcs.get(sid)
        t = target(svc) if svc is not None else None
        if sid in listed and t is not None and t.url == e.get("url"):
            continue
        if e.get("status") == "down" and e.get("notified"):
            name = svc.name if svc is not None else e.get("name") or "?"
            if svc is not None:
                engine.alert(db, svc, f"{name}: niet meer van buitenaf gecheckt",
                             "Was onbereikbaar van buitenaf; de tegel staat niet meer in de lijst (of kreeg een ander "
                             "adres).", "ok", key=f"buiten{sid}")
            else:
                notify(db, f"{name}: niet meer van buitenaf gecheckt", "De tegel is verwijderd.", level="ok",
                       source="buitencheck", key=f"buiten{sid}", recovers="err", push=bool(e.get("pushed")))
        del tiles[key]
        for g in groups.values():
            g["tiles"] = [x for x in g.get("tiles") or [] if int(x) != sid]

    # De Worker zelf.
    if reply.err:
        waiting = _dt(cfg["token_next_at"])
        ignore = cfg["token_at"] != token_at or (reply.code == 404 and pending and waiting is not None
                                                 and now - waiting < PASTE_GRACE)
        if not ignore:
            w["fail"] = int(w.get("fail") or 0) + 1
            w["error"], w["error_at"] = reply.err, iso(now)
    elif reply.data is not None:
        w.update(fail=0, ok_at=iso(now), colo=reply.data.get("colo"), script=reply.data.get("script"), error=None)
        if w.get("notified"):
            notify(db, "De check van buitenaf werkt weer", None, level="ok", source="buitencheck", key="buiten-worker",
                   recovers="warn")
            w["notified"] = False
        if tried_next:
            await promote(db, tried_next, now)

    # Stille tegels waarvan de reden voorbij is: zonder melding opnieuw beginnen. Alleen resultaten die gevraagd werden
    # nadat dat gezien werd, tellen nog (zoals de checks van binnenuit na een stille periode).
    for key, e in tiles.items():
        if not e.get("quiet"):
            continue
        r = quiet_reason(int(key), e, s, ctx)
        if r is None:
            e.update(status=None, fail=0, quiet=None, notified=False, reset_at=iso(now))
        elif r != e["quiet"]:
            e["quiet"] = r

    # De resultaten.
    sent_url = {c["i"]: c["u"] for c in sent}
    new_down, recovered = [], []
    colo = (reply.data or {}).get("colo")
    for r in (reply.data or {}).get("results") or []:
        if not isinstance(r, dict):
            continue
        sid = r.get("i")
        svc = listed.get(sid) if isinstance(sid, int) else None
        t = target(svc) if svc is not None else None
        if t is None or sent_url.get(sid) != t.url:
            continue
        e = tiles.setdefault(str(sid), {"url": t.url, "status": None, "since": None, "fail": 0, "quiet": None,
                                        "notified": False, "pushed": False, "reset_at": None})
        v = judge(r, t, npm_access(table, host_of(t.url)))
        e.update(name=svc.name, at=iso(at), code=r.get("c"), ms=r.get("ms"), colo=colo, why=v.why, note=v.note,
                 cause=v.cause)
        reset = _dt(e.get("reset_at"))
        if reset and at <= reset:
            continue  # gevraagd voor de stille reden voorbij was: wel tonen, niet meetellen
        e["reset_at"] = None
        if v.ok:
            e["fail"] = 0
            if e.get("status") != "up":
                if e.get("status") == "down" and e.get("notified") and not e.get("quiet"):
                    recovered.append((sid, _dt(e.get("since")) or at))
                e.update(status="up", since=iso(at), quiet=None, notified=False)
        else:
            e["fail"] = int(e.get("fail") or 0) + 1
            if e["fail"] >= DOWN_AFTER and e.get("status") != "down":
                e.update(status="down", since=iso(at))
                new_down.append(sid)

    # Massastoring: wat thuis al verklaard is (een node die down is), telt niet als "van buitenaf onbereikbaar".
    fresh = {int(k): e for k, e in tiles.items() if _fresh(e, now) and ctx.reason(int(k)) is None}
    total = len(fresh)
    bad = [e for e in fresh.values() if int(e.get("fail") or 0) > 0]
    mass = s["mass"]
    if not mass and total >= engine.MASS_MIN and len(bad) >= engine.MASS_SHARE * total and not ctx.dashboard:
        why = Counter(e.get("why") or "?" for e in bad).most_common(1)[0][0]
        # Meldde de tunnelwachter of de NPM-tegel het al op de gsm, dan alleen hier.
        push = not (ctx.tdown or ctx.npm_down)
        s["mass"] = mass = {"since": iso(now), "failing": len(bad), "total": total, "why": why, "push": push}
        notify(db, "Van buitenaf is bijna niets bereikbaar",
               _with_hints(f"{len(bad)} van de {total} checks van buitenaf mislukken: {why}. {NOT_HOME}", ctx),
               level="err", source="buitencheck", key="buiten-massa", push=push)
    elif mass and len(bad) < engine.MASS_END_SHARE * total:
        s["mass"] = None
        notify(db, "Van buitenaf weer bereikbaar",
               f"Na {engine._fmt_duration(now - (_dt(mass.get('since')) or now))}. Wat nog stuk is, meldt het apart.",
               level="ok", source="buitencheck", key="buiten-massa", recovers="err", push=bool(mass.get("push")))

    # Nieuw down: stil, bij een groep, een nieuwe groep, of één melding per tegel.
    causes: dict[str, list[int]] = {}
    for sid in new_down:
        e = tiles[str(sid)]
        if r := quiet_reason(sid, e, s, ctx):
            e["quiet"] = r
            continue
        causes.setdefault(e.get("cause") or "?", []).append(sid)
    for cause, sids in causes.items():
        if cause in groups:
            groups[cause]["tiles"] = sorted({*map(int, groups[cause]["tiles"]), *sids})
            for sid in sids:
                tiles[str(sid)]["quiet"] = "groep"
            continue
        # Elke tegel komt om de 5 rondes aan de beurt: als de eerste zijn 2e fout heeft, hebben alle andere tegels
        # met dezelfde storing hun 1e al. De golf is dan compleet.
        wave = sorted(int(k) for k, e in tiles.items()
                      if _fresh(e, now) and (_dt(e.get("at")) or now) >= now - GROUP_WAVE and e.get("cause") == cause
                      and int(e.get("fail") or 0) >= 1 and not e.get("quiet") and ctx.reason(int(k)) is None)
        if len(wave) >= GROUP_MIN:
            members = [listed[x] for x in wave if x in listed]
            mode = max((engine.notify_mode(m) for m in members), key=lambda m: MODE_RANK.get(m, 2), default="push")
            why = tiles[str(sids[0])].get("why") or cause
            groups[cause] = {"cause": cause, "why": why, "since": iso(now), "tiles": wave, "peak": len(wave),
                             "mode": mode}
            title = f"{len(wave)} tegels van buitenaf onbereikbaar: {why}"
            body = _with_hints(f"{_names(sorted(m.name for m in members))}. {NOT_HOME}", ctx)
            if mode == "uit":
                event(db, "netwerk", title, body, "err")
            else:
                notify(db, title, body, level="err", source="buitencheck", key=f"buiten-groep:{cause}",
                       push=mode == "push")
            for sid in sids:
                tiles[str(sid)]["quiet"] = "groep"
            continue
        for sid in sids:
            e, svc = tiles[str(sid)], listed[sid]
            body = (f"{_cap(e.get('why'))}. Laatste check {hhmm(e.get('at'))} vanuit {e.get('colo') or '?'}."
                    + (" Thuis werkt het wel." if sid in ctx.up else ""))
            engine.alert(db, svc, f"{svc.name}: van buitenaf onbereikbaar", body, "err", {"buiten": True},
                         key=f"buiten{sid}")
            e.update(notified=True, pushed=engine.notify_mode(svc) == "push", name=svc.name)

    # Weer bereikbaar (alleen wat apart gemeld was).
    for sid, since in recovered:
        svc = listed[sid]
        engine.alert(db, svc, f"{svc.name} weer bereikbaar van buitenaf",
                     f"Was {engine._fmt_duration(at - since)} onbereikbaar van buitenaf.", "ok", key=f"buiten{sid}")

    # Einde van een groep: wat nog stuk is, komt de volgende ronde vrij en meldt het daarna apart.
    for cause, g in list(groups.items()):
        still = [x for x in g.get("tiles") or [] if (e := tiles.get(str(x))) and e.get("cause") == cause
                 and (e.get("status") == "down" or int(e.get("fail") or 0) > 0)]
        g["peak"] = max(int(g.get("peak") or 0), len(still))
        if len(still) < max(GROUP_MIN, math.ceil(engine.MASS_END_SHARE * g["peak"])):
            title = f"Van buitenaf weer bereikbaar: {g['peak'] - len(still)} van de {g['peak']} tegels"
            if g.get("mode") == "uit":
                event(db, "netwerk", title, "Wat nog stuk is, meldt het apart.", "ok")
            else:
                notify(db, title, "Wat nog stuk is, meldt het apart.", level="ok", source="buitencheck",
                       key=f"buiten-groep:{cause}", recovers="err", push=g.get("mode") == "push")
            del groups[cause]

    # De Worker werkt al een paar rondes niet. Niet als het dashboard zelf geen internet heeft (dat zegt het publieke
    # IP al) of thuis bijna niets bereikt.
    if (int(w.get("fail") or 0) >= WORKER_FAIL_AFTER and not w.get("notified") and not ctx.ip_error
            and not ctx.dashboard):
        notify(db, "De check van buitenaf werkt niet", w.get("error"), level="warn", source="buitencheck",
               key="buiten-worker")
        w["notified"] = True

    s["round_at"] = iso(now)
    st.value = s


# --- voorstel ----------------------------------------------------------------------------------------------------

async def suggestions(db: AsyncSession) -> dict:
    """Welke tegels voor de lijst in aanmerking komen, zonder iets op te vragen: alleen de tabel van NPM. Aangevinkt
    als NPM de naam kent zonder toegangslijst (of als er geen tabel is); de rest kiest Jonas zelf."""
    cfg = await config(db)
    listed = set(cfg["services"])
    table = await routes.load(db)
    suggest, other = [], []
    for s in (await db.execute(select(Service).order_by(Service.name, Service.id))).scalars():
        if s.id in listed:
            continue
        t, why = eligible(s, cfg["suffixes"])
        if t is None:
            other.append({"id": s.id, "name": s.name, "url": s.url, "why": why})
            continue
        host = host_of(t.url)
        e = table.entry(host)
        if e and e.get("why") == "staat uit in NPM":
            other.append({"id": s.id, "name": s.name, "url": t.url, "why": "staat uit in NPM"})
            continue
        npm = "toegangslijst in NPM" if npm_access(table, host) else "niet in NPM" if table.hosts and e is None else None
        suggest.append({"id": s.id, "name": s.name, "url": t.url, "npm": npm, "pick": npm is None})
    return {"suggest": suggest, "other": other}
