"""Check van buitenaf (Infrastructuur → Netwerk → check van buitenaf): de lijst met tegels, de instellingen, het geheim
dat het dashboard en de Worker delen, de Worker in Cloudflare zetten (proef en echt) of zelf plakken, en een test.

Het geheim (HOMEPAGE_TOKEN) en het workers_token komen nooit in de browser. Bij zelf plakken maakt de browser het
geheim en stuurt het alleen naar hier. Elk nieuw geheim wacht eerst als token_next: het vorige blijft gelden tot de
Worker het nieuwe kent (na de upload, na "ik heb het geplakt", of bij de volgende ronde van de worker). Alles wat het
geheim of de Worker verandert, loopt na elkaar (job_lock), en in gebruik nemen is vergelijken en wisselen onder het
slot op de rij (buitencheck.promote).
"""

import re
import secrets
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside, proef
from ..db import get_db, job_lock
from ..deps import audit, confirm_silence, current_session, current_user, event, recent_auth
from ..health import domains
from ..integrations import IntegrationError, from_api
from ..integrations.cloudflare import ACCOUNT_RE
from ..models import ApiConnection, Service, Session, User
from ..monitoring import buitencheck as bc
from ..monitoring import routes
from ..security import decrypt_json, encrypt
from . import integrations as integrations_router
from .apis import _apply_secrets, _touch

router = APIRouter(prefix="/api/buitencheck", tags=["buitencheck"])

# Van buitenaf standaard uit (Beveiliging → van buitenaf → acties): wat de Worker of zijn geheim verandert, of met de
# bewaarde sleutels Cloudflare of de Worker aanspreekt. Kijken mag altijd.
ACTIES = outside.guard("acties")
ACTIES_VERS = outside.guard("acties", fresh=True)
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,200}$")
BUSY = "Er loopt al een wijziging aan de Worker; probeer zo opnieuw"
NO_WORKER = "Nog geen Worker: zet hem eerst in Cloudflare (of plak hem zelf)"
PROEF_AFTER = ["Elke minuut stuurt het dashboard de tegels met het oudste resultaat naar de Worker; elke tegel wordt om "
               "de 5 minuten van buitenaf bekeken.",
               "Meldingen gaan alleen naar 🔔 en je gsm (web push), zoals bij de gewone checks."]
PROEF_WARN = ["Dit token kan alle Workers van je Cloudflare-account aanpassen. Gebruik er een apart token voor met alleen "
              "Workers Scripts → Edit, en haal het weg na het zetten."]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _names(names: list[str], n: int = 3) -> str:
    return ", ".join(names[:n]) + (f" en {len(names) - n} meer" if len(names) > n else "")


# --- Cloudflare-API's ------------------------------------------------------------------------------------------

async def _connections(db: AsyncSession) -> list[ApiConnection]:
    return list((await db.execute(select(ApiConnection).where(ApiConnection.kind == "cloudflared")
                                  .order_by(ApiConnection.name, ApiConnection.id))).scalars())


def _keys(a: ApiConnection) -> dict:
    try:
        return decrypt_json(a.secrets) if a.secrets else {}
    except Exception:  # noqa: BLE001 - onleesbaar (andere sleutel): dan geen geheimen
        return {}


def _account(a: ApiConnection) -> str:
    return str((a.config or {}).get("account") or "").strip().lower()


def _info(a: ApiConnection) -> dict:
    """Welke API, en of het workers_token en de account-id er zijn (nooit de waarden)."""
    return {"id": a.id, "name": a.name, "workers_token": bool(_keys(a).get("workers_token")),
            "account": bool(ACCOUNT_RE.match(_account(a)))}


def _choose(conns: list[ApiConnection], api_id: int | None) -> ApiConnection | None:
    """De gekozen API, anders de eerste met een workers_token, anders de eerste."""
    if api_id is not None and (a := next((c for c in conns if c.id == api_id), None)):
        return a
    return next((c for c in conns if _keys(c).get("workers_token")), None) or (conns[0] if conns else None)


async def _conn(db: AsyncSession, cfg: dict, api_id: int | None) -> ApiConnection | None:
    conns = await _connections(db)
    if api_id is not None and not any(c.id == api_id for c in conns):
        raise HTTPException(422, "Die Cloudflare-API bestaat niet (meer): kies er een in de lijst")
    return _choose(conns, api_id if api_id is not None else cfg["api_id"])


# --- controleren -----------------------------------------------------------------------------------------------

async def _clean_suffixes(db: AsyncSession, raw: list[str]) -> list[str]:
    hosts = [bc.host_of(u) for u in (await db.execute(select(Service.url).where(Service.url.is_not(None)))).scalars()
             if str(u).lower().startswith("https://")]
    out: list[str] = []
    for x in raw:
        # Minstens twee labels (domains.clean): de Worker mag nooit een heel topdomein ophalen.
        n = domains.clean(x)
        if not n:
            raise HTTPException(422, f"Geen geldig domein: {str(x)[:60]} (bv. jbogaert.be)")
        if not any(bc.under(h, [n]) for h in hosts):
            raise HTTPException(422, f"Geen tegel onder {n}")
        if n not in out:
            out.append(n)
    if not out:
        raise HTTPException(422, "Geef minstens één domein (bv. jbogaert.be)")
    return out


async def _still_eligible(db: AsyncSession, ids: list[int], suffixes: list[str]) -> None:
    if not ids:
        return
    bad = [s.name for s in (await db.execute(select(Service).where(Service.id.in_(ids)).order_by(Service.name))).scalars()
           if bc.eligible(s, suffixes)[0] is None]
    if bad:
        raise HTTPException(422, f"Haal eerst {_names(bad)} uit de lijst")


def _worker_url(raw: str) -> str:
    url = raw.strip().lower().rstrip("/")
    # Alleen workers.dev: thuis wijst elke naam onder je eigen domein naar NPM, dus een eigen domein kwam nooit bij
    # Cloudflare uit.
    if not bc.WORKERS_DEV.match(url):
        raise HTTPException(422, "Alleen het adres van de Worker op workers.dev: https://<naam>.<jouw naam>.workers.dev")
    return url


# --- overzicht -------------------------------------------------------------------------------------------------

async def _overview(db: AsyncSession) -> dict:
    now = _now()
    cfg, s = await bc.config(db), await bc.state(db)
    conns = await _connections(db)
    chosen = _choose(conns, cfg["api_id"])
    ids = cfg["services"]
    svcs = {x.id: x for x in (await db.execute(select(Service).where(Service.id.in_(ids)))).scalars()} if ids else {}
    ctx = await bc.inside(db, now)
    tiles = []
    for sid in ids:
        svc = svcs.get(sid)
        if svc is None:
            continue
        t, why = bc.eligible(svc, cfg["suffixes"])
        home = "up" if sid in ctx.up else {"thuis": "down"}.get(ctx.reason(sid) or "", ctx.reason(sid))
        tiles.append({"id": sid, "name": svc.name, "url": t.url if t else svc.url, "inside": home, "problem": why,
                      "vanbuiten": bc.tile_view(s["tiles"].get(str(sid)), now)})
    tiles.sort(key=lambda x: x["name"].lower())
    w, mass = s["worker"], s["mass"]
    return {
        "enabled": bool(cfg["enabled"]), "ready": bool(cfg["worker_url"] and cfg["token"]), "name": cfg["name"],
        "worker_url": cfg["worker_url"], "how": cfg["how"], "token_set": bool(cfg["token"]),
        "token_at": cfg["token_at"], "token_next_at": cfg["token_next_at"], "suffixes": cfg["suffixes"],
        "api": _info(chosen) if chosen else None, "apis": [_info(a) for a in conns],
        "deployed": cfg["deployed"], "script_version": bc.SCRIPT_VERSION,
        "worker": {k: w.get(k) for k in ("ok_at", "colo", "script", "error", "error_at", "fail")},
        "mass": {k: mass.get(k) for k in ("since", "failing", "total", "why")} if mass else None,
        "groups": [{"cause": c, "why": g.get("why"), "since": g.get("since"), "count": len(g.get("tiles") or [])}
                   for c, g in s["groups"].items()],
        "limits": {"per_call": bc.PER_CALL, "rounds": bc.ROUNDS, "max": bc.MAX_TILES,
                   "calls_per_day": 86400 // bc.EVERY},
        "tiles": tiles,
    }


@router.get("")
async def overview(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await _overview(db)


@router.get("/voorstel")
async def voorstel(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Welke tegels in aanmerking komen (alleen de tabel van NPM, geen vragen naar buiten)."""
    return await bc.suggestions(db)


@router.get("/script")
async def script(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Het script om zelf te plakken, met de instellingen erbij. Het geheim staat er niet in."""
    cfg = await bc.config(db)
    return {"name": cfg["name"], "version": bc.SCRIPT_VERSION, "script": bc.SCRIPT,
            "bindings": [{"name": "HOMEPAGE_TOKEN", "kind": "secret", "value": None},
                         {"name": "ALLOWED_SUFFIXES", "kind": "text", "value": ",".join(cfg["suffixes"])}]}


# --- instellingen en tegels ------------------------------------------------------------------------------------

class SettingsIn(BaseModel):
    # Wat niet meekomt, blijft zoals het was; worker_url null wist het adres.
    enabled: bool | None = None
    worker_url: str | None = Field(default=None, max_length=300)
    suffixes: list[str] | None = Field(default=None, min_length=1, max_length=10)
    api_id: int | None = None


@router.put("/settings", dependencies=[ACTIES_VERS])
async def settings(body: SettingsIn, request: Request, sess: Session = Depends(current_session),
                   user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    given = body.model_fields_set
    url = _worker_url(body.worker_url) if "worker_url" in given and body.worker_url else None
    suffixes = await _clean_suffixes(db, body.suffixes) if "suffixes" in given and body.suffixes is not None else None
    if "api_id" in given and body.api_id is not None and not any(c.id == body.api_id for c in await _connections(db)):
        raise HTTPException(422, "Die Cloudflare-API bestaat niet (meer): kies er een in de lijst")
    async with job_lock(db, bc.LOCK) as ok:
        if not ok:
            raise HTTPException(status.HTTP_409_CONFLICT, BUSY)
        st = await bc.config_for_update(db)
        v = {**bc.CONFIG, **st.value}
        old = dict(v)
        if suffixes is not None:
            await _still_eligible(db, [int(x) for x in v["services"] or []], suffixes)
            v["suffixes"] = suffixes
        if "worker_url" in given and url != old["worker_url"]:
            # Een ander adres kan echte resultaten vervangen door verzonnen: zoals de bewaking stilleggen.
            if old["worker_url"]:
                await confirm_silence(db, request, sess, user, "Check van buitenaf: Worker-adres gewijzigd",
                                      "buitencheck_url", gewist=url is None)
            if url:
                v["how"] = "plakken"
            v["worker_url"] = url
        if body.enabled is not None and body.enabled != bool(old["enabled"]):
            if not body.enabled:
                await confirm_silence(db, request, sess, user, "Check van buitenaf uitgezet", "buitencheck_off")
            v["enabled"] = body.enabled
        if "api_id" in given:
            v["api_id"] = body.api_id
        st.value = v
        # Geen adres van de Worker in de auditlog: die gaat mee in de diagnose.
        await audit(db, request, user, "buitencheck_settings", enabled=bool(v["enabled"]), suffixes=v["suffixes"],
                    worker_url="gewijzigd" if v["worker_url"] != old["worker_url"] else "zelfde", api_id=v["api_id"])
        await db.commit()
    return await _overview(db)


class TilesIn(BaseModel):
    add: list[int] = Field(default_factory=list, max_length=300)
    remove: list[int] = Field(default_factory=list, max_length=300)


@router.put("/tiles")
async def tiles(body: TilesIn, request: Request, sess: Session = Depends(current_session),
                user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Tegels toevoegen (zonder 2FA: dat is meer bewaking) of weghalen (2FA en een melding, zoals een check pauzeren)."""
    st = await bc.config_for_update(db)
    v = {**bc.CONFIG, **st.value}
    suffixes = v["suffixes"] or await bc.default_suffixes(db)
    listed = [int(x) for x in v["services"] or []]
    want = set(body.add) | set(body.remove)
    svcs = {s.id: s for s in (await db.execute(select(Service).where(Service.id.in_(want)))).scalars()} if want else {}
    add = [x for x in dict.fromkeys(body.add) if x not in listed]
    for sid in add:
        svc = svcs.get(sid)
        if svc is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Tegel niet gevonden")
        why = bc.eligible(svc, suffixes)[1]
        if why:
            raise HTTPException(422, f"{svc.name}: {why}")
    remove = [x for x in dict.fromkeys(body.remove) if x in listed]
    new = [x for x in listed if x not in remove] + add
    if len(new) > bc.MAX_TILES:
        raise HTTPException(422, f"Hoogstens {bc.MAX_TILES} tegels: dat is wat het gratis plan in 5 minuten haalt")
    gone = [svcs[x].name if x in svcs else f"#{x}" for x in remove]
    if remove:
        await confirm_silence(db, request, sess, user, f"Check van buitenaf weg voor {_names(gone)}",
                              "buitencheck_tiles_removed", count=len(remove), tegels=gone[:20])
    v["services"] = new
    v["suffixes"] = suffixes
    st.value = v
    await audit(db, request, user, "buitencheck_tiles", added=[svcs[x].name for x in add][:50], removed=gone[:50])
    await db.commit()
    return {"count": len(new)}


# --- het geheim ------------------------------------------------------------------------------------------------

class TokenIn(BaseModel):
    token: str


@router.post("/token", dependencies=[ACTIES_VERS])
async def token(body: TokenIn, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """Zelf plakken: het geheim dat de browser maakte, wacht tot de Worker het kent. Het vorige blijft gelden."""
    # Zelf nagekeken: de standaardfout van de validatie zou de waarde terugsturen.
    if not TOKEN_RE.match(body.token):
        raise HTTPException(422, "Het geheim moet 32 tot 200 tekens zijn (letters, cijfers, - en _)")
    async with job_lock(db, bc.LOCK) as ok:
        if not ok:
            raise HTTPException(status.HTTP_409_CONFLICT, BUSY)
        st = await bc.config_for_update(db)
        at = bc.iso(_now())
        st.value = {**st.value, "token_next": encrypt(body.token), "token_next_at": at}
        name = st.value["name"]
        await audit(db, request, user, "buitencheck_token_next")
        await db.commit()
    return {"name": name, "token_next_at": at}


@router.delete("/token-next")
async def cancel_token(request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    async with job_lock(db, bc.LOCK) as ok:
        if not ok:
            raise HTTPException(status.HTTP_409_CONFLICT, BUSY)
        st = await bc.config_for_update(db)
        st.value = {**st.value, "token_next": None, "token_next_at": None}
        await audit(db, request, user, "buitencheck_token_next_cancelled")
        await db.commit()
    return await _overview(db)


# --- testen ----------------------------------------------------------------------------------------------------

async def _test(db: AsyncSession, cfg: dict, secret: str, service_id: int | None) -> dict:
    """Eén vraag aan de Worker met dit geheim: een tegel uit de lijst (de gekozen, anders de eerste), of zonder
    tegels een lege lijst, die alleen bewijst dat de Worker het geheim kent. Bewaart niets van de tegel."""
    ids = cfg["services"]
    sid = service_id if service_id in ids else ids[0] if ids else None
    svc = await db.get(Service, sid) if sid is not None else None
    t = bc.eligible(svc, cfg["suffixes"])[0] if svc is not None else None
    table = await routes.load(db)
    # Geen open transactie terwijl de Worker antwoordt (tot 90 s).
    await db.commit()
    checks = [{"i": sid, "u": t.url}] if t else []
    reply = await bc.call_worker(integrations_router.clients.get(False), cfg["worker_url"], secret, checks)
    if reply.err:
        return {"ok": False, "error": reply.err}
    data = reply.data
    out = {"ok": True, "error": None, "service": None, "url": None, "code": None, "ms": None, "why": None,
           "note": None, "colo": data.get("colo"), "script": data.get("script")}
    r = next((x for x in data["results"] if isinstance(x, dict) and x.get("i") == sid), None) if t else None
    if r:
        v = bc.judge(r, t, bc.npm_access(table, bc.host_of(t.url)))
        out.update(ok=v.ok, service=svc.name, url=t.url, code=r.get("c"), ms=r.get("ms"), why=v.why, note=v.note)
    return out


class TestIn(BaseModel):
    service_id: int | None = None
    # Zelf plakken ("ik heb het geplakt"): met het wachtende geheim, en in gebruik nemen als de Worker het kent.
    next: bool = False


@router.post("/test", dependencies=[ACTIES])
async def test(body: TestIn, request: Request, user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    if not body.next:
        cfg = await bc.config(db)
        secret = bc._decrypt(cfg["token"])
        if not cfg["worker_url"] or not secret:
            raise HTTPException(422, NO_WORKER)
        return {**await _test(db, cfg, secret, body.service_id), "promoted": False}
    async with job_lock(db, bc.LOCK) as ok:
        if not ok:
            raise HTTPException(status.HTTP_409_CONFLICT, BUSY)
        cfg = await bc.config(db)
        secret = bc._decrypt(cfg["token_next"])
        if not cfg["worker_url"]:
            raise HTTPException(422, "Vul eerst het adres van je Worker in")
        if not secret:
            raise HTTPException(422, "Er wacht geen nieuw geheim: klik eerst op geheim maken")
        res = await _test(db, cfg, secret, body.service_id)
        promoted = False
        if res.get("error") is None:
            # De eerste keer (nog geen geheim in gebruik) gaat de check meteen aan.
            extra = {"enabled": True} if not cfg["token"] else {}
            promoted = await bc.promote(db, secret, **extra)
            if promoted:
                await audit(db, request, user, "buitencheck_token_in_gebruik")
            await db.commit()
    return {**res, "promoted": promoted}


# --- in Cloudflare zetten --------------------------------------------------------------------------------------

class DeployIn(BaseModel):
    rotate: bool = False
    # Uit het formulier: welke API en welke domeinen (anders wat bewaard is). Zetten bewaart ze.
    api_id: int | None = None
    suffixes: list[str] | None = Field(default=None, min_length=1, max_length=10)


def _shown(name: str | None) -> str:
    return name or f"{bc.NAME_PREFIX}… (wordt gemaakt)"


async def _plan(db: AsyncSession, cfg: dict, conn: ApiConnection | None, suffixes: list[str], rotate: bool) -> dict:
    """Wat zetten zou doen. Kijkt alleen (met het bewaarde workers_token: wie, bestaat de Worker al, workers.dev)."""
    name = cfg["name"]
    title = f"Check van buitenaf in Cloudflare zetten: Worker {_shown(name)}"
    checks = []

    def done() -> dict:
        return proef.plan(title, [], checks=checks, warnings=PROEF_WARN)

    if conn is None:
        checks.append(proef.check("Cloudflare-API met workers_token", False,
                                  "Nog geen Cloudflare-API: maak er een in API-beheer (soort Cloudflare Tunnel, met je "
                                  "account-id) en voeg het geheim workers_token toe"))
        return done()
    has = bool(_keys(conn).get("workers_token"))
    checks.append(proef.check(f"Cloudflare-API '{conn.name}' met workers_token", has,
                              None if has else "Voeg in API-beheer het geheim workers_token toe"))
    account = _account(conn)
    acc_ok = bool(ACCOUNT_RE.match(account))
    checks.append(proef.check("Account-id", acc_ok, f"{account[:6]}…" if acc_ok else "ontbreekt of klopt niet (32 tekens)"))
    if not has or not acc_ok:
        return done()
    integ = from_api(conn, None, integrations_router.clients)
    try:
        integ._workers()
    except IntegrationError as e:
        checks.append(proef.check("Adres van de API", False, str(e)))
        return done()
    # Geen open transactie tijdens de vragen aan Cloudflare.
    await db.commit()
    try:
        token_id = await integ.token_id()
        scripts = await integ.worker_scripts()
        sub = await integ.workers_subdomain()
    except IntegrationError as e:
        checks.append(proef.check("Token mag Workers lezen", False, str(e)))
        return done()
    checks.append(proef.check("Token mag Workers lezen", True))
    mine = next((w for w in scripts if name and w["id"] == name), None)
    if mine is None:
        checks.append(proef.check(f"Worker {_shown(name)}", True, "bestaat nog niet: wordt aangemaakt"))
    elif mine.get("etag") and mine["etag"] == (cfg["deployed"] or {}).get("etag"):
        checks.append(proef.check(f"Worker {name}", True, "bestaat al: wordt vervangen"))
    else:
        checks.append(proef.check(f"Worker {name}", None, "bestaat al en is niet door het dashboard gezet (etag wijkt "
                                                          "af): wordt overschreven"))
    checks.append(proef.check("workers.dev-naam", bool(sub), f"{sub}.workers.dev" if sub
                              else "nog geen: open in Cloudflare één keer Workers & Pages"))
    n = len(cfg["services"])
    per = min(bc.PER_CALL, -(-n // bc.ROUNDS))
    checks.append(proef.check("Tegels in de lijst", True if n else None,
                              f"{n} tegels, elke ronde de {per} met het oudste resultaat" if n
                              else "nog geen: kies ze onder voorstel"))
    if not sub:
        return done()
    shown = name or f"{bc.NAME_PREFIX}…"
    calls = bc.worker_calls(account, shown, suffixes)
    acc, machine = f"{account[:6]}…", f"Cloudflare-API (api.cloudflare.com), account {account[:6]}…"
    who = proef.api_who(token_id)
    new = rotate or not cfg["token"]
    steps = []
    if new:
        steps.append(proef.step("dashboard", "dashboard", "nieuw geheim maken (32 willekeurige bytes) en apart bewaren; "
                                "het huidige blijft gelden tot de upload lukt"))
    steps += [
        proef.step(machine, "cloudflare-api", f"PUT /accounts/{acc}/workers/scripts/{shown} (metadata + worker.js)",
                   who=who, data=calls[0]["data"], script=bc.SCRIPT,
                   on_fail="er verandert niets in Cloudflare, en het dashboard houdt het huidige geheim"),
        proef.step(machine, "cloudflare-api", f"POST /accounts/{acc}/workers/scripts/{shown}/subdomain", who=who,
                   data=calls[1]["data"],
                   on_fail="de Worker en het nieuwe geheim staan er wel, maar workers.dev staat uit: zet het aan bij de "
                           "Worker (Settings → Domains & Routes)"),
        proef.step("dashboard", "dashboard", ("nieuw geheim in gebruik nemen, " if new else "")
                   + f"Worker-adres bewaren (https://{shown}.{sub}.workers.dev), aanzetten, één testcheck"),
    ]
    return proef.plan(title, steps, checks=checks, after=PROEF_AFTER, warnings=PROEF_WARN)


@router.post("/deploy/proef", dependencies=[ACTIES])
async def deploy_proef(body: DeployIn, request: Request, user: User = Depends(current_user),
                       db: AsyncSession = Depends(get_db)):
    """Proef: wat In Cloudflare zetten zou doen. Leest met het bewaarde workers_token, verandert niets."""
    cfg = await bc.config(db)
    conn = await _conn(db, cfg, body.api_id)
    suffixes = await _clean_suffixes(db, body.suffixes) if body.suffixes is not None else cfg["suffixes"]
    plan = await _plan(db, cfg, conn, suffixes, body.rotate)
    # Alleen dit wordt bewaard: wie keek er met het bewaarde token in Cloudflare.
    await audit(db, request, user, "buitencheck_deploy_proef", api=conn.name if conn else None, rotate=body.rotate)
    await db.commit()
    return {"plan": plan}


@router.post("/deploy", dependencies=[ACTIES_VERS])
async def deploy(body: DeployIn, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """De Worker in Cloudflare zetten. Een nieuw geheim (rotate, of de eerste keer) wacht eerst als token_next en komt
    pas in gebruik als Cloudflare de upload aanvaardde; mislukt die, dan blijft alles bij het oude."""
    async with job_lock(db, bc.LOCK) as ok:
        if not ok:
            raise HTTPException(status.HTTP_409_CONFLICT, BUSY)
        cfg = await bc.config(db)
        conn = await _conn(db, cfg, body.api_id)
        if conn is None:
            raise HTTPException(422, "Nog geen Cloudflare-API: maak er een in API-beheer met je account-id en het "
                                "geheim workers_token")
        suffixes = await _clean_suffixes(db, body.suffixes) if body.suffixes is not None else cfg["suffixes"]
        if not suffixes:
            raise HTTPException(422, "Geef minstens één domein (bv. jbogaert.be)")
        await _still_eligible(db, cfg["services"], suffixes)
        integ = from_api(conn, None, integrations_router.clients)
        try:
            account, _ = integ._workers()
        except IntegrationError as e:
            raise HTTPException(422, str(e)) from e
        conn_id, conn_name = conn.id, conn.name
        # 1. Het geheim kiezen (een nieuw wacht apart), dan de rij vrijgeven: het slot blijft.
        st = await bc.config_for_update(db)
        v = {**bc.CONFIG, **st.value}
        name = v["name"]
        rotated = body.rotate or not v["token"]
        if rotated:
            secret = secrets.token_urlsafe(32)
            v.update(token_next=encrypt(secret), token_next_at=bc.iso(_now()))
        else:
            secret = bc._decrypt(v["token"])
            if not secret:
                raise HTTPException(422, "Het bewaarde geheim is onleesbaar: kies nieuw geheim")
        st.value = v
        await db.commit()
        # 2. Cloudflare, zonder open transactie.
        err, done, token_id, sub = None, {}, None, None
        try:
            token_id = await integ.token_id()
            sub = await integ.workers_subdomain()
            if not sub:
                raise IntegrationError("Nog geen workers.dev-naam: open in Cloudflare één keer Workers & Pages")
        except IntegrationError as e:
            err = e
        if err is None:
            done, err = await integ.run_worker_calls(bc.worker_calls(account, name, suffixes), secret, bc.SCRIPT)
        # 3. Opnieuw gelezen en vergrendeld: de worker kan het nieuwe geheim intussen al in gebruik genomen hebben.
        now = _now()
        st = await bc.config_for_update(db)
        v = {**bc.CONFIG, **st.value}
        if "upload" in done:
            if bc._decrypt(v["token_next"]) == secret:
                v.update(token=v["token_next"], token_at=bc.iso(now), token_next=None, token_next_at=None)
            v.update(worker_url=f"https://{name}.{sub}.workers.dev", enabled=True, how="api", api_id=conn_id,
                     suffixes=suffixes,
                     deployed={"at": bc.iso(now), "by": user.username, "version": bc.SCRIPT_VERSION,
                               "etag": done["upload"], "token_id": token_id, "name": name})
            await audit(db, request, user, "buitencheck_deployed", api=conn_name, account=f"{account[:6]}…",
                        etag=done["upload"], rotated=rotated, workers_dev="subdomain" in done)
            # Zonder de naam van de Worker: de tijdlijn gaat mee in de diagnose.
            event(db, "wijziging", "Check van buitenaf in Cloudflare gezet", f"Versie {bc.SCRIPT_VERSION} van het script.")
        else:
            if bc._decrypt(v["token_next"]) == secret:
                v.update(token_next=None, token_next_at=None)
            await audit(db, request, user, "buitencheck_deploy_failed", api=conn_name, fout=str(err)[:200])
        st.value = v
        await db.commit()
        if err is not None:
            if "upload" in done:
                raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"De Worker staat er, maar workers.dev staat niet aan: {err}")
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"{err}. Er veranderde niets in Cloudflare; de check "
                                "gebruikt nog het vorige geheim.")
        cfg = await bc.config(db)
        test_result = await _test(db, cfg, secret, None)
    return {"ok": True, "worker_url": cfg["worker_url"], "test": test_result, "workers_token_stored": True}


@router.delete("/workers-token")
async def remove_workers_token(request: Request, api_id: int | None = None, user: User = Depends(current_user),
                               db: AsyncSession = Depends(get_db)):
    """Het token met Workers Scripts → Edit weer uit API-beheer: het is alleen nodig om de Worker opnieuw te zetten."""
    cfg = await bc.config(db)
    conns = [c for c in await _connections(db) if _keys(c).get("workers_token")]
    conn = next((c for c in conns if c.id == (api_id if api_id is not None else cfg["api_id"])), None)
    if conn is None and api_id is None and len(conns) == 1:
        conn = conns[0]
    if conn is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Geen Cloudflare-API met een workers_token")
    _apply_secrets(conn, {"workers_token": None})
    _touch(conn)
    await audit(db, request, user, "buitencheck_workers_token_removed", api=conn.name)
    await db.commit()
    return await _overview(db)
