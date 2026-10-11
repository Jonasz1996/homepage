"""Check van buitenaf: een Cloudflare Worker bekijkt tegels vanuit het netwerk van Cloudflare (monitoring/buitencheck.py,
routers/buitencheck.py). De Worker en de API van Cloudflare zijn nagebootst (World)."""

import json
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from sqlalchemy import delete, select

from app.db import ensure_state, get_db
from app.main import app
from app.models import AppState, Notification, Service, ServiceState
from app.monitoring import buitencheck as bc
from app.monitoring.checks import HttpClients
from app.security import encrypt

from .test_capacity import _db
from .test_integrations import _group

NAME = "homepage-buitencheck-ab12cd34"
WORKER = f"https://{NAME}.jonas.workers.dev"
SECRET_A = "A" * 43
SECRET_B = "B" * 43
T0 = datetime(2026, 10, 12, 9, 0, tzinfo=timezone.utc)
TUNNEL = {"c": 530, "cfe": 1033}


def _maker():
    """Zoals async_sessionmaker, op de testdatabase. open: hoeveel sessies er nu open zijn."""
    factory = app.dependency_overrides[get_db]
    count = [0]

    @asynccontextmanager
    async def make():
        gen = factory()
        count[0] += 1
        try:
            yield await anext(gen)
        finally:
            count[0] -= 1
            await gen.aclose()
    make.open = count
    return make


class World:
    """Nagebootst: de Worker op workers.dev en de API van Cloudflare."""

    def __init__(self):
        self.secret = SECRET_A          # wat Cloudflare als HOMEPAGE_TOKEN heeft
        self.results: dict[str, dict] = {}
        self.checks: list[tuple[str, dict]] = []  # (bearer, body) per POST /check
        self.reply: tuple[int, str] | None = None
        self.hook = None
        self.cf: list[httpx.Request] = []
        self.fail_upload = False
        self.scripts: list[dict] = []
        self.uploads: list[bytes] = []
        self.hosts: list[str] = []

    async def __call__(self, req: httpx.Request) -> httpx.Response:
        self.hosts.append(req.url.host)
        if self.hook:
            await self.hook(req)
        if req.url.host.endswith(".jonas.workers.dev"):
            assert req.method == "POST" and req.url.path == "/check"
            bearer = req.headers.get("authorization", "")
            body = json.loads(req.content)
            self.checks.append((bearer, body))
            if self.reply:
                return httpx.Response(self.reply[0], text=self.reply[1])
            if bearer != f"Bearer {self.secret}":
                return httpx.Response(404)
            res = [{"i": c["i"], "c": 200, "ms": 50, "e": None, "loc": None, "cfm": None, "cfe": None, "srv": None,
                    **self.results.get(c["u"], {})} for c in body["checks"]]
            return httpx.Response(200, json={"v": 1, "script": 1, "colo": "BRU", "results": res})
        if req.url.host == "api.cloudflare.com":
            return self.cloudflare(req)
        return httpx.Response(404)

    def cloudflare(self, req: httpx.Request) -> httpx.Response:
        self.cf.append(req)
        assert req.headers["authorization"] == "Bearer cf-workers"
        p = req.url.path.removeprefix("/client/v4")
        if p == "/user/tokens/verify":
            return httpx.Response(200, json={"success": True, "result": {"id": "tok123", "status": "active"}})
        if p.endswith("/workers/scripts") and req.method == "GET":
            return httpx.Response(200, json={"success": True, "result": self.scripts})
        if p.endswith("/workers/subdomain"):
            return httpx.Response(200, json={"success": True, "result": {"subdomain": "jonas"}})
        if re.search(r"/workers/scripts/[a-z0-9-]+$", p) and req.method == "PUT":
            self.uploads.append(req.content)
            if self.fail_upload:
                return httpx.Response(500, json={"success": False})
            m = re.search(rb'"name": ?"HOMEPAGE_TOKEN", ?"text": ?"([^"]+)"', req.content)
            self.secret = m.group(1).decode()
            return httpx.Response(200, json={"success": True, "result": {"etag": "e2"}})
        if p.endswith("/subdomain") and req.method == "POST":
            return httpx.Response(200, json={"success": True, "result": {"enabled": True}})
        return httpx.Response(404)


@pytest.fixture
def world(monkeypatch):
    from app.routers import integrations as integrations_router
    w = World()
    w.http = HttpClients(httpx.MockTransport(w))
    monkeypatch.setattr(integrations_router, "clients", w.http)
    return w


async def _tiles(authed, n, prefix="t", check=None, group=None) -> list[int]:
    group = group or await _group(authed)
    agen, db = await _db()
    svcs = [Service(group_id=group, name=f"{prefix}{i}", url=f"https://{prefix}{i}.jbogaert.be/",
                    check=dict(check or {}), position=i) for i in range(n)]
    db.add_all(svcs)
    await db.commit()
    ids = [s.id for s in svcs]
    await agen.aclose()
    return ids


async def _config(ids, **kw):
    agen, db = await _db()
    st = await ensure_state(db, bc.CONFIG_KEY, {})
    st.value = {"enabled": True, "name": NAME, "worker_url": WORKER, "token": encrypt(SECRET_A),
                "token_at": bc.iso(T0 - timedelta(days=1)), "suffixes": ["jbogaert.be"], "services": ids,
                "how": "api", **kw}
    await db.commit()
    await agen.aclose()


async def _value(key) -> dict:
    agen, db = await _db()
    st = await db.get(AppState, key)
    v = dict(st.value) if st else {}
    await agen.aclose()
    return v


async def _set(key, value):
    agen, db = await _db()
    st = await ensure_state(db, key, {})
    st.value = value
    await db.commit()
    await agen.aclose()


async def _inside(sid, status="down", fail=0, **check):
    """De check van binnenuit van een tegel: een lopende tcp-check met deze toestand."""
    agen, db = await _db()
    s = await db.get(Service, sid)
    s.check = {"type": "tcp", **check}
    st = await db.get(ServiceState, sid)
    if st is None:
        st = ServiceState(service_id=sid, status=status, since=T0, fail_count=fail, quiet=False, cert_notified=0)
        db.add(st)
    st.status, st.fail_count = status, fail
    await db.commit()
    await agen.aclose()


async def _edit(sid, **kw):
    agen, db = await _db()
    s = await db.get(Service, sid)
    for k, v in kw.items():
        setattr(s, k, v)
    await db.commit()
    await agen.aclose()


async def _notes() -> list[Notification]:
    agen, db = await _db()
    rows = (await db.execute(select(Notification).order_by(Notification.id))).scalars().all()
    await agen.aclose()
    return rows


def _outside(notes) -> list[Notification]:
    """Alleen de meldingen van de check van buitenaf (geen 2FA-meldingen)."""
    return [n for n in notes if n.source == "buitencheck" or (n.push_key or "").startswith("buiten")]


async def _tiles_state() -> dict:
    return (await _value(bc.STATE_KEY)).get("tiles") or {}


async def _rounds(world, first, count, maker=None):
    """count rondes, één per minuut vanaf minuut first (zoals de worker)."""
    for m in range(first, first + count):
        await bc.run_round(maker or _maker(), world.http, T0 + timedelta(minutes=m))


def _url(prefix, i):
    return f"https://{prefix}{i}.jbogaert.be/"


# --- 1, 2, 3, 25: de losse onderdelen ----------------------------------------------------------------------------

def test_judge():
    plain = bc.Target("https://jelly.jbogaert.be/", {}, False)
    tile = bc.Target("https://jelly.jbogaert.be/", {}, True)
    same = bc.Target("https://jelly.jbogaert.be/", {"same_host": True}, False)
    rule = bc.Target("https://jelly.jbogaert.be/", {"accept": "200-299,401"}, False)

    def j(r, t=plain, npm=False):
        return bc.judge({"c": 0, "e": None, "loc": None, "cfm": None, "cfe": None, "srv": None, **r}, t, npm)

    assert j({"c": 200}) == (True, None, None, None)
    v = j({"c": 302, "loc": "https://x.cloudflareaccess.com/cdn-cgi/access/login"})
    assert v.ok and v.note.startswith("achter Cloudflare Access")
    v = j({"c": 302, "loc": "https://auth.jbogaert.be/flow"}, same)
    assert not v.ok and v.why == "Doorverwezen naar auth.jbogaert.be (loginpagina?)" and v.cause == "redirect:auth.jbogaert.be"
    assert j({"c": 302, "loc": "https://auth.jbogaert.be/flow"}).note == "verwijst door naar auth.jbogaert.be"
    assert j({"c": 301, "loc": "/web/"}) == (True, None, None, None)
    v = j({"c": 530, "cfe": 1033})
    assert v == (False, "de Cloudflare Tunnel is niet verbonden (1033)", None, "cfe:1033")
    v = j({"c": 403, "cfe": 1020})
    assert v.why == "een WAF-regel van Cloudflare blokkeert de check (1020)" and v.cause == "cfe:1020"
    v = j({"c": 403, "cfm": "challenge"}, tile)
    assert not v.ok and v.why.startswith("Cloudflare houdt de check tegen") and v.cause == "challenge"
    v = j({"c": 0, "e": "time-out"})
    assert not v.ok and "poort 443, tunnel of NPM" in v.why and v.cause == "time-out"
    assert j({"c": 0, "e": "fetch failed"}) == (False, "geen antwoord: fetch failed", None, "net:fetch failed")
    assert j({"c": 502, "srv": "nginx"}) == (False, "NPM bereikt de app niet (502)", None, "http:502:npm")
    assert j({"c": 502}) == (False, "de tunnel of NPM bereikt het doel niet (502)", None, "http:502")
    assert j({"c": 521}).why == "NPM weigert de verbinding (521)"
    assert j({"c": 526}).cause == "http:526"
    # Een gewone GET met eigen goede statuscodes, en zonder.
    assert j({"c": 401}, rule).ok
    assert j({"c": 401}) == (False, "HTTP 401", None, "http:401")
    assert j({"c": 500}, rule).why == "HTTP 500 (verwacht 200-299,401)"
    v = j({"c": 401}, plain, npm=True)
    assert v.ok and v.note.startswith("achter toegangslijst in NPM")
    for c in (401, 403):
        v = j({"c": c}, tile)
        assert v.ok and v.note == f"NPM bereikt; de app vraagt een login ({c})"
    v = j({"e": "niet toegelaten"})
    assert not v.ok and "ALLOWED_SUFFIXES" in v.why and v.cause == "suffix"


def test_target():
    def svc(url="https://jelly.jbogaert.be", **check):
        return SimpleNamespace(url=url, check=check, name="Jelly")

    t = bc.target(svc(type="http", target="https://jelly.jbogaert.be/health#x", accept="200,401"))
    assert t == ("https://jelly.jbogaert.be/health", {"type": "http", "target": "https://jelly.jbogaert.be/health#x",
                                                       "accept": "200,401"}, False)
    assert bc.target(svc(type="http")).url == "https://jelly.jbogaert.be/"
    for extra in ({"method": "POST"}, {"method": "HEAD"}, {"headers": {"X-Api-Key": "x"}},
                  {"method": "POST", "body": "{}"}):
        t = bc.target(svc(type="http", target="https://jelly.jbogaert.be/api", **extra))
        assert t == ("https://jelly.jbogaert.be/", {}, True), extra
    assert bc.target(svc(type="http", target="https://192.168.0.5")) == ("https://jelly.jbogaert.be/", {}, True)
    assert bc.target(svc(type="http", target="http://jelly.lan:8096")).login_ok
    assert bc.target(svc(type="tcp")).login_ok
    assert bc.target(svc()).url == "https://jelly.jbogaert.be/"
    assert bc.eligible(svc("http://jelly.jbogaert.be"), ["jbogaert.be"]) == (None, "geen https-adres")
    assert bc.eligible(svc("https://192.168.0.5"), ["jbogaert.be"]) == (None, "IP-adres")
    assert bc.eligible(svc(None), ["jbogaert.be"]) == (None, "geen adres")
    assert bc.eligible(svc("https://plex.example.org"), ["jbogaert.be"]) == (None, "niet onder jbogaert.be")
    assert bc.eligible(svc(), ["jbogaert.be"])[0].url == "https://jelly.jbogaert.be/"


def test_oudste_eerst():
    """Elke ronde de 20 tegels met het oudste resultaat. Een ronde die overgeslagen werd (de vorige liep nog) of
    mislukte (geen resultaat bewaard): de volgende neemt dezelfde. Nooit meer dan 5 geslaagde rondes tussen twee checks
    van een tegel, zonder op de klok te rekenen."""
    ids = list(range(1, 101))
    tiles: dict = {}
    last: dict[int, int] = {}
    done = 0
    prev = None
    for minute in range(60):
        if minute % 7 == 3:
            continue  # overgeslagen
        picked = bc.pick(ids, tiles)
        assert len(picked) == 20
        if minute % 11 == 5:
            prev = picked  # de Worker antwoordde niet: niets bewaard
            continue
        if prev is not None:
            assert picked == prev
            prev = None
        done += 1
        for sid in picked:
            if sid in last:
                assert done - last[sid] <= 5
            last[sid] = done
            tiles[str(sid)] = {"at": bc.iso(T0 + timedelta(minutes=minute))}
    assert len(last) == 100
    assert bc.pick(list(range(1, 400)), {}) == list(range(1, 46))
    assert bc.pick([3, 1, 2], {}) == [1]


def test_script_versie_klopt():
    m = re.search(r"const SCRIPT_VERSION = (\d+)", bc.SCRIPT)
    assert m and int(m.group(1)) == bc.SCRIPT_VERSION
    assert "redirect: 'manual'" in bc.SCRIPT and "const MAX = 45" in bc.SCRIPT and "const LANES = 6" in bc.SCRIPT
    assert bc.MAX_TILES == 225


def test_tile_view_en_reset_text():
    now = T0
    assert bc.tile_view(None, now)["status"] == "wacht"
    e = {"status": "down", "at": bc.iso(now - timedelta(minutes=3)), "why": "x"}
    assert bc.tile_view(e, now)["status"] == "down"
    assert bc.tile_view(e, now + timedelta(minutes=17))["status"] == "wacht"
    assert bc.tile_view({**e, "status": None}, now)["status"] == "wacht"
    assert bc.reset_text(datetime(2026, 1, 15, 10, 0, tzinfo=timezone.utc)) == "01:00"
    assert bc.reset_text(datetime(2026, 7, 15, 23, 30, tzinfo=timezone.utc)) == "02:00"


# --- 4-11, 17: een ronde ----------------------------------------------------------------------------------------

async def test_ronde_stuurt_een_vijfde_met_geheim(authed, world):
    ids = await _tiles(authed, 10)
    await _config(ids)
    maker = _maker()

    async def hook(req):
        if req.url.host.endswith("workers.dev"):
            assert maker.open[0] == 0, "sessie open tijdens de vraag aan de Worker"
    world.hook = hook
    await bc.run_round(maker, world.http, T0)
    assert len(world.checks) == 1
    bearer, body = world.checks[0]
    assert bearer == f"Bearer {SECRET_A}"
    assert body == {"v": 1, "checks": [{"i": ids[0], "u": _url("t", 0)}, {"i": ids[1], "u": _url("t", 1)}]}
    tiles = await _tiles_state()
    assert set(tiles) == {str(ids[0]), str(ids[1])}
    e = tiles[str(ids[0])]
    assert (e["status"], e["fail"], e["code"], e["colo"], e["at"]) == ("up", 0, 200, "BRU", bc.iso(T0))
    w = (await _value(bc.STATE_KEY))["worker"]
    assert w["fail"] == 0 and w["colo"] == "BRU" and w["script"] == 1
    # De volgende ronde de volgende twee; uit of zonder geheim gebeurt er niets.
    await bc.run_round(maker, world.http, T0 + timedelta(minutes=1))
    assert [c["i"] for c in world.checks[1][1]["checks"]] == ids[2:4]
    await _config(ids, enabled=False)
    await bc.run_round(maker, world.http, T0 + timedelta(minutes=2))
    await _config(ids, token=None, token_next=encrypt(SECRET_B))
    await bc.run_round(maker, world.http, T0 + timedelta(minutes=3))
    assert len(world.checks) == 2


async def test_down_na_twee_en_herstel(authed, world):
    [sid] = await _tiles(authed, 1)
    await _config([sid])
    world.results[_url("t", 0)] = TUNNEL
    await _rounds(world, 0, 1)
    assert _outside(await _notes()) == []
    assert (await _tiles_state())[str(sid)]["fail"] == 1
    await _rounds(world, 1, 1)
    [n] = _outside(await _notes())
    assert n.title == "t0: van buitenaf onbereikbaar" and n.push_key == f"buiten{sid}" and n.source == "monitor"
    assert n.body.startswith("De Cloudflare Tunnel is niet verbonden (1033). Laatste check ")
    assert n.service_id == sid and n.level == "err" and n.pushed_at is None
    await _rounds(world, 2, 1)
    assert len(_outside(await _notes())) == 1  # nog altijd down: niets nieuws
    world.results.clear()
    await _rounds(world, 3, 1)
    notes = _outside(await _notes())
    assert len(notes) == 2
    assert notes[1].title == "t0 weer bereikbaar van buitenaf" and notes[1].recovers == "err"
    assert notes[1].push_key == f"buiten{sid}" and notes[1].level == "ok"


async def _five(authed, world, x_result=TUNNEL):
    """5 tegels, 1 per ronde: tegel x (de eerste) komt aan de beurt in de rondes 0, 5, 10, ..."""
    ids = await _tiles(authed, 5)
    await _config(ids)
    world.results[_url("t", 0)] = x_result
    return ids


async def test_stil_en_geen_melding_bij_einde_reden(authed, world):
    ids = await _five(authed, world)
    x = ids[0]
    await _inside(x, "down")
    await _rounds(world, 0, 6)  # x: 2 keer mislukt
    e = (await _tiles_state())[str(x)]
    assert (e["status"], e["quiet"], e["fail"]) == ("down", "thuis", 2)
    assert _outside(await _notes()) == []
    # Thuis weer in orde. De volgende ronde (x niet aan de beurt): opnieuw beginnen, zonder melding.
    await _inside(x, "up")
    await _rounds(world, 6, 1)
    e = (await _tiles_state())[str(x)]
    assert e["status"] is None and e["fail"] == 0 and e["quiet"] is None and e["reset_at"]
    assert e["why"] == "de Cloudflare Tunnel is niet verbonden (1033)"  # het laatste blijft te zien
    # Het volgende resultaat is goed: nog altijd geen enkele melding.
    world.results.clear()
    await _rounds(world, 7, 4)
    assert (await _tiles_state())[str(x)]["status"] == "up"
    assert _outside(await _notes()) == []


async def test_stil_dan_twee_nieuwe_fouten(authed, world):
    ids = await _five(authed, world)
    x = ids[0]
    await _inside(x, "down")
    await _rounds(world, 0, 6)
    await _inside(x, "up")
    await _rounds(world, 6, 5)  # minuut 10: x mislukt (1)
    assert _outside(await _notes()) == []
    assert (await _tiles_state())[str(x)]["fail"] == 1
    await _rounds(world, 11, 5)  # minuut 15: x mislukt (2)
    [n] = _outside(await _notes())
    assert n.title == "t0: van buitenaf onbereikbaar" and n.body.endswith("Thuis werkt het wel.")


async def test_reden_voorbij_in_de_ronde_van_het_resultaat(authed, world):
    ids = await _five(authed, world)
    x = ids[0]
    await _inside(x, "down")
    await _rounds(world, 0, 10)
    assert (await _tiles_state())[str(x)]["quiet"] == "thuis"
    # Thuis in orde net voor de ronde van x: dat resultaat werd gevraagd voor het einde gezien werd, telt niet mee.
    await _inside(x, "up")
    await _rounds(world, 10, 1)
    e = (await _tiles_state())[str(x)]
    assert e["fail"] == 0 and e["status"] is None and e["at"] == bc.iso(T0 + timedelta(minutes=10))
    await _rounds(world, 11, 5)
    assert (await _tiles_state())[str(x)]["fail"] == 1
    assert _outside(await _notes()) == []


@pytest.mark.parametrize("reason", ["onderhoud", "pauze", "massa"])
async def test_einde_onderhoud_pauze_massa(authed, world, reason):
    ids = await _five(authed, world)
    x = ids[0]
    if reason == "onderhoud":
        await _edit(x, maintenance_until=T0 + timedelta(minutes=8))
    elif reason == "pauze":
        await _edit(x, check={"type": "http", "paused": True})
    else:
        for i in range(1, 5):
            world.results[_url("t", i)] = {"c": 0, "e": "time-out"}
    await _rounds(world, 0, 6)
    e = (await _tiles_state())[str(x)]
    assert (e["status"], e["quiet"]) == ("down", reason)
    if reason == "pauze":
        await _edit(x, check={"type": "http"})
    if reason == "massa":
        notes = _outside(await _notes())
        assert [n.title for n in notes] == ["Van buitenaf is bijna niets bereikbaar"]
        for i in range(1, 5):
            del world.results[_url("t", i)]
    # Rondes tot x weer aan de beurt is (minuut 10): de reden is voorbij, maar er komt geen melding.
    await _rounds(world, 6, 5)
    titles = [n.title for n in _outside(await _notes())]
    assert not any("t0" in t for t in titles), titles
    e = (await _tiles_state())[str(x)]
    assert e["quiet"] is None and e["status"] is None
    # Bij een massastoring eindigde die pas in minuut 9: het resultaat van minuut 10 werd gevraagd voor x vrijkwam.
    first = 10 if reason != "massa" else 15
    await _rounds(world, 11, first - 10)
    assert (await _tiles_state())[str(x)]["fail"] == 1
    assert not any("t0" in n.title for n in _outside(await _notes()))
    # De tweede nieuwe mislukte check: één melding.
    await _rounds(world, first + 1, 5)
    tile = [n for n in _outside(await _notes()) if n.title.startswith("t0")]
    assert [n.title for n in tile] == ["t0: van buitenaf onbereikbaar"]


async def test_groep_bij_gedeeltelijke_storing(authed, world):
    ids = await _tiles(authed, 100)
    await _config(ids)
    bad = [i for i in range(100) if i % 10 in (0, 3, 6)]
    for i in bad:
        world.results[_url("t", i)] = TUNNEL
    await _rounds(world, 0, 12)
    notes = _outside(await _notes())
    assert [(n.title, n.push_key, n.source) for n in notes] == [
        ("30 tegels van buitenaf onbereikbaar: de Cloudflare Tunnel is niet verbonden (1033)", "buiten-groep:cfe:1033",
         "buitencheck")]
    assert notes[0].body.startswith("t0, t10, t13, ") and "en 22 meer" in notes[0].body
    assert notes[0].pushed_at is None
    tiles = await _tiles_state()
    assert {tiles[str(ids[i])]["quiet"] for i in bad} == {"groep"}
    s = await _value(bc.STATE_KEY)
    assert s["mass"] is None and list(s["groups"]) == ["cfe:1033"]
    assert sorted(s["groups"]["cfe:1033"]["tiles"]) == sorted(ids[i] for i in bad)
    # Alles weer goed: één melding met dezelfde sleutel, niets per tegel.
    world.results.clear()
    await _rounds(world, 12, 12)
    notes = _outside(await _notes())
    assert len(notes) == 2
    assert notes[1].title.startswith("Van buitenaf weer bereikbaar: ") and notes[1].title.endswith("van de 30 tegels")
    assert notes[1].push_key == "buiten-groep:cfe:1033" and notes[1].recovers == "err"
    assert (await _value(bc.STATE_KEY))["groups"] == {}


async def test_twee_tegels_is_geen_groep(authed, world):
    ids = await _tiles(authed, 10)
    await _config(ids)
    world.results[_url("t", 0)] = world.results[_url("t", 1)] = TUNNEL
    await _rounds(world, 0, 6)
    notes = _outside(await _notes())
    assert sorted(n.title for n in notes) == ["t0: van buitenaf onbereikbaar", "t1: van buitenaf onbereikbaar"]


async def test_tunnel_al_gemeld(authed, world):
    ids = await _tiles(authed, 100)
    await _config(ids)
    await _set("net_tunnel:1", {"items": [{"name": "thuis", "status": "down"}]})
    for i in range(100):
        if i % 10 in (0, 3, 6):
            world.results[_url("t", i)] = TUNNEL
    await _rounds(world, 0, 12)
    assert _outside(await _notes()) == []
    tiles = await _tiles_state()
    assert tiles[str(ids[0])]["quiet"] == "tunnel"


async def test_massastoring(authed, world):
    ids = await _tiles(authed, 10)
    await _config(ids)
    for i in range(10):
        world.results[_url("t", i)] = TUNNEL
    await _rounds(world, 0, 12)
    notes = _outside(await _notes())
    assert [n.title for n in notes] == ["Van buitenaf is bijna niets bereikbaar"]
    assert notes[0].body.startswith("6 van de 6 checks van buitenaf mislukken: de Cloudflare Tunnel is niet verbonden")
    assert notes[0].push_key == "buiten-massa" and notes[0].pushed_at is None
    assert {e["quiet"] for e in (await _tiles_state()).values()} == {"massa"}
    world.results.clear()
    await _rounds(world, 12, 6)
    notes = _outside(await _notes())
    assert [n.title for n in notes] == ["Van buitenaf is bijna niets bereikbaar", "Van buitenaf weer bereikbaar"]
    assert notes[1].push_key == "buiten-massa" and notes[1].recovers == "err"
    # De rest komt de volgende ronde vrij, zonder melding.
    await _rounds(world, 18, 5)
    assert len(_outside(await _notes())) == 2


async def test_massastoring_met_tunnel_alleen_hier(authed, world):
    ids = await _tiles(authed, 10)
    await _config(ids)
    await _set("net_tunnel:1", {"items": [{"name": "thuis", "status": "down"}]})
    for i in range(10):
        world.results[_url("t", i)] = TUNNEL
    await _rounds(world, 0, 6)
    [n] = _outside(await _notes())
    assert n.title == "Van buitenaf is bijna niets bereikbaar" and n.pushed_at is not None
    assert "Tunnel thuis is down (al gemeld)." in n.body


async def test_massastoring_thuis_verklaard(authed, world):
    ids = await _tiles(authed, 10)
    await _config(ids)
    for i in range(10):
        world.results[_url("t", i)] = TUNNEL
    for sid in ids[:7]:
        await _inside(sid, "down")
    await _rounds(world, 0, 12)
    notes = _outside(await _notes())
    # Geen massastoring: 7 zijn thuis al down. De andere 3 samen: één melding.
    assert [n.title for n in notes] == ["3 tegels van buitenaf onbereikbaar: de Cloudflare Tunnel is niet verbonden (1033)"]
    assert notes[0].body.startswith("t7, t8, t9.")
    tiles = await _tiles_state()
    assert {tiles[str(sid)]["quiet"] for sid in ids[:7]} == {"thuis"}


async def test_npm_en_ouder_stil(authed, world):
    g = await _group(authed)
    [x, y] = await _tiles(authed, 2, group=g)
    [npm, parent] = await _tiles(authed, 2, prefix="infra", group=g)
    await _edit(npm, type="npm")
    await _inside(npm, "down")
    await _inside(parent, "up", fail=1)
    await _edit(y, parent_id=parent)
    await _config([x, y])
    world.results[_url("t", 0)] = world.results[_url("t", 1)] = TUNNEL
    await _rounds(world, 0, 4)  # 1 tegel per ronde
    tiles = await _tiles_state()
    assert tiles[str(x)]["quiet"] == "npm" and tiles[str(y)]["quiet"] == "ouder"
    assert _outside(await _notes()) == []


async def test_worker_kapot(authed, world):
    [sid] = await _tiles(authed, 1)
    await _config([sid])
    await _rounds(world, 0, 1)
    world.secret = "iets anders"
    await _rounds(world, 1, 4)
    assert _outside(await _notes()) == []
    await _rounds(world, 5, 1)
    [n] = _outside(await _notes())
    assert (n.title, n.level, n.push_key) == ("De check van buitenaf werkt niet", "warn", "buiten-worker")
    assert n.body == bc.UNKNOWN_SECRET
    await _rounds(world, 6, 12)
    assert len(_outside(await _notes())) == 1
    e = (await _tiles_state())[str(sid)]
    assert e["status"] == "up"  # laatste waarde blijft, maar is niet vers meer
    assert bc.tile_view(e, T0 + timedelta(minutes=17))["status"] == "wacht"
    # De Worker antwoordt weer.
    world.secret = SECRET_A
    await _rounds(world, 18, 1)
    notes = _outside(await _notes())
    assert notes[-1].title == "De check van buitenaf werkt weer" and notes[-1].recovers == "warn"


async def test_worker_kapot_zonder_internet(authed, world):
    [sid] = await _tiles(authed, 1)
    await _config([sid])
    await _set("public_ip", {"error": "Geen antwoord van 1.1.1.1 of ipify (geen internet?)"})
    world.secret = "iets anders"
    await _rounds(world, 0, 8)
    assert _outside(await _notes()) == []
    assert (await _value(bc.STATE_KEY))["worker"]["fail"] == 8


@pytest.mark.parametrize("month,hour", [(1, "01:00"), (7, "02:00")])
async def test_limiet_van_de_dag(month, hour):
    async def handler(req):
        return httpx.Response(429, text="error code: 1027")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        r = await bc.call_worker(c, WORKER, SECRET_A, [], datetime(2026, month, 10, 15, 0, tzinfo=timezone.utc))
    assert r.data is None and r.code == 429 and f"om {hour} werkt het weer" in r.err


@pytest.mark.parametrize("status,text,want", [
    (500, "error code: 1102", "CPU-limiet"), (500, "error code: 1101", "liep vast (1101)"),
    (429, "slow down", "te veel verzoeken (1015)"), (503, "", "Worker gaf HTTP 503"),
    (200, "<html>", "Onverwacht antwoord van de Worker"), (200, '{"results": 1}', "Onverwacht antwoord")])
async def test_fouten_van_de_worker(status, text, want):
    async def handler(req):
        return httpx.Response(status, text=text)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
        r = await bc.call_worker(c, WORKER, SECRET_A, [])
    assert r.data is None and want in r.err


async def test_tegel_weg_sluit_de_melding(authed, world):
    [x, y] = await _tiles(authed, 2)
    await _config([x, y])
    world.results[_url("t", 0)] = world.results[_url("t", 1)] = {"c": 0, "e": "time-out"}
    await _rounds(world, 0, 4)  # 1 tegel per ronde
    assert len(_outside(await _notes())) == 2
    # x uit de lijst: de draad op de gsm wordt gesloten, met de instelling van de tegel.
    await _config([y])
    await _rounds(world, 4, 1)
    n = _outside(await _notes())[-1]
    assert (n.title, n.level, n.push_key, n.source) == ("t0: niet meer van buitenaf gecheckt", "ok", f"buiten{x}", "monitor")
    assert str(x) not in await _tiles_state()
    # y verwijderd: hetzelfde, zonder tegel.
    agen, db = await _db()
    await db.execute(delete(Service).where(Service.id == y))
    await db.commit()
    await agen.aclose()
    await _rounds(world, 5, 1)
    n = _outside(await _notes())[-1]
    assert (n.title, n.level, n.push_key, n.source) == ("t1: niet meer van buitenaf gecheckt", "ok", f"buiten{y}",
                                                         "buitencheck")
    assert n.body == "De tegel is verwijderd." and n.recovers == "err" and n.pushed_at is None
    assert await _tiles_state() == {}


async def test_ander_adres_begint_opnieuw(authed, world):
    [x] = await _tiles(authed, 1)
    await _config([x])
    world.results[_url("t", 0)] = TUNNEL
    await _rounds(world, 0, 1)
    await _edit(x, url="https://nieuw.jbogaert.be")
    await _rounds(world, 1, 1)
    e = (await _tiles_state())[str(x)]
    assert e["url"] == "https://nieuw.jbogaert.be/" and e["status"] == "up" and e["fail"] == 0
