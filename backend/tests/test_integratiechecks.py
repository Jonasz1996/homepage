"""Container-check (via Portainer) en API-check (met de sleutels die het dashboard al heeft)."""

import asyncio
import base64

import httpx
import pytest

from app import integrations
from app.models import Service
from app.monitoring import integrationchecks as ic
from app.monitoring.checks import HttpClients
from app.routers import integrations as router

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db

PKEY = "portainer-sleutel-123"
PASSWORD = "pw-zeer-geheim-42"
TOKEN = "tok-zeer-geheim-42"


class FakePortainer:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.down = False
        self.delay = 0.0

    async def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        if self.delay:
            await asyncio.sleep(self.delay)
        if self.down:
            raise httpx.ConnectError("[Errno 111] Connection refused")
        assert req.url.host == "portainer.jbogaert.be"
        assert req.headers["x-api-key"] == PKEY
        p = req.url.path
        if p == "/api/endpoints":
            return httpx.Response(200, json=[{"Id": 2, "Name": "docker", "Status": 1},
                                             {"Id": 3, "Name": "nas", "Status": 2}])
        if p == "/api/endpoints/2/docker/containers/json":
            assert req.url.params["all"] == "1"
            return httpx.Response(200, json=[
                {"Names": ["/sonarr"], "State": "running", "Status": "Up 3 hours"},
                {"Names": ["/radarr"], "State": "exited", "Status": "Exited (137) 2 hours ago"},
                {"Names": ["/jellyfin"], "State": "running", "Status": "Up 2 days (unhealthy)"},
                {"Names": ["/adguard"], "State": "running", "Status": "Up 5 minutes (health: starting)"},
            ])
        return httpx.Response(404)


@pytest.fixture(autouse=True)
def _fresh_cache():
    ic.clear_cache()
    yield
    ic.clear_cache()


@pytest.fixture
def pt():
    return FakePortainer()


async def _portainer_tile(authed) -> tuple[int, int]:
    g = await _group(authed)
    pid = await _svc(authed, g, "portainer", "https://portainer.jbogaert.be", secrets={"key": PKEY}, name="Portainer")
    return g, pid


def _c(pid, name, env=2):
    return {"type": "container", "portainer_id": pid, "env": env, "container": name}


async def test_container_states(authed, pt):
    g, pid = await _portainer_tile(authed)
    http = HttpClients(httpx.MockTransport(pt))
    agen, db = await _db()

    first = await ic.check_container(db, _c(pid, "sonarr"), http)
    assert first.ok and first.error is None and first.latency_ms is not None
    stopped = await ic.check_container(db, _c(pid, "radarr"), http)
    assert not stopped.ok and stopped.error == "gestopt (Exited (137) 2 hours ago)"
    assert stopped.latency_ms is None  # uit de cache: geen eigen API-call
    sick = await ic.check_container(db, _c(pid, "jellyfin"), http)
    assert not sick.ok and sick.error == "unhealthy (Up 2 days (unhealthy))"
    assert (await ic.check_container(db, _c(pid, "adguard"), http)).ok  # health: starting telt als draaiend
    assert (await ic.check_container(db, _c(pid, "/sonarr"), http)).ok
    assert (await ic.check_container(db, _c(pid, "Sonarr"), http)).error == "container Sonarr niet gevonden"
    assert (await ic.check_container(db, _c(pid, "plex"), http)).error == "container plex niet gevonden"
    assert (await ic.check_container(db, _c(pid, "plex", env="2"), http)).error == "container plex niet gevonden"
    assert len(pt.requests) == 1  # één lijst voor alle checks op dezelfde omgeving

    # Zonder omgeving: zoals de Portainer-tegel zelf, over alle omgevingen (de offline omgeving wordt vermeld).
    assert (await ic.check_container(db, _c(pid, "sonarr", env=None), http)).ok
    assert (await ic.check_container(db, _c(pid, "plex", env=""), http)).error == \
        "container plex niet gevonden (omgeving nas offline)"
    assert [r.url.path for r in pt.requests[1:]] == ["/api/endpoints", "/api/endpoints/2/docker/containers/json"]

    # Geen of geen Portainer-tegel meer.
    other = await _svc(authed, g, "link", "https://x.jbogaert.be", name="X")
    for bad in (999, other, None, "abc"):
        out = await ic.check_container(db, _c(bad, "sonarr"), http)
        assert not out.ok and out.error == "Portainer-tegel bestaat niet meer", bad
    assert (await ic.check_container(db, _c(pid, ""), http)).error == "Geen container ingesteld"
    assert "Ongeldige omgeving" in (await ic.check_container(db, _c(pid, "sonarr", env="x"), http)).error
    await db.close()


async def test_concurrent_checks_share_one_request(authed, pt):
    _, pid = await _portainer_tile(authed)
    pt.delay = 0.05
    http = HttpClients(httpx.MockTransport(pt))
    agen, db = await _db()
    await db.get(Service, pid)  # de tegel staat al in de sessie: de checks hieronder doen geen query
    names = ["sonarr", "radarr", "jellyfin", "adguard", "plex"] * 2
    outs = await asyncio.gather(*(ic.check_container(db, _c(pid, n), http) for n in names))
    assert len(pt.requests) == 1
    assert [o.ok for o in outs[:5]] == [True, False, False, True, False]
    assert sum(o.latency_ms is not None for o in outs) == 1  # alleen de check die de call deed

    # Ook een fout wordt gedeeld: een Portainer die plat ligt kost één verzoek, niet tien time-outs na elkaar.
    ic.clear_cache()
    pt.down = True
    outs = await asyncio.gather(*(ic.check_container(db, _c(pid, n), http) for n in names))
    assert len(pt.requests) == 2
    assert all(o.error.startswith("Portainer onbereikbaar: ") and o.latency_ms is None for o in outs)
    await db.close()


async def test_cache_expires_after_20_seconds(authed, pt, monkeypatch):
    _, pid = await _portainer_tile(authed)
    clock = [1000.0]
    monkeypatch.setattr(ic, "_clock", lambda: clock[0])
    http = HttpClients(httpx.MockTransport(pt))
    agen, db = await _db()
    assert (await ic.check_container(db, _c(pid, "sonarr"), http)).latency_ms is not None
    clock[0] += 19.5
    assert (await ic.check_container(db, _c(pid, "sonarr"), http)).latency_ms is None
    assert len(pt.requests) == 1
    clock[0] += 1
    assert (await ic.check_container(db, _c(pid, "sonarr"), http)).latency_ms is not None
    assert len(pt.requests) == 2
    await db.close()


async def test_portainer_down(authed, pt):
    _, pid = await _portainer_tile(authed)
    pt.down = True
    http = HttpClients(httpx.MockTransport(pt))
    agen, db = await _db()
    out = await ic.check_container(db, _c(pid, "sonarr"), http)
    assert not out.ok and out.error.startswith("Portainer onbereikbaar: ") and "verbinding geweigerd" in out.error
    assert PKEY not in out.error and out.latency_ms is None
    await db.close()


async def test_unexpected_errors_never_raise(authed, pt, monkeypatch):
    _, pid = await _portainer_tile(authed)
    agen, db = await _db()
    svc = await db.get(Service, pid)

    def boom(*a, **kw):
        raise RuntimeError("kapot")
    monkeypatch.setattr(integrations, "build", boom)
    http = HttpClients(httpx.MockTransport(pt))
    assert (await ic.check_container(db, _c(pid, "sonarr"), http)).error == "Interne fout in de check: RuntimeError"
    assert (await ic.check_api(db, svc, {"type": "api"}, http)).error == "Interne fout in de check: RuntimeError"
    await db.close()


# --- API-check ----------------------------------------------------------------------

class FakeApi:
    """Een eigen API (Radarr-achtig) achter basic auth, bearer of een sleutel in de query."""

    def __init__(self, expect: dict):
        self.expect = expect
        self.requests: list[httpx.Request] = []

    async def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        for k, v in self.expect.items():
            assert req.headers.get(k) == v, (k, req.headers.get(k))
        p = req.url.path
        if p == "/api/v3/system/status":
            return httpx.Response(200, json={"version": "5.8.3", "status": "OK", "disks": [{"free": 10}]})
        if p == "/fout401":
            return httpx.Response(401)
        if p == "/fout500":
            return httpx.Response(500, text="Internal Server Error")
        if p == "/redirect":
            return httpx.Response(302, headers={"location": f"https://auth.jbogaert.be/login?rd=/x&apikey={TOKEN}"})
        if p == "/traag":
            await asyncio.sleep(3)
            return httpx.Response(200, json={})
        if p == "/":
            return httpx.Response(200, text="<html><title>Radarr</title></html>")
        if p == "/api/v3/queue":
            return httpx.Response(200, json={"totalRecords": 0})
        return httpx.Response(404)


async def _api_tile(authed, auth: dict, secrets: dict) -> tuple[int, int]:
    g = await _group(authed)
    tile = await _svc(authed, g, "link", "https://radarr.jbogaert.be", name="Radarr")
    r = await authed.post("/api/apis", json={"name": "Radarr", "url": "https://radarr.jbogaert.be",
                                             "config": {"auth": auth}, "secrets": secrets})
    assert r.status_code == 201, r.text
    api = r.json()["id"]
    assert (await authed.post(f"/api/apis/{api}/tiles", json={"service_ids": [tile]})).json()["changed"] == 1
    return tile, api


async def test_api_check_with_basic_auth(authed):
    tile, _ = await _api_tile(authed, {"type": "basic"}, {"username": "jonas", "password": PASSWORD})
    fake = FakeApi({"authorization": "Basic " + base64.b64encode(f"jonas:{PASSWORD}".encode()).decode()})
    http = HttpClients(httpx.MockTransport(fake))
    agen, db = await _db()
    svc = await db.get(Service, tile)
    assert svc.api_id and svc.type == "rest"

    out = await ic.check_api(db, svc, {"type": "api", "path": "/api/v3/system/status"}, http)
    assert out.ok and out.status_code == 200 and out.latency_ms is not None and out.error is None
    assert fake.requests[-1].url.path == "/api/v3/system/status"

    for path, code in (("/fout401", 401), ("/fout500", 500)):
        out = await ic.check_api(db, svc, {"type": "api", "path": path}, http)
        assert not out.ok and out.status_code == code and f"HTTP {code}" in out.error
        assert PASSWORD not in out.error and base64.b64encode(f"jonas:{PASSWORD}".encode()).decode() not in out.error
    await db.close()


async def test_api_check_with_bearer_and_json(authed):
    tile, api = await _api_tile(authed, {"type": "bearer"}, {"token": TOKEN})
    fake = FakeApi({"authorization": f"Bearer {TOKEN}"})
    http = HttpClients(httpx.MockTransport(fake))
    agen, db = await _db()
    svc = await db.get(Service, tile)
    base = {"type": "api", "path": "/api/v3/system/status"}

    async def run(**kw):
        return await ic.check_api(db, svc, {**base, **kw}, http)

    assert (await run(json_path="status", json_value="ok")).ok  # hoofdletters tellen niet
    assert (await run(json_path="disks.0.free", json_value=10)).ok
    assert (await run(json_path="version")).ok  # zonder verwachte waarde: bestaan volstaat
    bad = await run(json_path="status", json_value="down")
    assert not bad.ok and bad.error == "status = OK (verwacht down)" and bad.status_code == 200
    assert (await run(json_path="nope")).error == "nope ontbreekt"
    assert (await run(path="/", json_path="status")).error == "Antwoord is geen JSON"

    for path in ("/fout401", "/fout500", "/redirect"):
        out = await run(path=path)
        assert not out.ok and TOKEN not in out.error, out.error
    assert (await run(path="/redirect")).error.startswith("Doorgestuurd (HTTP 302) naar https://auth.jbogaert.be/login")
    assert (await run(path="//evil.example/x")).error == "Ongeldig pad"  # blijft op de API zelf
    assert (await run(path="https://evil.example/x")).error.startswith("Een pad begint met /")

    # Eigen time-out van de check.
    slow = await run(path="/traag", timeout=1)
    assert not slow.ok and slow.error == "Time-out"

    # Zonder pad: de eerste GET-call uit API-beheer, en zonder calls het adres van de API zelf.
    out = await ic.check_api(db, svc, {"type": "api"}, http)
    assert out.ok and fake.requests[-1].url.path == "/"
    await db.close()
    assert (await authed.post(f"/api/apis/{api}/calls", json={"name": "wachtrij", "path": "/api/v3/queue"})).status_code == 201
    agen, db = await _db()
    svc = await db.get(Service, tile)
    out = await ic.check_api(db, svc, {"type": "api", "json_path": "totalRecords", "json_value": "0"}, http)
    assert out.ok and fake.requests[-1].url.path == "/api/v3/queue"
    await db.close()


async def test_api_check_key_in_query_is_never_shown(authed):
    tile, _ = await _api_tile(authed, {"type": "query", "name": "apikey"}, {"token": TOKEN})
    fake = FakeApi({})
    http = HttpClients(httpx.MockTransport(fake))
    agen, db = await _db()
    svc = await db.get(Service, tile)
    out = await ic.check_api(db, svc, {"type": "api", "path": "/api/v3/system/status"}, http)
    assert out.ok and fake.requests[-1].url.params["apikey"] == TOKEN
    for path in ("/fout500", "/redirect", "/nergens"):
        out = await ic.check_api(db, svc, {"type": "api", "path": path}, http)
        assert not out.ok and TOKEN not in out.error and "apikey" not in out.error, out.error
    await db.close()


async def test_api_check_on_builtin_integration(authed):
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "pve-geheim"}, name="pve")
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req.url.path)
        assert req.headers["authorization"] == "PVEAPIToken=homepage@pve!dash=pve-geheim"
        if req.url.path == "/api2/json/version":
            return httpx.Response(200, json={"data": {"version": "8.2.4", "release": "8.2"}})
        if req.url.path == "/api2/json/cluster/resources":
            return httpx.Response(200, json={"data": []})
        return httpx.Response(403)

    http = HttpClients(httpx.MockTransport(handler))
    agen, db = await _db()
    svc = await db.get(Service, pve)
    # Zonder pad: de lichte /version-call van Proxmox, niet de hele summary.
    out = await ic.check_api(db, svc, {"type": "api", "json_path": "data.version", "json_value": "8.2.4"}, http)
    assert out.ok and seen == ["/api2/json/version"]
    # Een pad is achter het API-pad (zoals een eigen call); met dat API-pad ervoor mag ook.
    for path in ("/cluster/resources", "/api2/json/cluster/resources"):
        assert (await ic.check_api(db, svc, {"type": "api", "path": path}, http)).ok
    assert seen[1:] == ["/api2/json/cluster/resources"] * 2
    forbidden = await ic.check_api(db, svc, {"type": "api", "path": "/nodes"}, http)
    assert not forbidden.ok and forbidden.status_code == 403 and "pve-geheim" not in forbidden.error

    # Een tegel zonder integratie of API.
    link = await _svc(authed, g, "link", "https://x.jbogaert.be", name="X")
    out = await ic.check_api(db, await db.get(Service, link), {"type": "api"}, http)
    assert not out.ok and out.error == ("Deze tegel heeft geen API of integratie: "
                                        "koppel er een via bewerken → Integratie en API")
    await db.close()


async def test_containers_endpoint(authed, pt, monkeypatch):
    g, pid = await _portainer_tile(authed)
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(pt)))
    r = await authed.get(f"/api/services/{pid}/containers")
    assert r.status_code == 200, r.text
    assert r.json() == [{"name": "adguard", "env": 2, "state": "running"},
                        {"name": "jellyfin", "env": 2, "state": "running"},
                        {"name": "radarr", "env": 2, "state": "exited"},
                        {"name": "sonarr", "env": 2, "state": "running"}]
    other = await _svc(authed, g, "link", "https://x.jbogaert.be", name="X")
    assert (await authed.get(f"/api/services/{other}/containers")).status_code == 400
    assert (await authed.get("/api/services/9999/containers")).status_code == 404
    ic.clear_cache()
    pt.down = True
    r = await authed.get(f"/api/services/{pid}/containers")
    assert r.status_code == 502 and r.json()["detail"].startswith("Portainer onbereikbaar: ")
    authed.cookies.clear()
    assert (await authed.get(f"/api/services/{pid}/containers")).status_code == 401
