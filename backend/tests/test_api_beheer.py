import json
from datetime import datetime, timedelta, timezone

import httpx
import pyotp
import pytest
from sqlalchemy import select, update

from app.integrations import build
from app.models import ApiConnection, Service, Session
from app.monitoring.checks import HttpClients
from app.routers import integrations as router

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db

KEY = "radarr-sleutel"


class Apps:
    """Radarr, Jellyfin en een Proxmox-node, zoals ze antwoorden."""

    def __init__(self):
        self.calls: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.calls.append(req)
        host, p = req.url.host, req.url.path
        if host == "radarr.jbogaert.be":
            if req.headers.get("x-api-key") != KEY:
                return httpx.Response(401)
            if p == "/api/v3/queue":
                if req.url.params.get("pageSize") == "1":
                    return httpx.Response(200, json={"totalRecords": 3, "records": [{"title": "Dune"}]})
                return httpx.Response(200, json={"totalRecords": 2, "records": [
                    {"title": "Dune", "status": "downloading", "sizeleft": 2 * 1024 ** 3},
                    {"title": "Alien", "status": "queued", "sizeleft": 0}]})
            if p == "/api/v3/wanted/missing":
                return httpx.Response(200, json={"totalRecords": 12})
            if p == "/api/v3/health":
                return httpx.Response(200, json=[{"type": "warning", "message": "indexer traag"}])
            if p == "/api/v3/system/status":
                return httpx.Response(200, json={"version": "5.8.3", "startTime": "2026-10-01T10:00:00Z"})
            if p == "/api/v3/command" and req.method == "POST":
                assert json.loads(req.content) == {"name": "MissingMoviesSearch"}
                return httpx.Response(201, json={"id": 1})
        if host == "jellyfin.jbogaert.be" and p == "/Sessions":
            assert req.headers["x-emby-token"] == "jf"
            return httpx.Response(200, json=[{"UserName": "jonas", "NowPlayingItem": {"Name": "Dune"}}, {"UserName": "tv"}])
        if host == "192.168.0.50":
            assert req.headers["authorization"] == "PVEAPIToken=a@pve!b=c"
            if p == "/api2/json/nodes/pve50/disks/list":
                return httpx.Response(200, json={"data": [{"devpath": "/dev/sda", "health": "PASSED", "wearout": 97},
                                                          {"devpath": "/dev/sdb", "health": "FAILED", "wearout": 40}]})
        return httpx.Response(404)


@pytest.fixture
def apps(monkeypatch):
    a = Apps()
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(a)))
    router._cache.clear()
    return a


async def test_rest_api_from_template_on_a_tile(authed, apps):
    g = await _group(authed)
    tile = await _svc(authed, g, "", "https://radarr.jbogaert.be", name="Radarr")
    r = await authed.post("/api/apis", json={"name": "Radarr", "category": "Downloads", "url": "https://radarr.jbogaert.be",
                                             "template": "radarr", "config": {}, "secrets": {"token": KEY}})
    assert r.status_code == 201, r.text
    api = r.json()["id"]
    # De tegel kiest de API: het type komt van de API.
    s = (await authed.get(f"/api/services/{tile}")).json()
    s.pop("id")
    r = await authed.patch(f"/api/services/{tile}", json={**s, "type": "link", "api_id": api})
    assert r.status_code == 200, r.text
    assert (await authed.get(f"/api/services/{tile}")).json()["type"] == "rest"

    w = (await authed.get("/api/widgets")).json()[str(tile)]["fields"]
    assert [(f["label"], f["value"], f["level"]) for f in w] == [
        ("wachtrij", 3, None), ("ontbrekend", 12, None), ("meldingen", 1, "warn")]

    d = (await authed.get(f"/api/services/{tile}/integration")).json()
    assert d["label"] == "Eigen API · Radarr" and d["api_id"] == api
    tbl = next(x for x in d["sections"] if x["kind"] == "table")
    assert tbl["columns"] == ["titel", "status", "resterend", "klaar"]
    assert [c["v"] for c in tbl["rows"][0][:3]] == ["Dune", "downloading", {"bytes": 2 * 1024 ** 3}]
    act = next(x for x in d["sections"] if x.get("actions"))["actions"][0]
    assert act["label"] == "zoek ontbrekende" and act["confirm"]
    r = await authed.post(f"/api/services/{tile}/integration/action", json={"action": act["id"]})
    assert r.status_code == 200 and r.json()["message"] == "zoek ontbrekende uitgevoerd"
    quick = (await authed.get("/api/actions")).json()
    assert any(q["id"] == act["id"] and q["service_id"] == tile for q in quick)

    # De sleutel komt nooit terug naar de browser.
    data = (await authed.get("/api/apis")).json()
    a = data["apis"][0]
    assert a["secret_keys"] == ["token"] and KEY not in json.dumps(data)
    assert a["tiles"] == [{"id": tile, "name": "Radarr"}] and len(a["calls"]) == 6


async def test_calls_try_and_validation(authed, apps):
    r = await authed.post("/api/apis", json={"name": "Radarr", "url": "https://radarr.jbogaert.be",
                                             "config": {"auth": {"type": "header", "name": "X-Api-Key"}}, "secrets": {"token": KEY}})
    api = r.json()["id"]
    draft = {"name": "wachtrij", "path": "/api/v3/queue", "query": {"pageSize": "50"},
             "fields": [{"label": "totaal", "path": "totalRecords"},
                        {"label": "resterend", "path": "records.*.sizeleft", "format": "sum", "suffix": ""},
                        {"label": "bezig", "path": "records.*.status", "format": "count", "equals": "downloading", "warn": 1}],
             "table": {"path": "records", "columns": [{"label": "titel", "path": "title"}]}}
    t = (await authed.post(f"/api/apis/{api}/try", json={"call": draft})).json()
    assert t["ok"] and t["data"]["totalRecords"] == 2
    assert [(f["label"], f["value"], f["level"]) for f in t["fields"]] == [
        ("totaal", 2, None), ("resterend", 2147483648, None), ("bezig", 1, "warn")]
    assert [r[0]["v"] for r in t["table"]["rows"]] == ["Dune", "Alien"]
    bad = (await authed.post(f"/api/apis/{api}/try", json={"call": {**draft, "path": "/nope"}})).json()
    assert not bad["ok"] and "404" in bad["error"]

    # Bewaren, aanpassen, volgorde, verwijderen.
    cid = (await authed.post(f"/api/apis/{api}/calls", json=draft)).json()["id"]
    c2 = (await authed.post(f"/api/apis/{api}/calls", json={"name": "status", "path": "/api/v3/system/status", "show": "detail"})).json()["id"]
    assert (await authed.patch(f"/api/apis/calls/{cid}", json={**draft, "name": "queue"})).status_code == 200
    assert (await authed.post(f"/api/apis/{api}/calls/order", json={"ids": [c2, cid]})).status_code == 200
    assert [c["name"] for c in (await authed.get("/api/apis")).json()["apis"][0]["calls"]] == ["status", "queue"]
    assert (await authed.delete(f"/api/apis/calls/{c2}")).status_code == 200

    # Een pad blijft op de API; iets anders dan GET is altijd een knop.
    for path in ("@evil.example/x", "//evil.example", "https://evil.example"):
        assert (await authed.post(f"/api/apis/{api}/calls", json={"name": "x", "path": path})).status_code == 422, path
    assert (await authed.post(f"/api/apis/{api}/calls", json={"name": "x", "method": "POST", "path": "/a"})).status_code == 422
    assert (await authed.post(f"/api/apis/{api}/calls", json={"name": "x", "method": "POST", "path": "/a",
                                                               "show": "action"})).status_code == 201


async def test_shared_builtin_api_with_variables_and_2fa(authed, apps):
    g = await _group(authed)
    r = await authed.post("/api/apis", json={"name": "Cluster", "category": "Proxmox en back-up", "kind": "proxmox",
                                             "url": "https://192.168.0.50:8006", "config": {"insecure": True},
                                             "secrets": {"username": "a@pve!b", "password": "c"}})
    api = r.json()["id"]
    # Een eigen endpoint op de ingebouwde Proxmox, met {node} uit de tegel.
    assert (await authed.post(f"/api/apis/{api}/calls", json={
        "name": "schijven", "path": "/nodes/{node}/disks/list",
        "fields": [{"label": "kapot", "path": "data.*.health", "format": "count", "equals": "FAILED", "err": 1},
                   {"label": "slijtage", "path": "data.*.wearout", "format": "min", "suffix": "%", "warn": 30, "err": 10}]})).status_code == 201
    n50 = await _svc(authed, g, "link", "https://pve50.jbogaert.be", config={"node": "pve50", "url": "https://evil.example"},
                     name="pve50")
    n51 = await _svc(authed, g, "link", "https://pve51.jbogaert.be", config={"node": "pve51"}, name="pve51")
    assert (await authed.post(f"/api/apis/{api}/tiles", json={"service_ids": [n50, n51]})).json()["changed"] == 2

    agen, db = await _db()
    s50 = await db.get(Service, n50)
    assert s50.type == "proxmox"
    integ = build(s50, router.clients)
    assert integ.base == "https://192.168.0.50:8006"  # niet de url uit de tegel
    from app.integrations import calls
    assert [(f["label"], f["value"], f["level"]) for f in await calls.tile_fields(integ)] == [
        ("kapot", 1, "err"), ("slijtage", "40%", "ok")]
    await db.close()

    # Adres van een API met sleutels wijzigen vraagt een recente 2FA.
    body = {"name": "Cluster", "kind": "proxmox", "url": "https://evil.example", "config": {"insecure": True}}
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    r = await authed.patch(f"/api/apis/{api}", json=body)
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await authed.patch(f"/api/apis/{api}", json={**body, "url": "https://192.168.0.50:8006",
                                                         "category": "Proxmox"})).status_code == 200
    assert (await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})).status_code == 200
    assert (await authed.patch(f"/api/apis/{api}", json=body)).status_code == 200

    # Verwijderen: de tegels worden weer gewone snelkoppelingen.
    assert (await authed.delete(f"/api/apis/{api}")).status_code == 200
    s = (await authed.get(f"/api/services/{n51}")).json()
    assert s["api_id"] is None and s["type"] == "link"


async def test_suggest_bulk_and_adopt(authed, apps):
    g = await _group(authed)
    radarr = await _svc(authed, g, "", "https://radarr.jbogaert.be", name="Radarr")
    jf = await _svc(authed, g, "", "https://jellyfin.jbogaert.be", name="Films")  # herkend aan het adres
    await _svc(authed, g, "", "https://iets.jbogaert.be", name="iets")
    p1 = await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", config={"node": "pve50", "insecure": True},
                    secrets={"username": "a@pve!b", "password": "c"}, name="pve50")
    p2 = await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", config={"node": "pve51", "insecure": True},
                    secrets={"username": "a@pve!b", "password": "c"}, name="pve51")

    sug = (await authed.get("/api/apis/suggest")).json()
    assert {(m["service_id"], m["template"]) for m in sug["matches"]} == {(radarr, "radarr"), (jf, "jellyfin")}
    assert {a["service_id"] for a in sug["adopt"]} == {p1, p2}

    r = await authed.post("/api/apis/bulk", json={"items": [
        {"service_id": radarr, "template": "radarr", "secrets": {"token": KEY}},
        {"service_id": jf, "template": "jellyfin", "secrets": {"token": "jf"}}]})
    assert r.json()["created"] == 2
    w = (await authed.get("/api/widgets")).json()
    assert w[str(jf)]["fields"][0] == {"label": "speelt nu", "value": 1, "level": None}
    assert w[str(radarr)]["fields"][0]["value"] == 3

    r = await authed.post("/api/apis/adopt", json={"service_ids": [p1, p2]})
    assert r.json() == {"moved": 2, "apis": 1}
    agen, db = await _db()
    conns = (await db.execute(select(ApiConnection).order_by(ApiConnection.id))).scalars().all()
    px = conns[-1]
    assert px.name == "Proxmox VE" and px.kind == "proxmox" and px.config == {"insecure": True}
    tiles = [await db.get(Service, i) for i in (p1, p2)]
    assert all(t.api_id == px.id and t.secrets is None for t in tiles)
    assert tiles[1].config == {"node": "pve51"}
    assert build(tiles[1], router.clients).config["node"] == "pve51"
    await db.close()
    assert (await authed.get("/api/apis/suggest")).json() == {"matches": [], "adopt": []}

    # Een oude versie terugzetten waarin een intussen verwijderde API zat: gewone snelkoppeling.
    revs = (await authed.get("/api/revisions")).json()
    linked = next(r for r in revs if "API voor 2 tegels" in r["summary"])
    await authed.delete(f"/api/apis/{conns[0].id}")
    assert (await authed.post(f"/api/revisions/{linked['id']}/restore")).status_code == 200
    s = (await authed.get(f"/api/services/{radarr}")).json()
    assert s["api_id"] is None and s["type"] == "link"
    assert (await authed.get(f"/api/services/{jf}")).json()["api_id"] == conns[1].id


def test_every_template_is_valid():
    from app.integrations import REGISTRY, templates
    from app.routers import apis

    for key, t in templates.TEMPLATES.items():
        assert t["category"] in templates.CATEGORIES, key
        assert t.get("kind", "rest") in REGISTRY, key
        apis._template_calls(key)  # valideert elke call zoals de API dat doet
    assert {t["key"] for t in templates.public()} == set(templates.TEMPLATES)


def test_values_and_levels():
    from app.integrations.calls import level, pick, value

    data = {"disks": [{"free": 10, "ok": True}, {"free": 30, "ok": False}], "n": "42"}
    assert pick(data, "disks.*.free") == [10, 30]
    assert value(data, {"path": "disks.*.free", "format": "bytes"}) == ({"bytes": 40}, 40)
    assert value(data, {"path": "disks.*.free", "format": "min"})[0] == 10
    assert value(data, {"path": "disks.*.ok", "format": "count", "equals": "true"})[0] == 1
    assert value(data, {"path": "n", "suffix": " °C"})[0] == "42 °C"
    assert value(data, {"path": "x"})[0] == "—"
    # Lager is slechter als geel groter is dan rood (bv. vrije ruimte).
    assert level(15, {"warn": 20, "err": 10}) == "warn" and level(5, {"warn": 20, "err": 10}) == "err"
    assert level(95, {"warn": 80, "err": 90}) == "err" and level(None, {"warn": 1}) is None
