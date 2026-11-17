"""ClusterForge: tegel (overzicht, één cluster, SOC), mini dashboard, check en tegels per cluster, tegen een
nagebootste dashboard-API met de velden zoals ClusterForge ze geeft (internal/httpapi/dashboard.go)."""

import httpx
import pytest
from sqlalchemy import select

from app.models import Service
from app.monitoring import integrationchecks as ic
from app.monitoring.checks import HttpClients
from app.routers import integrations as router

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db

TOKEN = "cfa_abcdefghijklmnop0123456789"
SCOPED = "cfa_alleendbcluster0000000000"
BASE = "http://192.168.113.153:8080"


def _cluster(slug, name, status="healthy", **kw):
    c = {"id": f"00000000-0000-0000-0000-{abs(hash(slug)) % 10**12:012d}", "slug": slug, "name": name,
         "environment": "prod", "type": "database", "url": f"{BASE}/clusters/detail?id={slug}",
         "status": status, "status_label": {"healthy": "Gezond", "degraded": "Verminderd", "down": "Down"}[status],
         "status_reason": "", "ok": status == "healthy", "score": 92, "grade": "A", "nodes_online": 3, "nodes_total": 3,
         "nodes": "3/3", "nodes_down": [], "vip": "192.168.113.10", "vip_owner": "db1",
         "vips": [{"address": "192.168.113.10", "owner": "db1"}], "db": "ok", "db_label": "MariaDB 3/3",
         "db_running": 3, "db_total": 3, "incidents_open": 0, "incidents_worst": "", "updates": 4, "updates_security": 0,
         "reboot_required": 0, "nodes_with_updates": 2, "crowdsec": "3/3 actief", "crowdsec_running": 3,
         "crowdsec_managed": 3, "crowdsec_bans": 7, "crowdsec_alerts_24h": 2, "firewall": "3/3 actief",
         "firewall_active": 3, "firewall_managed": 3, "firewall_blocked_24h": 120, "problems": []}
    c.update(kw)
    return c


class FakeCF:
    def __init__(self):
        self.requests: list[httpx.Request] = []
        self.clusters = [
            _cluster("databasecluster", "Databasecluster"),
            _cluster("homepage", "Homepage", "degraded", ok=False, status_reason="node3 reageert niet", nodes="2/3",
                     nodes_online=2, nodes_down=["hp3"], db="degraded", db_label="PostgreSQL 2/3", incidents_open=1,
                     incidents_worst="high", updates_security=2, reboot_required=1, vip_owner="",
                     vips=[{"address": "192.168.10.150", "owner": ""}], vip="192.168.10.150",
                     problems=["node3 reageert niet", "offline: hp3", "1 open incident(en)"]),
        ]
        self.soc = {"ok": True, "level": "waakzaam", "level_label": "Waakzaam", "reason": "2 aanvallen", "score": 81,
                    "attacks_24h": 2, "active_bans": 7, "blocked_24h": 120, "login_failures_24h": 3,
                    "protected": "5/6", "nodes_unprotected": 1, "attention": 1, "url": f"{BASE}/soc"}

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.requests.append(req)
        assert req.method == "GET" and req.url.host == "192.168.113.153"
        tok = (req.headers.get("authorization") or "").removeprefix("Bearer ")
        if tok not in (TOKEN, SCOPED):
            return httpx.Response(401, json={"code": "unauthenticated", "message": "onbekend, ingetrokken of verlopen API-token"})
        cl = self.clusters if tok == TOKEN else self.clusters[:1]
        p = req.url.path.removeprefix("/api/dashboard/v1")
        if p == "/":
            return httpx.Response(200, json={
                "generated_at": "2026-11-16T21:00:00Z", "clusters_total": len(cl),
                "clusters_healthy": sum(c["status"] == "healthy" for c in cl),
                "clusters_degraded": sum(c["status"] == "degraded" for c in cl),
                "clusters_down": sum(c["status"] == "down" for c in cl),
                "nodes_online": sum(c["nodes_online"] for c in cl), "nodes_total": sum(c["nodes_total"] for c in cl),
                "nodes": f"{sum(c['nodes_online'] for c in cl)}/{sum(c['nodes_total'] for c in cl)}",
                "incidents_open": sum(c["incidents_open"] for c in cl), "updates": sum(c["updates"] for c in cl),
                "updates_security": sum(c["updates_security"] for c in cl), "crowdsec_bans": 7, "crowdsec_alerts_24h": 2,
                "clusters": cl})
        if p == "/soc":
            if tok == SCOPED:
                return httpx.Response(403, json={"code": "forbidden", "message": "maak er een token voor alle clusters voor"})
            return httpx.Response(200, json=self.soc)
        if p.startswith("/clusters/"):
            key = p.removeprefix("/clusters/").lower()
            for c in cl:
                if key in (c["slug"], c["name"].lower(), c["id"]):
                    return httpx.Response(200, json=c)
            return httpx.Response(404, json={"code": "not_found", "message": "cluster niet gevonden (of niet zichtbaar met dit token)"})
        return httpx.Response(404, json={"code": "not_found", "message": "onbekend endpoint"})


@pytest.fixture
def cf(monkeypatch):
    fake = FakeCF()
    http = HttpClients(httpx.MockTransport(fake))
    monkeypatch.setattr(router, "clients", http)
    router._cache.clear()
    return fake, http


async def _api(authed, token=TOKEN, config=None) -> int:
    r = await authed.post("/api/apis", json={"name": "ClusterForge", "category": "Monitoring", "kind": "clusterforge",
                                             "url": BASE, "config": config or {}, "secrets": {"token": token}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _tile(authed, g, api, name="ClusterForge", config=None) -> int:
    sid = await _svc(authed, g, "link", "https://clusterforge.jbogaert.be", name=name, config=config)
    assert (await authed.post(f"/api/apis/{api}/tiles", json={"service_ids": [sid]})).json()["changed"] == 1
    return sid


def _fields(w):
    return {f["label"]: f for f in w["fields"]}


async def test_overview_tile_and_mini_dashboard(authed, cf):
    fake, _ = cf
    g = await _group(authed)
    sid = await _tile(authed, g, await _api(authed, config={"link": "https://clusterforge.jbogaert.be"}))

    f = _fields((await authed.get("/api/widgets")).json()[str(sid)])
    assert f["clusters"]["value"] == "1/2 gezond" and f["clusters"]["level"] == "warn"
    assert f["nodes"]["value"] == "5/6" and f["nodes"]["level"] == "err"
    assert f["incidenten"]["value"] == 1 and f["incidenten"]["level"] == "err"
    assert f["updates"]["value"] == "8 (2 beveiliging)" and f["SOC"]["value"] == "Waakzaam"
    # Op IP, met het token als Bearer, op het pad van de dashboard-API.
    assert all(r.url.path.startswith("/api/dashboard/v1") for r in fake.requests)
    assert fake.requests[0].headers["authorization"] == f"Bearer {TOKEN}"

    d = (await authed.get(f"/api/services/{sid}/integration")).json()
    secs = {s["title"]: s for s in d["sections"]}
    rows = secs["clusters"]["rows"]
    assert [r["cells"][0]["v"] for r in rows] == ["Homepage", "Databasecluster"]  # wat niet in orde is eerst
    hp = rows[0]["cells"]
    assert hp[0]["href"] == "https://clusterforge.jbogaert.be/clusters/detail?id=homepage"  # link i.p.v. het IP
    assert hp[1] == {"v": "Verminderd", "level": "warn"}
    assert hp[4]["v"] == "192.168.10.150 → geen node" and hp[4]["level"] == "err"
    assert rows[1]["cells"][4]["v"] == "192.168.113.10 → db1"
    assert [r[1]["v"] for r in secs["wat er mis is"]["rows"]][:2] == ["node3 reageert niet", "offline: hp3"]
    assert secs["beveiliging (SOC)"]["href"] == "https://clusterforge.jbogaert.be/soc"
    assert secs["tegels per cluster"]["kind"] == "clusterforge-tiles"
    assert TOKEN not in str(d)


async def test_cluster_tile_check_turns_red_with_reason(authed, cf):
    fake, http = cf
    g = await _group(authed)
    api = await _api(authed)
    ok = await _tile(authed, g, api, "DB", config={"cluster": "Databasecluster"})  # naam werkt ook
    bad = await _tile(authed, g, api, "HP", config={"cluster": "homepage"})

    w = (await authed.get("/api/widgets")).json()
    assert _fields(w[str(ok)])["status"] == {"label": "status", "value": "Gezond", "level": "ok"}
    f = _fields(w[str(bad)])
    assert f["status"]["level"] == "warn" and f["nodes"]["level"] == "err" and f["VIP"]["value"] == "geen node"

    agen, db = await _db()
    out = await ic.check_api(db, await db.get(Service, ok), {"type": "api"}, http)
    assert out.ok and out.status_code == 200
    out = await ic.check_api(db, await db.get(Service, bad), {"type": "api"}, http)
    assert not out.ok and "Homepage: Verminderd" in out.error and "node3 reageert niet" in out.error

    fake.clusters[1].update(status="healthy", status_label="Gezond", ok=True, problems=[])
    assert (await ic.check_api(db, await db.get(Service, bad), {"type": "api"}, http)).ok

    gone = await _tile(authed, g, api, "weg", config={"cluster": "bestaatniet"})
    out = await ic.check_api(db, await db.get(Service, gone), {"type": "api"}, http)
    assert not out.ok and "cluster niet gevonden" in out.error
    await db.close()

    d = (await authed.get(f"/api/services/{bad}/integration")).json()
    assert d["sections"][0]["title"] == "Homepage" and d["sections"][0]["href"].startswith(BASE)


async def test_soc_tile_and_scoped_token(authed, cf):
    fake, http = cf
    g = await _group(authed)
    soc = await _tile(authed, g, await _api(authed), "SOC", config={"soc": "true"})
    f = _fields((await authed.get("/api/widgets")).json()[str(soc)])
    assert f["niveau"]["value"] == "Waakzaam" and f["beschermd"]["level"] == "warn"

    agen, db = await _db()
    assert (await ic.check_api(db, await db.get(Service, soc), {"type": "api"}, http)).ok
    fake.soc.update(ok=False, level="verhoogd", level_label="Verhoogd", reason="brute force op db1")
    out = await ic.check_api(db, await db.get(Service, soc), {"type": "api"}, http)
    assert not out.ok and "SOC Verhoogd: brute force op db1" in out.error

    # Een token voor enkele clusters ziet geen SOC: het overzicht werkt gewoon, zonder SOC.
    g2 = await _group(authed)
    scoped = await _tile(authed, g2, await _api(authed, SCOPED), "CF beperkt")
    f = _fields((await authed.get("/api/widgets")).json()[str(scoped)])
    assert f["clusters"]["value"] == "1/1 gezond" and "SOC" not in f
    assert (await ic.check_api(db, await db.get(Service, scoped), {"type": "api"}, http)).ok
    await db.close()


async def test_wrong_token_says_so(authed, cf):
    g = await _group(authed)
    sid = await _tile(authed, g, await _api(authed, "cfa_fout"))
    w = (await authed.get("/api/widgets")).json()[str(sid)]
    assert "401" in w["error"] and "cfa_fout" not in str(w)


async def test_tiles_per_cluster(authed, cf):
    g = await _group(authed)
    api = await _api(authed)
    sid = await _tile(authed, g, api)
    lst = (await authed.get(f"/api/services/{sid}/clusterforge/clusters")).json()
    assert [(c["slug"], c["exists"], c["ok"]) for c in lst] == [("databasecluster", False, True), ("homepage", False, False)]

    r = await authed.post(f"/api/services/{sid}/clusterforge/import",
                          json={"group_id": g, "clusters": ["databasecluster", "homepage", "onbekend"]})
    assert r.json() == {"added": 2}
    agen, db = await _db()
    tiles = (await db.execute(select(Service).where(Service.parent_id == sid).order_by(Service.name))).scalars().all()
    assert [(t.name, t.type, t.api_id, t.config, t.check) for t in tiles] == [
        ("Databasecluster", "clusterforge", api, {"cluster": "databasecluster"}, {"type": "api", "interval": 60}),
        ("Homepage", "clusterforge", api, {"cluster": "homepage"}, {"type": "api", "interval": 60})]
    assert tiles[0].url == f"{BASE}/clusters/detail?id=databasecluster"
    await db.close()
    # Nog eens: niets dubbel.
    assert all(c["exists"] for c in (await authed.get(f"/api/services/{sid}/clusterforge/clusters")).json())
    r = await authed.post(f"/api/services/{sid}/clusterforge/import", json={"group_id": g, "clusters": ["homepage"]})
    assert r.json() == {"added": 0}

    # Een tegel met eigen sleutels (zonder API-beheer) geeft zijn url en sleutels door.
    own = await _svc(authed, g, "clusterforge", BASE, config={"insecure": False}, secrets={"token": TOKEN}, name="CF eigen")
    g2 = await _group(authed)
    await authed.delete(f"/api/services/{tiles[0].id}")
    r = await authed.post(f"/api/services/{own}/clusterforge/import", json={"group_id": g2, "clusters": ["databasecluster"]})
    assert r.json() == {"added": 1}
    w = (await authed.get("/api/widgets")).json()
    agen, db = await _db()
    new = (await db.execute(select(Service).where(Service.parent_id == own))).scalar_one()
    assert new.api_id is None and new.config == {"insecure": False, "url": BASE, "cluster": "databasecluster"}
    await db.close()
    assert _fields(w[str(new.id)])["status"]["value"] == "Gezond"

    link = await _svc(authed, g, "link", "https://x.jbogaert.be", name="gewoon")
    assert (await authed.get(f"/api/services/{link}/clusterforge/clusters")).status_code == 400
