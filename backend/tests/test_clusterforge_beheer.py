"""ClusterForge beheert het dashboard: groepen per cluster, tegels per cluster en node, bijwerken, weghalen,
veiligheidsrem, overnemen van bestaande tegels, en een ClusterForge zonder /nodes."""

import httpx
import pytest
from sqlalchemy import select

from app import clusterforge_sync as cfs
from app.models import Group, Page, Service
from app.monitoring import integrationchecks as ic
from app.monitoring.checks import HttpClients
from app.routers import integrations as router

from .test_clusterforge import BASE, TOKEN, FakeCF, _api, _tile
from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db

CL = {"databasecluster": "00000000-0000-0000-0000-00000000000d", "homepage": "00000000-0000-0000-0000-00000000000h"}


def _node(i, host, cluster=None, **kw):
    n = {"id": f"00000000-0000-0000-0000-0000000000{i:02d}", "hostname": host, "cluster_id": CL.get(cluster),
         "cluster_slug": cluster, "cluster_name": cluster and cluster.title(), "role": "db" if cluster else "",
         "description": "", "lifecycle": "active", "primary_ip": f"192.168.113.{20 + i}", "tags": [],
         "status": "healthy", "status_label": "Gezond", "status_reason": "", "online": True, "maintenance": False,
         "updates": 0, "updates_security": 0, "reboot_required": False,
         "proxmox": {"host": "pve50", "vmid": 100 + i, "type": "lxc", "name": host},
         "url": f"{BASE}/nodes/detail?id=n{i}"}
    n.update(kw)
    return n


class FakeCFNodes(FakeCF):
    def __init__(self, with_nodes=True):
        super().__init__()
        for c in self.clusters:
            c["id"] = CL[c["slug"]]
        self.with_nodes = with_nodes
        self.nodes = [_node(1, "db1", "databasecluster"), _node(2, "db2", "databasecluster"),
                      _node(3, "hp1", "homepage"), _node(4, "hp3", "homepage", online=False, status="down",
                                                         status_label="Down", status_reason="geen heartbeat"),
                      _node(5, "losse-vm")]

    def __call__(self, req):
        if req.url.path == "/api/dashboard/v1/nodes" and self.with_nodes:
            if (req.headers.get("authorization") or "") != f"Bearer {TOKEN}":
                return httpx.Response(401, json={"message": "fout token"})
            return httpx.Response(200, json=self.nodes)
        return super().__call__(req)


@pytest.fixture
def cfn(monkeypatch):
    fake = FakeCFNodes()
    http = HttpClients(httpx.MockTransport(fake))
    monkeypatch.setattr(router, "clients", http)
    router._cache.clear()
    return fake, http


async def _state(db):
    tiles = (await db.execute(select(Service).where(Service.type == "clusterforge"))).scalars().all()
    groups = {g.id: g.name for g in (await db.execute(select(Group))).scalars()}
    return {t.config.get(cfs.MARK): (t.name, groups[t.group_id]) for t in tiles if t.config.get(cfs.MARK)}, tiles


async def test_beheer_builds_and_keeps_the_dashboard_in_sync(authed, cfn):
    fake, http = cfn
    g = await _group(authed)
    api = await _api(authed)
    src = await _tile(authed, g, api)

    st = (await authed.get("/api/clusterforge/beheer")).json()
    assert st["service_id"] is None and st["sources"] == [{"id": src, "name": "ClusterForge"}]
    r = (await authed.put("/api/clusterforge/beheer", json={"service_id": src})).json()
    assert r["result"]["added"] == 7 and r["result"]["nodes"] == 5  # 2 clusters + 5 nodes

    agen, db = await _db()
    marks, tiles = await _state(db)
    assert marks == {
        f"cluster:{CL['databasecluster']}": ("Databasecluster", "Databasecluster"),
        f"cluster:{CL['homepage']}": ("Homepage", "Homepage"),
        f"node:{fake.nodes[0]['id']}": ("db1", "Databasecluster"), f"node:{fake.nodes[1]['id']}": ("db2", "Databasecluster"),
        f"node:{fake.nodes[2]['id']}": ("hp1", "Homepage"), f"node:{fake.nodes[3]['id']}": ("hp3", "Homepage"),
        f"node:{fake.nodes[4]['id']}": ("losse-vm", "Losse nodes")}
    page = (await db.execute(select(Page).where(Page.name == "ClusterForge"))).scalar_one()
    assert {gr.page_id for gr in (await db.execute(select(Group).where(Group.name != "G"))).scalars()} == {page.id}
    hp3 = next(t for t in tiles if t.name == "hp3")
    assert hp3.api_id == api and hp3.parent_id == src and hp3.check == {"type": "api", "interval": 60}
    assert hp3.url == f"{BASE}/nodes/detail?id=n4" and hp3.description == "db · 192.168.113.24"
    # De check van een node: rood als hij offline is, groen in onderhoud.
    out = await ic.check_api(db, hp3, {"type": "api"}, http)
    assert not out.ok and "hp3: Down" in out.error and "geen heartbeat" in out.error
    db1 = next(t for t in tiles if t.name == "db1")
    assert (await ic.check_api(db, db1, {"type": "api"}, http)).ok
    fake.nodes[3]["maintenance"] = True
    assert (await ic.check_api(db, hp3, {"type": "api"}, http)).ok
    db1_id, hp3_id = db1.id, hp3.id
    await db.close()

    w = (await authed.get("/api/widgets")).json()
    f = {x["label"]: x for x in w[str(db1_id)]["fields"]}
    assert f["IP"]["value"] == "192.168.113.21" and f["online"]["value"] == "ja"
    d = (await authed.get(f"/api/services/{hp3_id}/integration")).json()
    assert d["sections"][0]["title"] == "hp3" and d["sections"][0]["href"].endswith("id=n4")

    # Een eigen icoon en een eigen tegel in een beheerde groep blijven.
    agen, db = await _db()
    db1 = await db.get(Service, db1_id)
    db1.icon = "mariadb.png"
    gid = db1.group_id
    await db.commit()
    await db.close()
    own = await _svc(authed, gid, "link", "https://pma.jbogaert.be", name="phpMyAdmin")

    # ClusterForge verandert: db2 weg, nieuwe node db3, hp1 naar het databasecluster, cluster hernoemd,
    # het homepage-cluster weg (met zijn laatste node hp3).
    fake.nodes = [fake.nodes[0], _node(6, "db3", "databasecluster"), {**fake.nodes[2], "cluster_id": CL["databasecluster"]},
                  fake.nodes[4]]
    fake.clusters = [{**fake.clusters[0], "name": "DB-cluster"}]
    agen, db = await _db()
    r = await cfs.sync(db, http)
    await db.commit()
    assert (r["added"], r["removed"], r["held"]) == (1, 3, 0)  # db3 nieuw; db2, hp3 en cluster homepage weg
    marks, tiles = await _state(db)
    assert sorted(n for n, _ in marks.values()) == ["DB-cluster", "db1", "db3", "hp1", "losse-vm"]
    assert {g for _, g in marks.values()} == {"DB-cluster", "Losse nodes"}
    assert (await db.get(Service, db1_id)).icon == "mariadb.png"
    assert await db.get(Service, own) is not None
    assert (await db.execute(select(Group).where(Group.name == "Homepage"))).scalar_one_or_none() is None
    await db.close()

    # Veiligheidsrem: alles weg in één keer (bv. token beperkt) → de worker laat ze staan, met de hand gaat het wel.
    fake.clusters, fake.nodes = [], []
    agen, db = await _db()
    r = await cfs.sync(db, http)
    await db.commit()
    assert r["removed"] == 0 and r["held"] == 5
    await db.close()
    r = (await authed.post("/api/clusterforge/beheer/sync", json={"force": True})).json()
    assert r["removed"] == 5
    st = (await authed.get("/api/clusterforge/beheer")).json()
    assert st["managed"] == 0 and st["last"]["removed"] == 5


async def test_without_nodes_endpoint_and_adopting_imported_tiles(authed, monkeypatch):
    fake = FakeCFNodes(with_nodes=False)
    http = HttpClients(httpx.MockTransport(fake))
    monkeypatch.setattr(router, "clients", http)
    router._cache.clear()
    g = await _group(authed)
    src = await _svc(authed, g, "clusterforge", BASE, secrets={"token": TOKEN}, name="CF")
    # Eerder met "tegels per cluster" gemaakt: die tegel wordt overgenomen, niet verdubbeld.
    assert (await authed.post(f"/api/services/{src}/clusterforge/import",
                              json={"group_id": g, "clusters": ["homepage"]})).json() == {"added": 1}
    r = (await authed.put("/api/clusterforge/beheer", json={"service_id": src})).json()["result"]
    assert r["nodes"] is None and r["added"] == 1 and r["changed"] == 1
    agen, db = await _db()
    marks, tiles = await _state(db)
    assert len(tiles) == 3 and sorted(n for n, _ in marks.values()) == ["Databasecluster", "Homepage"]
    hp = next(t for t in tiles if t.name == "Homepage")
    assert hp.config == {"url": BASE, "cluster": "homepage", cfs.MARK: f"cluster:{CL['homepage']}"} and hp.secrets
    await db.close()
    st = (await authed.get("/api/clusterforge/beheer")).json()
    assert st["last"]["nodes"] is None and st["sources"] == [{"id": src, "name": "CF"}]

    # Fout token: niets verandert, de fout staat bij het beheer.
    agen, db = await _db()
    from app.security import encrypt_json
    (await db.get(Service, src)).secrets = encrypt_json({"token": "cfa_fout"})
    await db.commit()
    r = await cfs.sync(db, http)
    await db.commit()
    assert "401" in r["error"]
    assert len((await _state(db))[1]) == 3
    await db.close()

    # Uitzetten: de tegels blijven, de worker doet niets meer.
    assert (await authed.put("/api/clusterforge/beheer", json={"service_id": None})).json()["result"] is None
    agen, db = await _db()
    assert (await cfs.sync(db, http)) == {"skipped": True}
    await db.close()
    assert (await authed.put("/api/clusterforge/beheer", json={"service_id": hp.id})).status_code == 400
