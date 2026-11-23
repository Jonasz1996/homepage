"""ClusterForge (homepage-API v2): de tegels komen vanzelf, met de stats uit ClusterForge."""

import httpx
from sqlalchemy import select

from app.integrations import IntegrationError
from app.models import ApiConnection, AppState, Group, Page, Service
from app.monitoring import clusterforge
from app.monitoring.checks import HttpClients
from app.routers import integrations as router
from app.security import encrypt_json

from .test_capacity import _db

CF = "http://cf.lan:8080"


def layout(*tiles, version="v1"):
    groups = {}
    for g, t in tiles:
        groups.setdefault(g, []).append(t)
    return {"version": version, "managed_by": "clusterforge", "groups": [{"name": g, "tiles": ts} for g, ts in groups.items()]}


def tile(key, app, name, icon="plex.png", href="https://plex.jbogaert.be"):
    return {"key": key, "app": app, "name": name, "icon": icon, "href": href, "description": "plex1", "api": "", "gone": False}


class Fake:
    def __init__(self):
        self.layout = layout(("Media", tile("plex@plex1", "plex", "Plex")),
                             ("Infrastructuur", tile("homepage@hp", "homepage", "Homepage", "homepage.png", "https://homepage.jbogaert.be")))
        self.calls = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        assert request.headers["Authorization"] == "Bearer cfa_test"
        if request.url.path == "/api/dashboard/v2/homepage/layout":
            etag = '"' + self.layout["version"] + '"'
            if request.headers.get("If-None-Match") == etag:
                return httpx.Response(304)
            return httpx.Response(200, json=self.layout, headers={"ETag": etag})
        if request.url.path == "/api/dashboard/v2/apps/plex":
            return httpx.Response(200, json={
                "slug": "plex", "status": "warn", "status_label": "Let op",
                "fields": [{"key": "status", "label": "Status", "value": "Let op", "level": "warn"},
                           {"key": "cluster_health", "label": "Clusterscore", "value": 93.6, "format": "percent"},
                           {"key": "reboot_required", "label": "Herstart nodig", "value": False}],
                "sections": [{"type": "kv", "title": "Overzicht", "items": [{"label": "Actief op", "value": "plex1"}]},
                             {"type": "table", "title": "Waar het draait", "items": [{"node": "plex1", "status": "online"}]}],
                "clusterforge_url": CF + "/homepage-apps?app=plex"})
        return httpx.Response(404)


async def _setup(sync=True):
    agen, db = await _db()
    page = Page(name="Home")
    db.add(page)
    await db.flush()
    mine = Group(page_id=page.id, name="Media", position=0)
    db.add(mine)
    await db.flush()
    db.add(Service(group_id=mine.id, name="Eigen tegel", type="link", url="https://x"))
    cfg = {} if sync else {"sync": False}
    conn = ApiConnection(name="ClusterForge", kind="clusterforge", url=CF, config=cfg, secrets=encrypt_json({"token": "cfa_test"}))
    db.add(conn)
    await db.commit()
    return agen, db, conn


async def _services(db):
    db.expire_all()
    return {s.name: s for s in (await db.execute(select(Service))).scalars().all()}


async def test_sync_maakt_wijzigt_en_verwijdert(client):
    agen, db, conn = await _setup()
    fake = Fake()
    http = HttpClients(httpx.MockTransport(fake))
    await clusterforge.run_sync(db, http)
    await db.commit()
    s = await _services(db)
    assert set(s) == {"Eigen tegel", "Plex", "Homepage"}
    plex = s["Plex"]
    assert plex.type == "clusterforge" and plex.api_id == conn.id and plex.config["app"] == "plex"
    assert plex.check == {"type": "http", "interval": 60}  # met een link: de homepage kijkt zelf naar het doel
    assert plex.group_id == s["Eigen tegel"].group_id  # bestaande groep Media hergebruikt
    groups = {g.name for g in (await db.execute(select(Group))).scalars().all()}
    assert groups == {"Media", "Infrastructuur"}

    # Niets veranderd: 304, geen wijzigingen.
    n = len(fake.calls)
    await clusterforge.run_sync(db, http)
    await db.commit()
    assert fake.calls[n].headers.get("If-None-Match") == '"v1"'

    # In ClusterForge hernoemd, homepage verborgen: tegel bijgewerkt en verwijderd; de eigen tegel blijft.
    fake.layout = layout(("Media", tile("plex@plex1", "plex", "Plex films")), version="v2")
    await clusterforge.run_sync(db, http)
    await db.commit()
    s = await _services(db)
    assert set(s) == {"Eigen tegel", "Plex films"}
    await agen.aclose()


async def test_sync_uit_en_fout(client):
    agen, db, conn = await _setup(sync=False)
    await clusterforge.run_sync(db, HttpClients(httpx.MockTransport(Fake())))
    await db.commit()
    assert set(await _services(db)) == {"Eigen tegel"}
    conn.config = {}
    await db.commit()
    await clusterforge.run_sync(db, HttpClients(httpx.MockTransport(lambda r: httpx.Response(401))))
    await db.commit()
    st = (await db.execute(select(AppState).where(AppState.key == "clusterforge"))).scalar_one()
    assert "401" in st.value[str(conn.id)]["error"]
    await agen.aclose()


async def test_tegel_toont_velden_en_detail(authed, monkeypatch):
    agen, db, conn = await _setup()
    await clusterforge.run_sync(db, HttpClients(httpx.MockTransport(Fake())))
    await db.commit()
    plex = (await _services(db))["Plex"]
    await agen.aclose()
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(Fake())))
    r = await authed.get("/api/widgets")
    assert r.status_code == 200, r.text
    summary = r.json()[str(plex.id)]["fields"]
    assert summary[0] == {"label": "Status", "value": "Let op", "level": "warn"}
    assert summary[1]["value"] == "94%" and summary[2]["value"] == "nee"
    r = await authed.get(f"/api/services/{plex.id}/integration")
    assert r.status_code == 200, r.text
    kinds = [s["kind"] for s in r.json()["sections"]]
    assert kinds == ["kv", "table", "kv"]


async def test_check_vraagt_strict():
    from app.integrations.clusterforge import ClusterForge

    seen = []
    fake = Fake()

    def handler(request):
        seen.append(str(request.url))
        return fake(request)

    c = ClusterForge(CF, {"app": "plex"}, {"token": "cfa_test"}, httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    data = await c.health()
    assert isinstance(data, dict)
    assert seen and seen[-1].endswith("/api/dashboard/v2/apps/plex?strict=1")


# --- bevindingen 23/11: namen, dubbels, groepen, Proxmox, kopieën ------------------------------------------------

def test_prepare_namen_dubbels_groepen():
    lay = layout(
        ("Overig", tile("a@1", "web", "302 Found", "x.png", "http://192.168.10.203")),
        ("Overig", tile("b@1", "ai", "Ai", "ai.png", "https://ai.jbogaert.be")),
        ("Infra", tile("c@cl", "authentik", "Authentik (Authentik)", "authentik.png", "https://auth.jbogaert.be/")),
        ("Overig", tile("d@npm", "authentik", "Authentik (npm)", "authentik.png", "https://auth.jbogaert.be")),
        ("overig", tile("e@npm", "jellyfin", "Jellyfin (npm)", "jellyfin.png", "https://jellyfin.jbogaert.be")),
        ("Media", tile("f@1", "plex", "Plex", "plex.png", "https://plex.jbogaert.be")),
        ("Overig", tile("g@1", "gitea", "Gitea", "gitea.png", "https://git.jbogaert.be")),
        ("Overig", tile("h@1", "iets", "Iets", "iets.png", "https://iets.jbogaert.be")),
    )
    out = {o["key"]: o for o in clusterforge.prepare(lay)}
    assert set(out) == {"a@1", "b@1", "c@cl", "e@npm", "f@1", "g@1", "h@1"}  # d@npm is een dubbel van c@cl
    assert out["a@1"]["name"] == "Web" and out["a@1"]["group"] == "Overig"  # IP: de naam van de app
    assert out["b@1"]["name"] == "Ai" and out["b@1"]["group"] == "AI"
    assert out["c@cl"]["name"] == "Authentik"
    assert out["e@npm"]["name"] == "Jellyfin" and out["e@npm"]["group"] == "Media"  # bestaande groep Media
    assert out["g@1"]["group"] == "Infrastructuur"
    assert out["h@1"]["group"] == "Overig"


def test_naam_uit_link():
    assert clusterforge.clean_name("302 Found", "https://ai.jbogaert.be", "web") == "AI"
    assert clusterforge.clean_name("Welcome to nginx!", "https://home-assistant.x.be", "ha") == "Home Assistant"
    assert clusterforge.clean_name("Plex", "https://plex.x", "plex") == "Plex"


def test_match_node():
    pve = [(7, [{"name": "pve50", "ip": "192.168.0.50"}, {"name": "pve100", "ip": "192.168.0.100"}])]
    assert clusterforge.match_node({"href": "https://proxmox50.jbogaert.be", "name": "Proxmox"}, pve) == (7, "pve50")
    assert clusterforge.match_node({"href": "https://192.168.0.100:8006", "name": "Proxmox"}, pve) == (7, "pve100")
    assert clusterforge.match_node({"href": "https://x.be", "name": "Proxmox", "description": "pve50"}, pve) == (7, "pve50")
    assert clusterforge.match_node({"href": "https://proxmox.jbogaert.be", "name": "Proxmox"}, pve) is None
    assert clusterforge.is_proxmox("proxmox", "proxmox.png") and not clusterforge.is_proxmox("pbs", "proxmox-backup.png")


async def test_proxmox_tegels_aan_proxmox_api(client):
    agen, db, conn = await _setup()
    pve = ApiConnection(name="Proxmox", kind="proxmox", url="https://192.168.0.50:8006", config={},
                        secrets=encrypt_json({"username": "u@pve!t", "password": "x"}))
    db.add(pve)
    await db.commit()
    fake = Fake()
    fake.layout = layout(("Infrastructuur", tile("pve@50", "proxmox", "Proxmox", "proxmox.png", "https://proxmox50.jbogaert.be")),
                         ("Infrastructuur", tile("pve@100", "proxmox", "Proxmox 100", "proxmox.png", "https://proxmox100.jbogaert.be")),
                         ("Infrastructuur", tile("pve@x", "proxmox", "Proxmox X", "proxmox.png", "https://proxmoxx.jbogaert.be")))

    def handler(request):
        if request.url.path == "/api2/json/cluster/status":
            return httpx.Response(200, json={"data": [{"type": "cluster", "name": "c"},
                                                      {"type": "node", "name": "pve50", "ip": "192.168.0.50"},
                                                      {"type": "node", "name": "pve100", "ip": "192.168.0.100"}]})
        return fake(request)

    await clusterforge.run_sync(db, HttpClients(httpx.MockTransport(handler)))
    await db.commit()
    s = await _services(db)
    assert s["Proxmox"].type == "proxmox" and s["Proxmox"].api_id == pve.id and s["Proxmox"].config["node"] == "pve50"
    assert s["Proxmox 100"].config["node"] == "pve100"
    x = s["Proxmox X"]
    assert x.type == "clusterforge" and x.api_id == conn.id and x.config["cf_zelfde"] == "Proxmox"
    # Een volgende ronde (304) laat ze zo; de tegels blijven van deze ClusterForge-API.
    await clusterforge.run_sync(db, HttpClients(httpx.MockTransport(handler)))
    await db.commit()
    assert len(await _services(db)) == 4
    await agen.aclose()


async def test_kopie_toont_alleen_status():
    from app.integrations.clusterforge import ClusterForge

    def handler(request):
        return httpx.Response(200, json={"slug": "plex", "status": "ok", "status_label": "Gezond", "fields": [
            {"key": "status", "label": "Status", "value": "Gezond", "level": "ok"},
            {"key": "nodes", "label": "Nodes", "value": "0/0"}, {"key": "cpu", "label": "CPU", "value": "18%"}]})

    c = ClusterForge(CF, {"app": "plex"}, {"token": "cfa_test"}, httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert [f["label"] for f in await c.summary()] == ["Status", "CPU"]  # Nodes 0/0 weg
    c = ClusterForge(CF, {"app": "plex", "cf_zelfde": "Plex"}, {"token": "cfa_test"},
                     httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert [f["label"] for f in await c.summary()] == ["Status"]
