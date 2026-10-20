import yaml

HOMEPAGE_YAML = """
- Proxmox:
    - pve50:
        icon: proxmox.png
        href: https://proxmox50.jbogaert.be
        description: HP node
        siteMonitor: https://proxmox50.jbogaert.be
        widget:
          type: proxmox
          url: https://192.168.0.50:8006
          username: api@pam!homepage
          password: geheim-token
          node: pve50
    - Backups:
        - pbs:
            href: https://proxmoxbackup.jbogaert.be
            ping: 192.168.0.60
- Media:
    - Plex:
        href: https://plex.jbogaert.be
        icon: plex.png
"""


async def _make_basic(c):
    page = (await c.post("/api/pages", json={"name": "Home"})).json()["id"]
    g1 = (await c.post("/api/groups", json={"page_id": page, "name": "Netwerk"})).json()["id"]
    g2 = (await c.post("/api/groups", json={"page_id": page, "name": "Media"})).json()["id"]
    s1 = (await c.post("/api/services", json={
        "group_id": g1, "name": "AdGuard", "url": "https://adguard.jbogaert.be",
        "type": "adguard", "secrets": {"password": "s3cret"},
    })).json()["id"]
    s2 = (await c.post("/api/services", json={"group_id": g1, "name": "NPM"})).json()["id"]
    return page, g1, g2, s1, s2


async def test_requires_login(client):
    assert (await client.get("/api/layout")).status_code == 401
    assert (await client.post("/api/pages", json={"name": "x"})).status_code == 401


async def test_crud_and_secrets_hidden(authed):
    page, g1, g2, s1, s2 = await _make_basic(authed)
    layout = (await authed.get("/api/layout")).json()
    svc = layout["pages"][0]["groups"][0]["services"][0]
    assert svc["name"] == "AdGuard"
    assert svc["secret_keys"] == ["password"]
    assert "s3cret" not in str(layout)
    assert "secrets" not in svc

    # Secret leegmaken verwijdert de sleutel; secrets weglaten laat ze staan.
    body = {"group_id": g1, "name": "AdGuard Home", "type": "adguard"}
    assert (await authed.patch(f"/api/services/{s1}", json=body)).status_code == 200
    assert (await authed.get(f"/api/services/{s1}")).json()["secret_keys"] == ["password"]
    body["secrets"] = {"password": ""}
    await authed.patch(f"/api/services/{s1}", json=body)
    assert (await authed.get(f"/api/services/{s1}")).json()["secret_keys"] == []


async def test_bad_url_rejected(authed):
    _, g1, *_ = await _make_basic(authed)
    r = await authed.post("/api/services", json={"group_id": g1, "name": "x", "url": "javascript:alert(1)"})
    assert r.status_code == 422


async def test_order_moves_between_groups(authed):
    page, g1, g2, s1, s2 = await _make_basic(authed)
    r = await authed.put("/api/layout/order", json={
        "groups": {str(page): [g2, g1]},
        "services": {str(g1): [s2], str(g2): [s1]},
    })
    assert r.status_code == 200
    groups = (await authed.get("/api/layout")).json()["pages"][0]["groups"]
    assert [g["name"] for g in groups] == ["Media", "Netwerk"]
    assert [s["name"] for s in groups[0]["services"]] == ["AdGuard"]
    assert [s["name"] for s in groups[1]["services"]] == ["NPM"]


async def test_revision_restore(authed):
    page, g1, g2, s1, s2 = await _make_basic(authed)
    revs = (await authed.get("/api/revisions")).json()
    before_delete = revs[0]["id"]
    await authed.delete(f"/api/groups/{g1}")
    groups = (await authed.get("/api/layout")).json()["pages"][0]["groups"]
    assert [g["name"] for g in groups] == ["Media"]

    assert (await authed.post(f"/api/revisions/{before_delete}/restore")).status_code == 200
    groups = (await authed.get("/api/layout")).json()["pages"][0]["groups"]
    assert [g["name"] for g in groups] == ["Netwerk", "Media"]
    adguard = groups[0]["services"][0]
    assert adguard["id"] == s1 and adguard["secret_keys"] == ["password"]
    # Na het terugzetten werkt toevoegen nog (geen botsende id's).
    assert (await authed.post("/api/services", json={"group_id": g2, "name": "Plex"})).status_code == 201


async def test_import_homepage_dev(authed):
    r = await authed.post("/api/import", json={"yaml": HOMEPAGE_YAML, "page_name": "Homelab"})
    assert r.status_code == 200, r.text
    assert r.json() == {"groups": 3, "services": 3}
    page = (await authed.get("/api/layout")).json()["pages"][0]
    assert page["name"] == "Homelab"
    names = [g["name"] for g in page["groups"]]
    assert names == ["Proxmox", "Proxmox / Backups", "Media"]
    pve = page["groups"][0]["services"][0]
    assert pve["type"] == "proxmox"
    assert pve["check"] == {"type": "http", "target": "https://proxmox50.jbogaert.be", "interval": 60}
    assert pve["config"] == {"url": "https://192.168.0.50:8006", "node": "pve50"}
    assert pve["secret_keys"] == ["password", "username"]
    assert page["groups"][1]["services"][0]["check"]["type"] == "ping"


async def test_export_roundtrip_without_secrets(authed):
    await authed.post("/api/import", json={"yaml": HOMEPAGE_YAML})
    r = await authed.get("/api/export")
    assert r.status_code == 200
    assert "geheim-token" not in r.text
    doc = yaml.safe_load(r.text)
    assert doc["version"] == 1
    r = await authed.post("/api/import", json={"yaml": r.text})
    assert r.json() == {"groups": 3, "services": 3}
    pages = (await authed.get("/api/layout")).json()["pages"]
    assert len(pages) == 2


async def test_import_rejects_garbage(authed):
    r = await authed.post("/api/import", json={"yaml": "gewoon: tekst"})
    assert r.status_code == 400


async def test_notifications(authed):
    data = (await authed.get("/api/notifications")).json()
    assert data["unread"] == 1  # "2FA ingeschakeld"
    await authed.post("/api/notifications/read-all")
    assert (await authed.get("/api/notifications")).json()["unread"] == 0
