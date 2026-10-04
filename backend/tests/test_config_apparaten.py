import asyncio
from datetime import datetime, timedelta, timezone

import asyncssh
import httpx
from sqlalchemy import select

from app.db import get_db
from app.main import app
from app.models import ConfigVersion, Device, Notification, SshHost
from app.monitoring import configs, devices
from app.monitoring.checks import HttpClients
from app.security import decrypt

from .test_integrations import PVE, _group, _svc

XML = """<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>OPNsense</hostname>
    <user><name>root</name><password>$2y$11$geheimehash</password></user>
  </system>
  <filter>{rules}</filter>
</opnsense>
"""


class World:
    def __init__(self):
        self.rules = "<rule>allow lan</rule>"
        self.arp = [{"mac": "AA:BB:CC:00:00:01", "ip": "192.168.0.10", "manufacturer": "Hewlett Packard",
                     "hostname": "pve50", "intf_description": "LAN"}]
        self.leases = [{"address": "192.168.0.50", "mac": "aa:bb:cc:00:00:02", "hostname": "gsm-jonas", "state": "active",
                        "if_descr": "LAN"},
                       {"address": "192.168.0.51", "mac": "aa:bb:cc:00:00:09", "hostname": "oud", "state": "expired"}]

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p == "/api/core/backup/download/this":
            return httpx.Response(200, text=XML.format(rules=self.rules), headers={"content-type": "application/xml"})
        if p == "/api/diagnostics/interface/getArp":
            return httpx.Response(200, json=self.arp)
        if p == "/api/dhcpv4/leases/searchLease":
            return httpx.Response(200, json={"rows": self.leases})
        if p == "/api/kea/leases4/search":
            return httpx.Response(404)
        if p == "/api/tokens":
            return httpx.Response(200, json={"token": "jwt"})
        if p == "/api/nginx/proxy-hosts":
            return httpx.Response(200, json=[{"id": 1, "domain_names": ["plex.jbogaert.be"], "forward_host": "192.168.0.20",
                                              "forward_port": 32400, "modified_on": datetime.now().isoformat()}])
        if p.startswith("/api/nginx/"):
            return httpx.Response(200, json=[])
        if p == "/api2/json/cluster/resources":
            return httpx.Response(200, json=PVE)
        if p == "/api2/json/nodes/pve50/qemu/100/config":
            return httpx.Response(200, json={"data": {"cores": 2, "memory": 2048, "name": "opnsense", "digest": "abc"}})
        if p == "/api2/json/nodes/pve50/lxc/101/config":
            return httpx.Response(200, json={"data": {"cores": 1, "hostname": "homepage", "memory": 1024}})
        return httpx.Response(404)


class FileHost:
    def __init__(self):
        self.key = asyncssh.generate_private_key("ssh-ed25519")
        self.conf = "server { listen 80; }"

    async def handle(self, proc):
        cmd = proc.command or ""
        if "set --" in cmd:
            proc.stdout.write(f"@@F /etc/nginx/nginx.conf\n{self.conf}\n\n@@F /etc/nginx/leeg.conf\n\n@@MISSING /etc/weg\n")
        proc.exit(0)

    async def start(self):
        class S(asyncssh.SSHServer):
            def begin_auth(self, u):
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, u, p):
                return p == "pw"

        self.server = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[self.key],
                                                   process_factory=self.handle)
        return self.server.sockets[0].getsockname()[1]


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


def test_parse_files_and_mask():
    files, missing = configs.parse_files("@@F /a\nregel 1\nregel 2\n\n@@F /b\n\n@@MISSING /c\n")
    assert files == {"/a": "regel 1\nregel 2", "/b": ""} and missing == ["/c"]
    assert configs.mask("<password>x</password><apikey>y</apikey><name>root</name>") == \
        "<password>•••</password><apikey>•••</apikey><name>root</name>"
    assert configs.mask('{"password": "abc", "user": "x"}') == '{"password": "•••", "user": "x"}'
    assert configs.pve_text({"memory": 1, "cores": 2, "digest": "x"}) == "cores: 2\nmemory: 1\n"


async def test_config_versions_diff_and_download(authed):
    world = World()
    http = HttpClients(httpx.MockTransport(world))
    g = await _group(authed)
    await _svc(authed, g, "opnsense", "https://192.168.0.1", secrets={"key": "k", "secret": "s"}, name="OPNsense")
    await _svc(authed, g, "npm", "http://192.168.0.245:81", secrets={"username": "a@b.c", "password": "p"}, name="NPM")
    await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
               secrets={"username": "homepage@pve!dash", "password": "geheim"}, name="PVE")
    fh = FileHost()
    port = await fh.start()
    hid = (await authed.post("/api/ssh/hosts", json={"name": "proxy", "host": "127.0.0.1", "port": port,
                                                     "password": "pw"})).json()["id"]
    agen, db = await _db()
    h = await db.get(SshHost, hid)
    h.host_key = fh.key.export_public_key().decode()
    await db.commit()
    bad = await authed.put("/api/configs/settings", json={"files": [{"host_id": hid, "path": "/etc/../root"}]})
    assert bad.status_code == 422
    r = await authed.put("/api/configs/settings", json={"hour": 2, "files": [{"host_id": hid, "path": "/etc/nginx/"},
                                                                             {"host_id": hid, "path": "/etc/weg"}]})
    assert r.status_code == 200 and r.json()["files"][0]["path"] == "/etc/nginx"

    v = await configs.run_configs(db, http)
    await db.commit()
    assert v["items"] == 6 and v["changed"] == 0 and not v["errors"]
    items = {i["name"]: i for i in (await authed.get("/api/configs")).json()["items"]}
    assert set(items) == {"OPNsense · config.xml", "NPM · proxy hosts", "VM 100 opnsense · 100.conf",
                          "CT 101 homepage · 101.conf", "proxy:/etc/nginx/nginx.conf", "proxy:/etc/nginx/leeg.conf"}
    # NPM verandert modified_on bij elke aanvraag: telt niet als wijziging.
    stored = (await db.execute(select(ConfigVersion).where(ConfigVersion.kind == "opnsense"))).scalar_one()
    assert "geheimehash" not in stored.content and "geheimehash" in decrypt(stored.content)

    world.rules = "<rule>allow lan</rule><rule>block iot</rule>"
    fh.conf = "server { listen 8080; }"
    v = await configs.run_configs(db, http)
    await db.commit()
    assert v["changed"] == 2
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "config"))).scalars()]
    assert titles == ["2 configuraties gewijzigd"]
    items = {i["name"]: i for i in (await authed.get("/api/configs")).json()["items"]}
    x = items["OPNsense · config.xml"]
    assert x["versions"] == 2
    vers = (await authed.get("/api/configs/versions", params={"item": x["item"]})).json()
    d = (await authed.get(f"/api/configs/versions/{vers[0]['id']}/diff")).json()
    assert "+  <filter><rule>allow lan</rule><rule>block iot</rule></filter>" in d["diff"]
    assert "geheimehash" not in d["diff"]
    whole = (await authed.get(f"/api/configs/versions/{vers[0]['id']}/diff", params={"against": vers[1]["id"]})).json()
    assert whole["against"]["id"] == vers[1]["id"]
    dl = await authed.get(f"/api/configs/versions/{vers[0]['id']}/download")
    assert dl.status_code == 200 and "geheimehash" in dl.text and "attachment" in dl.headers["content-disposition"]
    tl = (await authed.get("/api/timeline?kind=wijziging")).json()["items"]
    assert any(i["title"] == "Configuratie gewijzigd: proxy:/etc/nginx/nginx.conf" for i in tl)

    # Elke nacht één keer op het ingestelde uur.
    night = datetime.now().astimezone().replace(hour=2)
    assert not await configs.due(db, night)  # vandaag al gedaan
    assert await configs.due(db, night + timedelta(days=1))
    assert not await configs.due(db, night.replace(hour=3) + timedelta(days=1))


async def test_devices_new_device_and_ports(authed):
    world = World()
    http = HttpClients(httpx.MockTransport(world))
    g = await _group(authed)
    await _svc(authed, g, "opnsense", "https://192.168.0.1", secrets={"key": "k", "secret": "s"}, name="OPNsense")
    agen, db = await _db()
    v = await devices.refresh(db, http)
    await db.commit()
    assert v["seen"] == 2 and v["new"] == 0  # eerste keer: alles wat er al is, is gekend
    world.arp.append({"mac": "de:ad:be:ef:00:01", "ip": "192.168.0.77", "manufacturer": "Espressif Inc.",
                      "hostname": None, "intf_description": "IoT"})
    v = await devices.refresh(db, http)
    await db.commit()
    assert v["new"] == 1
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "apparaat"))).scalars()]
    assert titles == ["Nieuw apparaat op je netwerk: Espressif Inc."]
    data = (await authed.get("/api/devices")).json()
    assert data["summary"] == {"total": 3, "online": 3, "unknown": 1}
    assert data["items"][0]["mac"] == "de:ad:be:ef:00:01" and data["items"][0]["vendor"] == "Espressif Inc."
    r = await authed.patch("/api/devices/DE:AD:BE:EF:00:01", json={"name": "slimme stekker", "scan": True})
    assert r.json()["known"] and r.json()["name"] == "slimme stekker"

    # Poortscan tegen een eigen luisterende poort.
    srv = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    open_port = srv.sockets[0].getsockname()[1]
    d = await db.get(Device, "aa:bb:cc:00:00:01")
    d.ip = "127.0.0.1"
    found = await devices.scan_device(db, d, ports=[open_port + 1 if open_port < 65535 else 1])
    assert found == [] and d.ports == []
    found = await devices.scan_device(db, d, ports=[open_port])
    await db.commit()
    assert found == [open_port]
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "apparaat"))).scalars()]
    assert titles[-1].startswith(f"Nieuwe poort open op pve50: {open_port}")
    srv.close()
    # Niet meer gezien → offline, wordt niet gescand.
    stale = datetime.now(timezone.utc) + timedelta(hours=1)
    assert await devices.scan_due(db, stale) == 0
