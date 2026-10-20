import asyncio
from datetime import datetime, timedelta, timezone

import asyncssh
import httpx
from sqlalchemy import delete, select

from app.db import get_db
from app.main import app
from app.models import AppState, ConfigVersion, Device, Notification, SshHost
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
        # De ARP-tabel geeft een fout (bv. een verlopen API-sleutel).
        self.broken = False

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p == "/api/core/backup/download/this":
            return httpx.Response(200, text=XML.format(rules=self.rules), headers={"content-type": "application/xml"})
        if p == "/api/diagnostics/interface/getArp":
            return httpx.Response(500, text="kapot") if self.broken else httpx.Response(200, json=self.arp)
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


# --- privé-adressen, samen melden, opruimen ------------------------------------------------------------------------

async def _lan(authed) -> tuple[World, HttpClients, datetime]:
    """Een OPNsense-tegel met de World erachter, en de eerste ronde (wat er al is, is gekend)."""
    world = World()
    http = HttpClients(httpx.MockTransport(world))
    g = await _group(authed)
    await _svc(authed, g, "opnsense", "https://192.168.0.1", secrets={"key": "k", "secret": "s"}, name="OPNsense")
    t0 = datetime.now(timezone.utc).replace(microsecond=0)
    v = await _refresh(http, t0)
    assert v["seen"] == 2 and v["new"] == 0
    return world, http, t0


async def _refresh(http: HttpClients, now: datetime) -> dict:
    agen, db = await _db()
    v = await devices.refresh(db, http, now)
    await db.commit()
    await agen.aclose()
    return v


async def _devs() -> dict[str, Device]:
    agen, db = await _db()
    out = {d.mac: d for d in (await db.execute(select(Device))).scalars()}
    await agen.aclose()
    return out


async def _notes() -> list[Notification]:
    agen, db = await _db()
    out = list((await db.execute(select(Notification).where(Notification.source == "apparaat")
                                 .order_by(Notification.id))).scalars())
    await agen.aclose()
    return out


def _lease(mac: str, hostname: str | None = "gsm-jonas", intf: str = "LAN", ip: str = "192.168.0.60") -> dict:
    return {"address": ip, "mac": mac, "hostname": hostname, "state": "active", "if_descr": intf}


def test_privé_adres_herkend():
    assert devices.private_mac("aa:bb:cc:00:00:01") and devices.private_mac("02:42:ac:11:00:02")
    assert devices.private_mac("de:ad:be:ef:00:01")
    assert not devices.private_mac("00:11:22:33:44:55") and not devices.private_mac("b8:27:eb:00:00:01")


async def test_privé_adres_houdt_zijn_naam(authed):
    world, http, t0 = await _lan(authed)
    r = await authed.patch("/api/devices/aa:bb:cc:00:00:02", json={"name": "gsm Jonas", "note": "van mij", "scan": True})
    assert r.json()["private"] is True and r.json()["known"]
    # De gsm neemt een nieuw privé-adres (de oude lease is nog even actief), met de hostnaam in andere hoofdletters.
    world.leases.append(_lease("aa:bb:cc:00:00:03", "GSM-Jonas"))
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["new"] == 0 and v["moved"] == 1
    d = await _devs()
    new, old = d["aa:bb:cc:00:00:03"], d["aa:bb:cc:00:00:02"]
    assert (new.known, new.name, new.note, new.scan, new.ports) == (True, "gsm Jonas", "van mij", True, None)
    assert (old.known, old.name, old.note, old.scan) == (True, None, None, False)
    # Alleen in 🔔 (meteen "verstuurd": niet naar de gsm), geen "Nieuw apparaat".
    (moved,) = await _notes()
    assert (moved.title, moved.level, moved.pushed_at is not None) == ("gsm Jonas: nieuw privé-adres", "info", True)
    assert moved.body.startswith("192.168.0.60 · aa:bb:cc:00:00:03 · LAN (was aa:bb:cc:00:00:02)")

    # Nog een nieuw adres: de oude adressen zonder naam staan niet in de weg.
    world.leases[-1] = _lease("aa:bb:cc:00:00:04")
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["moved"] == 1 and (await _devs())["aa:bb:cc:00:00:04"].name == "gsm Jonas"

    # Een vast adres met dezelfde hostnaam, en een privé-adres met die hostnaam op een andere interface: niet te
    # zeggen, dus melden (samen, in één melding).
    world.leases[-1] = _lease("00:11:22:33:44:55", ip="192.168.0.61")
    world.leases.append(_lease("aa:bb:cc:00:00:05", intf="GAST", ip="192.168.1.62"))
    v = await _refresh(http, t0 + timedelta(minutes=15))
    assert v["new"] == 2 and v["moved"] == 0
    d = await _devs()
    assert not d["00:11:22:33:44:55"].known and not d["aa:bb:cc:00:00:05"].known and d["aa:bb:cc:00:00:05"].name is None
    last = (await _notes())[-1]
    assert (last.title, last.level, last.pushed_at) == ("2 nieuwe apparaten op je netwerk", "warn", None)
    assert "gsm-jonas: 192.168.0.61 · 00:11:22:33:44:55" in last.body and "aa:bb:cc:00:00:05 · GAST" in last.body

    # Nu staat er een onbekend toestel met die hostnaam op LAN: een volgend nieuw adres kan ook dat zijn.
    world.leases.append(_lease("aa:bb:cc:00:00:06", ip="192.168.0.63"))
    v = await _refresh(http, t0 + timedelta(minutes=20))
    assert v["new"] == 1 and v["moved"] == 0
    assert (await _notes())[-1].title == "Nieuw apparaat op je netwerk: gsm-jonas"
    assert (await _devs())["aa:bb:cc:00:00:04"].name == "gsm Jonas"


async def test_privé_adres_twijfel_dan_melden(authed):
    world, http, t0 = await _lan(authed)
    # Twee nieuwe adressen met dezelfde hostnaam in één ronde: welk is de gsm? Allebei melden.
    world.leases += [_lease("aa:bb:cc:00:01:01"), _lease("aa:bb:cc:00:01:02", ip="192.168.0.64")]
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["new"] == 2 and v["moved"] == 0
    assert (await _devs())["aa:bb:cc:00:00:02"].known
    # Twee gekende toestellen met een naam en dezelfde hostnaam (twee keer "iPhone"): ook melden.
    for mac, name in (("aa:bb:cc:00:01:01", "iPhone Jonas"), ("aa:bb:cc:00:01:02", "iPhone mama")):
        await authed.patch(f"/api/devices/{mac}", json={"name": name})
    world.leases.append(_lease("aa:bb:cc:00:01:03", ip="192.168.0.65"))
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["new"] == 1 and v["moved"] == 0
    # Zonder hostnaam is er niets om te vergelijken; het label zegt wel dat het een privé-adres is.
    world.leases.append(_lease("aa:bb:cc:00:01:04", hostname=None, ip="192.168.0.66"))
    await _refresh(http, t0 + timedelta(minutes=15))
    assert (await _notes())[-1].title == "Nieuw apparaat op je netwerk: onbekend toestel met privé-adres"
    d = await _devs()
    assert d["aa:bb:cc:00:01:01"].name == "iPhone Jonas" and d["aa:bb:cc:00:01:02"].name == "iPhone mama"
    assert not d["aa:bb:cc:00:01:03"].known and not d["aa:bb:cc:00:01:04"].known


async def test_privé_adres_alleen_van_een_toestel_met_naam_dat_weg_is(authed):
    """Een nieuw privé-adres neemt alleen de naam over van een toestel met een naam dat niet meer in de ARP-tabel
    staat, op dezelfde interface. Anders is het een nieuw apparaat (gewoon melden), met de naam hoogstens als hint."""
    world, http, t0 = await _lan(authed)
    agen, db = await _db()
    db.add_all([
        # Online (staat hieronder in de ARP-tabel), met een naam, een notitie en "volgen".
        Device(mac="aa:00:00:00:01:01", known=True, name="gsm Jonas", note="van mij", scan=True, hostname="iPhone",
               intf="LAN", first_seen=t0, last_seen=t0),
        # Met een naam, maar zonder interface.
        Device(mac="aa:00:00:00:01:02", known=True, name="laptop", hostname="laptop-jonas", first_seen=t0,
               last_seen=t0),
    ])
    await db.commit()
    await agen.aclose()
    world.arp.append({"mac": "aa:00:00:00:01:01", "ip": "192.168.0.40", "hostname": "iPhone", "intf_description": "LAN"})
    # Een gekend toestel zonder naam (gsm-jonas uit de eerste ronde) staat niet in voor zijn hostnaam.
    world.leases.append(_lease("aa:bb:cc:00:02:01"))
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["new"] == 1 and v["moved"] == 0
    (n,) = await _notes()
    assert (n.title, n.level, n.pushed_at) == ("Nieuw apparaat op je netwerk: gsm-jonas", "warn", None)
    assert n.body == "192.168.0.60 · aa:bb:cc:00:02:01 · LAN\nGeef het een naam onder net → apparaten."
    # Een ander "iPhone" terwijl de gsm van Jonas online is: dat kan ook de gsm zelf zijn met een nieuw adres (het oude
    # staat tot 20 minuten na het laatste antwoord in de ARP-tabel). Het wacht, nog zonder melding.
    world.leases.append(_lease("aa:bb:cc:00:02:02", "iPhone", ip="192.168.0.61"))
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["new"] == 0 and v["moved"] == 0 and list(v["pending"]) == ["aa:bb:cc:00:02:02"]
    assert len(await _notes()) == 1
    # Een halfuur later staat de gsm van Jonas er nog: twee toestellen. Het "iPhone" komt in de melding van die ronde,
    # samen met een laptop-jonas waar de interface niet te vergelijken is: allebei nieuw, met de naam als hint.
    world.leases.append(_lease("aa:bb:cc:00:02:03", "laptop-jonas", ip="192.168.0.62"))
    v = await _refresh(http, t0 + timedelta(minutes=40))
    assert v["new"] == 2 and v["moved"] == 0 and v["pending"] == {}
    n = (await _notes())[-1]
    assert (n.title, n.level, n.pushed_at) == ("2 nieuwe apparaten op je netwerk", "warn", None)
    assert n.body.splitlines() == [
        "iPhone: 192.168.0.61 · aa:bb:cc:00:02:02 · LAN (zelfde hostnaam als gsm Jonas, maar dat toestel is nog online)",
        "laptop-jonas: 192.168.0.62 · aa:bb:cc:00:02:03 · LAN (zelfde hostnaam als laptop)",
        "Geef ze een naam onder net → apparaten."]
    d = await _devs()
    assert (d["aa:00:00:00:01:01"].name, d["aa:00:00:00:01:01"].note, d["aa:00:00:00:01:01"].scan) == (
        "gsm Jonas", "van mij", True)
    assert d["aa:00:00:00:01:02"].name == "laptop"
    assert not any(d[m].known or d[m].name for m in ("aa:bb:cc:00:02:01", "aa:bb:cc:00:02:02", "aa:bb:cc:00:02:03"))
    assert not [n for n in await _notes() if n.title.endswith("nieuw privé-adres")]


# --- het oude adres staat nog even in de ARP-tabel ---------------------------------------------------------------

async def _gsm_online(authed) -> tuple[World, HttpClients, datetime]:
    """Zoals _lan, met een naam, een notitie en "volgen" voor gsm-jonas (aa:bb:cc:00:00:02), die online is (in de
    ARP-tabel)."""
    world, http, t0 = await _lan(authed)
    await authed.patch("/api/devices/aa:bb:cc:00:00:02", json={"name": "gsm Jonas", "note": "van mij", "scan": True})
    world.arp.append({"mac": "aa:bb:cc:00:00:02", "ip": "192.168.0.50", "hostname": "gsm-jonas",
                      "intf_description": "LAN"})
    return world, http, t0


async def test_privé_adres_wacht_tot_het_oude_uit_de_arp_tabel_is(authed):
    """De gsm neemt een nieuw privé-adres terwijl het oude nog in de ARP-tabel staat (OPNsense houdt het tot 20
    minuten na het laatste antwoord): geen melding, en zodra het oude adres eruit is, houdt de gsm zijn naam."""
    world, http, t0 = await _gsm_online(authed)
    world.leases.append(_lease("aa:bb:cc:00:00:03"))
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["new"] == 0 and v["moved"] == 0
    assert v["pending"] == {"aa:bb:cc:00:00:03": {"old": "aa:bb:cc:00:00:02",
                                                  "since": (t0 + timedelta(minutes=5)).isoformat()}}
    assert not await _notes()
    # Al in de lijst, als onbekend; de naam blijft voorlopig bij het oude adres.
    d = await _devs()
    assert (d["aa:bb:cc:00:00:03"].known, d["aa:bb:cc:00:00:03"].name) == (False, None)
    assert (d["aa:bb:cc:00:00:02"].name, d["aa:bb:cc:00:00:02"].scan) == ("gsm Jonas", True)

    world.arp.pop()  # het oude adres is uit de ARP-tabel
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["new"] == 0 and v["moved"] == 1 and v["pending"] == {} and v["vacated"] == ["aa:bb:cc:00:00:02"]
    d = await _devs()
    new, old = d["aa:bb:cc:00:00:03"], d["aa:bb:cc:00:00:02"]
    assert (new.known, new.name, new.note, new.scan) == (True, "gsm Jonas", "van mij", True)
    assert (old.known, old.name, old.note, old.scan) == (True, None, None, False)
    (moved,) = await _notes()
    assert (moved.title, moved.level, moved.pushed_at is not None) == ("gsm Jonas: nieuw privé-adres", "info", True)
    assert moved.body.startswith("192.168.0.60 · aa:bb:cc:00:00:03 · LAN (was aa:bb:cc:00:00:02)")
    # Daarna gebeurt er niets meer.
    v = await _refresh(http, t0 + timedelta(minutes=40))
    assert v["new"] == 0 and v["moved"] == 0 and len(await _notes()) == 1


async def test_privé_adres_beide_online_een_melding_na_het_wachten(authed):
    """Staan het oude en het nieuwe adres er een halfuur samen, dan zijn het twee toestellen: één gewone melding, met
    de naam als hint, en geen enkele eerder of later."""
    world, http, t0 = await _gsm_online(authed)
    world.leases.append(_lease("aa:bb:cc:00:00:03"))
    for m in range(5, 35, 5):
        v = await _refresh(http, t0 + timedelta(minutes=m))
        assert v["new"] == 0 and list(v["pending"]) == ["aa:bb:cc:00:00:03"], m
    assert not await _notes()
    v = await _refresh(http, t0 + timedelta(minutes=35))
    assert v["new"] == 1 and v["moved"] == 0 and v["pending"] == {}
    v = await _refresh(http, t0 + timedelta(minutes=40))
    assert v["new"] == 0
    (n,) = await _notes()
    assert (n.title, n.level, n.pushed_at) == ("Nieuw apparaat op je netwerk: gsm-jonas", "warn", None)
    assert n.body == ("192.168.0.60 · aa:bb:cc:00:00:03 · LAN (zelfde hostnaam als gsm Jonas, maar dat toestel is nog "
                      "online)\nGeef het een naam onder net → apparaten.")
    d = await _devs()
    assert d["aa:bb:cc:00:00:02"].name == "gsm Jonas" and not d["aa:bb:cc:00:00:03"].known
    # Een genegeerd aandachtspunt komt pas nu terug: nu is er een echt nieuw apparaat.
    agen, db = await _db()
    assert (await db.get(AppState, devices.STATE_KEY)).value["last_new"] == (t0 + timedelta(minutes=35)).isoformat()
    await agen.aclose()


async def test_privé_adres_naam_tijdens_het_wachten(authed):
    """Geef je het wachtende adres zelf een naam, dan blijft het daarbij: het neemt geen naam over, en er komt geen
    melding meer."""
    world, http, t0 = await _gsm_online(authed)
    world.leases.append(_lease("aa:bb:cc:00:00:03"))
    await _refresh(http, t0 + timedelta(minutes=5))
    assert not await _notes()
    r = await authed.patch("/api/devices/aa:bb:cc:00:00:03", json={"name": "gsm van een gast"})
    assert r.json()["known"]
    world.arp.pop()
    for m in range(10, 45, 5):
        v = await _refresh(http, t0 + timedelta(minutes=m))
        assert v["new"] == 0 and v["moved"] == 0 and v["pending"] == {}, m
    assert not await _notes()
    d = await _devs()
    assert (d["aa:bb:cc:00:00:03"].name, d["aa:bb:cc:00:00:03"].scan) == ("gsm van een gast", False)
    assert (d["aa:bb:cc:00:00:02"].name, d["aa:bb:cc:00:00:02"].scan) == ("gsm Jonas", True)


async def test_privé_adres_vergeten_tijdens_het_wachten(authed):
    """Vergeet je het wachtende adres, dan wacht het niet meer. Vergeet je het oude, dan is er geen naam meer om over
    te nemen: een gewone melding, meteen."""
    world, http, t0 = await _gsm_online(authed)
    world.leases.append(_lease("aa:bb:cc:00:00:03"))
    await _refresh(http, t0 + timedelta(minutes=5))
    assert not await _notes()
    world.leases.pop()
    assert (await authed.delete("/api/devices/aa:bb:cc:00:00:03")).status_code == 204
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["pending"] == {} and not await _notes()

    world.leases.append(_lease("aa:bb:cc:00:00:04"))
    v = await _refresh(http, t0 + timedelta(minutes=15))
    assert list(v["pending"]) == ["aa:bb:cc:00:00:04"]
    # Het oude adres is weg (ook de lease) en vergeten.
    world.arp.pop()
    world.leases = [x for x in world.leases if x["mac"] != "aa:bb:cc:00:00:02"]
    assert (await authed.delete("/api/devices/aa:bb:cc:00:00:02")).status_code == 204
    v = await _refresh(http, t0 + timedelta(minutes=20))
    assert v["new"] == 1 and v["moved"] == 0 and v["pending"] == {}
    (n,) = await _notes()
    assert n.title == "Nieuw apparaat op je netwerk: gsm-jonas" and "zelfde hostnaam" not in n.body
    assert (await _devs())["aa:bb:cc:00:00:04"].name is None


async def test_verlopen_arp_rij_houdt_niet_tegen(authed):
    """Een verlopen rij in de ARP-tabel van OPNsense ("expired", nog niet opgeruimd) telt niet als online: het nieuwe
    adres neemt de naam meteen over. IP-adres en hostnaam komen er wel nog uit."""
    world, http, t0 = await _gsm_online(authed)
    world.arp[-1].update({"ip": "192.168.0.49", "expired": True, "expires": -1})
    world.leases.append(_lease("aa:bb:cc:00:00:03"))
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["new"] == 0 and v["moved"] == 1 and v["pending"] == {}
    d = await _devs()
    assert d["aa:bb:cc:00:00:03"].name == "gsm Jonas" and d["aa:bb:cc:00:00:02"].ip == "192.168.0.49"
    assert [n.title for n in await _notes()] == ["gsm Jonas: nieuw privé-adres"]
    # Een rij die nog loopt ("expires" in seconden), telt wel: dat toestel is online.
    world.arp.append({"mac": "aa:bb:cc:00:00:03", "ip": "192.168.0.60", "hostname": "gsm-jonas",
                      "intf_description": "LAN", "expired": False, "expires": 1183})
    world.leases.append(_lease("aa:bb:cc:00:00:05", ip="192.168.0.61"))
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["moved"] == 0 and list(v["pending"]) == ["aa:bb:cc:00:00:05"]


async def test_nieuwe_apparaten_samen_in_een_melding(authed, monkeypatch):
    world, http, t0 = await _lan(authed)
    monkeypatch.setattr(devices, "LIST_MAX", 3)
    world.arp += [{"mac": f"b8:27:eb:00:00:0{i}", "ip": f"192.168.0.7{i}", "manufacturer": "Raspberry Pi",
                   "hostname": None, "intf_description": "IoT"} for i in range(4)]
    world.arp.append({"mac": "02:42:ac:11:00:02", "ip": "192.168.0.80", "manufacturer": None, "hostname": None,
                      "intf_description": "LAN"})
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["new"] == 5
    (n,) = await _notes()
    assert n.title == "5 nieuwe apparaten op je netwerk" and n.level == "warn" and n.push_key is None
    assert n.body.splitlines() == ["Raspberry Pi: 192.168.0.70 · b8:27:eb:00:00:00 · IoT",
                                   "Raspberry Pi: 192.168.0.71 · b8:27:eb:00:00:01 · IoT",
                                   "Raspberry Pi: 192.168.0.72 · b8:27:eb:00:00:02 · IoT",
                                   "… en nog 2", "Geef ze een naam onder net → apparaten."]
    data = (await authed.get("/api/devices")).json()
    by = {d["mac"]: d for d in data["items"]}
    assert by["02:42:ac:11:00:02"]["private"] is True and by["b8:27:eb:00:00:00"]["private"] is False


async def test_lege_tabel_aanvaardt_niet_alles(authed):
    """Wie de tabel leegmaakt, krijgt bij de volgende ronde een melding over alles (niet stil alles als gekend)."""
    world, http, t0 = await _lan(authed)
    agen, db = await _db()
    assert (await db.get(AppState, devices.STATE_KEY)).value["baseline"] == t0.isoformat()
    await db.execute(delete(Device))
    await db.commit()
    await agen.aclose()
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["new"] == 2
    assert not any(d.known for d in (await _devs()).values())
    assert [n.title for n in await _notes()] == ["2 nieuwe apparaten op je netwerk"]


async def test_aandacht_komt_alleen_terug_voor_een_echt_nieuw_apparaat(authed):
    world, http, t0 = await _lan(authed)
    world.arp += [{"mac": f"b8:27:eb:00:00:0{i}", "ip": f"192.168.0.7{i}", "manufacturer": "Raspberry Pi",
                   "hostname": f"pi{i}", "intf_description": "IoT"} for i in range(3)]
    await _refresh(http, t0 + timedelta(minutes=5))

    async def item(r=None):
        r = r or (await authed.get("/api/attention")).json()
        return (next((i for i in r["items"] if i["key"] == "devices"), None),
                next((i for i in r["ignored"] if i["key"] == "devices"), None))

    shown, _ = await item()
    assert shown["title"] == "3 nieuwe apparaten op je netwerk"
    r = (await authed.put("/api/attention/ignore", json={"key": "devices", "sig": shown["sig"]})).json()
    shown, ignored = await item(r)
    assert shown is None and ignored is not None
    # "ken ik" voor één ervan, en een ronde zonder iets nieuws: blijft genegeerd.
    await authed.patch("/api/devices/b8:27:eb:00:00:00", json={"known": True})
    await _refresh(http, t0 + timedelta(minutes=10))
    shown, ignored = await item()
    assert shown is None and ignored["title"] == "2 nieuwe apparaten op je netwerk"
    # Een echt nieuw apparaat: weer zichtbaar.
    world.arp.append({"mac": "b8:27:eb:00:00:09", "ip": "192.168.0.79", "manufacturer": "Raspberry Pi",
                      "hostname": "pi9", "intf_description": "IoT"})
    await _refresh(http, t0 + timedelta(minutes=15))
    shown, ignored = await item()
    assert shown["title"] == "3 nieuwe apparaten op je netwerk" and ignored is None


async def test_oude_apparaten_opgeruimd(authed):
    world, http, t0 = await _lan(authed)
    old = t0 - timedelta(days=31)
    agen, db = await _db()
    db.add_all([
        Device(mac="aa:00:00:00:00:01", known=False, first_seen=old, last_seen=old),  # onbekend: weg
        Device(mac="aa:00:00:00:00:02", known=False, first_seen=old, last_seen=t0 - timedelta(days=29)),  # te kort
        Device(mac="00:11:22:33:44:55", known=True, first_seen=old, last_seen=t0 - timedelta(days=365)),  # vast adres
        Device(mac="aa:00:00:00:00:03", known=True, name="laptop", first_seen=old, last_seen=old),  # met naam
        # "ken ik" voor een privé-adres zonder naam (een VM, de laptop van een gast): geen verlaten oud adres, blijft.
        Device(mac="aa:00:00:00:00:04", known=True, first_seen=old, last_seen=old),
        Device(mac="aa:00:00:00:00:05", known=True, scan=True, first_seen=old, last_seen=old),  # volgen: blijft
        Device(mac="aa:00:00:00:00:06", known=False, note="van de buren", first_seen=old, last_seen=old),  # notitie
        Device(mac="00:11:22:33:44:66", known=False, first_seen=old, last_seen=old),  # onbekend vast adres: weg
    ])
    await db.commit()
    await agen.aclose()
    # Een ronde met een fout: "niet gezien" is dan niets waard, er verdwijnt niets.
    world.broken = True
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["errors"] and v["pruned"] == 0 and len(await _devs()) == 10
    world.broken = False
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["pruned"] == 2
    assert sorted(await _devs()) == ["00:11:22:33:44:55", "aa:00:00:00:00:02", "aa:00:00:00:00:03",
                                     "aa:00:00:00:00:04", "aa:00:00:00:00:05", "aa:00:00:00:00:06",
                                     "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]
    assert not await _notes()

    # Vergeten: een gekend apparaat met een vast adres gaat alleen zo weg (met een rij in de auditlog).
    r = await authed.delete("/api/devices/00:11:22:33:44:55")
    assert r.status_code == 204
    assert (await authed.delete("/api/devices/00:11:22:33:44:55")).status_code == 404
    audit = (await authed.get("/api/auth/audit?action=device_forgotten")).json()["items"]
    assert len(audit) == 1 and audit[0]["detail"]["mac"] == "00:11:22:33:44:55"
    # Komt het terug, dan is het een nieuw apparaat.
    world.arp.append({"mac": "00:11:22:33:44:55", "ip": "192.168.0.90", "manufacturer": "NAS-bouwer",
                      "hostname": "nas", "intf_description": "LAN"})
    v = await _refresh(http, t0 + timedelta(minutes=15))
    assert v["new"] == 1 and [n.title for n in await _notes()] == ["Nieuw apparaat op je netwerk: nas"]


async def test_verlaten_privé_adres_opgeruimd(authed):
    """Het oude adres van een toestel dat een nieuw privé-adres nam, verdwijnt na 30 dagen niet gezien. Staat zo'n
    oud adres intussen weer in de ARP-tabel, dan was het niet verlaten en blijft het."""
    world, http, t0 = await _lan(authed)
    await authed.patch("/api/devices/aa:bb:cc:00:00:02", json={"name": "gsm Jonas"})
    agen, db = await _db()
    db.add(Device(mac="aa:00:00:00:00:07", known=True, name="tablet", hostname="tablet", intf="LAN", first_seen=t0,
                  last_seen=t0))
    await db.commit()
    await agen.aclose()
    world.leases = [_lease("aa:bb:cc:00:00:03"), _lease("aa:bb:cc:00:00:08", "tablet", ip="192.168.0.68")]
    v = await _refresh(http, t0 + timedelta(minutes=5))
    assert v["moved"] == 2 and v["vacated"] == ["aa:00:00:00:00:07", "aa:bb:cc:00:00:02"]
    # De tablet neemt toch zijn oude adres weer.
    world.arp.append({"mac": "aa:00:00:00:00:07", "ip": "192.168.0.67", "hostname": "tablet", "intf_description": "LAN"})
    v = await _refresh(http, t0 + timedelta(minutes=10))
    assert v["vacated"] == ["aa:bb:cc:00:00:02"]
    world.arp.pop()
    v = await _refresh(http, t0 + timedelta(days=30, minutes=11))
    assert v["pruned"] == 1 and v["vacated"] == []
    assert sorted(await _devs()) == ["aa:00:00:00:00:07", "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:03",
                                     "aa:bb:cc:00:00:08"]
