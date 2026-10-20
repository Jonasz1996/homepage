import httpx

from app.monitoring.checks import HttpClients
from app.routers import ssh as ssh_router
from app.ssh_discovery import apply, discover, pick_ipv4

from .test_integrations import _group, _svc
from .test_ssh import WS, _cookie, _db, sshd  # noqa: F401 (fixture)


class Pve:
    """Neppe Proxmox: één node, een draaiende en een gestopte container, een VM met en een zonder agent."""

    def __init__(self):
        self.ct_ip = "192.168.0.105/24"

    def __call__(self, request: httpx.Request) -> httpx.Response:
        p = request.url.path.removeprefix("/api2/json")
        data = {
            "/cluster/resources": [
                {"type": "node", "node": "pve50", "status": "online"},
                {"type": "lxc", "vmid": 105, "node": "pve50", "name": "vaultwarden", "status": "running"},
                {"type": "lxc", "vmid": 106, "node": "pve50", "name": "oud", "status": "stopped"},
                {"type": "qemu", "vmid": 200, "node": "pve50", "name": "opnsense", "status": "running"},
                {"type": "qemu", "vmid": 201, "node": "pve50", "name": "zonder-agent", "status": "running"},
                {"type": "qemu", "vmid": 900, "node": "pve50", "name": "sjabloon", "status": "stopped", "template": 1},
            ],
            "/cluster/status": [{"type": "cluster", "name": "c"}, {"type": "node", "name": "pve50", "ip": "192.168.0.50"}],
            "/nodes/pve50/lxc/105/interfaces": [{"name": "lo", "inet": "127.0.0.1/8"},
                                                {"name": "eth0", "inet": self.ct_ip}],
            "/nodes/pve50/lxc/106/config": {"net0": "name=eth0,bridge=vmbr0,ip=192.168.0.106/24,gw=192.168.0.1"},
            "/nodes/pve50/qemu/200/agent/network-get-interfaces": {"result": [
                {"name": "lo", "ip-addresses": [{"ip-address": "127.0.0.1", "ip-address-type": "ipv4"}]},
                {"name": "docker0", "ip-addresses": [{"ip-address": "172.17.0.1", "ip-address-type": "ipv4"}]},
                {"name": "vtnet0", "ip-addresses": [{"ip-address": "fe80::1", "ip-address-type": "ipv6"},
                                                    {"ip-address": "192.168.0.1", "ip-address-type": "ipv4"}]},
            ]},
        }.get(p)
        if p.endswith("/201/agent/network-get-interfaces"):
            return httpx.Response(500, json={"data": None, "message": "QEMU guest agent is not running"})
        if data is None:
            return httpx.Response(404, json={"data": None})
        return httpx.Response(200, json={"data": data})


def test_pick_ipv4():
    assert pick_ipv4([("lo", "127.0.0.1"), ("docker0", "172.17.0.1"), ("eth0", "10.0.0.5/24")]) == "10.0.0.5"
    assert pick_ipv4([("eth0", "fe80::1"), ("eth0", "169.254.1.1")]) is None


async def test_discover_and_apply(authed):
    g = await _group(authed)
    await _svc(authed, g, "proxmox", "https://pve50.jbogaert.be", name="cluster",
               secrets={"username": "homepage@pve!dash", "password": "geheim"})
    # Zelfde node nog eens als losse tegel: geen dubbels.
    await _svc(authed, g, "proxmox", "https://pve50.jbogaert.be", name="pve50",
               secrets={"username": "homepage@pve!dash", "password": "geheim"})
    db = await _db()
    fake = Pve()
    clients = HttpClients(httpx.MockTransport(fake))
    found = await discover(db, clients)
    by = {i["name"]: i for i in found["items"]}
    assert set(by) == {"pve50", "vaultwarden", "oud", "opnsense", "zonder-agent"}
    assert by["pve50"]["host"] == "192.168.0.50" and by["pve50"]["kind"] == "node"
    assert by["vaultwarden"]["host"] == "192.168.0.105"
    assert by["oud"]["host"] == "192.168.0.106"  # uit, IP uit de config
    assert by["opnsense"]["host"] == "192.168.0.1"  # geen docker0 of IPv6
    assert by["zonder-agent"]["host"] is None and "agent" in by["zonder-agent"]["why"]
    assert all(i["folder"] == "pve50" for i in found["items"])

    r = await apply(db, found["items"])
    await db.commit()
    assert r == {"added": 4, "updated": 0}
    # Tweede ronde: container kreeg een ander IP.
    fake.ct_ip = "192.168.0.155/24"
    found = await discover(db, clients)
    assert all(i["known"] for i in found["items"] if i["host"])
    assert await apply(db, found["items"]) == {"added": 0, "updated": 1}
    await db.commit()
    hosts = {h["name"]: h for h in (await authed.get("/api/ssh/hosts")).json()}
    assert hosts["vaultwarden"]["host"] == "192.168.0.155"
    assert hosts["vaultwarden"]["uses_defaults"] and hosts["vaultwarden"]["username"] == ""
    assert hosts["vaultwarden"]["folder"] == "pve50"


async def test_discover_and_import_api(authed, monkeypatch):
    g = await _group(authed)
    await _svc(authed, g, "proxmox", "https://pve50.jbogaert.be",
               secrets={"username": "homepage@pve!dash", "password": "geheim"})
    monkeypatch.setattr(ssh_router, "clients", HttpClients(httpx.MockTransport(Pve())))
    items = (await authed.post("/api/ssh/discover")).json()["items"]
    pick = [i for i in items if i["name"] in ("pve50", "vaultwarden")]
    r = await authed.post("/api/ssh/import", json=pick)
    assert r.json() == {"added": 2, "updated": 0}
    bad = await authed.post("/api/ssh/import", json=[{**pick[0], "source": "x;rm -rf"}])
    assert bad.status_code == 422
    bad = await authed.post("/api/ssh/import", json=[{**pick[0], "host": "-oProxyCommand=x"}])
    assert bad.status_code == 422


async def test_defaults_used_for_login(authed, sshd):  # noqa: F811
    r = await authed.put("/api/ssh/defaults", json={"username": "root", "password": "goed", "auto_sync": True})
    assert r.status_code == 200, r.text
    assert r.json() == {"username": "root", "has_password": True, "key_id": None, "auto_sync": True}
    # Wachtwoord leeg laten = ongewijzigd.
    r = await authed.put("/api/ssh/defaults", json={"username": "root", "auto_sync": True})
    assert r.json()["has_password"]

    r = await authed.post("/api/ssh/hosts", json={"name": "ct", "host": "127.0.0.1", "port": sshd["port"]})
    assert r.status_code == 201, r.text
    assert r.json()["uses_defaults"] and r.json()["username"] == ""
    ws = WS(f"/api/ssh/ws/{r.json()['id']}", _cookie(authed))
    await ws.open()
    await ws.json()
    await ws.json()
    await ws.send_text({"t": "accept"})
    status = await ws.json()
    assert status["t"] == "status" and "root@127.0.0.1" in status["m"]
    assert (await ws.json())["t"] == "ready"
    assert b"welkom root" in await ws.read_until(b"welkom")
    await ws.close()


async def test_snippets(authed):
    assert (await authed.get("/api/ssh/snippets")).json() == []
    body = [{"name": "updates", "command": "apt update && apt list --upgradable", "run": True},
            {"name": "df", "command": "df -h", "run": False}]
    assert (await authed.put("/api/ssh/snippets", json=body)).status_code == 200
    assert (await authed.get("/api/ssh/snippets")).json() == body
    assert (await authed.put("/api/ssh/snippets", json=[{"name": "", "command": "x"}])).status_code == 422
