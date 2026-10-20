import json
import time

import httpx
import pytest
from sqlalchemy import select

from app.integrations import zabbix as zint
from app.models import AppState, ConfigVersion, Service, SshHost
from app.monitoring import zabbix as zmon
from app.monitoring.checks import HttpClients
from app.routers import integrations as router
from app.security import encrypt

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db

HOSTS = [
    {"hostid": "1", "host": "pve50", "name": "pve50", "status": "0", "available": "1",
     "interfaces": [{"ip": "192.168.0.50", "dns": "", "available": "1", "type": "1"}]},
    {"hostid": "2", "host": "plex-ct", "name": "Plex", "status": "0", "available": "1",
     "interfaces": [{"ip": "192.168.0.105", "dns": "", "available": "1", "type": "1"}]},
    {"hostid": "3", "host": "nas", "name": "Synology", "status": "0", "available": "2",
     "interfaces": [{"ip": "192.168.0.60", "dns": "nas.lan", "available": "2", "type": "2"}]},
    {"hostid": "4", "host": "radarr", "name": "radarr", "status": "0", "available": "0",
     "interfaces": [{"ip": "127.0.0.1", "dns": "", "available": "0", "type": "1"}], "active_available": "1"},
]


class Zab:
    def __init__(self, legacy=False):
        self.legacy = legacy
        self.calls = []
        self.triggers = [
            {"triggerid": "10", "description": "Hoge CPU op pve50", "priority": "4", "lastchange": str(int(time.time()) - 600),
             "hosts": [{"hostid": "1", "name": "pve50"}]},
            {"triggerid": "11", "description": "Weinig vrij op /", "priority": "2", "lastchange": "1",
             "hosts": [{"hostid": "2", "name": "Plex"}]}]

    def __call__(self, req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/api_jsonrpc.php"
        body = json.loads(req.content)
        self.calls.append(body["method"])
        tok = body.get("auth") if self.legacy else (req.headers.get("authorization") or "").removeprefix("Bearer ")
        if tok != "zbx-token":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "error": {
                "code": -32602, "message": "Invalid params.", "data": "Not authorized."}})
        m, p = body["method"], body["params"]
        if m == "host.get":
            r = HOSTS
        elif m == "trigger.get":
            r = [t for t in self.triggers if not p.get("hostids") or t["hosts"][0]["hostid"] in p["hostids"]]
        elif m == "item.get":
            r = [{"itemid": "100", "hostid": "1", "key_": "system.cpu.util", "lastvalue": "91.5", "lastclock": "1", "units": "%"},
                 {"itemid": "101", "hostid": "1", "key_": "system.uptime", "lastvalue": "86400", "lastclock": "1", "units": "s"},
                 {"itemid": "102", "hostid": "2", "key_": "vm.memory.utilization", "lastvalue": "40", "lastclock": "1", "units": "%"},
                 {"itemid": "103", "hostid": "2", "key_": "icmpping", "lastvalue": "1", "lastclock": "0", "units": ""}]
            r = [i for i in r if i["hostid"] in p["hostids"]]
        elif m == "trend.get":
            r = [{"itemid": "100", "clock": "1000", "value_avg": "50"}, {"itemid": "100", "clock": "4600", "value_avg": "91.5"}]
        else:
            r = []
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": r})


@pytest.fixture
def zab(monkeypatch):
    z = Zab()
    http = HttpClients(httpx.MockTransport(z))
    monkeypatch.setattr(router, "clients", http)
    zint._auth_in_body.clear()
    return z, http


async def test_zabbix_per_tile(authed, zab):
    z, http = zab
    g = await _group(authed)
    zs = await _svc(authed, g, "zabbix", "https://zabbix.jbogaert.be", secrets={"token": "zbx-token"}, name="Zabbix")
    pve = await _svc(authed, g, "", "https://192.168.0.50:8006", name="pve50")
    plex = await _svc(authed, g, "", "https://plex.jbogaert.be", name="Plex")  # via NPM → 192.168.0.105
    over = await _svc(authed, g, "", "https://overseerr.jbogaert.be", name="overseerr")  # draait op plex
    radarr = await _svc(authed, g, "", "http://192.168.0.106:7878", name="Radarr")  # zelfde naam; node via ⟳ pve
    nas = await _svc(authed, g, "", "https://nas.lan:5001", name="Opslag")  # via DNS-naam
    manual = await _svc(authed, g, "", "https://x.example", config={"zabbix": "pve50"}, name="iets")
    off = await _svc(authed, g, "", "https://192.168.0.50:8443", config={"zabbix": "-"}, name="uit")
    lone = await _svc(authed, g, "", "https://y.example", name="los")
    agen, db = await _db()
    (await db.get(Service, over)).parent_id = plex
    db.add(SshHost(name="radarr", host="192.168.0.106", username="root", folder="pve50"))
    db.add(ConfigVersion(item="npm:1", name="NPM-hosts", kind="npm", sha="x", size=1, content=encrypt(json.dumps(
        {"proxy-hosts": [{"id": 1, "domain_names": ["plex.jbogaert.be"], "forward_host": "192.168.0.105"}]}))))
    await db.commit()

    r = await zmon.run_zabbix(db, http)
    assert r == {"hosts": 4, "error": None}
    s = (await authed.get("/api/zabbix")).json()
    assert s["configured"] and s["error"] is None
    sv = s["services"]
    hosts = lambda sid: {(h["name"], h["role"]) for h in sv[str(sid)]["hosts"]}  # noqa: E731
    assert hosts(pve) == {("pve50", "eigen")} and sv[str(pve)]["level"] == "err"  # probleem "hoog"
    assert hosts(plex) == {("Plex", "eigen")} and sv[str(plex)]["level"] == "ok"  # alleen een waarschuwing
    assert hosts(over) == {("Plex", "node")}
    assert hosts(radarr) == {("radarr", "eigen"), ("pve50", "node")} and sv[str(radarr)]["level"] == "err"
    assert hosts(nas) == {("Synology", "eigen")} and sv[str(nas)]["level"] == "err"  # onbereikbaar
    assert hosts(manual) == {("pve50", "eigen")}
    assert str(off) not in sv and str(lone) not in sv and str(zs) not in sv

    d = (await authed.get(f"/api/services/{radarr}/zabbix")).json()
    by = {h["name"]: h for h in d["hosts"]}
    assert by["radarr"]["level"] == "ok" and not by["radarr"]["down"]  # actieve agent bereikbaar
    m = {x["label"]: x for x in by["pve50"]["metrics"]}
    assert m["cpu"]["value"] == 91.5 and m["cpu"]["points"] == [[1000, 50.0], [4600, 91.5]]
    assert m["uptime"]["format"] == "uptime"
    assert by["pve50"]["problems"][0]["name"] == "Hoge CPU op pve50"
    d = (await authed.get(f"/api/services/{plex}/zabbix")).json()
    assert [x["label"] for x in d["hosts"][0]["metrics"]] == ["ram"]  # icmpping nooit gemeten: weg
    assert (await authed.get(f"/api/services/{lone}/zabbix")).json() == {"configured": True, "hosts": []}
    assert (await authed.get(f"/api/services/{off}/zabbix")).json() == {"configured": False, "hosts": []}  # geen hint

    # Zabbix even weg: de vorige stand blijft, met de fout erbij.
    z.triggers = []
    agen, db = await _db()
    (await db.get(Service, zs)).secrets = encrypt(json.dumps({"token": "fout"}))
    await db.commit()
    r = await zmon.run_zabbix(db, http)
    assert "Not authorized" in r["error"]
    s = (await authed.get("/api/zabbix")).json()
    assert s["error"] and s["services"][str(pve)]["level"] == "err"


async def test_zabbix_tile_and_old_auth(authed, monkeypatch):
    z = Zab(legacy=True)
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(z)))
    router._cache.clear()
    zint._auth_in_body.clear()
    g = await _group(authed)
    zs = await _svc(authed, g, "zabbix", "https://zabbix.jbogaert.be", secrets={"token": "zbx-token"}, name="Zabbix")
    w = (await authed.get("/api/widgets")).json()[str(zs)]["fields"]
    assert [(f["label"], f["value"], f["level"]) for f in w] == [("hosts", 4, None), ("problemen", 2, "err"),
                                                                ("onbereikbaar", 1, "err")]
    d = (await authed.get(f"/api/services/{zs}/integration")).json()
    probs = next(x for x in d["sections"] if x["title"] == "open problemen")
    assert probs["rows"][0][2] == {"v": "hoog", "level": "err"}


async def test_no_zabbix_clears_state(authed):
    agen, db = await _db()
    db.add(AppState(key=zmon.STATE_KEY, value={"service_id": 1, "map": {}}))
    await db.commit()
    assert (await zmon.run_zabbix(db, None)) == {"skipped": True}
    assert (await authed.get("/api/zabbix")).json()["configured"] is False
    assert (await db.execute(select(AppState).where(AppState.key == zmon.STATE_KEY))).scalar_one().value == {}
