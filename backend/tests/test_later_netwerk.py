import base64
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from app import wol
from app.integrations.homeassistant import month_start
from app.models import AppState, Event, Metric, Notification
from app.monitoring import updates as upd
from app.monitoring.checks import HttpClients
from app.monitoring.network import (debounce, integrate, power_overview, sample_power, watch_gateways,
                                    watch_public_ip, watch_tunnels)
from app.routers import integrations as int_router
from app.routers import network as net_router

from .test_capacity import _db
from .test_integrations import _group, _svc

ACCOUNT = "0123456789abcdef0123456789abcdef"


class Net:
    """Neppe OPNsense, Cloudflare, Home Assistant en IP-dienst."""

    def __init__(self):
        self.gw = {"status": "none", "status_translated": "Online", "loss": "0.0 %", "delay": "4.2 ms"}
        self.tunnel = "healthy"
        self.ip = "81.82.83.84"
        self.watts = {"sensor.pve50_power": "120.5", "sensor.pve51_power": "0.08"}
        self.energy_now = 1250.0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p, host = req.url.path, req.url.host
        if p.startswith("/api/routes/") or p.startswith("/api/core/"):
            assert req.headers["authorization"] == "Basic " + base64.b64encode(b"k:s").decode()
            if p == "/api/routes/gateway/status":
                return httpx.Response(200, json={"status": "ok", "items": [
                    {"name": "WAN_DHCP", "address": "81.82.83.1", "monitor": "1.1.1.1", **self.gw},
                    {"name": "WAN6", "status": "none", "status_translated": "Online", "loss": "~", "delay": "~"}]})
            return httpx.Response(200, json={"status": "update", "status_msg": "Er zijn updates", "updates": "2",
                                             "product": {"product_version": "25.1.3", "product_latest": "25.1.5"},
                                             "upgrade_packages": [{"name": "opnsense", "current_version": "25.1.3",
                                                                   "new_version": "25.1.5"},
                                                                  {"name": "unbound", "current_version": "1.22",
                                                                   "new_version": "1.23"}]})
        if host == "api.cloudflare.com":
            assert req.headers["authorization"] == "Bearer cf-token"
            assert p == f"/client/v4/accounts/{ACCOUNT}/cfd_tunnel"
            return httpx.Response(200, json={"success": True, "result": [
                {"id": "t1", "name": "thuis", "status": self.tunnel, "conns_active_at": "2026-10-01T10:00:00Z",
                 "connections": [{"colo_name": "ams01", "client_version": "2025.9.1"}, {"colo_name": "bru01"}]}]})
        if p.startswith("/api/states/"):
            assert req.headers["authorization"] == "Bearer ha-token"
            ent = p.rsplit("/", 1)[1]
            if ent == "sensor.pve50_energy":
                return httpx.Response(200, json={"state": str(self.energy_now), "attributes": {"unit_of_measurement": "Wh"}})
            unit = "kW" if ent == "sensor.pve51_power" else "W"
            return httpx.Response(200, json={"state": self.watts[ent], "attributes": {"unit_of_measurement": unit}})
        if p.startswith("/api/history/period/"):
            assert req.url.params["filter_entity_id"] == "sensor.pve50_energy"
            return httpx.Response(200, json=[[{"state": "unavailable"}, {"state": "1000"}, {"state": "1100"}]])
        if host == "1.1.1.1":
            return httpx.Response(200, text=f"fl=1\nh=1.1.1.1\nip={self.ip}\nts=1\n")
        return httpx.Response(404)


@pytest.fixture
def net(monkeypatch):
    n = Net()
    clients = HttpClients(httpx.MockTransport(n))
    monkeypatch.setattr(int_router, "clients", clients)
    monkeypatch.setattr(net_router, "clients", clients)
    int_router._cache.clear()
    n.clients = clients
    return n


HA_CONFIG = {"price": 0.3, "nodes": {"pve50": {"power": "sensor.pve50_power", "energy": "sensor.pve50_energy"},
                                     "pve51": "sensor.pve51_power"}}


async def _setup(authed):
    g = await _group(authed)
    opn = await _svc(authed, g, "opnsense", "https://192.168.0.1", secrets={"key": "k", "secret": "s"}, name="OPNsense")
    cf = await _svc(authed, g, "cloudflared", "https://one.dash.cloudflare.com", config={"account": ACCOUNT},
                    secrets={"token": "cf-token"}, name="Tunnel")
    ha = await _svc(authed, g, "homeassistant", "http://192.168.0.30:8123", config=HA_CONFIG,
                    secrets={"token": "ha-token"}, name="HA")
    return g, opn, cf, ha


async def test_widgets(authed, net):
    g, opn, cf, ha = await _setup(authed)
    w = (await authed.get("/api/widgets")).json()
    f = {x["label"]: x for x in w[str(opn)]["fields"]}
    assert f["WAN"]["value"] == "Online" and f["WAN"]["level"] == "ok" and f["ping"]["value"] == "4 ms"
    assert f["updates"]["value"] == 2
    f = {x["label"]: x for x in w[str(cf)]["fields"]}
    assert f["status"]["value"] == "healthy" and f["tunnels"]["value"] == "1/1" and f["verbindingen"]["value"] == 2
    # pve50: 120.5 W, pve51: 0.08 kW = 80 W. Maandverbruik alleen als elke node een energy-sensor heeft.
    f = {x["label"]: x for x in w[str(ha)]["fields"]}
    assert f["nu"]["value"] == "200 W" and "maand" not in f
    d = (await authed.get(f"/api/services/{ha}/integration")).json()
    rows = d["sections"][0]["rows"]
    # Energy: 1250 Wh nu, 1000 Wh bij het begin van de maand → 0.25 kWh.
    assert [c["v"] for c in rows[0]] == ["pve50", "120 W", "0.2 kWh", "€ 0.07"]
    assert rows[1][2]["v"] == "zie df"
    d = (await authed.get(f"/api/services/{opn}/integration")).json()
    assert d["sections"][0]["rows"][1][2]["v"] == "—"  # "~" van OPNsense = geen meting


def test_debounce():
    state, ch = debounce({}, {"wan": "ok"})
    assert ch == []
    state, ch = debounce(state, {"wan": "err"})
    assert ch == [] and state["wan"]["status"] == "ok"  # één keer: nog niets
    state, ch = debounce(state, {"wan": "ok"})
    assert ch == []  # was maar een hapering
    state, ch = debounce(state, {"wan": "err"})
    state, ch = debounce(state, {"wan": "err"})
    assert ch == [("wan", "ok", "err")]


async def test_watchers_notify(authed, net):
    g, opn, cf, ha = await _setup(authed)
    agen, db = await _db()

    async def rnd():
        await watch_gateways(db, net.clients)
        await watch_tunnels(db, net.clients)
        await watch_public_ip(db, net.clients)
        await db.commit()

    await rnd()
    net.gw = {"status": "down", "status_translated": "Offline", "loss": "100.0 %", "delay": "0.0 ms"}
    net.tunnel = "down"
    net.ip = "81.82.83.99"
    await rnd()
    await rnd()
    notes = {n.title: n for n in (await db.execute(select(Notification).where(Notification.source == "netwerk"))).scalars()}
    assert set(notes) == {"WAN_DHCP: down", "Tunnel thuis: down", "Publiek IP gewijzigd"}
    assert notes["WAN_DHCP: down"].level == "err" and "100% verlies" in notes["WAN_DHCP: down"].body
    assert notes["Publiek IP gewijzigd"].body.startswith("81.82.83.84 → 81.82.83.99")
    net.gw = {"status": "none", "status_translated": "Online", "loss": "0 %", "delay": "5 ms"}
    await rnd()
    await rnd()
    assert (await db.execute(select(Notification).where(Notification.title == "WAN_DHCP is weer online"))).scalar_one()
    assert len((await db.execute(select(Event).where(Event.kind == "netwerk"))).scalars().all()) == 4

    data = (await authed.get("/api/network")).json()
    assert data["public_ip"]["ip"] == "81.82.83.99" and data["public_ip"]["history"][0]["ip"] == "81.82.83.84"
    assert data["gateways"][0]["items"][0]["level"] == "ok" and data["tunnels"][0]["items"][0]["status"] == "down"
    assert (await authed.post("/api/network/refresh")).json()["public_ip"]["ip"] == "81.82.83.99"
    await agen.aclose()


def test_wol_packet():
    assert wol.normalize_mac("AA-BB-CC-DD-EE-0F") == "aa:bb:cc:dd:ee:0f"
    assert wol.normalize_mac("aabbccddeeff") == "aa:bb:cc:dd:ee:ff"
    assert wol.normalize_mac("aa:bb-cc:dd:ee:ff") is None
    assert wol.normalize_mac("zz:bb:cc:dd:ee:ff") is None
    p = wol.magic_packet("aa:bb:cc:dd:ee:ff")
    assert len(p) == 102 and p[:6] == b"\xff" * 6 and p[6:12] == bytes.fromhex("aabbccddeeff")


async def test_wol_endpoint(authed, monkeypatch, net):
    sent = []
    monkeypatch.setattr(wol, "send", lambda mac, bc: sent.append((mac, bc)))
    g = await _group(authed)
    hp = await _svc(authed, g, "link", "https://pve52.jbogaert.be", config={"mac": "AA:BB:CC:DD:EE:01"}, name="pve52")
    plain = await _svc(authed, g, "link", "https://x.jbogaert.be", name="X")
    r = await authed.post(f"/api/services/{hp}/wol")
    assert r.status_code == 200, r.text
    assert sent == [("aa:bb:cc:dd:ee:01", "255.255.255.255")]
    assert (await authed.post(f"/api/services/{plain}/wol")).status_code == 400
    acts = [a for a in (await authed.get("/api/actions")).json() if a["id"] == "wol"]
    assert acts == [{"id": "wol", "label": "wekken (Wake-on-LAN)", "target": "pve52", "service_id": hp,
                     "service": "pve52", "endpoint": f"/services/{hp}/wol", "confirm": True}]
    tl = (await authed.get("/api/timeline", params={"kind": "actie"})).json()["items"]
    assert tl[0]["title"] == "pve52: Wake-on-LAN verstuurd"
    assert (await authed.get("/api/network")).json()["wol"][0]["mac"] == "aa:bb:cc:dd:ee:01"


def test_integrate():
    t0 = datetime(2026, 10, 1, tzinfo=timezone.utc)
    pts = [(t0 + timedelta(minutes=10 * i), 600.0) for i in range(7)]  # 1 uur 600 W
    assert [round(x, 6) for x in integrate(pts)] == [0.6, 1.0]
    gap = pts + [(t0 + timedelta(hours=5), 600.0), (t0 + timedelta(hours=5, minutes=10), 600.0)]
    kwh, hours = integrate(gap)  # het gat van 4 uur telt niet mee
    assert round(kwh, 3) == 0.7 and round(hours, 3) == round(1 + 1 / 6, 3)


async def test_power_overview(authed, net):
    g, opn, cf, ha = await _setup(authed)
    agen, db = await _db()
    assert await sample_power(db, net.clients) == 2
    await db.commit()
    w = {m.name: m.watts for m in (await db.execute(select(Metric).where(Metric.kind == "power"))).scalars()}
    assert w == {"pve50": 120.5, "pve51": 80.0}
    # pve51 zonder energy-sensor: 2 uur aan 100 W gemeten deze maand.
    start = max(month_start(), datetime.now(timezone.utc) - timedelta(hours=10))
    for i in range(13):
        db.add(Metric(service_id=ha, kind="power", name="pve51", ts=start + timedelta(minutes=10 * i), watts=100.0))
    await db.commit()
    data = await power_overview(db, net.clients)
    nodes = {n["name"]: n for n in data[0]["nodes"]}
    assert nodes["pve50"]["month_kwh"] == 0.25 and not nodes["pve50"]["measured"]
    assert round(nodes["pve51"]["month_kwh"], 3) == 0.2 and nodes["pve51"]["measured"]
    assert round(nodes["pve51"]["month_cost"], 3) == 0.06
    # Prognose: 100 W gemiddeld over de hele maand.
    hours = nodes["pve51"]["forecast_kwh"] / 0.1
    assert 27 * 24 < hours <= 31 * 24 + 1
    assert (await authed.get("/api/power")).status_code == 200
    await agen.aclose()


async def test_opnsense_updates(authed, net):
    await _setup(authed)
    agen, db = await _db()
    out = await upd.collect(db, net.clients)
    t = next(x for x in out if x["kind"] == "opnsense")
    assert t["count"] == 2 and [p["n"] for p in t["packages"]] == ["opnsense", "unbound"]
    await agen.aclose()


async def test_public_ip_can_be_disabled(authed, net, monkeypatch):
    from app.monitoring import network
    monkeypatch.setattr(network, "get_settings", lambda: type("S", (), {"public_ip_check": False})())
    agen, db = await _db()
    await watch_public_ip(db, net.clients)
    await db.commit()
    assert await db.get(AppState, "public_ip") is None
    await agen.aclose()
