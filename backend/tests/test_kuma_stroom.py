"""Stap 3 van het verbeterplan, deel 2: Uptime Kuma vervangen door het dashboard, en één node 's nachts uit."""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
from sqlalchemy import select

from app import kuma, setupcheck
from app.models import AuditLog, Metric, Revision, Service, WebhookSource
from app.monitoring.checks import HttpClients
from app.routers import capacity as capacity_router, kuma as kuma_router

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db

METRICS = r"""# HELP monitor_status Monitor Status (1 = UP, 0= DOWN, 2= PENDING, 3= MAINTENANCE)
# TYPE monitor_status gauge
monitor_status{monitor_name="Plex",monitor_type="http",monitor_url="https://plex.jbogaert.be/web",monitor_hostname="null",monitor_port="null"} 1
monitor_status{monitor_name="Jellyfin",monitor_type="keyword",monitor_url="https://jellyfin.jbogaert.be",monitor_hostname="null",monitor_port="null"} 1
monitor_status{monitor_name="NAS \"DSM\"",monitor_type="port",monitor_url="https://",monitor_hostname="192.168.0.60",monitor_port="5001"} 0
monitor_status{monitor_name="Router",monitor_type="ping",monitor_url="https://",monitor_hostname="192.168.0.1",monitor_port="null"} 1
monitor_status{monitor_name="DNS",monitor_type="dns",monitor_url="https://",monitor_hostname="jbogaert.be",monitor_port="53"} 1
monitor_status{monitor_name="Postgres",monitor_type="postgres",monitor_url="https://",monitor_hostname="null",monitor_port="null"} 1
monitor_status{monitor_name="watchtower",monitor_type="docker",monitor_url="https://",monitor_hostname="null",monitor_port="null"} 1
monitor_status{monitor_name="backup-script",monitor_type="push",monitor_url="https://",monitor_hostname="null",monitor_port="null"} 2
monitor_status{monitor_name="Media",monitor_type="group",monitor_url="https://",monitor_hostname="null",monitor_port="null"} 1
monitor_response_time{monitor_name="Plex",monitor_type="http",monitor_url="https://plex.jbogaert.be/web",monitor_hostname="null",monitor_port="null"} 120
"""


def test_kuma_metrics_lezen():
    ms = {m["name"]: m for m in kuma.parse(METRICS)}
    assert len(ms) == 9
    assert ms['NAS "DSM"'] == {"name": 'NAS "DSM"', "type": "port", "url": "https://", "host": "192.168.0.60",
                               "port": "5001", "status": "down"}
    assert ms["backup-script"]["status"] == "pending" and ms["Plex"]["port"] is None


def test_kuma_andere_poort_is_een_andere_dienst():
    svc = SimpleNamespace(id=1, name="Portainer", url="http://192.168.0.5:9000", check={"type": "http"})
    mon = [{"name": "Grafana", "type": "http", "url": "http://192.168.0.5:3000", "host": None, "port": None,
            "status": "up"}]
    assert kuma.compare(mon, [svc])[0]["state"] == "ontbreekt"
    mon[0]["url"] = "http://192.168.0.5:9000/#!/home"
    assert kuma.compare(mon, [svc])[0]["state"] == "gedekt"


async def test_kuma_vergelijken_en_overnemen(authed, monkeypatch):
    seen = {}

    def world(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("authorization")
        if req.url.path != "/metrics":
            return httpx.Response(404)
        return httpx.Response(200, text=METRICS) if seen["auth"] == "Basic OnVrMV9zbGV1dGVs" else httpx.Response(401)

    monkeypatch.setattr(kuma_router, "clients", HttpClients(httpx.MockTransport(world)))
    g = await _group(authed)
    r = await authed.post("/api/services", json={"group_id": g, "name": "plex", "url": "https://plex.jbogaert.be",
                                                 "type": "", "config": {}, "check": {"type": "http", "interval": 60}})
    assert r.status_code == 201
    jelly = await _svc(authed, g, "", "https://jellyfin.jbogaert.be", name="Jellyfin")

    bad = await authed.post("/api/kuma/compare", json={"url": "http://kuma:3001", "api_key": "fout"})
    assert bad.status_code == 502 and "API-sleutel" in bad.json()["detail"]
    r = (await authed.post("/api/kuma/compare", json={"url": "http://kuma:3001/", "api_key": "uk1_sleutel"})).json()
    rows = {m["name"]: m for m in r["monitors"]}
    assert "Media" not in rows
    assert r["counts"] == {"gedekt": 1, "zonder-check": 1, "ontbreekt": 3, "niet-overnemen": 3}
    assert rows["Plex"]["state"] == "gedekt" and rows["Plex"]["service"]["name"] == "plex"
    assert rows["Jellyfin"]["state"] == "zonder-check" and rows["Jellyfin"]["service"]["id"] == jelly
    assert rows["Jellyfin"]["why"].startswith("trefwoord")
    assert rows['NAS "DSM"']["proposal"] == {"name": 'NAS "DSM"', "url": "http://192.168.0.60:5001",
                                             "check": {"type": "tcp", "target": "192.168.0.60:5001", "interval": 60}}
    assert rows["Router"]["proposal"]["check"] == {"type": "ping", "target": "192.168.0.1", "interval": 60}
    assert rows["DNS"]["proposal"]["check"]["type"] == "dns"
    assert rows["watchtower"]["state"] == "niet-overnemen" and "Portainer" in rows["watchtower"]["why"]
    assert rows["Postgres"]["why"] == "geen adres in Kuma"

    add = [rows[n]["proposal"] for n in ('NAS "DSM"', "Router", "DNS")]
    assert (await authed.post("/api/kuma/apply", json={"add": add})).status_code == 404
    evil = {**add[0], "check": {"type": "tcp", "target": "x; rm -rf /"}}
    assert (await authed.post("/api/kuma/apply", json={"group_id": g, "add": [evil]})).status_code == 422
    r = (await authed.post("/api/kuma/apply", json={"group_id": g, "add": add + add[:1], "checks": [
        {"service_id": jelly, "check": rows["Jellyfin"]["proposal"]["check"]}]})).json()
    assert r == {"added": 3, "checks": 1}
    agen, db = await _db()
    svcs = {s.name: s for s in (await db.execute(select(Service))).scalars()}
    assert svcs["Router"].check == {"type": "ping", "target": "192.168.0.1", "interval": 60}
    assert svcs['NAS "DSM"'].icon == "nas-dsm.png" and svcs["Jellyfin"].check["type"] == "http"
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "kuma_import"))).scalars().one().detail == \
        {"added": 3, "checks": 1}
    assert (await db.execute(select(Revision).order_by(Revision.id.desc()))).scalars().first().summary == \
        "Uptime Kuma overgenomen: 3 tegels, 1 checks"
    r = (await authed.post("/api/kuma/compare", json={"url": "http://kuma:3001", "api_key": "uk1_sleutel"})).json()
    assert r["counts"] == {"gedekt": 5, "zonder-check": 0, "ontbreekt": 0, "niet-overnemen": 3}

    # Kuma stuurt nog meldingen: de checklist zegt dat hij uit mag na het overnemen.
    assert not [x for x in await setupcheck.webhooks(db) if x["key"] == "kuma"]
    await authed.post("/api/webhooks", json={"name": "Kuma", "kind": "uptimekuma"})
    row = next(x for x in await setupcheck.webhooks(db) if x["key"] == "kuma")
    assert row["state"] == "half" and row["fix"] == {"window": "kuma"} and "webhook Kuma" in row["todo"][0]
    assert (await db.execute(select(WebhookSource))).scalars().one().kind == "uptimekuma"


GB = 1 << 30


class Nodes:
    """Drie HP's en een Pi. pve51 heeft een VM met een grafische kaart, op pve52 draait een grote VM."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path.removeprefix("/api2/json")
        ok = lambda d: httpx.Response(200, json={"data": d})  # noqa: E731
        if p == "/cluster/resources":
            n = lambda name, mem, cpu=.1: {"type": "node", "node": name, "status": "online", "maxmem": mem,  # noqa: E731
                                           "mem": mem // 2, "maxcpu": 4, "cpu": cpu}
            gst = lambda t, v, name, node, mem, st="running": {"type": t, "vmid": v, "name": name, "node": node,  # noqa: E731
                                                               "status": st, "mem": mem, "maxmem": mem * 2,
                                                               "cpu": .05, "maxcpu": 2}
            return ok([n("pve50", 16 * GB), n("pve51", 16 * GB), n("pve52", 32 * GB), n("pi5", 8 * GB),
                       gst("lxc", 101, "adguard", "pve50", 1 * GB), gst("qemu", 102, "homeassistant", "pve50", 4 * GB),
                       gst("lxc", 103, "oud", "pve50", 0, "stopped"), gst("qemu", 110, "jellyfin-gpu", "pve51", 6 * GB),
                       gst("qemu", 120, "nextcloud", "pve52", 14 * GB), gst("lxc", 130, "pihole", "pi5", GB // 2),
                       {"type": "qemu", "vmid": 9000, "template": 1, "node": "pve50"}])
        if p == "/storage":
            return ok([{"storage": "local-lvm", "type": "lvmthin"}, {"storage": "nas", "type": "nfs", "shared": 1},
                       {"storage": "fast", "type": "zfspool", "nodes": "pve50,pve51"}])
        if p.endswith("/status") and p.startswith("/nodes/"):
            arm = p.split("/")[2] == "pi5"
            return ok({"current-kernel": {"machine": "aarch64" if arm else "x86_64"}, "cpuinfo": {"model": "x"}})
        if p.endswith("/config"):
            vmid = int(p.split("/")[4])
            return ok({101: {"rootfs": "nas:subvol-101-disk-0,size=8G", "mp0": "/mnt/media,mp=/media"},
                       102: {"scsi0": "fast:vm-102-disk-0,size=32G", "ide2": "nas:iso/x.iso,media=cdrom"},
                       103: {"rootfs": "local-lvm:vm-103-disk-0,size=4G"},
                       110: {"scsi0": "local-lvm:vm-110-disk-0", "hostpci0": "0000:01:00,pcie=1"},
                       120: {"scsi0": "nas:vm-120-disk-0"}}.get(vmid, {}))
        return httpx.Response(404)


async def test_een_node_s_nachts_uit(authed, monkeypatch):
    monkeypatch.setattr(capacity_router, "clients", HttpClients(httpx.MockTransport(Nodes())))
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", secrets={"username": "a@pve!b", "password": "c"})
    await _svc(authed, g, "homeassistant", "http://192.168.0.30:8123", config={"price": 0.30}, name="HA")
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    db.add(Metric(service_id=pve, kind="guest", name="pve51/102", ts=now - timedelta(days=2), mem=5 * GB))
    db.add(Metric(service_id=pve, kind="guest", name="pve50/102", ts=now - timedelta(days=9), mem=12 * GB))
    for i, w in enumerate((28, 32)):
        db.add(Metric(service_id=pve, kind="power", name="HP pve50", ts=now - timedelta(hours=i + 1), watts=w))
    await db.commit()

    r = (await authed.get("/api/capacity/nightly?hours=8")).json()
    c = {x["node"]: x for x in r["candidates"]}
    assert r["best"] == "pve50" and r["candidates"][0]["node"] == "pve50" and r["quorum_left"] is True
    p50 = c["pve50"]
    assert p50["feasible"] and p50["watts"] == 30 and not p50["estimated"]
    assert p50["kwh_year"] == 87.6 and p50["eur_year"] == 26.28
    moves = {m["vmid"]: m for m in p50["moves"]}
    # De piek van 102 (5 GB, op een andere node gemeten) telt, de meting van 9 dagen geleden niet.
    assert moves[102]["need"] == 5 * GB and moves[102]["to"] == "pve52"
    assert moves[102]["command"] == "qm migrate 102 pve52 --online --with-local-disks"
    assert "opslag fast bestaat niet op pve52" in moves[102]["notes"]
    assert moves[101]["command"].startswith("pct migrate 101 ") and moves[101]["command"].endswith(" --restart")
    assert "bind mount /mnt/media: die map moet ook op " + moves[101]["to"] + " bestaan" in moves[101]["notes"]
    assert moves[103]["command"] == f"pct migrate 103 {moves[103]['to']}" and "staat uit" in moves[103]["notes"]
    assert c["pve51"]["blockers"] == ["jellyfin-gpu (110): passthrough hostpci0"] and not c["pve51"]["feasible"]
    assert c["pve52"]["why"] == "nextcloud (120) past nergens: 9.2 GB RAM tekort"
    assert c["pi5"]["why"] == "geen andere node met dezelfde architectuur" and c["pi5"]["estimated"]
