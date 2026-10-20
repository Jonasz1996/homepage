"""Stap 3 van het verbeterplan, deel 2: één node 's nachts uit."""

from datetime import datetime, timedelta, timezone

import httpx

from app.models import Metric
from app.monitoring.checks import HttpClients
from app.routers import capacity as capacity_router

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db


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
