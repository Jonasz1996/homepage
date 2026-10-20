import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
from sqlalchemy import select

from app.db import get_db
from app.main import app
from app.models import ConfigVersion, Notification, Service, SshHost
from app.monitoring import restoretest
from app.monitoring.checks import HttpClients
from app.routers import netmap
from app.security import encrypt

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db


def _maker():
    factory = app.dependency_overrides[get_db]

    @asynccontextmanager
    async def make():
        gen = factory()
        try:
            yield await anext(gen)
        finally:
            await gen.aclose()
    return make


class Pve:
    def __init__(self):
        self.guests = {105: {"type": "lxc", "vmid": 105, "name": "plex", "node": "pve50", "status": "running"},
                       110: {"type": "lxc", "vmid": 110, "name": "pihole", "node": "pve51", "status": "running"},
                       200: {"type": "qemu", "vmid": 200, "name": "pbs", "node": "pve51", "status": "running"},
                       9900: {"type": "lxc", "vmid": 9900, "name": "iets", "node": "pve50", "status": "stopped"}}
        self.conf: dict[int, dict] = {}
        self.calls: list[tuple[str, str, dict]] = []
        self.restore_fails = False
        self.crashes = False

    def _task(self, ok=True):
        return httpx.Response(200, json={"data": "UPID:pve50:0001:" + ("ok" if ok else "fail") + ":"})

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p, m = req.url.path.removeprefix("/api2/json"), req.method
        body = {k: v[0] for k, v in parse_qs(req.content.decode()).items()} if req.content else {}
        self.calls.append((m, p, body))
        if p == "/cluster/resources":
            return httpx.Response(200, json={"data": [
                {"type": "node", "node": "pve50", "status": "online", "cpu": 0.1, "mem": 1, "maxmem": 4},
                {"type": "node", "node": "pve51", "status": "online", "cpu": 0.2, "mem": 2, "maxmem": 4},
                *self.guests.values()]})
        if p == "/storage":
            return httpx.Response(200, json={"data": [{"storage": "pbs-pi", "type": "pbs"}, {"storage": "local-lvm", "type": "lvmthin"}]})
        if p.endswith("/storage") and "content=rootdir" in str(req.url):
            return httpx.Response(200, json={"data": [{"storage": "local-lvm"}]})
        if p == "/nodes/pve50/storage/pbs-pi/content":
            return httpx.Response(200, json={"data": [
                {"volid": "pbs-pi:backup/ct/105/2026-10-01T01:00:00Z", "vmid": 105, "subtype": "lxc", "ctime": 1790000000},
                {"volid": "pbs-pi:backup/ct/105/2026-10-04T01:00:00Z", "vmid": 105, "subtype": "lxc", "ctime": 1790300000},
                {"volid": "pbs-pi:backup/ct/110/2026-10-04T01:00:00Z", "vmid": 110, "subtype": "lxc", "ctime": 1790300100},
                {"volid": "pbs-pi:backup/vm/200/2026-10-04T01:00:00Z", "vmid": 200, "subtype": "qemu", "ctime": 1790300200}]})
        if "/tasks/" in p:
            ok = "fail" not in p
            return httpx.Response(200, json={"data": {"status": "stopped", "exitstatus": "OK" if ok else "unable to restore"}})
        if p == "/nodes/pve50/lxc" and m == "POST":
            v = int(body["vmid"])
            self.guests[v] = {"type": "lxc", "vmid": v, "name": body["hostname"], "node": "pve50", "status": "stopped"}
            self.conf[v] = {"net0": "name=eth0,bridge=vmbr0", "net1": "name=eth1,bridge=vmbr1", "hostname": body["hostname"],
                            "description": body["description"], "onboot": 1}
            return self._task(not self.restore_fails)
        if p.startswith("/nodes/pve50/lxc/"):
            v = int(p.split("/")[4])
            if p.endswith("/config"):
                if m == "PUT":
                    for k in body.get("delete", "").split(","):
                        self.conf[v].pop(k, None)
                    self.conf[v]["onboot"] = int(body["onboot"])
                    return httpx.Response(200, json={"data": None})
                return httpx.Response(200, json={"data": self.conf.get(v, {"description": "eigen CT"})})
            if p.endswith("/status/start"):
                self.guests[v]["status"] = "stopped" if self.crashes else "running"
                return self._task()
            if p.endswith("/status/stop"):
                self.guests[v]["status"] = "stopped"
                return self._task()
            if p.endswith("/status/current"):
                return httpx.Response(200, json={"data": {"status": self.guests[v]["status"]}})
            if m == "DELETE":
                self.guests.pop(v)
                return self._task()
        return httpx.Response(404)


async def test_restore_test(authed, monkeypatch):
    monkeypatch.setattr(restoretest, "BOOT_WAIT", 0)
    world = Pve()
    http = HttpClients(httpx.MockTransport(world))
    g = await _group(authed)
    await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", secrets={"username": "a@pve!b", "password": "c"}, name="pve")
    make = _maker()

    r = await restoretest.run(make, http, manual=True)
    assert r["ok"], r
    assert r["source_vmid"] == 105 and r["vmid"] == 9901 and r["name"] == "plex"
    assert r["volid"] == "pbs-pi:backup/ct/105/2026-10-04T01:00:00Z"
    post = next(b for m, p, b in world.calls if m == "POST" and p == "/nodes/pve50/lxc")
    assert post["restore"] == "1" and post["unique"] == "1" and post["start"] == "0"
    put = next(b for m, p, b in world.calls if m == "PUT")
    assert put["delete"] == "net0,net1" and put["onboot"] == "0"
    assert 9901 not in world.guests and 9900 in world.guests  # opgeruimd, en niets anders aangeraakt
    # Volgende keer de CT die het langst niet getest is.
    r2 = await restoretest.run(make, http)
    assert r2["ok"] and r2["source_vmid"] == 110

    # Start, maar valt meteen stil: mislukt, en toch opgeruimd.
    world.crashes = True
    r3 = await restoretest.run(make, http)
    assert not r3["ok"] and r3["step"] == "opstarten" and "draait" in r3["error"] and 9901 not in world.guests
    world.crashes, world.restore_fails = False, True
    r4 = await restoretest.run(make, http)
    assert not r4["ok"] and r4["step"] == "terugzetten" and "unable to restore" in r4["error"]

    agen, db = await _db()
    notes = [(n.title, n.level) for n in (await db.execute(select(Notification).where(Notification.source == "backup")
                                                            .order_by(Notification.id))).scalars()]
    assert notes[0] == ("Hersteltest geslaagd: plex (105)", "ok")
    assert notes[2][1] == "err" and notes[2][0].startswith("Hersteltest mislukt")
    await db.close()
    st = (await authed.get("/api/restoretest")).json()
    assert [h["ok"] for h in st["history"]] == [False, False, True, True] and st["running"] is None

    # Een onderbroken test: de volgende run ruimt die CT op, maar alleen met het merkteken.
    world.restore_fails = False
    world.guests[9950] = {"type": "lxc", "vmid": 9950, "name": "hersteltest-105", "node": "pve50", "status": "running"}
    world.conf[9950] = {"description": f"{restoretest.MARKER}: kopie"}
    old = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    async with make() as db:
        s = await restoretest.ensure_state(db, restoretest.STATE_KEY, {})
        s.value = {**s.value, "running": {"at": old, "vmid": 9950, "node": "pve50"}}
        await db.commit()
    assert (await restoretest.run(make, http))["ok"] and 9950 not in world.guests
    async with make() as db:
        s = await restoretest.ensure_state(db, restoretest.STATE_KEY, {})
        s.value = {**s.value, "running": {"at": old, "vmid": 105, "node": "pve50"}}
        await db.commit()
    await restoretest.run(make, http)
    assert 105 in world.guests  # geen merkteken: blijft staan


async def test_restore_test_schedule_and_settings(authed):
    assert not restoretest.due({}, datetime.now(timezone.utc))
    v = {"settings": {"enabled": True, "day": 3, "hour": 5}}
    before = datetime(2026, 10, 3, 4, 59).astimezone()
    after = datetime(2026, 10, 3, 5, 1).astimezone()
    assert not restoretest.due(v, before) and restoretest.due(v, after)
    assert not restoretest.due({**v, "last_at": after.isoformat()}, after)
    assert restoretest.next_run({**v, "last_at": after.isoformat()}, after).month == 11
    r = await authed.put("/api/restoretest/settings", json={"enabled": True, "day": 1, "hour": 4, "node": "pve50"})
    assert r.status_code == 200 and r.json()["settings"]["node"] == "pve50" and r.json()["next"]
    assert (await authed.put("/api/restoretest/settings", json={"node": "pve; rm -rf"})).status_code == 422


async def test_netmap(authed, monkeypatch):
    world = Pve()
    monkeypatch.setattr(netmap, "clients", HttpClients(httpx.MockTransport(world)))
    netmap._cache.clear()
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", secrets={"username": "a@pve!b", "password": "c"},
                     name="pve50")
    plex = await _svc(authed, g, "", "https://plex.jbogaert.be", name="plex")
    radarr = await _svc(authed, g, "", "http://192.168.0.105:7878", name="radarr")
    pihole = await _svc(authed, g, "", "http://pihole.lan/admin", name="Pi-hole")
    over = await _svc(authed, g, "", "https://overseerr.example", name="overseerr")
    kuma = await _svc(authed, g, "", "https://kuma.example", name="kuma")
    nas = await _svc(authed, g, "", "https://192.168.0.60:5001", name="nas")
    agen, db = await _db()
    (await db.get(Service, over)).parent_id = plex
    (await db.get(Service, kuma)).parent_id = pve
    db.add(SshHost(name="plex", host="192.168.0.105", username="root", source=f"pve:{pve}:lxc/105"))
    db.add(ConfigVersion(item="npm:1", name="NPM-hosts", kind="npm", sha="x", size=1, content=encrypt(json.dumps(
        {"proxy-hosts": [{"id": 1, "domain_names": ["plex.jbogaert.be"], "forward_host": "192.168.0.105"}]}))))
    await db.commit()

    m = (await authed.get("/api/netmap")).json()
    assert [n["name"] for n in m["nodes"]] == ["pve50", "pve51"]
    assert next(x for x in m["guests"] if x["vmid"] == 105)["ip"] == "192.168.0.105"
    by = {s["id"]: s for s in m["services"]}
    assert by[plex]["guest"] == "lxc/105" and by[plex]["via_npm"] and by[plex]["how"] == "NPM → 192.168.0.105"
    assert by[radarr]["guest"] == "lxc/105" and by[radarr]["how"] == "ip"
    assert by[pihole]["guest"] == "lxc/110" and by[pihole]["node"] == "pve51"
    assert by[over]["guest"] == "lxc/105" and by[over]["how"] == "draait op plex"
    assert by[kuma]["guest"] is None and by[kuma]["node"] == "pve50"
    assert by[nas]["guest"] is None and by[nas]["node"] is None
    assert pve not in by
