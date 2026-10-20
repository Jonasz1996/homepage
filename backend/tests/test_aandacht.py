"""Aandacht-overzicht (alles wat nu mis is) en de instellingen-checklist."""

from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app import attention
from app.db import get_db
from app.health import selfcheck as sc
from app.main import app
from app.models import (AppState, CronJob, Device, MaintenanceWindow, Service, ServiceState, SshHost, UpdateRun,
                        WebhookSource)
from app.monitoring.checks import HttpClients
from app.routers import integrations as integrations_router

NOW = datetime.now(timezone.utc)


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _tiles(c, *specs) -> dict[str, int]:
    page = (await c.post("/api/pages", json={"name": "P"})).json()["id"]
    g = (await c.post("/api/groups", json={"page_id": page, "name": "G"})).json()["id"]
    out = {}
    for name, typ, extra in specs:
        r = await c.post("/api/services", json={"group_id": g, "name": name, "url": f"https://{name}.lan",
                                                "type": typ, **extra})
        assert r.status_code == 201, r.text
        out[name] = r.json()["id"]
    return out


def _state(db, key, value):
    db.add(AppState(key=key, value=value))


async def test_zonder_worker_staat_dat_bovenaan(authed):
    r = (await authed.get("/api/attention")).json()
    assert [i["key"] for i in r["items"]] == ["worker"]
    assert r["items"][0]["level"] == "err" and r["counts"] == {"err": 1, "warn": 0, "info": 0}
    assert r["items"][0]["fix"] == {"window": "health", "tab": "homepage"}


async def _seed(authed) -> dict[str, int]:
    ids = await _tiles(authed, ("pve2", "link", {}), ("plex", "link", {}), ("nas", "link", {}), ("wiki", "link", {}),
                       ("git", "link", {}), ("pbs-pi", "proxmoxbackupserver", {}), ("pve", "proxmox", {}),
                       ("zabbix", "zabbix", {}))
    agen, db = await _db()
    plex = await db.get(Service, ids["plex"])
    plex.parent_id = ids["pve2"]
    nas = await db.get(Service, ids["nas"])
    nas.maintenance_until = NOW + timedelta(hours=1)
    since = NOW - timedelta(minutes=20)
    for name in ("pve2", "plex", "nas"):
        db.add(ServiceState(service_id=ids[name], status="down", since=since, last_error="Timeout"))
    db.add(ServiceState(service_id=ids["wiki"], status="up", since=since, cert_expires_at=NOW + timedelta(days=2, hours=1)))
    db.add(ServiceState(service_id=ids["git"], status="up", since=since, cert_expires_at=NOW + timedelta(days=10, hours=1)))
    for i, (status, muted) in enumerate((("fout", False), ("gemist", False), ("fout", True))):
        db.add(CronJob(key=f"k{i}", target="ssh:1", target_name="pve2", kind="crontab", name=f"job{i}",
                       last_status=status, last_exit=1 if status == "fout" else None, muted=muted,
                       last_run_at=NOW - timedelta(hours=2)))
    _state(db, f"pbs_problems:{ids['pbs-pi']}", {"keys": ["pi:ct/101:task", "pi:ct/102:late"],
                                                 "items": {"pi:ct/101:task": "pi:ct/101 (plex): laatste back-up mislukt"}})
    _state(db, "restoretest", {"last_at": NOW.isoformat(), "history": [
        {"ok": False, "name": "plex", "source_vmid": 101, "step": "opstarten", "error": "CT stopte"}]})
    _state(db, "updates", {"targets": [{"key": "a", "name": "pve2", "count": 5, "security": 2, "error": None},
                                       {"key": "b", "name": "pve3", "count": 3, "security": 0, "error": None}]})
    db.add(UpdateRun(target="node:pve3", target_name="pve3", status="fout", error="E: dpkg was interrupted\n"))
    _state(db, "health", {"hosts": [
        {"key": "ssh:1", "name": "pve2", "disks": [{"dev": "/dev/sda", "model": "WD Red", "level": "warn",
                                                    "why": ["4 vervangen sectoren"]}],
         "pools": [{"name": "rpool", "level": "err", "why": ["DEGRADED"]}], "cpu_temp": 91},
        {"key": "ssh:2", "name": "pi", "error": "PermissionDenied"}]})
    _state(db, "snapshots", {"items": [{"vmid": 101, "name": "voor-update", "age_days": 40}]})
    _state(db, "domains", {"items": [{"name": "jbogaert.be", "days_left": 5, "expires": "2026-10-10"}]})
    _state(db, sc.HEARTBEAT_KEY, {"at": NOW.isoformat(), "started": NOW.isoformat()})
    _state(db, sc.STATE_KEY, {"stale": True})
    _state(db, "cluster", {"alerts": {"c|quorum": {"level": "err", "text": "Cluster home heeft geen quorum meer"}}})
    _state(db, f"disk_full:{ids['pve']}:local-zfs", {"level": 14})
    _state(db, "net_gw:9", {"items": [{"name": "WAN_DHCP", "level": "err", "label": "Offline", "loss_pct": 100}]})
    _state(db, "net_tunnel:9", {"items": [{"name": "thuis", "status": "degraded"}]})
    db.add(Device(mac="aa:bb:cc:dd:ee:ff", hostname="nieuw-ding", known=False))
    db.add(Device(mac="aa:bb:cc:dd:ee:00", hostname="oud", known=True))
    _state(db, "zabbix", {"service_id": ids["zabbix"], "hosts": [{"id": "1", "name": "plex-host", "down": False},
                                                                  {"id": "2", "name": "wiki-host", "down": True}],
                          "problems": [{"host_id": "1", "name": "Disk full", "severity": 4},
                                       {"host_id": "1", "name": "Iets kleins", "severity": 2}],
                          "map": {str(ids["wiki"]): [{"id": "2", "role": "eigen"}],
                                  str(ids["git"]): [{"id": "1", "role": "eigen"}]}})
    db.add(MaintenanceWindow(name="backup-venster", start=NOW - timedelta(minutes=10), minutes=60, repeat="once"))
    await db.commit()
    await agen.aclose()
    return ids


async def test_alles_wat_mis_is(authed, monkeypatch):
    ids = await _seed(authed)
    monkeypatch.setitem(integrations_router._cache, (ids["pve"], "summary"), (0, (), {"error": "401 Unauthorized"}))
    r = (await authed.get("/api/attention")).json()
    by = {i["key"]: i for i in r["items"]}
    # pve2 met plex eronder; nas (onderhoud) niet.
    assert by[f"down:{ids['pve2']}"]["title"] == "pve2 is down" and "Ook down: plex" in by[f"down:{ids['pve2']}"]["text"]
    assert f"down:{ids['plex']}" not in by and f"down:{ids['nas']}" not in by
    assert by[f"cert:{ids['wiki']}"]["level"] == "err" and by[f"cert:{ids['git']}"]["level"] == "warn"
    assert "verloopt over 2 dagen" in by[f"cert:{ids['wiki']}"]["title"]
    cron = [i for i in r["items"] if i["area"] == "cron"]
    assert [(i["level"], i["title"]) for i in cron] == [("err", "job0 op pve2: mislukt"), ("warn", "job1 op pve2: niet gelopen")]
    pbs = by[f"pbs:{ids['pbs-pi']}"]
    assert pbs["level"] == "err" and "2 back-ups" in pbs["title"]
    assert "pi:ct/101 (plex): laatste back-up mislukt" in pbs["text"] and "pi:ct/102: geen back-up" in pbs["text"]
    assert by["restoretest"]["title"] == "Hersteltest mislukt: plex (101)"
    assert by["updates"]["level"] == "warn" and by["updates"]["title"] == "2 beveiligingsupdates op 1 machine"
    assert by["update:node:pve3"]["title"] == "Update op pve3 mislukt" and by["update:node:pve3"]["text"] == "E: dpkg was interrupted"
    assert by["disk:ssh:1:/dev/sda"]["title"] == "pve2: schijf WD Red"
    assert by["pool:ssh:1:rpool"]["level"] == "err"
    assert by["hot:ssh:1"]["title"] == "pve2: CPU 91 °C"
    assert by["hw:ssh:2"]["text"] == "PermissionDenied"
    assert by["snapshots"]["level"] == "info" and by["domain:jbogaert.be"]["level"] == "err"
    assert "worker" not in by and by["selfbackup"]["level"] == "err"
    assert by["cluster:c|quorum"]["title"] == "Cluster home heeft geen quorum meer"
    assert by[f"full:{ids['pve']}:local-zfs"]["title"] == "local-zfs vol binnen 14 dagen"
    assert by["net_gw:9:WAN_DHCP"]["level"] == "err" and by["net_tunnel:9:thuis"]["level"] == "warn"
    assert by["devices"]["title"] == "1 nieuw apparaat op je netwerk" and "nieuw-ding" in by["devices"]["text"]
    # Zabbix: plex-host (tegel git) met een rood probleem (het kleine niet); wiki-host is down en de tegel wiki niet.
    assert by["zbx:1"]["text"] == "Disk full" and by["zbx:1"]["fix"] == {"window": "detail", "service_id": ids["git"]}
    assert by["zbx:2"]["title"] == "Zabbix: wiki-host onbereikbaar"
    assert by["maint:1"]["level"] == "info"
    assert by[f"api:{ids['pve']}"]["text"] == "401 Unauthorized"
    # Gesorteerd: eerst rood, dan oranje, dan info.
    levels = [i["level"] for i in r["items"]]
    assert levels == sorted(levels, key=attention.RANK.__getitem__)
    assert r["items"][0]["key"] == f"down:{ids['pve2']}"
    assert r["counts"]["err"] == sum(1 for x in levels if x == "err")


async def test_negeren_tot_het_verandert(authed):
    await _seed(authed)
    r = (await authed.get("/api/attention")).json()
    disk = next(i for i in r["items"] if i["key"] == "disk:ssh:1:/dev/sda")
    r = (await authed.put("/api/attention/ignore", json={"key": disk["key"], "sig": disk["sig"]})).json()
    assert disk["key"] not in {i["key"] for i in r["items"]}
    assert [i["key"] for i in r["ignored"]] == [disk["key"]] and r["ignored"][0]["ignored_at"]
    # De schijf wordt slechter: weer zichtbaar.
    agen, db = await _db()
    st = await db.get(AppState, "health")
    first = st.value["hosts"][0]
    st.value = {"hosts": [{**first, "disks": [{**first["disks"][0], "why": ["9 vervangen sectoren"]}]},
                          *st.value["hosts"][1:]]}
    await db.commit()
    r = (await authed.get("/api/attention")).json()
    assert disk["key"] in {i["key"] for i in r["items"]} and not r["ignored"]
    # Opgelost: het negeren wordt vergeten, zodat een volgend probleem weer verschijnt.
    st = await db.get(AppState, "health", populate_existing=True)
    st.value = {"hosts": []}
    await db.commit()
    await authed.get("/api/attention")
    acks = await db.get(AppState, attention.ACK_KEY, populate_existing=True)
    assert disk["key"] not in acks.value["items"]
    # Niet langer negeren.
    upd = next(i for i in (await authed.get("/api/attention")).json()["items"] if i["key"] == "updates")
    await authed.put("/api/attention/ignore", json={"key": "updates", "sig": upd["sig"]})
    r = (await authed.put("/api/attention/ignore", json={"key": "updates"})).json()
    assert "updates" in {i["key"] for i in r["items"]}
    await agen.aclose()


async def test_veel_cronjobs_samengevat(authed):
    agen, db = await _db()
    for i in range(12):
        db.add(CronJob(key=f"k{i}", target="ssh:1", target_name="pve2", kind="crontab", name=f"job{i:02d}",
                       last_status="fout", last_exit=2))
    await db.commit()
    await agen.aclose()
    cron = [i for i in (await authed.get("/api/attention")).json()["items"] if i["area"] == "cron"]
    assert len(cron) == attention.MAX_PER_AREA
    assert cron[-1]["key"] == "cron:meer" and cron[-1]["title"] == "Nog 5 cronjobs met een probleem"


async def test_instellingen_checklist(authed, monkeypatch):
    calls = []

    def handler(req: httpx.Request):
        calls.append(req.url.path)
        if req.url.path == "/api2/json/access/permissions":
            return httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1, "VM.Audit": 1, "Datastore.Audit": 1}}})
        if req.url.host == "opnsense.lan":
            return httpx.Response(401, json={"message": "Authentication Failed"})
        return httpx.Response(200, json={"data": []})
    monkeypatch.setattr(integrations_router, "clients", HttpClients(httpx.MockTransport(handler)))

    r = (await authed.get("/api/attention/setup")).json()
    rows = {x["key"]: x for g in r["groups"] for x in g["rows"]}
    assert [g["key"] for g in r["groups"]] == ["proxmox", "netwerk", "monitoring", "ssh", "beveiliging"]
    assert rows["proxmox"]["state"] == "none" and rows["proxmox"]["fix"] == {"window": "api"}
    assert rows["ssh_defaults"]["state"] == "none" and rows["ssh_hosts"]["state"] == "none"
    assert rows["restoretest"]["state"] == "none" and rows["restoretest"]["optional"]
    assert rows["webhook:proxmox"]["state"] == "none" and not rows["webhook:proxmox"]["optional"]
    assert rows["2fa"]["state"] == "ok" and rows["secret"]["state"] == "none"
    assert r["counts"]["half"] == 0 and r["counts"]["ok"] >= 2

    ids = await _tiles(authed, ("pve", "proxmox", {"secrets": {"username": "lees@pve!d", "password": "a"}}),
                       ("opnsense", "opnsense", {"secrets": {"key": "k", "secret": "s"}}),
                       ("pve50", "link", {}), ("pve51", "link", {"config": {"mac": "aa:bb:cc:dd:ee:01"}}))
    agen, db = await _db()
    _state(db, "cluster", {"items": [{"nodes": [{"name": "pve50"}, {"name": "pve51"}]}]})
    _state(db, "ssh_defaults", {"username": "jonas", "password": "x"})
    db.add(SshHost(name="pve50", host="192.168.0.50", source="pve:1:node/pve50"))
    db.add(SshHost(name="plex", host="192.168.0.60", source="pve:1:lxc/101"))
    db.add(WebhookSource(name="pve", kind="proxmox", token_hash="h", token="t"))
    await db.commit()
    host = (await db.execute(select(SshHost).where(SshHost.name == "pve50"))).scalar_one()
    await agen.aclose()

    r = (await authed.get("/api/attention/setup")).json()
    rows = {x["key"]: x for g in r["groups"] for x in g["rows"]}
    px = rows["proxmox"]
    assert px["state"] == "half"
    assert any("VM's aan- en uitzetten kan niet, het token mist VM.PowerMgmt" in t for t in px["todo"])
    assert any("Sys.Modify" in t for t in px["todo"]) and not any("hersteltest" in t for t in px["todo"])
    assert rows["opnsense"]["state"] == "half" and rows["opnsense"]["todo"][0].startswith("opnsense: ")
    assert rows["opnsense"]["fix"] == {"window": "detail", "service_id": ids["opnsense"]}
    assert rows["wol"]["state"] == "half" and "pve50" in rows["wol"]["todo"][0]
    assert rows["wol"]["fix"] == {"window": "edit", "service_id": ids["pve50"]}
    assert rows["ssh_defaults"]["state"] == "half"
    # De CT (via zijn node) heeft geen eigen host key nodig; de node wel.
    assert rows["ssh_hosts"]["state"] == "half" and "pve50" in rows["ssh_hosts"]["todo"][0]
    assert "plex" not in rows["ssh_hosts"]["todo"][0]
    assert rows["ssh_hosts"]["fix"] == {"window": "terminal", "host_id": host.id}
    assert rows["webhook:proxmox"]["state"] == "half" and "nog niets ontvangen" in rows["webhook:proxmox"]["todo"][0]

    # Twee tokens met alle rechten: in orde.
    def handler2(req: httpx.Request):
        if req.url.path == "/api2/json/access/permissions":
            if "acties@pve" in req.headers["authorization"]:
                return httpx.Response(200, json={"data": {"/vms": {"VM.PowerMgmt": 1, "VM.Snapshot": 1,
                                                                   "VM.Snapshot.Rollback": 1}, "/nodes": {"Sys.Modify": 1}}})
            return httpx.Response(200, json={"data": {"/": {"Sys.Audit": 1, "VM.Audit": 1, "Datastore.Audit": 1}}})
        return httpx.Response(200, json={"data": []})
    monkeypatch.setattr(integrations_router, "clients", HttpClients(httpx.MockTransport(handler2)))
    r = await authed.patch(f"/api/services/{ids['pve']}", json={
        "group_id": (await _group(authed, ids["pve"])), "name": "pve", "url": "https://pve.lan", "type": "proxmox",
        "secrets": {"action_username": "acties@pve!a", "action_password": "b"}})
    assert r.status_code == 200, r.text
    rows = {x["key"]: x for g in (await authed.get("/api/attention/setup")).json()["groups"] for x in g["rows"]}
    assert rows["proxmox"]["state"] == "ok", rows["proxmox"]


async def _group(c, sid: int) -> int:
    agen, db = await _db()
    gid = (await db.get(Service, sid)).group_id
    await agen.aclose()
    return gid
