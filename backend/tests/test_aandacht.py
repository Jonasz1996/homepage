"""Aandacht-overzicht (alles wat nu mis is) en de instellingen-checklist."""

from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app import attention
from app.config import get_settings
from app.db import get_db
from app.health import selfcheck as sc
from app.main import app
from app.models import (AppState, CheckResult, CronJob, Device, HealRule, MaintenanceWindow, Service, ServiceState,
                        SshHost, UpdateRun, WebhookSource)
from app.monitoring import rollup
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
    # Een nieuwe installatie: daarnaast alleen het voorstel voor een kopie buiten de container.
    assert [i["key"] for i in r["items"]] == ["worker", "offsite-voorstel"]
    assert r["items"][0]["level"] == "err" and r["counts"] == {"err": 1, "warn": 1, "info": 0}
    assert r["items"][0]["fix"] == {"window": "health", "tab": "homepage"}


async def test_syslog_ontvanger_onder_aandacht(authed):
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    _state(db, sc.HEARTBEAT_KEY, {"at": now.isoformat(), "started": now.isoformat()})
    _state(db, "syslog", {
        "at": (now - timedelta(minutes=12)).isoformat(), "started": (now - timedelta(days=1)).isoformat(),
        "received": 9000, "stored": 7766, "lost": 1234, "backlog": 0, "down_since": None,
        "last_error": {"since": (now - timedelta(hours=2)).isoformat(), "until": (now - timedelta(hours=1)).isoformat(),
                       "error": "ConnectionRefusedError: [Errno 111] Connect call failed"},
        "loss": {"since": (now - timedelta(hours=2)).isoformat(), "at": (now - timedelta(hours=1)).isoformat(),
                 "n": 1234, "why": "vol"}})
    await db.commit()
    r = (await authed.get("/api/attention")).json()
    by = {i["key"]: i for i in r["items"]}
    down = by["syslog"]
    assert (down["level"], down["area"], down["title"]) == ("warn", "homepage", "De syslog-ontvanger draait niet")
    assert down["text"].startswith("Laatste teken van leven 12 min geleden.") and "homepage-syslog" in down["text"]
    loss = by["syslog:verlies"]
    assert (loss["level"], loss["title"]) == ("warn", "1.234 logregels niet bewaard")
    assert "50.000 regels" in loss["text"] and "UDP" in loss["text"] and "ConnectionRefusedError" in loss["text"]
    assert loss["fix"] == down["fix"] == {"window": "health", "tab": "homepage"}
    assert r["counts"]["err"] == 0
    # Ook in Gezondheid › homepage.
    h = (await authed.get("/api/health")).json()["syslog"]
    assert h["ok"] is False and h["loss"]["n"] == 1234 and "12 min" in h["why"]

    # Draait weer, en het verlies is meer dan een dag oud: niets meer onder Aandacht.
    st = await db.get(AppState, "syslog")
    st.value = {**st.value, "at": now.isoformat(), "loss": {**st.value["loss"], "n": 1,
                                                             "at": (now - timedelta(hours=25)).isoformat()}}
    await db.commit()
    keys = [i["key"] for i in (await authed.get("/api/attention")).json()["items"]]
    assert not [k for k in keys if k.startswith("syslog")]
    h = (await authed.get("/api/health")).json()["syslog"]
    assert h["ok"] is True and h["loss"] is None and h["lost"] == 1234
    await agen.aclose()


async def test_kopie_buiten_de_container_voorgesteld(authed):
    async def voorstel():
        r = (await authed.get("/api/attention")).json()
        return next((i for i in r["items"] + r["ignored"] if i["key"] == "offsite-voorstel"), None)

    # Nergens een kopie van secret.key: oranje, met wat een back-up van de CT in PBS al doet.
    v = await voorstel()
    assert v["level"] == "warn" and v["title"] == "Back-up van het dashboard staat alleen in de container"
    assert "secret.key" in v["text"] and "PBS" in v["text"] and "negeren" in v["text"]
    assert str(get_settings().offsite_dir) in v["text"]
    assert v["fix"] == {"window": "health", "tab": "homepage"}
    # Negeren blijft tot het niveau verandert.
    r = (await authed.put("/api/attention/ignore", json={"key": v["key"], "sig": v["sig"]})).json()
    assert "offsite-voorstel" in {i["key"] for i in r["ignored"]}
    # Een kopie van de sleutel bevestigd: nog ter info (telt niet mee in de knop), en weer zichtbaar.
    assert (await authed.post("/api/security/secret-key-saved")).status_code == 200
    r = (await authed.get("/api/attention")).json()
    v = next(i for i in r["items"] if i["key"] == "offsite-voorstel")
    assert v["level"] == "info" and "onleesbaar" not in v["text"] and r["counts"]["warn"] == 0
    # Kopie buiten de container aan: geen voorstel meer.
    r = await authed.put("/api/health/settings", json={"cpu_warn": 85, "disk_warn": 55, "snapshot_days": 14,
                                                      "offsite": True})
    assert r.status_code == 200
    assert await voorstel() is None


async def test_zelfcontrole_van_de_back_up(authed):
    now = datetime.now(timezone.utc).replace(microsecond=0)
    agen, db = await _db()
    _state(db, sc.HEARTBEAT_KEY, {"at": NOW.isoformat(), "started": NOW.isoformat()})
    _state(db, sc.STATE_KEY, {
        "verified": {"name": "homepage-2026-10-04.dump", "ok": False, "why": "pg_restore: input file is too short"},
        "restore": {"status": "fout", "at": now.isoformat(), "dump": "homepage-2026-10-01.dump",
                    "why": "pg_restore: COPY failed for table \"users\": ERROR:  kapot", "last_ok": None},
        "offsite": {"enabled": True, "key": True, "key_stale": True, "dir": "/mnt/homepage-backup", "error": None}})
    await db.commit()

    async def items():
        return {i["key"]: i for i in (await authed.get("/api/attention")).json()["items"]}

    by = await items()
    # Onleesbaar: met de reden erbij (vroeger bleef de tekst leeg).
    assert by["selfverify"]["text"] == "pg_restore: input file is too short"
    assert by["selfrestore"]["level"] == "err"
    assert by["selfrestore"]["title"] == "De back-up van het dashboard lukt niet terug te zetten"
    assert 'COPY failed for table "users"' in by["selfrestore"]["text"]
    assert "systemctl start homepage-backuptest" in by["selfrestore"]["text"]
    assert by["offsite-sleutel"]["level"] == "err" and "wachtzin opnieuw" in by["offsite-sleutel"]["text"]

    async def restore(r):
        st = await db.get(AppState, sc.STATE_KEY, populate_existing=True)
        st.value = {**st.value, "restore": r}
        await db.commit()
        return (await items()).get("selfrestore")

    # Gelukt, een week geleden: niets.
    week = (now - timedelta(days=7)).isoformat()
    assert await restore({"status": "ok", "at": week, "last_ok": week}) is None
    # Overgeslagen (te weinig plaats), maar de laatste geslaagde test is recent: oranje, met de reden.
    i = await restore({"status": "overgeslagen", "at": now.isoformat(), "why": "te weinig plaats", "last_ok": week})
    assert i["level"] == "warn" and i["text"] == "te weinig plaats"
    # De laatste geslaagde test is 45 dagen oud (de timer loopt niet).
    old = (now - timedelta(days=45)).isoformat()
    i = await restore({"status": "ok", "at": old, "last_ok": old})
    assert i["level"] == "warn" and "al 45 dagen niet op een testdatabase teruggezet" in i["title"]
    assert "systemctl start homepage-backuptest" in i["text"]
    i2 = await restore({"status": "overgeslagen", "at": now.isoformat(), "why": "te weinig plaats", "last_ok": old})
    assert i2["sig"] == i["sig"] and "overgeslagen: te weinig plaats" in i2["text"]
    # Nog nooit getest: pas na 40 dagen een punt.
    assert await restore({"status": None, "missing_since": (now - timedelta(days=10)).isoformat()}) is None
    i = await restore({"status": None, "missing_since": (now - timedelta(days=41)).isoformat()})
    assert i["level"] == "warn" and "41 dagen" in i["title"]
    await agen.aclose()


async def _seed(authed) -> dict[str, int]:
    http = {"check": {"type": "http"}}
    ids = await _tiles(authed, ("pve2", "link", http), ("plex", "link", http), ("nas", "link", http),
                       ("wiki", "link", http), ("git", "link", http), ("pbs-pi", "proxmoxbackupserver", {}),
                       ("pve", "proxmox", {}),
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


async def test_uurtotalen_die_achterlopen(authed):
    """Telt de worker de checks niet meer per uur op, dan zegt ! het (met TimescaleDB gaan losse checks na 90 dagen
    toch weg, ook als ze nog niet opgeteld zijn)."""
    ids = await _tiles(authed, ("nas", "link", {"check": {"type": "http"}}))
    agen, db = await _db()
    _state(db, sc.HEARTBEAT_KEY, {"at": NOW.isoformat(), "started": NOW.isoformat()})
    _state(db, rollup.KEY, {"until": (rollup.floor_hour(NOW) - timedelta(hours=1)).isoformat()})
    await db.commit()

    async def items() -> dict:
        return {i["key"]: i for i in (await authed.get("/api/attention")).json()["items"]}

    assert "uurtotalen" not in await items()  # gewoon bij
    st = await db.get(AppState, rollup.KEY)
    st.value = {"until": (rollup.floor_hour(NOW) - timedelta(days=3)).isoformat()}
    await db.commit()
    it = (await items())["uurtotalen"]
    assert it["level"] == "warn" and it["title"] == "De worker telt de checks al 3 dagen niet meer per uur op"
    assert "verdwijnen over 87 dagen de eerste checks voor goed" in it["text"]
    assert it["fix"] == {"window": "health", "tab": "homepage"}

    # Nog nooit opgeteld, terwijl er al dagen checks zijn: ook.
    await db.delete(st)
    db.add(CheckResult(service_id=ids["nas"], ts=NOW - timedelta(days=2), ok=True, maintenance=False))
    await db.commit()
    assert (await items())["uurtotalen"]["title"] == "De worker telt de checks niet per uur op"

    # Draait de worker niet, dan zegt dat punt genoeg.
    hb = await db.get(AppState, sc.HEARTBEAT_KEY)
    hb.value = {"at": (NOW - timedelta(hours=1)).isoformat(), "started": NOW.isoformat()}
    await db.commit()
    got = await items()
    assert "worker" in got and "uurtotalen" not in got
    await agen.aclose()


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


async def test_checklist_proef_staat_op_half(authed):
    """Opruimen als proef (de snapshots blijven staan en nemen plaats in) en zelfherstelregels op alleen proef (ze
    herstarten niets): in de checklist half, met wat er te doen is."""
    ids = await _tiles(authed, ("plex", "link", {}), ("nas", "link", {}))
    rows = {x["key"]: x for g in (await authed.get("/api/attention/setup")).json()["groups"] for x in g["rows"]}
    assert rows["autoupdates"]["state"] == "none" and "zelfherstel" not in rows

    agen, db = await _db()
    _state(db, "update_settings", {"auto": True, "hour": 4, "keep_days": 7, "cleanup_proef": True})
    action = {"kind": "ssh", "host_id": 1, "op": "systemctl", "name": "x"}
    db.add_all([HealRule(service_id=ids["nas"], action=action, dry_run=False),
                HealRule(service_id=ids["plex"], action=action, dry_run=True)])
    await db.commit()
    rows = {x["key"]: x for g in (await authed.get("/api/attention/setup")).json()["groups"] for x in g["rows"]}
    up = rows["autoupdates"]
    assert up["state"] == "half" and up["text"] == "Aan, om 04:00, met een snapshot vooraf."
    assert any("opruimen staat op alleen proef" in t for t in up["todo"])
    heal = rows["zelfherstel"]
    assert heal["state"] == "half" and heal["group"] == "ssh" and heal["optional"]
    assert heal["text"].startswith("1 regel staat op alleen proef")
    assert heal["fix"] == {"window": "detail", "service_id": ids["plex"]}

    # Ook samen met de proef van de nachtelijke run zelf.
    st = await db.get(AppState, "update_settings")
    st.value = {**st.value, "proef": True}
    await db.commit()
    rows = {x["key"]: x for g in (await authed.get("/api/attention/setup")).json()["groups"] for x in g["rows"]}
    assert rows["autoupdates"]["state"] == "half" and len(rows["autoupdates"]["todo"]) == 2
    await agen.aclose()


async def test_checklist_dashboard_alleen_via_npm(authed, monkeypatch, tmp_path):
    """Wat nginx rechtstreeks toelaat (install.sh schrijft het in /etc/homepage/nginx): alleen NPM is in orde, het
    hele LAN (HOMEPAGE_LAN_OPEN=1, of het IP van NPM was niet opgegeven) is half, zonder bestand onbekend."""
    from app.config import get_settings
    f = tmp_path / "nginx"
    monkeypatch.setattr(get_settings(), "nginx_file", f)

    async def lan() -> dict:
        r = (await authed.get("/api/attention/setup")).json()
        return next(x for g in r["groups"] if g["key"] == "beveiliging" for x in g["rows"] if x["key"] == "lan")

    row = await lan()
    assert row["state"] == "none" and "install.sh" in row["todo"][0]

    f.write_text("lan=dicht\nreden=\nnpm=192.168.0.245\ndatum=2026-10-11T10:00:00+02:00\n")
    row = await lan()
    assert row["state"] == "ok" and "NPM (192.168.0.245)" in row["text"] and not row["todo"], row

    f.write_text("lan=open\nreden=lan-open\nnpm=192.168.0.245\n")
    row = await lan()
    assert row["state"] == "half" and "onversleuteld" in row["text"]
    assert "HOMEPAGE_LAN_OPEN=1 staat in /etc/homepage/homepage.env" in row["todo"][0]

    f.write_text("lan=open\nreden=npm-onbekend\nnpm=192.168.0.245\n")
    row = await lan()
    assert row["state"] == "half" and "HOMEPAGE_NPM_IP=192.168.0.245" in row["todo"][0]
    assert "HOMEPAGE_LAN_OPEN=0" in row["todo"][0]


async def _group(c, sid: int) -> int:
    agen, db = await _db()
    gid = (await db.get(Service, sid)).group_id
    await agen.aclose()
    return gid
