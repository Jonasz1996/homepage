import json
import os
import time
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import asyncssh
import httpx
from sqlalchemy import select

from app.db import get_db
from app.health import domains as dom, probe, scan as hw, selfcheck as sc, snapshots as snap
from app.main import app
from app.models import AppState, Notification, Reading, SshHost
from app.monitoring.checks import HttpClients

from .test_integrations import PVE, _group, _svc


def _smart_ata(serial, realloc=0, pending=0, temp=35, passed=True):
    return {"model_name": "WDC WD40EFRX", "serial_number": serial, "user_capacity": {"bytes": 4_000_000_000_000},
            "rotation_rate": 5400, "device": {"protocol": "ATA"}, "smart_status": {"passed": passed},
            "power_on_time": {"hours": 31000}, "temperature": {"current": temp},
            "ata_smart_attributes": {"table": [
                {"id": 5, "value": 100, "raw": {"value": realloc}},
                {"id": 197, "value": 100, "raw": {"value": pending}},
                {"id": 199, "value": 200, "raw": {"value": 0}},
                {"id": 194, "value": 115, "raw": {"value": 0x2300000023}}]}}


def _smart_nvme(used=12):
    return {"model_name": "Samsung SSD 980", "serial_number": "S64", "device": {"protocol": "NVMe"},
            "smart_status": {"passed": True}, "power_on_time": {"hours": 9000}, "temperature": {"current": 41},
            "nvme_smart_health_information_log": {"percentage_used": used, "media_errors": 0, "available_spare": 100,
                                                  "critical_warning": 0, "temperature": 41}}


def node_text(realloc=0, pending=0, cpu_milli=52000, used=12, scrub="Sun Sep 14 00:24:01 2026", health="ONLINE"):
    lsblk = {"blockdevices": [
        {"name": "sda", "model": "WDC WD40EFRX", "serial": "WD-1", "size": 4_000_000_000_000, "rota": True},
        {"name": "sdb", "model": "ST2000", "serial": "ZFL", "size": 2_000_000_000_000, "rota": True},
        {"name": "nvme0n1", "model": "Samsung SSD 980", "serial": "S64", "size": 1_000_000_000_000, "rota": False}]}
    standby = {"smartctl": {"messages": [{"string": "Device is in STANDBY mode, exit(2)", "severity": "error"}]},
               "device": {"protocol": "ATA"}}
    return "\n".join([
        "@@VIRT none", "@@MODEL |HP EliteDesk 800 G3", "@@LSBLK", json.dumps(lsblk),
        "@@SMART sda", json.dumps(_smart_ata("WD-1", realloc, pending)),
        "@@SMART sdb", json.dumps(standby),
        "@@SMART nvme0n1", json.dumps(_smart_nvme(used)),
        "@@ZLIST", f"rpool\t1000\t600\t400\t{health}\t12\t60",
        "@@ZSTATUS", "  pool: rpool", f" state: {health}",
        f"  scan: scrub repaired 0B in 00:10:12 with 0 errors on {scrub}", "errors: No known data errors",
        "@@TEMPS", "zone|acpitz|27800", "zone|x86_pkg_temp|51000",
        f"hwmon|coretemp|Package id 0|{cpu_milli}", "hwmon|coretemp|Core 0|50000", "hwmon|nvme|Composite|41850",
        "@@THROTTLE", ""])


PI_TEXT = "\n".join(["@@VIRT none", "@@MODEL Raspberry Pi 5 Model B Rev 1.0|", "@@LSBLK",
                     json.dumps({"blockdevices": []}), "@@NOSMART", "@@TEMPS", "zone|cpu-thermal|61250",
                     "@@THROTTLE", "50005"])


def test_parse_disks_pools_temps_and_throttle():
    m = probe.parse(node_text(realloc=8))
    sda, sdb, nv = m["disks"]
    assert (sda["serial"], sda["realloc"], sda["ssd"], sda["temp"], sda["hours"]) == ("WD-1", 8, False, 35, 31000)
    assert probe.disk_level(sda) == ("warn", ["8 sectoren vervangen"])
    # Slapende schijf: niet gewekt, gegevens uit lsblk, geen fout.
    assert sdb["standby"] and sdb["serial"] == "ZFL" and probe.disk_level(sdb)[0] == "ok"
    assert nv["ssd"] and nv["wear_used"] == 12 and probe.disk_level(nv) == ("ok", [])
    assert probe.disk_level({**nv, "wear_used": 91})[0] == "warn"
    assert probe.disk_level(probe.smart("sdc", _smart_ata("X", pending=3)))[1] == ["3 sectoren wachten op herallocatie"]
    assert m["cpu_temp"] == 52.0 and m["model"] == "HP EliteDesk 800 G3"
    pool = m["pools"][0]
    assert (pool["name"], pool["cap"], pool["scrub_errors"]) == ("rpool", 60, 0)
    assert probe.pool_level(pool, datetime(2026, 9, 20)) == ("ok", [])
    assert probe.pool_level(pool, datetime(2026, 11, 1))[1] == ["laatste scrub 47 dagen geleden"]
    assert probe.pool_level({**pool, "health": "DEGRADED"}, datetime(2026, 9, 20))[0] == "err"

    pi = probe.parse(PI_TEXT)
    assert pi["model"] == "Raspberry Pi 5 Model B Rev 1.0" and not pi["smartctl"] and pi["cpu_temp"] == 61.25
    assert pi["throttle"]["now"] == ["te lage spanning", "vertraagd (throttling)"]
    assert pi["throttle"]["since_boot"] == ["te lage spanning", "vertraagd (throttling)"]


class FakeNode:
    def __init__(self, text):
        self.text = text
        self.key = asyncssh.generate_private_key("ssh-ed25519")

    async def handle(self, proc):
        if "@@VIRT" in (proc.command or ""):
            proc.stdout.write(self.text())
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


async def _host(authed, name, port, key):
    hid = (await authed.post("/api/ssh/hosts", json={"name": name, "host": "127.0.0.1", "port": port,
                                                     "password": "pw"})).json()["id"]
    agen, db = await _db()
    h = await db.get(SshHost, hid)
    h.host_key = key.export_public_key().decode()
    await db.commit()
    return hid


async def _titles(db):
    stmt = select(Notification).where(Notification.source != "auth").order_by(Notification.id)
    return [n.title for n in (await db.execute(stmt)).scalars()]


async def test_hardware_scan_alerts_and_api(authed):
    st = {"realloc": 0, "cpu": 52000}
    node = FakeNode(lambda: node_text(realloc=st["realloc"], cpu_milli=st["cpu"]))
    pi = FakeNode(lambda: PI_TEXT)
    hid = await _host(authed, "pve50", await node.start(), node.key)
    await _host(authed, "pi5", await pi.start(), pi.key)
    agen, db = await _db()
    v = await hw.run_health(db)
    await db.commit()
    assert [h["name"] for h in v["hosts"]] == ["pve50", "pi5"]
    assert v["hosts"][0]["level"] == "ok" and v["hosts"][1]["level"] == "warn"
    # Eerste ronde: alleen wat nu al mis is (throttling op de Pi).
    assert await _titles(db) == ["pi5: te lage spanning, vertraagd (throttling)"]

    st.update(realloc=8, cpu=91000)
    await hw.run_health(db)
    await db.commit()
    titles = await _titles(db)
    assert "pve50: schijf WDC WD40EFRX (sda) gaat achteruit" in titles
    assert "pve50: processor is 91 °C" in titles and len(titles) == 3
    # Nog eens: niets nieuws.
    await hw.run_health(db)
    await db.commit()
    assert len(await _titles(db)) == 3
    temps = (await db.execute(select(Reading).where(Reading.target == f"ssh:{hid}"))).scalars().all()
    assert {r.sensor for r in temps} == {"cpu", "disk:WD-1", "disk:S64"}

    data = (await authed.get("/api/health")).json()
    assert data["summary"]["hosts"] == 2 and data["summary"]["hot"] == ["pve50"]
    assert data["summary"]["warn"] >= 2 and data["hardware"]["hosts"][0]["disks"][1]["standby"]
    series = (await authed.get(f"/api/health/temps?hours=1&target=ssh:{hid}")).json()["series"]
    cpu = next(s for s in series if s["sensor"] == "cpu")
    assert cpu["points"][-1][1] == 91.0
    tl = (await authed.get("/api/timeline?kind=gezondheid")).json()["items"]
    assert any("processor" in i["title"] for i in tl)


def _pve_with_snapshots(now):
    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p == "/api2/json/cluster/resources":
            return httpx.Response(200, json=PVE)
        if p == "/api2/json/nodes/pve50/qemu/100/snapshot":
            return httpx.Response(200, json={"data": [
                {"name": "voor-update", "snaptime": int(now - 40 * 86400), "description": "opnsense 25.1\n"},
                {"name": "gisteren", "snaptime": int(now - 86400), "parent": "voor-update"},
                {"name": "current", "parent": "gisteren", "running": 1}]})
        if p == "/api2/json/nodes/pve50/lxc/101/snapshot":
            return httpx.Response(200, json={"data": [{"name": "current"}]})
        if req.method == "DELETE" and p == "/api2/json/nodes/pve50/qemu/100/snapshot/voor-update":
            return httpx.Response(200, json={"data": "UPID:pve50:del"})
        return httpx.Response(404)
    return handler


async def test_forgotten_snapshots_and_delete(authed, monkeypatch):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"}, name="PVE")
    http = HttpClients(httpx.MockTransport(_pve_with_snapshots(time.time())))
    agen, db = await _db()
    v = await snap.run_snapshots(db, http, 14)
    await db.commit()
    assert [(s["name"], s["guest"], int(s["age_days"])) for s in v["items"]] == [
        ("voor-update", "opnsense", 40), ("gisteren", "opnsense", 1)]
    assert v["items"][0]["description"] == "opnsense 25.1"
    assert await _titles(db) == ["1 snapshot ouder dan 14 dagen"]
    await snap.run_snapshots(db, http, 14)
    await db.commit()
    assert len(await _titles(db)) == 1  # niet elke 6 uur opnieuw

    from app.routers import health as router
    monkeypatch.setattr(router, "clients", http)
    ref = {"service_id": sid, "node": "pve50", "type": "qemu", "vmid": 100, "name": "voor-update"}
    r = await authed.post("/api/health/snapshots/delete", json=ref)
    assert r.status_code == 200 and r.json()["task"] == "UPID:pve50:del"
    data = (await authed.get("/api/health")).json()
    assert [s["name"] for s in data["snapshots"]["items"]] == ["gisteren"]
    bad = await authed.post("/api/health/snapshots/delete", json={**ref, "name": "x;rm"})
    assert bad.status_code == 502
    audit = (await authed.get("/api/auth/audit?action=snapshot_delete")).json()["items"]
    assert audit[0]["detail"]["name"] == "voor-update"


RDAP_COM = {"objectClassName": "domain", "ldhName": "VOORBEELD.COM",
            "events": [{"eventAction": "registration", "eventDate": "2015-03-01T10:00:00Z"},
                       {"eventAction": "expiration", "eventDate": "EXP"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                                                           ["fn", {}, "text", "Cloudflare, Inc."]]]}],
            "status": ["client transfer prohibited"],
            "nameservers": [{"ldhName": "ADA.NS.CLOUDFLARE.COM"}, {"ldhName": "bob.ns.cloudflare.com"}]}


async def test_domains_rdap_manual_date_and_alerts(authed):
    soon = (date.today() + timedelta(days=20)).isoformat()
    ns = {"list": RDAP_COM["nameservers"]}

    def handler(req: httpx.Request) -> httpx.Response:
        name = req.url.path.rsplit("/", 1)[-1]
        if name == "voorbeeld.com":
            return httpx.Response(200, json={**json.loads(json.dumps(RDAP_COM).replace("EXP", soon + "T00:00:00Z")),
                                             "nameservers": ns["list"]})
        if name == "jbogaert.be":
            return httpx.Response(200, json={"ldhName": "jbogaert.be", "events": [], "nameservers": []})
        return httpx.Response(404)

    http = HttpClients(httpx.MockTransport(handler))
    assert dom.clean("https://JBOGAERT.be/x") == "jbogaert.be" and dom.clean("geen domein") is None
    r = await authed.put("/api/health/settings", json={"cpu_warn": 85, "disk_warn": 55, "snapshot_days": 14,
                                                       "domains": [{"name": "voorbeeld.com"},
                                                                   {"name": "jbogaert.be", "expires": "2027-02-01"},
                                                                   {"name": "bestaat-niet.org"}]})
    assert r.status_code == 200, r.text
    cfg = r.json()
    agen, db = await _db()
    v = await dom.run_domains(db, http, cfg["domains"])
    await db.commit()
    com, be, gone = v["items"]
    assert (com["expires"], com["source"], com["registrar"], com["days_left"]) == (soon, "rdap", "Cloudflare, Inc.", 20)
    assert com["nameservers"] == ["ada.ns.cloudflare.com", "bob.ns.cloudflare.com"]
    assert (be["expires"], be["source"]) == ("2027-02-01", "manueel")
    assert "kent dit domein niet" in gone["error"]
    assert await _titles(db) == ["Domein voorbeeld.com verloopt over 20 dagen"]
    ns["list"] = [{"ldhName": "ns1.kaper.example"}]
    await dom.run_domains(db, http, cfg["domains"])
    await db.commit()
    assert await _titles(db) == ["Domein voorbeeld.com verloopt over 20 dagen", "Nameservers van voorbeeld.com gewijzigd"]
    bad = await authed.put("/api/health/settings", json={**cfg, "domains": [{"name": "x", "expires": None}]})
    assert bad.status_code == 422


def test_key_encryption_round_trip():
    blob = sc.encrypt_key(b"geheime-sleutel", "een lange wachtzin", n=2 ** 12)
    assert sc.decrypt_key(blob, "een lange wachtzin") == b"geheime-sleutel"
    try:
        sc.decrypt_key(blob, "verkeerd")
    except Exception:
        pass
    else:
        raise AssertionError("verkeerde wachtzin mag niet lukken")


async def test_selfcheck_backup_offsite_and_worker(authed, tmp_path, monkeypatch):
    from app.config import get_settings
    src, dst = tmp_path / "backups", tmp_path / "offsite"
    src.mkdir()
    s = get_settings()
    monkeypatch.setattr(s, "backup_dir", src)
    monkeypatch.setattr(s, "offsite_dir", dst)
    agen, db = await _db()

    # Geen dump, geen worker: allebei gemeld.
    v = await sc.run_selfcheck(db, offsite_on=True)
    await db.commit()
    assert v["stale"] and "bestaat niet" in v["offsite"]["error"]
    assert await _titles(db) == ["Geen recente back-up van de homepage", "Kopie van de back-up buiten de container mislukt"]

    (src / "homepage-2026-10-03.dump").write_bytes(b"PGDMP-oud")
    old = time.time() - 3 * 86400
    os.utime(src / "homepage-2026-10-03.dump", (old, old))
    (src / "homepage-2026-10-04.dump").write_bytes(b"PGDMP" + b"x" * 100)
    dst.mkdir()
    r = await authed.put("/api/health/offsite-key", json={"passphrase": "kort"})
    assert r.status_code == 422
    r = await authed.put("/api/health/offsite-key", json={"passphrase": "een lange wachtzin"})
    assert r.status_code == 200 and r.json()["set"]
    v = await sc.run_selfcheck(db, offsite_on=True)
    await db.commit()
    assert not v["stale"] and v["backups"][0]["name"] == "homepage-2026-10-04.dump"
    assert v["offsite"]["error"] is None and v["offsite"]["count"] == 2 and v["offsite"]["key"]
    blob = json.loads((dst / "secret.key.enc").read_text())
    assert sc.decrypt_key(blob, "een lange wachtzin") == s.secret_key_file.read_bytes()
    assert "pg_restore" in (dst / "LEESMIJ.txt").read_text()
    # Een kapotte dump valt op als pg_restore er is (anders: onbekend, geen melding).
    assert v["verified"]["name"] == "homepage-2026-10-04.dump"
    assert v["verified"]["ok"] in (False, None)
    assert v["db"]["total"] is None or v["db"]["total"] > 0

    # Worker: nog nooit gemeld → niet "dood" melden; daarna stil → één melding, en weer terug.
    data = (await authed.get("/api/health/summary")).json()
    assert "worker draait niet" in data["problems"]
    await sc.heartbeat(db, datetime.now(timezone.utc))
    await db.commit()
    assert "worker draait niet" not in (await authed.get("/api/health/summary")).json()["problems"]
    hb = await db.get(AppState, sc.HEARTBEAT_KEY)
    hb.value = {**hb.value, "at": (datetime.now(timezone.utc) - timedelta(minutes=9)).isoformat()}
    await db.commit()
    await authed.get("/api/health/summary")
    await authed.get("/api/health/summary")
    agen2, db2 = await _db()
    titles = await _titles(db2)
    assert titles.count("De worker van de homepage draait niet") == 1


async def test_settings_and_scan_endpoints(authed):
    r = await authed.get("/api/health")
    assert r.status_code == 200
    d = r.json()
    assert d["settings"]["snapshot_days"] == 14 and not d["offsite_key"]["set"]
    assert (await authed.post("/api/health/scan/onbekend")).status_code == 404
    assert (await authed.put("/api/health/settings", json={"cpu_warn": 20, "disk_warn": 55, "snapshot_days": 14})
            ).status_code == 422
    assert Path(d["offsite_dir"]).name == "homepage-backup"
