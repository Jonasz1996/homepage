"""Stap 3 van het verbeterplan: versies en QDevice in de cluster, back-updekking per VM/CT en een PBS-sync."""

import time

import httpx
from sqlalchemy import select

from app import setupcheck
from app.models import AppState, AuditLog, Notification, SshHost
from app.monitoring import cluster, coverage, pbssync
from app.monitoring.checks import HttpClients
from app.routers import backups

from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db, _notes

PX = {"username": "a@pve!b", "password": "c"}
PB = {"username": "a@pbs!b", "password": "c"}
FP = ":".join(["AB"] * 32)


class Cluster4:
    """Vier nodes, waarvan één al op 8.3 en één met een nieuwere patch; nog geen QDevice."""

    def __init__(self):
        self.versions = {"pve50": "8.2.4", "pve51": "8.2.4", "pve52": "8.3.1", "pi": "8.2.7"}
        self.qdevice = {}

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path.removeprefix("/api2/json")
        if p == "/cluster/status":
            return httpx.Response(200, json={"data": [{"type": "cluster", "name": "thuis", "quorate": 1, "nodes": 4}] + [
                {"type": "node", "name": n, "online": 1, "nodeid": i} for i, n in enumerate(self.versions, 1)]})
        if p == "/cluster/config/nodes":
            return httpx.Response(200, json={"data": [{"node": n, "quorum_votes": "1"} for n in self.versions]})
        if p == "/cluster/config/qdevice":
            return httpx.Response(200, json={"data": self.qdevice})
        if p.endswith("/version"):
            return httpx.Response(200, json={"data": {"version": self.versions[p.split("/")[2]], "release": "8"}})
        if p == "/cluster/ha/status/current" or p.endswith("/replication"):
            return httpx.Response(200, json={"data": []})
        return httpx.Response(404)


async def test_cluster_versies_en_qdevice(authed):
    world = Cluster4()
    http = HttpClients(httpx.MockTransport(world))
    await _svc(authed, await _group(authed), "proxmox", "https://192.168.0.50:8006", secrets=PX, name="pve50")
    agen, db = await _db()
    v = await cluster.run_cluster(db, http)
    await db.commit()
    c = v["items"][0]
    assert [n["version"] for n in c["nodes"]] == ["8.2.7", "8.2.4", "8.2.4", "8.3.1"] and c["qdevice"] == {}
    assert v["alerts"]["thuis|version:mix"]["level"] == "warn"
    assert "pve52 8.3.1" in v["alerts"]["thuis|version:mix"]["text"]
    # Vier stemmen zonder QDevice: een tip in het aandacht-overzicht, geen melding.
    assert v["alerts"]["thuis|qdevice:none"]["level"] == "info"
    got = await _notes(db, "cluster")
    assert [lvl for _, lvl, _ in got] == ["warn"]
    rows = await setupcheck.homelab_rows(db, False)
    assert [(r["key"], r["state"]) for r in rows] == [("qdevice:thuis", "half")] and "4 stemmen" in rows[0]["text"]
    att = (await authed.get("/api/attention")).json()
    tip = next(i for i in att["items"] if i["key"] == "cluster:thuis|qdevice:none")
    assert tip["level"] == "info" and "4 stemmen" in tip["title"] and tip["fix"]["tab"] == "cluster"
    assert (await authed.get("/api/health/summary")).json()["cluster"]["warn"] == 1

    # Alles op 8.3, alleen de patch verschilt nog; de QDevice staat er maar is niet verbonden.
    world.versions = {"pve50": "8.3.1", "pve51": "8.3.1", "pve52": "8.3.2", "pi": "8.3.1"}
    world.qdevice = {"QNetd host": "192.168.0.80:5403", "State": "Connect failed", "Algorithm": "Fifty-Fifty split"}
    v = await cluster.run_cluster(db, http)
    await db.commit()
    assert set(v["alerts"]) == {"thuis|version:patch", "thuis|qdevice:state"}
    world.qdevice = {**world.qdevice, "State": "Connected"}
    v = await cluster.run_cluster(db, http)
    await db.commit()
    assert set(v["alerts"]) == {"thuis|version:patch"}
    assert [r["state"] for r in await setupcheck.homelab_rows(db, False)] == ["ok"]
    got = [(t, lvl) for t, lvl, _ in await _notes(db, "cluster")]
    assert ("Alle nodes van cluster thuis draaien weer dezelfde Proxmox-versie", "ok") in got
    assert ("QDevice van cluster thuis is weer verbonden", "ok") in got
    assert len(got) == 4
    r = (await authed.get("/api/cluster")).json()
    assert r["items"][0]["qdevice"]["state"] == "Connected" and r["qnetd"] == []


class Lab:
    """Een cluster met twee back-upjobs naar de PBS-VM, en een PBS op de Pi die (nog) bijna niets heeft."""

    def __init__(self):
        now = int(time.time())
        self.guests = [
            {"type": "lxc", "vmid": 100, "name": "plex", "node": "pve50", "status": "running"},
            {"type": "qemu", "vmid": 101, "name": "homeassistant", "node": "pve51", "status": "running"},
            {"type": "lxc", "vmid": 102, "name": "test", "node": "pve50", "status": "running"},
            {"type": "lxc", "vmid": 103, "name": "oud", "node": "pve50", "status": "stopped"},
            {"type": "lxc", "vmid": 104, "name": "sonarr", "node": "pve51", "status": "running", "pool": "media"},
            {"type": "qemu", "vmid": 9000, "name": "debian-sjabloon", "node": "pve50", "template": 1},
        ]
        self.pbs = {
            "192.168.0.70": {"store": "backup", "used": 400e9, "total": 2e12, "avail": 1.6e12, "ns": None, "groups": {
                "": [("ct", "100", now - 3600), ("vm", "101", now - 7200), ("ct", "102", now - 40 * 86400)]}},
            "192.168.0.80": {"store": "pi", "used": 50e9, "total": 1e12, "avail": 950e9, "ns": ["", "kopie"], "groups": {
                "": [], "kopie": [("ct", "100", now - 5 * 3600)]}},
        }
        self.syncs = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        host, p = req.url.host, req.url.path.removeprefix("/api2/json")
        ok = lambda d: httpx.Response(200, json={"data": d})  # noqa: E731
        if req.url.port == 8006:
            if p == "/cluster/resources":
                return ok([{"type": "node", "node": n} for n in ("pve50", "pve51")]
                          + [{**g, "id": f"{g['type']}/{g['vmid']}"} for g in self.guests])
            if p == "/cluster/backup":
                return ok([{"id": "nacht", "vmid": "100,101", "storage": "pbs-vm", "schedule": "21:00"},
                           {"id": "media", "pool": "media", "storage": "pbs-vm", "schedule": "sun 02:30"},
                           {"id": "uit", "all": 1, "enabled": 0, "storage": "pbs-vm"}])
            if p == "/storage":
                return ok([{"storage": "pbs-vm", "type": "pbs", "server": "192.168.0.70", "datastore": "backup"},
                           {"storage": "local", "type": "dir"}])
            return httpx.Response(404)
        s = self.pbs[host]
        if p == "/status/datastore-usage":
            return ok([{k: s[k] for k in ("store", "used", "total", "avail")}])
        if p.endswith("/namespace"):
            return ok([{"ns": n} for n in s["ns"]]) if s["ns"] else httpx.Response(400)
        if p.endswith("/groups"):
            ns = req.url.params.get("ns", "")
            return ok([{"backup-type": t, "backup-id": i, "last-backup": at, "backup-count": 3}
                       for t, i, at in s["groups"].get(ns, [])])
        if p == "/admin/sync":
            if req.url.params.get("sync-direction"):
                return httpx.Response(400)
            return ok(self.syncs if host == "192.168.0.80" else [])
        if p == "/config/remote":
            return ok([{"name": "pbs-vm", "host": "192.168.0.70"}] if self.syncs and host == "192.168.0.80" else [])
        if p == "/nodes/localhost/certificates/info":
            return ok([{"filename": "proxy.pem", "fingerprint": FP}])
        return ok([])


async def _lab(authed):
    g = await _group(authed)
    await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", secrets=PX, name="pve50")
    vm = await _svc(authed, g, "proxmoxbackupserver", "https://192.168.0.70:8007", secrets=PB, name="PBS-VM")
    pi = await _svc(authed, g, "proxmoxbackupserver", "https://192.168.0.80:8007", secrets=PB, name="PBS-Pi")
    return vm, pi


async def test_backupdekking(authed):
    world = Lab()
    http = HttpClients(httpx.MockTransport(world))
    vm, pi = await _lab(authed)
    agen, db = await _db()
    db.add(AppState(key="restoretest", value={"history": [{"at": "2026-10-01T05:00:00+00:00", "ok": True,
                                                           "source_vmid": 100}]}))
    await db.commit()
    v = await coverage.run_coverage(db, http)
    await db.commit()
    rows = {r["vmid"]: r for r in v["clusters"][0]["rows"]}
    assert 9000 not in rows
    assert rows[100]["level"] == "ok" and rows[100]["pbs_count"] == 2 and rows[100]["jobs"] == ["nacht"]
    assert rows[100]["restore"] == {"at": "2026-10-01T05:00:00+00:00", "ok": True}
    assert {c["ns"] for c in rows[100]["copies"]} == {"", "kopie"}
    assert rows[101]["level"] == "warn" and rows[101]["why"] == "maar één kopie, op PBS-VM"
    assert rows[102]["level"] == "err" and rows[102]["why"] == "zit in geen enkele back-upjob, oude back-up blijft staan"
    assert rows[103]["level"] == "warn" and rows[103]["stopped"]
    assert rows[104]["level"] == "err" and rows[104]["jobs"] == ["media"] and rows[104]["why"] == "staat op geen enkele PBS"
    assert coverage.counts(v) == {"err": 2, "warn": 2, "ok": 1, "total": 5}

    att = (await authed.get("/api/attention")).json()["items"]
    cov = {i["key"]: i for i in att if i["key"].startswith("cov:")}
    assert set(cov) == {"cov:102", "cov:104", "cov:103", "cov:single"}
    assert cov["cov:102"]["title"] == "test (CT 102) zit in geen enkele back-upjob, oude back-up blijft staan"
    assert cov["cov:single"]["title"] == "1 VM/CT maar op één PBS" and cov["cov:single"]["fix"]["tab"] == "backups"
    assert (await authed.get("/api/health/summary")).json()["backups"]["err"] == 2

    r = (await authed.get("/api/backups")).json()
    assert r["counts"]["total"] == 5 and r["ssh"] == {str(vm): None, str(pi): None}
    s = r["sync"]
    assert s["state"] == "voorstel" and s["links"] == []
    assert s["plan"] == {"source_id": vm, "target_id": pi, "host": "192.168.0.70", "port": 8007, "src_store": "backup",
                         "dst_store": "pi", "schedule": "06:00", "fingerprint": FP}
    row = (await setupcheck.homelab_rows(db, True))[0]
    assert row["state"] == "half" and "PBS-Pi laat elke nacht om 06:00 een kopie ophalen van PBS-VM" in row["todo"][0]

    # Er staat al een sync op de Pi: geen voorstel meer, wel zichtbaar.
    world.syncs = [{"id": "vm-naar-pi", "store": "pi", "remote": "pbs-vm", "remote-store": "backup",
                    "schedule": "06:00", "last-run-state": "OK"}]
    await coverage.run_coverage(db, http)
    await db.commit()
    s = (await authed.get("/api/backups")).json()["sync"]
    assert s["state"] == "bestaat"
    row = (await setupcheck.homelab_rows(db, True))[0]
    assert row["state"] == "ok" and row["text"] == "PBS-VM → PBS-Pi (06:00)."
    assert s["links"] == [{"from": "PBS-VM", "to": "PBS-Pi", "job": "vm-naar-pi", "on": "PBS-Pi", "store": "pi",
                           "remote_store": "backup", "schedule": "06:00", "last_state": "OK", "known": True}]


def test_uur_voor_de_sync():
    assert pbssync.pick_time(["21:00", "sun 02:30"]) == "06:00"
    assert pbssync.pick_time(["05:00"]) == "07:00"
    assert pbssync.pick_time([]) == "06:00"


async def test_sync_plan_en_aanmaken(authed, monkeypatch):
    http = HttpClients(httpx.MockTransport(Lab()))
    vm, pi = await _lab(authed)
    agen, db = await _db()
    await coverage.run_coverage(db, http)
    await db.commit()
    plan = (await authed.get("/api/backups")).json()["sync"]["plan"]

    r = (await authed.post("/api/backups/sync/plan", json=plan)).json()
    assert r["level"] == "ok" and r["notes"] == ["Past: 400 GB op PBS-VM, 950 GB vrij op PBS-Pi."]
    assert r["plan"]["job"] == "pbs-vm-naar-pbs-pi" and r["plan"]["remote"] == "pbs-vm"
    src, dst = r["commands"]["source"], r["commands"]["target"]
    assert "acl update /datastore/backup DatastoreReader --auth-id 'homepage-sync@pbs!pbs-pi'" in src[3]
    assert "--host 192.168.0.70 --port 8007 --auth-id 'homepage-sync@pbs!pbs-pi'" in dst[0] and FP in dst[0]
    assert "--store pi --remote pbs-vm --remote-store backup --schedule '06:00'" in dst[1]
    assert r["ssh"] == {"source": None, "target": None}

    bad = await authed.post("/api/backups/sync/plan", json={**plan, "host": "x; rm -rf /"})
    assert bad.status_code == 422 and bad.json()["detail"] == "Geen geldig adres voor de bron"
    bad = await authed.post("/api/backups/sync/plan", json={**plan, "dst_store": "bestaat-niet"})
    assert bad.status_code == 422
    r = (await authed.post("/api/backups/sync/plan", json={**plan, "src_store": "backup", "port": 443})).json()
    assert any("Nginx Proxy Manager" in n for n in r["notes"])

    # Aanmaken zonder SSH-hosts: zeggen wat er ontbreekt.
    r = await authed.post("/api/backups/sync/create", json=plan)
    assert r.status_code == 422 and "PBS-VM en PBS-Pi" in r.json()["detail"]

    db.add(SshHost(name="pbs-vm", host="192.168.0.70", host_key="ssh-ed25519 AAAA"))
    db.add(SshHost(name="pbs-pi", host="10.0.0.9", service_id=pi, host_key="ssh-ed25519 AAAA"))
    await db.commit()
    assert (await authed.get("/api/backups")).json()["ssh"] == {str(vm): "pbs-vm", str(pi): "pbs-pi"}
    calls = []

    async def fake_run(db, h, script, stdin=None):
        calls.append((h.name, script, stdin))
        if h.name == "pbs-vm":
            return 0, '{"tokenid":"homepage-sync@pbs!pbs-pi","value":"geheim-123"}\n'
        return 0, "klaar\n"

    monkeypatch.setattr(pbssync, "_run", fake_run)
    r = await authed.post("/api/backups/sync/create", json=plan)
    assert r.status_code == 200, r.text
    assert [c[0] for c in calls] == ["pbs-vm", "pbs-pi"]
    assert "generate-token \"$U\" \"$T\"" in calls[0][1] and "/datastore/$S" in calls[0][1]
    # Het geheim gaat via stdin, niet in het script.
    assert calls[1][2] == "geheim-123\n" and "geheim-123" not in calls[1][1]
    assert "sync-job create \"$J\" --store 'pi'" in calls[1][1]
    assert "geheim-123" not in str(r.json())
    got = await _notes(db, "backup")
    assert ("PBS-sync ingesteld: PBS-VM → PBS-Pi", "ok", "Sync-job pbs-vm-naar-pbs-pi op PBS-Pi, elke dag om 06:00.") in got
    a = (await db.execute(select(AuditLog).where(AuditLog.action == "pbs_sync_create"))).scalars().one()
    assert a.detail["job"] == "pbs-vm-naar-pbs-pi"

    # Mislukt op de bron: geen geheim in de foutmelding.
    async def broken(db, h, script, stdin=None):
        return 1, '{"value":"geheim-456"} en toen ging het mis'

    monkeypatch.setattr(pbssync, "_run", broken)
    r = await authed.post("/api/backups/sync/create", json=plan)
    assert r.status_code == 502 and "geheim-456" not in r.text and "ging het mis" in r.text
    assert len((await db.execute(select(Notification).where(Notification.source == "backup"))).scalars().all()) == 1
    assert backups.router.prefix == "/api/backups"
