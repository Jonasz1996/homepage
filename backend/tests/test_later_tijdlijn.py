import copy
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app.models import AppState, CheckResult, Event, Notification
from app.monitoring import updates as upd
from app.monitoring.capacity import sample
from app.monitoring.checks import HttpClients
from app.monitoring.engine import record
from app.monitoring.checks import Outcome
from app.monitoring.report import build_report, weekly_notification
from app.monitoring.watchers import watch_pbs
from app.models import Service

from .test_capacity import _db
from .test_integrations import PVE, Fake, _group, _svc

PVE_SECRETS = {"username": "homepage@pve!dash", "password": "geheim"}
PBS_SECRETS = {"username": "homepage@pbs!dash", "password": "geheim"}


class Fake2(Fake):
    """Fake met aanpasbare Proxmox-gegevens en de update-endpoints."""

    def __init__(self):
        super().__init__()
        self.pve = copy.deepcopy(PVE)
        self.apt = [{"Package": "pve-manager", "OldVersion": "8.2.4", "Version": "8.2.7", "Origin": "Proxmox"},
                    {"Package": "openssl", "OldVersion": "3.0.13", "Version": "3.0.14", "Origin": "Debian-Security"}]
        self.image = "outdated"

    def __call__(self, req):
        p = req.url.path
        if p == "/api2/json/cluster/resources":
            self.calls.append(req)
            return httpx.Response(200, json=self.pve)
        if p == "/api2/json/nodes/pve50/apt/update":
            return httpx.Response(200, json={"data": self.apt})
        if p == "/api2/json/nodes/localhost/apt/update":
            return httpx.Response(403)
        if p.endswith("/image_status"):
            return httpx.Response(200, json={"Status": self.image, "Message": ""})
        return super().__call__(req)


def test_parse_output():
    out = "\n".join([
        "@@HOST",
        "openssl/stable-security 3.0.14-1~deb12u2 amd64 [upgradable from: 3.0.13-1~deb12u1]",
        "curl/stable 7.88.1-10+deb12u8 amd64 [upgradable from: 7.88.1-10+deb12u7]",
        "@@CT 101 vaultwarden",
        "musl-1.2.4-r3 x86_64 {musl} (MIT) [upgradable from: musl-1.2.4-r2]",
        "@@CT 102 leeg",
        "@@CT 103 raar",
        "@@NOPKG",
    ])
    parts = upd.parse_output(out)
    assert [(k, n) for k, n, _ in parts] == [("host", None), ("ct", "101 vaultwarden"), ("ct", "102 leeg"), ("ct", "103 raar")]
    host = parts[0][2]
    assert host[0] == {"n": "openssl", "from": "3.0.13-1~deb12u1", "to": "3.0.14-1~deb12u2", "sec": True}
    assert host[1]["sec"] is False
    assert parts[1][2] == [{"n": "musl", "from": "1.2.4-r2", "to": "1.2.4-r3", "sec": False}]
    assert parts[2][2] == [] and parts[3][2] is None
    # Het script loopt ook alle containers af als dat gevraagd is.
    assert "pct exec" in upd.script(True) and "pct exec" not in upd.script(False)


async def test_restarts_on_timeline(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be", secrets=PVE_SECRETS, name="PVE")
    fake = Fake2()
    clients = HttpClients(httpx.MockTransport(fake))
    agen, db = await _db()
    for r in fake.pve["data"]:
        if r.get("vmid") == 100:
            r["uptime"] = 7200
    await sample(db, clients)
    await db.commit()
    assert [e.title for e in (await db.execute(select(Event).where(Event.kind == "herstart"))).scalars()] == []  # eerste meting: niets te vergelijken

    # VM 100 herstart, CT 101 gestart.
    for r in fake.pve["data"]:
        if r.get("vmid") == 100:
            r["uptime"] = 60
        if r.get("vmid") == 101:
            r.update(status="running", uptime=30, mem=1e8)
    await sample(db, clients)
    await db.commit()
    titles = sorted(e.title for e in (await db.execute(select(Event).where(Event.kind == "herstart"))).scalars())
    assert titles == ["CT 101 homepage gestart", "VM 100 opnsense herstart"]

    # De node herstart: één melding, met de VM's/CT's erbij; CT 101 kwam niet terug.
    for r in fake.pve["data"]:
        if r.get("type") == "node" and r["node"] == "pve50":
            r["uptime"] = 120
        if r.get("vmid") == 100:
            r["uptime"] = 90
        if r.get("vmid") == 101:
            r.update(status="stopped", uptime=0)
    await sample(db, clients)
    await db.commit()
    note = (await db.execute(select(Notification).where(Notification.source == "herstart"))).scalar_one()
    assert note.title == "Node pve50 is herstart" and note.service_id == sid
    assert "VM 100 opnsense herstart om" in note.body and "Niet meer actief:\nCT 101 homepage" in note.body
    assert len((await db.execute(select(Event).where(Event.kind == "herstart"))).scalars().all()) == 3
    await agen.aclose()


async def test_timeline_merges_sources(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "link", "https://x.jbogaert.be", name="Wiki")
    await authed.post(f"/api/services/{sid}/maintenance", json={"minutes": 30})
    agen, db = await _db()
    svc = await db.get(Service, sid)
    svc.check = {"type": "http"}
    now = datetime.now(timezone.utc)
    # Down en weer up (onderhoud eerst uitzetten, anders telt het niet).
    svc.maintenance_until = None
    for i in range(3):
        await record(db, svc, Outcome(False, error="timeout"), now + timedelta(seconds=i))
    await record(db, svc, Outcome(True, latency_ms=12), now + timedelta(minutes=5))
    await db.commit()

    items = (await authed.get("/api/timeline")).json()["items"]
    kinds = [(i["kind"], i["title"]) for i in items]
    assert ("storing", "Wiki is weer bereikbaar") in kinds and ("storing", "Wiki is down") in kinds
    assert ("wijziging", "Service 'Wiki' toegevoegd") in kinds
    assert any(k == "wijziging" and t.startswith("Onderhoud Wiki: 30 min") for k, t in kinds)
    recovered = next(i for i in items if i["title"] == "Wiki is weer bereikbaar")
    assert recovered["data"]["down_s"] == 300 - 2

    only = (await authed.get("/api/timeline", params={"kind": "storing"})).json()["items"]
    assert {i["kind"] for i in only} == {"storing"}
    per = (await authed.get("/api/timeline", params={"service_id": sid})).json()["items"]
    assert len(per) == 2
    # Bladeren: alles van vóór het oudste item.
    first = (await authed.get("/api/timeline", params={"limit": 2})).json()
    assert len(first["items"]) == 2 and first["more"]
    rest = (await authed.get("/api/timeline", params={"before": first["items"][-1]["ts"]})).json()["items"]
    assert {i["id"] for i in rest}.isdisjoint({i["id"] for i in first["items"]})
    # Notificaties wissen laat de tijdlijn staan.
    await authed.post("/api/notifications/read-all")
    await authed.delete("/api/notifications")
    assert len((await authed.get("/api/timeline", params={"kind": "storing"})).json()["items"]) == 2
    await agen.aclose()


async def test_report_and_weekly_notification(authed):
    g = await _group(authed)
    a = await _svc(authed, g, "link", "https://a.jbogaert.be", name="Alfa")
    b = await _svc(authed, g, "link", "https://b.jbogaert.be", name="Beta")
    agen, db = await _db()
    now = datetime.now(timezone.utc)
    for i in range(100):
        ts = now - timedelta(hours=1, minutes=i)
        db.add(CheckResult(service_id=a, ts=ts, ok=True, latency_ms=10 + i % 3, maintenance=False))
        db.add(CheckResult(service_id=b, ts=ts, ok=i >= 4, latency_ms=200 if i >= 4 else None, maintenance=False))
    # Onderhoud telt niet mee.
    db.add(CheckResult(service_id=b, ts=now - timedelta(minutes=5), ok=False, maintenance=True))
    db.add(Event(kind="storing", title="Beta is down", service_id=b, ts=now - timedelta(hours=2), data={"down": True}))
    db.add(Event(kind="storing", title="Beta is weer bereikbaar", service_id=b, ts=now - timedelta(hours=1),
                 data={"down_s": 3600}))
    db.add(Event(kind="backup", level="ok", title="PBS: 5 back-ups gemaakt", ts=now - timedelta(hours=3), data={"count": 5}))
    db.add(Event(kind="herstart", title="VM 100 herstart", ts=now - timedelta(hours=4)))
    db.add(AppState(key="pbs_problems:1", value={"keys": ["hdd:ct/101:late"]}))
    db.add(AppState(key="updates", value={"targets": [upd.target("ssh:1", "docker01", "host", None,
                                                                 [{"n": "x", "sec": True}, {"n": "y", "sec": False}])]}))
    await db.commit()

    r = (await authed.get("/api/report")).json()
    assert r["uptime"] == 98.0
    assert [(s["name"], s["uptime"]) for s in r["services"]] == [("Beta", 96.0), ("Alfa", 100.0)]
    assert r["slowest"][0]["name"] == "Beta" and r["slowest"][0]["avg_ms"] == 200
    assert r["outages"]["count"] == 1 and r["outages"]["longest"]["seconds"] == 3600
    assert r["outages"]["longest"]["name"] == "Beta"
    assert r["backups"]["made"] == 5 and r["backups"]["open"][0]["problem"] == "te oud"
    assert len(r["restarts"]) == 1
    assert r["updates"] == {"installed": 0, "pending": 2, "security": 1,
                            "machines": [{"name": "docker01", "count": 2, "security": 1}]}

    # Maandagmelding: alleen op maandag na 8 uur, en maar één keer per week. Het rapport gaat over de vorige week.
    local = datetime.now().astimezone()
    monday = (local + timedelta(days=(7 - local.weekday()) % 7)).replace(hour=9, minute=0, second=0, microsecond=0)
    assert await weekly_notification(db, monday - timedelta(hours=2)) is False  # 7 uur: nog te vroeg
    assert await weekly_notification(db, monday + timedelta(days=1)) is False  # dinsdag
    assert await weekly_notification(db, monday) is True
    await db.commit()
    assert await weekly_notification(db, monday + timedelta(hours=3)) is False
    week = await build_report(db, now - timedelta(days=7), now)
    assert week["uptime"] == 98.0
    await agen.aclose()


async def test_updates_overview(authed):
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be", secrets=PVE_SECRETS, name="PVE")
    pbs = await _svc(authed, g, "proxmoxbackupserver", "https://pbs.jbogaert.be", secrets=PBS_SECRETS, name="PBS")
    ptr = await _svc(authed, g, "portainer", "https://portainer.jbogaert.be", secrets={"key": "ptr_geheim"}, name="Docker")
    fake = Fake2()
    clients = HttpClients(httpx.MockTransport(fake))
    agen, db = await _db()
    await upd.run_updates(db, clients)
    await db.commit()

    data = (await authed.get("/api/updates")).json()
    t = {x["key"]: x for x in data["targets"]}
    assert t[f"pve:{pve}:pve50"]["count"] == 2 and t[f"pve:{pve}:pve50"]["security"] == 1
    assert "pve51" not in str(t)  # offline node
    assert "Sys.Audit" in t[f"pbs:{pbs}"]["error"]
    assert t[f"docker:{ptr}:2"]["packages"] == [{"n": "vaultwarden", "to": "vw:latest", "sec": False}]
    assert data["total"] == 3 and data["security"] == 1
    assert data["by_service"] == {str(pve): {"count": 2, "security": 1}, str(ptr): {"count": 1, "security": 0}}

    # Bijgewerkt: minder updates → op de tijdlijn.
    fake.apt = fake.apt[:1]
    fake.image = "updated"
    await upd.run_updates(db, clients)
    await db.commit()
    titles = sorted(e.title for e in (await db.execute(select(Event).where(Event.kind == "updates"))).scalars())
    assert titles == ["docker01: 1 container op een nieuw image", "pve50: 1 update geïnstalleerd"]
    ev = (await db.execute(select(Event).where(Event.title.like("pve50%")))).scalar_one()
    assert ev.body == "openssl"
    await agen.aclose()

    # Nu controleren loopt op de achtergrond.
    r = await authed.post("/api/updates/refresh")
    assert r.status_code == 202


async def test_ssh_host_updates_flag(authed):
    r = await authed.post("/api/ssh/hosts", json={"name": "pve50", "host": "192.168.0.50", "updates": "cts"})
    assert r.status_code == 201 and r.json()["updates"] == "cts"
    assert (await authed.post("/api/ssh/hosts", json={"name": "x", "host": "h", "updates": "alles"})).status_code == 422
    # Zonder bevestigde hostsleutel wordt er niet verbonden.
    agen, db = await _db()
    out = await upd.collect(db, HttpClients(httpx.MockTransport(Fake2())))
    assert out[0]["name"] == "pve50" and "hostsleutel" in out[0]["error"]
    await agen.aclose()


async def test_pbs_backups_on_timeline(authed):
    g = await _group(authed)
    await _svc(authed, g, "proxmoxbackupserver", "https://pbs.jbogaert.be", secrets=PBS_SECRETS, name="PBS")
    agen, db = await _db()
    clients = HttpClients(httpx.MockTransport(Fake()))
    await watch_pbs(db, clients)
    await db.commit()
    assert not (await db.execute(select(Event).where(Event.kind == "backup", Event.level == "ok"))).scalars().all()
    # Volgende ronde: de tijdstempels gaan vooruit alsof er nieuwe back-ups zijn.
    st = (await db.execute(select(AppState).where(AppState.key.like("pbs_last:%")))).scalar_one()
    st.value = {k: v - 7200 for k, v in st.value.items()}
    await db.commit()
    await watch_pbs(db, clients)
    await db.commit()
    ev = (await db.execute(select(Event).where(Event.kind == "backup", Event.level == "ok"))).scalar_one()
    assert ev.title == "PBS: 3 back-ups gemaakt" and ev.data == {"count": 3}
    await agen.aclose()
