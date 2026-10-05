from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from app.db import get_db
from app.deps import notify
from app.main import app
from app.models import Event, MaintenanceWindow, Notification, Service
from app.monitoring import cluster, planned
from app.monitoring.checks import HttpClients

from .test_integrations import _group, _svc

NO_CSRF = {"X-Requested-With": ""}


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _notes(db, source):
    return [(n.title, n.level, n.body) for n in
            (await db.execute(select(Notification).where(Notification.source == source).order_by(Notification.id))).scalars()]


async def test_webhooks_into_notification_center(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "", "https://pve.jbogaert.be", name="pve50")
    pve = (await authed.post("/api/webhooks", json={"name": "Proxmox", "kind": "proxmox", "service_id": sid})).json()
    kuma = (await authed.post("/api/webhooks", json={"name": "Kuma", "kind": "uptimekuma"})).json()
    assert len(pve["token"]) >= 40

    r = await authed.post(f"/api/hooks/{pve['token']}", headers=NO_CSRF,
                          json={"title": "vzdump backup status (pve50): backup failed", "message": "CT 105: fout",
                                "severity": "error"})
    assert r.status_code == 202
    await authed.post(f"/api/hooks/{kuma['token']}", headers=NO_CSRF,
                      json={"heartbeat": {"status": 0, "msg": "timeout"}, "monitor": {"name": "Plex"}, "msg": "x"})
    await authed.post(f"/api/hooks/{pve['token']}", headers={**NO_CSRF, "content-type": "text/plain"},
                      content="Schijf /dev/sda: SMART-fout\nreallocated 12")
    assert (await authed.post("/api/hooks/" + "x" * 43, headers=NO_CSRF, json={})).status_code == 404
    agen, db = await _db()
    got = await _notes(db, "webhook")
    assert got == [("Proxmox: vzdump backup status (pve50): backup failed", "err", "CT 105: fout"),
                   ("Kuma: Plex down", "err", "timeout"),
                   ("Proxmox: Schijf /dev/sda: SMART-fout", "info", "reallocated 12")]
    n = (await db.execute(select(Notification).where(Notification.source == "webhook"))).scalars().first()
    assert n.service_id == sid
    tl = (await authed.get("/api/timeline?kind=melding")).json()["items"]
    assert any(i["title"].startswith("Kuma: Plex down") for i in tl)

    # Nieuw adres: het oude werkt niet meer. Uitgezet: ook niet.
    new = (await authed.post(f"/api/webhooks/{pve['id']}/rotate")).json()
    assert (await authed.post(f"/api/hooks/{pve['token']}", headers=NO_CSRF, json={"title": "x"})).status_code == 404
    assert (await authed.post(f"/api/hooks/{new['token']}", headers=NO_CSRF, json={"title": "x"})).status_code == 202
    await authed.patch(f"/api/webhooks/{pve['id']}", json={"name": "Proxmox", "kind": "proxmox", "enabled": False})
    assert (await authed.post(f"/api/hooks/{new['token']}", headers=NO_CSRF, json={"title": "x"})).status_code == 404
    lst = (await authed.get("/api/webhooks")).json()
    assert {x["name"]: x["count"] for x in lst} == {"Kuma": 1, "Proxmox": 3}


async def test_planned_maintenance(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "", "https://plex.jbogaert.be", name="plex")
    other = await _svc(authed, g, "", "https://nas.jbogaert.be", name="nas")
    start = datetime.now(timezone.utc) - timedelta(minutes=10)
    bad = await authed.post("/api/maintenance/windows", json={"name": "x", "start": start.isoformat(), "minutes": 30})
    assert bad.status_code == 422
    r = await authed.post("/api/maintenance/windows", json={"name": "herstart plex", "service_id": sid,
                                                            "start": start.isoformat(), "minutes": 30})
    assert r.status_code == 201 and r.json()["active_until"]
    st = (await authed.get("/api/status")).json()
    assert st[str(sid)]["maintenance_until"] and not st.get(str(other), {}).get("maintenance_until")
    # Verwijderen terwijl het loopt: het onderhoud stopt meteen.
    assert (await authed.delete(f"/api/maintenance/windows/{r.json()['id']}")).status_code == 204
    agen, db = await _db()
    s = await db.get(Service, sid)
    assert s.maintenance_until.replace(tzinfo=s.maintenance_until.tzinfo or timezone.utc) <= datetime.now(timezone.utc)
    await db.close()
    # Elke zondag om 3:00, een uur, voor de hele groep.
    sunday = datetime(2026, 10, 4, 3, 0).astimezone()
    w = (await authed.post("/api/maintenance/windows", json={
        "name": "back-up", "group_id": g, "repeat": "weekly", "weekdays": [6], "start": sunday.isoformat(),
        "minutes": 60})).json()
    assert w["text"] == "elke zo om 03:00, 1 u 00" and w["next"]
    agen, db = await _db()
    win = await db.get(MaintenanceWindow, w["id"])
    nxt = planned.next_run(win, datetime(2026, 10, 6, 12, tzinfo=timezone.utc))
    assert nxt.astimezone().weekday() == 6 and nxt.astimezone().hour == 3
    during = datetime(2026, 10, 11, 3, 30).astimezone()
    assert planned.active(win, during)
    assert not planned.active(win, during + timedelta(hours=1))
    assert await planned.apply(db, during) == 2
    await db.commit()
    assert (await db.execute(select(Event).where(Event.title == "Gepland onderhoud: back-up"))).scalars().first()


async def test_incident_notes(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "", "https://plex.jbogaert.be", name="plex")
    agen, db = await _db()
    notify(db, "plex is down", "timeout", level="err", source="monitor", service_id=sid)
    notify(db, "plex is weer up", None, level="ok", source="monitor", service_id=sid)
    await db.commit()
    tl = (await authed.get(f"/api/timeline?service_id={sid}")).json()["items"]
    down = next(i for i in tl if i["title"] == "plex is down")
    r = await authed.put(f"/api/timeline/events/{down['event_id']}/note", json={"note": "  NFS-share hing, remount  "})
    assert r.json()["note"] == "NFS-share hing, remount"
    inc = (await authed.get(f"/api/services/{sid}/incidents")).json()
    assert inc["count_year"] == 1 and inc["items"][0]["note"] == "NFS-share hing, remount"
    await authed.put(f"/api/timeline/events/{down['event_id']}/note", json={"note": ""})
    inc = (await authed.get(f"/api/services/{sid}/incidents")).json()
    assert all(i["note"] is None for i in inc["items"])


class Cluster:
    def __init__(self):
        self.quorate = 1
        self.ha = "started"
        self.fail = 0

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path
        if p == "/api2/json/cluster/status":
            return httpx.Response(200, json={"data": [
                {"type": "cluster", "name": "thuis", "quorate": self.quorate, "nodes": 2},
                {"type": "node", "name": "pve50", "online": 1, "nodeid": 1, "ip": "192.168.0.50"},
                {"type": "node", "name": "pve51", "online": self.quorate, "nodeid": 2, "ip": "192.168.0.51"}]})
        if p == "/api2/json/cluster/ha/status/current":
            return httpx.Response(200, json={"data": [{"type": "quorum", "status": "OK"},
                                                      {"type": "service", "sid": "ct:105", "state": self.ha, "node": "pve50"}]})
        if p.endswith("/replication"):
            return httpx.Response(200, json={"data": [{"id": "105-0", "guest": 105, "target": "pve51",
                                                       "fail_count": self.fail, "last_sync": 1}]})
        return httpx.Response(404)


async def test_cluster_status_alerts(authed):
    world = Cluster()
    http = HttpClients(httpx.MockTransport(world))
    g = await _group(authed)
    await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", secrets={"username": "a@pve!b", "password": "c"},
               name="pve50")
    await _svc(authed, g, "proxmox", "https://192.168.0.51:8006", secrets={"username": "a@pve!b", "password": "c"},
               name="pve51")
    agen, db = await _db()
    v = await cluster.run_cluster(db, http)
    await db.commit()
    assert len(v["items"]) == 1 and v["items"][0]["quorate"] is True and not v["alerts"]
    world.quorate, world.ha, world.fail = 0, "error", 1
    await cluster.run_cluster(db, http)
    await db.commit()
    got = [(t, lvl) for t, lvl, _ in await _notes(db, "cluster")]
    assert ("Cluster thuis heeft geen quorum meer", "err") in got
    assert ("Node pve51 is weg uit cluster thuis", "err") in got
    assert ("HA-resource ct:105 staat in error", "err") in got
    assert any(t.startswith("Replicatie 105-0") for t, _ in got)
    summ = (await authed.get("/api/health/summary")).json()
    assert summ["cluster"]["err"] == 3 and summ["err"] >= 3
    # Nog eens hetzelfde: geen nieuwe meldingen. Daarna in orde: één melding per herstel.
    await cluster.run_cluster(db, http)
    world.quorate, world.ha, world.fail = 1, "started", 0
    await cluster.run_cluster(db, http)
    await db.commit()
    got = [(t, lvl) for t, lvl, _ in await _notes(db, "cluster")]
    assert len(got) == 8 and ("Cluster thuis heeft weer quorum", "ok") in got
    assert (await authed.get("/api/cluster")).json()["summary"]["err"] == 0
