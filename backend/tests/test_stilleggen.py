"""Wat meldingen stillegt (onderhoud, gepland onderhoud, een cronjob dempen, een webhook of logregel uit, een
beveiligingspunt negeren, een check onder een ouder hangen die down is) vraagt een recente 2FA, komt in het auditlog
en geeft een melding die ook naar de gsm gaat: zoals een check pauzeren."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app import attention
from app.db import get_db
from app.deps import SILENCE_HINT
from app.main import app
from app.models import AuditLog, CronJob, MaintenanceWindow, Notification, Service, ServiceState, Session
from app.monitoring import planned
from app.monitoring.engine import silencing

from .test_beveiliging import _reauth
from .test_kuma_vervangen import _group, _svc


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


async def _stale() -> None:
    """2FA-bevestiging een uur oud (zoals iemand met een gestolen sessie)."""
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    await agen.aclose()


async def _notes() -> list[tuple]:
    """De meldingen dat iets stilgelegd werd: (titel, niveau, tekst, service). Bron auth: die gaan altijd naar de gsm."""
    agen, db = await _db()
    rows = [(n.title, n.level, n.body, n.service_id) for n in (await db.execute(
        select(Notification).where(Notification.source == "auth", Notification.body == SILENCE_HINT)
        .order_by(Notification.id))).scalars()]
    await agen.aclose()
    return rows


async def _actions() -> list[str]:
    agen, db = await _db()
    rows = [a.action for a in (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars()]
    await agen.aclose()
    return rows


def _needs_2fa(r) -> bool:
    return r.status_code == 403 and r.json()["detail"] == "reauth_required"


# --- onderhoud ----------------------------------------------------------------------------------------------------

async def test_onderhoud_beginnen_of_verlengen_vraagt_2fa(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "plex", {"type": "http"})
    await _stale()
    assert _needs_2fa(await authed.post(f"/api/services/{sid}/maintenance", json={"minutes": 60}))
    agen, db = await _db()
    assert (await db.get(Service, sid)).maintenance_until is None
    await agen.aclose()
    assert not await _notes()

    await _reauth(authed)
    r = await authed.post(f"/api/services/{sid}/maintenance", json={"minutes": 60})
    assert r.status_code == 200 and r.json()["maintenance_until"]
    ((title, level, body, service),) = await _notes()
    assert title.startswith("Onderhoud: plex tot ") and level == "warn" and body == SILENCE_HINT and service == sid
    assert (await _actions()).count("maintenance") == 1

    # Inkorten en stoppen blijven vrij; verlengen niet.
    await _stale()
    assert (await authed.post(f"/api/services/{sid}/maintenance", json={"minutes": 30})).status_code == 200
    assert _needs_2fa(await authed.post(f"/api/services/{sid}/maintenance", json={"minutes": 120}))
    assert (await authed.post(f"/api/services/{sid}/maintenance", json={"minutes": 0})).json() == {
        "maintenance_until": None}
    assert len(await _notes()) == 1 and (await _actions()).count("maintenance") == 3


async def test_onderhoud_voor_een_groep_vraagt_2fa(authed):
    g = await _group(authed)
    for name in ("pve50", "pve51"):
        await _svc(authed, g, name, {"type": "ping"})
    await _stale()
    assert _needs_2fa(await authed.post(f"/api/groups/{g}/maintenance", json={"minutes": 60}))
    await _reauth(authed)
    assert (await authed.post(f"/api/groups/{g}/maintenance", json={"minutes": 60})).status_code == 200
    ((title, level, *_),) = await _notes()
    assert title.startswith("Onderhoud voor groep G: 2 services tot ") and level == "warn"
    await _stale()
    assert (await authed.post(f"/api/groups/{g}/maintenance", json={"minutes": 0})).status_code == 200
    agen, db = await _db()
    assert all(s.maintenance_until is None for s in (await db.execute(select(Service))).scalars())
    await agen.aclose()


async def test_gepland_onderhoud_vraagt_2fa(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "plex", {"type": "http"})
    later = datetime.now(timezone.utc) + timedelta(days=2)
    win = {"name": "herstart", "service_id": sid, "start": later.isoformat(), "minutes": 30}
    await _stale()
    assert _needs_2fa(await authed.post("/api/maintenance/windows", json=win))
    r = await authed.post("/api/maintenance/windows", json={**win, "enabled": False})
    assert r.status_code == 201, r.text
    wid = r.json()["id"]
    assert _needs_2fa(await authed.put(f"/api/maintenance/windows/{wid}", json=win))
    assert (await authed.put(f"/api/maintenance/windows/{wid}", json={**win, "name": "x", "enabled": False})
            ).status_code == 200
    assert not await _notes()

    await _reauth(authed)
    assert (await authed.put(f"/api/maintenance/windows/{wid}", json=win)).status_code == 200
    ((title, level, *_),) = await _notes()
    assert title.startswith("Gepland onderhoud: herstart (plex, ") and level == "warn"
    assert "maintenance_planned" in await _actions()

    # Aan: de naam wijzigen en uitzetten blijven vrij, anders plannen niet. Verwijderen is vrij.
    await _stale()
    assert (await authed.put(f"/api/maintenance/windows/{wid}", json={**win, "name": "reboot"})).status_code == 200
    assert _needs_2fa(await authed.put(f"/api/maintenance/windows/{wid}", json={**win, "minutes": 600}))
    assert _needs_2fa(await authed.post("/api/maintenance/windows", json={**win, "group_id": g, "service_id": None}))
    assert (await authed.put(f"/api/maintenance/windows/{wid}", json={**win, "enabled": False})).status_code == 200
    assert (await authed.delete(f"/api/maintenance/windows/{wid}")).status_code == 204
    assert len(await _notes()) == 1


async def test_herhalend_venster_hoogstens_12_uur(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "plex", {"type": "http"})
    start = datetime(2026, 10, 4, 3, 0).astimezone()
    daily = {"name": "altijd", "service_id": sid, "repeat": "daily", "start": start.isoformat(), "minutes": 1440}
    r = await authed.post("/api/maintenance/windows", json=daily)
    assert r.status_code == 422 and "hoogstens 12 uur" in r.text
    r = await authed.post("/api/maintenance/windows", json={**daily, "repeat": "weekly", "weekdays": [0, 1, 2, 3, 4, 5, 6],
                                                            "minutes": 721})
    assert r.status_code == 422
    assert (await authed.post("/api/maintenance/windows", json={**daily, "minutes": 720})).status_code == 201
    # Eenmalig mag langer (tot 7 dagen).
    assert (await authed.post("/api/maintenance/windows", json={**daily, "repeat": "once"})).status_code == 201
    # Een ouder venster dat nog langer bewaard is, loopt maar 12 uur per keer.
    old = MaintenanceWindow(name="oud", service_id=sid, repeat="daily", start=start, minutes=1440, weekdays=[],
                            enabled=True)
    begin, end = planned.occurrences(old, start)[0]
    assert end - begin == timedelta(hours=12)
    assert not planned.active(old, start + timedelta(days=1, hours=13))
    assert planned.describe(old) == "elke dag om 03:00, 12 u 00"


async def test_onderhoud_met_de_hand_valt_op_in_aandacht(authed):
    g = await _group(authed)
    ids = [await _svc(authed, g, f"s{i}", {"type": "http"}) for i in range(13)]
    g2 = await _group(authed)
    lone = await _svc(authed, g2, "nas", {"type": "http"})
    now = datetime.now(timezone.utc)
    agen, db = await _db()
    (await db.get(Service, ids[0])).maintenance_until = now + timedelta(hours=2)  # kort: niets
    (await db.get(Service, lone)).maintenance_until = now + timedelta(days=3)
    # Een gepland venster dat nu loopt: dat staat er al als "Onderhoud bezig".
    db.add(MaintenanceWindow(name="nacht", service_id=ids[1], repeat="once", start=now - timedelta(minutes=5),
                             minutes=3 * 24 * 60, weekdays=[], enabled=True))
    await db.commit()
    await planned.apply(db)
    await db.commit()
    r = (await authed.get("/api/attention")).json()
    hand = [i for i in r["items"] if i["key"].startswith("maint:")]
    assert [(i["key"], i["level"]) for i in hand if i["key"].startswith("maint:hand")] == [(f"maint:hand:{lone}", "warn")]
    item = next(i for i in hand if i["key"] == f"maint:hand:{lone}")
    assert item["title"].startswith("nas in onderhoud tot ") and item["fix"] == {"window": "detail", "service_id": lone}
    assert any(i["title"] == "Onderhoud bezig: nacht" for i in hand)

    # Een hele groep tegelijk (met de knop bij de groep): één punt voor de groep.
    for sid in ids[2:5]:
        (await db.get(Service, sid)).maintenance_until = now + timedelta(days=2)
    await db.commit()
    keys = {i["key"]: i for i in (await authed.get("/api/attention")).json()["items"]}
    assert keys[f"maint:hand:{ids[2]}"]["title"].startswith("3 services (s2, s3, s4) in onderhoud tot")

    # Veel services tegelijk, ook kort: één punt.
    for sid in ids[2:]:
        (await db.get(Service, sid)).maintenance_until = now + timedelta(hours=1)
    await db.commit()
    hand = [i for i in (await authed.get("/api/attention")).json()["items"] if i["key"].startswith("maint:")
            and not i["title"].startswith("Onderhoud bezig")]
    assert [i["key"] for i in hand] == ["maint:veel"] and hand[0]["title"] == "13 services in onderhoud"
    assert hand[0]["fix"] == {"window": "detail", "service_id": lone}
    await agen.aclose()
    assert attention.MAINT_MANY == 10


# --- cron, webhooks, logregels ---------------------------------------------------------------------------------

async def test_cronjob_dempen_vraagt_2fa(authed):
    agen, db = await _db()
    job = CronJob(key="k1", target="ssh:1", target_name="pve2", kind="cron", name="sync.sh", last_status="fout")
    db.add(job)
    await db.commit()
    jid = job.id
    await agen.aclose()
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/cron/jobs/{jid}", json={"muted": True}))
    assert _needs_2fa(await authed.patch(f"/api/cron/jobs/{jid}", json={"alias": "sync", "muted": True}))
    r = await authed.patch(f"/api/cron/jobs/{jid}", json={"alias": "sync"})
    assert r.status_code == 200 and not r.json()["muted"]
    await _reauth(authed)
    assert (await authed.patch(f"/api/cron/jobs/{jid}", json={"muted": True})).json()["muted"]
    ((title, level, *_),) = await _notes()
    assert title == "Cronjob gedempt: sync op pve2" and level == "warn"
    await _stale()
    assert (await authed.patch(f"/api/cron/jobs/{jid}", json={"muted": True})).status_code == 200  # al gedempt
    assert not (await authed.patch(f"/api/cron/jobs/{jid}", json={"muted": False})).json()["muted"]
    assert (await _actions()).count("cron_job_changed") == 4


async def test_webhook_uitzetten_vernieuwen_of_verwijderen_vraagt_2fa(authed):
    hook = {"name": "Proxmox", "kind": "proxmox"}
    wid = (await authed.post("/api/webhooks", json=hook)).json()["id"]
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/webhooks/{wid}", json={**hook, "enabled": False}))
    assert _needs_2fa(await authed.post(f"/api/webhooks/{wid}/rotate"))
    assert _needs_2fa(await authed.delete(f"/api/webhooks/{wid}"))
    assert (await authed.patch(f"/api/webhooks/{wid}", json={**hook, "name": "PVE"})).status_code == 200
    assert not await _notes()

    await _reauth(authed)
    assert (await authed.patch(f"/api/webhooks/{wid}", json={**hook, "enabled": False})).json()["enabled"] is False
    # Een webhook die uit staat: vernieuwen en weer aanzetten zijn vrij.
    await _stale()
    assert (await authed.post(f"/api/webhooks/{wid}/rotate")).status_code == 200
    assert (await authed.patch(f"/api/webhooks/{wid}", json={**hook, "enabled": True})).json()["enabled"] is True
    assert _needs_2fa(await authed.delete(f"/api/webhooks/{wid}"))
    await _reauth(authed)
    assert (await authed.post(f"/api/webhooks/{wid}/rotate")).status_code == 200
    assert (await authed.delete(f"/api/webhooks/{wid}")).status_code == 204
    assert [t for t, *_ in await _notes()] == ["Webhook uitgezet: PVE", "Nieuw adres voor webhook Proxmox: het oude "
                                               "werkt niet meer", "Webhook verwijderd: Proxmox"]
    assert {"webhook_changed", "webhook_rotated", "webhook_deleted"} <= set(await _actions())


async def test_logregel_uitzetten_lager_of_verwijderen_vraagt_2fa(authed):
    rule = {"name": "ssh", "pattern": "Failed password", "level": "err"}
    r = (await authed.post("/api/logs/rules", json=rule)).json()
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/logs/rules/{r['id']}", json={**rule, "enabled": False}))
    assert _needs_2fa(await authed.patch(f"/api/logs/rules/{r['id']}", json={**rule, "level": "warn"}))
    assert _needs_2fa(await authed.delete(f"/api/logs/rules/{r['id']}"))
    # Hoger, een andere naam en een nieuwe regel blijven vrij.
    assert (await authed.patch(f"/api/logs/rules/{r['id']}", json={**rule, "name": "SSH"})).status_code == 200
    assert (await authed.post("/api/logs/rules", json={**rule, "name": "kernel"})).status_code == 201
    assert not await _notes()

    await _reauth(authed)
    assert (await authed.patch(f"/api/logs/rules/{r['id']}", json={**rule, "level": "warn"})).json()["level"] == "warn"
    assert (await authed.patch(f"/api/logs/rules/{r['id']}", json={**rule, "enabled": False})).json()["enabled"] is False
    assert [t for t, *_ in await _notes()] == ["Logregel lager gezet: SSH (err → warn)", "Logregel uitgezet: ssh"]
    # Een regel die al uit staat, verwijderen is vrij.
    await _stale()
    assert (await authed.delete(f"/api/logs/rules/{r['id']}")).status_code == 200
    assert len(await _notes()) == 2


# --- aandacht: een beveiligingspunt negeren ------------------------------------------------------------------------

async def test_beveiligingspunt_negeren_vraagt_2fa(authed):
    agen, db = await _db()
    await db.execute(update(Session).values(ip="8.8.8.8"))
    await db.commit()
    await agen.aclose()
    items = (await authed.get("/api/attention")).json()["items"]
    sec = next(i for i in items if i["key"] == "sec:sessions")
    other = next(i for i in items if not i["key"].startswith("sec:"))
    await _stale()
    assert _needs_2fa(await authed.put("/api/attention/ignore", json={"key": sec["key"], "sig": sec["sig"]}))
    r = await authed.put("/api/attention/ignore", json={"key": other["key"], "sig": other["sig"]})
    assert r.status_code == 200 and other["key"] in {i["key"] for i in r.json()["ignored"]}
    assert not await _notes()

    await _reauth(authed)
    r = await authed.put("/api/attention/ignore", json={"key": sec["key"], "sig": sec["sig"]})
    assert r.status_code == 200 and sec["key"] in {i["key"] for i in r.json()["ignored"]}
    ((title, level, body, _),) = await _notes()
    assert title == "Beveiligingswaarschuwing genegeerd: Sessies van buitenaf" and level == "warn" and body == SILENCE_HINT
    assert (await _actions()).count("attention_ignored") == 1
    # Terugzetten is vrij.
    await _stale()
    r = await authed.put("/api/attention/ignore", json={"key": sec["key"]})
    assert r.status_code == 200 and sec["key"] in {i["key"] for i in r.json()["items"]}


# --- de check zelf: certificaatmeldingen en afhankelijkheden ----------------------------------------------------

def test_certificaatmeldingen_uit_legt_stil():
    http = {"type": "http"}
    assert silencing(http, {**http, "cert_notify": False}) == "certificaatmeldingen uitgezet"
    assert silencing({**http, "cert_notify": True}, {**http, "cert_notify": False}) == "certificaatmeldingen uitgezet"
    assert silencing({**http, "cert_notify": False}, {**http, "cert_notify": False}) is None
    assert silencing({**http, "cert_notify": False}, http) is None
    assert silencing({}, {**http, "cert_notify": False}) is None


async def test_certificaatmeldingen_uit_vraagt_2fa(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "wiki", {"type": "http"})
    base = {"group_id": g, "name": "wiki", "url": "https://wiki.lan"}
    await _stale()
    r = await authed.patch(f"/api/services/{sid}", json={**base, "check": {"type": "http", "cert_notify": False}})
    assert _needs_2fa(r)
    await _reauth(authed)
    r = await authed.patch(f"/api/services/{sid}", json={**base, "check": {"type": "http", "cert_notify": False}})
    assert r.status_code == 200
    assert [t for t, *_ in await _notes()] == ["Certificaatmeldingen uitgezet: wiki"]


async def test_onder_een_ouder_die_down_of_in_onderhoud_is_vraagt_2fa(authed):
    g = await _group(authed)
    node = await _svc(authed, g, "pve50", {"type": "ping"})
    up = await _svc(authed, g, "pve51", {"type": "ping"})
    ct = await _svc(authed, g, "plex", {"type": "http"})
    base = {"group_id": g, "name": "plex", "url": "https://plex.lan", "check": {"type": "http"}}
    agen, db = await _db()
    db.add(ServiceState(service_id=node, status="down", since=datetime.now(timezone.utc), fail_count=3))
    await db.commit()
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/services/{ct}", json={**base, "parent_id": node}))
    # Een ouder die in orde is: vrij.
    assert (await authed.patch(f"/api/services/{ct}", json={**base, "parent_id": up})).status_code == 200
    # Die ouder in onderhoud (dat vroeg zelf al 2FA): een kind eronder hangen ook.
    await _reauth(authed)
    assert (await authed.post(f"/api/services/{up}/maintenance", json={"minutes": 60})).status_code == 200
    other = await _svc(authed, g, "jellyfin", {"type": "http"})
    await _stale()
    r = await authed.patch(f"/api/services/{other}", json={**base, "name": "jellyfin", "parent_id": up})
    assert _needs_2fa(r)
    await _reauth(authed)
    assert (await authed.patch(f"/api/services/{ct}", json={**base, "parent_id": node})).status_code == 200
    titles = [t for t, *_ in await _notes()]
    assert "Afhankelijk van pve50 (down): plex" in titles

    # Een oude versie terugzetten waarin plex onder pve50 hing: geen achterdoor.
    revs = (await authed.get("/api/revisions")).json()
    await authed.patch(f"/api/services/{ct}", json={**base, "parent_id": None})
    await _stale()
    r = await authed.post(f"/api/revisions/{revs[0]['id']}/restore")
    assert _needs_2fa(r)
    await agen.aclose()
