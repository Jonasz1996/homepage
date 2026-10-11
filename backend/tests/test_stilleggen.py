"""Wat meldingen stillegt (onderhoud, gepland onderhoud, een cronjob dempen, een webhook of logregel uit, een
beveiligingspunt negeren, een check onder een ouder hangen die down is of naar een groep met gepland onderhoud)
vraagt een recente 2FA, komt in het auditlog en geeft een melding die ook naar de gsm gaat: zoals een check pauzeren."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

from app import attention
from app.db import get_db
from app.deps import SILENCE_HINT
from app.main import app
from app.models import AuditLog, CronJob, MaintenanceWindow, Notification, Service, ServiceState, Session
from app.monitoring import planned
from app.monitoring.engine import _aware, silencing

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


async def _old_window(**target) -> tuple[int, datetime, datetime]:
    """Een herhalend venster van een hele dag (van vóór de grens van 12 uur), sinds 2 uur bezig."""
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=2)).replace(second=0, microsecond=0)
    w = MaintenanceWindow(name="altijd", repeat="daily", start=start, minutes=1440, weekdays=[], enabled=True, **target)
    agen, db = await _db()
    db.add(w)
    await db.commit()
    begin, end = planned.active(w, now)
    await agen.aclose()
    return w.id, begin, end


async def _until(sid: int) -> datetime | None:
    agen, db = await _db()
    until = _aware((await db.get(Service, sid)).maintenance_until)
    await agen.aclose()
    return until


async def test_ouder_venster_van_een_dag_blijft_uit_te_zetten_en_te_hernoemen(authed):
    """Vroeger kon een herhalend venster een hele dag duren. Zo'n venster gaat gewoon uit, en het in de editor openen
    en bewaren (die zet de duur op 12 uur) is niet anders plannen. Het loopt nog maar 12 uur per keer."""
    g = await _group(authed)
    plex = await _svc(authed, g, "plex", {"type": "http"})
    nas = await _svc(authed, g, "nas", {"type": "http"})
    wid, begin, end = await _old_window(service_id=plex)
    assert end - begin == timedelta(hours=12)
    # Wat de oude versie zette: de volle dag. Nu zet een lopend venster hoogstens 12 uur.
    agen, db = await _db()
    (await db.get(Service, plex)).maintenance_until = begin + timedelta(days=1)
    await db.commit()
    await agen.aclose()
    old = {"name": "altijd", "service_id": plex, "repeat": "daily", "start": begin.isoformat(), "minutes": 1440}

    # Uitzetten met de duur die de lijst vroeger meestuurde: vrij, en het onderhoud van de volle dag stopt.
    await _stale()
    r = await authed.put(f"/api/maintenance/windows/{wid}", json={**old, "enabled": False})
    assert r.status_code == 200, r.text
    assert await _until(plex) <= datetime.now(timezone.utc)
    # Weer aanzetten: met een hele dag niet, met 12 uur (wat de lijst nu stuurt) met 2FA.
    r = await authed.put(f"/api/maintenance/windows/{wid}", json=old)
    assert r.status_code == 422 and "hoogstens 12 uur" in r.text
    assert _needs_2fa(await authed.put(f"/api/maintenance/windows/{wid}", json={**old, "minutes": 720}))

    # Openen en bewaren in de editor (die zet de duur op 12 uur) is niet anders plannen: geen 2FA, geen melding.
    wid, begin, end = await _old_window(service_id=nas)
    r = await authed.put(f"/api/maintenance/windows/{wid}", json={**old, "service_id": nas, "name": "nacht",
                                                                   "start": begin.isoformat(), "minutes": 720})
    assert r.status_code == 200, r.text
    assert r.json()["active_until"] and await _until(nas) == end
    assert not await _notes()
    assert (await _actions()).count("maintenance_planned") == 2


async def test_ouder_venster_verwijderen_stopt_ook_de_volle_dag(authed):
    """Een venster van een hele dag dat al liep voor de update, zette het onderhoud tot het einde van die dag. Na 12 uur
    loopt het venster niet meer, maar verwijderen stopt dat onderhoud toch (en laat onderhoud met de hand staan)."""
    g = await _group(authed)
    plex = await _svc(authed, g, "plex", {"type": "http"})
    nas = await _svc(authed, g, "nas", {"type": "http"})
    wid, begin, _ = await _old_window(group_id=g)
    agen, db = await _db()
    w = await db.get(MaintenanceWindow, wid)
    w.start = begin = begin - timedelta(hours=12)
    (await db.get(Service, plex)).maintenance_until = begin + timedelta(days=1)
    (await db.get(Service, nas)).maintenance_until = hand = begin + timedelta(days=2)
    await db.commit()
    assert not planned.active(w, datetime.now(timezone.utc))
    assert await planned.apply(db) == 0
    await db.commit()
    await agen.aclose()
    assert await _until(plex) == begin + timedelta(days=1)
    await _stale()
    assert (await authed.delete(f"/api/maintenance/windows/{wid}")).status_code == 204
    assert await _until(plex) <= datetime.now(timezone.utc)
    assert await _until(nas) == hand


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


async def test_zonder_eigen_check_onder_een_ouder_die_down_of_in_onderhoud_is_telt_wat_eronder_hangt(authed):
    """Een tegel zonder check meldt zelf niets, maar wat eronder hangt wel: een kind van een ouder die down is, meldt
    niets, en onderhoud geldt voor alles eronder. Zo'n tegel daaronder hangen vraagt dus ook 2FA."""
    g = await _group(authed)
    node = await _svc(authed, g, "pve50", {"type": "ping"})
    up = await _svc(authed, g, "pve51", {"type": "ping"})
    docker = await _svc(authed, g, "docker")
    plex = await _svc(authed, g, "plex", {"type": "http"}, parent_id=docker)
    agen, db = await _db()
    db.add(ServiceState(service_id=node, status="down", since=datetime.now(timezone.utc), fail_count=3))
    await db.commit()
    base = {"group_id": g, "name": "docker", "url": "https://docker.lan"}
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/services/{docker}", json={**base, "parent_id": node}))
    await _reauth(authed)
    assert (await authed.post(f"/api/services/{up}/maintenance", json={"minutes": 60})).status_code == 200
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/services/{docker}", json={**base, "parent_id": up}))
    # Wat eronder hangt en zelf al in onderhoud is, valt niet extra stil.
    (await db.get(Service, plex)).maintenance_until = datetime.now(timezone.utc) + timedelta(hours=2)
    await db.commit()
    assert (await authed.patch(f"/api/services/{docker}", json={**base, "parent_id": node})).status_code == 200
    (await db.get(Service, plex)).maintenance_until = None
    await db.commit()
    await agen.aclose()
    await _reauth(authed)
    assert (await authed.patch(f"/api/services/{docker}", json={**base, "parent_id": up})).status_code == 200
    assert [t for t, *_ in await _notes()][1:] == ["Afhankelijk van pve51 (in onderhoud), legt plex stil: docker"]


async def test_naar_een_groep_met_gepland_onderhoud_vraagt_2fa(authed):
    """Een venster voor een groep geldt voor alles wat er dan in zit: een tegel erin slepen, of er via de editor of een
    oude versie in zetten, legt zijn check stil. Ook vlak voor het venster begint: dan is hij er elke keer stil. Een
    venster dat voorbij is of uit staat, telt niet."""
    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    home, backup, later, past = [(await authed.post("/api/groups", json={"page_id": page, "name": n})).json()["id"]
                                 for n in ("Thuis", "Back-up", "Later", "Voorbij")]
    plex = await _svc(authed, home, "plex", {"type": "http"})
    wiki = await _svc(authed, home, "wiki")
    now = datetime.now(timezone.utc)
    sunday = now + timedelta(hours=3)
    agen, db = await _db()
    for name, group, start, on in (("nacht", backup, now - timedelta(minutes=10), True),
                                   ("vorige keer", past, now - timedelta(hours=3), True),
                                   ("oud", past, now - timedelta(minutes=10), False)):
        db.add(MaintenanceWindow(name=name, group_id=group, repeat="once", start=start, minutes=60, weekdays=[],
                                 enabled=on))
    db.add(MaintenanceWindow(name="zondag", group_id=later, repeat="weekly", start=sunday, minutes=60,
                             weekdays=[sunday.astimezone().weekday()], enabled=True))
    await db.commit()
    await agen.aclose()
    base = {"name": "plex", "url": "https://plex.lan", "check": {"type": "http"}}
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/services/{plex}", json={**base, "group_id": backup}))
    assert _needs_2fa(await authed.put("/api/layout/order", json={"services": {backup: [plex], home: [wiki]}}))
    # Een herhalend venster dat pas later loopt: bij elke keer stil.
    assert _needs_2fa(await authed.patch(f"/api/services/{plex}", json={**base, "group_id": later}))
    assert _needs_2fa(await authed.put("/api/layout/order", json={"services": {later: [plex]}}))
    agen, db = await _db()
    assert (await db.get(Service, plex)).group_id == home
    await agen.aclose()
    # Vrij: een tegel zonder check (en zonder iets eronder), een groep waar het onderhoud voorbij is of uit staat.
    assert (await authed.put("/api/layout/order", json={"services": {backup: [wiki]}})).status_code == 200
    assert (await authed.patch(f"/api/services/{plex}", json={**base, "group_id": past})).status_code == 200
    assert (await authed.put("/api/layout/order", json={"services": {home: [plex]}})).status_code == 200
    assert not await _notes()

    await _reauth(authed)
    assert (await authed.patch(f"/api/services/{plex}", json={**base, "group_id": later})).status_code == 200
    assert (await authed.put("/api/layout/order", json={"services": {backup: [wiki, plex]}})).status_code == 200
    assert [t for t, *_ in await _notes()] == [
        f"Naar groep Later (gepland onderhoud 'zondag', volgende keer {sunday.astimezone():%d/%m %H:%M}): plex",
        "Naar groep Back-up (gepland onderhoud 'nacht' loopt): plex"]
    assert (await _actions()).count("check_silenced") == 2
    # Al in die groep: de volgorde wijzigen blijft vrij.
    await _stale()
    assert (await authed.put("/api/layout/order", json={"services": {backup: [plex, wiki]}})).status_code == 200

    # Een oude versie terugzetten waarin plex in die groep zat: geen achterdeur.
    rev = (await authed.get("/api/revisions")).json()[0]["id"]
    assert (await authed.put("/api/layout/order", json={"services": {home: [plex]}})).status_code == 200
    assert _needs_2fa(await authed.post(f"/api/revisions/{rev}/restore"))
    await _reauth(authed)
    assert (await authed.post(f"/api/revisions/{rev}/restore")).status_code == 200
    agen, db = await _db()
    assert (await db.get(Service, plex)).group_id == backup
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "auth"))).scalars()]
    assert "Checks stil door een oude versie: plex" in titles
    await agen.aclose()


async def test_zonder_eigen_check_naar_een_groep_met_gepland_onderhoud_telt_wat_eronder_hangt(authed):
    """Een venster voor een groep zet ook een tegel zonder check (of gepauzeerd) in onderhoud, en onderhoud geldt voor
    alles wat eronder hangt: zo'n node in de groep zetten legt de checks van zijn CT's stil. Wat zelf al in die groep zit
    of al in onderhoud is, valt niet extra stil."""
    page = (await authed.post("/api/pages", json={"name": "P"})).json()["id"]
    home, backup = [(await authed.post("/api/groups", json={"page_id": page, "name": n})).json()["id"]
                    for n in ("Thuis", "Back-up")]
    node = await _svc(authed, home, "pve50", {"type": "ping", "paused": True})
    plex = await _svc(authed, home, "plex", {"type": "http"}, parent_id=node)
    await _svc(authed, home, "jellyfin", {"type": "http"}, parent_id=plex)
    await _svc(authed, backup, "wiki", {"type": "http"}, parent_id=node)
    nas = await _svc(authed, home, "nas")
    now = datetime.now(timezone.utc)
    agen, db = await _db()
    db.add(MaintenanceWindow(name="nacht", group_id=backup, repeat="once", start=now - timedelta(minutes=10),
                             minutes=60, weekdays=[], enabled=True))
    await db.commit()
    base = {"name": "pve50", "url": "https://pve50.lan", "check": {"type": "ping", "paused": True}}
    await _stale()
    assert _needs_2fa(await authed.patch(f"/api/services/{node}", json={**base, "group_id": backup}))
    assert _needs_2fa(await authed.put("/api/layout/order", json={"services": {backup: [node]}}))
    # Zonder iets eronder: vrij. Met alles eronder al in onderhoud ook.
    assert (await authed.put("/api/layout/order", json={"services": {backup: [nas]}})).status_code == 200
    (await db.get(Service, plex)).maintenance_until = now + timedelta(hours=2)
    await db.commit()
    assert (await authed.put("/api/layout/order", json={"services": {backup: [nas, node]}})).status_code == 200
    assert (await authed.put("/api/layout/order", json={"services": {home: [node]}})).status_code == 200
    (await db.get(Service, plex)).maintenance_until = None
    await db.commit()
    await agen.aclose()
    assert not await _notes()

    await _reauth(authed)
    assert (await authed.patch(f"/api/services/{node}", json={**base, "group_id": backup})).status_code == 200
    assert [t for t, *_ in await _notes()] == [
        "Naar groep Back-up (gepland onderhoud 'nacht' loopt), legt jellyfin en 1 andere stil: pve50"]
    # Een oude versie terugzetten waarin de node in die groep zat: geen achterdeur.
    rev = (await authed.get("/api/revisions")).json()[0]["id"]
    await _stale()
    assert (await authed.put("/api/layout/order", json={"services": {home: [node]}})).status_code == 200
    assert _needs_2fa(await authed.post(f"/api/revisions/{rev}/restore"))
