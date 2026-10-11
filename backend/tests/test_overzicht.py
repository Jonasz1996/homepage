"""Overzicht: alles wat het hoofdscherm geregeld opvraagt in één verzoek (GET /api/overzicht)."""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import httpx
import pytest
from fastapi import HTTPException
from sqlalchemy import delete, select, text

from app.attention import ACK_KEY
from app.db import get_db
from app.health import scan as hw, selfcheck as sc
from app.integrations import IntegrationError
from app.main import app
from app.models import AppState, CheckResult, CronJob, Notification, Service, ServiceState
from app.monitoring import zabbix as zmon
from app.monitoring.checks import HttpClients
from app.monitoring.updates import KEY as UPDATES_KEY
from app.routers import cron as cron_router, integrations as integrations_router, monitoring as monitoring_router
from app.routers import overzicht, zabbix as zabbix_router

from .test_integrations import Fake, _group, _svc

# deel -> het eigen endpoint (meldingen is nieuw: dat wordt met /api/notifications vergeleken).
ENDPOINTS = {"status": "/api/status", "widgets": "/api/widgets", "zabbix": "/api/zabbix", "updates": "/api/updates",
             "net": "/api/network", "cron": "/api/cron/summary", "health": "/api/health/summary",
             "aandacht": "/api/attention", "buiten": "/api/outside"}
CF = {"X-Homepage-Via-Cf": "1"}


async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


@pytest.fixture
def nep(monkeypatch):
    """De API's van de integraties nagebootst (zoals in test_integrations), met een lege cache van de tegels."""
    f = Fake()
    monkeypatch.setattr(integrations_router, "clients", HttpClients(httpx.MockTransport(f)))
    integrations_router._cache.clear()
    monkeypatch.setattr(overzicht, "_tegels_taak", None)
    monkeypatch.setattr(overzicht, "_tegels_vorige", None)
    monkeypatch.setattr(overzicht, "_tegels_begin", float("-inf"))
    return f


async def _seed(authed) -> dict:
    """Van elk deel iets: tegels (een met en een zonder geheim), een service die down is met checks, Zabbix, updates,
    het publieke IP, een mislukte cronjob, een worker die stilviel, meldingen en een genegeerd punt dat weg is."""
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be", name="pve",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"})
    ag = await _svc(authed, g, "adguard", "https://adguard.jbogaert.be", name="AdGuard")  # geheim ontbreekt
    r = await authed.post("/api/services", json={"group_id": g, "name": "web", "url": "https://web.lan",
                                                 "check": {"type": "http"}, "config": {"mac": "AA:BB:CC:DD:EE:FF"}})
    assert r.status_code == 201, r.text
    web = r.json()["id"]
    now = datetime.now(timezone.utc)
    agen, db = await _db()
    (await db.get(Service, pve)).check = {"type": "http"}
    db.add(ServiceState(service_id=web, status="down", since=now - timedelta(minutes=20), last_check=now,
                        fail_count=3, last_error="Time-out"))
    db.add(ServiceState(service_id=pve, status="up", since=now - timedelta(days=2), last_check=now, latency_ms=12.5))
    for i in range(6):
        db.add(CheckResult(service_id=web, ts=now - timedelta(minutes=50 - i * 5), ok=i < 3,
                           latency_ms=20.0 + i if i < 3 else None))
        db.add(CheckResult(service_id=pve, ts=now - timedelta(minutes=50 - i * 5), ok=True, latency_ms=10.0 + i))
    db.add(AppState(key=zmon.STATE_KEY, value={
        "service_id": pve, "at": now.isoformat(), "url": "https://zabbix.lan", "error": None,
        "hosts": [{"id": "1", "name": "pve50", "host": "pve50", "down": False, "ips": ["192.168.0.50"]},
                  {"id": "2", "name": "nas", "host": "nas", "down": True, "ips": []}],
        "map": {str(pve): [{"id": "1", "role": "eigen"}, {"id": "2", "role": "node"}]},
        "problems": [{"host_id": "1", "name": "Hoge CPU op pve50", "severity": 4}]}))
    db.add(AppState(key=UPDATES_KEY, value={"checked_at": now.isoformat(), "targets": [
        {"key": "ct:101", "name": "pve", "kind": "ct", "count": 4, "security": 1, "service_id": pve},
        {"key": "host:pve50", "name": "web", "kind": "host", "count": 2}]}))
    db.add(AppState(key="public_ip", value={"ip": "203.0.113.7", "since": now.isoformat(),
                                            "checked_at": now.isoformat(), "history": []}))
    job = CronJob(key="k1", target="ssh:1", target_name="pve2", kind="crontab", name="rsync", last_status="fout",
                  last_exit=2, last_run_at=now - timedelta(hours=1))
    db.add(job)
    db.add(CronJob(key="k2", target="ssh:1", target_name="pve2", kind="crontab", name="backup", last_status="gemist"))
    # Laatste teken van leven 30,5 min geleden: de workercheck van gezondheid meldt dat (één keer) en bewaart het.
    stil = now - timedelta(minutes=30, seconds=30)
    db.add(AppState(key=sc.HEARTBEAT_KEY, value={"at": stil.isoformat(), "started": stil.isoformat()}))
    db.add(AppState(key=hw.STATE_KEY, value={"hosts": [{"name": "pve50", "cpu_temp": 91, "pools": [],
                                                        "disks": [{"name": "sda", "level": "warn"}]}]}))
    db.add(AppState(key=ACK_KEY, value={"items": {"weg:al-lang": {"sig": "x", "at": now.isoformat(), "by": "jonas"}}}))
    db.add(Notification(title="Eerste", level="info", source="system"))
    db.add(Notification(title="Gelezen", level="warn", source="system", read_at=now))
    await db.commit()
    await agen.aclose()
    return {"pve": pve, "ag": ag, "web": web, "job": job.id}


def _zonder_tijd(data: dict) -> dict:
    # Het aandacht-overzicht zegt wanneer het rekende.
    return {k: v for k, v in data.items() if k != "at"}


async def _zelfde_als_eigen_endpoints(authed, delen: dict) -> None:
    for naam, data in delen.items():
        if naam == "meldingen":
            eigen = (await authed.get("/api/notifications")).json()
            nieuwste = eigen["items"][0] if eigen["items"] else None
            assert data == {"unread": eigen["unread"], "newest": {
                k: nieuwste[k] for k in ("id", "level", "read", "title")} if nieuwste else None}
            continue
        eigen = await authed.get(ENDPOINTS[naam])
        assert eigen.status_code == 200, (naam, eigen.text)
        if naam == "aandacht":
            assert _zonder_tijd(data) == _zonder_tijd(eigen.json())
        else:
            assert data == eigen.json(), naam


async def test_alle_delen_zoals_hun_eigen_endpoint(authed, nep):
    ids = await _seed(authed)
    ongelezen = (await authed.get("/api/notifications")).json()["unread"]
    r = await authed.get("/api/overzicht")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"tijd", "delen", "fouten"}
    tijd = datetime.fromisoformat(body["tijd"])
    assert tijd.utcoffset() == timedelta(0) and abs(datetime.now(timezone.utc) - tijd) < timedelta(minutes=1)
    assert body["fouten"] == {}
    assert list(body["delen"]) == list(overzicht.DELEN)
    d = body["delen"]
    # Er zit echt iets in (anders bewijst de vergelijking hieronder weinig).
    assert d["status"][str(ids["web"])]["status"] == "down" and d["status"][str(ids["web"])]["spark"]
    assert {f["label"] for f in d["widgets"][str(ids["pve"])]["fields"]} >= {"VM", "nodes"}
    assert "Geheim ontbreekt" in d["widgets"][str(ids["ag"])]["error"]
    assert d["zabbix"]["services"][str(ids["pve"])]["level"] == "err"
    assert d["updates"]["total"] == 6 and d["updates"]["by_service"][str(ids["pve"])]["security"] == 1
    assert d["net"]["public_ip"]["ip"] == "203.0.113.7" and d["net"]["wol"][0]["service_id"] == ids["web"]
    assert d["cron"] == {"fout": 1, "gemist": 1}
    assert "worker draait niet" in d["health"]["problems"] and d["health"]["hot"] == ["pve50"]
    keys = {i["key"] for i in d["aandacht"]["items"]}
    # aandacht komt na de tegels: de fout van de tegel zonder geheim staat er al in.
    assert f"api:{ids['ag']}" in keys and f"cron:{ids['job']}" in keys and "updates" in keys
    assert d["buiten"]["outside"] is False and d["buiten"]["why"] == "thuisnetwerk"
    # De workercheck van gezondheid is bewaard, en meldingen (daarna) telt die melding al mee.
    assert d["meldingen"]["unread"] == ongelezen + 1
    assert d["meldingen"]["newest"]["title"] == "De worker van de homepage draait niet"
    assert set(d["meldingen"]["newest"]) == {"id", "level", "read", "title"}
    assert d["meldingen"]["newest"]["read"] is False and d["meldingen"]["newest"]["level"] == "err"

    agen, db = await _db()
    assert (await db.get(AppState, "worker_alert")).value == {"down": True}
    # Aandacht vergat het genegeerde punt dat er niet meer is, en bewaarde dat.
    assert (await db.get(AppState, ACK_KEY)).value["items"] == {}
    await agen.aclose()

    await _zelfde_als_eigen_endpoints(authed, d)
    # Nog een keer: de workercheck meldde al, dus er komt geen tweede melding bij (zoals bij /api/health/summary).
    again = (await authed.get("/api/overzicht", params={"delen": "health,meldingen"})).json()
    assert again["delen"]["meldingen"] == d["meldingen"]


async def test_meldingen_zonder_meldingen(authed):
    agen, db = await _db()
    await db.execute(delete(Notification))  # "2FA ingeschakeld" van het instellen
    await db.commit()
    await agen.aclose()
    r = (await authed.get("/api/overzicht", params={"delen": "meldingen"})).json()
    assert r == {"tijd": r["tijd"], "delen": {"meldingen": {"unread": 0, "newest": None}}, "fouten": {}}


async def test_alleen_de_gevraagde_delen(authed, nep):
    await _seed(authed)
    r = await authed.get("/api/overzicht", params={"delen": "status,meldingen"})
    assert r.status_code == 200, r.text
    assert list(r.json()["delen"]) == ["status", "meldingen"] and r.json()["fouten"] == {}
    # De tegels niet gevraagd: geen berekening gestart, geen API van een integratie gevraagd.
    assert overzicht._tegels_taak is None and nep.calls == []
    await _zelfde_als_eigen_endpoints(authed, r.json()["delen"])

    # Spaties en lege stukken tellen niet; zonder (of met een lege) delen: alles.
    r = (await authed.get("/api/overzicht", params={"delen": " net , cron,,"})).json()
    assert list(r["delen"]) == ["net", "cron"]
    for params in ({"delen": ""}, {"delen": " , "}, {}):
        assert list((await authed.get("/api/overzicht", params=params)).json()["delen"]) == list(overzicht.DELEN)


async def test_onbekend_deel_geeft_422(authed, monkeypatch):
    called = []
    monkeypatch.setattr(cron_router, "summary", lambda **kw: called.append(1))
    r = await authed.get("/api/overzicht", params={"delen": "status,bestaatniet"})
    assert r.status_code == 422
    assert r.json()["detail"].startswith("Onbekend deel: bestaatniet") and "status" in r.json()["detail"]
    r = await authed.get("/api/overzicht", params={"delen": "cron,x,y"})
    assert r.status_code == 422 and r.json()["detail"].startswith("Onbekende delen: x, y")
    assert called == []  # er liep niets


async def test_zonder_login_401(client):
    assert (await client.get("/api/overzicht")).status_code == 401
    assert (await client.get("/api/overzicht", params={"delen": "meldingen"})).status_code == 401


async def test_buiten_kijkt_naar_het_verzoek(authed):
    """buiten vraagt het verzoek zelf (van waar het komt) en onthoudt een bezoek van buitenaf, zoals /api/outside."""
    r = (await authed.get("/api/overzicht", params={"delen": "buiten"}, headers=CF)).json()
    b = r["delen"]["buiten"]
    assert b["outside"] is True and b["why"] == "via Cloudflare" and b["seen"]["visits"] == 1
    eigen = (await authed.get("/api/outside", headers=CF)).json()
    assert eigen["seen"]["visits"] == 2
    assert {k: v for k, v in b.items() if k != "seen"} == {k: v for k, v in eigen.items() if k != "seen"}
    # Thuis: geen bezoek erbij.
    r = (await authed.get("/api/overzicht", params={"delen": "buiten"})).json()
    assert r["delen"]["buiten"]["outside"] is False and r["delen"]["buiten"]["seen"]["visits"] == 2


async def test_een_deel_dat_misloopt_breekt_de_rest_niet(authed, nep, monkeypatch, caplog):
    await _seed(authed)

    async def stuk(**kw):
        raise RuntimeError("wachtwoord=geheim123 in een stacktrace")

    async def weg(**kw):
        raise HTTPException(404, "Zabbix-tegel niet gevonden")

    with monkeypatch.context() as m:
        m.setattr(cron_router, "summary", stuk)
        m.setattr(zabbix_router, "zabbix_status", weg)
        m.setattr(integrations_router, "widgets", stuk)
        r = await authed.get("/api/overzicht")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["fouten"] == {"widgets": "onverwachte fout", "zabbix": "Zabbix-tegel niet gevonden",
                              "cron": "onverwachte fout"}
    assert list(body["delen"]) == [d for d in overzicht.DELEN if d not in ("widgets", "zabbix", "cron")]
    assert "geheim123" not in r.text and "Traceback" not in r.text
    # Wel in de log, voor wie het moet uitzoeken.
    assert "overzicht: deel cron mislukt" in caplog.text and "overzicht: tegels laden mislukt" in caplog.text
    await _zelfde_als_eigen_endpoints(authed, {k: v for k, v in body["delen"].items() if k != "aandacht"})
    # De tegels gaven geen fout: aandacht ziet dus (nog) geen tegel met een fout, zoals het eigen endpoint toen.
    assert not [i for i in body["delen"]["aandacht"]["items"] if i["key"].startswith("api:")]


async def test_databasefout_in_een_deel(authed, nep, monkeypatch):
    """Een deel met een databasefout (half werk erin): teruggedraaid, en de delen erna werken gewoon (PostgreSQL weigert
    anders alles tot het einde van de transactie). Het halve werk van dat deel wordt niet met een later deel bewaard."""
    await _seed(authed)

    async def kapot(user, db):
        db.add(Notification(title="Half werk", level="info", source="system"))
        await db.flush()
        await db.execute(text("SELECT geen_kolom FROM bestaat_niet"))

    # Eerst zonder de tegels: die hebben een eigen sessie, maar in de tests met SQLite delen alle sessies één
    # verbinding, en het sluiten van die van de tegels zou het halve werk dan toevallig ook terugdraaien.
    zonder_tegels = [d for d in overzicht.DELEN if d != "widgets"]
    with monkeypatch.context() as m:
        m.setattr(monitoring_router, "all_status", kapot)
        r = await authed.get("/api/overzicht", params={"delen": ",".join(zonder_tegels)})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["fouten"] == {"status": "databasefout"}
    assert "bestaat_niet" not in r.text
    assert list(body["delen"]) == [d for d in zonder_tegels if d != "status"]
    # Ook de delen die daarna iets bewaren (gezondheid, aandacht): gelukt en bewaard.
    agen, db = await _db()
    assert (await db.get(AppState, "worker_alert")).value == {"down": True}
    assert (await db.get(AppState, ACK_KEY)).value["items"] == {}
    assert (await db.execute(select(Notification).where(Notification.title == "Half werk"))).first() is None
    await agen.aclose()
    assert body["delen"]["meldingen"]["newest"]["title"] == "De worker van de homepage draait niet"
    await _zelfde_als_eigen_endpoints(authed, body["delen"])

    # Met alles erbij: alleen status ontbreekt.
    with monkeypatch.context() as m:
        m.setattr(monitoring_router, "all_status", kapot)
        alles = await authed.get("/api/overzicht")
    assert alles.status_code == 200, alles.text
    assert alles.json()["fouten"] == {"status": "databasefout"}
    assert list(alles.json()["delen"]) == [d for d in overzicht.DELEN if d != "status"]
    await _zelfde_als_eigen_endpoints(authed, alles.json()["delen"])


async def test_trage_tegels(authed, nep, monkeypatch):
    """Tegels trager dan het budget: antwoord zonder, de berekening loopt verder en vult de cache. Zolang ze loopt,
    start er geen tweede; de vraag daarna krijgt de tegels uit de cache."""
    g = await _group(authed)
    sid = await _svc(authed, g, "adguard", "https://adguard.jbogaert.be", secrets={"username": "a", "password": "b"})
    monkeypatch.setattr(overzicht, "WIDGETS_BUDGET", 0.3)
    los = asyncio.Event()
    started = []
    echt = integrations_router._fields

    async def traag(i):
        started.append(1)
        await los.wait()
        return await echt(i)

    monkeypatch.setattr(integrations_router, "_fields", traag)
    r = (await authed.get("/api/overzicht")).json()
    assert r["fouten"] == {"widgets": "te traag, volgende keer"}
    assert list(r["delen"]) == [d for d in overzicht.DELEN if d != "widgets"]
    taak = overzicht._tegels_taak
    assert taak is not None and not taak.done() and started == [1]

    # Loopt nog: dezelfde berekening, geen tweede.
    r = (await authed.get("/api/overzicht", params={"delen": "widgets,cron"})).json()
    assert r["fouten"] == {"widgets": overzicht.TRAAG} and list(r["delen"]) == ["cron"]
    assert overzicht._tegels_taak is taak and started == [1]

    los.set()
    await asyncio.wait_for(asyncio.shield(taak), 5)
    r = (await authed.get("/api/overzicht", params={"delen": "widgets"})).json()
    assert r["fouten"] == {}
    w = r["delen"]["widgets"]
    assert {f["label"]: f["value"] for f in w[str(sid)]["fields"]}["geblokkeerd"] == "12.5%"
    assert started == [1]  # uit de cache: de API niet opnieuw gevraagd
    assert w == (await authed.get("/api/widgets")).json() and started == [1]
    assert overzicht._tegels_taak.done()


async def test_vers_na_een_wijziging(authed, nep, monkeypatch):
    """Na een gewijzigde tegel vraagt het scherm de tegels met vers=1: dan niet aansluiten bij een berekening die nog
    loopt (die las de tegel van vóór de wijziging), maar opnieuw rekenen. De oude berekening die pas daarna afloopt,
    overschrijft de nieuwe vorige stand niet."""
    g = await _group(authed)
    sid = await _svc(authed, g, "adguard", "https://oud.jbogaert.be", secrets={"username": "a", "password": "b"})
    los = asyncio.Event()
    echt = integrations_router._fields

    async def velden(i):
        if "oud" in i.base:
            await los.wait()
            raise IntegrationError("Time-out")
        return await echt(i)

    monkeypatch.setattr(integrations_router, "_fields", velden)
    monkeypatch.setattr(overzicht, "WIDGETS_BUDGET", 0.2)
    r = (await authed.get("/api/overzicht", params={"delen": "widgets"})).json()
    assert r["fouten"] == {"widgets": overzicht.TRAAG}
    oud = overzicht._tegels_taak
    assert not oud.done()

    r = await authed.patch(f"/api/services/{sid}", json={"group_id": g, "name": "X", "url": "https://adguard.jbogaert.be", "type": "adguard", "config": {}})
    assert r.status_code == 200, r.text
    monkeypatch.setattr(overzicht, "WIDGETS_BUDGET", 2)
    # Zonder vers: dezelfde (oude) berekening, die nog loopt.
    await authed.get("/api/overzicht", params={"delen": "widgets", "vers": "0"})
    assert overzicht._tegels_taak is oud
    # Met vers: een nieuwe, met het nieuwe adres.
    r = (await authed.get("/api/overzicht", params={"delen": "widgets", "vers": "1"})).json()
    assert overzicht._tegels_taak is not oud and r["fouten"] == {}
    assert {f["label"]: f["value"] for f in r["delen"]["widgets"][str(sid)]["fields"]}["geblokkeerd"] == "12.5%"
    nieuw = overzicht._tegels_vorige

    los.set()
    await asyncio.wait_for(asyncio.shield(oud), 5)
    assert overzicht._tegels_vorige is nieuw


async def test_trage_kapotte_tegel_geeft_de_vorige_stand(authed, nep, monkeypatch):
    """Een tegel die pas na het budget een fout geeft (een host die niet antwoordt: de time-out van een integratie is
    even lang als het budget). Die fout blijft maar 10 s in de cache en het scherm vraagt elke 60 s, dus elke
    berekening mist het budget. Het overzicht antwoordt dan met de vorige stand (de berekening van de vraag ervoor, die
    op de achtergrond afliep), ook met de gezonde tegels erin, in plaats van nooit meer tegels te geven."""
    g = await _group(authed)
    goed = await _svc(authed, g, "adguard", "https://adguard.jbogaert.be", secrets={"username": "a", "password": "b"})
    dood = await _svc(authed, g, "adguard", "https://dood.jbogaert.be", secrets={"username": "a", "password": "b"})
    monkeypatch.setattr(overzicht, "WIDGETS_BUDGET", 0.3)
    # De klok van de cache van de tegels: zo ligt er een minuut tussen twee vragen, zonder te wachten.
    klok = [0.0]
    monkeypatch.setattr(integrations_router, "time", SimpleNamespace(monotonic=lambda: time.monotonic() + klok[0]))
    echt = integrations_router._fields
    gevraagd = []

    async def velden(i):
        gevraagd.append("dood" if "dood" in i.base else "goed")
        if "dood" in i.base:
            await asyncio.sleep(0.5)
            raise IntegrationError("Time-out")
        return await echt(i)

    monkeypatch.setattr(integrations_router, "_fields", velden)

    async def vraag() -> dict:
        r = await authed.get("/api/overzicht", params={"delen": "widgets,cron"})
        assert r.status_code == 200, r.text
        # De berekening rekent op de achtergrond verder: laten aflopen, zoals vóór de volgende vraag.
        await asyncio.wait_for(asyncio.shield(overzicht._tegels_taak), 5)
        return r.json()

    # Nog geen vorige stand: zonder tegels.
    r = await vraag()
    assert r["fouten"] == {"widgets": overzicht.TRAAG} and list(r["delen"]) == ["cron"]
    assert sorted(gevraagd) == ["dood", "goed"]
    eerste = overzicht._tegels_vorige[1]
    assert eerste[str(dood)] == {"error": "Time-out"} and eerste[str(goed)]["fields"]

    # Een minuut later: de fout van de dode tegel is verlopen (de goede tegel staat nog in de cache), dus weer te
    # traag. Nu met de vorige stand, en die is wat /api/widgets gaf.
    klok[0] += 60
    r = await vraag()
    assert r["fouten"] == {"widgets": overzicht.VORIGE}
    assert list(r["delen"]) == ["widgets", "cron"] and r["delen"]["widgets"] == eerste
    assert sorted(gevraagd) == ["dood", "dood", "goed"]  # één berekening per vraag
    assert r["delen"]["widgets"] == (await authed.get("/api/widgets")).json()

    # Nog een minuut later (ook de goede tegel is verlopen): de stand van de berekening van de vorige vraag.
    klok[0] += 60
    tweede = overzicht._tegels_vorige
    r = await vraag()
    assert r["fouten"] == {"widgets": overzicht.VORIGE} and r["delen"]["widgets"] == tweede[1]
    assert sorted(gevraagd) == ["dood", "dood", "dood", "goed", "goed"]
    assert overzicht._tegels_vorige[0] > tweede[0]

    # Een vorige stand die te oud is (niemand vroeg nog tegels): dan toch zonder.
    t, w = overzicht._tegels_vorige
    monkeypatch.setattr(overzicht, "_tegels_vorige", (t - overzicht.VORIGE_MAX - 1, w))
    klok[0] += 60
    r = await vraag()
    assert r["fouten"] == {"widgets": overzicht.TRAAG} and list(r["delen"]) == ["cron"]


async def test_geen_open_transactie_tijdens_het_wachten_op_de_tegels(authed, nep, monkeypatch):
    """Terwijl het overzicht op trage tegels wacht, houdt het verzoek geen databaseverbinding vast (een open
    transactie), zoals /api/widgets zelf: de delen ervoor zijn afgesloten. aandacht daarna werkt gewoon."""
    await _seed(authed)
    monkeypatch.setattr(overzicht, "WIDGETS_BUDGET", 0.3)
    los = asyncio.Event()
    echt = integrations_router._fields

    async def traag(i):
        await los.wait()
        return await echt(i)

    monkeypatch.setattr(integrations_router, "_fields", traag)
    # De sessies die het verzoek krijgt: de eerste is die van het verzoek zelf, daarna die van de tegels.
    sessies = []
    maak = app.dependency_overrides[get_db]

    async def _sessie():
        agen = maak()
        s = await agen.__anext__()
        sessies.append(s)
        try:
            yield s
        finally:
            await agen.aclose()

    monkeypatch.setitem(app.dependency_overrides, get_db, _sessie)
    tijdens = []
    wacht = overzicht._wacht_op_tegels

    async def wacht_en_kijk(taak, *a):
        tijdens.append({"transactie": sessies[0].in_transaction(), "tegels klaar": taak.done()})
        return await wacht(taak, *a)

    monkeypatch.setattr(overzicht, "_wacht_op_tegels", wacht_en_kijk)
    r = await authed.get("/api/overzicht")
    assert r.status_code == 200, r.text
    assert tijdens == [{"transactie": False, "tegels klaar": False}]
    body = r.json()
    assert body["fouten"] == {"widgets": overzicht.TRAAG}
    assert list(body["delen"]) == [d for d in overzicht.DELEN if d != "widgets"]
    los.set()
    await asyncio.wait_for(asyncio.shield(overzicht._tegels_taak), 5)
    # Wat de delen bewaarden, is bewaard (gezondheid voor het wachten, aandacht erna).
    agen = maak()
    db = await agen.__anext__()
    assert (await db.get(AppState, "worker_alert")).value == {"down": True}
    assert (await db.get(AppState, ACK_KEY)).value["items"] == {}
    await agen.aclose()
    # aandacht rekende vóór de tegels klaar waren (zonder hun fouten): het eigen endpoint ziet die nu wel.
    await _zelfde_als_eigen_endpoints(authed, {k: v for k, v in body["delen"].items() if k != "aandacht"})
