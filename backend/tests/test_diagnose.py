"""Diagnose-export (knop onder !): toegang, inhoud, geheimen gemaskeerd, geen bijwerkingen, en de logregels van de
processen (logring)."""

import asyncio
import json
import logging
import os
import platform
import time
from datetime import datetime, timezone
from types import SimpleNamespace
from urllib.parse import quote

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker

from app import diagnose, logring, proef, setupcheck
from app.config import get_settings
from app.masking import basic
from app.models import (ApiConnection, AppState, AuditLog, Event, HealRule, Notification, PushMonitor,
                        PushSubscription, Service, ServiceState, SshHost, SshKey, UpdateRun, User, WebhookSource)
from app.monitoring.checks import HttpClients
from app.monitoring.worker import Worker
from app.routers import attention as attention_router
from app.routers import diagnose as diagnose_router
from app.routers import integrations as integ
from app.security import encrypt, encrypt_json

from .test_buitenaf import CF, _stale
from .test_integrations import _group, _svc
from .test_meldingen_onderhoud import _db
from .test_verbindingen import _idle_in_transaction


@pytest.fixture
def ring(monkeypatch):
    """logring.install() in een test: daarna de handlers en niveaus terug zoals ze waren."""
    root = logging.getLogger()
    levels = {n: logging.getLogger(n).level for n in ("", *logring.QUIET)}
    monkeypatch.setattr(logring, "_ring", None)
    monkeypatch.setattr(logring, "_started", None)
    monkeypatch.setattr(logring, "_flushed", {})
    yield
    for lg in (root, logging.getLogger("uvicorn.error")):
        for h in list(lg.handlers):
            if isinstance(h, (logring.RingHandler, logring._Stderr)):
                lg.removeHandler(h)
    for n, lv in levels.items():
        logging.getLogger(n).setLevel(lv)


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """De checklist in de export vraagt de API's van de tegels: in de tests nooit echt het netwerk op."""
    monkeypatch.setattr(integ, "clients", HttpClients(httpx.MockTransport(lambda r: httpx.Response(503))))


async def _diagnose(c, **kw) -> dict:
    r = await c.get("/api/diagnose", **kw)
    assert r.status_code == 200, r.text
    return r.json()


# --- toegang ---------------------------------------------------------------------------------------------------

async def test_zonder_login(client):
    assert (await client.get("/api/diagnose")).status_code == 401


async def test_vraagt_2fa_staat_buiten_uit_en_laat_een_spoor(authed):
    r = await authed.get("/api/diagnose?frontend=31")
    assert r.status_code == 200, r.text
    assert r.headers["content-disposition"].startswith('attachment; filename="homepage-diagnose-')
    d = r.json()
    assert d["formaat"] == 1 and r.headers["content-disposition"] == f'attachment; filename="{d["bestand"]}"'
    for k in ("versie", "processen", "aandacht", "instellingen", "integraties", "achtergrond", "webhooks",
              "pushtoestellen", "zelfherstel", "updates", "cron", "meldingen", "tijdlijn", "audit", "proef", "logs",
              "gemaskeerd"):
        assert k in d, k

    agen, db = await _db()
    rows = list((await db.execute(select(AuditLog).where(AuditLog.action == "diagnose_download"))).scalars())
    assert len(rows) == 1
    assert "logs" in rows[0].detail["sections"] and rows[0].detail["bytes"] == len(r.content)
    await agen.aclose()

    r = await authed.get("/api/diagnose", headers=CF)
    assert r.status_code == 403 and r.json()["detail"] == "buiten:downloads"
    await _stale(authed)
    r = await authed.get("/api/diagnose")
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    # Van buitenaf eerst de buitenmodus, zoals bij een configuratie downloaden.
    assert (await authed.get("/api/diagnose", headers=CF)).json()["detail"] == "buiten:downloads"


async def test_een_tegelijk(authed, monkeypatch):
    gate = asyncio.Event()
    real = setupcheck.run

    async def slow(*a, **kw):
        await gate.wait()
        return await real(*a, **kw)
    monkeypatch.setattr(setupcheck, "run", slow)
    first = asyncio.create_task(authed.get("/api/diagnose"))
    for _ in range(200):
        if diagnose_router._lock.locked():
            break
        await asyncio.sleep(0.01)
    r = await authed.get("/api/diagnose")
    assert r.status_code == 409
    gate.set()
    assert (await first).status_code == 200
    assert not diagnose_router._lock.locked()


# --- inhoud ----------------------------------------------------------------------------------------------------

async def test_versies(authed, tmp_path, monkeypatch):
    f = tmp_path / "versie"
    f.write_text("versie=v1.2.0\ncommit=abc123def\nkanaal=stabiel\ndatum=2026-10-05T14:00:00+02:00\n")
    monkeypatch.setattr(get_settings(), "version_file", f)
    await authed.post("/api/version/seen", json={"id": "30"})
    v = (await _diagnose(authed, params={"frontend": 31}))["versie"]
    assert (v["versie"], v["commit"], v["kanaal"]) == ("v1.2.0", "abc123def", "stabiel")
    assert v["frontend_nieuws"] == 31 and v["gezien"] == "30"
    assert v["python"] == platform.python_version() and v["pakketten"]["fastapi"]
    db = v["database"]
    if db["soort"] == "postgresql":
        assert db["server_version"] and db["grootte"]["total"] > 0
    else:
        # SQLite (de tests): geen PostgreSQL-gegevens, en geen fout.
        assert db == {"soort": "sqlite", "server_version": None, "timescaledb": None, "alembic": None,
                      "hypertables": None, "grootte": None}
    assert (await authed.get("/api/diagnose", params={"frontend": -1})).status_code == 422


async def test_processen_aandacht_en_integraties(authed, monkeypatch):
    g = await _group(authed)
    sid = await _svc(authed, g, "link", "https://plex.lan", name="Plex")
    agen, db = await _db()
    api = ApiConnection(name="radarr-api", kind="rest", url="https://radarr.lan")
    db.add(api)
    await db.flush()
    (await db.get(Service, sid)).api_id = api.id
    db.add(ServiceState(service_id=sid, status="up", fail_count=0))
    db.add(AppState(key="worker", value={"at": datetime.now(timezone.utc).isoformat(), "started": "x", "pid": 4242}))
    await db.commit()
    await agen.aclose()
    monkeypatch.setitem(integ._cache, (sid, "summary"), (0.0, (), {"error": "HTTP 401 van radarr"}))

    d = await _diagnose(authed)
    p = d["processen"]
    assert p["api"]["pid"] == os.getpid() and p["worker"]["ok"] is True and p["worker"]["pid"] == 4242
    [row] = [r for r in d["integraties"] if r["id"] == sid]
    assert row["api"] == {"kind": "rest", "name": "radarr-api"} and row["tegel_fout"] == "HTTP 401 van radarr"
    assert row["status"] == "up" and "url" not in row
    assert any(i["key"] == f"api:{sid}" for i in d["aandacht"]["items"])
    assert "stale" not in d["aandacht"]
    assert d["instellingen"]["counts"]["ok"] >= 0 and d["instellingen"]["groups"]


async def test_geen_transactie_open_terwijl_de_api_s_antwoorden(authed, monkeypatch):
    seen = []
    real = attention_router._widgets

    async def widgets(svcs):
        seen.append(await _idle_in_transaction())
        return await real(svcs)
    monkeypatch.setattr(attention_router, "_widgets", widgets)
    await _diagnose(authed)
    assert seen == [0]


async def test_checklist_te_traag(authed, monkeypatch):
    async def slow(*a, **kw):
        await asyncio.sleep(5)
    monkeypatch.setattr(setupcheck, "run", slow)
    monkeypatch.setattr(diagnose, "SETUP_TIMEOUT", 0.2)
    d = await _diagnose(authed)
    assert d["instellingen"] == {"fout": "time-out"}
    # De rest is er gewoon.
    assert d["versie"]["versie"] and d["aandacht"]["counts"] is not None and "api" in d["logs"]
    assert any(a["action"] == "setup" for a in d["audit"])


async def test_achtergrond_alleen_tijdstippen_fouten_en_aantallen(authed):
    agen, db = await _db()
    now = datetime.now(timezone.utc).isoformat()
    db.add_all([
        AppState(key="updates", value={"checked_at": now, "targets": [
            {"key": "ssh:1", "name": "pve50", "count": 3, "packages": [{"n": "openssl-pakket"}], "error": None},
            {"key": "ssh:2", "name": "nas", "error": "SSH: verbinding geweigerd", "packages": []}]}),
        AppState(key="pbs_problems:3", value={"keys": ["ds:ct/105:task"],
                                              "items": {"ds:ct/105:task": "ds:ct/105: mislukt"}}),
        AppState(key="net_gw:4", value={"checked_at": now, "error": "OPNsense: 401", "track": ["WAN"],
                                        "items": [{"name": "WAN", "level": "ok"}]}),
        AppState(key="restoretest", value={"settings": {"enabled": True}, "last_at": now, "history": [
            {"at": now, "ok": False, "step": "opstarten", "error": "CT draait niet", "volid": "pbs:backup/ct/105"}]}),
        AppState(key="selfcheck", value={"checked_at": now, "stale": False,
                                         "backups": [{"name": f"d{i}"} for i in range(9)],
                                         "offsite": {"enabled": True, "dir": "/mnt/homepage-backup", "error": "vol",
                                                     "files": ["x"]}}),
        AppState(key="zomaar_iets", value={"error": "hoort er niet bij"}),
        AppState(key="offsite_key", value={"blob": "OFFSITE-BLOB-MARKER"}),
        AppState(key="ssh_snippets", value={"items": [{"cmd": "echo SNIPPET-MARKER"}]}),
        AppState(key="outside_seen", value={"last": {"ip": "OUTSIDE-SEEN-MARKER"}}),
        AppState(key="ssh_pin", value={"marker": "SSH-PIN-MARKER"}),
    ])
    await db.commit()
    await agen.aclose()

    d = await _diagnose(authed)
    a = d["achtergrond"]
    assert set(a) == {"updates", "pbs_problems:3", "net_gw:4", "restoretest", "selfcheck"}
    assert a["updates"] == {"checked_at": now, "targets": {
        "aantal": 2, "fouten": [{"key": "ssh:2", "name": "nas", "error": "SSH: verbinding geweigerd"}]}}
    assert a["pbs_problems:3"] == {"aantal": 1, "problemen": ["ds:ct/105: mislukt"]}
    assert a["net_gw:4"] == {"checked_at": now, "error": "OPNsense: 401", "track": {"aantal": 1},
                             "items": {"aantal": 1}}
    assert a["restoretest"]["laatste"]["error"] == "CT draait niet" and a["restoretest"]["tests"] == 1
    assert len(a["selfcheck"]["backups"]) == 3 and a["selfcheck"]["offsite"]["error"] == "vol"
    raw = json.dumps(d)
    for marker in ("openssl-pakket", "OFFSITE-BLOB-MARKER", "SNIPPET-MARKER", "OUTSIDE-SEEN-MARKER", "SSH-PIN-MARKER",
                   "hoort er niet bij", "pbs:backup/ct/105"):
        assert marker not in raw, marker
    assert not set(diagnose.BACKGROUND) & set(diagnose.DENY)


async def test_proef_in_de_export(authed):
    g = await _group(authed)
    sid = await _svc(authed, g, "link", "https://plex.lan", name="Plex")
    plan = proef.plan("Nachtelijke updates", [proef.step("pve50 (root@192.168.0.50:22)", "ssh", "apt-get upgrade",
                                                         who="root")])
    agen, db = await _db()
    db.add_all([
        AppState(key="update_settings", value={"auto": True, "hour": 4, "keep_days": 7, "proef": True}),
        AppState(key="update_auto_proef", value=plan),
        AppState(key="restoretest", value={"settings": {"enabled": True, "dry": True}, "dry_history": [
            {"at": "2026-10-01T05:00:00+00:00", "plan": plan, "manual": False},
            {"at": "2026-10-08T05:00:00+00:00", "plan": plan, "manual": True}]}),
        HealRule(service_id=sid, action={"kind": "ssh", "host_id": 1, "op": "systemctl", "name": "plex",
                                         "params": {"x": "y"}}, last_result="herstart"),
    ])
    proef.record(db, "updates", "Nachtelijke updates", plan)
    await db.commit()
    notes = (await db.execute(select(func.count()).select_from(Notification))).scalar()
    await agen.aclose()

    d = await _diagnose(authed)
    p = d["proef"]
    assert p["vlaggen"] == {"update_settings.proef": True, "update_settings.cleanup_proef": False,
                            "heal_rules.dry_run": 0, "restoretest.dry": True}
    assert p["update_auto_proef"]["steps"][0]["call"] == "apt-get upgrade" and p["update_cleanup_proef"] is None
    assert [h["at"] for h in p["restoretest_dry_history"]] == ["2026-10-08T05:00:00+00:00", "2026-10-01T05:00:00+00:00"]
    [e] = p["tijdlijn"]
    assert e["title"] == "Proef: Nachtelijke updates" and e["plan"]["steps"][0]["machine"].startswith("pve50")
    [h] = d["zelfherstel"]
    assert h["dry_run"] is False and h["actie"] == {"kind": "ssh", "op": "systemctl", "name": "plex", "host_id": 1}
    assert h["last_result"] == "herstart"
    # De export schreef geen melding.
    agen, db = await _db()
    assert (await db.execute(select(func.count()).select_from(Notification))).scalar() == notes
    await agen.aclose()


# --- geheimen --------------------------------------------------------------------------------------------------

SECRETS = {
    "svc": "SVC-geheim-7f3a9c",
    "api": "0b1c2d3e-aaaa-4bbb-8ccc-1234567890ab",
    "api_actie": "ACTIE-geheim-5d6e7f",
    "ssh": "ssh/wacht+woord=9911",
    "sshdef": "standaard-wachtwoord-4242",
    "hook": "HookToken0123456789abcdefXYZ",
    "push": "PushToken0123456789abcdefXYZ",
    "endpoint": "EndpointGeheim1234567890",
    "p256dh": "BP256dhGeheimeSleutel0987654321",
    "auth": "AuthGeheim1234",
    "oidc": "oidc-client-geheim-55",
    "webpush": "webpush-prive-sleutel-66",
    "keyline": "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAAB",
    "db": "db-wachtwoord-77",
}
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlMTIz"


async def test_geheimen_gemaskeerd(authed, ring, monkeypatch):
    s = SECRETS
    fernet_key = get_settings().secret_key_file.read_text().strip()
    setup_token = get_settings().setup_token_file.read_text().strip()
    monkeypatch.setattr(get_settings(), "database_url", f"postgresql+asyncpg://homepage:{s['db']}@db.lan/homepage")
    raw_secrets = [*s.values(), authed.totp_secret, fernet_key, setup_token]
    b64 = basic("homepage@pve!dash", s["svc"])
    pem = (f"-----BEGIN OPENSSH PRIVATE KEY-----\n{s['keyline']}\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=\n"
           "-----END OPENSSH PRIVATE KEY-----\n")
    cipher = encrypt("iets-versleuteld")
    # Elk geheim, in elke vorm waarin het in een fout of logregel kan opduiken.
    text = "\n".join([
        f"PVEAPIToken=homepage@pve!dashboard={s['api']}", f"Authorization: Bearer {JWT}",
        f"https://admin:{s['svc']}@npm.lan/api?apikey={s['hook']}", f"POST /api/push/{s['push']}",
        f"POST /api/hooks/{s['hook']}", f"https://fcm.googleapis.com/fcm/send/{s['endpoint']}",
        f"wachtwoord was {s['sshdef']}", f"gecodeerd {quote(s['ssh'], safe='')}", f"basic {b64}", f"blob {cipher}",
        f"regel {s['keyline']}", f"totp {authed.totp_secret}", f"sleutel {fernet_key}", f"code {setup_token}",
        f"oidc {s['oidc']} webpush {s['webpush']} p256 {s['p256dh']} auth {s['auth']} db {s['db']}",
        f"actie {s['api_actie']} ssh {s['ssh']}"])

    g = await _group(authed)
    sid = await _svc(authed, g, "link", "https://plex.lan", name="Plex")
    agen, db = await _db()
    uid = (await db.execute(select(User.id))).scalar_one()
    api = ApiConnection(name="pve-api", kind="rest", url="https://pve.lan",
                        secrets=encrypt_json({"username": "homepage@pve!dashboard", "password": s["api"],
                                              "action_username": "homepage@pve!acties",
                                              "action_password": s["api_actie"]}))
    db.add(api)
    await db.flush()
    svc = await db.get(Service, sid)
    svc.api_id = api.id
    svc.secrets = encrypt_json({"username": "homepage@pve!dash", "password": s["svc"]})
    key = SshKey(name="k", public_key="ssh-ed25519 AAAA", private_key=encrypt(pem))
    db.add(key)
    db.add_all([
        SshHost(name="nas", host="192.168.0.9", username="beheer", password=encrypt(s["ssh"])),
        WebhookSource(name="pve", kind="proxmox", token_hash="h1", token=encrypt(s["hook"]),
                      last_error=f"fout met /api/hooks/{s['hook']}"),
        PushMonitor(service_id=sid, token_hash="h2", token=encrypt(s["push"]), last_msg=f"token {s['push']}"),
        PushSubscription(user_id=uid, endpoint_hash="h3", label="gsm", renew_hash="r",
                         last_error=f"410 {s['endpoint']}",
                         data=encrypt_json({"endpoint": f"https://fcm.googleapis.com/fcm/send/{s['endpoint']}",
                                            "p256dh": s["p256dh"], "auth": s["auth"]})),
        AppState(key="ssh_defaults", value={"username": "beheer", "password": encrypt(s["sshdef"])}),
        AppState(key="oidc", value={"enabled": True, "client_secret": encrypt(s["oidc"])}),
        AppState(key="webpush", value={"private": encrypt(s["webpush"]), "public": "WEBPUSH-PUBLIC-MARKER"}),
        AppState(key="containerlogs", value={"at": "x", "errors": {"plex": text}}),
        AppState(key="zabbix", value={"at": "x", "error": text, "url": f"https://u:{s['svc']}@zabbix.lan"}),
        AppState(key="restoretest", value={"history": [{"at": "x", "ok": False, "error": text}]}),
        AppState(key="logs:worker", value={"at": "x", "pid": 1, "lines": [{"ts": "x", "level": "ERROR",
                                                                           "name": "homepage.worker", "msg": text}]}),
        ServiceState(service_id=sid, status="down", last_error=f"401 met token {s['svc']}"),
        Notification(title="Fout", body=text, level="err"),
        Event(kind="melding", title="Fout", body=text),
        AuditLog(action="integration_action", detail={"params": text}),
        HealRule(service_id=sid, action={"kind": "ssh", "op": "systemctl", "name": "plex"}, last_result=text),
        UpdateRun(target="ssh:1", target_name="nas", status="fout", error=text, output="x" * 5000 + text),
    ])
    await db.commit()
    await agen.aclose()
    tile_error = f"401 PVEAPIToken=homepage@pve!dashboard={s['api']}"
    monkeypatch.setitem(integ._cache, (sid, "summary"), (0.0, (), {"error": tile_error}))
    logring.install("api")
    logging.getLogger("homepage.api").warning("verzoek mislukt: %s", text)

    r = await authed.get("/api/diagnose")
    assert r.status_code == 200, r.text
    raw = r.text
    for v in raw_secrets:
        assert v not in raw, v
        assert quote(v, safe="") not in raw, v
    assert b64 not in raw and JWT not in raw and "gAAAAA" not in raw
    for marker in ("WEBPUSH-PUBLIC-MARKER",):
        assert marker not in raw
    # De ID's blijven leesbaar.
    assert "PVEAPIToken=homepage@pve!dashboard=***" in raw and "/api/hooks/***" in raw
    d = r.json()
    m = d["gemaskeerd"]
    assert m["bekend"] > 10 and m["token"] and m["url"] and m["header"] and "onleesbaar" not in m
    [line] = [x["msg"] for x in d["logs"]["api"]["regels"] if x["msg"].startswith("verzoek mislukt")]
    assert line.startswith("verzoek mislukt: PVEAPIToken=homepage@pve!dashboard=***")
    assert d["updates"][0]["output"].startswith("… ") and len(d["updates"][0]["output"]) < 2200
    assert not set(diagnose.DENY) & set(d["achtergrond"])


async def test_cronregels_en_mislukte_loginnamen_niet_in_de_export(authed):
    """Een cronregel kan een wachtwoord bevatten (mysqldump -p...), en wie zich vergist typt zijn wachtwoord soms in
    het vak van de gebruikersnaam. Geen patroon herkent die: ze gaan er helemaal niet in."""
    agen, db = await _db()
    db.add_all([
        Event(kind="cron", title="Nieuwe cronjob op nas", body="0 3 * * * mysqldump -u root -pS3cretDbPw --all"),
        Event(kind="cron", title="Cronjob weg op nas", body=None),
        Event(kind="melding", title="Back-up klaar", body="plex: 2 GB"),
        AuditLog(action="login_failed", detail={"username": "MijnEchtWachtwoord!"}, ip="192.168.0.10"),
        AuditLog(action="login_failed", detail={"username": "jonas"}, ip="192.168.0.11"),
    ])
    await db.commit()
    await agen.aclose()

    r = await authed.get("/api/diagnose")
    assert r.status_code == 200, r.text
    assert "S3cretDbPw" not in r.text and "MijnEchtWachtwoord" not in r.text
    d = r.json()
    bodies = {e["title"]: e["body"] for e in d["tijdlijn"]}
    assert bodies["Nieuwe cronjob op nas"] == diagnose.WITHHELD
    assert bodies["Cronjob weg op nas"] is None and bodies["Back-up klaar"] == "plex: 2 GB"
    # Een bestaande gebruiker blijft staan: dan is het een gewone mislukte login.
    failed = {a["ip"]: a["detail"] for a in d["audit"] if a["action"] == "login_failed"}
    assert failed == {"192.168.0.10": {"username": "***"}, "192.168.0.11": {"username": "jonas"}}


async def test_zwak_wachtwoord_niet_overal_vervangen(authed):
    """Een gewoon woord als wachtwoord overal door *** vervangen zou het net verraden ("***-diagnose-…"). Alleen de
    patronen vangen het, en de export zegt dat het er is."""
    agen, db = await _db()
    db.add(SshHost(name="nas", host="192.168.0.9", username="beheer", password=encrypt("homepage")))
    db.add(Notification(title="NAS", body="https://beheer:homepage@nas.lan/api faalt, password=homepage"))
    await db.commit()
    await agen.aclose()

    r = await authed.get("/api/diagnose")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["bestand"].startswith("homepage-diagnose-")
    assert r.headers["content-disposition"] == f'attachment; filename="{d["bestand"]}"'
    assert d["gemaskeerd"]["zwak"] >= 1 and "kort of een gewoon woord" in d["let_op"]
    [n] = [x for x in d["meldingen"] if x["title"] == "NAS"]
    assert n["body"] == "https://beheer:***@nas.lan/api faalt, password=***"


async def test_onleesbare_geheimen_geteld(authed):
    agen, db = await _db()
    db.add(SshHost(name="oud", host="10.0.0.1", password="gAAAAABnietmetdezesleutel0123456789abcdef"))
    await db.commit()
    await agen.aclose()
    d = await _diagnose(authed)
    assert d["gemaskeerd"]["onleesbaar"] == 1


async def test_lange_teksten_begrensd(authed):
    """Een blob of een heel lange tekst (bv. uit een webhook) mag de export niet minutenlang laten maskeren."""
    agen, db = await _db()
    db.add(Notification(title="Blob", body="a-" * 50000 + " einde"))
    db.add(Notification(title="Lang", body=" ".join(f"w{i:05d}" for i in range(5000))))
    await db.commit()
    await agen.aclose()
    t = time.monotonic()
    d = await _diagnose(authed)
    assert time.monotonic() - t < 10
    bodies = {n["title"]: n["body"] for n in d["meldingen"]}
    assert bodies["Blob"] == "[100000 tekens] einde"
    assert len(bodies["Lang"]) <= diagnose.MAX_TEXT and " … " in bodies["Lang"] and bodies["Lang"].endswith("w04999")


async def test_geen_bijwerkingen(authed):
    agen, db = await _db()
    # Een genegeerd punt dat er niet meer is: het overzicht ruimt het op, de export niet.
    db.add(AppState(key="attention_ack", value={"items": {"weg:1": {"sig": "x", "at": "2026-10-01", "by": "jonas"}}}))
    await db.commit()

    async def snapshot():
        await db.rollback()
        return ({st.key: st.value for st in (await db.execute(select(AppState).execution_options(
                    populate_existing=True))).scalars()},
                (await db.execute(select(func.count()).select_from(Notification))).scalar(),
                (await db.execute(select(func.count()).select_from(Event))).scalar(),
                (await db.execute(select(AuditLog.action).order_by(AuditLog.id))).scalars().all())

    before = await snapshot()
    await _diagnose(authed)
    after = await snapshot()
    assert after[:3] == before[:3]
    assert "webpush" not in after[0]  # geen VAPID-sleutels aangemaakt
    assert after[3] == [*before[3], "diagnose_download"]

    assert (await authed.get("/api/attention")).status_code == 200
    assert "weg:1" not in (await snapshot())[0]["attention_ack"]["items"]
    await agen.aclose()


# --- logregels van de processen --------------------------------------------------------------------------------

def test_ring_houdt_de_laatste_regels_en_maskeert():
    h = logring.RingHandler(size=3)
    lg = logging.getLogger("homepage.test.ring")
    lg.addHandler(h)
    lg.setLevel(logging.DEBUG)
    lg.propagate = False
    try:
        for i in range(5):
            lg.info("regel %d", i)
        lg.debug("te fijn")
        assert [x["msg"] for x in h.tail()] == ["regel 2", "regel 3", "regel 4"] and h.total == 5
        assert h.tail()[0]["level"] == "INFO" and h.tail()[0]["name"] == "homepage.test.ring"
        lg.warning("GET https://radarr.lan/api/v3?apikey=1234567890abcdef met Bearer abcdefghijklmnopqrstuv")
        assert h.tail()[-1]["msg"] == "GET https://radarr.lan/api/v3?apikey=*** met Bearer ***"
        try:
            raise ValueError("password=hunter2222")
        except ValueError:
            lg.exception("mislukt")
        msg = h.tail()[-1]["msg"]
        assert msg.startswith("mislukt\nTraceback") and "ValueError: password=***" in msg and "hunter2222" not in msg
        # Een blob zonder spaties: alleen zijn lengte (het maskeren zou er seconden over doen).
        t = time.monotonic()
        lg.error("x" * 5000 + " token=abcdefgh12345678 " + "a-" * 20000)
        assert time.monotonic() - t < 0.5
        assert h.tail()[-1]["msg"] == "[5000 tekens] token=*** [40000 tekens]"
        # Lang: het begin en het einde, zonder half woord aan de snede.
        lg.error(" ".join(f"w{i:05d}" for i in range(3000)) + " Traceback-einde")
        msg = h.tail()[-1]["msg"]
        assert len(msg) <= logring.MAX_MSG and msg.startswith("w00000 ") and msg.endswith(" Traceback-einde")
        assert " … " in msg and all(len(w) == 6 for w in msg.split()[:-1] if w != "…")
    finally:
        lg.removeHandler(h)
        lg.propagate = True


def test_api_houdt_waarschuwingen_in_journald(ring, capfd):
    """Een handler op de root-logger zet logging.lastResort uit: zonder eigen handler naar stderr zouden de
    waarschuwingen van de API uit journald verdwijnen."""
    logring.install("api")
    logring.install("api")  # twee keer kan geen kwaad
    root = logging.getLogger()
    assert sum(isinstance(h, logring.RingHandler) for h in root.handlers) == 1
    assert sum(isinstance(h, logring._Stderr) for h in root.handlers) == 1
    logging.getLogger("homepage.api").warning("schijf bijna vol")
    logging.getLogger("httpx").info("HTTP Request: GET https://radarr.lan/?apikey=geheim")
    err = capfd.readouterr().err
    assert "WARNING homepage.api: schijf bijna vol" in err and "HTTP Request" not in err
    assert logring.lines()[-1]["msg"] == "schijf bijna vol"
    assert logging.getLogger("asyncssh").level == logging.WARNING


async def test_flush_alleen_bij_nieuwe_regels(client, ring):
    agen, db = await _db()
    assert await logring.flush(db, "worker") is False  # geen ring
    logring.install("worker")
    assert not any(isinstance(h, logring._Stderr) for h in logging.getLogger().handlers)
    logging.getLogger("homepage.worker").info("eerste regel")
    assert await logring.flush(db, "worker") is True
    await db.commit()
    st = await db.get(AppState, "logs:worker")
    assert st.value["lines"][-1]["msg"] == "eerste regel" and st.value["pid"] == os.getpid()
    at = st.value["at"]
    assert await logring.flush(db, "worker") is False

    # De hartslag van de worker bewaart ze elke minuut.
    maker = async_sessionmaker(db.bind, expire_on_commit=False)
    logging.getLogger("homepage.worker").warning("tweede regel")
    await Worker.beat(SimpleNamespace(maker=maker, started=datetime.now(timezone.utc)))
    await db.rollback()
    st = await db.get(AppState, "logs:worker", populate_existing=True)
    assert st.value["lines"][-1]["msg"] == "tweede regel" and (await db.get(AppState, "worker")) is not None
    assert st.value["at"] >= at

    # De syslog-ontvanger heeft daar een eigen lus voor.
    task = asyncio.create_task(logring.flush_loop(maker, "syslog", every=0.01))
    try:
        for _ in range(300):
            await asyncio.sleep(0.01)
            await db.rollback()
            if await db.get(AppState, "logs:syslog", populate_existing=True):
                break
        else:
            raise AssertionError("logs:syslog niet bewaard")
    finally:
        task.cancel()
    await agen.aclose()


async def test_hartslag_ook_als_de_logregels_niet_in_de_database_kunnen(client, monkeypatch, caplog):
    """Kan flush() niet bewaren (zoals PostgreSQL met een NUL in JSONB), dan blijft de hartslag van de worker toch
    komen: anders zou het dashboard melden dat de worker niet meer draait."""
    async def broken(db, role):
        raise ValueError("unsupported Unicode escape sequence")
    monkeypatch.setattr(logring, "flush", broken)
    agen, db = await _db()
    maker = async_sessionmaker(db.bind, expire_on_commit=False)
    await Worker.beat(SimpleNamespace(maker=maker, started=datetime.now(timezone.utc)))
    st = await db.get(AppState, "worker")
    assert st is not None and st.value["pid"] == os.getpid()
    assert "eigen logregels bewaren mislukt" in caplog.text
    await agen.aclose()


async def test_export_toont_de_logregels(authed, ring):
    logring.install("api")
    logging.getLogger("homepage.api").warning("iets in de API")
    agen, db = await _db()
    lines = [{"ts": f"t{i}", "level": "INFO", "name": "homepage.worker", "msg": f"w{i}"} for i in range(300)]
    db.add(AppState(key="logs:worker", value={"at": "nu", "pid": 7, "started": "s", "lines": lines}))
    await db.commit()
    await agen.aclose()
    logs = (await _diagnose(authed))["logs"]
    assert logs["api"]["regels"][-1]["msg"] == "iets in de API" and logs["api"]["pid"] == os.getpid()
    assert len(logs["worker"]["regels"]) == 200 and logs["worker"]["regels"][-1]["msg"] == "w299"
    assert logs["worker"]["pid"] == 7 and logs["syslog"]["regels"] == []
    assert "journalctl" in logs["tip"]
