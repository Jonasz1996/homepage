"""Proefmodus voor updates: installeren, terugdraaien, de nachtelijke run en snapshots opruimen tonen wat ze zouden
doen, met dezelfde commando's en calls als het echte werk, zonder iets uit te voeren."""

import json
import re
from datetime import datetime, timedelta, timezone

import asyncssh
import httpx
from sqlalchemy import func, select

from app import setupcheck
from app.models import AppState, AuditLog, Event, Notification, Service, SshHost, SshKey, UpdateRun
from app.monitoring import upgrade, worker
from app.monitoring.checks import HttpClients
from app.routers import upgrade as router
from app.security import encrypt
from app.ssh_exec import command
from app.ssh_login import Login

from .test_integrations import _group, _svc
from .test_upgrade_herstel import Node, _db, _host, _maker_from, _pve_with_tasks, _t, _updates_state, _wait
from .test_verbindingen import _idle_in_transaction

READ_SECRET = "pve-lees-geheim-7f3a9c"
ACTION_SECRET = "pve-actie-geheim-2b8e41"
HOST_PW = "host-wachtwoord-9d5c27"
ROOT = Login("root", None, None)


def _norm(s: str) -> str:
    """Zonder het tijdstip in de snapshotnaam en de beschrijving: dat verschilt tussen proef en echte run."""
    s = re.sub(r"hp-upd-\d{8}-\d{6}", "hp-upd-X", s)
    return re.sub(r"\d\d/\d\d/\d{4} \d\d:\d\d", "D", s)


async def _count(db, model, *where) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar_one()


async def _pve(authed, g) -> int:
    return await _svc(authed, g, "proxmox", "https://pve.jbogaert.be", name="PVE",
                      secrets={"username": "homepage@pve!dash", "password": READ_SECRET,
                               "action_username": "homepage-acties@pve!acties", "action_password": ACTION_SECRET})


async def test_proef_installeren_in_ct_dezelfde_commandos_als_echt(authed, monkeypatch):
    monkeypatch.setattr(upgrade, "CHECK_WAIT", 0)
    monkeypatch.setattr(upgrade, "CHECK_GAP", 0)
    node = Node()
    port = await node.start()
    hid = await _host(authed, "pve50", port, node.key, source="pve:9:node/pve50")
    g = await _group(authed)
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="plex")
    agen, db = await _db()
    s = await db.get(Service, plex)
    s.check = {"type": "tcp", "target": f"127.0.0.1:{port}", "interval": 60}
    await db.commit()
    ct, phys = f"ssh:{hid}:ct:105", f"ssh:{hid}"
    await _updates_state(db, [_t(ct, "plex", "ct"), _t(phys, "pve50", "host"), _t("portainer:1:x", "nginx", "docker")])
    before = {m: await _count(db, m) for m in (Event, Notification, AuditLog, UpdateRun)}

    body = {"targets": [ct, phys, "portainer:1:x", "weg:1"], "security_only": True}
    r = await authed.post("/api/updates/install/proef", json=body)
    assert r.status_code == 200, r.text
    p = r.json()
    # Niets gedaan: geen SSH, geen runs, geen meldingen, geen tijdlijn, geen audit.
    assert node.commands == []
    assert {m: await _count(db, m) for m in before} == before
    assert p["proef"] is True and p["runs"] == [{"key": ct, "name": "plex"}]

    snap, inst, chk, back = p["steps"]
    assert [x["nr"] for x in p["steps"]] == [1, 2, 3, 4]
    assert snap["machine"] == f"pve50 (root@127.0.0.1:{port})" and snap["via"] == "ssh" and snap["who"] == "root"
    assert snap["call"].startswith("pct snapshot 105 hp-upd-") and snap["script"] == command(snap["call"], ROOT)
    assert inst["machine"] == f"pve50 (root@127.0.0.1:{port}) → CT 105 via pct exec"
    plan = await upgrade.plan_for(db, ct)
    assert inst["script"] == upgrade.install_cmd(plan, ROOT, ["openssl"])
    assert inst["script"].startswith("pct exec 105 -- sh -c") and "PKGS=openssl" in inst["script"]
    assert "alleen de beveiligingsupdates (1)" in inst["call"]
    assert "apt-get install --only-upgrade openssl" in inst["call"] and "met apk: apk update" in inst["call"]
    assert chk["via"] == "dashboard" and f"plex (tcp 127.0.0.1:{port})" in chk["call"] and chk["when"]
    assert back["call"].startswith("pct rollback 105 hp-upd-") and "knop terugdraaien" in back["when"]
    checks = {c["what"]: c["ok"] for c in p["checks"]}
    assert checks == {"plex: hostsleutel van pve50 bevestigd": True, "plex: inloggen als root": True,
                      "plex: snapshot kan": True}
    skipped = {x["what"]: x["why"] for x in p["skipped"]}
    assert "fysieke machine" in skipped["pve50"] and "bewust zonder snapshot" in skipped["pve50"]
    assert "nginx" in skipped and skipped["weg:1"] == "Staat niet in de laatste updatescan"
    assert any("opnieuw scannen" in a for a in p["after"]) and any("auditlog" in a for a in p["after"])

    # Alleen beveiliging, maar er staat er geen meer open: overgeslagen, zoals run_batch het doet.
    await _updates_state(db, [_t(ct, "plex", "ct", sec=0)])
    p0 = (await authed.post("/api/updates/install/proef", json={"targets": [ct], "security_only": True})).json()
    assert p0["steps"] == [] and upgrade.NO_SECURITY in p0["skipped"][0]["why"]
    # Zonder "alleen beveiliging": alles uit de scan, en de machine kiest zelf apt of apk.
    p1 = (await authed.post("/api/updates/install/proef", json={"targets": [ct]})).json()
    assert "alle openstaande (1)" in p1["steps"][1]["call"] and "dist-upgrade" in p1["steps"][1]["call"]
    assert p1["steps"][1]["script"] == upgrade.install_cmd(plan, ROOT, None)
    await _updates_state(db, [_t(ct, "plex", "ct"), _t(phys, "pve50", "host"), _t("portainer:1:x", "nginx", "docker")])

    # De echte installatie: dezelfde weigeringen en precies de commando's uit de proef.
    real = (await authed.post("/api/updates/install", json=body)).json()
    assert real["refused"] == p["refused"]
    run = await _wait(authed, real["runs"][0]["id"])
    assert run["status"] == "ok", run
    assert [_norm(c) for c in node.commands] == [_norm(snap["script"]), inst["script"]]

    # Terugdraaien als proef: het commando met de echte snapshotnaam, en niets gedaan.
    rp = await authed.post(f"/api/updates/runs/{run['id']}/rollback/proef")
    assert rp.status_code == 200, rp.text
    step = rp.json()["steps"][0]
    name = run["snapshot"]["name"]
    assert step["call"] == f"pct rollback 105 {name} && (pct status 105 | grep -q running || pct start 105)"
    assert len(node.commands) == 2 and (await authed.get(f"/api/updates/runs/{run['id']}")).json()["status"] == "ok"
    assert any("gaat verloren" in w for w in rp.json()["warnings"])
    assert (await authed.post(f"/api/updates/runs/{run['id']}/rollback")).status_code == 202
    await _wait(authed, run["id"], until=("teruggedraaid",))
    assert node.commands[-1] == step["script"]
    # Kan het echt niet meer, dan weigert ook de proef.
    assert (await authed.post(f"/api/updates/runs/{run['id']}/rollback/proef")).status_code == 409
    assert (await authed.post("/api/updates/runs/999/rollback/proef")).status_code == 404


async def test_proef_vm_via_api_zonder_geheimen_en_zonder_open_transactie(authed, monkeypatch):
    g = await _group(authed)
    sid = await _pve(authed, g)
    vm = Node()
    port = await vm.start()
    hid = await _host(authed, "opnsense", port, vm.key, source=f"pve:{sid}:qemu/100")
    agen, db = await _db()
    # Eigen gebruiker, sleutel en wachtwoord op de host: alleen de gebruikersnaam mag in de proef staan.
    pem = asyncssh.generate_private_key("ssh-ed25519").export_private_key().decode()
    key = SshKey(name="k", public_key="ssh-ed25519 AAAA", private_key=encrypt(pem))
    db.add(key)
    await db.flush()
    h = await db.get(SshHost, hid)
    h.key_id, h.password, h.username = key.id, encrypt(HOST_PW), "jonas"
    await db.commit()
    vm_key = f"ssh:{hid}"
    await _updates_state(db, [_t(vm_key, "opnsense", "host"), _t(f"pve:{sid}:pve50", "pve50", "node")])
    calls = []
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(_pve_with_tasks(calls))))

    r = await authed.post("/api/updates/install/proef", json={"targets": [vm_key, f"pve:{sid}:pve50"],
                                                              "security_only": True})
    assert r.status_code == 200, r.text
    p = r.json()
    # Alleen de node opgezocht: geen POST, geen DELETE, geen SSH.
    assert calls == [("GET", "/api2/json/cluster/resources")] and vm.commands == []
    snap, inst, back = p["steps"]
    assert snap["via"] == "proxmox-api" and snap["call"] == "POST /api2/json/nodes/pve50/qemu/100/snapshot"
    assert snap["machine"] == "qemu 100 op node pve50 (https://pve.jbogaert.be)"
    assert snap["who"] == "API-token homepage-acties@pve!acties"
    name = snap["data"]["snapname"]
    assert name.startswith("hp-upd-") and snap["data"]["description"].startswith("voor updates via homepage")
    assert inst["machine"] == f"opnsense (jonas@127.0.0.1:{port})" and inst["who"] == "jonas met sudo -n"
    assert inst["script"].startswith("sudo -n sh -c")
    assert back["call"] == f"POST /api2/json/nodes/pve50/qemu/100/snapshot/{name}/rollback" and back["data"] == {"start": 1}
    checks = {c["what"]: c for c in p["checks"]}
    assert checks["opnsense: inloggen als jonas"]["ok"] is None
    assert checks["opnsense: snapshot via de Proxmox-API"]["ok"] is True
    assert checks["opnsense: gekoppelde services"]["ok"] is None
    assert "staat nog niet in de terminal" in {x["what"]: x["why"] for x in p["skipped"]}["pve50"]
    # Geen enkel geheim: niet van Proxmox, niet van de host.
    text = json.dumps(p)
    for secret in (READ_SECRET, ACTION_SECRET, HOST_PW, pem.splitlines()[1], "PVEAPIToken"):
        assert secret not in text

    # Proxmox antwoordt niet: de node blijft onbekend, de proef gaat verder.
    monkeypatch.setattr(router, "clients", HttpClients(httpx.MockTransport(lambda req: httpx.Response(500))))
    p = (await authed.post("/api/updates/install/proef", json={"targets": [vm_key], "security_only": True})).json()
    c = next(c for c in p["checks"] if "Proxmox-API" in c["what"])
    assert c["ok"] is None and "HTTP 500" in c["detail"]
    assert p["steps"][0]["call"] == "POST /api2/json/nodes/?/qemu/100/snapshot" and len(p["steps"]) == 3

    # Terwijl Proxmox antwoordt staat er geen transactie open.
    _, s2 = await _db()
    seen = []
    base = _pve_with_tasks([])

    async def handler(req):
        seen.append((s2.in_transaction(), await _idle_in_transaction()))
        return base(req)
    await upgrade.describe_batch(s2, HttpClients(httpx.MockTransport(handler)), [(vm_key, None)],
                                 security_only=True, snapshot=True, trigger="manueel")
    assert seen == [(False, 0)]


async def test_nachtelijke_proef_noteert_alleen_en_echte_run_gebruikt_dezelfde_calls(authed, monkeypatch):
    monkeypatch.setattr(upgrade, "CHECK_WAIT", 0)
    monkeypatch.setattr(upgrade, "CHECK_GAP", 0)
    g = await _group(authed)
    sid = await _pve(authed, g)
    vm = Node()
    hid = await _host(authed, "opnsense", await vm.start(), vm.key, source=f"pve:{sid}:qemu/100")
    nas = Node()
    nas_id = await _host(authed, "nas", await nas.start(), nas.key)
    agen, db = await _db()
    await _updates_state(db, [_t(f"ssh:{hid}", "opnsense", "host"), _t(f"ssh:{nas_id}", "nas", "host"),
                              _t(f"ssh:{nas_id}:ct:200", "zonder", "ct", sec=0)])
    r = await authed.put("/api/updates/settings", json={"auto": True, "hour": 3, "keep_days": 7, "proef": True})
    assert r.json()["proef"] is True and r.json()["cleanup_proef"] is False
    cfg = (await authed.get("/api/updates/settings")).json()
    assert cfg["proef"] is True and cfg["last_proef"] == {"auto": None, "cleanup": None}
    audit = (await db.execute(select(AuditLog).where(AuditLog.action == "updates_settings"))).scalar_one()
    assert audit.detail["proef"] is True
    up = next(x for x in await setupcheck.ssh_rows(db, True) if x["key"] == "autoupdates")
    assert up["state"] == "half" and up["text"].startswith("Aan als proef: er wordt niets geïnstalleerd")
    assert up["todo"]

    calls = []
    http = HttpClients(httpx.MockTransport(_pve_with_tasks(calls)))
    maker = _maker_from(agen)
    assert await upgrade.auto_updates(maker, http, datetime(2026, 10, 5, 2, 0).astimezone()) == []  # niet het uur
    assert await db.get(AppState, upgrade.AUTO_PROEF_KEY) is None
    assert await upgrade.auto_updates(maker, http, datetime(2026, 10, 5, 3, 1).astimezone()) == []
    assert await upgrade.auto_updates(maker, http, datetime(2026, 10, 5, 3, 30).astimezone()) == []  # vandaag al
    # Geen run, geen SSH, alleen de node opgezocht, geen melding; één regel op de tijdlijn.
    assert await _count(db, UpdateRun) == 0 and vm.commands == [] and nas.commands == []
    assert calls == [("GET", "/api2/json/cluster/resources")]
    assert await _count(db, Notification, Notification.source == "updates") == 0
    events = (await db.execute(select(Event).where(Event.kind == "updates"))).scalars().all()
    assert [e.title for e in events] == ["Proef: nachtelijke updates"]
    assert events[0].level == "info" and events[0].data["proef"] is True
    assert (await db.get(AppState, upgrade.AUTO_KEY)).value == {"date": "2026-10-05"}
    plan = (await db.get(AppState, upgrade.AUTO_PROEF_KEY)).value
    assert plan["title"] == "Nachtelijke beveiligingsupdates om 03:00" and plan == events[0].data["plan"]
    assert [s["via"] for s in plan["steps"]] == ["proxmox-api", "ssh", "proxmox-api"]
    assert "automatisch" in plan["steps"][2]["when"] and "zelf terug" in plan["steps"][1]["on_fail"]
    skipped = {x["what"]: x["why"] for x in plan["skipped"]}
    # Een fysieke machine slaat de nachtelijke run stil over; de proef zegt het.
    assert "fysieke machine" in skipped["nas"] and "nooit geïnstalleerd" in skipped["nas"]
    assert "zonder" not in skipped  # geen beveiligingsupdates: komt 's nachts niet aan de beurt
    assert any("Alleen proef staat aan" in w for w in plan["warnings"])
    assert (await authed.get("/api/updates/settings")).json()["last_proef"]["auto"]["title"] == plan["title"]

    # De knop "proef van vannacht" toont hetzelfde, los van het uur.
    monkeypatch.setattr(router, "clients", http)
    now = (await authed.get("/api/updates/auto/proef")).json()
    assert [_norm(s["call"]) for s in now["steps"]] == [_norm(s["call"]) for s in plan["steps"]]
    assert [s.get("script") for s in now["steps"]] == [s.get("script") for s in plan["steps"]]

    # De worker start na een proef geen nieuwe scan (die logt op elke machine in).
    scans = []

    async def scan(db, http):
        scans.append(1)
    monkeypatch.setattr(worker, "run_updates", scan)
    monkeypatch.setattr(worker, "auto_updates",
                        lambda m, h: upgrade.auto_updates(m, h, datetime(2026, 10, 6, 3, 1).astimezone()))
    w = worker.Worker(maker)
    w.http = http
    await w.auto_updates()
    assert scans == [] and await _count(db, UpdateRun) == 0
    assert await _count(db, Event, Event.kind == "updates") == 2

    # Proef uit: de echte run maakt precies de snapshot en de rollback uit de proef.
    await authed.put("/api/updates/settings", json={"auto": True, "hour": 3, "keep_days": 7})
    calls.clear()
    ids = await upgrade.auto_updates(maker, http, datetime(2026, 10, 7, 3, 1).astimezone())
    assert len(ids) == 1
    run = (await authed.get(f"/api/updates/runs/{ids[0]}")).json()
    assert run["status"] == "ok", run
    method, path = plan["steps"][0]["call"].split(" ")
    assert (method, path) in calls
    assert vm.commands == [plan["steps"][1]["script"]]
    rp = (await authed.post(f"/api/updates/runs/{run['id']}/rollback/proef")).json()
    assert rp["steps"][0]["call"] == f"POST /api2/json/nodes/pve50/qemu/100/snapshot/{run['snapshot']['name']}/rollback"
    assert rp["steps"][0]["who"] == "API-token homepage-acties@pve!acties"
    assert not any(m == "POST" and p.endswith("/rollback") for m, p in calls)
    assert (await authed.post(f"/api/updates/runs/{run['id']}/rollback")).status_code == 202
    await _wait(authed, run["id"], until=("teruggedraaid",))
    assert ("POST", rp["steps"][0]["call"].split(" ")[1]) in calls


async def test_snapshots_opruimen_als_proef(authed, monkeypatch):
    node = Node()
    port = await node.start()
    hid = await _host(authed, "pve50", port, node.key, source="pve:9:node/pve50")
    g = await _group(authed)
    sid = await _pve(authed, g)
    agen, db = await _db()
    now = datetime.now(timezone.utc)

    def run(name, status, days, snap):
        r = UpdateRun(target=name, target_name=name, trigger="manueel", security_only=False, status=status,
                      snapshot=snap, reboot_needed=False, finished_at=now - timedelta(days=days))
        db.add(r)
        return r
    pct = {"kind": "pct", "host_id": hid, "vmid": 105, "node": "pve50", "name": "hp-upd-20261001-030000"}
    api = {"kind": "api", "service_id": sid, "type": "qemu", "vmid": 100, "node": "pve50", "name": "hp-upd-20261001-031000"}
    old_ct = run("plex", "ok", 10, pct)
    old_vm = run("opnsense", "teruggedraaid", 10, api)
    run("jong", "ok", 1, {**pct, "name": "hp-upd-20261010-030000"})
    run("kapot", "fout", 10, {**pct, "name": "hp-upd-20261001-040000"})
    await db.commit()
    await authed.put("/api/updates/settings", json={"auto": False, "hour": 4, "keep_days": 7, "cleanup_proef": True})
    calls = []
    http = HttpClients(httpx.MockTransport(_pve_with_tasks(calls)))
    maker = _maker_from(agen)

    assert await upgrade.cleanup_snapshots(maker, http) == 0
    # Niets verwijderd, niets aangeraakt: geen SSH, geen Proxmox, removed_at blijft leeg.
    assert node.commands == [] and calls == []
    for r in (await db.execute(select(UpdateRun))).scalars():
        await db.refresh(r)
        assert not r.snapshot.get("removed_at")
    plan = (await db.get(AppState, upgrade.CLEANUP_PROEF_KEY)).value
    ct_step, vm_step = plan["steps"]
    assert ct_step["call"] == "pct delsnapshot 105 hp-upd-20261001-030000" and ct_step["script"] == command(ct_step["call"], ROOT)
    assert ct_step["machine"] == f"pve50 (root@127.0.0.1:{port})"
    assert vm_step["call"] == "DELETE /api2/json/nodes/pve50/qemu/100/snapshot/hp-upd-20261001-031000"
    assert vm_step["who"] == "API-token homepage-acties@pve!acties"
    skipped = {x["what"]: x["why"] for x in plan["skipped"]}
    assert "nog geen 7 dagen oud" in skipped["hp-upd-20261010-030000 van jong"]
    assert "run 'fout'" in skipped["hp-upd-20261001-040000 van kapot"]
    assert {s["name"] for s in plan["snapshots"]} == {"hp-upd-20261001-030000", "hp-upd-20261001-031000"}
    assert ACTION_SECRET not in json.dumps(plan) and READ_SECRET not in json.dumps(plan)

    def proef_events():
        return _count(db, Event, Event.title == "Proef: snapshots van updates opruimen")
    assert await proef_events() == 1 and await _count(db, Notification, Notification.source == "updates") == 0
    # Dezelfde snapshots zes uur later: geen nieuwe regel op de tijdlijn.
    assert await upgrade.cleanup_snapshots(maker, http) == 0
    assert await proef_events() == 1
    # Eén snapshot minder: wel.
    old_ct.finished_at = now
    await db.commit()
    assert await upgrade.cleanup_snapshots(maker, http) == 0
    assert await proef_events() == 2
    old_ct.finished_at = now - timedelta(days=10)
    await db.commit()

    # De knop toont wat de volgende ronde zou doen.
    monkeypatch.setattr(router, "clients", http)
    r = (await authed.get("/api/updates/cleanup/proef")).json()
    assert [s["call"] for s in r["steps"]] == [ct_step["call"], vm_step["call"]] and calls == []

    # Echt opruimen: precies dezelfde commando's.
    await authed.put("/api/updates/settings", json={"auto": False, "hour": 4, "keep_days": 7})
    assert await upgrade.cleanup_snapshots(maker, http) == 2
    assert node.commands == [ct_step["script"]]
    assert ("DELETE", vm_step["call"].split(" ")[1]) in calls
    await db.refresh(old_ct)
    await db.refresh(old_vm)
    assert old_ct.snapshot["removed_at"] and old_vm.snapshot["removed_at"]
