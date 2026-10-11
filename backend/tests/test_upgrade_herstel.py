import asyncio
from datetime import datetime, timedelta, timezone

import asyncssh
import httpx
from sqlalchemy import select

from app.db import get_db
from app.main import app
from app.models import AppState, CheckResult, Event, HealRule, Notification, Service, ServiceState, SshHost
from app.monitoring import healing, upgrade, webpush
from app.monitoring.checks import HttpClients

from .test_integrations import PVE, Fake as PveFake, _group, _svc
from .test_webpush import A, Phone, PushService, _run, _subscribe


class Node:
    """Nep-Proxmox-node over SSH: pct snapshot/rollback/exec, systemctl en docker."""

    def __init__(self):
        self.key = asyncssh.generate_private_key("ssh-ed25519")
        self.commands: list[str] = []
        self.rc = 0
        self.snap_rc = 0

    async def handle(self, proc):
        cmd = proc.command or ""
        self.commands.append(cmd)
        if "pct snapshot" in cmd:
            if self.snap_rc:
                proc.stderr.write("snapshot feature is not available\n")
            proc.exit(self.snap_rc)
            return
        if "apt-get" in cmd:
            for line in ["Reading package lists...", "The following packages will be upgraded:", "  openssl",
                         "Setting up openssl (3.0.15-1) ..."]:
                proc.stdout.write(line + "\n")
                await asyncio.sleep(0.01)
            if self.rc == 0:
                proc.stdout.write("@@REBOOT\n")
            proc.exit(self.rc)
            return
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


async def _host(authed, name, port, key, source=None):
    hid = (await authed.post("/api/ssh/hosts", json={"name": name, "host": "127.0.0.1", "port": port,
                                                     "password": "pw"})).json()["id"]
    agen, db = await _db()
    h = await db.get(SshHost, hid)
    h.host_key = key.export_public_key().decode()
    h.source = source
    await db.commit()
    return hid


async def _updates_state(db, targets):
    st = await db.get(AppState, "updates")
    value = {"checked_at": datetime.now(timezone.utc).isoformat(), "targets": targets}
    if st:
        st.value = value
    else:
        db.add(AppState(key="updates", value=value))
    await db.commit()


def _t(key, name, kind, sec=1):
    pk = [{"n": "openssl", "from": "3.0.14", "to": "3.0.15", "sec": True}] if sec else []
    pk.append({"n": "vim", "from": "9.0", "to": "9.1", "sec": False})
    return {"key": key, "name": name, "kind": kind, "service_id": None, "count": len(pk), "security": sec,
            "packages": pk, "error": None}


async def _wait(authed, run_id, until=upgrade.DONE, timeout=15):
    # Eerst de achtergrondtaak laten afwerken: met SQLite delen alle sessies één verbinding, en een
    # rollback van een leesverzoek tussendoor zou de schrijfacties van de run meenemen.
    from app.routers import upgrade as router
    await asyncio.wait_for(asyncio.gather(*list(router._tasks)), timeout)
    r = (await authed.get(f"/api/updates/runs/{run_id}")).json()
    assert r["status"] in until, r
    return r


async def test_install_ct_with_snapshot_check_and_rollback(authed, monkeypatch):
    monkeypatch.setattr(upgrade, "CHECK_WAIT", 0)
    monkeypatch.setattr(upgrade, "CHECK_GAP", 0)
    node = Node()
    port = await node.start()
    hid = await _host(authed, "pve50", port, node.key, source="pve:9:node/pve50")
    g = await _group(authed)
    # Plex draait in CT 105 (zelfde naam): na de updates wordt hij nagekeken.
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="plex")
    agen, db = await _db()
    s = await db.get(Service, plex)
    s.check = {"type": "tcp", "target": f"127.0.0.1:{port}", "interval": 60}
    await db.commit()
    await _updates_state(db, [_t(f"ssh:{hid}:ct:105", "plex", "ct"), _t(f"ssh:{hid}", "pve50", "host"),
                              _t("portainer:1:x", "nginx", "docker")])

    plans = (await authed.get("/api/updates/plans")).json()
    assert plans[f"ssh:{hid}:ct:105"] == {"can": True, "why": None, "snapshot": "pct", "nosnap": None}
    assert plans[f"ssh:{hid}"]["snapshot"] is None and "fysieke" in plans[f"ssh:{hid}"]["nosnap"]
    assert not plans["portainer:1:x"]["can"]

    r = await authed.post("/api/updates/install", json={"targets": [f"ssh:{hid}:ct:105", f"ssh:{hid}", "portainer:1:x"],
                                                        "security_only": True})
    assert r.status_code == 202, r.text
    body = r.json()
    assert [x["name"] for x in body["runs"]] == ["plex"]
    # Zonder snapshot weigeren tot je dat bewust kiest; Docker kan niet.
    assert {x["name"]: bool(x.get("nosnap")) for x in body["refused"]} == {"pve50": True, "nginx": False}
    run = await _wait(authed, body["runs"][0]["id"])
    assert run["status"] == "ok", run
    assert run["snapshot"]["kind"] == "pct" and run["snapshot"]["name"].startswith("hp-upd-")
    assert run["reboot_needed"] and run["checks"] == [{"service_id": plex, "name": "plex", "ok": True, "error": None}]
    assert "Setting up openssl" in run["output"]
    snap_cmd = next(c for c in node.commands if "pct snapshot" in c)
    apt_cmd = next(c for c in node.commands if "apt-get" in c)
    assert "105" in snap_cmd and apt_cmd.startswith("pct exec 105 -- sh -c")
    assert "PKGS=openssl" in apt_cmd  # alleen de beveiligingsupdate

    # Terugdraaien naar die snapshot.
    r = await authed.post(f"/api/updates/runs/{run['id']}/rollback")
    assert r.status_code == 202
    back = await _wait(authed, run["id"], until=("teruggedraaid", "terugdraaien_mislukt"))
    assert back["status"] == "teruggedraaid" and back["rolled_back_at"]
    assert any(f"pct rollback 105 {run['snapshot']['name']}" in c for c in node.commands)
    assert (await authed.post(f"/api/updates/runs/{run['id']}/rollback")).status_code == 409

    # Zonder snapshot op de node zelf, en apt faalt: melding.
    node.rc = 100
    r = (await authed.post("/api/updates/install", json={"targets": [f"ssh:{hid}"], "snapshot": False})).json()
    run2 = await _wait(authed, r["runs"][0]["id"])
    assert run2["status"] == "fout" and run2["snapshot"] is None and "exitcode 100" in run2["error"]
    assert not run2["can_rollback"]
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "updates"))).scalars()]
    assert titles == ["Updates op pve50 mislukt"]
    listed = (await authed.get("/api/updates/runs")).json()
    assert [x["id"] for x in listed] == [run2["id"], run["id"]]
    tl = (await authed.get("/api/timeline?kind=updates")).json()["items"]
    assert any("teruggedraaid" in i["title"] for i in tl) and any("updates geïnstalleerd" in i["title"] for i in tl)


def _pve_with_tasks(calls):
    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        calls.append((req.method, p))
        if p == "/api2/json/cluster/resources":
            return httpx.Response(200, json=PVE)
        if req.method == "POST" and p.endswith("/snapshot"):
            return httpx.Response(200, json={"data": "UPID:pve50:1:snap"})
        if req.method == "POST" and p.endswith("/rollback"):
            return httpx.Response(200, json={"data": "UPID:pve50:2:rb"})
        if "/tasks/" in p:
            return httpx.Response(200, json={"data": {"status": "stopped", "exitstatus": "OK"}})
        if req.method == "DELETE":
            return httpx.Response(200, json={"data": "UPID:pve50:3:del"})
        return httpx.Response(404)
    return handler


async def test_vm_snapshot_via_api_auto_mode_rolls_back(authed, monkeypatch):
    monkeypatch.setattr(upgrade, "CHECK_WAIT", 0)
    monkeypatch.setattr(upgrade, "CHECK_GAP", 0)
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"}, name="PVE")
    vm = Node()
    hid = await _host(authed, "opnsense", await vm.start(), vm.key, source=f"pve:{sid}:qemu/100")
    agen, db = await _db()
    down = await _svc(authed, g, "", "http://opnsense.jbogaert.be", name="opnsense")
    s = await db.get(Service, down)
    s.check = {"type": "tcp", "target": "127.0.0.1:1", "interval": 60}
    await db.commit()
    await _updates_state(db, [_t(f"ssh:{hid}", "opnsense", "host")])
    calls = []
    http = HttpClients(httpx.MockTransport(_pve_with_tasks(calls)))
    await authed.put("/api/updates/settings", json={"auto": True, "hour": 3, "keep_days": 7})

    maker = _maker_from(agen)
    assert await upgrade.auto_updates(maker, http, datetime(2026, 10, 5, 2, 0).astimezone()) == []  # niet het uur
    ids = await upgrade.auto_updates(maker, http, datetime(2026, 10, 5, 3, 1).astimezone())
    assert len(ids) == 1
    assert await upgrade.auto_updates(maker, http, datetime(2026, 10, 5, 3, 30).astimezone()) == []  # vandaag al
    run = (await authed.get(f"/api/updates/runs/{ids[0]}")).json()
    assert run["trigger"] == "auto" and run["snapshot"]["kind"] == "api" and run["snapshot"]["node"] == "pve50"
    # Service down na de updates → zelf teruggedraaid via de API.
    assert run["status"] == "teruggedraaid" and "opnsense" in run["checks"][0]["name"]
    assert ("POST", "/api2/json/nodes/pve50/qemu/100/snapshot") in calls
    assert any(m == "POST" and p.endswith("/rollback") for m, p in calls)
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "updates"))).scalars()]
    assert titles == ["Nachtelijke updates op opnsense mislukt, teruggedraaid"]

    # Eigen snapshots van geslaagde (of teruggedraaide) runs gaan na keep_days weg.
    from app.models import UpdateRun
    r = await db.get(UpdateRun, ids[0])
    await db.refresh(r)
    r.finished_at = datetime.now(timezone.utc) - timedelta(days=8)
    await db.commit()
    assert await upgrade.cleanup_snapshots(maker, http) == 1
    assert any(m == "DELETE" for m, p in calls)
    await db.refresh(r)
    assert r.snapshot["removed_at"]


def _maker_from(_):
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def maker():
        agen = app.dependency_overrides[get_db]()
        db = await agen.__anext__()
        try:
            yield db
        finally:
            await agen.aclose()
    return maker


async def test_heal_rules_fire_with_cooldown_and_limit(authed, monkeypatch):
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"}, name="PVE")
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    action = {"kind": "integration", "service_id": pve, "action": "reboot", "label": "herstart CT 101",
              "params": {"node": "pve50", "type": "lxc", "vmid": 101}}
    r = await authed.post("/api/heal", json={"service_id": plex, "after": 3, "max_per_hour": 2, "action": action})
    assert r.status_code == 201, r.text
    bad = await authed.post("/api/heal", json={"service_id": plex, "action": {**action, "action": "rm-rf"}})
    assert bad.status_code == 422
    bad = await authed.post("/api/heal", json={"service_id": plex, "action": {"kind": "ssh", "host_id": 1, "op": "rm", "name": "x"}})
    assert bad.status_code == 422

    agen, db = await _db()
    db.add(ServiceState(service_id=plex, status="down", fail_count=2, quiet=False, cert_notified=0))
    await db.commit()
    fake = PveFake()
    http = HttpClients(httpx.MockTransport(fake))
    maker = _maker_from(agen)
    t0 = datetime.now(timezone.utc)
    assert await healing.check(maker, plex, http, t0) is None  # pas na 3 keer
    st = await db.get(ServiceState, plex)
    st.fail_count = 3
    await db.commit()
    res = await healing.check(maker, plex, http, t0)
    # CT 101 staat uit: geen herstart maar een start.
    assert res.startswith("ok") and fake.calls[-1].url.path == "/api2/json/nodes/pve50/lxc/101/status/start"
    assert await healing.check(maker, plex, http, t0 + timedelta(minutes=5)) is None  # wachttijd
    assert (await healing.check(maker, plex, http, t0 + timedelta(minutes=11))).startswith("ok")
    res = await healing.check(maker, plex, http, t0 + timedelta(minutes=22))
    assert res is None
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "herstel")
                                                 .order_by(Notification.id))).scalars()]
    assert titles == ["Zelfherstel: Plex was 3× down", "Zelfherstel: Plex was 3× down", "Zelfherstel voor Plex gepauzeerd"]
    rule = (await db.execute(select(HealRule))).scalar_one()
    await db.refresh(rule)
    assert rule.last_result.startswith("limiet") and len(rule.fired) == 2
    # Een uur later mag het weer.
    assert (await healing.check(maker, plex, http, t0 + timedelta(minutes=75))).startswith("ok")
    # Afhankelijk van iets dat plat ligt: niets doen.
    st.quiet = True
    await db.commit()
    assert await healing.check(maker, plex, http, t0 + timedelta(minutes=95)) is None

    listed = (await authed.get(f"/api/heal?service_id={plex}")).json()
    assert listed[0]["describe"] == "herstart CT 101" and listed[0]["service"] == "Plex"


def test_limiet_per_uur_past_bij_de_wachttijd():
    """Met 10 min wachttijd gaat een regel hoogstens 6× per uur af: een limiet van 6 pauzeerde dus nooit."""
    assert healing.MAX_PER_HOUR == 5
    t0 = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
    rule = HealRule(enabled=True, after=3, max_per_hour=6, fired=[], last_at=None, dry_run=False, action={})
    times, paused = [], 0
    for m in range(12 * 60):  # elke minuut een check, een storing van 12 uur
        now = t0 + timedelta(minutes=m)
        g = healing.gates(rule, 3, False, False, now)
        if g.blocked is None:
            rule.fired, rule.last_at = g.fired + [now.isoformat()], now
            times.append(now)
        paused += g.blocked == healing.LIMIT
    assert paused
    assert max(sum(1 for t in times if s <= t < s + timedelta(hours=1)) for s in times) == 5
    assert healing.gates(rule, 3, False, False, t0).checks[-1]["what"] == "hoogstens 5× per uur"


async def _heal_notes(db) -> list[Notification]:
    return list((await db.execute(select(Notification).where(Notification.source == "herstel")
                                  .order_by(Notification.id))).scalars())


async def _heal_setup(authed, fake=None, max_per_hour=2):
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be",
                     secrets={"username": "homepage@pve!dash", "password": "geheim"}, name="PVE")
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    action = {"kind": "integration", "service_id": pve, "action": "reboot", "label": "herstart CT 101",
              "params": {"node": "pve50", "type": "lxc", "vmid": 101}}
    r = await authed.post("/api/heal", json={"service_id": plex, "after": 3, "max_per_hour": max_per_hour,
                                             "action": action})
    assert r.status_code == 201, r.text
    agen, db = await _db()
    db.add(ServiceState(service_id=plex, status="down", fail_count=3, quiet=False, cert_notified=0))
    await db.commit()
    return plex, r.json()["id"], agen, db, HttpClients(httpx.MockTransport(fake or PveFake())), _maker_from(agen)


async def test_zelfherstel_een_push_per_storing(authed):
    """Een lange storing met een herstart om de 10 min: elke poging in 🔔, maar op de gsm alleen de eerste poging en
    de eerste pauze. Na een geslaagde check (buiten onderhoud) is het een nieuwe storing."""
    webpush._sent.clear()
    plex, rid, agen, db, http, maker = await _heal_setup(authed)
    await _run(PushService([]))  # wat er al was (2FA ingeschakeld), zoals door de worker
    phone = Phone(A)
    await _subscribe(authed, phone, "Pixel", "warn")
    t0 = datetime.now(timezone.utc)
    # Twee herstarts, pauze, een uur later weer twee herstarts en weer een pauze.
    for m in (0, 11, 22, 75, 86, 97):
        await healing.check(maker, plex, http, t0 + timedelta(minutes=m))
    attempt, pause = "Zelfherstel: Plex was 3× down", "Zelfherstel voor Plex gepauzeerd"
    notes = await _heal_notes(db)
    # Alleen wat naar de gsm moet, heeft een sleutel; de rest is meteen "verstuurd" (alleen in 🔔).
    assert [(n.title, n.level, n.push_key, n.pushed_at is None) for n in notes] == [
        (attempt, "warn", f"heal{rid}", True), (attempt, "warn", None, False), (pause, "err", f"heal{rid}:pauze", True),
        (attempt, "warn", None, False), (attempt, "warn", None, False), (pause, "err", None, False)]
    # Alles staat ook op de tijdlijn.
    events = (await db.execute(select(Event.title).where(Event.service_id == plex, Event.kind == "actie"))).scalars()
    assert sorted(events) == sorted(n.title for n in notes)
    svc = PushService([phone])
    await _run(svc)
    got = svc.to(phone)
    assert [m["title"] for m in got] == [attempt, pause]
    assert got[0]["tag"] == f"k{webpush.topic_for(f'heal{rid}')}"

    # Een geslaagde check tijdens onderhoud maakt geen einde aan de storing.
    db.add(CheckResult(service_id=plex, ts=datetime.now(timezone.utc), ok=True, maintenance=True))
    await db.commit()
    await healing.check(maker, plex, http, t0 + timedelta(hours=3))
    # Plex was even terug: wat nu komt, is een nieuwe storing, en mag weer één keer naar de gsm.
    await asyncio.sleep(0.01)
    db.add(CheckResult(service_id=plex, ts=datetime.now(timezone.utc), ok=True, maintenance=False))
    await db.commit()
    await asyncio.sleep(0.01)
    for m in (11, 22, 33):
        await healing.check(maker, plex, http, t0 + timedelta(hours=3, minutes=m))
    notes = (await _heal_notes(db))[6:]
    assert [(n.title, n.push_key, n.pushed_at is None) for n in notes] == [
        (attempt, None, False), (attempt, f"heal{rid}", True), (pause, f"heal{rid}:pauze", True)]
    await _run(svc)
    assert [m["title"] for m in svc.to(phone)] == [attempt, pause, attempt, pause]
    await agen.aclose()


class BrokenPve(PveFake):
    """Proxmox die elke actie weigert: de herstart mislukt."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.method == "POST":
            self.calls.append(req)
            return httpx.Response(500, text="kapot")
        return super().__call__(req)


async def test_zelfherstel_mislukt_en_melden_van_de_tegel(authed):
    plex, rid, agen, db, http, maker = await _heal_setup(authed, BrokenPve(), max_per_hour=5)
    t0 = datetime.now(timezone.utc)
    assert (await healing.check(maker, plex, http, t0)).startswith("mislukt")
    assert (await healing.check(maker, plex, http, t0 + timedelta(minutes=11))).startswith("mislukt")
    notes = await _heal_notes(db)
    assert [(n.title, n.level, n.push_key, n.pushed_at is None) for n in notes] == [
        ("Zelfherstel voor Plex mislukt", "err", f"heal{rid}", True),
        ("Zelfherstel voor Plex mislukt", "err", None, False)]

    async def melden(mode: str) -> None:
        svc = await db.get(Service, plex)
        svc.check = {"type": "http", "notify": mode}
        # Een nieuwe storing: zonder de instelling van de tegel zou dit weer naar de gsm gaan.
        db.add(CheckResult(service_id=plex, ts=datetime.now(timezone.utc), ok=True, maintenance=False))
        await db.commit()
        await asyncio.sleep(0.01)

    # Melden: alleen hier (🔔). Nooit naar de gsm, ook niet de eerste van een nieuwe storing.
    await melden("centrum")
    assert (await healing.check(maker, plex, http, t0 + timedelta(minutes=22))).startswith("mislukt")
    (n,) = (await _heal_notes(db))[2:]
    assert n.push_key is None and n.pushed_at is not None
    # Melden: niet (alleen de tijdlijn). Geen melding, wel de tijdlijn; ook de pauze.
    await melden("uit")
    before = len(await _heal_notes(db))
    for m in (33, 44, 55):
        await healing.check(maker, plex, http, t0 + timedelta(minutes=m))
    assert len(await _heal_notes(db)) == before
    titles = list((await db.execute(select(Event.title).where(Event.service_id == plex, Event.kind == "actie")
                                    .order_by(Event.id))).scalars())
    assert titles[-2:] == ["Zelfherstel voor Plex mislukt", "Zelfherstel voor Plex gepauzeerd"]
    rule = await db.get(HealRule, rid)
    await db.refresh(rule)
    assert rule.last_result.startswith("limiet")

    # De proef zegt hetzelfde.
    g = healing.gates(rule, 3, False, False, t0)
    for mode, end in (("push", "in 🔔; op je gsm alleen de eerste poging van deze storing"),
                      ("centrum", "in 🔔, niet op je gsm (Melden staat op alleen hier)"),
                      ("uit", "alleen op de tijdlijn (Melden staat op niet)")):
        assert healing.rule_plan(rule, "Plex", g, ValueError("x"), t0, mode=mode)["after"][0].endswith(end)

    # Een limiet van 6 kan niet meer (die pauzeerde nooit); een oudere regel op 6 telt als 5.
    r = await authed.put(f"/api/heal/{rid}", json={"service_id": plex, "after": 3, "max_per_hour": 6,
                                                   "action": rule.action})
    assert r.status_code == 422
    rule.max_per_hour = 6
    await db.commit()
    assert (await authed.get(f"/api/heal?service_id={plex}")).json()[0]["max_per_hour"] == 5
    await agen.aclose()


async def test_heal_ssh_action_and_test_button(authed):
    node = Node()
    hid = await _host(authed, "media", await node.start(), node.key)
    g = await _group(authed)
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    r = await authed.post("/api/heal", json={"service_id": plex, "action": {"kind": "ssh", "host_id": hid,
                                                                           "op": "systemctl", "name": "plexmediaserver"}})
    rid = r.json()["id"]
    assert r.json()["describe"] == "herstart dienst plexmediaserver op media"
    t = await authed.post(f"/api/heal/{rid}/test")
    assert t.status_code == 200, t.text
    assert any("systemctl restart plexmediaserver" in c for c in node.commands)
    r = await authed.put(f"/api/heal/{rid}", json={"service_id": plex, "enabled": False, "after": 5,
                                                   "action": {"kind": "ssh", "host_id": hid, "op": "docker", "name": "plex"}})
    assert r.json()["enabled"] is False and r.json()["describe"] == "herstart container plex op media"
    assert (await authed.delete(f"/api/heal/{rid}")).status_code == 204
    audit = (await authed.get("/api/auth/audit?action=heal_rule_tested")).json()["items"]
    assert audit
