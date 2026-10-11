"""Proefmodus van zelfherstel: tonen wat een regel zou doen (machine, call of commando, als wie), zonder het te doen.
Ook een regel op "alleen proef": hij gaat automatisch af zoals altijd, maar zet alleen op de tijdlijn wat hij zou doen."""

import json
from datetime import datetime, timedelta, timezone

import asyncssh
import httpx
from sqlalchemy import func, select

from app.models import Event, HealRule, Notification, Service, ServiceState, SshHost
from app.monitoring import healing
from app.monitoring.checks import HttpClients
from app.routers import heal as heal_router

from .test_integrations import Fake as PveFake, _group, _svc
from .test_upgrade_herstel import Node, _db, _maker_from

PVE_URL = "https://pve.jbogaert.be"
PVE_SECRETS = {"username": "homepage@pve!dash", "password": "geheim",
               "action_username": "homepage-acties@pve!acties", "action_password": "actie-geheim-9876"}
CT101 = {"kind": "integration", "action": "reboot", "label": "herstart CT 101",
         "params": {"node": "pve50", "type": "lxc", "vmid": 101}}
SSH_PW = "ssh-geheim-7731"


class StatusNode(Node):
    """Zoals Node, met een eigen wachtwoord en antwoorden op wat de proef vraagt (sudo -n, is-active, inspect)."""

    def __init__(self):
        super().__init__()
        self.users: list[str] = []
        self.sudo_rc = 0
        self.status, self.status_rc = "inactive", 3

    async def handle(self, proc):
        cmd = proc.command or ""
        if cmd.endswith("sh -c true"):
            self.commands.append(cmd)
            if self.sudo_rc:
                proc.stderr.write("sudo: a password is required\n")
            proc.exit(self.sudo_rc)
            return
        if "is-active" in cmd:
            self.commands.append(cmd)
            proc.stdout.write(self.status + "\n")
            proc.exit(self.status_rc)
            return
        if "docker inspect" in cmd:
            self.commands.append(cmd)
            proc.stderr.write("Error: No such object: plex\n")
            proc.exit(1)
            return
        await super().handle(proc)

    async def start(self):
        node = self

        class S(asyncssh.SSHServer):
            def begin_auth(self, u):
                node.users.append(u)
                return True

            def password_auth_supported(self):
                return True

            def validate_password(self, u, p):
                return p == SSH_PW

        self.server = await asyncssh.create_server(S, "127.0.0.1", 0, server_host_keys=[self.key],
                                                   process_factory=self.handle)
        return self.server.sockets[0].getsockname()[1]


async def _ssh_host(authed, node, username="beheer", pin=True):
    port = await node.start()
    r = await authed.post("/api/ssh/hosts", json={"name": "media", "host": "127.0.0.1", "port": port,
                                                  "username": username, "password": SSH_PW})
    assert r.status_code == 201, r.text
    hid = r.json()["id"]
    if pin:
        agen, db = await _db()
        h = await db.get(SshHost, hid)
        h.host_key = node.key.export_public_key().decode()
        await db.commit()
        await agen.aclose()
    return hid, port


async def _state(db, sid, fails):
    st = await db.get(ServiceState, sid)
    if st is None:
        db.add(ServiceState(service_id=sid, status="down", fail_count=fails, quiet=False, cert_notified=0))
    else:
        st.fail_count = fails
    await db.commit()


async def _count(db, model, *where) -> int:
    return (await db.execute(select(func.count()).select_from(model).where(*where))).scalar()


def _check(plan, what):
    return next(c for c in plan["checks"] if c["what"] == what)


async def _audits(authed, action):
    return (await authed.get(f"/api/auth/audit?action={action}")).json()["items"]


def test_gates_in_dezelfde_volgorde_als_check():
    now = datetime(2026, 10, 11, 12, 0, tzinfo=timezone.utc)
    rule = HealRule(enabled=True, after=3, max_per_hour=2, fired=[], last_at=None, dry_run=False, action={})
    g = healing.gates(rule, 3, False, False, now)
    assert g.blocked is None and all(c["ok"] for c in g.checks)
    assert [c["what"] for c in g.checks] == ["service faalt", "niets waar ze van afhangt ligt plat", "niet in onderhoud",
                                            "regel staat aan", "3× na elkaar down", "minstens 10 min ertussen",
                                            "hoogstens 2× per uur"]
    assert healing.gates(rule, 2, False, False, now).blocked == "na"
    assert healing.gates(rule, 3, True, False, now).blocked == "stil"
    assert healing.gates(rule, 3, False, True, now).blocked == "onderhoud"
    rule.last_at = now - timedelta(minutes=4)
    g = healing.gates(rule, 3, False, False, now)
    assert g.blocked == "wachttijd" and g.checks[5]["detail"] == "nog 6 min"
    # Twee keer het afgelopen uur, één keer langer geleden: die telt niet meer.
    rule.last_at = now - timedelta(minutes=20)
    rule.fired = [(now - timedelta(minutes=m)).isoformat() for m in (20, 40, 70)]
    g = healing.gates(rule, 3, False, False, now)
    assert g.blocked == healing.LIMIT and len(g.fired) == 2 and g.checks[-1]["detail"] == "2× het afgelopen uur"
    # De limiet weegt pas als de rest in orde is (zoals vroeger: geen pauzemelding tijdens de wachttijd).
    rule.last_at = now - timedelta(minutes=5)
    assert healing.gates(rule, 3, False, False, now).blocked == "wachttijd"


async def test_proef_proxmox_toont_de_call_zonder_ze_te_doen(authed, monkeypatch):
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", PVE_URL, secrets=PVE_SECRETS, name="PVE")
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    rid = (await authed.post("/api/heal", json={"service_id": plex, "action": {**CT101, "service_id": pve}})).json()["id"]
    fake = PveFake()
    http = HttpClients(httpx.MockTransport(fake))
    monkeypatch.setattr(heal_router, "clients", http)
    agen, db = await _db()
    await _state(db, plex, 1)
    events, notes = await _count(db, Event), await _count(db, Notification)

    r = await authed.post(f"/api/heal/{rid}/proef")
    assert r.status_code == 200, r.text
    plan = r.json()
    # Alleen gelezen: de stand van CT 101, met het leestoken.
    assert [(c.method, c.url.path) for c in fake.calls] == [("GET", "/api2/json/cluster/resources")]
    assert plan["proef"] is True and plan["title"] == "Zelfherstel voor Plex: herstart CT 101"
    read, act = plan["steps"]
    assert read["call"] == f"GET {PVE_URL}/api2/json/cluster/resources" and read["who"] == "API-token homepage@pve!dash"
    # CT 101 staat uit: de herstart wordt een start, met het actietoken.
    assert act["call"] == f"POST {PVE_URL}/api2/json/nodes/pve50/lxc/101/status/start"
    assert act["who"] == "API-token homepage-acties@pve!acties" and act["via"] == "proxmox-api"
    assert "start in plaats van reboot" in act["note"] and act["machine"] == f"PVE ({PVE_URL})"
    assert _check(plan, "CT 101 (homepage)") == {"what": "CT 101 (homepage)", "ok": True,
                                                  "detail": "staat nu stopped op pve50"}
    # Nu nog maar één keer mislukt: de regel zou nog niet afgaan, en de proef zegt waarom.
    assert _check(plan, "3× na elkaar down")["ok"] is False and plan["would_fire"] is False
    assert any(w.startswith("Nu zou de regel niet afgaan: 3× na elkaar down (nu 1×)") for w in plan["warnings"])
    text = json.dumps(plan)
    assert "actie-geheim-9876" not in text and "=geheim" not in text and "PVEAPIToken" not in text

    # Niets veranderd: geen telling, geen melding, geen gebeurtenis; wel wie er keek.
    rule = await db.get(HealRule, rid)
    await db.refresh(rule)
    assert rule.fired == [] and rule.last_at is None and rule.last_result is None
    assert await _count(db, Event) == events and await _count(db, Notification) == notes
    assert (await _audits(authed, "heal_rule_proef"))[0]["detail"] == {"rule": rid, "what": "herstart CT 101"}

    # Zonder te kijken: beide mogelijkheden, en geen enkele call.
    fake.calls.clear()
    quick = await healing.plan_rule(db, rule, http, probe=False)
    assert fake.calls == []
    assert [(s["call"].split("/")[-1], s.get("when")) for s in quick["steps"]] == [
        ("resources", None), ("reboot", "als 101 draait"), ("start", "als 101 uit staat")]

    # Het echte werk stuurt precies dezelfde calls als de proef toonde, met het token dat de proef noemde.
    await _state(db, plex, 3)
    res = await healing.check(_maker_from(agen), plex, http, datetime.now(timezone.utc))
    assert res == "ok: start gestart voor 101 op pve50"
    assert [f"{c.method} {c.url}" for c in fake.calls] == [read["call"], act["call"]]
    assert fake.calls[-1].headers["authorization"] == "PVEAPIToken=homepage-acties@pve!acties=actie-geheim-9876"
    await agen.aclose()


async def test_proef_via_ssh_kijkt_alleen(authed):
    node = StatusNode()
    hid, port = await _ssh_host(authed, node)
    g = await _group(authed)
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    action = {"kind": "ssh", "host_id": hid, "op": "systemctl", "name": "plexmediaserver"}
    rid = (await authed.post("/api/heal", json={"service_id": plex, "action": action})).json()["id"]

    plan = (await authed.post(f"/api/heal/{rid}/proef")).json()
    (step,) = plan["steps"]
    assert step["machine"] == f"media (beheer@127.0.0.1:{port})" and step["via"] == "ssh"
    assert step["who"] == "beheer met sudo -n"
    assert step["call"] == "sudo -n sh -c 'systemctl restart plexmediaserver'"
    # Op de machine: alleen kijken, niets herstarten.
    assert node.commands == ["sudo -n sh -c true", "sudo -n sh -c 'systemctl is-active plexmediaserver'"]
    assert node.users == ["beheer"]
    assert _check(plan, "hostsleutel bevestigd")["ok"] is True
    assert _check(plan, "aanmelden als beheer")["detail"] == "met wachtwoord"
    assert _check(plan, "SSH naar media")["ok"] is True and _check(plan, "sudo -n zonder wachtwoord")["ok"] is True
    status = _check(plan, "nu: systemctl is-active plexmediaserver")
    assert status["ok"] is None and status["detail"].startswith("inactive")
    text = json.dumps(plan)
    assert SSH_PW not in text and "PRIVATE KEY" not in text
    assert (await _audits(authed, "heal_rule_proef"))[0]["detail"]["rule"] == rid

    # sudo vraagt een wachtwoord: dan zou de herstart mislukken, en de proef zegt het.
    node.sudo_rc = 1
    plan = (await authed.post(f"/api/heal/{rid}/proef")).json()
    assert _check(plan, "sudo -n zonder wachtwoord") == {"what": "sudo -n zonder wachtwoord", "ok": False,
                                                         "detail": "sudo: a password is required"}
    node.sudo_rc = 0

    # "nu testen" voert echt uit: precies het commando dat de proef toonde.
    node.commands.clear()
    t = await authed.post(f"/api/heal/{rid}/test")
    assert t.status_code == 200, t.text
    assert node.commands == [step["call"]]


async def test_proef_van_een_regel_uit_het_formulier(authed):
    node = StatusNode()
    hid, port = await _ssh_host(authed, node, username="")
    g = await _group(authed)
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    bad = await authed.post("/api/heal/proef", json={"service_id": plex,
                                                     "action": {"kind": "ssh", "host_id": hid, "op": "rm", "name": "x"}})
    assert bad.status_code == 422
    body = {"service_id": plex, "after": 2, "action": {"kind": "ssh", "host_id": hid, "op": "docker", "name": "plex"}}
    r = await authed.post("/api/heal/proef", json=body)
    assert r.status_code == 200, r.text
    plan = r.json()
    # Als root: geen sudo, en geen sudo-check.
    assert plan["steps"][0]["call"] == "sh -c 'docker restart plex'" and plan["steps"][0]["who"] == "root"
    assert node.commands == ["sh -c 'docker inspect -f '\"'\"'{{.State.Status}}'\"'\"' plex'"]
    assert _check(plan, "nu: docker inspect -f '{{.State.Status}}' plex") == {
        "what": "nu: docker inspect -f '{{.State.Status}}' plex", "ok": False, "detail": "Error: No such object: plex"}
    assert plan["rule"] is None and _check(plan, "2× na elkaar down")["ok"] is False
    agen, db = await _db()
    assert await _count(db, HealRule) == 0
    audit = (await _audits(authed, "heal_rule_proef"))[0]["detail"]
    assert audit == {"rule": None, "what": "herstart container plex op media"}

    # Een host waarvan de sleutel nog niet bevestigd is: de echte herstart zou weigeren, de proef ook.
    other = StatusNode()
    hid2, _ = await _ssh_host(authed, other, pin=False)
    body["action"]["host_id"] = hid2
    plan = (await authed.post("/api/heal/proef", json=body)).json()
    assert _check(plan, "hostsleutel bevestigd")["ok"] is False and _check(plan, "SSH naar media")["ok"] is False
    assert other.commands == []
    await agen.aclose()


async def test_alleen_proef_automatisch(authed):
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", PVE_URL, secrets=PVE_SECRETS, name="PVE")
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    r = await authed.post("/api/heal", json={"service_id": plex, "after": 3, "max_per_hour": 2, "dry_run": True,
                                             "action": {**CT101, "service_id": pve}})
    assert r.status_code == 201 and r.json()["dry_run"] is True
    rid = r.json()["id"]
    fake = PveFake()
    http = HttpClients(httpx.MockTransport(fake))
    agen, db = await _db()
    maker = _maker_from(agen)
    await _state(db, plex, 3)
    notes = await _count(db, Notification)
    t0 = datetime.now(timezone.utc)

    res = await healing.check(maker, plex, http, t0)
    assert res == "proef: herstart CT 101, niet uitgevoerd (zie de tijdlijn)"
    # Automatisch wordt er niets gelezen of veranderd op de machine.
    assert fake.calls == []
    ev = (await db.execute(select(Event).where(Event.title.startswith("Proef: ")))).scalars().all()
    assert [e.title for e in ev] == ["Proef: Zelfherstel: Plex was 3× down"]
    assert ev[0].kind == "actie" and ev[0].level == "info" and ev[0].service_id == plex and ev[0].data["proef"] is True
    steps = ev[0].data["plan"]["steps"]
    assert [s["call"] for s in steps] == [f"GET {PVE_URL}/api2/json/cluster/resources",
                                          f"POST {PVE_URL}/api2/json/nodes/pve50/lxc/101/status/reboot",
                                          f"POST {PVE_URL}/api2/json/nodes/pve50/lxc/101/status/start"]
    assert "POST" in ev[0].body and "actie-geheim-9876" not in json.dumps(ev[0].data) + ev[0].body
    assert await _count(db, Notification) == notes
    rule = await db.get(HealRule, rid)
    await db.refresh(rule)
    assert len(rule.fired) == 1 and rule.last_at is not None

    # Dezelfde wachttijd en limiet als een echte regel.
    assert await healing.check(maker, plex, http, t0 + timedelta(minutes=5)) is None
    assert (await healing.check(maker, plex, http, t0 + timedelta(minutes=11))).startswith("proef:")
    assert await healing.check(maker, plex, http, t0 + timedelta(minutes=22)) is None
    assert await healing.check(maker, plex, http, t0 + timedelta(minutes=23)) is None
    await db.refresh(rule)
    assert rule.last_result == "limiet bereikt (proef): al 2× het afgelopen uur" and len(rule.fired) == 2
    # De pauze één keer op de tijdlijn, als proef; nog altijd geen melding en geen push.
    paused = (await db.execute(select(Event).where(Event.title == "Proef: Zelfherstel voor Plex gepauzeerd"))).scalars().all()
    assert len(paused) == 1 and paused[0].data["plan"]["skipped"][0]["what"] == "herstart CT 101"
    assert await _count(db, Notification) == notes and fake.calls == []

    # Aan/uit zetten zonder dry_run (zoals een oudere pagina) laat de proef staan.
    keep = await authed.put(f"/api/heal/{rid}", json={"service_id": plex, "enabled": True, "after": 3, "max_per_hour": 2,
                                                      "action": {**CT101, "service_id": pve}})
    assert keep.json()["dry_run"] is True and len(keep.json()["fired"]) == 2
    # Naar echt: de proefbeurten tellen niet mee, de eerste echte herstart volgt meteen.
    real = await authed.put(f"/api/heal/{rid}", json={"service_id": plex, "enabled": True, "after": 3, "max_per_hour": 2,
                                                      "dry_run": False, "action": {**CT101, "service_id": pve}})
    out = real.json()
    assert out["dry_run"] is False and out["fired"] == [] and out["last_at"] is None and out["last_result"] is None
    res = await healing.check(maker, plex, http, t0 + timedelta(minutes=24))
    assert res == "ok: start gestart voor 101 op pve50"
    assert [c.method for c in fake.calls] == ["GET", "POST"]
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "herstel"))).scalars()]
    assert titles == ["Zelfherstel: Plex was 3× down"] and await _count(db, Notification) == notes + 1
    audit = (await _audits(authed, "heal_rule_changed"))[0]["detail"]
    assert audit == {"rule": rid, "enabled": True, "dry_run": False}
    await agen.aclose()


async def test_geen_zelfherstel_tijdens_onderhoud(authed, monkeypatch):
    g = await _group(authed)
    pve = await _svc(authed, g, "proxmox", PVE_URL, secrets=PVE_SECRETS, name="PVE")
    plex = await _svc(authed, g, "", "http://plex.jbogaert.be", name="Plex")
    rid = (await authed.post("/api/heal", json={"service_id": plex, "action": {**CT101, "service_id": pve}})).json()["id"]
    fake = PveFake()
    http = HttpClients(httpx.MockTransport(fake))
    monkeypatch.setattr(heal_router, "clients", http)
    agen, db = await _db()
    maker = _maker_from(agen)
    await _state(db, plex, 3)
    now = datetime.now(timezone.utc)
    # De node waar Plex van afhangt is in onderhoud (gepland of met de hand): niet ingrijpen.
    svc, node = await db.get(Service, plex), await db.get(Service, pve)
    svc.parent_id, node.maintenance_until = pve, now + timedelta(hours=1)
    await db.commit()
    assert await healing.check(maker, plex, http, now) is None
    assert fake.calls == [] and await _count(db, Notification, Notification.source == "herstel") == 0
    rule = await db.get(HealRule, rid)
    await db.refresh(rule)
    assert rule.fired == [] and rule.last_result is None
    plan = (await authed.post(f"/api/heal/{rid}/proef")).json()
    assert _check(plan, "niet in onderhoud")["ok"] is False and plan["would_fire"] is False

    node.maintenance_until = None
    await db.commit()
    assert (await healing.check(maker, plex, http, now)).startswith("ok")
    await agen.aclose()


class ContainerFake(PveFake):
    """Portainer kent de container van vaultwarden nog (inspect), een ander id niet meer."""

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if req.method == "GET" and req.url.path == f"/api/endpoints/2/docker/containers/{'a' * 64}/json":
            self.calls.append(req)
            assert req.headers["x-api-key"] == "ptr_geheim"
            return httpx.Response(200, json={"Name": "/vaultwarden", "State": {"Status": "running"}})
        return super().__call__(req)


async def test_proef_portainer_en_adguard_in_volgorde(authed, monkeypatch):
    g = await _group(authed)
    ptr = await _svc(authed, g, "portainer", "https://portainer.jbogaert.be", secrets={"key": "ptr_geheim"}, name="Portainer")
    adg = await _svc(authed, g, "adguard", "https://adguard.jbogaert.be",
                     secrets={"username": "admin", "password": "adg-geheim-55"}, name="AdGuard")
    vw = await _svc(authed, g, "", "http://vw.jbogaert.be", name="Vaultwarden")
    restart = {"kind": "integration", "service_id": ptr, "action": "restart", "label": "herstart vaultwarden",
               "params": {"env": 2, "id": "a" * 64, "name": "vaultwarden"}}
    protect = {"kind": "integration", "service_id": adg, "action": "protection", "label": "bescherming aan",
               "params": {"enabled": True}}
    r1 = (await authed.post("/api/heal", json={"service_id": vw, "action": restart})).json()["id"]
    r2 = (await authed.post("/api/heal", json={"service_id": vw, "action": protect})).json()["id"]
    fake = ContainerFake()
    http = HttpClients(httpx.MockTransport(fake))
    monkeypatch.setattr(heal_router, "clients", http)

    p1 = (await authed.post(f"/api/heal/{r1}/proef")).json()
    (s1,) = p1["steps"]
    assert s1["call"] == f"POST https://portainer.jbogaert.be/api/endpoints/2/docker/containers/{'a' * 64}/restart"
    assert s1["via"] == "portainer-api" and s1["who"] == "API-sleutel"
    assert _check(p1, "container vaultwarden") == {"what": "container vaultwarden", "ok": True, "detail": "staat nu running"}
    p2 = (await authed.post(f"/api/heal/{r2}/proef")).json()
    (s2,) = p2["steps"]
    assert s2["call"] == "POST https://adguard.jbogaert.be/control/protection" and s2["data"] == {"enabled": True}
    assert s2["via"] == "adguard-api" and s2["who"] == "gebruiker admin"
    assert all(c.method == "GET" for c in fake.calls) and len(fake.calls) == 1
    text = json.dumps([p1, p2])
    assert "ptr_geheim" not in text and "adg-geheim-55" not in text

    # Een container die opnieuw gemaakt is, heeft een ander id: de proef ziet dat.
    stale = await authed.post("/api/heal/proef", json={"service_id": vw, "action": {
        **restart, "params": {"env": 2, "id": "c" * 64, "name": "vaultwarden"}}})
    check = _check(stale.json(), "container vaultwarden")
    assert check["ok"] is False and "bestaat niet meer" in check["detail"]

    # Echt: in de volgorde van de regels, met precies de calls van de proef.
    agen, db = await _db()
    await _state(db, vw, 3)
    fake.calls.clear()
    assert (await healing.check(_maker_from(agen), vw, http, datetime.now(timezone.utc))).startswith("ok")
    assert [f"{c.method} {c.url}" for c in fake.calls] == [s1["call"], s2["call"]]
    assert json.loads(fake.calls[-1].content) == s2["data"]
    await agen.aclose()
