"""Proefmodus voor de hersteltest en het verwijderen van snapshots (hw → snapshots): tonen wat er zou gebeuren,
zonder iets te veranderen, met dezelfde calls als het echte werk."""

import json
import time
from datetime import datetime, timezone
from urllib.parse import parse_qs

import httpx
from sqlalchemy import select

from app import proef, setupcheck
from app.health import snapshots as snap
from app.models import AppState, AuditLog, Event, Notification, UpdateRun
from app.monitoring import restoretest
from app.monitoring.checks import HttpClients
from app.routers import health as health_router, restoretest as rt_router

from .test_buitenaf import CF
from .test_integrations import _group, _svc
from .test_kaart_hersteltest import Pve, _maker
from .test_meldingen_onderhoud import _db

READ_SECRET = "LEESGEHEIM-1234567"
ACT_SECRET = "ACTIEGEHEIM-7654321"
SECRETS = {"username": "lees@pve!dash", "password": READ_SECRET,
           "action_username": "actie@pve!acties", "action_password": ACT_SECRET}
ACT_PRIVS = {p: 1 for p in (*setupcheck.RESTORE_PRIVS, "VM.PowerMgmt", "VM.Snapshot", "Datastore.Audit")}


def _perms(req: httpx.Request) -> httpx.Response:
    act = ACT_SECRET in req.headers.get("authorization", "")
    return httpx.Response(200, json={"data": {"/": ACT_PRIVS if act else {"Sys.Audit": 1, "VM.Audit": 1}}})


class World(Pve):
    """De nep-Proxmox van de hersteltest, plus wat de proef extra navraagt, en elke call met query en token."""

    def __init__(self):
        super().__init__()
        self.full: list[tuple[str, str, dict, bool]] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        p = req.url.path.removeprefix("/api2/json")
        q = req.url.query.decode()
        body = {k: v[0] for k, v in parse_qs(req.content.decode()).items()} if req.content else {}
        self.full.append((req.method, req.url.path + (f"?{q}" if q else ""), body,
                          ACT_SECRET in req.headers.get("authorization", "")))
        if p == "/access/permissions":
            return _perms(req)
        if p == "/cluster/nextid":
            v = int(parse_qs(q)["vmid"][0])
            return httpx.Response(400) if v in self.guests else httpx.Response(200, json={"data": str(v)})
        if p == "/nodes/pve50/storage/local-lvm/status":
            return httpx.Response(200, json={"data": {"avail": 50_000_000_000, "total": 100_000_000_000}})
        r = super().__call__(req)
        if p == "/nodes/pve50/storage/pbs-pi/content":
            r = httpx.Response(200, json={"data": [{**b, "size": 2_000_000_000} for b in r.json()["data"]]})
        return r

    def writes(self, since: int = 0) -> list[tuple[str, str, dict]]:
        return [(m, p.removeprefix("/api2/json"), b) for m, p, b, _ in self.full[since:] if m != "GET"]


def _calls(plan: dict) -> list[tuple[str, str, dict | None]]:
    out = []
    for s in plan["steps"]:
        method, path = s["call"].split(" ", 1)
        out.append((method, path.removeprefix("/api2/json"), s.get("data")))
    return out


def _str(d: dict) -> dict:
    return {k: str(v) for k, v in d.items()}


async def _state(make) -> dict:
    async with make() as db:
        st = await restoretest.ensure_state(db, restoretest.STATE_KEY, {})
        return dict(st.value or {})


async def _rows() -> tuple[int, int, int]:
    """Meldingen, gebeurtenissen en auditregels."""
    agen, db = await _db()
    out = tuple([len((await db.execute(select(m))).scalars().all()) for m in (Notification, Event, AuditLog)])
    await agen.aclose()
    return out


async def _put_state(make, **changes) -> None:
    async with make() as db:
        st = await restoretest.ensure_state(db, restoretest.STATE_KEY, {})
        st.value = {**(st.value or {}), **changes}
        await db.commit()


async def _setup(authed, monkeypatch):
    monkeypatch.setattr(restoretest, "BOOT_WAIT", 0)
    world = World()
    http = HttpClients(httpx.MockTransport(world))
    monkeypatch.setattr(rt_router, "clients", http)
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://192.168.0.50:8006", secrets=SECRETS, name="pve")
    return world, http, sid


async def test_proef_verandert_niets_en_doet_wat_de_echte_test_doet(authed, monkeypatch):
    world, http, sid = await _setup(authed, monkeypatch)
    make = _maker()
    r = await authed.put("/api/restoretest/settings", json={"storage": "local-lvm"})
    assert r.status_code == 200
    before = (await _state(make), await _rows())

    r = await authed.post("/api/restoretest/proef")
    assert r.status_code == 200, r.text
    plan = r.json()
    # Alleen gelezen, niets bewaard: geen slot, geen geschiedenis, geen melding, geen auditregel.
    assert world.full and all(m == "GET" for m, *_ in world.full)
    assert (await _state(make), await _rows()) == before

    assert plan["proef"] and plan["title"].startswith("Hersteltest zou plex (105) terugzetten als CT 9901 op pve50")
    assert {s["machine"] for s in plan["steps"]} == {"pve50 via tegel pve"}
    assert {s["who"] for s in plan["steps"]} == {"API-token actie@pve!acties"}
    assert [c[:2] for c in _calls(plan)] == [
        ("POST", "/nodes/pve50/lxc"), ("PUT", "/nodes/pve50/lxc/9901/config"),
        ("POST", "/nodes/pve50/lxc/9901/status/start"), ("POST", "/nodes/pve50/lxc/9901/status/stop"),
        ("DELETE", "/nodes/pve50/lxc/9901?purge=1&destroy-unreferenced-disks=1")]
    assert plan["steps"][3]["when"] == "als CT 9901 draait" and "purge=1" in plan["steps"][4]["note"]
    checks = {c["what"]: c for c in plan["checks"]}
    assert checks["back-up"]["ok"] and "nog nooit getest" in checks["back-up"]["detail"]
    assert checks["ID 9901 vrij in de hele cluster"]["ok"] is True
    assert checks["vrije ruimte op local-lvm (pve50)"]["ok"] is True
    assert checks["rechten (actietoken)"]["ok"] is True
    text = json.dumps(plan)
    assert READ_SECRET not in text and ACT_SECRET not in text and "PVEAPIToken" not in text

    # Dezelfde calls in dezelfde volgorde als de echte test, met dezelfde gegevens.
    n = len(world.full)
    real = await restoretest.run(make, http, manual=True)
    assert real["ok"] and real["vmid"] == 9901
    done = world.writes(n)
    assert [(m, p) for m, p, _ in done] == [c[:2] for c in _calls(plan)]
    assert done[0][2] == _str(plan["steps"][0]["data"])
    assert done[0][2]["storage"] == "local-lvm"
    # De netwerkkaarten van de kopie zijn pas na het terugzetten te zien; de rest van de PUT staat in het plan.
    assert done[1][2] == _str(restoretest.detach_call("pve50", 9901, {"net0": "x", "net1": "y"})[2])
    assert _str(plan["steps"][1]["data"]).items() <= done[1][2].items()
    assert all(act for m, _, _, act in world.full[n:] if m != "GET")  # wat verandert, met het actietoken

    # Terwijl er een test loopt: dezelfde 409 als ▶ nu testen, en de proef neemt geen slot.
    await _put_state(make, running={"at": datetime.now(timezone.utc).isoformat(), "step": "terugzetten"})
    r = await authed.post("/api/restoretest/proef")
    assert r.status_code == 409 and r.json()["detail"] == "Er loopt al een hersteltest"
    # Van buitenaf mag kijken: de proef staat niet achter de buitenmodus.
    await _put_state(make, running=None)
    r = await authed.post("/api/restoretest/proef", headers=CF)
    assert r.status_code == 200 and (await _state(make))["running"] is None


async def test_proef_zonder_proxmox_tegel(authed):
    plan = (await authed.post("/api/restoretest/proef")).json()
    assert plan["proef"] and plan["steps"] == [] and plan["checks"][0]["ok"] is False
    assert plan["title"] == "Hersteltest zou mislukken: geen Proxmox-tegel"


async def test_echte_test_gebruikt_dezelfde_bouwers(authed, monkeypatch):
    world, http, sid = await _setup(authed, monkeypatch)
    seen = []
    for name in ("restore_call", "detach_call", "start_call", "stop_call", "delete_call"):
        orig = getattr(restoretest, name)
        monkeypatch.setattr(restoretest, name, lambda *a, _o=orig, _n=name: seen.append(_n) or _o(*a))
    assert (await restoretest.run(_maker(), http, manual=True))["ok"]
    assert seen == ["restore_call", "detach_call", "start_call", "stop_call", "delete_call"]


async def test_proef_met_een_onderbroken_test(authed, monkeypatch):
    world, http, sid = await _setup(authed, monkeypatch)
    make = _maker()
    old = datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat()
    # Zonder merkteken: niet verwijderd, en dat staat erbij.
    await _put_state(make, running={"at": old, "vmid": 105, "node": "pve50"})
    plan = (await authed.post("/api/restoretest/proef")).json()
    assert plan["skipped"][0]["what"] == "oude test-CT 105 op pve50 opruimen"
    assert "geen test-CT van de homepage" in plan["skipped"][0]["why"]
    assert not any("/lxc/105" in s["call"] for s in plan["steps"])

    # Met merkteken: eerst opruimen (opvallend), en het ID komt dan vrij voor de kopie.
    world.guests[9901] = {"type": "lxc", "vmid": 9901, "name": "hersteltest-110", "node": "pve50", "status": "running"}
    world.conf[9901] = {"description": f"{restoretest.MARKER}: kopie van CT 110"}
    await _put_state(make, running={"at": old, "vmid": 9901, "node": "pve50"})
    plan = (await authed.post("/api/restoretest/proef")).json()
    assert all(m == "GET" for m, *_ in world.full) and 9901 in world.guests
    assert [c[:2] for c in _calls(plan)][:2] == [("POST", "/nodes/pve50/lxc/9901/status/stop"),
                                                ("DELETE", "/nodes/pve50/lxc/9901?purge=1&destroy-unreferenced-disks=1")]
    assert "purge=1" in plan["warnings"][0] and "CT 9901" in plan["warnings"][0]
    assert "na het opruimen hierboven" in next(c for c in plan["checks"] if c["what"] == "vrij ID")["detail"]
    n = len(world.full)
    assert (await restoretest.run(make, http, manual=True))["ok"]
    assert [(m, p) for m, p, _ in world.writes(n)] == [c[:2] for c in _calls(plan)]


async def test_automatisch_alleen_proef(authed, monkeypatch):
    world, http, sid = await _setup(authed, monkeypatch)
    make = _maker()
    r = await authed.put("/api/restoretest/settings", json={"enabled": True, "dry": True, "day": 1, "hour": 0})
    assert r.status_code == 200 and r.json()["settings"]["dry"] is True
    audit = (await authed.get("/api/auth/audit?action=restoretest_settings")).json()["items"]
    assert audit[0]["detail"]["dry"] is True
    now = datetime.now(timezone.utc)
    assert restoretest.due(await _state(make), now)  # in proefmodus mag de proef meteen

    out = await restoretest.run(make, http)  # zoals de worker
    assert out["proef"] and all(m == "GET" for m, *_ in world.full)
    v = await _state(make)
    assert "running" not in v and not v.get("history")
    assert len(v["dry_history"]) == 1 and v["dry_history"][0]["manual"] is False
    assert v["dry_history"][0]["plan"]["title"].startswith("Hersteltest zou plex (105)")
    assert v["last_at"] and not restoretest.due(v, datetime.now(timezone.utc))
    agen, db = await _db()
    ev = (await db.execute(select(Event).where(Event.kind == "backup"))).scalars().all()
    assert len(ev) == 1 and ev[0].title.startswith(proef.EVENT_PREFIX + "Hersteltest zou")
    assert ev[0].data["proef"] is True and ev[0].level == "info" and ev[0].service_id == sid
    assert not (await db.execute(select(Notification).where(Notification.source == "backup"))).scalars().all()
    blob = json.dumps(v) + (ev[0].body or "") + json.dumps(ev[0].data)
    assert READ_SECRET not in blob and ACT_SECRET not in blob

    # De checklist zegt dat er niets echt teruggezet wordt.
    row = await setupcheck.restore(db)
    assert row["state"] == "half" and row["text"] == "Aan in proefmodus: er wordt niets echt teruggezet."
    await agen.aclose()
    data = (await authed.get("/api/restoretest")).json()
    assert data["history"] == [] and len(data["dry_history"]) == 1

    # ▶ nu testen test ook in proefmodus echt; de proef heeft de keuze van de CT niet beïnvloed.
    real = await restoretest.run(make, http, manual=True)
    assert real["ok"] and real["source_vmid"] == 105
    assert any(m == "POST" and p == "/nodes/pve50/lxc" for m, p, _ in world.writes())


async def test_aanzetten_na_het_moment_start_geen_echte_test(authed, monkeypatch):
    world, http, sid = await _setup(authed, monkeypatch)
    make = _maker()
    # Dag 1 om 0 uur: dat moment is deze maand altijd al voorbij.
    r = await authed.put("/api/restoretest/settings", json={"enabled": True, "day": 1, "hour": 0})
    v = await _state(make)
    assert v["last_at"] and not restoretest.due(v, datetime.now(timezone.utc))
    nxt = datetime.fromisoformat(r.json()["next"]).astimezone()
    assert nxt > datetime.now(timezone.utc) and nxt.month != datetime.now().astimezone().month

    # Alleen proef aan (en de proef van deze maand nog niet gedaan), dan weer uit: ook geen echte test.
    await authed.put("/api/restoretest/settings", json={"enabled": True, "dry": True, "day": 1, "hour": 0})
    await _put_state(make, last_at=datetime(2020, 1, 1, tzinfo=timezone.utc).isoformat())
    assert restoretest.due(await _state(make), datetime.now(timezone.utc))
    await authed.put("/api/restoretest/settings", json={"enabled": True, "dry": False, "day": 1, "hour": 0})
    v = await _state(make)
    assert not restoretest.due(v, datetime.now(timezone.utc)) and v["settings"]["dry"] is False
    assert not world.writes() and not v.get("history")


def _pve_snapshots(calls: list, now: float):
    def handler(req: httpx.Request) -> httpx.Response:
        p = req.url.path
        calls.append((req.method, p))
        if p == "/api2/json/access/permissions":
            return _perms(req)
        if p == "/api2/json/nodes/pve50/qemu/100/snapshot":
            return httpx.Response(200, json={"data": [
                {"name": "hp-upd-20261001-040000", "snaptime": int(now - 40 * 86400), "vmstate": 1},
                {"name": "gisteren", "snaptime": int(now - 86400), "parent": "hp-upd-20261001-040000"},
                {"name": "current", "parent": "gisteren", "running": 1}]})
        if req.method == "DELETE" and p.startswith("/api2/json/nodes/pve50/qemu/100/snapshot/"):
            return httpx.Response(200, json={"data": "UPID:pve50:del"})
        return httpx.Response(404)
    return handler


async def test_snapshot_verwijderen_proef_en_terugdraaien(authed, monkeypatch):
    calls: list = []
    http = HttpClients(httpx.MockTransport(_pve_snapshots(calls, time.time())))
    monkeypatch.setattr(health_router, "clients", http)
    g = await _group(authed)
    sid = await _svc(authed, g, "proxmox", "https://pve.jbogaert.be", secrets=SECRETS, name="PVE")
    name = "hp-upd-20261001-040000"
    agen, db = await _db()
    mine = UpdateRun(target="ssh:1", target_name="opnsense", status="ok", finished_at=datetime.now(timezone.utc),
                     snapshot={"kind": "api", "service_id": sid, "type": "qemu", "vmid": 100, "node": "pve50",
                               "name": name})
    other = UpdateRun(target="ssh:2", target_name="ander", status="ok", finished_at=datetime.now(timezone.utc),
                      snapshot={"kind": "pct", "host_id": 9, "vmid": 105, "node": "pve50", "name": name})
    db.add_all([mine, other])
    db.add(AppState(key=snap.STATE_KEY, value={"items": [{"node": "pve50", "vmid": 100, "name": name}]}))
    await db.commit()
    ids = (mine.id, other.id)
    await agen.aclose()
    assert (await authed.get(f"/api/updates/runs/{ids[0]}")).json()["can_rollback"]

    ref = {"service_id": sid, "node": "pve50", "type": "qemu", "vmid": 100, "name": name}
    r = await authed.post("/api/health/snapshots/proef", json=ref)
    assert r.status_code == 200, r.text
    plan = r.json()
    assert calls and all(m == "GET" for m, _ in calls)
    checks = {c["what"]: c for c in plan["checks"]}
    exists = checks[f"snapshot {name} van VM 100 bestaat"]
    assert exists["ok"] and "40 dagen oud" in exists["detail"] and "RAM" in exists["detail"]
    assert "gisteren" in exists["detail"] and checks["VM.Snapshot (actietoken)"]["ok"] is True
    assert [s["call"] for s in plan["steps"]] == [f"DELETE /api2/json/nodes/pve50/qemu/100/snapshot/{name}"]
    assert plan["steps"][0]["who"] == "API-token actie@pve!acties"
    assert len(plan["warnings"]) == 1 and f"#{ids[0]}" in plan["warnings"][0]
    text = json.dumps(plan)
    assert READ_SECRET not in text and ACT_SECRET not in text
    # Niets veranderd: de rij staat er nog, geen auditregel, terugdraaien kan nog.
    data = (await authed.get("/api/health")).json()
    assert [s["name"] for s in data["snapshots"]["items"]] == [name]
    assert (await authed.get("/api/auth/audit?action=snapshot_delete")).json()["items"] == []
    assert (await authed.get(f"/api/updates/runs/{ids[0]}")).json()["can_rollback"]

    gone = (await authed.post("/api/health/snapshots/proef", json={**ref, "name": "bestaat-niet"})).json()
    assert gone["checks"][0]["ok"] is False and not gone["warnings"]
    n = len(calls)
    bad = await authed.post("/api/health/snapshots/proef", json={**ref, "name": "x;rm"})
    assert bad.status_code == 502 and len(calls) == n
    assert (await authed.post("/api/health/snapshots/proef", json=ref, headers=CF)).status_code == 200

    # Het echte verwijderen: dezelfde call, met dezelfde bouwer, en die run biedt terugdraaien niet meer aan.
    used = []
    orig = snap.delete_call
    monkeypatch.setattr(snap, "delete_call", lambda *a: used.append(a) or orig(*a))
    n = len(calls)
    r = await authed.post("/api/health/snapshots/delete", json=ref)
    assert r.status_code == 200 and used == [("pve50", "qemu", 100, name)]
    assert [f"{m} {p}" for m, p in calls[n:] if m != "GET"] == [plan["steps"][0]["call"]]
    assert not (await authed.get(f"/api/updates/runs/{ids[0]}")).json()["can_rollback"]
    agen, db = await _db()
    assert (await db.get(UpdateRun, ids[0])).snapshot["removed_at"]
    assert not (await db.get(UpdateRun, ids[1])).snapshot.get("removed_at")  # andere CT, zelfde naam
    await agen.aclose()
