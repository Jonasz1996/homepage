"""Nieuwe service in één keer, en opruimen: tegen een nep-NPM, -Cloudflare, -AdGuard en -Proxmox met toestand."""

import asyncio
import base64
import copy
import json
import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import httpx
import pytest
import pyotp
from sqlalchemy import select, update

from app import nieuweservice as ns
from app.db import get_db
from app.integrations import cloudflare as cfm
from app.integrations import npm as npmm
from app.main import app
from app.models import AppState, AuditLog, Notification, Service, Session, SshHost
from app.monitoring import routes
from app.monitoring.checks import HttpClients
from app.routers import integrations as integrations_router
from app.routers import nieuweservice as router

from .test_integrations import _group, _svc

NPM = "http://192.168.0.245:81"
PVE = "https://192.168.0.50:8006"
AG = "http://192.168.0.2"
READ, WRITE = "lees@jbogaert.be", "dashboard-acties@jbogaert.be"
NPM_PW = {READ: "lees-GEHEIM-1", WRITE: "schrijf-GEHEIM-2"}
CF_TOKEN = "cf-GEHEIM-3"
AG_PW = "ag-GEHEIM-4"
PVE_READ, PVE_READ_PW = "homepage@pve!dash", "pve-GEHEIM-5"
PVE_ACT, PVE_ACT_PW = "homepage-acties@pve!acties", "pve-GEHEIM-6"
ZONE_ID = "f" * 32
ACCOUNT = "0123456789abcdef0123456789abcdef"
TUNNEL = "6f1c2d3e-0000-4000-8000-000000000001"
FQDN = "jellyfin.jbogaert.be"
ADDR = ("A", "AAAA", "CNAME")


def _ok(result, **extra) -> httpx.Response:
    return httpx.Response(200, json={"success": True, "errors": [], "result": result, **extra})


def _cf_error(code: int, message: str, status: int = 400) -> httpx.Response:
    return httpx.Response(status, json={"success": False, "errors": [{"code": code, "message": message}]})


def _pve(data) -> httpx.Response:
    return httpx.Response(200, json={"data": data})


class Lab:
    """NPM (192.168.0.245:81), Cloudflare (api.cloudflare.com), AdGuard en Proxmox in één nep met toestand."""

    def __init__(self):
        now = datetime.now(timezone.utc)
        self.calls: list[httpx.Request] = []
        self.npm_version: tuple | None = (2, 16, 0)
        self.npm_users = {READ: {"visibility": "all"}, WRITE: {"visibility": "all"}}
        self.hosts = [{"id": 1, "domain_names": ["plex.jbogaert.be"], "forward_scheme": "http",
                       "forward_host": "192.168.0.20", "forward_port": 32400, "certificate_id": 3, "enabled": 1,
                       "access_list_id": 0, "advanced_config": "", "meta": {"nginx_online": True}}]
        self.redirs: list[dict] = []
        self.dead: list[dict] = []
        self.nginx_ok = True
        self.certs = [{"id": 3, "nice_name": "*.jbogaert.be", "domain_names": ["*.jbogaert.be", "jbogaert.be"],
                       "provider": "letsencrypt", "expires_on": (now + timedelta(days=54)).strftime("%Y-%m-%d %H:%M:%S"),
                       "meta": {"dns_challenge": True,
                                "dns_provider_credentials": "dns_cloudflare_api_token = GEHEIM-CF"}}]
        self.access_lists = [{"id": 1, "name": "LAN", "satisfy_any": 0, "items": [],
                              "clients": [{"address": "192.168.0.0/16", "directive": "allow"}]}]
        self.records = [{"id": "a" * 32, "type": "CNAME", "name": "plex.jbogaert.be",
                         "content": f"{TUNNEL}.cfargotunnel.com", "proxied": True, "ttl": 1, "comment": None}]
        self.tunnel = {"version": 4, "source": "cloudflare", "config": {
            "originRequest": {"connectTimeout": 30}, "warp-routing": {"enabled": False}, "ingress": [
                {"hostname": "plex.jbogaert.be", "service": "https://192.168.0.245:443",
                 "originRequest": {"noTLSVerify": True, "originServerName": "plex.jbogaert.be"}},
                {"service": "http_status:404"}]}}
        self.tunnel_puts: list[dict] = []
        self.rewrites = [{"domain": "*.jbogaert.be", "answer": "192.168.0.245", "enabled": True}]
        self.guests = [{"vmid": 123, "type": "lxc", "node": "pve50", "pool": None, "status": "running",
                        "name": "jellyfin", "ip": "192.168.0.27"}]
        self.jobs = [{"id": "backup-1a2b", "type": "vzdump", "storage": "pbs-pi", "vmid": "101,105", "enabled": 1,
                      "schedule": "02:00"}]
        self.storages = [{"storage": "pbs-pi", "type": "pbs"}]
        self.acl = {"/": {"Sys.Modify"}, "/storage/pbs-pi": {"Datastore.Allocate"}, "/vms/123": {"VM.Allocate"}}
        self.fail: dict[tuple[str, str], httpx.Response] = {}
        self.lie: set[tuple[str, str]] = set()          # doen, maar 500 antwoorden
        self.hold = None                                # ((method, path), bereikt, loslaten)
        self.tokens: dict[str, str] = {}
        self.next_host, self.next_cert = 57, 12

    # --- verkeer ---

    def __call__(self, req: httpx.Request):
        self.calls.append(req)
        if self.hold and (req.method, req.url.path) == self.hold[0]:
            return self._held(req)
        return self._answer(req)

    async def _held(self, req):
        _, reached, release = self.hold
        self.hold = None
        reached.set()
        await release.wait()
        return self._answer(req)

    def _answer(self, req):
        key = (req.method, req.url.path)
        if key in self.fail:
            return self.fail[key]
        res = self._route(req)
        if key in self.lie and res.status_code < 400:
            return httpx.Response(500, json={"error": {"code": 500, "message": "Internal Error"}})
        return res

    def _route(self, req):
        host = req.url.host
        if host == "192.168.0.245":
            return self._npm(req)
        if host == "api.cloudflare.com":
            return self._cf(req)
        if host == "192.168.0.2":
            return self._ag(req)
        if host == "192.168.0.50":
            return self._pvex(req)
        return httpx.Response(404)

    def writes(self, host: str | None = None) -> list[tuple[str, str]]:
        return [(r.method, r.url.path) for r in self.calls
                if r.method != "GET" and r.url.path != "/api/tokens" and (host is None or r.url.host == host)]

    # --- NPM ---

    def _npm(self, req):
        p, m = req.url.path, req.method
        if p == "/api/" and m == "GET":
            v = self.npm_version
            return httpx.Response(200, json={"status": "OK", **({"version": {"major": v[0], "minor": v[1],
                                                                             "revision": v[2]}} if v else {})})
        if p == "/api/tokens" and m == "POST":
            b = json.loads(req.content)
            if NPM_PW.get(b.get("identity")) != b.get("secret"):
                return httpx.Response(401, json={"error": {"code": 401, "message": "Invalid email or password"}})
            t = f"jwt-GEHEIM-{len(self.tokens)}"
            self.tokens[t] = b["identity"]
            return httpx.Response(200, json={"token": t, "expires": "2099-01-01T00:00:00.000Z"})
        user = self.tokens.get(req.headers.get("authorization", "").removeprefix("Bearer "))
        if user is None:
            return httpx.Response(401, json={"error": {"code": 401, "message": "Unauthorized"}})
        if p == "/api/users/me":
            u = dict(self.npm_users[user])
            roles = u.pop("roles", [])
            perms = {"visibility": "all", "proxy_hosts": "manage", "redirection_hosts": "view", "dead_hosts": "view",
                     "streams": "view", "access_lists": "view", "certificates": "manage", **u}
            return httpx.Response(200, json={"id": 2, "email": user, "roles": roles, "permissions": perms})
        if m != "GET" and user != WRITE:
            return httpx.Response(403, json={"error": {"code": 403, "message": "Permission Denied"}})
        body = json.loads(req.content) if req.content else None
        if p == "/api/nginx/proxy-hosts":
            if m == "GET":
                return httpx.Response(200, json=self.hosts)
            taken = [n for n in body["domain_names"] for h in [*self.hosts, *self.redirs, *self.dead]
                     if n in h["domain_names"]]
            if taken:
                return httpx.Response(400, json={"error": {"code": 400, "message": f"{taken[0]} is already in use"}})
            h = {"id": self.next_host, **body, "enabled": 1, "owner_user_id": 2, "meta": self._nginx()}
            self.next_host += 1
            self.hosts.append(h)
            # NPM geeft de rij terug van vóór nginx ze laadde.
            return httpx.Response(201, json={**h, "meta": {}})
        if mm := re.fullmatch(r"/api/nginx/proxy-hosts/(\d+)", p):
            h = next((h for h in self.hosts if h["id"] == int(mm.group(1))), None)
            if h is None:
                return httpx.Response(404, json={"error": {"code": 404, "message": "Not Found"}})
            if m == "GET":
                return httpx.Response(200, json=h)
            if m == "PUT":
                h.update(body)
                h["meta"] = self._nginx()
                return httpx.Response(200, json=h)
            self.hosts.remove(h)
            return httpx.Response(200, json=True)
        if p == "/api/nginx/certificates":
            if m == "GET":
                return httpx.Response(200, json=self.certs)
            meta = body.get("meta") or {}
            new = tuple(self.npm_version or (2, 16, 0))[:2] >= (2, 13)
            if new and "letsencrypt_email" in meta:
                return httpx.Response(400, json={"error": {"code": 400,
                                                           "message": "data/meta must NOT have additional properties"}})
            if not new and not meta.get("letsencrypt_email"):
                return httpx.Response(400, json={"error": {"code": 400, "message": "letsencrypt_email is required"}})
            c = {"id": self.next_cert, "provider": "letsencrypt", "nice_name": body["domain_names"][0],
                 "domain_names": body["domain_names"], "expires_on": "2027-01-09 10:00:00",
                 "meta": {**meta, "letsencrypt_certificate": {"cn": body["domain_names"][0]}}}
            self.next_cert += 1
            self.certs.append(c)
            return httpx.Response(201, json=c)
        if mm := re.fullmatch(r"/api/nginx/certificates/(\d+)", p):
            c = next((c for c in self.certs if c["id"] == int(mm.group(1))), None)
            if c is None:
                return httpx.Response(404, json={"error": {"code": 404, "message": "Not Found"}})
            self.certs.remove(c)
            return httpx.Response(200, json=True)
        lists = {"/api/nginx/redirection-hosts": self.redirs, "/api/nginx/dead-hosts": self.dead,
                 "/api/nginx/access-lists": self.access_lists}
        if p in lists and m == "GET":
            return httpx.Response(200, json=lists[p])
        return httpx.Response(404, json={"error": {"code": 404, "message": "Not Found"}})

    def _nginx(self) -> dict:
        return {"nginx_online": self.nginx_ok, "nginx_err": None if self.nginx_ok else 'unknown directive "foo"'}

    # --- Cloudflare ---

    def _cf(self, req):
        if req.headers.get("authorization") != f"Bearer {CF_TOKEN}":
            return _cf_error(10000, "Authentication error", 403)
        p, m, q = req.url.path.removeprefix("/client/v4"), req.method, req.url.params
        body = json.loads(req.content) if req.content else None
        if p == "/zones":
            return _ok([{"id": ZONE_ID, "name": "jbogaert.be"}] if q.get("name") == "jbogaert.be" else [])
        if p == f"/zones/{ZONE_ID}/dns_records":
            if m == "GET":
                recs = [r for r in self.records if not q.get("name") or r["name"] == q.get("name")]
                return _ok(recs, result_info={"page": 1, "per_page": 1000, "total_pages": 1, "count": len(recs)})
            if body["type"] in ADDR and any(r["name"] == body["name"] and r["type"] in ADDR for r in self.records):
                return _cf_error(81053, "An A, AAAA, or CNAME record with that host already exists.")
            rec = {"id": secrets.token_hex(16), "ttl": 1, "proxied": False, "comment": None, **body}
            self.records.append(rec)
            return _ok(rec)
        if mm := re.fullmatch(rf"/zones/{ZONE_ID}/dns_records/([0-9a-f]{{32}})", p):
            rec = next((r for r in self.records if r["id"] == mm.group(1)), None)
            if rec is None:
                return _cf_error(81044, "Record does not exist.", 404)
            if m == "DELETE":
                self.records.remove(rec)
                return _ok({"id": rec["id"]})
            return _ok(rec)
        if p == f"/accounts/{ACCOUNT}/cfd_tunnel/{TUNNEL}/configurations":
            if m == "PUT":
                self.tunnel_puts.append(body)
                self.tunnel = {"version": self.tunnel["version"] + 1, "source": "cloudflare", "config": body["config"]}
            return _ok({"tunnel_id": TUNNEL, **self.tunnel})
        return _cf_error(7003, "Could not route to this path", 404)

    # --- AdGuard ---

    def _ag(self, req):
        if req.headers.get("authorization") != "Basic " + base64.b64encode(f"admin:{AG_PW}".encode()).decode():
            return httpx.Response(401)
        p = req.url.path
        if p == "/control/rewrite/list":
            return httpx.Response(200, json=self.rewrites)
        body = json.loads(req.content)
        if p == "/control/rewrite/add":
            self.rewrites.append({**body, "enabled": True})
            return httpx.Response(200, text="OK\n")
        if p == "/control/rewrite/delete":
            self.rewrites = [r for r in self.rewrites if (r["domain"], r["answer"]) != (body["domain"], body["answer"])]
            return httpx.Response(200)
        return httpx.Response(404)

    # --- Proxmox ---

    def _guest(self, vmid: int) -> dict | None:
        return next((g for g in self.guests if g["vmid"] == int(vmid)), None)

    def _pvex(self, req):
        auth = req.headers.get("authorization", "")
        action = auth == f"PVEAPIToken={PVE_ACT}={PVE_ACT_PW}"
        if not action and auth != f"PVEAPIToken={PVE_READ}={PVE_READ_PW}":
            return httpx.Response(401)
        p, m, q = req.url.path.removeprefix("/api2/json"), req.method, req.url.params
        form = {k: v[0] for k, v in parse_qs(req.content.decode()).items()} if req.content else {}
        if p == "/cluster/resources":
            if q.get("type") == "node":
                return _pve([{"type": "node", "node": "pve50", "status": "online"}])
            return _pve([{"id": f"{g['type']}/{g['vmid']}", "type": g["type"], "vmid": g["vmid"], "node": g["node"],
                          "status": g["status"], "name": g["name"], **({"pool": g["pool"]} if g["pool"] else {})}
                         for g in self.guests])
        if p == "/cluster/backup" and m == "GET":
            return _pve(self.jobs)
        if (mm := re.fullmatch(r"/cluster/backup/([\w-]+)", p)) and m == "PUT":
            job = next((j for j in self.jobs if j["id"] == mm.group(1)), None)
            if job is None:
                return httpx.Response(500, json={"data": None, "errors": {"id": "no such job"}})
            if not action or "Sys.Modify" not in self.acl.get("/", set()) \
                    or "Datastore.Allocate" not in self.acl.get(f"/storage/{job['storage']}", set()):
                return httpx.Response(403, json={"data": None})
            job["vmid"] = form["vmid"]
            return _pve(None)
        if p == "/storage":
            return _pve(self.storages)
        if p == "/access/permissions":
            path = q.get("path")
            return _pve({path: {priv: 1 for priv in self.acl.get(path, set())}})
        if p == "/pools" and m == "PUT":
            pool, g = form["poolid"], self._guest(form["vms"])
            if not action or "Pool.Allocate" not in self.acl.get(f"/pool/{pool}", set()):
                return httpx.Response(403, json={"data": None})
            if form.get("delete"):
                if g["pool"] == pool:
                    g["pool"] = None
            elif g["pool"] and g["pool"] != pool:
                return httpx.Response(500, json={"data": None, "message": f"VM {g['vmid']} belongs already to pool"})
            else:
                g["pool"] = pool
            return _pve(None)
        if mm := re.fullmatch(r"/nodes/(\w+)/lxc/(\d+)/(interfaces|config)", p):
            g = self._guest(mm.group(2))
            if mm.group(3) == "interfaces":
                return _pve([{"name": "lo", "inet": "127.0.0.1/8"}, {"name": "eth0", "inet": f"{g['ip']}/24"}])
            return _pve({"net0": f"name=eth0,bridge=vmbr0,ip={g['ip']}/24"})
        return httpx.Response(404)


# --- opzet -------------------------------------------------------------------------------------------------------

async def _db():
    agen = app.dependency_overrides[get_db]()
    return agen, await agen.__anext__()


@pytest.fixture
async def lab(authed, monkeypatch):
    f = Lab()
    monkeypatch.setattr(integrations_router, "clients", HttpClients(httpx.MockTransport(f)))

    async def probe(where):
        return True, None
    monkeypatch.setattr(routes, "_probe", probe)
    monkeypatch.setattr(ns.get_settings(), "syslog_target", "192.168.10.156")
    npmm._tokens.clear()
    cfm._zones.clear()
    ns._guest_cache.clear()
    ns._options.clear()
    f.apis = {}
    for name, kind, url, config, sec in (
            ("NPM", "npm", NPM, {}, {"username": READ, "password": NPM_PW[READ], "action_username": WRITE,
                                     "action_password": NPM_PW[WRITE]}),
            ("Cloudflare DNS", "cloudflare", cfm.API, {"zone": "jbogaert.be", "account": ACCOUNT}, {"token": CF_TOKEN}),
            ("AdGuard", "adguard", AG, {}, {"username": "admin", "password": AG_PW}),
            ("Proxmox", "proxmox", PVE, {}, {"username": PVE_READ, "password": PVE_READ_PW, "action_username": PVE_ACT,
                                             "action_password": PVE_ACT_PW})):
        r = await authed.post("/api/apis", json={"name": name, "kind": kind, "url": url, "config": config,
                                                 "secrets": sec})
        assert r.status_code == 201, r.text
        f.apis[kind] = r.json()["id"]
    f.group = await _group(authed)
    f.pve_tile = await _svc(authed, f.group, "link", PVE, name="pve50")
    r = await authed.post(f"/api/apis/{f.apis['proxmox']}/tiles", json={"service_ids": [f.pve_tile]})
    assert r.json()["changed"] == 1
    agen, db = await _db()
    db.add(SshHost(name="jellyfin", host="192.168.0.27", source=f"pve:{f.pve_tile}:lxc/123", folder="pve50"))
    db.add(AppState(key="zabbix", value={"hosts": [{"id": "10501", "host": "jellyfin", "name": "Jellyfin",
                                                     "ips": ["192.168.0.27"], "dns": []}]}))
    await db.commit()
    await agen.aclose()
    f.calls.clear()
    return f


def _body(lab, **kw) -> dict:
    return {"name": "jellyfin", "ip": "192.168.0.27", "port": 8096,
            "tile": {"group_id": lab.group, "label": "Jellyfin"}, **kw}


async def _wait(timeout: float = 10) -> None:
    # Eerst de run laten afwerken: met SQLite delen alle sessies één verbinding.
    await asyncio.wait_for(asyncio.gather(*list(router._tasks)), timeout)


async def _proef(authed, body: dict) -> dict:
    r = await authed.post("/api/nieuweservice/proef", json=body)
    assert r.status_code == 200, r.text
    return r.json()["plan"]


async def _start(authed, body: dict, plan: dict | None = None) -> dict:
    plan = plan or await _proef(authed, body)
    r = await authed.post("/api/nieuweservice/maken", json={**body, "plan_hash": plan["hash"]})
    assert r.status_code == 202, r.text
    await _wait()
    return (await authed.get(f"/api/nieuweservice/runs/{r.json()['run']['id']}")).json()


async def _cleanup(authed, body: dict) -> tuple[dict, dict]:
    r = await authed.post("/api/nieuweservice/opruimen/proef", json=body)
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    r = await authed.post("/api/nieuweservice/opruimen", json={**body, "plan_hash": plan["hash"]})
    assert r.status_code == 202, r.text
    await _wait()
    return plan, (await authed.get(f"/api/nieuweservice/runs/{r.json()['run']['id']}")).json()


async def _undo(authed, run_id: str) -> tuple[dict, dict]:
    r = await authed.post(f"/api/nieuweservice/runs/{run_id}/ongedaan/proef")
    assert r.status_code == 200, r.text
    plan = r.json()["plan"]
    r = await authed.post(f"/api/nieuweservice/runs/{run_id}/ongedaan", json={"plan_hash": plan["hash"]})
    assert r.status_code == 202, r.text
    await _wait()
    return plan, (await authed.get(f"/api/nieuweservice/runs/{r.json()['run']['id']}")).json()


def _keys(plan: dict) -> list[str]:
    return [s["call"] for s in plan["steps"]]


def _whats(plan: dict, field: str = "skipped") -> str:
    return json.dumps(plan[field], ensure_ascii=False)


def _host(lab, name=FQDN) -> dict | None:
    return next((h for h in lab.hosts if name in h["domain_names"]), None)


async def _attention(authed) -> dict:
    return {i["key"]: i for i in (await authed.get("/api/attention")).json()["items"]}


async def _checklist(authed) -> dict:
    r = (await authed.get("/api/attention/setup")).json()
    return next(x for g in r["groups"] for x in g["rows"] if x["key"] == "nieuweservice")


# --- proef -------------------------------------------------------------------------------------------------------

async def test_proef_doet_niets_en_toont_elke_call(lab, authed):
    plan = await _proef(authed, _body(lab))
    calls = _keys(plan)
    assert calls[0] == f"POST {NPM}/api/nginx/proxy-hosts"
    assert calls[1] == f"PUT {cfm.API}/accounts/{ACCOUNT}/cfd_tunnel/{TUNNEL}/configurations"
    assert calls[2] == f"POST {cfm.API}/zones/{ZONE_ID}/dns_records"
    assert calls[3].startswith("tegel 'Jellyfin' in P / G")
    assert calls[4] == f"PUT {PVE}/api2/json/cluster/backup/backup-1a2b"
    assert len(calls) == 5
    assert plan["steps"][4]["data"] == {"vmid": "101,105,123"}
    assert WRITE in plan["steps"][0]["who"] and plan["steps"][1]["who"] == "API-token van 'Cloudflare DNS'"
    assert PVE_ACT in plan["steps"][4]["who"]
    assert "*.jbogaert.be" in _whats(plan)
    assert plan["kan"] is True and re.fullmatch(r"[0-9a-f]{16}", plan["hash"])
    assert plan["fqdn"] == FQDN and plan["guest"]["vmid"] == 123
    assert lab.writes() == []
    text = json.dumps(plan)
    assert "GEHEIM" not in text and "dns_provider_credentials" not in text
    # De proef staat in het auditlog (ze probeert een poort die je intikte).
    agen, db = await _db()
    a = (await db.execute(select(AuditLog).where(AuditLog.action == "nieuwe_service_proef"))).scalar_one()
    assert a.detail["fqdn"] == FQDN and a.detail["input"]["ip"] == "192.168.0.27"
    await agen.aclose()


async def test_proef_zonder_npm(authed):
    g = await _group(authed)
    plan = await _proef(authed, {"name": "test", "ip": "192.168.0.50", "port": 8080, "exposure": "lan",
                                 "tile": {"group_id": g, "label": "Test"}})
    assert plan["kan"] is False and plan["steps"] == []
    assert plan["waarom"][0].startswith("Geen NPM-API")


async def test_ongeldige_invoer(lab, authed):
    for bad in ({"ip": "8.8.8.8"}, {"ip": "127.0.0.1"}, {"name": "a.b"}, {"name": "-x"}, {"port": 0},
                {"backup_job": "../x"}, {"domain": "evil.example"}, {"scheme": "ftp"}, {"exposure": "beide"}):
        r = await authed.post("/api/nieuweservice/proef", json={**_body(lab), **bad})
        assert r.status_code == 422, bad
    r = await authed.post("/api/nieuweservice/proef", json={**_body(lab), "tile": {"group_id": lab.group, "label": " "}})
    assert r.status_code == 422
    assert lab.calls == []


async def test_letsencrypt_in_de_juiste_volgorde(lab, authed):
    lab.certs = []
    body = _body(lab)
    plan = await _proef(authed, body)
    assert plan["kan"] is True, plan["waarom"]
    assert [s["call"].split(" ")[0] + " " + s["call"].split("/")[-1] for s in plan["steps"]][:5] == [
        "POST proxy-hosts", "PUT configurations", "POST dns_records", "POST certificates",
        "PUT <host uit stap 1>"]
    assert plan["steps"][3]["data"]["meta"] == {"dns_challenge": False}
    assert any("poort 80" in w and WRITE in w for w in plan["warnings"])
    run = await _start(authed, body, plan)
    assert run["status"] == "klaar", run
    assert [s["key"] for s in run["steps"]] == ["npm_host", "cf_ingress", "cf_record", "npm_cert", "npm_attach",
                                                 "tile", "backup"]
    cert_call = next(r for r in lab.calls if r.method == "POST" and r.url.path == "/api/nginx/certificates")
    assert cert_call.extensions["timeout"]["read"] == 120
    assert json.loads(cert_call.content)["meta"] == {"dns_challenge": False}
    h = _host(lab)
    assert h["certificate_id"] == 12 and h["ssl_forced"] is True
    agen, db = await _db()
    s = (await db.execute(select(Service).where(Service.name == "Jellyfin"))).scalar_one()
    assert s.url == f"https://{FQDN}"
    await agen.aclose()


async def test_letsencrypt_body_oude_npm(lab, authed):
    lab.certs = []
    lab.npm_version = (2, 12, 6)
    plan = await _proef(authed, _body(lab))
    meta = plan["steps"][3]["data"]["meta"]
    assert meta == {"dns_challenge": False, "letsencrypt_email": WRITE, "letsencrypt_agree": True}
    run = await _start(authed, _body(lab), plan)
    assert run["status"] == "klaar", run
    lab.npm_version = None
    npmm._tokens.clear()
    plan = await _proef(authed, _body(lab, name="emby"))
    assert plan["kan"] is False and any("NPM-versie onbekend" in w for w in plan["waarom"])


async def test_lan_met_portforward_patroon_vraagt_een_lijst(lab, authed):
    lab.records = [{"id": "b" * 32, "type": "A", "name": "jbogaert.be", "content": "203.0.113.10", "proxied": True},
                   {"id": "c" * 32, "type": "A", "name": "plex.jbogaert.be", "content": "203.0.113.10", "proxied": True}]
    lab.access_lists += [
        {"id": 2, "name": "Iedereen", "satisfy_any": 0, "items": [],
         "clients": [{"address": "0.0.0.0/0", "directive": "allow"}]},
        {"id": 3, "name": "Wachtwoord", "satisfy_any": 1, "items": [{"username": "jonas"}],
         "clients": [{"address": "192.168.0.0/16", "directive": "allow"}]}]
    plan = await _proef(authed, _body(lab, exposure="lan"))
    assert plan["kan"] is False and any("toegangslijst" in w for w in plan["waarom"])
    plan = await _proef(authed, _body(lab, exposure="lan", access_list_id=1))
    assert plan["kan"] is True, plan["waarom"]
    assert not [s for s in plan["steps"] if "cloudflare" in s["via"]]
    assert plan["steps"][0]["data"]["access_list_id"] == 1
    plan = await _proef(authed, _body(lab, exposure="lan", access_list_id=2))
    assert plan["kan"] is False and any("0.0.0.0/0" in w for w in plan["waarom"])
    plan = await _proef(authed, _body(lab, exposure="lan", access_list_id=3))
    assert plan["kan"] is False and any("satisfy any" in w for w in plan["waarom"])
    plan = await _proef(authed, _body(lab, exposure="lan", poort_443_dicht=True))
    assert plan["kan"] is True and any("Op jouw woord" in w for w in plan["warnings"])
    agen, db = await _db()
    a = (await db.execute(select(AuditLog).where(AuditLog.action == "nieuwe_service_proef")
                          .order_by(AuditLog.id.desc()).limit(1))).scalar_one()
    assert a.detail["input"]["poort_443_dicht"] is True
    await agen.aclose()


async def test_lan_via_tunnel_wildcard_kan_niet(lab, authed):
    lab.records.append({"id": "d" * 32, "type": "CNAME", "name": "*.jbogaert.be",
                        "content": f"{TUNNEL}.cfargotunnel.com", "proxied": True})
    lab.tunnel["config"]["ingress"].insert(1, {"hostname": "*.jbogaert.be", "service": "https://192.168.0.245:443"})
    plan = await _proef(authed, _body(lab, exposure="lan", access_list_id=1))
    assert plan["kan"] is False and any("Via de tunnel is elke naam publiek" in w for w in plan["waarom"])


async def test_lan_tunnel_zonder_wildcard_mag_zonder_lijst(lab, authed, monkeypatch):
    lab.access_lists[0]["clients"] = [{"address": "192.168.0.0/24", "directive": "allow"}]
    plan = await _proef(authed, _body(lab, exposure="lan"))
    assert plan["kan"] is True, plan["waarom"]
    assert plan["steps"][0]["data"]["access_list_id"] == 0
    assert any("192.168.10.156" in w for w in plan["warnings"])
    assert any("Aanbevolen: toegangslijst LAN" in w for w in plan["warnings"])
    monkeypatch.setattr(ns.get_settings(), "syslog_target", "")
    plan = await _proef(authed, _body(lab, exposure="lan"))
    check = next(c for c in plan["checks"] if "laat het dashboard" in c["what"])
    assert check["ok"] is None


async def test_lan_zonder_wildcardcertificaat_kan_niet(lab, authed):
    lab.certs = []
    plan = await _proef(authed, _body(lab, exposure="lan", access_list_id=1))
    assert plan["kan"] is False and any("Let's Encrypt" in w for w in plan["waarom"])
    plan = await _proef(authed, _body(lab, exposure="lan", access_list_id=1, cert="geen"))
    assert plan["kan"] is True, plan["waarom"]
    assert plan["steps"][0]["data"]["certificate_id"] == 0
    assert next(s for s in plan["steps"] if s["via"] == "dashboard")["data"]["url"] == f"http://{FQDN}"


async def test_wildcardcertificaat_vaste_keuze(lab, authed):
    later = copy.deepcopy(lab.certs[0])
    later.update(id=4, expires_on=(datetime.now(timezone.utc) + timedelta(days=80)).strftime("%Y-%m-%d %H:%M:%S"))
    lab.certs.append(later)
    a = await _proef(authed, _body(lab))
    b = await _proef(authed, _body(lab))
    assert a["steps"][0]["data"]["certificate_id"] == 4
    assert a["hash"] == b["hash"]


async def test_adguard_uitgezette_rewrite_telt_niet(lab, authed):
    lab.rewrites[0]["enabled"] = False
    plan = await _proef(authed, _body(lab, exposure="lan", access_list_id=1))
    step = next(s for s in plan["steps"] if s["via"] == "adguard-api")
    assert step["call"] == f"POST {AG}/control/rewrite/add"
    assert step["data"] == {"domain": FQDN, "answer": "192.168.0.245"}


async def test_waarschuwingen_bescherming_en_beheerpagina(lab, authed):
    lab.hosts[0]["access_list_id"] = 1
    lab.hosts[0]["advanced_config"] = "auth_request /outpost.goauthentik.io/auth/nginx;"
    lab.hosts.append({"id": 2, "domain_names": ["photos.jbogaert.be"], "forward_scheme": "http",
                      "forward_host": "192.168.0.21", "forward_port": 2342, "certificate_id": 3, "access_list_id": 1,
                      "advanced_config": "", "meta": {"nginx_online": True}})
    plan = await _proef(authed, _body(lab))
    assert any("De meeste hosts hebben een toegangslijst of login" in w for w in plan["warnings"])
    plan = await _proef(authed, _body(lab, bescherming_van=1))
    assert not any("De meeste hosts" in w for w in plan["warnings"])
    assert plan["steps"][0]["data"]["access_list_id"] == 1
    assert "auth_request" in plan["steps"][0]["data"]["advanced_config"]
    plan = await _proef(authed, _body(lab, name="pve", port=8006, scheme="https"))
    assert any("beheerpagina van Proxmox VE" in w for w in plan["warnings"])


async def test_leesgebruiker_ziet_niet_alles(lab, authed):
    lab.npm_users[READ]["visibility"] = "user"
    plan = await _proef(authed, _body(lab))
    assert plan["kan"] is True and any("De leesgebruiker van NPM" in w for w in plan["warnings"])
    lab.npm_users[WRITE]["visibility"] = "user"
    plan = await _proef(authed, _body(lab))
    assert plan["kan"] is False and any("NPM-schrijfgebruiker" in w for w in plan["waarom"])


async def test_ingress_voor_het_record_en_rest_ongewijzigd(lab, authed):
    before = copy.deepcopy(lab.tunnel["config"])
    run = await _start(authed, _body(lab))
    assert run["status"] == "klaar", run
    order = [(r.method, r.url.host) for r in lab.calls if r.method in ("PUT", "POST") and r.url.host == "api.cloudflare.com"]
    assert order == [("PUT", "api.cloudflare.com"), ("POST", "api.cloudflare.com")]
    put = lab.tunnel_puts[0]["config"]
    assert put["originRequest"] == before["originRequest"] and put["warp-routing"] == before["warp-routing"]
    assert put["ingress"][0] == before["ingress"][0] and put["ingress"][-1] == before["ingress"][-1]
    assert len(put["ingress"]) == 3
    assert put["ingress"][1] == {"hostname": FQDN, "service": "https://192.168.0.245:443",
                                 "originRequest": {"noTLSVerify": True, "originServerName": FQDN}}
    rec = next(r for r in lab.records if r["name"] == FQDN)
    assert (rec["type"], rec["content"], rec["proxied"], rec["comment"]) == (
        "CNAME", f"{TUNNEL}.cfargotunnel.com", True, ns.COMMENT)
    # Een voorbeeld met een andere vaste Host is geen voorbeeld.
    for rule in lab.tunnel["config"]["ingress"][:-1]:
        rule["originRequest"] = {"httpHostHeader": "x.y"}
    plan = await _proef(authed, _body(lab, name="emby"))
    assert plan["kan"] is False and any("maak de tunnelregel zelf" in w for w in plan["waarom"])


# --- uitvoeren ---------------------------------------------------------------------------------------------------

async def test_maken_vraagt_verse_2fa_en_de_hash(lab, authed):
    body = _body(lab)
    plan = await _proef(authed, body)
    agen, db = await _db()
    await db.execute(update(Session).values(auth_at=datetime.now(timezone.utc) - timedelta(hours=1)))
    await db.commit()
    await agen.aclose()
    r = await authed.post("/api/nieuweservice/maken", json={**body, "plan_hash": plan["hash"]})
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    assert (await authed.post("/api/auth/reauth", json={"code": pyotp.TOTP(authed.totp_secret).now()})).status_code == 200
    r = await authed.post("/api/nieuweservice/maken", json={**body, "plan_hash": "0" * 16})
    assert r.status_code == 409 and r.json()["detail"] == "plan_veranderd"
    assert lab.writes() == []
    run = await _start(authed, body, plan)
    assert run["status"] == "klaar", run
    assert [s["status"] for s in run["steps"]] == ["ok"] * 5
    assert [c["kind"] for c in run["created"]] == ["npm_host", "cf_ingress", "cf_record", "tile", "backup"]
    h = _host(lab)
    assert {k: v for k, v in h.items() if k not in ("id", "enabled", "owner_user_id", "meta")} == {
        "domain_names": [FQDN], "forward_scheme": "http", "forward_host": "192.168.0.27", "forward_port": 8096,
        "certificate_id": 3, "ssl_forced": True, "http2_support": True, "hsts_enabled": False,
        "hsts_subdomains": False, "block_exploits": True, "caching_enabled": False, "allow_websocket_upgrade": True,
        "access_list_id": 0, "advanced_config": "", "locations": []}
    assert lab.jobs[0]["vmid"] == "101,105,123"
    agen, db = await _db()
    s = (await db.execute(select(Service).where(Service.name == "Jellyfin"))).scalar_one()
    assert s.url == f"https://{FQDN}" and s.check == {"type": "http", "interval": 60}
    assert s.config == {"zabbix": ""} or s.config == {}
    n = (await db.execute(select(Notification).where(Notification.source == "nieuweservice"))).scalar_one()
    assert n.title == f"Nieuwe service {FQDN} klaar" and n.level == "info" and n.service_id == s.id
    assert n.pushed_at is not None   # geen push voor een gelukte run
    a = (await db.execute(select(AuditLog).where(AuditLog.action == "nieuwe_service_maken"))).scalar_one()
    assert a.detail["steps"] == ["npm_host", "cf_ingress", "cf_record", "tile", "backup"]
    assert a.detail["plan_hash"] == plan["hash"] and a.detail["input"]["name"] == "jellyfin"
    await agen.aclose()
    runs = (await authed.get("/api/nieuweservice/runs")).json()
    assert runs["busy"] is None and runs["runs"][0]["id"] == run["id"]
    assert "call" not in runs["runs"][0]["steps"][0] and "call" in run["steps"][0]


async def test_plan_veranderd_na_de_proef(lab, authed):
    body = _body(lab)
    plan = await _proef(authed, body)
    lab.jobs[0]["vmid"] = "101"
    r = await authed.post("/api/nieuweservice/maken", json={**body, "plan_hash": plan["hash"]})
    assert r.status_code == 409 and r.json()["detail"] == "plan_veranderd"
    assert lab.writes() == []


async def test_kan_niet_is_422(lab, authed):
    lab.hosts[0]["domain_names"] = [FQDN]
    body = _body(lab)
    plan = await _proef(authed, body)
    assert plan["kan"] is False
    r = await authed.post("/api/nieuweservice/maken", json={**body, "plan_hash": plan["hash"]})
    assert r.status_code == 422 and r.json()["detail"] == f"Kan niet: {FQDN} staat al in NPM"


async def test_stopt_bij_de_eerste_fout(lab, authed):
    lab.fail[("POST", f"/client/v4/zones/{ZONE_ID}/dns_records")] = _cf_error(
        81053, "An A, AAAA, or CNAME record with that host already exists.")
    run = await _start(authed, _body(lab))
    assert run["status"] == "gestopt" and run["can_undo"] is True
    assert [s["status"] for s in run["steps"]] == ["ok", "ok", "fout", "wacht", "wacht"]
    assert run["steps"][2]["detail"] == "Cloudflare: An A, AAAA, or CNAME record with that host already exists. (81053)"
    assert run["error"].startswith("stap 3 (DNS-record in Cloudflare): Cloudflare:")
    assert [c["kind"] for c in run["created"]] == ["npm_host", "cf_ingress"]
    assert "spec" not in run["steps"][0]
    agen, db = await _db()
    n = (await db.execute(select(Notification).where(Notification.source == "nieuweservice"))).scalar_one()
    assert n.level == "warn" and n.pushed_at is None and n.push_key == f"ns:{run['id']}"
    assert "Gestopt bij stap 3 (DNS-record in Cloudflare)" in n.body and "Al gemaakt: NPM-host #57, tunnelregel" in n.body
    await agen.aclose()
    item = (await _attention(authed))[f"ns:{run['id']}"]
    assert item["level"] == "warn" and item["title"] == f"Nieuwe service {FQDN} half gemaakt"
    assert item["text"].startswith("Gestopt bij stap 3: stap 3 (DNS-record in Cloudflare): Cloudflare:")
    assert item["text"].endswith("Al gemaakt: NPM-host #57, tunnelregel.")
    assert item["fix"] == {"window": "nieuweservice", "tab": "geschiedenis"}


async def test_nginx_offline_stopt_bij_stap_1(lab, authed):
    lab.nginx_ok = False
    run = await _start(authed, _body(lab))
    assert run["status"] == "gestopt"
    assert run["steps"][0]["status"] == "fout"
    assert run["steps"][0]["detail"].startswith("NPM: nginx weigerde de configuratie")
    assert [c["kind"] for c in run["created"]] == ["npm_host"]
    assert lab.writes("api.cloudflare.com") == []
    plan, undo = await _undo(authed, run["id"])
    assert _keys(plan) == [f"DELETE {NPM}/api/nginx/proxy-hosts/57"]
    assert undo["status"] == "klaar" and _host(lab) is None
    orig = (await authed.get(f"/api/nieuweservice/runs/{run['id']}")).json()
    assert orig["status"] == "ongedaan" and orig["undone_by"] == undo["id"] and orig["can_undo"] is False


async def test_onbekende_uitkomst_wordt_nagekeken(lab, authed):
    lab.lie.add(("POST", "/api/nginx/proxy-hosts"))
    run = await _start(authed, _body(lab))
    assert run["status"] == "gestopt" and run["steps"][0]["status"] == "fout"
    assert run["steps"][0]["detail"] == "NPM: Internal Error"
    assert [(c["kind"], c["id"]) for c in run["created"]] == [("npm_host", 57)]


async def test_ongedaan_maken(lab, authed):
    lab.fail[("POST", f"/client/v4/zones/{ZONE_ID}/dns_records")] = _cf_error(81053, "already exists.")
    run = await _start(authed, _body(lab))
    assert run["status"] == "gestopt"
    plan, undo = await _undo(authed, run["id"])
    assert _keys(plan) == [f"PUT {cfm.API}/accounts/{ACCOUNT}/cfd_tunnel/{TUNNEL}/configurations",
                           f"DELETE {NPM}/api/nginx/proxy-hosts/57"]
    assert undo["status"] == "klaar" and undo["kind"] == "ongedaan" and undo["of"] == run["id"]
    assert [r["kind"] for r in undo["removed"]] == ["cf_ingress", "npm_host"]
    assert _host(lab) is None and len(lab.tunnel["config"]["ingress"]) == 2
    orig = (await authed.get(f"/api/nieuweservice/runs/{run['id']}")).json()
    assert orig["status"] == "ongedaan" and orig["can_undo"] is False
    r = await authed.post(f"/api/nieuweservice/runs/{run['id']}/ongedaan/proef")
    assert r.status_code == 409
    assert not [k for k in await _attention(authed) if k.startswith("ns:")]
    agen, db = await _db()
    titles = [n.title for n in (await db.execute(select(Notification).where(Notification.source == "nieuweservice")))
              .scalars()]
    assert f"Ongedaan gemaakt: {FQDN}" in titles
    await agen.aclose()


async def test_ongedaan_maken_van_een_onbekende_stap(lab, authed):
    """Een stap waarvan de uitkomst onbekend is: ongedaan maken zoekt het object op en haalt het mee weg."""
    lab.fail[("POST", f"/client/v4/zones/{ZONE_ID}/dns_records")] = _cf_error(81053, "already exists.")
    run = await _start(authed, _body(lab))
    agen, db = await _db()
    st = await db.get(AppState, ns.STATE_KEY)
    value = copy.deepcopy(st.value)
    r0 = value["runs"][0]
    r0["created"] = [c for c in r0["created"] if c["kind"] != "npm_host"]
    r0["steps"][0]["status"] = "onbekend"
    st.value = value
    await db.commit()
    await agen.aclose()
    plan, undo = await _undo(authed, run["id"])
    step = next(s for s in plan["steps"] if s["call"].startswith("DELETE"))
    assert step["note"] == "uitkomst van stap 1 onbekend: gevonden, dus mee weg"
    assert _host(lab) is None


async def test_herstart_markeert_onderbroken(lab, authed):
    agen, db = await _db()
    run = {"id": "ns-20261011-153012-a1b2", "kind": "maken", "of": None, "fqdn": FQDN, "by": "jonas",
           "at": "2026-10-11T15:30:12+00:00", "updated_at": "2026-10-11T15:30:19+00:00", "status": "bezig",
           "warning": None, "input": {}, "hash": "0" * 16,
           "steps": [{"nr": 1, "key": "npm_host", "title": "proxy host in NPM", "call": "POST x", "status": "bezig",
                      "detail": None, "spec": {"kind": "npm_host", "name": FQDN, "forward": "http://192.168.0.27:8096"}}],
           "created": [], "removed": [], "error": None, "undone_by": None}
    db.add(AppState(key=ns.STATE_KEY, value={"runs": [run]}))
    await db.commit()
    assert await ns.mark_interrupted(db) == 1
    await db.commit()
    await agen.aclose()
    out = (await authed.get(f"/api/nieuweservice/runs/{run['id']}")).json()
    assert out["status"] == "onderbroken" and out["steps"][0]["status"] == "onbekend" and out["can_undo"] is True
    assert "herstartte" in out["error"]
    run2 = await _start(authed, _body(lab))
    assert run2["status"] == "klaar"


async def test_checklist_rij(lab, authed):
    row = await _checklist(authed)
    assert row["state"] == "ok" and row["fix"] == {"window": "api"}
    r = await authed.patch(f"/api/apis/{lab.apis['npm']}", json={
        "name": "NPM", "kind": "npm", "url": NPM, "secrets": {"action_username": "", "action_password": ""}})
    assert r.status_code == 200, r.text
    await authed.delete(f"/api/apis/{lab.apis['adguard']}")
    row = await _checklist(authed)
    assert row["state"] == "half"
    assert any("README → Nieuwe service" in t for t in row["todo"])
    assert any("LAN-DNS" in t for t in row["todo"])
    for kind in ("npm", "cloudflare", "proxmox"):
        await authed.delete(f"/api/apis/{lab.apis[kind]}")
    row = await _checklist(authed)
    assert row["state"] == "none" and row["optional"] is True


async def test_bezig_zonder_taak_is_onderbroken(lab, authed):
    """Een run die "bezig" bewaard staat maar in dit proces niet loopt, is onderbroken (ook zonder herstart)."""
    agen, db = await _db()
    db.add(AppState(key=ns.STATE_KEY, value={"runs": [{"id": "ns-x", "kind": "maken", "status": "bezig", "fqdn": FQDN,
                                                       "steps": [], "created": []}]}))
    await db.commit()
    await agen.aclose()
    assert (await authed.get("/api/nieuweservice/runs/ns-x")).json()["status"] == "onderbroken"
    assert (await authed.get("/api/nieuweservice/runs")).json()["busy"] is None
    assert (await authed.get("/api/nieuweservice/runs/ns-y")).status_code == 404


async def test_een_run_tegelijk(lab, authed):
    body = _body(lab)
    plan = await _proef(authed, body)
    assert (await authed.get("/api/nieuweservice/opties")).json()["busy"] is None
    reached, release = asyncio.Event(), asyncio.Event()
    lab.hold = (("POST", "/api/nginx/proxy-hosts"), reached, release)
    r = await authed.post("/api/nieuweservice/maken", json={**body, "plan_hash": plan["hash"]})
    assert r.status_code == 202
    run_id = r.json()["run"]["id"]
    await asyncio.wait_for(reached.wait(), 5)
    try:
        other = _body(lab, name="emby", port=8920)
        p2 = await _proef(authed, other)
        r = await authed.post("/api/nieuweservice/maken", json={**other, "plan_hash": p2["hash"]})
        assert r.status_code == 409 and r.json()["detail"] == "bezig"
        opties = (await authed.get("/api/nieuweservice/opties")).json()
        assert opties["busy"]["id"] == run_id and opties["busy"]["steps"][0]["status"] == "bezig"
        assert (await authed.get("/api/nieuweservice/runs")).json()["busy"] == run_id
    finally:
        release.set()
        await _wait()
    assert (await authed.get(f"/api/nieuweservice/runs/{run_id}")).json()["status"] == "klaar"
    assert (await authed.get("/api/nieuweservice/opties")).json()["busy"] is None


async def test_backup_fout_is_niet_fataal(lab, authed):
    lab.fail[("PUT", "/api2/json/cluster/backup/backup-1a2b")] = httpx.Response(403, json={"data": None})
    run = await _start(authed, _body(lab))
    assert run["status"] == "klaar" and run["can_undo"] is False
    assert run["steps"][4]["status"] == "fout" and "403" in run["warning"]
    assert _host(lab) is not None and any(r["name"] == FQDN for r in lab.records)
    agen, db = await _db()
    assert (await db.execute(select(Service).where(Service.name == "Jellyfin"))).scalar_one()
    n = (await db.execute(select(Notification).where(Notification.source == "nieuweservice"))).scalar_one()
    assert n.level == "warn" and n.pushed_at is not None and "Back-up niet ingesteld" in n.body
    await agen.aclose()


async def test_backup_alleen_als_niet_gedekt_en_met_rechten(lab, authed):
    lab.jobs = [{"id": "alles", "storage": "pbs-pi", "all": 1, "enabled": 1}]
    plan = await _proef(authed, _body(lab))
    assert "zit al in back-upjob alles" in _whats(plan) and not [s for s in plan["steps"] if s["via"] == "proxmox-api"]
    lab.jobs = [{"id": "dump", "storage": "pbs-pi", "vmid": "101", "dumpdir": "/mnt/backup", "enabled": 1}]
    plan = await _proef(authed, _body(lab))
    assert "geen back-upjob naar een PBS" in _whats(plan)
    lab.jobs = [{"id": "backup-1a2b", "storage": "pbs-pi", "vmid": "101,105", "enabled": 1}]
    lab.acl["/storage/pbs-pi"] = set()
    plan = await _proef(authed, _body(lab))
    assert "het actietoken mist Datastore.Allocate op /storage/pbs-pi" in _whats(plan)
    assert plan["kan"] is True
    plan = await _proef(authed, _body(lab, backup=False))
    assert "niet gevraagd" in _whats(plan)


async def test_backup_pool_job(lab, authed):
    lab.jobs = [{"id": "backup-pool", "storage": "pbs-pi", "pool": "backup", "enabled": 1}]
    lab.acl["/pool/backup"] = {"Pool.Allocate"}
    plan = await _proef(authed, _body(lab))
    step = next(s for s in plan["steps"] if s["via"] == "proxmox-api")
    assert step["call"] == f"PUT {PVE}/api2/json/pools" and step["data"] == {"poolid": "backup", "vms": "123"}
    run = await _start(authed, _body(lab), plan)
    assert run["status"] == "klaar" and lab.guests[0]["pool"] == "backup"
    assert run["created"][-1]["how"] == "pool"
    ns._guest_cache.clear()
    plan = await _proef(authed, _body(lab, name="emby", port=8920))
    assert "zit al in back-upjob backup-pool (via pool backup)" in _whats(plan)
    lab.guests[0]["pool"] = "media"
    ns._guest_cache.clear()
    plan = await _proef(authed, _body(lab, name="emby", port=8920))
    assert "zit al in pool media: niet verplaatst" in _whats(plan)


# --- opruimen ----------------------------------------------------------------------------------------------------

async def test_opruimen_eerst_dns_tegel_laatst(lab, authed):
    run = await _start(authed, _body(lab, backup=False))
    assert run["status"] == "klaar"
    lab.rewrites.append({"domain": FQDN, "answer": "192.168.0.245", "enabled": True})
    lab.calls.clear()
    plan, done = await _cleanup(authed, {"fqdn": FQDN})
    assert [s["via"] for s in plan["steps"]] == ["cloudflare-api", "cloudflare-api", "adguard-api", "npm-api",
                                                  "dashboard"]
    assert plan["steps"][0]["call"].startswith(f"DELETE {cfm.API}/zones/{ZONE_ID}/dns_records/")
    assert "certificaat #3" in _whats(plan) and "back-up" in _whats(plan)
    assert done["status"] == "klaar", done
    assert [r["kind"] for r in done["removed"]] == ["cf_record", "cf_ingress", "lan_dns", "npm_host", "tile"]
    assert _host(lab) is None and not [r for r in lab.records if r["name"] == FQDN]
    assert not [r for r in lab.tunnel["config"]["ingress"] if r.get("hostname") == FQDN]
    assert [r["domain"] for r in lab.rewrites] == ["*.jbogaert.be"]
    assert lab.certs and lab.certs[0]["id"] == 3
    agen, db = await _db()
    assert not (await db.execute(select(Service).where(Service.name == "Jellyfin"))).scalars().all()
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "check_silenced"))).scalar_one()
    assert (await db.execute(select(AuditLog).where(AuditLog.action == "nieuwe_service_opruimen"))).scalar_one()
    titles = [n.title for n in (await db.execute(select(Notification))).scalars()]
    assert "Check verwijderd: Jellyfin" in titles and f"Opgeruimd: {FQDN}" in titles
    await agen.aclose()
    # Daarna is er niets meer op te ruimen.
    r = await authed.post("/api/nieuweservice/opruimen/proef", json={"fqdn": FQDN})
    plan = r.json()["plan"]
    assert plan["steps"] == [] and plan["kan"] is False
    r = await authed.post("/api/nieuweservice/opruimen", json={"fqdn": FQDN, "plan_hash": plan["hash"]})
    assert r.status_code == 422 and r.json()["detail"] == "Niets op te ruimen"


async def test_opruimen_alleen_npm_records(lab, authed):
    lab.hosts.append({"id": 57, "domain_names": [FQDN], "forward_scheme": "http", "forward_host": "192.168.0.27",
                      "forward_port": 8096, "certificate_id": 3, "access_list_id": 0, "meta": {"nginx_online": True}})
    lab.records += [
        {"id": "1" * 32, "type": "CNAME", "name": FQDN, "content": f"{TUNNEL}.cfargotunnel.com", "proxied": True},
        {"id": "2" * 32, "type": "MX", "name": FQDN, "content": "mail.example.com"},
        {"id": "3" * 32, "type": "TXT", "name": FQDN, "content": "v=spf1 -all"},
        {"id": "4" * 32, "type": "A", "name": FQDN, "content": "203.0.113.9"}]
    lab.tunnel["config"]["ingress"].insert(1, {"hostname": FQDN, "service": "http://192.168.0.99:8080"})
    plan, done = await _cleanup(authed, {"fqdn": FQDN})
    assert [s["call"] for s in plan["steps"]] == [f"DELETE {cfm.API}/zones/{ZONE_ID}/dns_records/{'1' * 32}",
                                                  f"DELETE {NPM}/api/nginx/proxy-hosts/57"]
    skipped = _whats(plan)
    assert "MX-record" in skipped and "TXT-record" in skipped and "203.0.113.9 blijft" in skipped
    assert "http://192.168.0.99:8080 gaat niet naar NPM" in skipped
    assert done["status"] == "klaar"
    assert sorted(r["type"] for r in lab.records if r["name"] == FQDN) == ["A", "MX", "TXT"]
    assert any(r.get("hostname") == FQDN for r in lab.tunnel["config"]["ingress"])


async def test_opruimen_weigert_vreemde_namen(lab, authed):
    for fqdn in ("jbogaert.be", "*.jbogaert.be", "a.b.jbogaert.be", "x.example.com", "192.168.0.5"):
        r = await authed.post("/api/nieuweservice/opruimen/proef", json={"fqdn": fqdn})
        assert r.status_code == 422 and r.json()["detail"] == "Alleen namen als x.jbogaert.be", fqdn
    sid = await _svc(authed, lab.group, "link", "https://192.168.0.5:8006", name="pve")
    r = await authed.post("/api/nieuweservice/opruimen/proef", json={"service_id": sid})
    assert r.status_code == 422
    assert (await authed.post("/api/nieuweservice/opruimen/proef", json={})).status_code == 422
    assert (await authed.post("/api/nieuweservice/opruimen/proef", json={"fqdn": FQDN, "x": 1})).status_code == 422
    assert lab.writes() == []


async def test_opruimen_laat_een_host_met_meer_namen_staan(lab, authed):
    lab.hosts.append({"id": 57, "domain_names": [FQDN, "media.jbogaert.be"], "forward_scheme": "http",
                      "forward_host": "192.168.0.27", "forward_port": 8096, "certificate_id": 3})
    r = await authed.post("/api/nieuweservice/opruimen/proef", json={"fqdn": FQDN})
    plan = r.json()["plan"]
    assert "heeft ook media.jbogaert.be" in _whats(plan)
    assert not [s for s in plan["steps"] if s["call"].startswith("DELETE")]


async def test_opruimen_met_backup(lab, authed):
    run = await _start(authed, _body(lab))
    assert run["status"] == "klaar" and lab.jobs[0]["vmid"] == "101,105,123"
    plan, done = await _cleanup(authed, {"fqdn": FQDN, "backup": True})
    assert plan["steps"][-2]["call"] == f"PUT {PVE}/api2/json/cluster/backup/backup-1a2b"
    assert plan["steps"][-2]["data"] == {"vmid": "101,105"}
    assert done["status"] == "klaar" and lab.jobs[0]["vmid"] == "101,105"


async def test_opruimen_via_de_tegel(lab, authed):
    run = await _start(authed, _body(lab, backup=False))
    tile = next(c for c in run["created"] if c["kind"] == "tile")
    r = await authed.post("/api/nieuweservice/opruimen/proef", json={"service_id": tile["id"]})
    plan = r.json()["plan"]
    assert plan["fqdn"] == FQDN and plan["kan"] is True


async def test_losse_dns_alleen_eigen_records(lab, authed):
    lab.records += [
        {"id": "5" * 32, "type": "CNAME", "name": "oud.jbogaert.be", "content": "jbogaert.be", "comment": ns.COMMENT},
        {"id": "6" * 32, "type": "CNAME", "name": "weg.jbogaert.be", "content": f"{TUNNEL}.cfargotunnel.com"}]
    out = (await authed.get("/api/nieuweservice/losse-dns")).json()
    assert out == {"items": [{"name": "oud.jbogaert.be", "type": "CNAME", "content": "jbogaert.be"}], "error": None}
    lab.fail[("GET", "/api/nginx/proxy-hosts")] = httpx.Response(502)
    out = (await authed.get("/api/nieuweservice/losse-dns")).json()
    assert out["items"] == [] and out["error"].startswith("NPM:")


# --- lezen en geheimen -------------------------------------------------------------------------------------------

async def test_opties_en_domein(lab, authed):
    assert (await authed.get("/api/nieuweservice/domein")).json() == {"domain": "jbogaert.be"}
    o = (await authed.get("/api/nieuweservice/opties")).json()
    assert o["domain"] == "jbogaert.be" and o["npm_version"] == "2.16.0" and o["pattern"] == "tunnel"
    assert o["systems"]["npm"] == {"label": "NPM", "write": WRITE, "split": True, "sees_all": True}
    assert o["systems"]["cloudflare"] == {"label": "Cloudflare DNS", "zone": "jbogaert.be", "tunnel_account": True}
    assert o["systems"]["adguard"] == {"label": "AdGuard"} and o["systems"]["proxmox"] == [{"label": "pve50"}]
    assert o["certs"] == [{"id": 3, "name": "*.jbogaert.be", "wildcard": True, "days": 54}]
    assert o["access_lists"] == [{"id": 1, "name": "LAN", "lan_only": True, "why": "alleen 192.168.0.0/16"}]
    assert o["jobs"] == [{"id": "backup-1a2b", "label": "backup-1a2b → pbs-pi, 02:00", "pool": None, "pbs": True}]
    assert o["zabbix_hosts"] == [{"host": "jellyfin", "name": "Jellyfin", "ips": ["192.168.0.27"]}]
    assert o["busy"] is None
    n = len(lab.calls)
    await authed.get("/api/nieuweservice/opties")
    assert len(lab.calls) == n      # 60 s onthouden
    r = await authed.patch(f"/api/apis/{lab.apis['adguard']}", json={"name": "AdGuard 2", "kind": "adguard",
                                                                       "url": AG})
    assert r.status_code == 200
    assert (await authed.get("/api/nieuweservice/opties")).json()["systems"]["adguard"] == {"label": "AdGuard 2"}


async def test_geen_geheimen_naar_de_browser(lab, authed):
    lab.records.append({"id": "5" * 32, "type": "CNAME", "name": "oud.jbogaert.be", "content": "jbogaert.be",
                        "comment": ns.COMMENT})
    out = [await _proef(authed, _body(lab))]
    out.append((await authed.post("/api/nieuweservice/opruimen/proef", json={"fqdn": "plex.jbogaert.be"})).json())
    run = await _start(authed, _body(lab))
    for path in ("/opties", "/domein", "/runs", f"/runs/{run['id']}", "/losse-dns"):
        out.append((await authed.get(f"/api/nieuweservice{path}")).json())
    text = json.dumps(out)
    for secret in ("GEHEIM", "dns_provider_credentials", '"meta"', "eyJ", CF_TOKEN):
        assert secret not in text, secret


async def test_foutdetail_gemaskeerd(lab, authed):
    lab.fail[("GET", f"/client/v4/zones/{ZONE_ID}/dns_records")] = _cf_error(
        1000, "Invalid request token=abc123secretvalue")
    plan = await _proef(authed, _body(lab))
    assert "abc123secretvalue" not in json.dumps(plan) and "Cloudflare" in json.dumps(plan)
    del lab.fail[("GET", f"/client/v4/zones/{ZONE_ID}/dns_records")]
    lab.fail[("POST", f"/client/v4/zones/{ZONE_ID}/dns_records")] = _cf_error(
        1000, "Invalid request token=abc123secretvalue")
    run = await _start(authed, _body(lab))
    assert run["status"] == "gestopt" and "abc123secretvalue" not in json.dumps(run)
    assert "Cloudflare: Invalid request" in run["steps"][2]["detail"]
    agen, db = await _db()
    n = (await db.execute(select(Notification).where(Notification.source == "nieuweservice"))).scalar_one()
    assert "abc123secretvalue" not in n.body
    await agen.aclose()
