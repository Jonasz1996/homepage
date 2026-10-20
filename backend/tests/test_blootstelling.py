"""Netwerk › publiek (monitoring/exposure.py): per publieke naam of iemand op internet erbij kan, en welke login
ervoor staat. Cloudflare, NPM en 1.1.1.1 zijn nep; de kopie van OPNsense staat in de database."""

import asyncio
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest
from sqlalchemy import select

from app.integrations import IntegrationError
from app.integrations import npm as npm_integration
from app.integrations.base import Forbidden
from app.integrations.cloudflare import CloudflareTunnel, access_app
from app.integrations.npm import NginxProxyManager
from app.models import AppState, AuditLog, Notification
from app.monitoring import configs
from app.monitoring import exposure as ex
from app.monitoring.checks import HttpClients
from app.routers import exposure as exposure_router
from app.routers import integrations as int_router

from .test_beveiliging import _reauth
from .test_buitenaf import _stale
from .test_capacity import _db
from .test_integrations import _group, _svc

ACCOUNT = "0123456789abcdef0123456789abcdef"
ZONE = "1234567890abcdef1234567890abcdef"
T_THUIS = "11111111-1111-4111-8111-111111111111"
T_OUD = "22222222-2222-4222-8222-222222222222"
T_TWEEDE = "33333333-3333-4333-8333-333333333333"
DOCS_APP = "44444444-4444-4444-8444-444444444444"
HOME = "81.82.83.84"
OLD = "81.82.83.1"
NPM = "192.168.0.245"
TUN = f"{T_THUIS}.cfargotunnel.com"
AUTHENTIK = ("# login via Authentik\nauth_request /outpost.goauthentik.io/auth/nginx;\n"
             "error_page 401 = @goauthentik_proxy_signin;")


def _full(name: str) -> str:
    return name if "." in name else f"{name}.jbogaert.be"


def _r(name: str, kind: str, content: str, proxied: bool = False) -> dict:
    """Een DNS-record zoals Cloudflare het geeft (met commentaar dat nooit naar de browser mag)."""
    return {"id": f"r-{name}-{kind}", "name": _full(name), "type": kind, "content": content, "proxied": proxied,
            "comment": "notitie-in-dns", "tags": ["geheim-label"]}


def _h(id_: int, name: str, host: str = "192.168.0.20", port: int = 8096, **kw) -> dict:
    """Een proxy host zoals NPM hem geeft."""
    return {"id": id_, "domain_names": [_full(name)], "forward_scheme": "http", "forward_host": host,
            "forward_port": port, "certificate_id": 5, "ssl_forced": True, "enabled": True, "access_list_id": 0,
            "advanced_config": "", "locations": [], **kw}


RECORDS = [
    _r("jellyfin", "CNAME", TUN, True), _r("nas", "CNAME", TUN, True), _r("direct", "CNAME", TUN, True),
    _r("docker", "CNAME", TUN, True), _r("admin", "CNAME", TUN, True),
    _r("dash", "A", HOME, True), _r("git", "A", HOME, True), _r("docs", "A", HOME, True), _r("pin", "A", HOME, True),
    _r("blog", "A", HOME, True), _r("home", "A", HOME), _r("oud-ip", "A", OLD), _r("shop", "CNAME", "gone.herokuapp.com", True),
    _r("stale", "A", HOME), _r("oude-tunnel", "CNAME", f"{T_OUD}.cfargotunnel.com", True),
    _r("jbogaert.be", "TXT", "v=spf1 -all"), _r("jbogaert.be", "MX", "mail.voorbeeld.net"),
]
HOSTS = [
    _h(1, "jellyfin"), _h(2, "dash", "192.168.0.21", 3000, advanced_config=AUTHENTIK),
    _h(3, "nas", "192.168.0.22", 5000, access_list_id=1), _h(4, "git", "192.168.0.23", 3000, access_list_id=1),
    _h(5, "docs", "192.168.0.24", 80), _h(6, "pin", "192.168.0.25", 80), _h(7, "blog", "192.168.0.26", 80),
    _h(8, "home", "192.168.0.27", 80, access_list_id=2), _h(9, "intern", "192.168.0.28", 80),
    _h(10, "docker", "192.168.0.29", 80, advanced_config=AUTHENTIK),
]
LISTS = [
    {"id": 1, "name": "LAN", "satisfy_any": 0, "pass_auth": 0, "items": [],
     "clients": [{"id": 1, "directive": "allow", "address": "192.168.0.0/16"}]},
    {"id": 2, "name": "Wachtwoord", "satisfy_any": 0, "pass_auth": 0,
     "items": [{"id": 1, "username": "gast-gebruiker", "hint": "hint-geheim", "password": ""}], "clients": []},
    {"id": 3, "name": "Eén", "satisfy_any": 0, "pass_auth": 0, "items": [],
     "clients": [{"id": 2, "directive": "allow", "address": "192.168.0.50/32"}]},
]
TUNNELS = [
    {"id": T_THUIS, "name": "thuis", "status": "healthy", "deleted_at": None, "connections": [{"colo_name": "ams01"}]},
    {"id": T_OUD, "name": "oud", "status": "inactive", "deleted_at": "2026-01-01T00:00:00Z", "connections": []},
    {"id": T_TWEEDE, "name": "tweede", "status": "healthy", "deleted_at": None, "connections": []},
]
INGRESS = [
    {"hostname": "jellyfin.jbogaert.be", "service": "https://192.168.0.245:443",
     "originRequest": {"noTLSVerify": True, "httpHostHeader": "header-geheim", "access": {"audTag": ["aud-geheim"]}}},
    {"hostname": "nas.jbogaert.be", "service": "https://192.168.0.245:443"},
    {"hostname": "direct.jbogaert.be", "service": "http://192.168.0.20:8096"},
    {"hostname": "docker.jbogaert.be", "service": "http://npm:80"},
    {"hostname": "admin.jbogaert.be", "service": "http://192.168.0.245:81"},
    {"service": "http_status:404"},
]
APPS = [
    {"id": DOCS_APP, "name": "Docs", "type": "self_hosted", "domain": "docs.jbogaert.be", "aud": "aud-geheim",
     "destinations": [{"type": "public", "uri": "docs.jbogaert.be"}]},
    {"id": "55555555-5555-4555-8555-555555555555", "name": "Jellyfin", "type": "bookmark",
     "domain": "jellyfin.jbogaert.be"},
    {"id": "66666666-6666-4666-8666-666666666666", "name": "Pin", "type": "self_hosted", "domain": "pin.jbogaert.be",
     "policies": [{"decision": "allow", "include": [{"everyone": {}}]}]},
    {"id": "77777777-7777-4777-8777-777777777777", "name": "Mail", "type": "self_hosted",
     "domain": "mail.jbogaert.be",
     "policies": [{"decision": "allow", "include": [{"email_domain": {"domain": "gmail.com"}}]}]},
    {"id": "88888888-8888-4888-8888-888888888888", "name": "Blog", "type": "self_hosted", "domain": "blog.jbogaert.be",
     "policies": [{"decision": "bypass", "include": [{"everyone": {}}]}]},
]
DOCS_POLICIES = [{"id": "p1", "decision": "allow", "include": [{"email": {"email": "jonas@voorbeeld.be"}}]}]

# OPNsense: 443 naar NPM alleen van Cloudflare (urltable), WireGuard voor iedereen.
OPN_CF = """<?xml version="1.0"?>
<opnsense>
  <system><user><name>root</name><password>$2y$10$hash-geheim</password></user></system>
  <interfaces>
    <wan><if>igb0</if><ipaddr>dhcp</ipaddr></wan>
    <lan><if>igb1</if><ipaddr>192.168.0.1</ipaddr></lan>
  </interfaces>
  <nat>
    <outbound><mode>automatic</mode><rule><interface>wan</interface><target>81.82.83.84</target></rule></outbound>
    <rule>
      <protocol>tcp</protocol><interface>wan</interface>
      <source><network>{src}</network></source>
      <destination><network>wanip</network><port>443</port></destination>
      <target>192.168.0.245</target><local-port>443</local-port><descr>NPM</descr>
    </rule>
    <rule>
      <protocol>tcp</protocol><interface>wan</interface><disabled>1</disabled>
      <source><any/></source>
      <destination><network>wanip</network><port>443</port></destination>
      <target>192.168.0.245</target><local-port>443</local-port><descr>oud</descr>
    </rule>
    <rule>
      <protocol>udp</protocol><interface>wan</interface>
      <source><any/></source>
      <destination><network>wanip</network><port>51820</port></destination>
      <target>192.168.0.10</target><local-port>51820</local-port><descr>WireGuard</descr>
    </rule>
    <rule>
      <protocol>tcp</protocol><interface>lan</interface>
      <source><any/></source>
      <destination><port>53</port></destination>
      <target>127.0.0.1</target><local-port>53</local-port><descr>DNS</descr>
    </rule>
  </nat>
  <OPNsense><Firewall><Alias><aliases>
    <alias><enabled>1</enabled><name>cf_ips</name><type>urltable</type><url>https://www.cloudflare.com/ips-v4</url><content/></alias>
    <alias><enabled>1</enabled><name>cf_twee</name><type>network</type><content>173.245.48.0/20
103.21.244.0/22</content></alias>
    <alias><enabled>1</enabled><name>geo_be</name><type>geoip</type><content>BE</content></alias>
  </aliases></Alias></Firewall></OPNsense>
</opnsense>
"""
OPN_MVC = """<opnsense>
  <interfaces><wan><ipaddr>pppoe</ipaddr></wan><opt1><ipaddr>dhcp</ipaddr></opt1></interfaces>
  <OPNsense><Firewall>
    <DNat><rule><enabled>1</enabled><interface>opt1</interface><protocol>TCP</protocol>
      <source><network>any</network></source><destination><port>80-443</port></destination>
      <target>192.168.0.245</target><local_port>80</local_port><descr>NPM</descr></rule>
      <rule><enabled>0</enabled><interface>wan</interface><protocol>TCP</protocol>
      <source><network>any</network></source><destination><port>22</port></destination>
      <target>192.168.0.5</target><descr>uit</descr></rule></DNat>
    <SourceNat><rule><interface>wan</interface><target>wanip</target></rule></SourceNat>
  </Firewall></OPNsense>
</opnsense>"""


class Pub:
    """Neppe Cloudflare-API, NPM (192.168.0.245:81) en 1.1.1.1 (DNS over HTTPS)."""

    def __init__(self):
        self.records = [dict(r) for r in RECORDS]
        self.hosts = [dict(h) for h in HOSTS]
        self.lists = LISTS
        self.tunnels = TUNNELS
        self.ingress = INGRESS
        self.apps = APPS
        self.https = "on"
        self.access_forbidden = self.dns_forbidden = self.zones_empty = self.settings_forbidden = False
        self.npm_down = self.nx = self.slow = False
        self.calls: list[httpx.Request] = []
        self.doh_now = self.doh_max = 0
        self.doh: list[str] = []

    def __call__(self, req: httpx.Request):
        self.calls.append(req)
        if req.url.host == "api.cloudflare.com":
            return self.cloudflare(req)
        if req.url.host == NPM and req.url.port == 81:
            return self.npm(req)
        if req.url.host == "1.1.1.1" and req.url.path == "/dns-query":
            return self.dns(req)
        return httpx.Response(404)

    def cloudflare(self, req: httpx.Request) -> httpx.Response:
        assert req.method == "GET"
        assert req.headers["authorization"] == "Bearer cf-token"
        p, q = req.url.path.removeprefix("/client/v4"), req.url.params
        page = int(q.get("page") or 1)

        def ok(result, pages: int = 1) -> httpx.Response:
            return httpx.Response(200, json={"success": True, "errors": [], "result": result,
                                             "result_info": {"page": page, "total_pages": pages}})

        no = httpx.Response(403, json={"success": False, "errors": [{"code": 10000, "message": "Authentication error"}]})
        if p == "/zones":
            return ok([] if self.zones_empty else [{"id": ZONE, "name": "jbogaert.be", "status": "active"}])
        if p == f"/zones/{ZONE}/dns_records":
            if self.dns_forbidden:
                return no
            half = (len(self.records) + 1) // 2
            return ok(self.records[:half] if page == 1 else self.records[half:], 2)
        if p == f"/accounts/{ACCOUNT}/cfd_tunnel":
            return ok([t for t in self.tunnels if not (q.get("is_deleted") == "false" and t["deleted_at"])])
        m = re.fullmatch(rf"/accounts/{ACCOUNT}/cfd_tunnel/([0-9a-f-]+)/configurations", p)
        if m:
            if m[1] == T_THUIS:
                return ok({"tunnel_id": T_THUIS, "source": "cloudflare", "version": 7,
                           "config": {"ingress": self.ingress, "originRequest": {"connectTimeout": 10}}})
            return ok({"tunnel_id": m[1], "source": "local", "config": None})
        if p == f"/accounts/{ACCOUNT}/access/apps":
            return no if self.access_forbidden else ok(self.apps)
        if p == f"/accounts/{ACCOUNT}/access/apps/{DOCS_APP}/policies":
            return ok(DOCS_POLICIES)
        if p == f"/zones/{ZONE}/access/apps":
            return no
        if p == f"/zones/{ZONE}/settings/always_use_https":
            return no if self.settings_forbidden else ok({"id": "always_use_https", "value": self.https})
        return httpx.Response(404, json={"success": False})

    def npm(self, req: httpx.Request) -> httpx.Response:
        if self.npm_down:
            return httpx.Response(502)
        p = req.url.path
        if p == "/api/tokens":
            body = json.loads(req.content)
            assert body == {"identity": "dashboard@jbogaert.be", "secret": "npm-geheim"}
            return httpx.Response(200, json={"token": "jwt-npm-sessie", "expires": "2026-12-01T00:00:00Z"})
        assert req.headers["authorization"] == "Bearer jwt-npm-sessie"
        if p == "/api/nginx/proxy-hosts":
            return httpx.Response(200, json=self.hosts)
        if p == "/api/nginx/access-lists":
            assert req.url.params["expand"] == "items,clients"
            return httpx.Response(200, json=self.lists)
        if p in ("/api/nginx/redirection-hosts", "/api/nginx/dead-hosts"):
            return httpx.Response(200, json=[])
        return httpx.Response(404)

    async def dns(self, req: httpx.Request) -> httpx.Response:
        assert req.headers["accept"] == "application/dns-json"
        name = req.url.params["name"]
        self.doh.append(name)
        self.doh_now += 1
        self.doh_max = max(self.doh_max, self.doh_now)
        try:
            await asyncio.sleep(4 if self.slow else 0.01)
        finally:
            self.doh_now -= 1
        if name == "gone.herokuapp.com" or self.nx:
            return httpx.Response(200, json={"Status": 3, "Answer": []})
        if name == "home.duckdns.org":
            return httpx.Response(200, json={"Status": 0, "Answer": [{"name": name, "type": 1, "data": HOME}]})
        return httpx.Response(200, json={"Status": 0, "Answer": [{"name": name, "type": 5, "data": "x.example.net."}]})


@pytest.fixture
def pub(monkeypatch):
    p = Pub()
    clients = HttpClients(httpx.MockTransport(p))
    monkeypatch.setattr(int_router, "clients", clients)
    int_router._cache.clear()
    npm_integration._tokens.clear()

    async def resolve(hosts):
        return {h: None for h in hosts}  # "npm" is een Docker-naam: het dashboard kan hem niet opzoeken

    monkeypatch.setattr(ex, "resolve", resolve)
    monkeypatch.setattr(exposure_router, "_last_refresh", 0.0)
    p.clients = clients
    return p


# --- integraties ------------------------------------------------------------------------------------------------

def _cf(pub: Pub, **config) -> CloudflareTunnel:
    return CloudflareTunnel("https://one.dash.cloudflare.com", {"account": ACCOUNT, **config}, {"token": "cf-token"},
                            pub.clients.get(False))


async def test_cloudflare_paginering_en_403(pub):
    cf = _cf(pub)
    recs = await cf.dns_records(ZONE)
    assert len(recs) == len(RECORDS)
    assert {r["name"] for r in recs} >= {"jellyfin.jbogaert.be", "stale.jbogaert.be", "jbogaert.be"}
    pages = [c.url.params["page"] for c in pub.calls if c.url.path.endswith("/dns_records")]
    assert pages == ["1", "2"]
    assert set(recs[0]) == {"name", "type", "content", "proxied"}  # geen commentaar of labels
    assert next(r for r in recs if r["type"] == "TXT")["content"] == ""
    pub.dns_forbidden = True
    with pytest.raises(Forbidden) as e:
        await cf.dns_records(ZONE)
    assert isinstance(e.value, IntegrationError)
    pub.calls.clear()

    async def nope(*a, **kw):
        return {"success": False, "errors": [{"message": "x"}]}

    cf.request = nope
    with pytest.raises(IntegrationError) as e:
        await cf.zones()
    assert not isinstance(e.value, Forbidden)


async def test_tunnellijst_negeert_tegelfilter(pub):
    cf = _cf(pub, tunnel="thuis")
    ts = await cf.tunnel_list()
    assert [(t["name"], t["deleted"]) for t in ts] == [("thuis", False), ("oud", True), ("tweede", False)]
    assert [t["name"] for t in await cf.tunnels()] == ["thuis"]
    cfg = await cf.tunnel_config(T_THUIS)
    assert cfg["source"] == "cloudflare"
    assert cfg["ingress"][0] == {"hostname": "jellyfin.jbogaert.be", "path": None,
                                 "service": "https://192.168.0.245:443", "access_required": False}
    assert cfg["ingress"][-1]["hostname"] is None and cfg["ingress"][-1]["service"] == "http_status:404"
    assert "header-geheim" not in json.dumps(cfg) and "aud-geheim" not in json.dumps(cfg)
    assert await cf.tunnel_config(T_TWEEDE) == {"source": "local", "ingress": []}
    with pytest.raises(IntegrationError):
        await cf.tunnel_config("../zones")


def test_access_apps_soorten():
    assert access_app({"type": "bookmark", "domain": "x.jbogaert.be"}) is None
    assert access_app({"type": "saas", "domain": "x.jbogaert.be"}) is None
    a = access_app({"name": "A", "type": "self_hosted", "domain": "oud.jbogaert.be", "aud": "aud-geheim",
                    "self_hosted_domains": ["extra.jbogaert.be"],
                    "destinations": [{"type": "public", "uri": "App.jbogaert.be/beheer"},
                                     {"type": "private", "uri": "10.0.0.1"}],
                    "policies": [{"decision": "allow", "include": [{"email": {"email": "jonas@voorbeeld.be"}}]}]})
    assert a == {"name": "A", "type": "self_hosted", "hosts": [{"host": "app.jbogaert.be", "path": "/beheer"}],
                 "verdict": "login"}
    b = access_app({"name": "B", "type": "ssh", "domain": "ssh.jbogaert.be", "policies": []})
    assert b["hosts"] == [{"host": "ssh.jbogaert.be", "path": None}] and b["verdict"] == "login"

    def verdict(*policies):
        return access_app({"type": "self_hosted", "domain": "x.jbogaert.be", "policies": list(policies)})["verdict"]

    everyone = {"decision": "allow", "include": [{"everyone": {}}]}
    login = {"decision": "allow", "include": [{"email": {"email": "jonas@voorbeeld.be"}}]}
    assert verdict(everyone) == "everyone"
    assert verdict({"decision": "allow", "include": [{"email_domain": {"domain": "gmail.com"}}]}) == "public_mail"
    assert verdict({"decision": "allow", "include": [{"email_domain": {"domain": "jbogaert.be"}}]}) == "login"
    assert verdict({"decision": "bypass", "include": [{"everyone": {}}]}) == "bypass"
    assert verdict({"decision": "non_identity", "include": [{"everyone": {}}]}) == "bypass"
    assert verdict({"decision": "allow", "include": [{"everyone": {}}], "require": [{"group": {"id": "g"}}]}) == "login"
    assert verdict(login, everyone) == "everyone"  # de zwakste regel telt
    # De include-regels gelden met "of": één open regel naast een echte maakt de policy open.
    assert verdict({"decision": "allow", "include": [{"everyone": {}}, {"email": {"email": "jonas@voorbeeld.be"}}]}) == \
        "everyone"
    assert verdict({"decision": "allow", "include": [{"email_domain": {"domain": "gmail.com"}},
                                                     {"email": {"email": "jonas@voorbeeld.be"}}]}) == "public_mail"
    assert verdict({"decision": "allow", "include": [{"geo": {"country_code": "BE"}}]}) == "everyone"
    assert set(a) == {"name", "type", "hosts", "verdict"}
    assert "jonas@" not in json.dumps([a, b]) and "aud-geheim" not in json.dumps(a)


async def test_access_apps_haalt_ontbrekende_policies(pub):
    apps = await _cf(pub).access_apps()
    assert {a["name"]: a["verdict"] for a in apps} == {"Docs": "login", "Pin": "everyone", "Mail": "public_mail",
                                                        "Blog": "bypass"}
    assert any(c.url.path.endswith(f"/apps/{DOCS_APP}/policies") for c in pub.calls)
    with pytest.raises(Forbidden):
        await _cf(pub).access_apps(ZONE)
    assert await _cf(pub).always_https(ZONE) is True


async def test_npm_toegangslijsten_zonder_namen(pub):
    npm = NginxProxyManager("http://192.168.0.245:81", {}, {"username": "dashboard@jbogaert.be",
                                                            "password": "npm-geheim"}, pub.clients.get(False))
    lists = await npm.access_lists()
    assert lists[1] == {"id": 2, "name": "Wachtwoord", "satisfy_any": False, "users": 1, "clients": []}
    assert lists[0]["clients"] == [{"directive": "allow", "address": "192.168.0.0/16"}]
    text = json.dumps(lists)
    assert "gast-gebruiker" not in text and "hint-geheim" not in text and "password" not in text


# --- analyse zonder HTTP ----------------------------------------------------------------------------------------

PARSED_LISTS = {al["id"]: {"id": al["id"], "name": al["name"], "satisfy_any": bool(al["satisfy_any"]),
                           "users": len(al["items"]),
                           "clients": [{"directive": c["directive"], "address": c["address"]} for c in al["clients"]]}
                for al in LISTS}
CONFIG = {T_THUIS: {"source": "cloudflare", "ingress": [
    {"hostname": i.get("hostname"), "path": None, "service": i["service"], "access_required": False} for i in INGRESS]}}


def cfd(records, apps=(), configs=None, https=True, **rights) -> ex.CfData:
    """Een Cloudflare-bron zoals fetch_cf hem maakt. records: (naam, soort, inhoud, oranje wolk)."""
    return ex.CfData(
        label="Cloudflare", zones=[{"id": ZONE, "name": "jbogaert.be"}],
        records=[{"name": _full(n), "type": t, "content": c, "proxied": p} for n, t, c, p in records],
        tunnels=[{"id": t["id"], "name": t["name"], "status": t["status"], "deleted": bool(t["deleted_at"])}
                 for t in TUNNELS],
        configs=CONFIG if configs is None else configs, apps=list(apps), https={"jbogaert.be": https},
        rights={"zone_read": True, "dns_read": True, "tunnel_read": True, "tunnel_config": True, "access_read": True,
                **rights})


def npmd(hosts, lists=PARSED_LISTS, names=(), ipv6=(), redirects=()) -> ex.NpmData:
    return ex.NpmData(label="NPM", ip=NPM, names=set(names), ipv6=set(ipv6), proxy=hosts, redirects=list(redirects),
                      dead=[], lists=lists, rights={"npm_access_lists": lists is not None, "npm_redirects": True})


def ctx(**kw) -> ex.Ctx:
    base = {"ip_known": True, "public_ip": HOME, "home_ips": {HOME}, "old_ips": {OLD}, "npm_lan": {NPM},
            "resolved": {"npm": None}}
    return ex.Ctx(**{**base, **kw})


def run(cf, npm, c=None) -> tuple[dict[str, dict], dict]:
    out = ex.analyse([cf], [npm] if npm else [], c or ctx())
    return {r["name"]: r for r in out["rows"]}, out


def keys(row: dict) -> set[str]:
    return {n["key"] for n in row["notes"]}


def test_login_in_config():
    assert ex.login_in_config(AUTHENTIK)["login"] == "Authentik"
    assert ex.login_in_config("auth_request /authelia;")["login"] == "Authelia"
    assert ex.login_in_config("auth_request /auth;")["login"] == "forward-auth"
    part = ex.login_in_config(AUTHENTIK + "\nlocation /api { auth_request off; }")
    assert part["login"] == "Authentik" and part["partial"] == ["/api"]
    pw = ex.login_in_config('auth_basic "Beheer";\nauth_basic_user_file /data/access/1;')
    assert pw["login"] == "wachtwoord (eigen nginx-config)"
    assert ex.login_in_config("# auth_request /outpost.goauthentik.io/auth/nginx;\n")["login"] is None
    assert ex.login_in_config("auth_basic off;")["login"] is None
    assert ex.login_in_config("ssl_verify_client on;\nssl_client_certificate /data/cf.pem;")["origin_lock"] is True
    jwt = ex.login_in_config('if ($http_cf_access_jwt_assertion = "") { return 403; }')
    assert jwt["jwt_presence"] is True and jwt["login"] is None
    own = ex.login_in_config("allow 192.168.0.0/16;\ndeny all;\nset_real_ip_from 192.0.2.255/32;")
    assert own["allows"] == ["192.168.0.0/16"] and own["realip"] is True
    assert ex.login_in_config(None) == {"login": None, "partial": [], "allows": [], "origin_lock": False,
                                        "jwt_presence": False, "realip": False}


def test_toegangslijst_via_tunnel():
    lan, pw, one = PARSED_LISTS[1], PARSED_LISTS[2], PARSED_LISTS[3]
    g = ex.list_guard(lan, "tunnel", npm_ip=NPM)
    assert g["login"] is None and g["closed"] is None and g["ip_tunnel"] == "LAN" and g["notes"] == [("ip_tunnel", {})]
    g = ex.list_guard(lan, "proxied", npm_ip=NPM)
    assert g["closed"] == "toegangslijst 'LAN' laat alleen je eigen netwerk toe" and ("xrealip", {}) in g["notes"]
    assert ex.list_guard(lan, "proxied", npm_ip=NPM, realip=True)["notes"] == []
    assert ex.list_guard(lan, "thuis", npm_ip=NPM)["closed"]
    g = ex.list_guard(one, "tunnel", npm_ip=NPM)
    assert g["closed"] and g["notes"] == [("single_host", {"ip": "192.168.0.50"})]
    npm_only = {**one, "clients": [{"directive": "allow", "address": f"{NPM}/32"}]}
    assert ex.list_guard(npm_only, "tunnel", npm_ip=NPM)["ip_tunnel"]
    any_of = {**lan, "users": 2, "satisfy_any": True}
    assert ex.list_guard(any_of, "tunnel", npm_ip=NPM)["login"] is None
    assert ex.list_guard(any_of, "proxied", npm_ip=NPM)["login"] == "wachtwoord (toegangslijst 'LAN')"
    both = {**lan, "users": 2, "satisfy_any": False}
    assert ex.list_guard(both, "tunnel", npm_ip=NPM)["login"] == "wachtwoord (toegangslijst 'LAN')"
    assert ex.list_guard(pw, "dns-only")["login"] == "wachtwoord (toegangslijst 'Wachtwoord')"
    public = {**lan, "clients": [{"directive": "allow", "address": "203.0.113.0/24"}]}
    assert ex.list_guard(public, "proxied")["login"] == "IP-lijst (toegangslijst 'LAN')"
    everyone = {**lan, "clients": [{"directive": "allow", "address": "all"}]}
    assert ex.list_guard(everyone, "proxied") == {"login": None, "closed": None, "notes": [], "ip_tunnel": None}
    g = ex.list_guard(None, "tunnel", al_id=7)
    assert g["login"] == "toegangslijst #7" and g["notes"] == [("al_unknown", {"id": 7})]


def test_wildcard_regels():
    by_name = {"*.jbogaert.be": [{"name": "*.jbogaert.be", "type": "A", "content": HOME, "proxied": True}],
               "txt.jbogaert.be": [{"name": "txt.jbogaert.be", "type": "TXT", "content": "", "proxied": False}],
               "a.b.jbogaert.be": [{"name": "a.b.jbogaert.be", "type": "A", "content": HOME, "proxied": True}]}
    assert ex.public_records("x.jbogaert.be", by_name)[1] == "*.jbogaert.be"
    assert ex.public_records("y.x.jbogaert.be", by_name)[1] == "*.jbogaert.be"
    assert ex.public_records("txt.jbogaert.be", by_name) == ([], None)  # TXT houdt de wildcard tegen
    assert ex.public_records("b.jbogaert.be", by_name) == ([], None)  # bestaat (er staat een naam onder)
    assert ex.public_records("c.b.jbogaert.be", by_name) == ([], None)
    # Een naam die alleen NPM kent, is publiek via de wildcard.
    rows, _ = run(cfd([("*.jbogaert.be", "A", HOME, True)]), npmd([_h(1, "app")]), ctx(forwards=OPN_OK_CF()))
    assert rows["app.jbogaert.be"]["state"] == "open" and rows["app.jbogaert.be"]["dns"][0]["wildcard"] == "*.jbogaert.be"
    assert rows["*.jbogaert.be"]["state"] == "wildcard" and rows["*.jbogaert.be"]["level"] == "warn"
    # Met een wildcard-host in NPM zonder login: rood.
    rows, _ = run(cfd([("*.jbogaert.be", "A", HOME, True)]), npmd([_h(1, "*.jbogaert.be")]), ctx(forwards=OPN_OK_CF()))
    wc = rows["*.jbogaert.be"]
    assert (wc["state"], wc["level"], wc["why_key"]) == ("wildcard", "err", "open_wildcard")
    assert "*.jbogaert.be" in wc["why"]


def OPN_OK_CF() -> dict:
    return ex.wan_forwards(OPN_CF.format(src="cf_ips"), 1000)


def test_wan_doorverwijzingen():
    fw = ex.wan_forwards(OPN_CF.format(src="any"), 1000)
    assert fw["status"] == "ok"
    assert [(r["ext"], r["to_ip"], r["to_port"], r["from"], r["from_cf"], r["descr"]) for r in fw["rules"]] == [
        ("443", NPM, 443, "any", False, "NPM"), ("51820", "192.168.0.10", 51820, "any", False, "WireGuard")]
    assert "hash-geheim" not in json.dumps(fw)
    assert OPN_OK_CF()["rules"][0]["from_cf"] is True
    assert ex.wan_forwards(OPN_CF.format(src="cf_twee"), 1000)["rules"][0]["from_cf"] is True
    assert ex.wan_forwards(OPN_CF.format(src="geo_be"), 1000)["rules"][0]["from_cf"] is False
    assert ex.wan_forwards(OPN_CF.format(src="203.0.113.0/24"), 1000)["rules"][0]["from_cf"] is False
    mvc = ex.wan_forwards(OPN_MVC, 1000)
    assert mvc["status"] == "ok" and len(mvc["rules"]) == 1
    r = mvc["rules"][0]
    assert (r["iface"], r["proto"], r["to_ip"], r["to_port"], r["to_last"], r["from_cf"]) == (
        "opt1", "tcp", NPM, 80, 443, False)
    assert ex.origin_state(mvc, set(), set(), {NPM})["open"] is True
    # Een NAT-regel van any zonder "Pass": de WAN-filterregel naar NPM beslist mee wie binnen mag.
    cf_only = ("<filter><rule><type>pass</type><interface>wan</interface><protocol>tcp</protocol>"
               "<source><address>cf_ips</address></source>"
               "<destination><address>192.168.0.245</address><port>443</port></destination></rule>{more}</filter>")
    with_filter = lambda more="", nat="": OPN_CF.format(src="any").replace(  # noqa: E731
        "</nat>", "</nat>" + cf_only.format(more=more)).replace("<descr>NPM</descr>", "<descr>NPM</descr>" + nat)
    fw = ex.wan_forwards(with_filter(), 1000)
    assert [(r["from"], r["from_cf"]) for r in fw["rules"]] == [("cf_ips (filterregel)", True), ("any", False)]
    assert ex.origin_state(fw, set(), set(), {NPM})["basis"] == "cloudflare"
    any_too = ("<rule><type>pass</type><interface>wan</interface><source><any/></source>"
               "<destination><any/></destination></rule>")
    assert ex.wan_forwards(with_filter(any_too), 1000)["rules"][0]["from_cf"] is False
    other = ("<rule><type>pass</type><interface>wan</interface><source><any/></source>"
             "<destination><address>192.168.0.10</address></destination></rule>")
    assert ex.wan_forwards(with_filter(other), 1000)["rules"][0]["from_cf"] is True
    off = ("<rule><type>pass</type><interface>wan</interface><disabled>1</disabled><source><any/></source>"
           "<destination><any/></destination></rule>")
    assert ex.wan_forwards(with_filter(off), 1000)["rules"][0]["from_cf"] is True
    passing = with_filter(nat="<associated-rule-id>pass</associated-rule-id>")
    assert ex.wan_forwards(passing, 1000)["rules"][0]["from_cf"] is False  # "Pass": geen filterregel ertussen
    no_target = OPN_CF.format(src="any").replace("<target>192.168.0.10</target>", "")
    assert ex.wan_forwards(no_target, 1000)["status"] == "onbekend"
    assert ex.wan_forwards(OPN_CF.format(src="any"), configs.MAX_SIZE)["status"] == "onbekend"
    assert ex.wan_forwards("geen xml <", 100)["status"] == "onbekend"
    assert ex.wan_forwards("<opnsense><system/></opnsense>", 100)["status"] == "onbekend"
    assert ex.wan_forwards("<opnsense><nat/></opnsense>", 100) == {"status": "ok", "why": None, "rules": []}
    # Dezelfde blokken van Cloudflare als in deploy/nginx-map.conf.
    text = (Path(__file__).resolve().parents[2] / "deploy" / "nginx-map.conf").read_text()
    part = text.split("# Cloudflare, IPv4", 1)[1].split("# Niet publiek", 1)[0]
    nets = re.findall(r"^\s*([0-9a-f:.]+/\d+)\s+1;", part, re.M)
    assert [str(n) for n in ex.CF_NETS] == nets


def test_origin():
    assert ex.origin_state(OPN_OK_CF(), {"a"}, set(), {NPM})["basis"] == "cloudflare"
    o = ex.origin_state(ex.wan_forwards(OPN_CF.format(src="any"), 1000), set(), set(), {NPM})
    assert o["open"] is True and o["basis"] == "opnsense" and "voor iedereen (van: any)" in o["text"]
    none = ex.wan_forwards(OPN_CF.format(src="any").replace("192.168.0.245", "192.168.0.99"), 1000)
    assert ex.origin_state(none, {"a"}, set(), {NPM})["basis"] == "geen_doorverwijzing"
    assert ex.origin_state(None, {"a.jbogaert.be"}, set(), {NPM})["basis"] == "dns"
    assert ex.origin_state({"status": "onbekend"}, set(), set(), {NPM})["open"] is None
    assert ex.origin_state(OPN_OK_CF(), set(), {"v6.jbogaert.be"}, {NPM})["basis"] == "ipv6"


def test_thuis_ip_maakt_access_ongeldig():
    docs_app = {"name": "Docs", "type": "self_hosted", "hosts": [{"host": "docs.jbogaert.be", "path": None}],
                "verdict": "login"}
    recs = [("docs", "A", HOME, True)]
    open_fw = ex.wan_forwards(OPN_CF.format(src="any"), 1000)
    rows, out = run(cfd(recs, [docs_app]), npmd([_h(1, "docs")]), ctx(forwards=open_fw))
    d = rows["docs.jbogaert.be"]
    assert (d["state"], d["level"], d["why_key"]) == ("open", "err", "open_thuis")
    assert "Cloudflare Access is zo te omzeilen" in d["why"]
    assert {p["path"]: p["state"] for p in d["paths"]} == {"proxied": "slot", "thuis": "open"}
    assert out["inbound"]["origin"]["basis"] == "opnsense"
    # Alleen Cloudflare mag naar NPM: Access telt.
    rows, _ = run(cfd(recs, [docs_app]), npmd([_h(1, "docs")]), ctx(forwards=OPN_OK_CF()))
    assert (rows["docs.jbogaert.be"]["state"], rows["docs.jbogaert.be"]["level"]) == ("slot", "ok")
    # Geen kopie van OPNsense: een record naar het thuis-IP voor een naam van NPM zegt genoeg.
    rows, out = run(cfd(recs, [docs_app]), npmd([_h(1, "docs")]))
    assert out["inbound"]["origin"]["open"] is True and out["inbound"]["origin"]["basis"] == "dns"
    assert rows["docs.jbogaert.be"]["state"] == "open"
    # Geen kopie en alleen tunnels: niet na te gaan, Access telt met een opmerking.
    cfg = {T_THUIS: {"source": "cloudflare", "ingress": [
        {"hostname": "docs.jbogaert.be", "path": None, "service": "https://192.168.0.245:443", "access_required": False},
        {"hostname": None, "path": None, "service": "http_status:404", "access_required": False}]}}
    rows, out = run(cfd([("docs", "CNAME", TUN, True)], [docs_app], configs=cfg), npmd([_h(1, "docs")]))
    d = rows["docs.jbogaert.be"]
    assert out["inbound"]["origin"]["open"] is None
    assert (d["state"], d["level"]) == ("slot", "warn") and "origin_unknown" in keys(d)
    # ssl_verify_client on: via het thuis-IP komt niemand binnen.
    lock = _h(1, "docs", advanced_config="ssl_verify_client on;\nssl_client_certificate /data/cf-origin-pull.pem;")
    rows, _ = run(cfd(recs, [docs_app]), npmd([lock]), ctx(forwards=open_fw))
    d = rows["docs.jbogaert.be"]
    assert (d["state"], d["level"]) == ("slot", "ok")
    assert {p["path"]: p["state"] for p in d["paths"]}["thuis"] == "dicht" and "origin_lock" in keys(d)
    # Een naam zonder record, alleen in NPM: via het thuis-IP open (verborgen), met een LAN-lijst intern.
    rows, _ = run(cfd(recs, [docs_app]), npmd([_h(1, "docs"), _h(2, "geheim"), _h(3, "lan", access_list_id=1)]),
                  ctx(forwards=open_fw))
    assert (rows["geheim.jbogaert.be"]["state"], rows["geheim.jbogaert.be"]["level"]) == ("verborgen", "warn")
    assert rows["lan.jbogaert.be"]["state"] == "intern"
    rows, _ = run(cfd(recs, [docs_app]), npmd([_h(1, "docs"), _h(2, "geheim")]), ctx(forwards=OPN_OK_CF()))
    assert rows["geheim.jbogaert.be"]["state"] == "intern"


def test_tunnel_naar_docker_naam():
    recs = [(n, "CNAME", TUN, True) for n in ("docker", "direct", "admin", "jellyfin")]
    hosts = [_h(10, "docker", "192.168.0.29", 80, advanced_config=AUTHENTIK), _h(1, "jellyfin")]
    rows, _ = run(cfd(recs), npmd(hosts))
    d = rows["docker.jbogaert.be"]
    assert (d["state"], d["level"]) == ("slot", "warn") and "tunnel_guess" in keys(d)
    assert d["tunnel"]["target"] == "npm?"
    rows, _ = run(cfd(recs), npmd(hosts, names={"npm"}), ctx(npm_names={"npm"}))
    assert (rows["docker.jbogaert.be"]["state"], rows["docker.jbogaert.be"]["level"]) == ("slot", "ok")
    d = rows["direct.jbogaert.be"]
    assert (d["state"], d["level"], d["why_key"]) == ("open", "err", "open_tunnel_direct")
    assert "http://192.168.0.20:8096" in d["why"]
    a = rows["admin.jbogaert.be"]
    assert (a["state"], a["why_key"], a["tunnel"]["target"]) == ("open", "open_tunnel_direct", "direct")
    j = rows["jellyfin.jbogaert.be"]
    assert (j["state"], j["why_key"], j["tunnel"]["target"]) == ("open", "open", "npm")
    # Een Docker-naam die NPM niet kent: niet na te gaan.
    rows, _ = run(cfd(recs), npmd([_h(1, "jellyfin")]))
    assert (rows["docker.jbogaert.be"]["state"], rows["docker.jbogaert.be"]["why_key"]) == ("onbekend", "onbekend_tunnel")
    c = ctx()
    assert ex.tunnel_target("http://172.17.0.1:80", c) == "npm?" and ex.tunnel_target("ssh://192.168.0.5:22", c) == "direct"
    assert ex.tunnel_target("https://192.168.0.245", c) == "npm" and ex.tunnel_target("http_status:503", c) == "dicht"


def test_pad_ipv6_en_ander_ip():
    pw = {"access_list_id": 2}
    rows, _ = run(cfd([("v6", "AAAA", "2a02::99", False)]), npmd([_h(1, "v6", **pw)]), ctx(forwards=OPN_OK_CF()))
    v6 = rows["v6.jbogaert.be"]
    assert (v6["state"], v6["level"], v6["why_key"], v6["login"]) == ("elders", "warn", "elders_ipv6", [])
    rows, _ = run(cfd([("ander", "A", "203.0.113.7", False)]), npmd([_h(1, "ander")]), ctx(forwards=OPN_OK_CF()))
    a = rows["ander.jbogaert.be"]
    assert (a["state"], a["level"], a["why_key"]) == ("elders", "info", "elders_ip") and "npm_unused" in keys(a)
    looked = {"home.duckdns.org": {"status": "ok", "a": [HOME], "at": "2026-10-11T00:00:00+00:00"}}
    rows, _ = run(cfd([("ddns", "CNAME", "home.duckdns.org", False)]), npmd([_h(1, "ddns", **pw)]),
                  ctx(lookups=looked, forwards=OPN_OK_CF()))
    d = rows["ddns.jbogaert.be"]
    assert d["state"] == "slot" and d["dns"][0]["to"] == "home.duckdns.org (→ thuis-IP)"
    rows, out = run(cfd([("v6", "AAAA", "2a02::245", False)]), npmd([_h(1, "v6", **pw)], ipv6={"2a02::245"}),
                    ctx(npm_ipv6={"2a02::245"}, forwards=OPN_OK_CF()))
    assert rows["v6.jbogaert.be"]["state"] == "slot" and rows["v6.jbogaert.be"]["dns"][0]["to"] == "2a02::245 (NPM)"
    assert out["inbound"]["origin"]["basis"] == "ipv6"


def test_anker_en_wees():
    recs = [("ddns", "A", HOME, False), ("vpn", "A", HOME, False)] + [(f"a{i}", "CNAME", "ddns.jbogaert.be", True)
                                                                      for i in range(5)]
    hosts = [_h(i + 1, f"a{i}", access_list_id=2) for i in range(5)]
    fw = ex.wan_forwards(OPN_CF.format(src="cf_ips"), 1000)
    rows, _ = run(cfd(recs), npmd(hosts), ctx(forwards=fw))
    d = rows["ddns.jbogaert.be"]
    assert (d["state"], d["level"]) == ("elders", "muted") and "Anker voor 5 andere namen" in d["why"]
    v = rows["vpn.jbogaert.be"]
    assert (v["state"], v["level"], v["why_key"]) == ("wees", "warn", "wees_npm")
    assert "Markeer hem dan als bewust" in v["why"]
    assert next(n for n in v["notes"] if n["key"] == "other_forwards")["text"] == \
        "Je OPNsense stuurt ook 51820/udp door: hoort deze naam daarbij?"
    assert rows["a0.jbogaert.be"]["state"] == "slot" and rows["a0.jbogaert.be"]["dns"][0]["to"] == \
        "ddns.jbogaert.be (→ thuis-IP)"


def test_plaatshouders():
    recs = [("worker", "A", "192.0.2.1", True), ("worker6", "AAAA", "100::", True), ("grijs", "A", "192.0.2.1", False),
            ("lan", "A", "192.168.0.20", False), ("doc", "A", "203.0.113.7", False)]
    rows, _ = run(cfd(recs), npmd([]), ctx(forwards=OPN_OK_CF()))
    for n in ("worker", "worker6"):
        r = rows[f"{n}.jbogaert.be"]
        assert (r["state"], r["level"], r["why_key"]) == ("elders", "muted", "placeholder")
    assert (rows["grijs.jbogaert.be"]["level"], rows["grijs.jbogaert.be"]["why_key"]) == ("info", "elders_intern")
    assert rows["lan.jbogaert.be"]["why_key"] == "elders_intern"
    assert rows["doc.jbogaert.be"]["why_key"] == "elders_ip"  # een documentatieblok is gewoon elders


def test_zone_niet_zichtbaar():
    hosts = [_h(1, "x.other.be"), {**_h(2, "nas"), "domain_names": ["nas.lan"]}, {**_h(3, "ip"), "domain_names": ["192.168.0.20"]}]
    rows, _ = run(cfd([]), npmd(hosts))
    assert (rows["x.other.be"]["state"], rows["x.other.be"]["level"]) == ("onbekend", "warn")
    assert "other.be" in rows["x.other.be"]["why"]
    assert rows["nas.lan"]["state"] == "intern" and rows["192.168.0.20"]["state"] == "intern"


def test_vingerafdruk_en_markeringen():
    rows, out = run(cfd([("blog", "A", HOME, True), ("stale", "A", HOME, False)]), npmd([_h(1, "blog")]),
                    ctx(forwards=OPN_OK_CF()))
    blog = rows["blog.jbogaert.be"]
    value = {**out, "at": "2026-10-11T10:00:00+00:00"}
    marked = ex.apply_marks(value, {"blog.jbogaert.be": {"reason": "publieke blog", "by": "jonas", "at": "x",
                                                         "sig": blog["sig"]}})
    m = {r["name"]: r for r in marked["rows"]}["blog.jbogaert.be"]
    assert (m["state"], m["level"], m["base"]) == ("bewust", "info", "open") and m["why"] == "Bewust zo: publieke blog"
    assert marked["counts"]["bewust"] == 1 and marked["counts"]["err"] == 0
    assert ex.alarms(marked) == {}
    old = ex.apply_marks(value, {"blog.jbogaert.be": {"reason": "x", "sig": "anders"}})
    m = {r["name"]: r for r in old["rows"]}["blog.jbogaert.be"]
    assert m["state"] == "open" and "mark_old" in keys(m)
    assert ex.alarms(value) == {"pub:blog.jbogaert.be": {"title": "blog.jbogaert.be staat open van buitenaf",
                                                          "why": blog["why"], "kind": "open"}}
    s = ex.summary(value, datetime.now(timezone.utc))
    assert s["red"][0]["name"] == "blog.jbogaert.be" and s["wees"] == ["stale.jbogaert.be"] and s["wees_n"] == 1
    assert s["origin"] == "cf" and s["never"] is False and s["public"] == 2


def test_lezen_mislukt_is_niet_na_te_gaan():
    """Een fout bij Cloudflare of NPM (geen 403) mag geen oordeel geven dat de ronde erna weer anders is."""
    recs = [(n, "CNAME", TUN, True) for n in ("direct", "jellyfin", "nas")]
    hosts = [_h(1, "jellyfin"), _h(3, "nas", "192.168.0.22", 5000, access_list_id=1)]
    rows, _ = run(cfd(recs, access_read=None), npmd(hosts))
    for n in ("direct", "jellyfin"):
        r = rows[f"{n}.jbogaert.be"]
        assert (r["state"], r["level"], r["why_key"], r["undecided"]) == ("onbekend", "warn", "onbekend_access", True)
    # De instellingen van de tunnel: een fout maakt de rij onzeker, een 403 niet (die blijft elke ronde gelijk).
    rows, _ = run(cfd(recs, configs={T_THUIS: None}, tunnel_config=None), npmd(hosts))
    assert rows["jellyfin.jbogaert.be"]["undecided"] is True and "tunnel_unread" in keys(rows["jellyfin.jbogaert.be"])
    rows, _ = run(cfd(recs, configs={T_THUIS: None}, tunnel_config=False), npmd(hosts))
    assert rows["jellyfin.jbogaert.be"]["undecided"] is False
    # Toegangslijsten: leesbaar is de LAN-lijst via de tunnel rood; niet leesbaar door een fout is het onzeker.
    rows, _ = run(cfd(recs), npmd(hosts))
    assert (rows["nas.jbogaert.be"]["state"], rows["nas.jbogaert.be"]["undecided"]) == ("open", False)
    broken = npmd(hosts, lists=None)
    broken.rights["npm_access_lists"] = None
    rows, _ = run(cfd(recs), broken)
    assert (rows["nas.jbogaert.be"]["state"], rows["nas.jbogaert.be"]["undecided"]) == ("slot", True)


def test_tunnels_met_dezelfde_naam():
    cf = cfd([("a", "CNAME", TUN, True), ("b", "CNAME", TUN, True), ("c", "CNAME", f"{T_OUD}.cfargotunnel.com", True)])
    cf.tunnels = [{"id": T_THUIS, "name": "homelab", "status": "healthy", "deleted": False},
                  {"id": T_OUD, "name": "homelab", "status": "inactive", "deleted": True},
                  {"id": T_TWEEDE, "name": "homelab", "status": "inactive", "deleted": True}]
    _, out = run(cf, npmd([_h(1, "a"), _h(2, "b")]))
    assert [(t["name"], t["deleted"], t["names"]) for t in out["inbound"]["tunnels"]] == [
        ("homelab", False, 2), ("homelab", True, 1)]


def test_access_app_voor_de_hele_naam():
    apps = [{"name": "API", "type": "self_hosted", "hosts": [{"host": "sonarr.jbogaert.be", "path": "/api"}],
             "verdict": "bypass"},
            {"name": "Alles", "type": "self_hosted", "hosts": [{"host": "*.jbogaert.be", "path": None}],
             "verdict": "login"}]
    assert ex.access_for(apps, "sonarr.jbogaert.be") == ("login", "Alles", None, ["/api"])
    rows, _ = run(cfd([("sonarr", "A", HOME, True)], apps), npmd([_h(1, "sonarr")]), ctx(forwards=OPN_OK_CF()))
    s = rows["sonarr.jbogaert.be"]
    assert (s["state"], s["login"]) == ("slot", ["Cloudflare Access (Alles)"])
    assert next(n for n in s["notes"] if n["key"] == "partial")["text"] == "Deels zonder login: /api (Cloudflare Access)."
    assert "access_path" not in keys(s)


def test_publiek_ip_onbekend():
    recs = [("blog", "A", HOME, True), ("pw", "A", HOME, True)]
    hosts = [_h(1, "blog"), _h(2, "pw", access_list_id=2)]
    rows, _ = run(cfd(recs), npmd(hosts), ctx(forwards=OPN_OK_CF()))
    known = rows["blog.jbogaert.be"]
    rows, _ = run(cfd(recs), npmd(hosts), ctx(forwards=OPN_OK_CF(), ip_known=False, public_ip=None, home_ips=set(),
                                                old_ips=set(), ip_why="geen antwoord"))
    blog, pw = rows["blog.jbogaert.be"], rows["pw.jbogaert.be"]
    # Dezelfde vingerafdruk: een markering "bewust" blijft gelden (geen nieuwe melding).
    assert (blog["state"], blog["undecided"], blog["sig"]) == ("open", "ip", known["sig"]) and "ip_unknown" in keys(blog)
    # Een login geldt hoe dan ook; alleen een overname is niet na te gaan.
    assert (pw["state"], pw["undecided"]) == ("slot", "ip")


def test_alarm_bij_onzekere_rijen():
    """Zonder publiek IP geldt een login nog (herstel); een overname of een rij die niet te lezen was, houdt het alarm."""
    class Db:
        def __init__(self):
            self.added = []

        def add(self, x):
            self.added.append(x)

    old = {f"pub:{n}.jbogaert.be": {"title": n, "why": "", "kind": k}
           for n, k in (("slot", "open"), ("overname", "overname_ip"), ("lijst", "open"), ("wees", "open"))}
    rows = [{"name": "slot.jbogaert.be", "state": "slot", "undecided": "ip"},
            {"name": "overname.jbogaert.be", "state": "slot", "undecided": "ip"},
            {"name": "lijst.jbogaert.be", "state": "slot", "undecided": True},
            {"name": "wees.jbogaert.be", "state": "wees", "undecided": "ip"}]
    db = Db()
    alarm = ex._notify(db, {"alarm": old}, {"rows": rows}, {})
    assert set(alarm) == {"pub:overname.jbogaert.be", "pub:lijst.jbogaert.be", "pub:wees.jbogaert.be"}
    assert [x.title for x in db.added if isinstance(x, Notification)] == ["slot.jbogaert.be is niet meer open"]


def test_dit_dashboard_alleen_op_nginx():
    hosts = [_h(1, "home", "192.168.10.156", 80), _h(2, "proef", "192.168.10.156", 8080)]
    rows, _ = run(cfd([("home", "A", HOME, True), ("proef", "A", HOME, True)]), npmd(hosts),
                  ctx(forwards=OPN_OK_CF(), dashboard_ip="192.168.10.156"))
    assert rows["home.jbogaert.be"]["login"] == ["eigen login met 2FA (dit dashboard)"]
    assert (rows["proef.jbogaert.be"]["state"], rows["proef.jbogaert.be"]["login"]) == ("open", [])


# --- de ronde, de API en de veiligheid ----------------------------------------------------------------------------

def _ip_state(ip: str = HOME, history=None, error: str | None = None) -> dict:
    now = datetime.now(timezone.utc)
    if history is None:
        history = [{"ip": OLD, "since": (now - timedelta(days=30)).isoformat(), "until": (now - timedelta(days=3)).isoformat()}]
    return {"ip": ip, "since": (now - timedelta(days=3)).isoformat(), "checked_at": now.isoformat(), "error": error,
            "history": history}


async def _put_state(key: str, value: dict) -> None:
    agen, db = await _db()
    st = await db.get(AppState, key)
    if st is None:
        db.add(AppState(key=key, value=value))
    else:
        st.value = value
    await db.commit()
    await agen.aclose()


async def _get_state(key: str) -> dict | None:
    agen, db = await _db()
    st = await db.get(AppState, key)
    value = dict(st.value or {}) if st else None
    await agen.aclose()
    return value


async def _notifications() -> list[Notification]:
    agen, db = await _db()
    out = list((await db.execute(select(Notification).order_by(Notification.id))).scalars())
    await agen.aclose()
    return out


async def _setup(authed, opn: str | None = "cf_ips", cf_config: dict | None = None) -> dict:
    g = await _group(authed)
    ids = {"cf": await _svc(authed, g, "cloudflared", "https://one.dash.cloudflare.com",
                            config={"account": ACCOUNT, "tunnel": "thuis", **(cf_config or {})},
                            secrets={"token": "cf-token"}, name="Cloudflare"),
           "npm": await _svc(authed, g, "npm", "http://192.168.0.245:81", secrets={"username": "dashboard@jbogaert.be",
                                                                                    "password": "npm-geheim"}, name="NPM")}
    if opn:
        ids["opn"] = await _svc(authed, g, "opnsense", "https://192.168.0.1", secrets={"key": "k", "secret": "s"},
                                name="OPNsense")
    await _put_state("public_ip", _ip_state())
    if opn:
        agen, db = await _db()
        await configs.store(db, f"opnsense:{ids['opn']}", "OPNsense · config.xml", "opnsense", OPN_CF.format(src=opn),
                            datetime.now(timezone.utc))
        await db.commit()
        await agen.aclose()
    return ids


async def _run(pub: Pub) -> bool:
    agen, db = await _db()
    try:
        done = await ex.run_exposure(db, pub.clients)
        await db.commit()
    finally:
        await agen.aclose()
    return done


async def _rows(authed) -> dict[str, dict]:
    return {r["name"]: r for r in (await authed.get("/api/exposure")).json()["rows"]}


def _st(r: dict) -> tuple[str, str]:
    return r["state"], r["level"]


async def _checklist(authed) -> dict:
    data = (await authed.get("/api/attention/setup")).json()
    return next(r for g in data["groups"] for r in g["rows"] if r["key"] == "exposure")


async def _attention_keys(authed) -> dict[str, dict]:
    return {i["key"]: i for i in (await authed.get("/api/attention")).json()["items"]}


async def test_overzicht_per_naam(authed, pub):
    await _setup(authed)
    assert await _run(pub) is True
    rows = await _rows(authed)
    assert _st(rows["jellyfin.jbogaert.be"]) == ("open", "err") and rows["jellyfin.jbogaert.be"]["why_key"] == "open"
    assert rows["jellyfin.jbogaert.be"]["tunnel"] == {"name": "thuis", "service": "https://192.168.0.245:443",
                                                      "target": "npm", "managed": "cloudflare"}
    assert rows["jellyfin.jbogaert.be"]["dns"][0]["to"] == "tunnel thuis"
    assert _st(rows["dash.jbogaert.be"]) == ("slot", "ok") and rows["dash.jbogaert.be"]["login"] == ["Authentik"]
    assert rows["nas.jbogaert.be"]["why_key"] == "open_ip_tunnel" and _st(rows["nas.jbogaert.be"]) == ("open", "err")
    git = rows["git.jbogaert.be"]
    assert _st(git) == ("dicht", "ok") and [n["level"] for n in git["notes"] if n["key"] == "xrealip"] == ["info"]
    assert _st(rows["docs.jbogaert.be"]) == ("slot", "ok") and rows["docs.jbogaert.be"]["login"] == ["Cloudflare Access (Docs)"]
    assert _st(rows["pin.jbogaert.be"]) == ("slot", "warn") and "access_everyone" in keys(rows["pin.jbogaert.be"])
    assert _st(rows["blog.jbogaert.be"]) == ("open", "err") and "access_bypass" in keys(rows["blog.jbogaert.be"])
    assert _st(rows["oud-ip.jbogaert.be"]) == ("overname", "err") and rows["oud-ip.jbogaert.be"]["dns"][0]["to"] == \
        f"{OLD} (vroeger thuis-IP)"
    assert _st(rows["shop.jbogaert.be"]) == ("overname", "err") and "gone.herokuapp.com" in rows["shop.jbogaert.be"]["why"]
    assert _st(rows["stale.jbogaert.be"]) == ("wees", "warn") and "other_forwards" in keys(rows["stale.jbogaert.be"])
    assert rows["oude-tunnel.jbogaert.be"]["why_key"] == "wees_tunnel_weg"
    assert _st(rows["home.jbogaert.be"]) == ("slot", "warn") and "dns_only" in keys(rows["home.jbogaert.be"])
    assert _st(rows["intern.jbogaert.be"]) == ("intern", "muted")
    assert _st(rows["direct.jbogaert.be"]) == ("open", "err") and _st(rows["admin.jbogaert.be"]) == ("open", "err")
    assert _st(rows["docker.jbogaert.be"]) == ("slot", "warn")
    assert "jbogaert.be" not in rows  # alleen TXT en MX
    data = (await authed.get("/api/exposure")).json()
    assert data["counts"] == {"err": 7, "warn": 5, "ok": 3, "bewust": 0, "rest": 1}
    assert data["inbound"]["paths"] == {"tunnel": 6, "proxied": 6, "dns-only": 3}
    assert data["inbound"]["origin"]["basis"] == "cloudflare" and data["inbound"]["public_ip"] == HOME
    assert [(t["name"], t["names"], t["managed"], t["deleted"]) for t in data["inbound"]["tunnels"]] == [
        ("oud", 1, None, True), ("thuis", 5, "cloudflare", False), ("tweede", 0, "local", False)]
    assert data["configured"] == {"cloudflare": True, "npm": True} and data["errors"] == [] and data["stale"] is False
    assert data["sources"]["cloudflare"][0]["zones"] == ["jbogaert.be"] and data["sources"]["npm"][0]["hosts"] == 10
    assert data["rights"]["access_zone"] is False and data["rights"]["access_read"] is True
    assert [r["name"] for r in data["rows"][:7]] == sorted(n for n, r in rows.items() if r["level"] == "err")
    # Hetzelfde via de knop.
    r = await authed.post("/api/exposure/refresh")
    assert r.status_code == 200 and r.json()["counts"] == data["counts"]


async def test_geen_geheimen_naar_de_browser(authed, pub):
    pub.hosts[0] = {**pub.hosts[0], "advanced_config": "# eigen-nginx-tekst\nproxy_set_header X-Geheim abc;"}
    await _setup(authed)
    await _run(pub)
    text = (await authed.get("/api/exposure")).text + (await authed.get("/api/exposure/proef")).text
    for secret in ("cf-token", "npm-geheim", "jwt-npm-sessie", "gast-gebruiker", "hint-geheim", "eigen-nginx-tekst",
                   "X-Geheim", "outpost.goauthentik", "jonas@voorbeeld.be", "aud-geheim", "header-geheim",
                   "notitie-in-dns", "geheim-label", "hash-geheim", "igb0", "lookups", "alarm"):
        assert secret not in text, secret


async def test_rechten_ontbreken(authed, pub):
    await _setup(authed)
    pub.access_forbidden = True
    await _run(pub)
    data = (await authed.get("/api/exposure")).json()
    assert data["rights"]["access_read"] is False and data["errors"] == []
    docs = {r["name"]: r for r in data["rows"]}["docs.jbogaert.be"]
    assert _st(docs) == ("onbekend", "warn") and docs["undecided"] is True
    assert not any("docs" in (n.body or "") + n.title or "Access" in n.title for n in await _notifications())
    row = await _checklist(authed)
    assert row["state"] == "half" and any("Account → Access: Apps and Policies → Read" in t for t in row["todo"])
    assert "pub:fout" not in await _attention_keys(authed)
    pub.access_forbidden, pub.settings_forbidden = False, True
    await authed.post("/api/exposure/refresh")
    row = await _checklist(authed)
    assert row["state"] == "ok" and "Optioneel: Zone → Zone Settings → Read" in row["text"]
    assert row["text"].startswith("15 publieke namen: 7 open zonder login, 0 bewust.")


async def test_lege_zonelijst_is_fout(authed, pub):
    ids = await _setup(authed)
    await _run(pub)
    before = await _rows(authed)
    pub.zones_empty = True
    assert await _run(pub) is True
    data = (await authed.get("/api/exposure")).json()
    assert data["errors"][0] == ("Het Cloudflare-token ziet geen zone jbogaert.be: geef Zone → Zone → Read en Zone → DNS "
                                 "→ Read, met Zone Resources → jbogaert.be.")
    assert {r["name"] for r in data["rows"]} == set(before) and data["at"] != data["checked_at"]
    assert (await _checklist(authed))["state"] == "half"
    assert (await _attention_keys(authed))["pub:fout"]["level"] == "warn"
    pub.zones_empty = False
    agen, db = await _db()
    from app.models import Service
    svc = await db.get(Service, ids["cf"])
    svc.config = {**svc.config, "zones": "jbogaert.be,other.be"}
    await db.commit()
    await agen.aclose()
    await _run(pub)
    assert (await _get_state(ex.STATE_KEY))["errors"][0].startswith("Het Cloudflare-token ziet geen zone other.be:")
    agen, db = await _db()
    svc = await db.get(Service, ids["cf"])
    svc.config = {k: v for k, v in svc.config.items() if k != "zones"}
    await db.commit()
    await agen.aclose()
    pub.records = []
    await _run(pub)
    assert (await _get_state(ex.STATE_KEY))["errors"] == [
        "Het Cloudflare-token ziet geen enkel record in jbogaert.be, maar NPM heeft er 10 namen onder: geef Zone → DNS → "
        "Read, met Zone Resources → jbogaert.be."]


async def test_npm_weg_geen_valse_wezen(authed, pub):
    await _setup(authed)
    await _run(pub)
    before = await _get_state(ex.STATE_KEY)
    n = len(await _notifications())
    pub.npm_down = True
    await _run(pub)
    after = await _get_state(ex.STATE_KEY)
    assert after["rows"] == before["rows"] and after["alarm"] == before["alarm"] and after["at"] == before["at"]
    assert after["errors"] and after["errors"][0].startswith("NPM: HTTP 502")
    assert len(await _notifications()) == n


async def test_meldingen(authed, pub):
    await _setup(authed)
    await _run(pub)
    first = [x for x in await _notifications() if x.source == "blootstelling"]
    assert len(first) == 1 and first[0].pushed_at is not None and first[0].level == "warn"
    assert first[0].title == "Netwerk › publiek: 7 namen open van buitenaf"
    # Een nieuwe open naam: één melding.
    pub.records.append(_r("new", "A", HOME, True))
    pub.hosts.append(_h(20, "new", "192.168.0.40", 80))
    await _run(pub)
    new = [x for x in await _notifications() if x.source == "blootstelling"][1:]
    assert [(x.level, x.push_key, x.pushed_at) for x in new] == [("err", "pub:new.jbogaert.be", None)]
    # Een toegangslijst ervoor: hersteld.
    pub.hosts[-1] = {**pub.hosts[-1], "access_list_id": 2}
    await _run(pub)
    ok = [x for x in await _notifications() if x.source == "blootstelling"][2:]
    assert [(x.level, x.push_key, x.recovers, x.title) for x in ok] == [
        ("ok", "pub:new.jbogaert.be", "err", "new.jbogaert.be is niet meer open")]
    # Weer open, dan bewust markeren: geen herstelmelding.
    pub.hosts[-1] = {**pub.hosts[-1], "access_list_id": 0}
    await _run(pub)
    r = await authed.put("/api/exposure/intended", json={"name": "new.jbogaert.be", "reason": "publieke testsite"})
    assert r.status_code == 200, r.text
    count = len([x for x in await _notifications() if x.source == "blootstelling"])
    await _run(pub)
    assert len([x for x in await _notifications() if x.source == "blootstelling"]) == count
    # Een opgeslagen leeg alarm is geen eerste ronde: per naam, hoogstens vijf en één samenvatting.
    st = await _get_state(ex.STATE_KEY)
    await _put_state(ex.STATE_KEY, {**st, "alarm": {}})
    await _run(pub)
    many = [x for x in await _notifications() if x.source == "blootstelling"][count:]
    assert [x.level for x in many] == ["err"] * 6
    assert len({x.push_key for x in many[:5]}) == 5 and many[5].title == "Netwerk › publiek: nog 2 namen open van buitenaf"


async def test_ip_geschiedenis(authed, pub):
    await _setup(authed)
    now = datetime.now(timezone.utc)
    # A → B → A: het huidige IP staat ook in de geschiedenis.
    await _put_state("public_ip", _ip_state(history=[
        {"ip": HOME, "since": (now - timedelta(days=9)).isoformat(), "until": (now - timedelta(days=5)).isoformat()},
        {"ip": OLD, "since": (now - timedelta(days=5)).isoformat(), "until": (now - timedelta(days=3)).isoformat()}]))
    await _run(pub)
    rows = await _rows(authed)
    assert _st(rows["dash.jbogaert.be"]) == ("slot", "ok") and rows["oud-ip.jbogaert.be"]["state"] == "overname"
    n = len(await _notifications())
    alarm = (await _get_state(ex.STATE_KEY))["alarm"]
    # Nieuw IP sinds 2 uur: de records naar het vorige IP blijven zoals ze waren, met een opmerking.
    older = {"ip": OLD, "since": (now - timedelta(days=30)).isoformat(), "until": (now - timedelta(days=3)).isoformat()}
    await _put_state("public_ip", _ip_state("81.82.83.99", history=[
        {"ip": HOME, "since": (now - timedelta(days=3)).isoformat(), "until": (now - timedelta(hours=2)).isoformat()},
        older]))
    await _run(pub)
    rows = await _rows(authed)
    assert _st(rows["dash.jbogaert.be"]) == ("slot", "warn") and "ip_wissel" in keys(rows["dash.jbogaert.be"])
    assert rows["dash.jbogaert.be"]["dns"][0]["to"].startswith("thuis-IP (vorig, tot ")
    assert _st(rows["blog.jbogaert.be"]) == ("open", "err") and rows["oud-ip.jbogaert.be"]["state"] == "overname"
    assert (await _get_state(ex.STATE_KEY))["alarm"] == alarm
    assert len(await _notifications()) == n
    # Een dag later: wie dat adres nu heeft, kan de naam overnemen.
    await _put_state("public_ip", _ip_state("81.82.83.99", history=[
        {"ip": HOME, "since": (now - timedelta(days=3)).isoformat(), "until": (now - timedelta(hours=25)).isoformat()},
        older]))
    await _run(pub)
    rows = await _rows(authed)
    assert _st(rows["dash.jbogaert.be"]) == ("overname", "err")
    # Publiek IP onbekend: geen overname of wees op basis van het IP, en het alarm blijft staan zonder herstel.
    await _put_state("public_ip", _ip_state(error="time-out"))
    before = (await _get_state(ex.STATE_KEY))["alarm"]
    n = len(await _notifications())
    await _run(pub)
    rows = await _rows(authed)
    assert rows["dash.jbogaert.be"]["undecided"] == "ip" and rows["dash.jbogaert.be"]["state"] != "overname"
    assert rows["stale.jbogaert.be"]["state"] == "elders" and "ip_unknown" in keys(rows["stale.jbogaert.be"])
    assert not any(r["why_key"] == "overname_ip" for r in rows.values())
    assert "pub:dash.jbogaert.be" in (await _get_state(ex.STATE_KEY))["alarm"]
    assert set(before) <= set((await _get_state(ex.STATE_KEY))["alarm"])
    assert [x for x in await _notifications()][n:] == []


async def test_gelijktijdige_rondes(authed, pub, monkeypatch):
    await _setup(authed)
    await _run(pub)
    base_state, base_summary = await _get_state(ex.STATE_KEY), await _get_state(ex.SUMMARY_KEY)
    pub.records.append(_r("new", "A", HOME, True))
    pub.hosts.append(_h(20, "new", "192.168.0.40", 80))
    got, real = [], ex.commit_result

    async def grab(db, started, result, errors):
        got.append((started, result, errors))
        return True

    monkeypatch.setattr(ex, "commit_result", grab)
    await _run(pub)  # A
    await _run(pub)  # B
    monkeypatch.setattr(ex, "commit_result", real)
    (sa, ra, ea), (sb, rb, eb) = got
    assert sa < sb

    async def commit(started, result, errors) -> bool:
        agen, db = await _db()
        done = await ex.commit_result(db, started, result, errors)
        await db.commit()
        await agen.aclose()
        return done

    def news(rows):
        return [x for x in rows if x.push_key == "pub:new.jbogaert.be"]

    # B eerst, dan A (ouder): A schrijft niets.
    n = len(await _notifications())
    assert await commit(sb, rb, eb) is True
    assert await commit(sa, ra, ea) is False
    assert (await _get_state(ex.STATE_KEY))["checked_at"] == sb.isoformat()
    assert len(news((await _notifications())[n:])) == 1
    # A eerst, dan B: B vergelijkt met het alarm van A.
    await _put_state(ex.STATE_KEY, base_state)
    await _put_state(ex.SUMMARY_KEY, base_summary)
    n = len(await _notifications())
    assert await commit(sa, ra, ea) is True
    assert await commit(sb, rb, eb) is True
    assert len(news((await _notifications())[n:])) == 1


async def test_doh_begrensd(pub, monkeypatch):
    client = pub.clients.get(False)
    targets = [f"app{i}.voorbeeld.net" for i in range(50)]
    out = await ex.lookup(client, targets, {})
    assert len(pub.doh) == ex.MAX_LOOKUPS and 2 <= pub.doh_max <= ex.LOOKUP_PARALLEL
    assert sum(v["status"] == "ok" for v in out.values()) == 40 and sum(v["status"] == "?" for v in out.values()) == 10
    pub.doh.clear()
    again = await ex.lookup(client, targets, {k: v for k, v in out.items() if v.get("at")})
    assert len(pub.doh) == 10 and all(v["status"] == "ok" for v in again.values())
    assert (await ex.lookup(client, ["gone.herokuapp.com"], {}))["gone.herokuapp.com"]["status"] == "nx"
    monkeypatch.setattr(ex, "LOOKUP_TIMEOUT", 0.2)
    pub.slow = True
    t0 = asyncio.get_running_loop().time()
    slow = await ex.lookup(client, ["traag.voorbeeld.net"], {})
    assert slow["traag.voorbeeld.net"] == {"status": "?", "a": [], "at": None}
    assert asyncio.get_running_loop().time() - t0 < 2


async def test_bewust_vraagt_2fa(authed, pub):
    await _setup(authed)
    await _run(pub)
    await _stale(authed)
    body = {"name": "jellyfin.jbogaert.be", "reason": "publieke mediaserver met eigen login"}
    r = await authed.put("/api/exposure/intended", json=body)
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    await _reauth(authed)
    r = await authed.put("/api/exposure/intended", json=body)
    assert r.status_code == 200, r.text
    row = {x["name"]: x for x in r.json()["rows"]}["jellyfin.jbogaert.be"]
    assert (row["state"], row["level"], row["base"]) == ("bewust", "info", "open")
    assert row["intended"]["reason"] == "publieke mediaserver met eigen login" and row["intended"]["by"] == "jonas"
    agen, db = await _db()
    audit = [(a.action, a.detail) for a in (await db.execute(select(AuditLog).order_by(AuditLog.id))).scalars()]
    note = (await db.execute(select(Notification).where(Notification.source == "auth"))).scalars().all()
    await agen.aclose()
    assert ("exposure_intended", {"name": "jellyfin.jbogaert.be", "reason": "publieke mediaserver met eigen login"}) in audit
    assert [n.title for n in note][-1] == "Bewust open: jellyfin.jbogaert.be" and note[-1].level == "warn"
    summary = await _get_state(ex.SUMMARY_KEY)
    assert "jellyfin.jbogaert.be" not in [x["name"] for x in summary["red"]] and summary["counts"]["bewust"] == 1
    r = await authed.delete("/api/exposure/intended/jellyfin.jbogaert.be")
    assert r.status_code == 200
    assert {x["name"]: x for x in r.json()["rows"]}["jellyfin.jbogaert.be"]["state"] == "open"
    agen, db = await _db()
    actions = [a.action for a in (await db.execute(select(AuditLog))).scalars()]
    await agen.aclose()
    assert "exposure_intended_removed" in actions
    assert (await authed.delete("/api/exposure/intended/jellyfin.jbogaert.be")).status_code == 404


async def test_bewust_welke_staten(authed, pub):
    await _setup(authed)
    await _run(pub)

    async def put(name):
        return await authed.put("/api/exposure/intended", json={"name": name, "reason": "eigen reden"})

    r = await put("stale.jbogaert.be")
    assert r.status_code == 200 and {x["name"]: x for x in r.json()["rows"]}["stale.jbogaert.be"]["state"] == "bewust"
    assert (await _notifications())[-1].title == "Bewust zo: stale.jbogaert.be"
    assert (await put("dash.jbogaert.be")).status_code == 409
    r = await put("oud-ip.jbogaert.be")
    assert r.status_code == 409 and r.json()["detail"].startswith("Alleen open namen, wildcards")
    assert (await put("onbekend.jbogaert.be")).status_code == 404
    assert (await authed.put("/api/exposure/intended", json={"name": "blog.jbogaert.be", "reason": "x"})).status_code == 422


async def test_markering_vervalt_bij_wijziging(authed, pub):
    await _setup(authed)
    await _run(pub)
    r = await authed.put("/api/exposure/intended", json={"name": "jellyfin.jbogaert.be", "reason": "eigen login"})
    assert {x["name"]: x for x in r.json()["rows"]}["jellyfin.jbogaert.be"]["state"] == "bewust"
    pub.hosts[0] = {**pub.hosts[0], "forward_port": 8097}
    r = await authed.post("/api/exposure/refresh")
    row = {x["name"]: x for x in r.json()["rows"]}["jellyfin.jbogaert.be"]
    assert row["state"] == "open" and "mark_old" in keys(row)


async def test_vernieuwen_te_snel(authed, pub):
    await _setup(authed)
    assert (await authed.post("/api/exposure/refresh")).status_code == 200
    r = await authed.post("/api/exposure/refresh")
    assert r.status_code == 429 and r.json()["detail"] == "Net vernieuwd, probeer zo opnieuw"


async def test_proef_stuurt_niets(authed, pub):
    await _setup(authed)
    pub.calls.clear()
    p = (await authed.get("/api/exposure/proef")).json()
    assert p["proef"] is True and pub.calls == []
    calls = [s["call"] for s in p["steps"]]
    assert "GET /zones?status=active&per_page=50&page=1" in calls
    assert "GET /api/nginx/access-lists?expand=items,clients" in calls
    assert any(s["who"] == "NPM-gebruiker dashboard@jbogaert.be" for s in p["steps"])
    assert {c["what"]: c["ok"] for c in p["checks"]}["nachtelijke kopie van OPNsense"] is True


async def test_eerste_ronde_met_fout(authed, pub):
    await _setup(authed)
    pub.dns_forbidden = True
    await _run(pub)
    data = (await authed.get("/api/exposure")).json()
    assert data["at"] is None and data["errors"] == [
        "Het Cloudflare-token mag de DNS-records van jbogaert.be niet lezen: geef Zone → DNS → Read."]
    assert (await _get_state(ex.SUMMARY_KEY))["never"] is True
    assert "pub:fout" in await _attention_keys(authed)
    row = await _checklist(authed)
    assert row["state"] == "half" and any(t.startswith("Nog niet gelukt") for t in row["todo"])
    assert [x for x in await _notifications() if x.source == "blootstelling"] == []


async def test_overzicht_leest_alleen_samenvatting(authed, pub):
    await _setup(authed)
    await _run(pub)
    err = (await _get_state(ex.STATE_KEY))["counts"]["err"]
    await _put_state(ex.STATE_KEY, {})
    assert (await authed.get("/api/network")).json()["exposure"]["err"] == err == 7
    items = await _attention_keys(authed)
    item = items["pub:jellyfin.jbogaert.be"]
    assert item["fix"] == {"window": "net", "tab": "publiek"} and item["level"] == "err"
    assert items["pub:overname:shop.jbogaert.be"]["title"] == "shop.jbogaert.be: DNS-record kan overgenomen worden"
    assert items["pub:wees"]["title"] == "2 DNS-records zonder host"
    await _stale(authed)
    r = await authed.put("/api/attention/ignore", json={"key": "pub:jellyfin.jbogaert.be", "sig": item["sig"]})
    assert r.status_code == 403 and r.json()["detail"] == "reauth_required"
    await _reauth(authed)
    r = await authed.put("/api/attention/ignore", json={"key": "pub:jellyfin.jbogaert.be", "sig": item["sig"]})
    assert r.status_code == 200
    assert (await _notifications())[-1].title == \
        "Waarschuwing over publiek genegeerd: jellyfin.jbogaert.be staat open van buitenaf"


async def test_verborgen_vingerafdruk_per_naam(authed):
    base = {"at": datetime.now(timezone.utc).isoformat(), "verborgen_n": 2, "origin_text": "Poort 443 staat open."}
    await _put_state(ex.SUMMARY_KEY, {**base, "verborgen": ["a.jbogaert.be", "b.jbogaert.be"]})
    sig = (await _attention_keys(authed))["pub:verborgen"]["sig"]
    await _put_state(ex.SUMMARY_KEY, {**base, "verborgen": ["a.jbogaert.be", "pve.jbogaert.be"]})
    assert (await _attention_keys(authed))["pub:verborgen"]["sig"] != sig


async def test_checklist_optioneel(authed, pub):
    row = await _checklist(authed)
    assert (row["state"], row["optional"], row["fix"]) == ("none", True, {"window": "api"})
    data = (await authed.get("/api/exposure")).json()
    assert data["configured"] == {"cloudflare": False, "npm": False} and data["rows"] == []
    agen, db = await _db()
    assert await ex.run_exposure(db, pub.clients) is True
    await db.commit()
    await agen.aclose()
    assert pub.calls == []


async def test_npm_zonder_hosts_is_fout(authed, pub):
    await _setup(authed)
    pub.hosts = []
    await _run(pub)
    assert (await _get_state(ex.STATE_KEY))["errors"] == [
        "NPM: NPM gaf geen enkele proxy host: ziet de NPM-gebruiker alle items?"]


async def test_diagnose_zonder_namen(authed, pub):
    await _setup(authed)
    await _run(pub)
    data = (await authed.get("/api/diagnose")).json()
    pub_ = data["achtergrond"]["exposure_summary"]
    assert pub_["counts"] == {"err": 7, "warn": 5, "ok": 3, "bewust": 0, "rest": 1} and pub_["never"] is False
    assert pub_["origin"] == "cf" and pub_["optional"] == ["access_zone"] and pub_["errors"] == []
    text = json.dumps(data["achtergrond"])
    assert "jbogaert.be" not in text and "exposure_intended" not in text and '"exposure"' not in text
