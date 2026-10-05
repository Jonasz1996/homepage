"""Checks rechtstreeks naar de server achter NPM (monitoring/routes.py): zonder DNS, met de headers van NPM; de link
van de tegel blijft de naam."""

from datetime import datetime, timedelta, timezone

import httpx
import pytest
from sqlalchemy import select

from app.integrations import npm as npm_integration
from app.models import AppState, AuditLog, Service
from app.monitoring import checks, ports, routes
from app.monitoring.checks import HttpClients, check_service, run_check
from app.routers import integrations as integrations_router
from app.routers import npmroutes

from .test_kuma_vervangen import _db, _group

NOW = datetime(2026, 10, 5, 21, 0, tzinfo=timezone.utc)
CERT = "2026-12-01 10:00:00"
HOSTS = [
    {"id": 1, "domain_names": ["jelly.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.27",
     "forward_port": 8096, "certificate_id": 5, "enabled": True},
    {"id": 2, "domain_names": ["pve.jbogaert.be"], "forward_scheme": "https", "forward_host": "192.168.0.50",
     "forward_port": 8006, "certificate_id": 5, "enabled": True},
    {"id": 3, "domain_names": ["uit.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.60",
     "forward_port": 80, "enabled": False},
    {"id": 4, "domain_names": ["eigen.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.61",
     "forward_port": 80, "enabled": True, "advanced_config": "location / { proxy_pass http://192.168.0.62; }"},
    {"id": 5, "domain_names": ["docker.jbogaert.be"], "forward_scheme": "http", "forward_host": "jellyfin",
     "forward_port": 8096, "enabled": True},
    {"id": 6, "domain_names": ["npm.jbogaert.be"], "forward_scheme": "http", "forward_host": "127.0.0.1",
     "forward_port": 81, "enabled": True},
    {"id": 7, "domain_names": ["*.lab.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.40",
     "forward_port": 80, "enabled": True},
    {"id": 8, "domain_names": ["app.jbogaert.be", "App2.JBogaert.be"], "forward_scheme": "http",
     "forward_host": "192.168.0.30", "forward_port": 3000, "enabled": True,
     "locations": [{"path": "/api", "forward_scheme": "http", "forward_host": "192.168.0.31", "forward_port": 4000},
                   {"path": "/api/oud", "forward_scheme": "http", "forward_host": "192.168.0.32/oud",
                    "forward_port": 80}]},
    {"id": 9, "domain_names": ["sso.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.70",
     "forward_port": 9000, "certificate_id": 5, "enabled": True},
    {"id": 10, "domain_names": ["dicht.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.80",
     "forward_port": 8080, "enabled": True},
]
CERTS = [{"id": 5, "expires_on": CERT, "nice_name": "*.jbogaert.be"}]
REACH = {"192.168.0.80:8080": (False, "time-out")}


@pytest.fixture(autouse=True)
def _vergeten():
    routes.forget()
    yield
    routes.forget()


NPM_IP = "192.168.0.245"


def table(probes_ok: bool = True, enabled: bool = True, via: str | None = NPM_IP) -> routes.Table:
    hosts = routes.build_hosts(HOSTS, CERTS, npm_id=1, via=via)
    probes = {}
    for where in (routes.endpoint(h, p) for h, p in routes._endpoints(hosts)):
        ok, error = REACH.get(where, (True, None)) if probes_ok else (False, "geweigerd")
        probes[where] = {"ok": ok, "error": error, "at": NOW.isoformat()}
    return routes.Table({"enabled": enabled, "hosts": hosts, "probes": probes})


# --- de tabel ------------------------------------------------------------------------------------------------------

def test_tabel_uit_npm():
    t = table()
    jelly = t.find("JELLY.jbogaert.be.")
    assert jelly == routes.Route("http", "192.168.0.27", 8096, datetime(2026, 12, 1, 10, tzinfo=timezone.utc))
    assert t.find("pve.jbogaert.be").scheme == "https"
    # Waarom het niet rechtstreeks kan.
    assert t.explain("uit.jbogaert.be")[1] == "staat uit in NPM"
    assert "proxy_pass" in t.explain("eigen.jbogaert.be")[1]
    assert t.explain("docker.jbogaert.be")[1] == "het doel (jellyfin) is geen IP-adres"
    assert "localhost" in t.explain("npm.jbogaert.be")[1]
    assert t.explain("onbekend.jbogaert.be") == (None, None, None)
    # Wildcard: alleen een naam eronder, niet het domein zelf.
    assert t.find("grafana.lab.jbogaert.be").where == "192.168.0.40:80"
    assert t.entry("lab.jbogaert.be") is None
    # Meerdere namen, locaties zoals nginx: de langste die past.
    assert t.find("app2.jbogaert.be", "/").where == "192.168.0.30:3000"
    assert t.find("app.jbogaert.be", "/api/v1").where == "192.168.0.31:4000"
    assert "het doel heeft een pad" in t.explain("app.jbogaert.be", "/api/oud/x")[1]
    # Wat de firewall tegenhoudt: naar NPM op zijn IP (zonder DNS), met het adres erbij; forward() kent het doel toch
    # (voor de firewallregel).
    route, why, blocked = t.explain("dicht.jbogaert.be", "/", "https")
    assert route == routes.Route("https", NPM_IP, 443, None, npm=True) and route.label == f"via NPM op {NPM_IP}"
    assert blocked == "192.168.0.80:8080" and "time-out" in why and "firewall" in why
    assert t.forward("dicht.jbogaert.be") == ("192.168.0.80", 8080)
    # Ook voor wat NPM zelf doet (uit, containernaam, localhost, proxy_pass): naar NPM, voor tcp en ping 443 of 80.
    for name in ("uit", "docker", "npm", "eigen"):
        assert t.find(f"{name}.jbogaert.be", "/", "http") == routes.Route("http", NPM_IP, 80, None, npm=True)
    assert t.find("pve.jbogaert.be", "/", "https").npm is False
    # Zonder het IP van NPM (of NPM niet bereikbaar): via de naam.
    assert table(via=None).explain("dicht.jbogaert.be")[0] is None
    assert table(probes_ok=False).find("jelly.jbogaert.be") is None
    # Een eigen poort in het adres: NPM luistert alleen op 80 en 443, dus via de naam.
    assert t.explain("jelly.jbogaert.be", "/", "https", 8443) == (None, "het adres heeft een eigen poort (:8443)", None)
    assert t.find("jelly.jbogaert.be", "/", "https", 443).where == "192.168.0.27:8096"
    # Nog niet geprobeerd, of alles uit.
    assert routes.Table({"hosts": t.hosts}).explain("jelly.jbogaert.be") == (None, "nog niet geprobeerd", None)
    off = table(enabled=False)
    assert off.find("jelly.jbogaert.be") is None and off.forward("jelly.jbogaert.be") is None


def test_uitleg_per_tegel():
    t = table()
    d = routes.describe
    assert d({"type": "http"}, "https://jelly.jbogaert.be/web", t) == {"direct": True, "to": "http://192.168.0.27:8096"}
    assert d({"type": "tcp"}, "https://jelly.jbogaert.be", t) == {"direct": True, "to": "192.168.0.27:8096"}
    assert d({"type": "tcp", "target": "jelly.jbogaert.be:22"}, None, t) == {"direct": True, "to": "192.168.0.27:22"}
    assert d({"type": "ping"}, "https://jelly.jbogaert.be", t) == {"direct": True, "to": "192.168.0.27"}
    assert d({"type": "http", "direct": False}, "https://jelly.jbogaert.be", t)["why"] == "uitgezet voor deze tegel"
    assert d({"type": "http"}, "https://jelly.jbogaert.be", table(enabled=False))["why"] == "uitgezet op de NPM-tegel"
    dicht = d({"type": "http"}, "https://dicht.jbogaert.be", t)
    assert dicht == {"direct": False, "npm": NPM_IP, "to": f"https://{NPM_IP}:443", "blocked": "192.168.0.80:8080",
                     "why": "192.168.0.80:8080 niet bereikbaar vanaf het dashboard (time-out), firewall?"}
    assert d({"type": "tcp"}, "https://dicht.jbogaert.be", t)["to"] == f"{NPM_IP}:443"
    assert d({"type": "tcp", "target": "dicht.jbogaert.be:22"}, None, t)["to"] == f"{NPM_IP}:22"
    assert d({"type": "ping"}, "https://dicht.jbogaert.be", t)["to"] == NPM_IP
    assert "npm" not in d({"type": "http"}, "https://dicht.jbogaert.be", table(via=None))
    assert d({"type": "http"}, "https://jelly.jbogaert.be:8443/", t) == {
        "direct": False, "why": "het adres heeft een eigen poort (:8443)", "blocked": None}
    # Niets te zeggen: een IP, een naam die NPM niet kent, een check die niet op een naam gaat.
    assert d({"type": "http"}, "http://192.168.0.27:8096", t) is None
    assert d({"type": "http"}, "https://ander.lan", t) is None
    assert d({"type": "dns"}, "https://jelly.jbogaert.be", t) is None
    assert d({"type": "api"}, "https://jelly.jbogaert.be", t) is None


# --- de checks zelf ------------------------------------------------------------------------------------------------

class Server:
    """Jellyfin, Proxmox en een SSO achter NPM, plus een login die NPM niet kent. Een vraag aan de naam zelf
    (via DNS en NPM) wordt ook opgeschreven."""

    def __init__(self):
        self.seen: list[httpx.Request] = []

    def __call__(self, req: httpx.Request) -> httpx.Response:
        self.seen.append(req)
        host, path = req.url.host, req.url.path
        if host == "192.168.0.27":
            if path == "/web":
                return httpx.Response(302, headers={"location": "/web/index.html"})
            if path == "/web/index.html":
                return httpx.Response(200, text="<title>Jellyfin</title>")
            if path == "/eigen-adres":
                # Sommige apps kennen alleen hun eigen adres.
                return httpx.Response(301, headers={"location": "http://192.168.0.27:8096/web/index.html"})
            if path == "/sso":
                return httpx.Response(302, headers={"location": "https://sso.jbogaert.be/login"})
            if path == "/extern":
                return httpx.Response(302, headers={"location": "https://login.voorbeeld.be/flow"})
            if path == "/kring":
                return httpx.Response(302, headers={"location": "/kring"})
            if path == "/post":
                return httpx.Response(303, headers={"location": "/klaar"})
            if path == "/klaar":
                return httpx.Response(200, text=req.method)
            if path == "/traag":
                raise httpx.ReadTimeout("traag", request=req)
        if host == "192.168.0.70" and path == "/login":
            return httpx.Response(200, text="SSO")
        if host == "192.168.0.245":
            return httpx.Response(200, text=f"NPM voor {req.headers['host']}")
        if host == "192.168.0.50":
            return httpx.Response(200, json={"data": {"ok": 1}})
        if host == "login.voorbeeld.be":
            return httpx.Response(200, text="login")
        return httpx.Response(599, text="via de naam")


async def test_rechtstreekse_http_check():
    s, t = Server(), table()
    clients = HttpClients(httpx.MockTransport(s))
    o = await run_check({"type": "http", "keyword": "Jellyfin"}, "https://jelly.jbogaert.be/web", clients, t)
    assert o.ok and o.status_code == 200 and o.redirected_to is None, o
    # Het certificaat van NPM: dat ziet een check op het IP niet meer.
    assert o.cert_expires == datetime(2026, 12, 1, 10, tzinfo=timezone.utc)
    first = s.seen[0]
    assert str(first.url) == "http://192.168.0.27:8096/web"
    assert first.headers["host"] == "jelly.jbogaert.be"
    assert first.headers["x-forwarded-proto"] == "https" and first.headers["x-forwarded-scheme"] == "https"
    assert {r.url.host for r in s.seen} == {"192.168.0.27"}
    await clients.aclose()


async def test_doorverwijzingen_in_namen():
    s, t = Server(), table()
    clients = HttpClients(httpx.MockTransport(s))
    # Een Location met het eigen IP en de eigen poort van de server is dezelfde naam: geen "doorverwezen".
    o = await run_check({"type": "http", "same_host": True}, "https://jelly.jbogaert.be/eigen-adres", clients, t)
    assert o.ok and o.redirected_to is None, o
    assert s.seen[-1].headers["host"] == "jelly.jbogaert.be" and s.seen[-1].headers["x-forwarded-proto"] == "https"
    # Naar een andere naam achter NPM: ook rechtstreeks, en "doorverwezen naar" klopt.
    s.seen.clear()
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/sso", clients, t)
    assert o.ok and o.redirected_to == "sso.jbogaert.be", o
    assert str(s.seen[-1].url) == "http://192.168.0.70:9000/login" and s.seen[-1].headers["host"] == "sso.jbogaert.be"
    o = await run_check({"type": "http", "same_host": True}, "https://jelly.jbogaert.be/sso", clients, t)
    assert not o.ok and "sso.jbogaert.be" in o.error
    # Naar een naam die NPM niet kent: vanaf daar zoals vroeger, via de naam.
    s.seen.clear()
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/extern", clients, t)
    assert o.ok and o.redirected_to == "login.voorbeeld.be" and s.seen[-1].url.host == "login.voorbeeld.be", o
    # Niet volgen: het antwoord zelf, met waar het heen zou gaan.
    o = await run_check({"type": "http", "follow_redirects": False}, "https://jelly.jbogaert.be/sso", clients, t)
    assert o.ok and o.status_code == 302 and o.redirected_to == "sso.jbogaert.be", o
    # Een kringetje is een fout, zoals bij httpx.
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/kring", clients, t)
    assert not o.ok and "redirects" in o.error
    # Na een 303 wordt het een GET zonder body.
    o = await run_check({"type": "http", "method": "POST", "body": "{}", "keyword": "GET"},
                        "https://jelly.jbogaert.be/post", clients, t)
    assert o.ok, o
    await clients.aclose()


async def test_https_doel_fouten_en_uitzonderingen():
    s, t = Server(), table()
    clients = HttpClients(httpx.MockTransport(s))
    # Een https-server erachter: zoals NPM, zonder certificaatcontrole (het eigen certificaat van Proxmox).
    o = await run_check({"type": "http"}, "https://pve.jbogaert.be/api2/json/version", clients, t)
    assert o.ok and str(s.seen[-1].url) == "https://192.168.0.50:8006/api2/json/version", o
    assert clients._clients.keys() == {True}
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/traag", clients, t)
    assert not o.ok and o.error == "Time-out (rechtstreeks naar 192.168.0.27:8096)"
    # Via de naam: per tegel uitgezet, een eigen poort, of NPM kent de naam niet.
    for check, url in (({"type": "http", "direct": False}, "https://jelly.jbogaert.be/web"),
                       ({"type": "http"}, "https://jelly.jbogaert.be:8443/"),
                       ({"type": "http"}, "https://onbekend.jbogaert.be/")):
        o = await run_check(check, url, clients, t)
        assert o.status_code == 599 and s.seen[-1].url.host == httpx.URL(url).host, (check, url)
    # De server onbereikbaar: naar NPM op zijn IP, met de naam in Host en SNI, het certificaat gecontroleerd zoals
    # vroeger, geen X-Forwarded (dat doet NPM) en geen verbinding die bij een andere naam hoort.
    o = await run_check({"type": "http", "keyword": "dicht.jbogaert.be"}, "https://dicht.jbogaert.be/", clients, t)
    req = s.seen[-1]
    assert o.ok and str(req.url) == f"https://{NPM_IP}/", o
    assert req.headers["host"] == "dicht.jbogaert.be" and req.extensions["sni_hostname"] == "dicht.jbogaert.be"
    assert req.headers["connection"] == "close" and "x-forwarded-proto" not in req.headers
    assert o.cert_expires is None  # dicht.jbogaert.be heeft in NPM geen certificaat, en de test geen TLS
    assert clients._clients.keys() == {True, False}
    o = await run_check({"type": "http"}, "http://uit.jbogaert.be/", clients, t)
    assert o.ok and str(s.seen[-1].url) == f"http://{NPM_IP}/" and "sni_hostname" not in s.seen[-1].extensions
    # Zonder tabel (bv. een test of de knop "probeer"): zoals vroeger.
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/web", clients)
    assert o.status_code == 599
    await clients.aclose()


async def test_tcp_en_ping_rechtstreeks(monkeypatch):
    seen = []

    async def tcp(target, timeout=5):
        seen.append(("tcp", target))
        return checks.Outcome(True, 1.0)

    async def ping(target):
        seen.append(("ping", target))
        return checks.Outcome(True, 1.0)
    monkeypatch.setattr(checks, "check_tcp", tcp)
    monkeypatch.setattr(checks, "check_ping", ping)
    t = table()
    await run_check({"type": "tcp"}, "https://jelly.jbogaert.be", None, t)
    await run_check({"type": "tcp", "target": "jelly.jbogaert.be:22"}, None, None, t)
    await run_check({"type": "ping"}, "https://jelly.jbogaert.be", None, t)
    await run_check({"type": "ping", "direct": False}, "https://jelly.jbogaert.be", None, t)
    await run_check({"type": "tcp", "target": "jelly.jbogaert.be:443"}, None, None, t)
    await run_check({"type": "tcp"}, "https://dicht.jbogaert.be", None, t)
    await run_check({"type": "tcp", "target": "dicht.jbogaert.be:22"}, None, None, t)
    await run_check({"type": "ping"}, "https://dicht.jbogaert.be", None, t)
    await run_check({"type": "tcp"}, "https://dicht.jbogaert.be", None, table(via=None))
    assert seen == [("tcp", "192.168.0.27:8096"), ("tcp", "192.168.0.27:22"), ("ping", "192.168.0.27"),
                    ("ping", "jelly.jbogaert.be"), ("tcp", "192.168.0.27:8096"), ("tcp", f"{NPM_IP}:443"),
                    ("tcp", f"{NPM_IP}:22"), ("ping", NPM_IP), ("tcp", "dicht.jbogaert.be:443")]


# --- vernieuwen, de API en de rest ---------------------------------------------------------------------------------

class Npm:
    def __init__(self):
        self.down = False
        self.hosts = HOSTS

    def __call__(self, req: httpx.Request) -> httpx.Response:
        if self.down:
            return httpx.Response(502, text="bad gateway")
        if req.url.path == "/api/tokens":
            return httpx.Response(200, json={"token": "jwt"})
        if req.url.path == "/api/nginx/proxy-hosts":
            return httpx.Response(200, json=self.hosts)
        if req.url.path == "/api/nginx/certificates":
            return httpx.Response(200, json=CERTS)
        return httpx.Response(404)


async def _npm_tile(c, g, check=None) -> int:
    r = await c.post("/api/services", json={"group_id": g, "name": "NPM", "url": "http://192.168.0.245:81",
                                            "type": "npm", "secrets": {"username": "a@b.c", "password": "p"},
                                            "check": check or {}})
    assert r.status_code == 201, r.text
    return r.json()["id"]


async def _tile(c, g, name, url, check) -> int:
    r = await c.post("/api/services", json={"group_id": g, "name": name, "url": url, "check": check})
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture
def probes(monkeypatch):
    calls = []

    async def probe(where):
        calls.append(routes.endpoint(*where))
        return REACH.get(routes.endpoint(*where), (True, None))
    monkeypatch.setattr(routes, "_probe", probe)
    npm_integration._tokens.clear()
    return calls


async def test_vernieuwen(authed, probes):
    g = await _group(authed)
    nid = await _npm_tile(authed, g)
    npm = Npm()
    clients = HttpClients(httpx.MockTransport(npm))
    agen, db = await _db()
    v = await routes.refresh(db, clients, now=NOW)
    await db.commit()
    assert v["hosts"]["jelly.jbogaert.be"]["npm"] == nid and v["hosts"]["jelly.jbogaert.be"]["via"] == NPM_IP
    assert v["errors"] == {}
    assert v["probes"]["192.168.0.27:8096"]["ok"] and not v["probes"]["192.168.0.80:8080"]["ok"]
    # Niet geprobeerd: wat toch niet rechtstreeks kan (uit, proxy_pass, containernaam, localhost, een pad).
    assert set(probes) == {"192.168.0.27:8096", "192.168.0.50:8006", "192.168.0.40:80", "192.168.0.30:3000",
                           "192.168.0.31:4000", "192.168.0.70:9000", "192.168.0.80:8080", f"{NPM_IP}:443",
                           f"{NPM_IP}:80"}
    # De checks lezen dezelfde tabel uit het geheugen.
    assert (await routes.table(None)).find("jelly.jbogaert.be").where == "192.168.0.27:8096"

    # Volgende ronde: alleen wat niet lukte; na een uur alles opnieuw; met de knop alles meteen.
    probes.clear()
    await routes.refresh(db, clients, now=NOW + timedelta(minutes=5))
    assert probes == ["192.168.0.80:8080"]
    probes.clear()
    await routes.refresh(db, clients, now=NOW + timedelta(minutes=70))
    assert len(probes) == 9
    probes.clear()
    await routes.refresh(db, clients, now=NOW + timedelta(minutes=71), force_probe=True)
    assert len(probes) == 9

    # NPM even weg: de routes blijven, met de fout erbij.
    npm.down = True
    npm_integration._tokens.clear()
    v = await routes.refresh(db, clients, now=NOW + timedelta(minutes=75))
    assert "jelly.jbogaert.be" in v["hosts"] and v["errors"][str(nid)]
    # Een host weg uit NPM: weg uit de tabel, en zijn proef ook.
    npm.down = False
    npm.hosts = [h for h in HOSTS if h["id"] != 10]
    v = await routes.refresh(db, clients, now=NOW + timedelta(minutes=80))
    assert "dicht.jbogaert.be" not in v["hosts"] and "192.168.0.80:8080" not in v["probes"]
    await agen.aclose()
    await clients.aclose()


async def test_api_overzicht_aan_uit_en_checklist(authed, probes, monkeypatch):
    g = await _group(authed)
    nid = await _npm_tile(authed, g)
    jelly = await _tile(authed, g, "Jellyfin", "https://jelly.jbogaert.be", {"type": "http"})
    await _tile(authed, g, "Dicht", "https://dicht.jbogaert.be", {"type": "http"})
    await _tile(authed, g, "Eigen", "https://eigen.jbogaert.be", {"type": "http", "direct": False})
    await _tile(authed, g, "Ander", "https://ander.lan", {"type": "http"})
    monkeypatch.setattr(integrations_router, "clients", HttpClients(httpx.MockTransport(Npm())))
    monkeypatch.setattr(npmroutes, "_last_refresh", 0.0)

    r = await authed.get("/api/npm/routes")
    assert r.json()["at"] is None and r.json()["enabled"]
    r = await authed.post("/api/npm/routes/refresh")
    assert r.status_code == 200, r.text
    o = r.json()
    rows = {x["name"]: x for x in o["rows"]}
    assert rows["Jellyfin"] == {"service_id": jelly, "name": "Jellyfin", "host": "jelly.jbogaert.be", "direct": True,
                                "to": "http://192.168.0.27:8096"}
    assert rows["Dicht"]["blocked"] == "192.168.0.80:8080" and rows["Dicht"]["npm"] == NPM_IP
    assert rows["Eigen"]["why"] == "uitgezet voor deze tegel" and "npm" not in rows["Eigen"]
    assert "Ander" not in rows and o["counts"] == {"direct": 1, "npm": 1, "naam": 1}
    assert o["blocked"] == [{"endpoint": "192.168.0.80:8080", "tiles": ["Dicht"]}]
    assert (await authed.post("/api/npm/routes/refresh")).status_code == 429

    # Het mini dashboard van de tegel zegt hoe de check loopt.
    h = (await authed.get(f"/api/services/{jelly}/history?range=24h")).json()
    assert h["route"] == {"direct": True, "to": "http://192.168.0.27:8096"}

    # De checklist: de firewall houdt een server tegen, en NPM zelf heeft geen check.
    rows = {x["key"]: x for g_ in (await authed.get("/api/attention/setup")).json()["groups"] for x in g_["rows"]}
    row = rows["monitoring:rechtstreeks"]
    assert row["state"] == "half" and row["fix"] == {"window": "net", "tab": "firewall"}, row
    assert any("192.168.0.80:8080" in t for t in row["todo"]) and any("NPM-tegel" in t for t in row["todo"])
    assert row["text"] == "1 check rechtstreeks naar de server, 1 via NPM zonder DNS, 1 via de naam.", row

    # De firewallregels: de check gaat naar de server, niet meer naar NPM.
    agen, db = await _db()
    svcs = list((await db.execute(select(Service))).scalars())
    rt = await db.get(AppState, routes.KEY)
    used = ports.uses(svcs, [], [], routes.Table(rt.value))
    assert ("192.168.0.27", "tcp", 8096, "Jellyfin (check, rechtstreeks)") in used
    assert ("192.168.0.80", "tcp", 8080, "Dicht (check, rechtstreeks)") in used
    assert ("eigen.jbogaert.be", "tcp", 443, "Eigen (check)") in used
    assert ("192.168.0.245", "tcp", 81, "NPM (npm)") in used

    # Alles uit op de NPM-tegel: alles via de naam, en dat staat in het auditlog.
    r = await authed.put("/api/npm/routes", json={"enabled": False})
    assert r.status_code == 200 and not r.json()["enabled"]
    assert {x["why"] for x in r.json()["rows"]} == {"uitgezet op de NPM-tegel", "uitgezet voor deze tegel"}
    assert "npm_routes" in [a.action for a in (await db.execute(select(AuditLog))).scalars()]
    assert routes._cache is None  # de checks lezen het meteen opnieuw
    rows = {x["key"]: x for g_ in (await authed.get("/api/attention/setup")).json()["groups"] for x in g_["rows"]}
    assert rows["monitoring:rechtstreeks"]["state"] == "none" and rows["monitoring:rechtstreeks"]["optional"]
    # Een vernieuwing zet het niet stilletjes weer aan.
    monkeypatch.setattr(npmroutes, "_last_refresh", 0.0)
    assert not (await authed.post("/api/npm/routes/refresh")).json()["enabled"]
    await agen.aclose()
    assert nid


async def test_worker_check_gebruikt_de_tabel(authed, probes):
    """check_service (de worker) leest de tabel uit de database: een check op de naam gaat rechtstreeks."""
    g = await _group(authed)
    await _npm_tile(authed, g)
    agen, db = await _db()
    await routes.refresh(db, HttpClients(httpx.MockTransport(Npm())), now=NOW)
    await db.commit()
    routes.forget()
    s = Server()
    clients = HttpClients(httpx.MockTransport(s))
    maker = _Maker()
    o = await check_service(maker, 0, {"type": "http"}, "https://jelly.jbogaert.be/web/index.html", clients)
    assert o.ok and s.seen[-1].url.host == "192.168.0.27", o
    await agen.aclose()
    await clients.aclose()


class _Maker:
    """Zoals async_sessionmaker: een nieuwe sessie op de testdatabase."""

    def __call__(self):
        from app.db import get_db
        from app.main import app
        agen = app.dependency_overrides[get_db]()

        class Ctx:
            async def __aenter__(self_):
                return await agen.__anext__()

            async def __aexit__(self_, *a):
                await agen.aclose()
        return Ctx()
