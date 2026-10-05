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
     "forward_port": 8080, "certificate_id": 5, "enabled": True},
    {"id": 11, "domain_names": ["geencert.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.90",
     "forward_port": 80, "certificate_id": 0, "enabled": True},
    {"id": 12, "domain_names": ["kapot.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.91",
     "forward_port": 80, "enabled": True, "meta": {"nginx_online": False}},
    {"id": 13, "domain_names": ["login.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.92",
     "forward_port": 80, "enabled": True, "advanced_config": "auth_request /outpost.goauthentik.io/auth/nginx;"},
    {"id": 14, "domain_names": ["regex.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.93",
     "forward_port": 80, "enabled": True,
     "locations": [{"path": "~ ^/api", "forward_scheme": "http", "forward_host": "192.168.0.94", "forward_port": 80}]},
    {"id": 15, "domain_names": ["grafana.lab.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.41",
     "forward_port": 3000, "certificate_id": 6, "enabled": True},
    {"id": 16, "domain_names": ["lijst.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.95",
     "forward_port": 80, "certificate_id": 5, "access_list_id": 2, "enabled": True},
    {"id": 17, "domain_names": ["forced.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.27",
     "forward_port": 8096, "certificate_id": 5, "ssl_forced": True, "enabled": True},
    {"id": 18, "domain_names": ["oudcert.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.27",
     "forward_port": 8096, "certificate_id": 7, "enabled": True},
]
CERTS = [{"id": 5, "expires_on": CERT, "nice_name": "*.jbogaert.be", "domain_names": ["*.jbogaert.be", "jbogaert.be"]},
         {"id": 6, "expires_on": CERT, "domain_names": ["*.lab.jbogaert.be"]},
         {"id": 7, "expires_on": "2026-01-01 00:00:00", "domain_names": ["oudcert.jbogaert.be"]}]
REDIRECTS = [{"id": 1, "domain_names": ["oud.lab.jbogaert.be"], "enabled": True}]
REACH = {"192.168.0.80:8080": (False, "time-out")}


@pytest.fixture(autouse=True)
def _vergeten():
    routes.forget()
    yield
    routes.forget()


NPM_IP = "192.168.0.245"


def table(probes_ok: bool = True, enabled: bool = True, via: str | None = NPM_IP, certs=CERTS) -> routes.Table:
    hosts = routes.build_hosts(HOSTS, certs, npm_id=1, via=via, others=[(REDIRECTS, "NPM stuurt deze naam door")])
    probes = {}
    for where in (routes.endpoint(h, p) for h, p in routes._endpoints(hosts)):
        ok, error = REACH.get(where, (True, None)) if probes_ok else (False, "geweigerd")
        probes[where] = {"ok": ok, "error": error, "at": NOW.isoformat()}
    return routes.Table({"hosts": hosts, "probes": probes}, enabled)


# --- de tabel ------------------------------------------------------------------------------------------------------

def test_tabel_uit_npm():
    t = table()
    jelly = t.find("JELLY.jbogaert.be.", "/", "https")
    assert jelly == routes.Route("http", "192.168.0.27", 8096, datetime(2026, 12, 1, 10, tzinfo=timezone.utc))
    assert t.find("pve.jbogaert.be").scheme == "https"
    # Waarom het niet rechtstreeks kan.
    assert t.explain("uit.jbogaert.be")[1] == "staat uit in NPM"
    assert t.explain("eigen.jbogaert.be")[1] == "eigen nginx-configuratie in NPM"
    assert t.explain("login.jbogaert.be")[1] == "eigen nginx-configuratie in NPM"  # forward auth (Authentik)
    assert routes._own_config({"advanced_config": "include /snippets/authelia.conf;"})
    assert not routes._own_config({"advanced_config": "# niets\n  \n"})
    assert t.explain("kapot.jbogaert.be")[1] == "offline in NPM (fout in de configuratie)"
    assert t.explain("regex.jbogaert.be")[1] == "aparte locatie met een regex of = in NPM"
    assert t.explain("lijst.jbogaert.be")[1] == "toegangslijst in NPM"
    # NPM stuurt http door naar https: de eerste stap via NPM, https daarna rechtstreeks.
    assert t.explain("forced.jbogaert.be", "/", "http")[:2] == (routes.Route("http", NPM_IP, 80, datetime(
        2026, 12, 1, 10, tzinfo=timezone.utc), npm=True), "NPM stuurt http door naar https")
    assert t.find("forced.jbogaert.be", "/", "https").where == "192.168.0.27:8096"
    assert t.explain("docker.jbogaert.be")[1] == "het doel (jellyfin) is geen IP-adres"
    assert "localhost" in t.explain("npm.jbogaert.be")[1]
    assert t.explain("onbekend.jbogaert.be") == (None, None, None, None)
    # Wildcard: alleen een naam eronder, niet het domein zelf; een exacte naam (ook een redirection host) gaat voor.
    assert t.find("x.lab.jbogaert.be").where == "192.168.0.40:80"
    assert t.find("grafana.lab.jbogaert.be").where == "192.168.0.41:3000"
    assert t.explain("oud.lab.jbogaert.be")[:2] == (routes.Route("https", NPM_IP, 443, None, npm=True),
                                                     "NPM stuurt deze naam door")
    assert t.entry("lab.jbogaert.be") is None
    # https: alleen rechtstreeks met een certificaat in NPM dat op de naam past (een wildcard telt voor één label).
    assert t.explain("geencert.jbogaert.be", "/", "https")[1] == "NPM heeft voor deze naam geen passend certificaat"
    assert t.find("geencert.jbogaert.be", "/", "http").npm is False
    assert t.find("x.lab.jbogaert.be", "/", "https").npm is True  # *.lab heeft geen certificaat
    assert t.find("grafana.lab.jbogaert.be", "/", "https").npm is False  # wel: *.lab.jbogaert.be
    assert routes._covers(["*.jbogaert.be"], "jelly.jbogaert.be") and not routes._covers(["*.jbogaert.be"], "a.b.jbogaert.be")
    # Certificaten niet op te halen (rechten in NPM): https via NPM, dat het echte certificaat toont; http rechtstreeks.
    assert table(certs=None).explain("grafana.lab.jbogaert.be", "/", "https")[:2] == (
        routes.Route("https", NPM_IP, 443, None, npm=True), "de vervaldatum van het certificaat is niet te lezen in NPM")
    assert table(certs=None).find("grafana.lab.jbogaert.be", "/", "http").npm is False
    # Meerdere namen, locaties zoals nginx: de langste die past.
    assert t.find("app2.jbogaert.be", "/").where == "192.168.0.30:3000"
    assert t.find("app.jbogaert.be", "/api/v1").where == "192.168.0.31:4000"
    assert "het doel heeft een pad" in t.explain("app.jbogaert.be", "/api/oud/x")[1]
    # Wat de firewall tegenhoudt: naar NPM op zijn IP (zonder DNS), met het adres erbij en de server voor de
    # firewallregel.
    route, why, blocked, fw = t.explain("dicht.jbogaert.be", "/", "https")
    assert route == routes.Route("https", NPM_IP, 443, datetime(2026, 12, 1, 10, tzinfo=timezone.utc), npm=True)
    assert route.label == f"via NPM op {NPM_IP}" and fw == ("192.168.0.80", 8080)
    assert blocked == "192.168.0.80:8080" and "time-out" in why and "firewall" in why
    # Ook voor wat NPM zelf doet (uit, containernaam, localhost, eigen configuratie): naar NPM.
    for name in ("uit", "docker", "npm", "eigen"):
        assert t.find(f"{name}.jbogaert.be", "/", "http") == routes.Route("http", NPM_IP, 80, None, npm=True)
    # Zonder het IP van NPM (of NPM niet bereikbaar): via de naam.
    assert table(via=None).explain("dicht.jbogaert.be")[0] is None
    assert table(probes_ok=False).find("jelly.jbogaert.be") is None
    assert table(probes_ok=False).explain("jelly.jbogaert.be")[1] == (
        "192.168.0.27:8096 weigert de verbinding: draait de service (of weigert een firewall)?")
    # Een eigen poort in het adres: NPM luistert alleen op 80 en 443, dus via de naam.
    assert t.explain("jelly.jbogaert.be", "/", "https", 8443) == (
        None, "het adres heeft een eigen poort (:8443)", None, None)
    assert t.find("jelly.jbogaert.be", "/", "https", 443).where == "192.168.0.27:8096"
    # Nog niet geprobeerd, of alles uit.
    assert routes.Table({"hosts": t.hosts}).explain("jelly.jbogaert.be")[:3] == (None, "nog niet geprobeerd", None)
    off = table(enabled=False)
    assert off.find("jelly.jbogaert.be") is None and off.npm_for("jelly.jbogaert.be") is None


def test_uitleg_per_tegel():
    t = table()
    d = routes.describe
    assert d({"type": "http"}, "https://jelly.jbogaert.be/web", t) == {"direct": True, "to": "http://192.168.0.27:8096"}
    # tcp en ping: naar NPM op zijn IP, zoals de naam altijd deed (alleen zonder DNS). Rechtstreeks zou een tcp-check
    # down gaan als de server uitvalt, en na de volgende ronde weer "up" via NPM.
    for target, to in (("jelly.jbogaert.be:443", f"{NPM_IP}:443"), ("jelly.jbogaert.be:22", f"{NPM_IP}:22")):
        assert d({"type": "tcp", "target": target}, None, t) == {
            "direct": False, "npm": NPM_IP, "to": to, "blocked": None,
            "why": "een tcp-check op een naam test NPM, zoals altijd"}
    assert d({"type": "tcp"}, "https://jelly.jbogaert.be", t)["to"] == f"{NPM_IP}:443"
    assert d({"type": "ping"}, "https://jelly.jbogaert.be", t)["to"] == NPM_IP
    assert d({"type": "ping"}, "https://jelly.jbogaert.be", table(probes_ok=False)) == {
        "direct": False, "why": "NPM niet bereikbaar vanaf het dashboard", "blocked": None}
    assert d({"type": "http", "direct": False}, "https://jelly.jbogaert.be", t)["why"] == "uitgezet voor deze tegel"
    assert d({"type": "http"}, "https://jelly.jbogaert.be", table(enabled=False))["why"] == "uitgezet op de NPM-tegel"
    dicht = d({"type": "http"}, "https://dicht.jbogaert.be", t)
    assert dicht == {"direct": False, "npm": NPM_IP, "to": f"https://{NPM_IP}:443", "blocked": "192.168.0.80:8080",
                     "why": "192.168.0.80:8080 niet bereikbaar vanaf het dashboard (time-out), firewall?"}
    assert d({"type": "tcp"}, "https://dicht.jbogaert.be", t)["to"] == f"{NPM_IP}:443"
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
                return httpx.Response(200, text=f"{req.method}:{len(req.content)}")
            if path == "/traag":
                raise httpx.ReadTimeout("traag", request=req)
            if path == "/verhuisd":
                raise httpx.ConnectError("[Errno 113] No route to host", request=req)
            if path == "/zet":
                return httpx.Response(302, headers=[("location", "/lees"), ("set-cookie", "sess=abc; Path=/; HttpOnly"),
                                                    ("set-cookie", "wijd=1; Domain=.jbogaert.be"),
                                                    ("set-cookie", "vreemd=1; Domain=ander.be")])
            if path == "/zet2":
                return httpx.Response(302, headers=[
                    ("location", "/lees"), ("set-cookie", "p=1; Path=/; Secure; HttpOnly; Partitioned"),
                    ("set-cookie", "oud=1; Path=/; expires=Thursday, 01-Jan-2099 00:00:00 GMT"),
                    ("set-cookie", "x=deleted; expires=Thu, 01-Jan-1970 00:00:01 GMT")])
            if path == "/lees":
                return httpx.Response(200, text=f"cookie:{req.headers.get('cookie', '')}")
        if host == "192.168.0.70" and path == "/login":
            return httpx.Response(200, text="SSO")
        if host == "192.168.0.245":
            if req.url.scheme == "http" and req.headers["host"] == "forced.jbogaert.be":
                return httpx.Response(301, headers={"location": f"https://forced.jbogaert.be{path}"})
            return httpx.Response(200, text=f"NPM voor {req.headers['host']}",
                                  headers={"set-cookie": f"npm_{req.headers['host'].split('.')[0]}=1"})
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
    # Een Location met het eigen IP van de server (NPM past Location niet aan): zoals vroeger naar dat IP, en dat is
    # "doorverwezen" (ook in de browser kom je daar terecht).
    o = await run_check({"type": "http", "same_host": True}, "https://jelly.jbogaert.be/eigen-adres", clients, t)
    assert not o.ok and o.redirected_to == "192.168.0.27", o
    assert str(s.seen[-1].url) == "http://192.168.0.27:8096/web/index.html"
    assert (await run_check({"type": "http"}, "https://jelly.jbogaert.be/eigen-adres", clients, t)).ok
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
    o = await run_check({"type": "http", "method": "POST", "body": "{}", "keyword": "GET:0"},
                        "https://jelly.jbogaert.be/post", clients, t)
    assert o.ok, o
    # NPM stuurt http door naar https: eerst NPM (zonder DNS), dan rechtstreeks met het certificaat uit NPM.
    s.seen.clear()
    o = await run_check({"type": "http"}, "http://forced.jbogaert.be/web/index.html", clients, t)
    assert o.ok and o.cert_expires == datetime(2026, 12, 1, 10, tzinfo=timezone.utc), o
    assert [str(r.url) for r in s.seen] == [f"http://{NPM_IP}/web/index.html", "http://192.168.0.27:8096/web/index.html"]
    assert s.seen[-1].headers["x-forwarded-proto"] == "https"
    await clients.aclose()


async def test_cookies_blijven_bij_de_check():
    """Een cookie geldt binnen één check (zet het en verwijs door), maar wordt niet bewaard: op een IP zou één jar de
    cookies van alle apps achter NPM, of op dezelfde server, met elkaar delen."""
    s, t = Server(), table()
    clients = HttpClients(httpx.MockTransport(s))
    o = await run_check({"type": "http", "keyword": "cookie:sess=abc; wijd=1"}, "https://jelly.jbogaert.be/zet",
                        clients, t)
    assert o.ok and str(s.seen[-1].url) == "http://192.168.0.27:8096/lees", o
    assert "vreemd" not in s.seen[-1].headers["cookie"]  # een cookie voor een ander domein telt niet
    # Zoals een gewone cookiejar: Partitioned, een oude datumvorm, en een verlopen cookie (= wissen).
    o = await run_check({"type": "http", "keyword": "cookie:p=1; oud=1"}, "https://jelly.jbogaert.be/zet2", clients, t)
    assert o.ok and "x=" not in s.seen[-1].headers["cookie"], (o, s.seen[-1].headers["cookie"])
    for url in ("https://jelly.jbogaert.be/lees", "https://forced.jbogaert.be/lees"):  # zelfde server, andere naam
        o = await run_check({"type": "http"}, url, clients, t)
        assert o.ok and str(s.seen[-1].url) == "http://192.168.0.27:8096/lees" and "cookie" not in s.seen[-1].headers
    for name in ("dicht", "uit"):  # via NPM op zijn IP
        o = await run_check({"type": "http"}, f"http://{name}.jbogaert.be/", clients, t)
        assert o.ok and s.seen[-1].url.host == NPM_IP and "cookie" not in s.seen[-1].headers, name
    # Zoals httpx: een eigen Cookie-header (van voor die geweigerd werd) alleen bij de eerste vraag.
    o = await run_check({"type": "http", "headers": {"Cookie": "mijn=1"}, "keyword": "cookie:sess=abc; wijd=1"},
                        "https://jelly.jbogaert.be/zet", clients, t)
    assert o.ok and s.seen[-2].headers["cookie"] == "mijn=1", o
    await clients.aclose()


async def test_namen_doelen_en_headers():
    """IDN en een punt op het einde zoals nginx ze doorgeeft, IPv6 en Docker-netwerken als doel, en Authorization
    (van een oude check) niet naar een andere host na een doorverwijzing, zoals httpx."""
    hosts = routes.build_hosts([
        {"id": 1, "domain_names": ["bücher.jbogaert.be"], "forward_scheme": "http", "forward_host": "192.168.0.27",
         "forward_port": 8096, "certificate_id": 5, "enabled": True},
        {"id": 2, "domain_names": ["v6.jbogaert.be"], "forward_scheme": "http", "forward_host": "[fd00::5]",
         "forward_port": 8096, "enabled": True},
        {"id": 3, "domain_names": ["ha.jbogaert.be"], "forward_scheme": "http", "forward_host": "172.17.0.1",
         "forward_port": 8123, "enabled": True},
        *HOSTS], CERTS, npm_id=1, via=NPM_IP)
    t = routes.Table({"hosts": hosts, "probes": {routes.endpoint(h, p): {"ok": True} for h, p in
                                                 routes._endpoints(hosts)}})
    assert t.find("xn--bcher-kva.jbogaert.be", "/", "https").where == "192.168.0.27:8096"
    assert t.find("BÜCHER.jbogaert.be.", "/", "https").where == "192.168.0.27:8096"
    v6 = t.find("v6.jbogaert.be")
    assert v6.where == "[fd00::5]:8096" and str(v6.url(httpx.URL("http://v6.jbogaert.be/x"))) == "http://[fd00::5]:8096/x"
    assert t.explain("ha.jbogaert.be")[1] == "het doel (172.17.0.1) is een Docker-netwerk bij NPM"
    assert routes._why_not(("http", "172.17.0.1", 80), via="172.20.0.2") is None  # NPM zelf in zo'n netwerk
    s = Server()
    clients = HttpClients(httpx.MockTransport(s))
    o = await run_check({"type": "http"}, "https://BÜCHER.jbogaert.be./web/index.html", clients, t)
    assert o.ok and s.seen[-1].headers["host"] == "xn--bcher-kva.jbogaert.be", o
    assert s.seen[-1].headers["x-forwarded-host"] == "xn--bcher-kva.jbogaert.be"
    old = {"type": "http", "headers": {"Authorization": "Bearer x"}}
    await run_check(old, "https://jelly.jbogaert.be/web", clients, t)
    assert [r.headers.get("authorization") for r in s.seen[-2:]] == ["Bearer x", "Bearer x"]
    await run_check(old, "https://jelly.jbogaert.be/extern", clients, t)
    assert [r.headers.get("authorization") for r in s.seen[-2:]] == ["Bearer x", None]
    assert s.seen[-1].url.host == "login.voorbeeld.be"
    await clients.aclose()


async def test_https_doel_fouten_en_uitzonderingen():
    s, t = Server(), table()
    clients = HttpClients(httpx.MockTransport(s))
    # Een https-server erachter: zoals NPM, zonder certificaatcontrole (het eigen certificaat van Proxmox).
    o = await run_check({"type": "http"}, "https://pve.jbogaert.be/api2/json/version", clients, t)
    assert o.ok and str(s.seen[-1].url) == "https://192.168.0.50:8006/api2/json/version", o
    assert clients._bare.keys() == {True} and not clients._clients
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/traag", clients, t)
    assert not o.ok and o.error == "Time-out (rechtstreeks naar 192.168.0.27:8096)"
    # Een verlopen certificaat in NPM: via de naam weigert de browser dat, dus ook hier down (tenzij genegeerd), ook
    # als die naam maar een tussenstap is.
    o = await run_check({"type": "http"}, "https://oudcert.jbogaert.be/web/index.html", clients, t)
    assert not o.ok and o.error == "Certificaat verlopen op 01/01/2026 (volgens NPM)", o
    n = len(s.seen)
    o = await run_check({"type": "http"}, "https://oudcert.jbogaert.be/sso", clients, t)
    assert not o.ok and o.error == "Certificaat verlopen op 01/01/2026 (volgens NPM)" and len(s.seen) == n, o
    assert (await run_check({"type": "http", "insecure": True}, "https://oudcert.jbogaert.be/web/index.html",
                            clients, t)).ok
    # Via de naam: per tegel uitgezet, een eigen poort, of NPM kent de naam niet.
    for check, url in (({"type": "http", "direct": False}, "https://jelly.jbogaert.be/web"),
                       ({"type": "http"}, "https://jelly.jbogaert.be:8443/"),
                       ({"type": "http"}, "https://onbekend.jbogaert.be/")):
        o = await run_check(check, url, clients, t)
        assert o.status_code == 599 and s.seen[-1].url.host == httpx.URL(url).host, (check, url)
    # De server onbereikbaar: naar NPM op zijn IP, met de naam in Host en SNI, het certificaat gecontroleerd zoals
    # vroeger, geen X-Forwarded (dat doet NPM) en geen verbinding die bij een andere naam hoort.
    asked = []
    bare = clients.bare
    clients.bare = lambda insecure: asked.append(insecure) or bare(insecure)
    o = await run_check({"type": "http", "keyword": "dicht.jbogaert.be"}, "https://dicht.jbogaert.be/", clients, t)
    clients.bare = bare
    assert asked == [False]  # het certificaat van NPM wordt gecontroleerd, zoals vroeger
    req = s.seen[-1]
    assert o.ok and str(req.url) == f"https://{NPM_IP}/", o
    assert req.headers["host"] == "dicht.jbogaert.be" and req.extensions["sni_hostname"] == "dicht.jbogaert.be"
    assert req.headers["connection"] == "close" and "x-forwarded-proto" not in req.headers
    # Via NPM het certificaat dat NPM toont; zonder TLS (in de test) de vervaldatum uit NPM.
    assert o.cert_expires == datetime(2026, 12, 1, 10, tzinfo=timezone.utc)
    o = await run_check({"type": "http"}, "http://uit.jbogaert.be/", clients, t)
    assert o.ok and str(s.seen[-1].url) == f"http://{NPM_IP}/" and "sni_hostname" not in s.seen[-1].extensions
    # De server niet te bereiken (verhuisd, de route nog van voor de wijziging in NPM): via NPM, zoals de link.
    routes._suspect.clear()
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/verhuisd", clients, t)
    assert o.ok and s.seen[-1].url.host == NPM_IP and s.seen[-2].url.host == "192.168.0.27", o
    assert routes._suspect == {"192.168.0.27:8096"}
    # Geen NPM om op terug te vallen: een fout, met waarheen, en de volgende ronde probeert de server opnieuw.
    routes._suspect.clear()
    o = await run_check({"type": "http"}, "https://jelly.jbogaert.be/verhuisd", clients,
                        table(via=None))
    assert not o.ok and o.error.endswith("(rechtstreeks naar 192.168.0.27:8096)"), o
    assert routes._suspect == {"192.168.0.27:8096"}
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
    # Naar NPM op zijn IP, zoals de naam vroeger (zonder DNS); zonder IP van NPM via de naam.
    assert seen == [("tcp", f"{NPM_IP}:443"), ("tcp", f"{NPM_IP}:22"), ("ping", NPM_IP),
                    ("ping", "jelly.jbogaert.be"), ("tcp", f"{NPM_IP}:443"), ("tcp", f"{NPM_IP}:443"),
                    ("tcp", f"{NPM_IP}:22"), ("ping", NPM_IP), ("tcp", "dicht.jbogaert.be:443")]


def test_firewall_zoals_de_check():
    """net → firewall: precies de server en poort die de check zal gebruiken, ook als de firewall hem nu tegenhoudt."""
    from types import SimpleNamespace as NS

    def svc(name, url, check):
        return NS(name=name, url=url, check=check, type="link", api_id=None, config={})
    used = ports.uses([svc("A", "https://jelly.jbogaert.be/web", {"type": "http"}),
                       svc("B", None, {"type": "tcp", "target": "jelly.jbogaert.be:443"}),
                       svc("C", None, {"type": "tcp", "target": "jelly.jbogaert.be:22"}),
                       svc("D", "https://jelly.jbogaert.be:8443/", {"type": "http"}),
                       svc("E", "https://dicht.jbogaert.be/", {"type": "http"}),
                       svc("F", "https://jelly.jbogaert.be", {"type": "ping"}),
                       svc("G", "https://jelly.jbogaert.be", {"type": "http", "direct": False})], [], [], table())
    assert used == [("192.168.0.27", "tcp", 8096, "A (check, rechtstreeks)"),
                    (NPM_IP, "tcp", 443, "B (check, via NPM)"),
                    (NPM_IP, "tcp", 22, "C (check, via NPM)"),
                    ("jelly.jbogaert.be", "tcp", 8443, "D (check)"),
                    ("192.168.0.80", "tcp", 8080, "E (check, rechtstreeks)"),
                    ("jelly.jbogaert.be", "icmp", None, "F (ping)"),
                    ("jelly.jbogaert.be", "tcp", 443, "G (check)"),
                    (NPM_IP, "tcp", 443, "NPM (checks zonder DNS)"), (NPM_IP, "tcp", 80, "NPM (checks zonder DNS)")]
    assert ports.uses([], [], [], table(enabled=False)) == []


# --- vernieuwen, de API en de rest ---------------------------------------------------------------------------------

class Npm:
    """NPM op 192.168.0.245; een tweede NPM (192.168.0.246) heeft alleen jelly."""

    def __init__(self):
        self.down = self.other_down = False
        self.hosts = HOSTS
        self.broken: set[str] = set()

    def __call__(self, req: httpx.Request) -> httpx.Response:
        path, other = req.url.path, req.url.host == "192.168.0.246"
        if self.down or (other and self.other_down):
            return httpx.Response(502, text="bad gateway")
        if path in self.broken:
            return httpx.Response(500, text="kapot")
        if path == "/api/tokens":
            return httpx.Response(200, json={"token": "jwt"})
        if path == "/api/nginx/proxy-hosts":
            return httpx.Response(200, json=[HOSTS[0]] if other else self.hosts)
        if path == "/api/nginx/certificates":
            return httpx.Response(200, json=CERTS)
        if path == "/api/nginx/redirection-hosts" and not other:
            return httpx.Response(200, json=REDIRECTS)
        if path == "/api/nginx/dead-hosts" and not other:
            return httpx.Response(200, json=[{"id": 1, "domain_names": ["weg.jbogaert.be"], "enabled": True}])
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
    # Namen die NPM zelf beantwoordt (redirection host, 404-host): via NPM, ook onder een wildcard.
    assert v["hosts"]["oud.lab.jbogaert.be"]["why"] == "NPM stuurt deze naam door (redirection host)"
    assert v["hosts"]["weg.jbogaert.be"]["why"] == "404-host in NPM"
    # Niet geprobeerd: wat toch niet rechtstreeks kan (uit, proxy_pass, containernaam, localhost, een pad).
    assert set(probes) == {"192.168.0.27:8096", "192.168.0.50:8006", "192.168.0.40:80", "192.168.0.30:3000",
                           "192.168.0.31:4000", "192.168.0.70:9000", "192.168.0.80:8080", f"{NPM_IP}:443",
                           f"{NPM_IP}:80", "192.168.0.41:3000", "192.168.0.90:80"}
    # De checks lezen dezelfde tabel uit het geheugen.
    assert (await routes.table(None)).find("jelly.jbogaert.be").where == "192.168.0.27:8096"

    # Volgende ronde: alleen wat niet lukte; na een uur alles opnieuw; met de knop alles meteen.
    probes.clear()
    await routes.refresh(db, clients, now=NOW + timedelta(minutes=5))
    assert probes == ["192.168.0.80:8080"]
    # Een check kon net niet bij een server die werkte: de volgende ronde opnieuw proberen.
    probes.clear()
    routes.suspect("192.168.0.27:8096")
    await routes.refresh(db, clients, now=NOW + timedelta(minutes=10))
    assert sorted(probes) == ["192.168.0.27:8096", "192.168.0.80:8080"] and not routes._suspect
    probes.clear()
    await routes.refresh(db, clients, now=NOW + timedelta(minutes=70))
    assert len(probes) == 10 and "192.168.0.27:8096" not in probes  # die is op minuut 10 opnieuw geprobeerd
    probes.clear()
    await routes.refresh(db, clients, now=NOW + timedelta(minutes=71), force_probe=True)
    assert len(probes) == 11

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

    # Twee NPM's met dezelfde naam: welke DNS kiest, weten we niet, dus via de naam.
    r = await authed.post("/api/services", json={"group_id": g, "name": "NPM 2", "url": "http://192.168.0.246:81",
                                                 "type": "npm", "secrets": {"username": "a@b.c", "password": "p"}})
    assert r.status_code == 201, r.text
    npm_integration._tokens.clear()
    v = await routes.refresh(db, clients, now=NOW + timedelta(minutes=85))
    assert v["hosts"]["jelly.jbogaert.be"]["why"] == "staat in meer dan één NPM"
    assert v["hosts"]["pve.jbogaert.be"]["why"] is None
    t = routes.Table(v)
    assert t.find("jelly.jbogaert.be") is None and t.find("pve.jbogaert.be").where == "192.168.0.50:8006"
    # De tweede NPM even weg: de naam blijft "in meer dan één NPM" (anders ging hij plots rechtstreeks).
    npm.other_down = True
    npm_integration._tokens.clear()
    v = await routes.refresh(db, clients, now=NOW + timedelta(minutes=90))
    assert v["hosts"]["jelly.jbogaert.be"]["why"] == "staat in meer dan één NPM" and list(v["errors"]) != [str(nid)]
    assert len(v["errors"]) == 1
    # Half gelukt (de certificaten niet op te halen): de vorige ronde blijft, met de fout erbij.
    before = v["hosts"]["pve.jbogaert.be"]
    npm.other_down = False
    npm.broken = {"/api/nginx/certificates"}
    v = await routes.refresh(db, clients, now=NOW + timedelta(minutes=95))
    assert v["hosts"]["pve.jbogaert.be"] == before and before["cert_names"]
    assert v["errors"][str(nid)] == "certificaten, redirection- of 404-hosts niet op te halen"
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
    assert o["blocked"] == [{"endpoint": "192.168.0.80:8080", "tiles": ["Dicht"], "refused": False}]
    assert (await authed.post("/api/npm/routes/refresh")).status_code == 429

    # Het mini dashboard van de tegel zegt hoe de check loopt.
    h = (await authed.get(f"/api/services/{jelly}/history?range=24h")).json()
    assert h["route"] == {"direct": True, "to": "http://192.168.0.27:8096"}

    # De checklist: de firewall houdt een server tegen, en NPM zelf heeft geen check.
    rows = {x["key"]: x for g_ in (await authed.get("/api/attention/setup")).json()["groups"] for x in g_["rows"]}
    row = rows["monitoring:rechtstreeks"]
    assert row["state"] == "half" and row["fix"] == {"window": "net", "tab": "firewall"}, row
    assert len(row["todo"]) == 2 and "192.168.0.80:8080" in row["todo"][0] and "OPNsense" in row["todo"][0]
    assert "heeft zelf geen check" in row["todo"][1]
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

    # Weigert de server de verbinding (hij antwoordt, niets luistert), dan is het geen firewallprobleem. En met een
    # eigen check op de NPM-tegel valt die opmerking weg.
    rt.value = {**rt.value, "probes": {**rt.value["probes"], "192.168.0.80:8080": {
        "ok": False, "error": routes.REFUSED, "at": NOW.isoformat()}}}
    (await db.get(Service, nid)).check = {"type": "http"}
    await db.commit()
    routes.forget()
    o = (await authed.get("/api/npm/routes")).json()
    assert o["blocked"] == [{"endpoint": "192.168.0.80:8080", "tiles": ["Dicht"], "refused": True}]
    why = {x["name"]: x for x in o["rows"]}["Dicht"]["why"]
    assert why == "192.168.0.80:8080 weigert de verbinding: draait de service (of weigert een firewall)?"
    rows = {x["key"]: x for g_ in (await authed.get("/api/attention/setup")).json()["groups"] for x in g_["rows"]}
    row = rows["monitoring:rechtstreeks"]
    assert row["fix"] == {"window": "detail", "service_id": nid} and len(row["todo"]) == 1, row
    assert "weigert de verbinding" in row["todo"][0] and "OPNsense" not in row["todo"][0]

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
