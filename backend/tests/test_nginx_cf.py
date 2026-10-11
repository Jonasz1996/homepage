"""De headers van Cloudflare in nginx (deploy/nginx-map.conf): alleen geloofd als NPM het verzoek van Cloudflare of
een tunnel kreeg. Draait een echte nginx met de configuratie uit deploy/, met 127.0.0.1 als NPM, voor een kleine
echo-server die de headers teruggeeft die de API zou krijgen. Zonder nginx (of zonder 127.0.0.2) overgeslagen.

Daarna wie er rechtstreeks bij mag ($homepage_blocked): NPM en de container zelf alles, het LAN alleen push,
webhooks en /api/healthz (of alles met HOMEPAGE_LAN_OPEN=1), een publiek IP niets."""

import contextlib
import http.client
import json
import shutil
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
NGINX = shutil.which("nginx") or next((p for p in ("/usr/sbin/nginx", "/usr/local/sbin/nginx") if Path(p).exists()),
                                      None)
pytestmark = pytest.mark.skipif(NGINX is None, reason="nginx niet geïnstalleerd")

NPM = "127.0.0.1"
OTHER = "127.0.0.2"  # een toestel op het LAN dat NPM overslaat
HEADERS = ("x-forwarded-for", "x-homepage-via-cf", "x-country", "x-homepage-access", "x-homepage-cf-forged")


class _Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps({"path": self.path, "headers": {k.lower(): v for k, v in self.headers.items()}}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def render(tmp: Path, port: int, api_port: int, npm: str = NPM, lan_dicht: str = "1", host: str = "127.0.0.1",
           peers: str = "") -> Path:
    """De configuratie zoals install.sh ze neerzet, met andere poorten en paden. lan_dicht: wat install.sh invult ("0"
    met HOMEPAGE_LAN_OPEN=1). peers: extra regels voor de geo $homepage_peer, om een 127.0.0.x als toestel op het LAN
    of als publiek IP te laten tellen (andere afzenders heeft een test niet)."""
    (tmp / "snippets").mkdir(parents=True, exist_ok=True)
    shutil.copy(DEPLOY / "nginx-headers.conf", tmp / "snippets" / "homepage-headers.conf")
    maps = (DEPLOY / "nginx-map.conf").read_text()
    for old, new in (("__NPM_IP_RE__", npm.replace(".", "\\.")), ("__LAN_DICHT__", lan_dicht),
                     ("    default          buiten;\n", f"    default          buiten;\n{peers}")):
        assert old in maps, old
        maps = maps.replace(old, new)
    (tmp / "homepage-map.conf").write_text(maps)
    site = (DEPLOY / "nginx.conf").read_text()
    for old, new in (("__NPM_IP__", npm), ("listen 80 default_server;", f"listen {host}:{port};"),
                     ("listen [::]:80 default_server;", ""), ("127.0.0.1:8000", f"127.0.0.1:{api_port}"),
                     ("/var/log/nginx/error.log", str(tmp / "error.log")), ("/opt/homepage/frontend/dist", str(tmp))):
        assert old in site, old
        site = site.replace(old, new)
    (tmp / "homepage.conf").write_text(site)
    temp = "\n".join(f"    {d}_temp_path {tmp / d};" for d in ("client_body", "proxy", "fastcgi", "uwsgi", "scgi"))
    main = tmp / "nginx.conf"
    main.write_text(f"""daemon off;
error_log {tmp / "error.log"};
pid {tmp / "nginx.pid"};
events {{ worker_connections 64; }}
http {{
    access_log off;
{temp}
    include homepage-map.conf;
    include homepage.conf;
}}
""")
    return main


def _bindable(*addrs: str) -> None:
    for addr in addrs:
        try:
            with socket.socket() as s:
                s.bind((addr, 0))
        except OSError:
            pytest.skip(f"{addr} niet bruikbaar als bronadres")


@contextlib.contextmanager
def _running(tmp: Path, host: str = "127.0.0.1", **kw):
    """nginx met de configuratie uit deploy/ (render) voor de echo-server; geeft de poort."""
    echo = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    port = _free_port()
    conf = render(tmp, port, echo.server_address[1], host=host, **kw)
    test = subprocess.run([NGINX, "-t", "-p", str(tmp), "-c", str(conf)], capture_output=True, text=True)
    assert test.returncode == 0, test.stderr
    proc = subprocess.Popen([NGINX, "-p", str(tmp), "-c", str(conf)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection((host, port), timeout=0.2).close()
                break
            except OSError:
                if proc.poll() is not None:
                    log = tmp / "error.log"
                    pytest.fail(f"nginx startte niet: {log.read_text() if log.exists() else ''}")
                time.sleep(0.05)
        yield port
    finally:
        proc.terminate()
        proc.wait(10)
        echo.shutdown()
        echo.server_close()


@pytest.fixture(scope="module")
def nginx(tmp_path_factory):
    _bindable(OTHER)
    with _running(tmp_path_factory.mktemp("nginx")) as port:
        yield port


def _get(port: int, headers: dict, source: str = NPM, path: str = "/api/outside") -> dict:
    """Wat de API krijgt. Vanaf NPM staat in X-Forwarded-For achteraan het adres waarvan NPM het verzoek kreeg."""
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5, source_address=(source, 0))
    try:
        conn.request("GET", path, headers=headers)
        r = conn.getresponse()
        data = json.loads(r.read())
    finally:
        conn.close()
    assert data["path"] == path
    return {h: data["headers"].get(h) for h in HEADERS}


def _want(ip, via=None, country=None, access=None, forged=None) -> dict:
    return dict(zip(HEADERS, (ip, via, country, access, forged)))


CF_IP = {"CF-Connecting-IP": "94.224.1.7"}  # bv. het eigen publieke IP, om als thuis te tellen

CASES = {
    # Rechtstreeks bij NPM (poort 443) van een publiek IP dat niet van Cloudflare is: vervalst, het IP is de afzender.
    "publiek, geen Cloudflare": ({"X-Forwarded-For": "203.0.113.9", **CF_IP, "CF-IPCountry": "BE"}, NPM,
                                 _want("203.0.113.9", forged="1")),
    "publiek IPv6, geen Cloudflare": ({"X-Forwarded-For": "2a02:1810:1::5", **CF_IP}, NPM,
                                      _want("2a02:1810:1::5", forged="1")),
    # Poortdoorverwijzing via de proxy van Cloudflare.
    "Cloudflare IPv4": ({"X-Forwarded-For": "172.70.1.2", "CF-Connecting-IP": "81.82.83.84", "CF-IPCountry": "be"}, NPM,
                        _want("81.82.83.84", via="1", country="be")),
    "Cloudflare IPv6 met Access": ({"X-Forwarded-For": "2400:cb00:2049::1", "CF-Connecting-IP": "2a02:1810:1::5",
                                    "CF-IPCountry": "NL", "Cf-Access-Jwt-Assertion": "eyJ.x.y"}, NPM,
                                   _want("2a02:1810:1::5", via="1", country="NL", access="cloudflare-access")),
    # Een IPv4-adres in IPv6-vorm (NPM op een dual-stack socket).
    "Cloudflare als ::ffff:": ({"X-Forwarded-For": "::ffff:172.70.1.2", "CF-Connecting-IP": "81.82.83.84"}, NPM,
                               _want("81.82.83.84", via="1")),
    "publiek als ::ffff:": ({"X-Forwarded-For": "::ffff:203.0.113.9", **CF_IP}, NPM,
                            _want("::ffff:203.0.113.9", forged="1")),
    # Cloudflare voegt het IP van de bezoeker toe aan diens eigen X-Forwarded-For; NPM zet Cloudflare erachter.
    "Cloudflare na XFF van de bezoeker": ({"X-Forwarded-For": "10.0.0.1, 81.82.83.84, 162.158.5.6",
                                           "CF-Connecting-IP": "81.82.83.84"}, NPM, _want("81.82.83.84", via="1")),
    # Cloudflare Tunnel: cloudflared komt van een privé-adres bij NPM.
    "tunnel": ({"X-Forwarded-For": "192.168.0.50", "CF-Connecting-IP": "81.82.83.84"}, NPM,
               _want("81.82.83.84", via="1")),
    "tunnel IPv6": ({"X-Forwarded-For": "fd00::50", "CF-Connecting-IP": "81.82.83.84"}, NPM,
                    _want("81.82.83.84", via="1")),
    "tunnel op de host van NPM": ({"X-Forwarded-For": "172.17.0.1", "CF-Connecting-IP": "81.82.83.84"}, NPM,
                                  _want("81.82.83.84", via="1")),
    # cloudflared op de host van NPM, naar het LAN-adres van NPM: NPM kreeg het van zichzelf en zet zijn eigen IP
    # achteraan. Dat telt (niet recursief), niet het adres van de bezoeker dat Cloudflare ervoor zette.
    "tunnel naar het LAN-adres van NPM": ({"X-Forwarded-For": f"81.82.83.84, {NPM}", "CF-Connecting-IP": "81.82.83.84",
                                           "CF-IPCountry": "BE", "Cf-Access-Jwt-Assertion": "eyJ.x.y"}, NPM,
                                          _want("81.82.83.84", via="1", country="BE", access="cloudflare-access")),
    "NPM van zichzelf, zonder Cloudflare": ({"X-Forwarded-For": f"203.0.113.9, {NPM}"}, NPM, _want(NPM)),
    # Gewoon via NPM, zonder Cloudflare (bv. thuis via de eigen DNS).
    "NPM zonder Cloudflare": ({"X-Forwarded-For": "192.168.0.20"}, NPM, _want("192.168.0.20")),
    "NPM publiek zonder Cloudflare": ({"X-Forwarded-For": "81.82.83.84"}, NPM, _want("81.82.83.84")),
    # Niet via NPM (rechtstreeks op poort 80): X-Forwarded-For telt niet, CF-headers zijn vervalst.
    "niet van NPM": ({"X-Forwarded-For": "172.70.1.2", **CF_IP}, OTHER, _want(OTHER, forged="1")),
    "niet van NPM, zonder CF": ({"X-Forwarded-For": "172.70.1.2"}, OTHER, _want(OTHER)),
    # Wat de bezoeker zelf links in X-Forwarded-For zet (ook Cloudflare of NPM), telt niet.
    "XFF van de bezoeker": ({"X-Forwarded-For": f"104.16.0.1, 10.0.0.1, {NPM}, 203.0.113.9", **CF_IP}, NPM,
                            _want("203.0.113.9", forged="1")),
    # Een waarde die geen IP is: van Cloudflare telt het als via Cloudflare (het IP van de afzender), anders vervalst.
    "geen IP van Cloudflare": ({"X-Forwarded-For": "172.70.1.2", "CF-Connecting-IP": "abc"}, NPM,
                               _want("172.70.1.2", via="1")),
    "lijst van Cloudflare": ({"X-Forwarded-For": "172.70.1.2", "CF-Connecting-IP": "1.2.3.4, 5.6.7.8"}, NPM,
                             _want("172.70.1.2", via="1")),
    "geen IP, geen Cloudflare": ({"X-Forwarded-For": "203.0.113.9", "CF-Connecting-IP": "abc"}, NPM,
                                 _want("203.0.113.9", forged="1")),
    # Elke header van Cloudflare apart.
    "alleen CF-IPCountry": ({"X-Forwarded-For": "203.0.113.9", "CF-IPCountry": "BE"}, NPM,
                            _want("203.0.113.9", forged="1")),
    "alleen Access": ({"X-Forwarded-For": "203.0.113.9", "Cf-Access-Jwt-Assertion": "eyJ.x.y"}, NPM,
                      _want("203.0.113.9", forged="1")),
    # Authentik (forward-auth in NPM): van NPM, ook zonder Cloudflare; niet rechtstreeks en niet bij vervalste headers.
    "Authentik": ({"X-Forwarded-For": "203.0.113.9", "X-authentik-username": "jonas"}, NPM,
                  _want("203.0.113.9", access="authentik")),
    "Authentik via Cloudflare": ({"X-Forwarded-For": "172.70.1.2", "CF-Connecting-IP": "81.82.83.84",
                                  "X-authentik-username": "jonas"}, NPM,
                                 _want("81.82.83.84", via="1", access="authentik")),
    "Authentik niet van NPM": ({"X-authentik-username": "jonas"}, OTHER, _want(OTHER)),
    "Authentik met vervalste CF": ({"X-Forwarded-For": "203.0.113.9", **CF_IP, "X-authentik-username": "jonas"}, NPM,
                                   _want("203.0.113.9", forged="1")),
    # Eigen X-Homepage-headers van de bezoeker worden altijd overschreven.
    "eigen headers": ({"X-Forwarded-For": "81.82.83.84", "X-Homepage-Cf-Forged": "0", "X-Homepage-Via-Cf": "1",
                       "X-Homepage-Access": "authentik", "X-Country": "BE"}, NPM, _want("81.82.83.84")),
    "eigen headers, vervalst": ({"X-Forwarded-For": "203.0.113.9", **CF_IP, "X-Homepage-Cf-Forged": "0"}, NPM,
                                _want("203.0.113.9", forged="1")),
}


@pytest.mark.parametrize("name", CASES)
def test_cloudflare_headers(nginx, name):
    headers, source, want = CASES[name]
    assert _get(nginx, headers, source) == want


@pytest.mark.parametrize("path", ["/api/push/geheim", "/api/hooks/geheim", "/api/auth/login"])
def test_elke_locatie(nginx, path):
    """Ook de push-monitors en webhooks (eigen location) krijgen de vlag."""
    assert _get(nginx, {"X-Forwarded-For": "203.0.113.9", **CF_IP}, path=path) == _want("203.0.113.9", forged="1")
    assert _get(nginx, {"X-Forwarded-For": "172.70.1.2", **CF_IP}, path=path) == _want("94.224.1.7", via="1")


# --- wie mag er rechtstreeks bij ($homepage_blocked) ------------------------------------------------------------------

# Een eigen nginx: NPM op 127.0.0.4 en de container op 127.0.0.5. Alle 127.0.0.x tellen voor nginx als de container
# zelf (loopback); peers laat er een paar als toestel op het LAN of als publiek IP tellen. NPM en het eigen adres van
# de container staan daarbij als publiek en LAN: werden ze niet herkend, dan zou (bijna) alles geweigerd worden.
G_NPM, G_SELF, G_LAN, G_PUBLIC = "127.0.0.4", "127.0.0.5", "127.0.0.2", "127.0.0.3"
PEERS = "".join(f"    {ip}/32     {kind};\n" for ip, kind in ((G_LAN, "lan"), (G_PUBLIC, "buiten"), (G_NPM, "buiten"),
                                                              (G_SELF, "lan")))


@pytest.fixture(scope="module", params=["dicht", "open"])
def gate(request, tmp_path_factory):
    """(poort, "dicht" of "open"): zonder en met HOMEPAGE_LAN_OPEN=1."""
    _bindable(G_NPM, G_SELF, G_LAN, G_PUBLIC)
    tmp = tmp_path_factory.mktemp(f"gate-{request.param}")
    with _running(tmp, host=G_SELF, npm=G_NPM, peers=PEERS, lan_dicht="1" if request.param == "dicht" else "0") as port:
        yield port, request.param


def _request(port: int, source: str, path: str) -> tuple[int, str]:
    conn = http.client.HTTPConnection(G_SELF, port, timeout=5, source_address=(source, 0))
    try:
        conn.request("GET", path, headers={"X-Forwarded-For": "192.168.0.20"})
        r = conn.getresponse()
        return r.status, r.read().decode(errors="replace")
    finally:
        conn.close()


def _blocked(port: int, source: str, path: str) -> bool:
    """Geweigerd door de toegang in nginx (403 met uitleg)? Anders antwoordt voor /api/ de API (hier de echo; /api/push
    zonder / stuurt nginx door naar /api/push/); voor de app hangt de status af van de map (geen index.html, en als
    root lezen de workers als nobody)."""
    status, body = _request(port, source, path)
    if status == 403 and "HOMEPAGE_LAN_OPEN=1" in body:
        return True
    if path.startswith("/api/") and path != "/api/push":
        assert status == 200 and json.loads(body)["path"] == path, (status, body)
    return False


ALWAYS = ["/api/outside", "/api/auth/login", "/api/ssh/ws", "/"]
LAN_OK = ["/api/healthz", "/api/healthz?x=1", "/api/push/geheim", "/api/push/geheim?status=up", "/api/hooks/geheim"]
# Ook met omwegen in het pad: nginx kijkt naar het opgeschoonde pad ($uri), net als de locations.
LAN_NOT = ["/", "/index.html", "/assets/x.js", "/api/outside", "/api/auth/login", "/api/ssh/ws", "/api/healthz/",
           "/api/healthzx", "/api/push", "/api/push/../auth/login", "/api/push/%2e%2e/auth/login",
           "/api/hooks/x/../../auth/login", "//api/auth/login", "/api/./push/../outside"]


@pytest.mark.parametrize("source", ["127.0.0.1", G_NPM, G_SELF])
def test_npm_en_de_container_zelf_mogen_alles(gate, source):
    port, _ = gate
    for path in ALWAYS + LAN_OK:
        assert not _blocked(port, source, path), (source, path)


def test_lan_alleen_push_webhooks_en_healthz(gate):
    port, mode = gate
    for path in LAN_OK:
        assert not _blocked(port, G_LAN, path), path
    for path in LAN_NOT:
        assert _blocked(port, G_LAN, path) is (mode == "dicht"), path


def test_publiek_ip_zonder_npm_niets(gate):
    port, _ = gate
    for path in ALWAYS + LAN_OK:
        assert _blocked(port, G_PUBLIC, path), path


def test_geweigerd_met_uitleg(gate):
    port, mode = gate
    status, body = _request(port, G_LAN, "/api/outside")
    if mode == "dicht":
        assert status == 403 and "Nginx Proxy Manager" in body and "/etc/homepage/homepage.env" in body
    else:
        assert status == 200
