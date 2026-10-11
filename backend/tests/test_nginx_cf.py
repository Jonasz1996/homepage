"""De headers van Cloudflare in nginx (deploy/nginx-map.conf): alleen geloofd als NPM het verzoek van Cloudflare of
een tunnel kreeg. Draait een echte nginx met de configuratie uit deploy/, met 127.0.0.1 als NPM, voor een kleine
echo-server die de headers teruggeeft die de API zou krijgen. Zonder nginx (of zonder 127.0.0.2) overgeslagen."""

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


def render(tmp: Path, port: int, api_port: int) -> Path:
    """De configuratie zoals install.sh ze neerzet, met andere poorten en paden."""
    (tmp / "snippets").mkdir(parents=True, exist_ok=True)
    shutil.copy(DEPLOY / "nginx-headers.conf", tmp / "snippets" / "homepage-headers.conf")
    (tmp / "homepage-map.conf").write_text(
        (DEPLOY / "nginx-map.conf").read_text().replace("__NPM_IP_RE__", NPM.replace(".", "\\.")))
    site = (DEPLOY / "nginx.conf").read_text()
    for old, new in (("__NPM_IP__", NPM), ("listen 80 default_server;", f"listen 127.0.0.1:{port};"),
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


@pytest.fixture(scope="module")
def nginx(tmp_path_factory):
    try:
        with socket.socket() as s:
            s.bind((OTHER, 0))
    except OSError:
        pytest.skip(f"{OTHER} niet bruikbaar als bronadres")
    tmp = tmp_path_factory.mktemp("nginx")
    echo = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=echo.serve_forever, daemon=True).start()
    port = _free_port()
    conf = render(tmp, port, echo.server_address[1])
    test = subprocess.run([NGINX, "-t", "-p", str(tmp), "-c", str(conf)], capture_output=True, text=True)
    assert test.returncode == 0, test.stderr
    proc = subprocess.Popen([NGINX, "-p", str(tmp), "-c", str(conf)], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
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
