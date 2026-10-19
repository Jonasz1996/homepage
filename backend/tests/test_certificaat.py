"""Het certificaat voor https rechtstreeks op de container (certificaat in deploy/install.sh, deploy/nginx-tls.conf):
een eigen CA en een servercertificaat van 9999 dagen, de sleutel van de CA meteen weer weg, en alleen opnieuw als er
een naam of IP ontbreekt, het bijna verloopt of iets niet past. Draait de echte functies uit install.sh in bash, met
een eigen map als /etc/ssl/homepage en een nep-hostname. Daarna nginx met dat certificaat op een eigen poort."""

import datetime as dt
import http.client
import json
import os
import re
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .test_install_lan import SCRIPT, _functie
from .test_nginx_cf import NGINX, _bindable, _running

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None or shutil.which("bash") is None, reason="openssl of bash ontbreekt")

FUNCTIES = "\n".join(map(_functie, ("certificaat_past", "certificaat")))
VARS = ("TLS_OK", "TLS_NIEUW", "TLS_REDEN", "TLS_FOUT", "TLS_VORIG", "rc")
NAAM, IPS = "jbogaerthomepage", "192.168.10.156 2a02:1810:abcd:1234:be24:11ff:fe12:3456 "


def _bin(tmp: Path, naam: str, ips: str, kapot: str = "") -> Path:
    """Een nep-hostname (de naam, of met -I de adressen) en, met kapot, een openssl die bij dat commando faalt."""
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    (b / "hostname").write_text(f"#!/bin/sh\nif [ \"$1\" = -I ]; then echo '{ips}'; else echo '{naam}'; fi\n")
    (b / "hostname").chmod(0o755)
    if kapot:
        (b / "openssl").write_text(f"#!/bin/sh\nif [ \"$1\" = {kapot} ]; then echo 'kapot: {kapot}' >&2; exit 1; fi\n"
                                   f"exec {OPENSSL} \"$@\"\n")
        (b / "openssl").chmod(0o755)
    else:
        (b / "openssl").unlink(missing_ok=True)
    return b


def _cert(tmp: Path, naam: str = NAAM, ips: str = IPS, kapot: str = "", functies: str = FUNCTIES,
          ssl_dir: Path | None = None) -> dict:
    """Eén keer certificaat, zoals install.sh het aanroept (set -euo pipefail, `certificaat || ...`). De map voor
    /etc/ssl/homepage is tmp/ssl, of ssl_dir."""
    b = _bin(tmp, naam, ips, kapot)
    (tmp / "stap.sh").write_text(f"set -euo pipefail\nTLS_DIR='{ssl_dir or tmp / 'ssl'}'\n{functies}\nrc=0\n"
                                 "certificaat || rc=$?\n"
                                 f'for v in {" ".join(VARS)}; do printf "%s=%s\\n" "$v" "${{!v}}"; done\n')
    r = subprocess.run(["bash", str(tmp / "stap.sh")], capture_output=True, text=True,
                       env={"PATH": f"{b}:{os.environ['PATH']}", "LC_ALL": "C.UTF-8"})
    assert r.returncode == 0, r.stdout + r.stderr
    return dict(line.split("=", 1) for line in r.stdout.splitlines() if re.match(r"^[A-Za-z_]+=", line))


def _laad(tmp: Path) -> tuple[x509.Certificate, x509.Certificate]:
    d = tmp / "ssl"
    return (x509.load_pem_x509_certificate((d / "homepage.crt").read_bytes()),
            x509.load_pem_x509_certificate((d / "homepage-ca.crt").read_bytes()))


def _bestanden(tmp: Path) -> dict:
    d = tmp / "ssl"
    return {p.name: p.read_bytes() for p in d.iterdir()} if d.exists() else {}


def _namen(cert: x509.Certificate) -> set[str]:
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return {*san.get_values_for_type(x509.DNSName), *map(str, san.get_values_for_type(x509.IPAddress))}


def test_eerste_keer(tmp_path):
    v = _cert(tmp_path)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_VORIG"], v["rc"]) == ("1", "1", "", "0")
    assert v["TLS_REDEN"] == "er was er nog geen" and v["TLS_FOUT"] == ""
    d = tmp_path / "ssl"
    # Alleen de drie bestanden: geen sleutel van de CA, geen aanvraag, geen .srl, geen tijdelijke map.
    assert sorted(p.name for p in d.iterdir()) == ["homepage-ca.crt", "homepage.crt", "homepage.key"]
    assert stat.S_IMODE(d.stat().st_mode) == 0o755
    assert stat.S_IMODE((d / "homepage.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((d / "homepage.crt").stat().st_mode) == stat.S_IMODE((d / "homepage-ca.crt").stat().st_mode) \
        == 0o644

    cert, ca = _laad(tmp_path)
    for c in (cert, ca):
        assert c.not_valid_after_utc - c.not_valid_before_utc == dt.timedelta(days=9999)
    # De naam van de container, localhost, 127.0.0.1, ::1 en het IPv4-adres; het publieke IPv6-adres niet.
    assert _namen(cert) == {NAAM, "localhost", "127.0.0.1", "::1", "192.168.10.156"}
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == NAAM
    ca_cn = ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    assert re.fullmatch(rf"homepage CA {NAAM} \d{{4}}-\d{{2}}-\d{{2}}", ca_cn)

    # Een CA die alleen certificaten mag tekenen, zonder tussen-CA; het certificaat alleen voor een server.
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign and not ku.digital_signature
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    assert list(cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value) == [ExtendedKeyUsageOID.SERVER_AUTH]
    cert.verify_directly_issued_by(ca)
    # De sleutel hoort bij het certificaat.
    key = serialization.load_pem_private_key((d / "homepage.key").read_bytes(), None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    # Python 3.13 controleert strenger (VERIFY_X509_STRICT): zo laadt het toch.
    ssl.create_default_context(cafile=str(d / "homepage-ca.crt"))


def test_tweede_keer_niets_nieuws(tmp_path):
    _cert(tmp_path)
    voor = _bestanden(tmp_path)
    v = _cert(tmp_path)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_REDEN"], v["rc"]) == ("1", "", "", "0")
    assert _bestanden(tmp_path) == voor
    # Een adres minder (of een ander IPv6-adres): ook niets nieuws, want wat er nog is, staat er al in.
    v = _cert(tmp_path, ips="2a02:1810:abcd:1234::99")
    assert (v["TLS_OK"], v["TLS_NIEUW"]) == ("1", "") and _bestanden(tmp_path) == voor


@pytest.mark.parametrize("naam, ips, reden", [
    (NAAM, IPS + "192.168.20.5", "192.168.20.5 stond niet in het vorige"),
    ("nieuwenaam", IPS, "nieuwenaam stond niet in het vorige"),
])
def test_nieuw_adres_of_naam(tmp_path, naam, ips, reden):
    """Een nieuw IP of een nieuwe naam: een nieuw certificaat met een nieuwe CA (de vorige kan niets meer tekenen)."""
    _cert(tmp_path)
    oud_cert, oud_ca = _laad(tmp_path)
    v = _cert(tmp_path, naam=naam, ips=ips)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_VORIG"], v["TLS_REDEN"]) == ("1", "1", "1", reden)
    cert, ca = _laad(tmp_path)
    assert ca.fingerprint(ca.signature_hash_algorithm) != oud_ca.fingerprint(oud_ca.signature_hash_algorithm)
    cert.verify_directly_issued_by(ca)
    assert reden.split()[0] in _namen(cert)
    assert sorted(p.name for p in (tmp_path / "ssl").iterdir()) == ["homepage-ca.crt", "homepage.crt", "homepage.key"]


@pytest.mark.parametrize("stuk", ["sleutel", "ca", "certificaat"])
def test_iets_past_niet(tmp_path, stuk):
    """Een andere sleutel, een andere of ontbrekende CA, of geen certificaat meer: opnieuw."""
    _cert(tmp_path)
    d = tmp_path / "ssl"
    if stuk == "sleutel":
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out",
                        str(d / "homepage.key")], check=True, capture_output=True)
    elif stuk == "ca":
        (d / "homepage-ca.crt").unlink()
    else:
        (d / "homepage.crt").unlink()
    v = _cert(tmp_path)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_VORIG"]) == ("1", "1", "" if stuk == "ca" else "1")
    assert v["TLS_REDEN"] == ("er was er nog geen" if stuk == "certificaat" else "het vorige paste niet meer")
    cert, ca = _laad(tmp_path)
    cert.verify_directly_issued_by(ca)
    key = serialization.load_pem_private_key((d / "homepage.key").read_bytes(), None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()


def test_bijna_verlopen(tmp_path):
    """Verloopt het binnen 30 dagen (hier: gemaakt voor 10 dagen), dan opnieuw voor 9999 dagen."""
    kort = FUNCTIES.replace("-days 9999", "-days 10")
    assert kort.count("-days 10") == 2
    _cert(tmp_path, functies=kort)
    v = _cert(tmp_path)
    assert (v["TLS_NIEUW"], v["TLS_REDEN"]) == ("1", "het vorige verliep binnen 30 dagen")
    cert, _ = _laad(tmp_path)
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == dt.timedelta(days=9999)


@pytest.mark.parametrize("kapot", ["genpkey", "req", "x509", "verify"])
def test_mislukt_zonder_vorige(tmp_path, kapot):
    """Lukt het niet, dan geen https (TLS_OK leeg) en niets halfs in de map, ook geen sleutel van een CA."""
    v = _cert(tmp_path, kapot=kapot)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["rc"]) == ("", "", "1")
    assert f"kapot: {kapot}" in v["TLS_FOUT"]
    assert _bestanden(tmp_path) == {}


@pytest.mark.parametrize("kapot", ["genpkey", "req"])
def test_mislukt_met_vorige(tmp_path, kapot):
    """Lukt een nieuw (voor een nieuw IP) niet, dan blijft het vorige in gebruik, onveranderd."""
    _cert(tmp_path)
    voor = _bestanden(tmp_path)
    v = _cert(tmp_path, ips=IPS + "192.168.20.5", kapot=kapot)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["rc"], v["TLS_REDEN"]) == ("1", "", "1",
                                                                       "192.168.20.5 stond niet in het vorige")
    assert _bestanden(tmp_path) == voor


def test_rest_van_een_onderbroken_keer(tmp_path):
    """Werd install.sh onderbroken terwijl de sleutel van de CA er nog was: de volgende keer is die weg."""
    _cert(tmp_path)
    rest = tmp_path / "ssl" / ".nieuw.abc123"
    rest.mkdir()
    (rest / "ca.key").write_text("geheim")
    v = _cert(tmp_path)
    assert v["TLS_NIEUW"] == "" and not rest.exists()


def test_rare_naam_en_adressen(tmp_path):
    """Een naam die geen geldige DNS-naam is en adressen die niet passen, slaat het over."""
    v = _cert(tmp_path, naam="niet_geldig", ips="127.0.1.1 999.1.1 fe80::1 10.0.0.7 10.0.0.7")
    assert v["TLS_OK"] == "1"
    cert, ca = _laad(tmp_path)
    assert _namen(cert) == {"localhost", "127.0.0.1", "::1", "10.0.0.7"}
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "homepage"
    assert ca.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value.startswith("homepage CA homepage ")


# --- de stap nginx in install.sh --------------------------------------------------------------------------------------

def _nginx_stap() -> str:
    start = SCRIPT.index("if ! certificaat; then")
    stop = SCRIPT.index("  /etc/nginx/snippets/homepage-tls.conf", start)
    return "\n".join(SCRIPT[start:stop + 1])


@pytest.mark.parametrize("ok, rc, ipv6", [("1", 0, True), ("1", 0, False), ("1", 1, True), ("", 1, True)])
def test_stap_nginx(tmp_path, ok, rc, ipv6):
    """Met een certificaat komt deploy/nginx-tls.conf in snippets (zonder IPv6 zonder de regel voor [::]), zonder
    een leeg bestand: dan luistert nginx alleen op poort 80, zoals vroeger."""
    etc = tmp_path / "nginx"
    (etc / "snippets").mkdir(parents=True)
    (etc / "sites-available").mkdir()
    inet6 = tmp_path / "if_inet6"
    if ipv6:
        inet6.write_text("")
    stap = (_nginx_stap().replace("/etc/nginx", str(etc)).replace("$APP_DIR/deploy", str(DEPLOY))
            .replace("/proc/net/if_inet6", str(inet6)))
    (tmp_path / "stap.sh").write_text(
        "set -euo pipefail\nNPM_IP=192.168.0.245\nwarn() { echo \"!! $*\"; }\n"
        f'certificaat() {{ TLS_OK="{ok}" TLS_REDEN="192.168.20.5 stond niet in het vorige" TLS_FOUT="kapot"; '
        f"return {rc}; }}\n{stap}\n")
    r = subprocess.run(["bash", str(tmp_path / "stap.sh")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    snippet = (etc / "snippets" / "homepage-tls.conf").read_text()
    site = (etc / "sites-available" / "homepage").read_text()
    if not ok:
        assert snippet == "" and "!! Geen certificaat voor https (kapot)" in r.stdout
    else:
        want = (DEPLOY / "nginx-tls.conf").read_text()
        if not ipv6:
            want = want.replace("listen [::]:443 ssl default_server;\n", "")
        assert snippet == want and "listen 443 ssl default_server;" in snippet
        assert ("vorige blijft in gebruik" in r.stdout) is (rc == 1)
    assert "include snippets/homepage-tls.conf;" in site and ("listen [::]:80" in site) is ipv6


# --- nginx met het certificaat ----------------------------------------------------------------------------------------

NPM, OTHER, PUBLIC = "127.0.0.1", "127.0.0.2", "127.0.0.3"


@pytest.fixture(scope="module")
def https(tmp_path_factory):
    """nginx met https op een eigen poort, met het certificaat van certificaat. NPM is 127.0.0.1, 127.0.0.2 de
    container zelf (loopback), 127.0.0.3 een publiek IP. Geeft (poort, poort voor https, map met het certificaat).
    De map met het certificaat ligt buiten die van pytest (alleen voor de eigenaar): als root lezen de workers van
    nginx als nobody, zoals www-data op de server /etc/ssl/homepage."""
    if NGINX is None:
        pytest.skip("nginx niet geïnstalleerd")
    _bindable(OTHER, PUBLIC)
    tmp = tmp_path_factory.mktemp("https")
    base = Path(tempfile.mkdtemp(prefix="homepage-ssl-"))
    try:
        base.chmod(0o755)
        assert _cert(tmp, naam="testhost", ips="", ssl_dir=base / "ssl")["TLS_OK"] == "1"
        with _running(tmp / "nginx", tls_dir=base / "ssl", peers=f"    {PUBLIC}/32 buiten;\n") as (port, tls_port):
            yield port, tls_port, base / "ssl"
    finally:
        shutil.rmtree(base)


def _context(ssl_dir: Path) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=str(ssl_dir / "homepage-ca.crt"))


def _vraag(https, tls: bool, source: str, path: str = "/api/outside", headers: dict | None = None):
    port, tls_port, ssl_dir = https
    if tls:
        conn = http.client.HTTPSConnection("127.0.0.1", tls_port, timeout=5, source_address=(source, 0),
                                           context=_context(ssl_dir))
    else:
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5, source_address=(source, 0))
    try:
        conn.request("GET", path, headers=headers or {})
        r = conn.getresponse()
        return r.status, r.getheader("Content-Type"), r.read()
    finally:
        conn.close()


def _proto(https, tls: bool, source: str, sent: str | None) -> str | None:
    status, _, body = _vraag(https, tls, source, headers={"X-Forwarded-Proto": sent} if sent else {})
    assert status == 200, body
    return json.loads(body)["headers"].get("x-forwarded-proto")


@pytest.mark.parametrize("tls, source, sent, want", [
    # Van NPM: wat NPM doorgeeft (https bij een host met SSL), ook als NPM zelf via http of https naar de container
    # gaat; zonder (of met iets anders): hoe het binnenkwam.
    (False, NPM, "https", "https"),
    (True, NPM, "http", "http"),
    (True, NPM, None, "https"),
    (False, NPM, None, "http"),
    (False, NPM, "HTTPS", "http"),
    (False, NPM, "https, http", "http"),
    # Niet van NPM: hoe het bij nginx binnenkwam, wat de afzender ook meestuurt.
    (False, OTHER, "https", "http"),
    (True, OTHER, "http", "https"),
    (True, OTHER, None, "https"),
])
def test_schema_voor_de_api(https, tls, source, sent, want):
    assert _proto(https, tls, source, sent) == want


@pytest.mark.parametrize("tls", [False, True])
def test_ca_downloaden(https, tls):
    status, ctype, body = _vraag(https, tls, NPM, "/homepage-ca.crt")
    assert (status, ctype) == (200, "application/x-x509-ca-cert")
    assert body == (https[2] / "homepage-ca.crt").read_bytes() and b"PRIVATE" not in body


def test_https_zelfde_toegang(https):
    """Op poort 443 dezelfde regels: een publiek IP dat NPM overslaat, krijgt ook daar de 403 met uitleg."""
    status, _, body = _vraag(https, True, PUBLIC)
    assert status == 403 and b"HOMEPAGE_LAN_OPEN=1" in body
    status, _, _ = _vraag(https, True, PUBLIC, "/homepage-ca.crt")
    assert status == 403


def test_alleen_met_de_eigen_ca(https):
    """Zonder de CA vertrouwt een client het certificaat niet; met de CA wel, op een naam en op een IP-adres (de
    andere tests hierboven gaan naar 127.0.0.1)."""
    _, tls_port, ssl_dir = https
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as s:
            ssl.create_default_context().wrap_socket(s, server_hostname="127.0.0.1")
    for naam in ("localhost", "testhost"):
        with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as s:
            with _context(ssl_dir).wrap_socket(s, server_hostname=naam) as t:
                assert t.version() in ("TLSv1.2", "TLSv1.3")
    with pytest.raises(ssl.SSLCertVerificationError):
        with socket.create_connection(("127.0.0.1", tls_port), timeout=5) as s:
            _context(ssl_dir).wrap_socket(s, server_hostname="andere.naam")
