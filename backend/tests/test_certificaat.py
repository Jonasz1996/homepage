"""Het certificaat voor https rechtstreeks op de container (certificaat in deploy/install.sh, deploy/nginx-tls.conf):
een eigen CA en een servercertificaat van 9999 dagen, een CA die alleen voor de container mag tekenen en waarvan de
sleutel meteen weer weg is, en alleen opnieuw als er een naam of IP ontbreekt, het bijna verloopt of iets niet past.
Draait de echte functies uit install.sh in bash, met eigen mappen als /etc/ssl/homepage en /dev/shm en een
nep-hostname. Daarna nginx met dat certificaat op een eigen poort."""

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
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .test_install_lan import SCRIPT, _functie
from .test_nginx_cf import NGINX, _bindable, _running

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
OPENSSL = shutil.which("openssl")
pytestmark = pytest.mark.skipif(OPENSSL is None or shutil.which("bash") is None, reason="openssl of bash ontbreekt")

FUNCTIES = "\n".join(map(_functie, ("certificaat_past", "certificaat_zetten", "certificaat")))
VARS = ("TLS_OK", "TLS_NIEUW", "TLS_REDEN", "TLS_FOUT", "TLS_VORIG", "TLS_VORIG_SHA1", "rc")
NAAM, IPS = "jbogaerthomepage", "192.168.10.156 2a02:1810:abcd:1234:be24:11ff:fe12:3456 "
DRIE = ["homepage-ca.crt", "homepage.crt", "homepage.key"]


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
          ssl_dir: Path | None = None, tmpfs: Path | None = None, voor: str = "", na: str = "") -> dict:
    """Eén keer certificaat, zoals install.sh het aanroept (set -euo pipefail, `certificaat || ...`). De map voor
    /etc/ssl/homepage is tmp/ssl (of ssl_dir), die voor /dev/shm tmp/shm (of tmpfs). voor en na: bash ervoor en
    erna; wat na schrijft als NAAM=waarde, komt ook in het resultaat."""
    b = _bin(tmp, naam, ips, kapot)
    if tmpfs is None:
        tmpfs = tmp / "shm"
        tmpfs.mkdir(exist_ok=True)
    (tmp / "stap.sh").write_text(f"set -euo pipefail\nTLS_DIR='{ssl_dir or tmp / 'ssl'}'\nTLS_TMPFS='{tmpfs}'\n"
                                 f"{functies}\n{voor}\nrc=0\ncertificaat || rc=$?\n"
                                 f'for v in {" ".join(VARS)}; do printf "%s=%s\\n" "$v" "${{!v}}"; done\n{na}\n')
    r = subprocess.run(["bash", str(tmp / "stap.sh")], capture_output=True, text=True,
                       env={"PATH": f"{b}:{os.environ['PATH']}", "LC_ALL": "C.UTF-8"})
    assert r.returncode == 0, r.stdout + r.stderr
    return dict(line.split("=", 1) for line in r.stdout.splitlines() if re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", line))


def _laad(d: Path) -> tuple[x509.Certificate, x509.Certificate]:
    return (x509.load_pem_x509_certificate((d / "homepage.crt").read_bytes()),
            x509.load_pem_x509_certificate((d / "homepage-ca.crt").read_bytes()))


def _bestanden(d: Path) -> dict:
    return {p.name: p.read_bytes() for p in d.iterdir()} if d.exists() else {}


def _namen(cert: x509.Certificate) -> set[str]:
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return {*san.get_values_for_type(x509.DNSName), *map(str, san.get_values_for_type(x509.IPAddress))}


def _cn(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value


def _sha1(cert: x509.Certificate) -> str:
    return ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA1()))


def _past(d: Path) -> None:
    """Het certificaat komt van de CA, de sleutel hoort erbij, en openssl vindt het ook streng in orde."""
    cert, ca = _laad(d)
    cert.verify_directly_issued_by(ca)
    key = serialization.load_pem_private_key((d / "homepage.key").read_bytes(), None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()
    r = subprocess.run([OPENSSL, "verify", "-x509_strict", "-purpose", "sslserver", "-CAfile",
                        str(d / "homepage-ca.crt"), str(d / "homepage.crt")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_eerste_keer(tmp_path):
    v = _cert(tmp_path)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_VORIG"], v["TLS_VORIG_SHA1"], v["rc"]) == ("1", "1", "", "", "0")
    assert v["TLS_REDEN"] == "er nog geen was" and v["TLS_FOUT"] == ""
    d = tmp_path / "ssl"
    # Alleen de drie bestanden: geen sleutel van de CA (ook niet in het geheugen), geen aanvraag, geen .srl, geen
    # tijdelijke map.
    assert sorted(p.name for p in d.iterdir()) == DRIE and list((tmp_path / "shm").iterdir()) == []
    assert stat.S_IMODE(d.stat().st_mode) == 0o755
    assert stat.S_IMODE((d / "homepage.key").stat().st_mode) == 0o600
    assert stat.S_IMODE((d / "homepage.crt").stat().st_mode) == stat.S_IMODE((d / "homepage-ca.crt").stat().st_mode) \
        == 0o644

    cert, ca = _laad(d)
    for c in (cert, ca):
        assert c.not_valid_after_utc - c.not_valid_before_utc == dt.timedelta(days=9999)
    # De naam van de container, localhost, 127.0.0.1, ::1 en het IPv4-adres; het publieke IPv6-adres niet.
    want = {NAAM, "localhost", "127.0.0.1", "::1", "192.168.10.156"}
    assert _namen(cert) == want and _cn(cert) == NAAM
    assert re.fullmatch(rf"homepage CA {NAAM} \d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}", _cn(ca))

    # Een CA die alleen certificaten mag tekenen, zonder tussen-CA, en alleen voor die namen en precies die adressen.
    bc = ca.extensions.get_extension_for_class(x509.BasicConstraints)
    assert bc.critical and bc.value.ca and bc.value.path_length == 0
    ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    assert ku.key_cert_sign and ku.crl_sign and not ku.digital_signature
    nc = ca.extensions.get_extension_for_class(x509.NameConstraints)
    assert nc.critical and nc.value.excluded_subtrees is None
    toegelaten = set()
    for g in nc.value.permitted_subtrees:
        toegelaten.add(str(g.value.network_address) if isinstance(g, x509.IPAddress) else g.value)
        if isinstance(g, x509.IPAddress):
            assert g.value.prefixlen == g.value.max_prefixlen
    assert toegelaten == want
    # Het certificaat alleen voor een server.
    assert not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
    _past(d)


def test_streng_genoeg_voor_python(tmp_path):
    """Een echte handdruk met VERIFY_X509_STRICT (standaard vanaf Python 3.13), ook op 3.11, zonder nginx."""
    _cert(tmp_path, naam="testhost", ips="")
    d = tmp_path / "ssl"
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(d / "homepage.crt", d / "homepage.key")
    for naam in ("testhost", "localhost", "127.0.0.1", "::1"):
        client = ssl.create_default_context(cafile=str(d / "homepage-ca.crt"))
        client.verify_flags |= ssl.VERIFY_X509_STRICT
        a, b = socket.socketpair()
        fout = []

        def kant(a=a, fout=fout):
            try:
                with server.wrap_socket(a, server_side=True) as t:
                    t.recv(1)
            except (ssl.SSLError, OSError) as e:
                fout.append(e)

        th = threading.Thread(target=kant)
        th.start()
        with client.wrap_socket(b, server_hostname=naam) as t:
            assert t.version() in ("TLSv1.2", "TLSv1.3")
            t.send(b"x")
        th.join(10)
        assert not fout, fout


def test_ca_tekent_niets_anders(tmp_path):
    """Had iemand de sleutel van de CA toch (hier bewaard voor ze gewist wordt): een certificaat voor een andere
    naam of een ander IP gelooft niemand, door de nameConstraints. Een naam onder die van de container wel (zo werken
    nameConstraints; de README zegt het)."""
    bewaar = FUNCTIES.replace('&& rm -f "$ca/ca.key"', f'&& cp "$ca/ca.key" \'{tmp_path / "gestolen.key"}\' '
                                                       '&& rm -f "$ca/ca.key"')
    assert bewaar != FUNCTIES
    _cert(tmp_path, functies=bewaar)
    d = tmp_path / "ssl"
    for naam, san, mag in (("bank", "DNS:www.bank.example", False), ("ander-ip", "IP:192.168.10.1", False),
                           ("erachter", f"DNS:{NAAM}.evil.example", False), ("eronder", f"DNS:nas.{NAAM}", True)):
        key, csr, crt, ext = (tmp_path / f"{naam}.{e}" for e in ("key", "csr", "crt", "ext"))
        ext.write_text(f"basicConstraints = critical, CA:FALSE\nextendedKeyUsage = serverAuth\n"
                       f"subjectAltName = {san}\n")
        for cmd in (["genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key)],
                    ["req", "-new", "-key", str(key), "-subj", "/CN=x", "-out", str(csr)],
                    ["x509", "-req", "-in", str(csr), "-CA", str(d / "homepage-ca.crt"), "-CAkey",
                     str(tmp_path / "gestolen.key"), "-days", "30", "-set_serial", "7", "-extfile", str(ext),
                     "-out", str(crt)]):
            subprocess.run([OPENSSL, *cmd], check=True, capture_output=True)
        r = subprocess.run([OPENSSL, "verify", "-purpose", "sslserver", "-CAfile", str(d / "homepage-ca.crt"),
                            str(crt)], capture_output=True, text=True)
        if mag:
            assert r.returncode == 0, r.stdout + r.stderr
        else:
            assert r.returncode != 0 and "permitted subtree violation" in r.stdout + r.stderr, naam
    _past(d)


def test_tweede_keer_niets_nieuws(tmp_path):
    _cert(tmp_path)
    voor = _bestanden(tmp_path / "ssl")
    v = _cert(tmp_path)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_REDEN"], v["TLS_VORIG"], v["rc"]) == ("1", "", "", "1", "0")
    assert _bestanden(tmp_path / "ssl") == voor
    # Een adres minder (of een ander IPv6-adres): ook niets nieuws, want wat er nog is, staat er al in.
    v = _cert(tmp_path, ips="2a02:1810:abcd:1234::99")
    assert (v["TLS_OK"], v["TLS_NIEUW"]) == ("1", "") and _bestanden(tmp_path / "ssl") == voor


@pytest.mark.parametrize("naam, ips, reden", [
    (NAAM, IPS + "192.168.20.5", "192.168.20.5 niet in het vorige stond"),
    ("nieuwenaam", IPS, "nieuwenaam niet in het vorige stond"),
])
def test_nieuw_adres_of_naam(tmp_path, naam, ips, reden):
    """Een nieuw IP of een nieuwe naam: een nieuw certificaat met een nieuwe CA (de vorige kan niets meer tekenen). Die
    heeft een andere naam (met datum en uur, hier nagebootst), en TLS_VORIG_SHA1 zegt welke de vorige was."""
    _cert(tmp_path)
    _, oud_ca = _laad(tmp_path / "ssl")
    v = _cert(tmp_path, naam=naam, ips=ips, voor="date() { echo '2030-01-01 12:00:00'; }")
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_VORIG"], v["TLS_REDEN"]) == ("1", "1", "1", reden)
    assert v["TLS_VORIG_SHA1"] == _sha1(oud_ca)
    cert, ca = _laad(tmp_path / "ssl")
    assert _sha1(ca) != _sha1(oud_ca) and _cn(ca) == f"homepage CA {naam} 2030-01-01 12:00:00" != _cn(oud_ca)
    assert reden.split()[0] in _namen(cert)
    assert sorted(p.name for p in (tmp_path / "ssl").iterdir()) == DRIE
    _past(tmp_path / "ssl")


@pytest.mark.parametrize("stuk", ["sleutel", "ca weg", "andere ca", "certificaat weg"])
def test_iets_past_niet(tmp_path, stuk):
    """Een andere sleutel, een andere of ontbrekende CA, of geen certificaat meer: opnieuw."""
    _cert(tmp_path)
    d = tmp_path / "ssl"
    if stuk == "sleutel":
        subprocess.run([OPENSSL, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out",
                        str(d / "homepage.key")], check=True, capture_output=True)
    elif stuk == "ca weg":
        (d / "homepage-ca.crt").unlink()
    elif stuk == "andere ca":
        # Een geldige CA, maar niet die van dit certificaat (bv. een half teruggezette kopie).
        _cert(tmp_path, ssl_dir=tmp_path / "ander")
        shutil.copy(tmp_path / "ander" / "homepage-ca.crt", d / "homepage-ca.crt")
    else:
        (d / "homepage.crt").unlink()
    v = _cert(tmp_path)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["TLS_VORIG"]) == ("1", "1", "1")
    assert v["TLS_REDEN"] == "het vorige niet meer paste"
    _past(d)


def test_bijna_verlopen(tmp_path):
    """Verloopt het binnen 30 dagen (hier: gemaakt voor 10 dagen), dan opnieuw voor 9999 dagen."""
    kort = FUNCTIES.replace("-days 9999", "-days 10")
    assert kort.count("-days 10") == 2
    _cert(tmp_path, functies=kort)
    v = _cert(tmp_path)
    assert (v["TLS_NIEUW"], v["TLS_REDEN"]) == ("1", "het vorige binnen 30 dagen verloopt")
    cert, _ = _laad(tmp_path / "ssl")
    assert cert.not_valid_after_utc - cert.not_valid_before_utc == dt.timedelta(days=9999)


@pytest.mark.parametrize("kapot", ["genpkey", "req", "x509", "verify"])
def test_mislukt_zonder_vorige(tmp_path, kapot):
    """Lukt het niet, dan geen https (TLS_OK leeg) en niets halfs, ook geen sleutel van een CA."""
    v = _cert(tmp_path, kapot=kapot)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["rc"]) == ("", "", "1")
    assert f"kapot: {kapot}" in v["TLS_FOUT"]
    assert _bestanden(tmp_path / "ssl") == {} and list((tmp_path / "shm").iterdir()) == []


@pytest.mark.parametrize("kapot", ["genpkey", "req"])
def test_mislukt_met_vorige(tmp_path, kapot):
    """Lukt een nieuw (voor een nieuw IP) niet, dan blijft het vorige in gebruik, onveranderd."""
    _cert(tmp_path)
    voor = _bestanden(tmp_path / "ssl")
    v = _cert(tmp_path, ips=IPS + "192.168.20.5", kapot=kapot)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["rc"]) == ("1", "", "1")
    assert v["TLS_REDEN"] == "192.168.20.5 niet in het vorige stond"
    assert _bestanden(tmp_path / "ssl") == voor


def _waar_de_sleutel_stond(tmp: Path) -> str:
    """certificaat dat opschrijft in welke map de sleutel van de CA stond, net voor ze gewist wordt."""
    f = FUNCTIES.replace('&& rm -f "$ca/ca.key"', f'&& printf %s "$ca" > \'{tmp / "waar"}\' && rm -f "$ca/ca.key"')
    assert f != FUNCTIES
    return f


def test_sleutel_van_de_ca_in_het_geheugen(tmp_path):
    """De sleutel van de CA staat in $TLS_TMPFS (/dev/shm), nooit op de schijf naast de rest."""
    v = _cert(tmp_path, functies=_waar_de_sleutel_stond(tmp_path))
    assert v["TLS_NIEUW"] == "1"
    assert Path((tmp_path / "waar").read_text()).parent == tmp_path / "shm"


def test_zonder_tmpfs(tmp_path):
    """Kan de sleutel van de CA niet in het geheugen (geen /dev/shm), dan naast de rest; ook dan is ze weg."""
    v = _cert(tmp_path, functies=_waar_de_sleutel_stond(tmp_path), tmpfs=tmp_path / "bestaat-niet")
    assert (v["TLS_OK"], v["TLS_NIEUW"]) == ("1", "1")
    waar = Path((tmp_path / "waar").read_text())
    assert waar.parent == tmp_path / "ssl" and waar.name.startswith(".nieuw.")
    assert sorted(p.name for p in (tmp_path / "ssl").iterdir()) == DRIE
    _past(tmp_path / "ssl")


def test_rest_van_een_onderbroken_keer(tmp_path):
    """Werd install.sh onderbroken terwijl de sleutel van de CA er nog was: de volgende keer is die weg, ook als er
    niets nieuws nodig is."""
    _cert(tmp_path)
    rest, geheugen = tmp_path / "ssl" / ".nieuw.abc123", tmp_path / "shm" / "homepage-ca.def456"
    for d in (rest, geheugen):
        d.mkdir()
        (d / "ca.key").write_text("geheim")
    (tmp_path / "shm" / "iets-anders").write_text("blijft")
    v = _cert(tmp_path)
    assert v["TLS_NIEUW"] == "" and not rest.exists() and not geheugen.exists()
    assert (tmp_path / "shm" / "iets-anders").exists()


def test_signalen_terug_na_het_wisselen(tmp_path):
    """Tijdens het wisselen negeert het Ctrl+C (anders een sleutel naast een ander certificaat); daarna doen de
    traps van install.sh weer wat ze deden."""
    v = _cert(tmp_path, voor="trap 'echo int' INT\ntrap 'echo hup' HUP",
              na='printf "INT=%s\\nHUP=%s\\nTERM=%s\\n" "$(trap -p INT)" "$(trap -p HUP)" "$(trap -p TERM)"')
    assert v["TLS_NIEUW"] == "1"
    assert (v["INT"], v["HUP"], v["TERM"]) == ("trap -- 'echo int' SIGINT", "trap -- 'echo hup' SIGHUP", "")


def test_ctrl_c_tijdens_het_wisselen(tmp_path):
    """Een Ctrl+C tussen de mv's in (hier stuurt elke mv er een naar install.sh) onderbreekt niets: daarna liggen de
    drie nieuwe bestanden er, en passen ze bij elkaar."""
    b = _bin(tmp_path, NAAM, IPS)
    (b / "mv").write_text(f'#!/bin/sh\nkill -INT "$PPID"\nexec {shutil.which("mv")} "$@"\n')
    (b / "mv").chmod(0o755)
    v = _cert(tmp_path, voor="trap 'echo onderbroken; exit 130' INT")
    assert v["TLS_NIEUW"] == "1"
    _past(tmp_path / "ssl")


def test_lange_naam(tmp_path):
    """Een hostname van 63 tekens (het meeste dat mag): het certificaat heeft ze, in de naam van de CA (hoogstens 64
    tekens) staan de eerste 32."""
    naam = "a" * 30 + "-" + "b" * 32
    v = _cert(tmp_path, naam=naam)
    assert (v["TLS_OK"], v["TLS_NIEUW"], v["rc"]) == ("1", "1", "0"), v
    cert, ca = _laad(tmp_path / "ssl")
    assert _cn(cert) == naam and naam in _namen(cert)
    assert re.fullmatch(rf"homepage CA {naam[:32]} \d{{4}}-\d{{2}}-\d{{2}} \d{{2}}:\d{{2}}:\d{{2}}", _cn(ca))
    _past(tmp_path / "ssl")


@pytest.mark.parametrize("naam", ["niet_geldig", "156", "localhost", ""])
def test_rare_naam_en_adressen(tmp_path, naam):
    """Een naam die geen DNS-naam is of alleen cijfers (dat zou een IP lijken), en adressen die niet passen, slaat het
    over."""
    v = _cert(tmp_path, naam=naam, ips="127.0.1.1 999.1.1 fe80::1 10.0.0.7 10.0.0.7")
    assert v["TLS_OK"] == "1"
    cert, ca = _laad(tmp_path / "ssl")
    assert _namen(cert) == {"localhost", "127.0.0.1", "::1", "10.0.0.7"}
    assert _cn(cert) == "homepage" and _cn(ca).startswith("homepage CA homepage ")
    _past(tmp_path / "ssl")


# --- de stap nginx in install.sh --------------------------------------------------------------------------------------

def _nginx_stap() -> str:
    start = SCRIPT.index("if certificaat; then")
    stop = SCRIPT.index("  /etc/nginx/snippets/homepage-tls.conf", start)
    return "\n".join(SCRIPT[start:stop + 1])


def _poort_443_bezet(tmp: Path, master: str | None) -> str:
    """poort_443_bezet met tmp/nginx.pid voor /run/nginx.pid, met master erin (None: geen bestand)."""
    pid = tmp / "nginx.pid"
    if master is not None:
        pid.write_text(master + "\n")
    f = _functie("poort_443_bezet")
    assert "/run/nginx.pid" in f
    return f.replace("/run/nginx.pid", str(pid))


def _ss(tmp: Path, wie: str) -> Path:
    """Een nep-ss: wie luistert op poort 443 (niets, deze nginx met master 7, of een ander programma)."""
    b = tmp / "bin"
    b.mkdir(exist_ok=True)
    pid = 7 if wie == "nginx" else 9
    lijn = f"LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:((\"{wie}\",pid={pid},fd=6))" if wie else ""
    (b / "ss").write_text(f"#!/bin/sh\nprintf '%s\\n' '{lijn}'\n" if wie else "#!/bin/sh\n")
    (b / "ss").chmod(0o755)
    return b


@pytest.mark.parametrize("ok, rc, nieuw, vorig, ipv6, op443", [
    ("1", 0, "", "1", True, ""), ("1", 0, "1", "1", False, "nginx"), ("1", 0, "1", "", True, ""),
    ("1", 1, "", "1", True, ""), ("", 1, "", "", True, ""), ("1", 0, "", "1", True, "caddy"),
])
def test_stap_nginx(tmp_path, ok, rc, nieuw, vorig, ipv6, op443):
    """Met een certificaat komt deploy/nginx-tls.conf in snippets (zonder IPv6 zonder de regel voor [::]), zonder
    een leeg bestand: dan luistert nginx alleen op poort 80, zoals vroeger. Ook leeg als een ander programma al op
    poort 443 luistert. Een nieuwe CA meldt het meteen, maar niet bij de eerste keer (er was er nog geen)."""
    etc = tmp_path / "nginx"
    (etc / "snippets").mkdir(parents=True)
    (etc / "sites-available").mkdir()
    inet6 = tmp_path / "if_inet6"
    if ipv6:
        inet6.write_text("")
    stap = (_nginx_stap().replace("/etc/nginx", str(etc)).replace("$APP_DIR/deploy", str(DEPLOY))
            .replace("/proc/net/if_inet6", str(inet6)))
    (tmp_path / "stap.sh").write_text(
        f"set -euo pipefail\nNPM_IP=192.168.0.245\nTLS_DIR=/etc/ssl/homepage\nwarn() {{ echo \"!! $*\"; }}\n"
        f"{_functie('nieuwe_ca_melden')}\n{_poort_443_bezet(tmp_path, '7')}\n"
        f'certificaat() {{ TLS_OK="{ok}" TLS_NIEUW="{nieuw}" TLS_VORIG="{vorig}" TLS_VORIG_SHA1="AA:BB" '
        f'TLS_REDEN="192.168.20.5 niet in het vorige stond" TLS_FOUT="kapot"; return {rc}; }}\n{stap}\n'
        'echo "HTTPS_AAN=$HTTPS_AAN"\n')
    r = subprocess.run(["bash", str(tmp_path / "stap.sh")], capture_output=True, text=True,
                       env={**os.environ, "PATH": f"{_ss(tmp_path, op443)}:{os.environ['PATH']}"})
    assert r.returncode == 0, r.stderr
    snippet = (etc / "snippets" / "homepage-tls.conf").read_text()
    site = (etc / "sites-available" / "homepage").read_text()
    bezet = "!! Poort 443 is al in gebruik door caddy: nginx luistert daarom alleen op http (poort 80)."
    assert (bezet in r.stdout) is (op443 == "caddy")
    assert ("HTTPS_AAN=1" in r.stdout) is (bool(ok) and op443 != "caddy")
    if not ok:
        assert snippet == "" and "!! Geen certificaat voor https (kapot)" in r.stdout
        assert "zet het dan terug op http en poort 80" in r.stdout
    elif op443 == "caddy":
        assert snippet == ""
    else:
        want = (DEPLOY / "nginx-tls.conf").read_text()
        if not ipv6:
            want = want.replace("listen [::]:443 ssl default_server;\n", "")
        assert snippet == want and "listen 443 ssl default_server;" in snippet
        assert ("Het vorige blijft in gebruik" in r.stdout) is (rc == 1)
        assert ("omdat 192.168.20.5 niet in het vorige stond" in r.stdout) is (rc == 1 or bool(nieuw and vorig))
    melding = "!! Nieuw certificaat voor https, met een nieuwe CA, omdat 192.168.20.5 niet in het vorige stond."
    assert (melding in r.stdout) is bool(nieuw and vorig)
    if nieuw and vorig:
        assert "(vingerafdruk SHA-1 AA:BB), verwijder die daar en importeer de nieuwe" in r.stdout
    assert "include snippets/homepage-tls.conf;" in site and ("listen [::]:80" in site) is ipv6


EIGEN = 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=8,fd=6),("nginx",pid=7,fd=6))'


@pytest.mark.parametrize("uitvoer, master, want", [
    ("", "7", ""),
    (EIGEN, "7", ""),
    # Een andere nginx (of openresty), of geen master om mee te vergelijken: een ander programma.
    (EIGEN, "99", "nginx"),
    (EIGEN, None, "nginx"),
    ('LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=70,fd=6))', "7", "nginx"),
    ('LISTEN 0 4096 *:443 *:* users:(("caddy",pid=9,fd=7))', "7", "caddy"),
    (EIGEN + '\nLISTEN 0 4096 [::]:443 [::]:* users:(("docker-proxy",pid=3,fd=4))', "7", "docker-proxy"),
    ('LISTEN 0 4096 0.0.0.0:443 0.0.0.0:* users:(("",pid=9,fd=3))', "7", "een ander programma"),
    ("LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*", "7", "een ander programma"),
    (None, "7", ""),
])
def test_poort_443_bezet(tmp_path, uitvoer, master, want):
    """Wie er al op poort 443 luistert, behalve deze nginx: die van de master in /run/nginx.pid (de uitvoer van
    ss -Hltnp; None: geen ss)."""
    b = tmp_path / "bin"
    b.mkdir()
    if uitvoer is not None:
        (b / "ss").write_text(f"#!/bin/sh\ncat <<'UIT'\n{uitvoer}\nUIT\n")
        (b / "ss").chmod(0o755)
    (tmp_path / "stap.sh").write_text(f"set -euo pipefail\n{_poort_443_bezet(tmp_path, master)}\n"
                                      'printf "[%s]\\n" "$(poort_443_bezet)"\n')
    # Zonder ss: alleen de nep-map op PATH (de functie gebruikt verder alleen wat bash zelf kan, en cat in de nep-ss).
    path = f"{b}:{os.path.dirname(shutil.which('cat'))}" if uitvoer is not None else str(b)
    r = subprocess.run([shutil.which("bash"), str(tmp_path / "stap.sh")], capture_output=True, text=True,
                       env={"PATH": path})
    assert r.returncode == 0, r.stderr
    assert r.stdout == f"[{want}]\n"


def test_bij_fout_ruimt_op(tmp_path):
    """Onderbroken (of een fout) terwijl certificaat bezig was: bij_fout wist wat er half lag, met de sleutel van de
    CA."""
    rest, geheugen = tmp_path / "ssl" / ".nieuw.abc", tmp_path / "shm" / "homepage-ca.def"
    for d in (rest, geheugen):
        d.mkdir(parents=True)
        (d / "ca.key").write_text("geheim")
    (tmp_path / "stap.sh").write_text("\n".join([
        "set -euo pipefail", f"TLS_DIR='{tmp_path / 'ssl'}' TLS_TMPFS='{tmp_path / 'shm'}'",
        'INSTALL_LOG="" TEE_PID=""',
        *map(_functie, ("warn", "log_dicht", "bij_fout")), "trap bij_fout EXIT", "exit 0"]))
    r = subprocess.run(["bash", str(tmp_path / "stap.sh")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert not rest.exists() and not geheugen.exists()


# --- nginx met het certificaat ----------------------------------------------------------------------------------------

NPM, OTHER, PUBLIC = "127.0.0.1", "127.0.0.2", "127.0.0.3"
LAN_NETS = "198.51.100.0/24 lan; 2001:db8:1::/48 lan; "


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
        with _running(tmp / "nginx", tls_dir=base / "ssl", peers=f"    {PUBLIC}/32 buiten;\n",
                      lan_nets=LAN_NETS) as (port, tls_port):
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
    # Van NPM: wat NPM doorgeeft (https bij een host met SSL, http zonder), ook als NPM zelf via http of https naar
    # de container gaat; zonder (of met iets anders): hoe het binnenkwam.
    (False, NPM, "https", "https"),
    (True, NPM, "http", "http"),
    (True, NPM, None, "https"),
    (False, NPM, None, "http"),
    (False, NPM, "HTTPS", "http"),
    (False, NPM, "https, http", "http"),
    # Van een ander net zo: wat de afzender zegt (alleen voor zijn eigen cookie), anders hoe het binnenkwam. Zo ook
    # NPM met een ander IP dan HOMEPAGE_NPM_IP, via https naar de container voor een host zonder SSL.
    (False, OTHER, "https", "https"),
    (False, OTHER, "http", "http"),
    (False, OTHER, None, "http"),
    (True, OTHER, "http", "http"),
    (True, OTHER, None, "https"),
])
def test_schema_voor_de_api(https, tls, source, sent, want):
    assert _proto(https, tls, source, sent) == want


@pytest.mark.parametrize("tls", [False, True])
def test_ca_downloaden(https, tls):
    status, ctype, body = _vraag(https, tls, NPM, "/homepage-ca.crt")
    assert (status, ctype) == (200, "application/x-x509-ca-cert")
    assert body == (https[2] / "homepage-ca.crt").read_bytes() and b"PRIVATE" not in body


@pytest.mark.parametrize("tls", [False, True])
@pytest.mark.parametrize("source, headers, status", [
    (NPM, {"X-Forwarded-For": "192.168.1.5"}, 200),
    (NPM, {"X-Forwarded-For": "10.8.0.2"}, 200),
    # Een netwerk dat install.sh ook als LAN invult (HOMEPAGE_LAN_NETS, het IPv6-netwerk van de container).
    (NPM, {"X-Forwarded-For": "198.51.100.7"}, 200),
    (NPM, {"X-Forwarded-For": "2001:db8:1::5"}, 200),
    (NPM, {"X-Forwarded-For": "9.9.9.9"}, 404),
    (NPM, {"X-Forwarded-For": "2a02:1810::5"}, 404),
    (NPM, {"CF-Connecting-IP": "192.168.1.5"}, 404),
    # Vervalst: niet van Cloudflare of een tunnel, met een privé-adres (alleen de vervalsing beslist).
    (NPM, {"X-Forwarded-For": "169.254.1.1", "CF-Connecting-IP": "192.168.1.5"}, 404),
    (OTHER, {"CF-Connecting-IP": "192.168.1.5"}, 404),
    (OTHER, {}, 200),
])
def test_ca_alleen_thuis(https, tls, source, headers, status):
    """Alleen voor wie thuis is (LAN of VPN), zoals /api/healthz: niet van een publiek IP, niet via Cloudflare (ook
    niet met een privé-adres erin), en niet met een vervalste header van Cloudflare. In de CA staan de naam en de
    adressen van de container."""
    got, _, body = _vraag(https, tls, source, "/homepage-ca.crt", headers)
    assert got == status and (b"BEGIN CERTIFICATE" in body) is (status == 200)


def test_https_zelfde_toegang(https):
    """Op poort 443 dezelfde regels: een publiek IP dat NPM overslaat, krijgt ook daar de 403 met uitleg."""
    status, _, body = _vraag(https, True, PUBLIC)
    assert status == 403 and b"HOMEPAGE_LAN_OPEN=1" in body
    status, _, _ = _vraag(https, True, PUBLIC, "/homepage-ca.crt")
    assert status == 403


def test_alleen_met_de_eigen_ca(https):
    """Zonder de CA vertrouwt een client het certificaat niet; met de CA wel, op een naam en op een IP-adres (de
    andere tests hierboven gaan naar 127.0.0.1), maar niet op een andere naam."""
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
