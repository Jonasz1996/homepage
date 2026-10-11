"""Wat install.sh voor het LAN beslist: of nginx het LAN dichtzet, wat er in /etc/homepage/nginx komt (en wat de rij
"Dashboard alleen via NPM" daarvan maakt), en welke netwerken nginx ook als LAN telt. Draait de echte stukken uit
deploy/install.sh in bash, met een eigen map als /etc/homepage en een nep-ip voor de adressen van de container."""

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app.config import get_settings
from app.setupcheck import lan_row

from .test_nginx_cf import NGINX, render

DEPLOY = Path(__file__).resolve().parents[2] / "deploy"
SCRIPT = (DEPLOY / "install.sh").read_text().splitlines()
pytestmark = pytest.mark.skipif(shutil.which("bash") is None or shutil.which("python3") is None,
                                reason="bash of python3 ontbreekt")

# homepage.env van een installatie van voor de LAN-regel: het vorige script schreef altijd HOMEPAGE_NPM_IP weg (ook
# de standaard) en kende HOMEPAGE_LAN_OPEN niet.
OUD = """HOMEPAGE_DATABASE_URL=postgresql+asyncpg://homepage@/homepage?host=/var/run/postgresql
HOMEPAGE_COOKIE_SECURE=auto
HOMEPAGE_SITE_NAME=homepage
HOMEPAGE_NPM_IP=192.168.0.245
HOMEPAGE_SYSLOG_TARGET=192.168.10.156
"""
# Wat `ip -6 -o addr show scope global` in de container geeft: een publiek adres (SLAAC) en een ULA.
IP6 = ("2: eth0    inet6 2a02:1810:abcd:1234:be24:11ff:fe12:3456/64 scope global dynamic mngtmpaddr \\       "
       "valid_lft 86321sec preferred_lft 14321sec\n"
       "2: eth0    inet6 fd12:3456:789a:1::5/64 scope global \\       valid_lft forever preferred_lft forever\n")


def _regels(begin: str, eind: str, tot: bool = False) -> str:
    """De regels van install.sh van de eerste die met begin start tot en met de eerste daarna die eind bevat (met
    tot: tot de eerste daarna die met eind start, zonder die)."""
    start = next(i for i, line in enumerate(SCRIPT) if line.startswith(begin))
    stop = next(i for i in range(start, len(SCRIPT)) if (SCRIPT[i].startswith(eind) if tot else eind in SCRIPT[i]))
    return "\n".join(SCRIPT[start:stop if tot else stop + 1])


def _functie(naam: str) -> str:
    start = next(i for i, line in enumerate(SCRIPT) if line.startswith(f"{naam}() {{"))
    if SCRIPT[start].rstrip().endswith("}"):
        return SCRIPT[start]
    return "\n".join(SCRIPT[start:SCRIPT.index("}", start) + 1])


# Zoals install.sh: het IP van NPM (opgegeven, bewaard of een gok) en het bewaren in homepage.env, homepage.env
# inlezen, en in de stap nginx de keuze en /etc/homepage/nginx.
NGINX_STAP = "lan_bijgewerkt\nlan_keuze\nlan_netwerken"
STUKKEN = "\n".join([
    _regels('NPM_IP="${NPM_IP:-', "NPM_GOK=1; }"),
    *map(_functie, ("warn", "lan_bijgewerkt", "lan_keuze", "lan_netwerken")),
    _regels("# NPM-IP bewaren", "# Map voor de dagelijkse back-up", tot=True),
    'set -a\n. "$CONF_DIR/homepage.env"\nset +a',
    NGINX_STAP,
    _regels("printf 'lan=%s", '> "$CONF_DIR/nginx"'),
    _regels('[ -z "$BIJGEWERKT" ] ||', '"$CONF_DIR/homepage.env"'),
])


def test_stukken_zoals_in_install_sh():
    """De stap nginx roept ze zo aan, na het bijwerken van de database (KLAAR)."""
    text = "\n".join(SCRIPT)
    assert f"\n{NGINX_STAP}\n" in text and text.index(f"\n{NGINX_STAP}\n") > text.index("\nKLAAR=1\n")
    # Het bewaren loopt tot en met het blok voor een gok (NPM_GOK).
    assert STUKKEN.count('echo "HOMEPAGE_LAN_OPEN=1" >> "$CONF_DIR/homepage.env"\n  fi\nfi\n') == 1


def _install(tmp: Path, npm_ip: str = "", ip6: str = IP6, ip_rc: int = 0) -> dict:
    """Eén keer install.sh (het deel over het LAN); geeft de variabelen en de uitvoer."""
    bin_ = tmp / "bin"
    bin_.mkdir(exist_ok=True)
    (tmp / "ip6").write_text(ip6)
    (bin_ / "ip").write_text(f"#!/bin/sh\ncat '{tmp / 'ip6'}'\nexit {ip_rc}\n")
    (bin_ / "ip").chmod(0o755)
    (tmp / "stap.sh").write_text(f"set -euo pipefail\nCONF_DIR='{tmp / 'etc'}'\n{STUKKEN}\n"
                                 'for v in NPM_IP NPM_GOK BIJGEWERKT LAN_OPEN LAN_DICHT LAN_STAAT LAN_REDEN LAN_NETS '
                                 'LAN_GEO; do printf "%s=%s\\n" "$v" "${!v}"; done\n')
    r = subprocess.run(["bash", str(tmp / "stap.sh")], capture_output=True, text=True,
                       env={"PATH": f"{bin_}:{os.environ['PATH']}", "NPM_IP": npm_ip, "LC_ALL": "C.UTF-8"})
    assert r.returncode == 0, r.stdout + r.stderr
    uit = dict(line.split("=", 1) for line in r.stdout.splitlines() if re.match(r"^[A-Z_]+=", line))
    return {**uit, "uitvoer": r.stdout}


@pytest.fixture
def etc(tmp_path, monkeypatch):
    d = tmp_path / "etc"
    d.mkdir()
    monkeypatch.setattr(get_settings(), "nginx_file", d / "nginx")
    return d


def _env(etc: Path) -> list[str]:
    return [x for x in (etc / "homepage.env").read_text().splitlines() if x.startswith("HOMEPAGE_LAN_OPEN=")]


def _staat(etc: Path) -> dict:
    return dict(x.split("=", 1) for x in (etc / "nginx").read_text().splitlines())


def test_update_van_voor_de_regel_laat_het_lan_open(tmp_path, etc):
    """Het IP van NPM in een oude homepage.env is niet nagekeken: de update zet het LAN niet zelf dicht. Pas als
    Jonas HOMEPAGE_LAN_OPEN=0 zet, gaat het dicht, en dan blijft het dicht."""
    (etc / "homepage.env").write_text(OUD)
    v = _install(tmp_path)
    assert (v["NPM_IP"], v["NPM_GOK"], v["BIJGEWERKT"], v["LAN_DICHT"]) == ("192.168.0.245", "", "1", "0")
    assert _env(etc) == ["HOMEPAGE_LAN_OPEN=1"]
    assert _staat(etc)["lan"] == "open" and _staat(etc)["reden"] == "bijgewerkt"
    row = lan_row()
    assert row["state"] == "half" and row["todo"][0].startswith("Bijgewerkt van een installatie van voor deze regel")

    # Een volgende update zonder dat Jonas iets deed: nog altijd open, met dezelfde uitleg.
    v = _install(tmp_path)
    assert (v["BIJGEWERKT"], v["LAN_DICHT"], v["LAN_REDEN"]) == ("", "0", "bijgewerkt")
    assert _env(etc) == ["HOMEPAGE_LAN_OPEN=1"]

    # Werkt het via NPM: Jonas zet 0 en voert install.sh uit. Dicht, ook bij elke volgende update.
    env = etc / "homepage.env"
    env.write_text(env.read_text().replace("HOMEPAGE_LAN_OPEN=1", "HOMEPAGE_LAN_OPEN=0"))
    for _ in range(2):
        v = _install(tmp_path)
        assert (v["BIJGEWERKT"], v["LAN_DICHT"], v["LAN_STAAT"], v["LAN_REDEN"]) == ("", "1", "dicht", "")
        assert _env(etc) == ["HOMEPAGE_LAN_OPEN=0"] and _staat(etc)["lan"] == "dicht"
    assert lan_row()["state"] == "ok"

    # Daarna zelf weer open om te testen: de gewone uitleg, niet meer die van de update.
    env.write_text(env.read_text().replace("HOMEPAGE_LAN_OPEN=0", "HOMEPAGE_LAN_OPEN=1"))
    v = _install(tmp_path)
    assert (v["LAN_DICHT"], v["LAN_REDEN"]) == ("0", "lan-open")
    assert lan_row()["todo"][0].startswith("HOMEPAGE_LAN_OPEN=1 staat in")


def test_update_die_mislukt_in_de_stap_nginx(tmp_path, etc):
    """Mislukt de update in de stap nginx (nginx -t, een herstart, Ctrl+C) nadat het script al wist dat het een
    installatie van voor de regel is, dan zegt de volgende poging dat nog altijd: HOMEPAGE_LAN_OPEN=1 komt pas in
    homepage.env na de uitleg in /etc/homepage/nginx."""
    text = "\n".join(SCRIPT)
    assert text.index('[ -z "$BIJGEWERKT" ] ||') > text.index("printf 'lan=%s")
    (etc / "homepage.env").write_text(OUD)
    (tmp_path / "fout.sh").write_text(f"set -euo pipefail\nCONF_DIR='{etc}'\n"
                                      + STUKKEN.replace(NGINX_STAP, NGINX_STAP + "\nfalse"))
    bin_ = tmp_path / "bin"
    bin_.mkdir()
    (bin_ / "ip").write_text("#!/bin/sh\nexit 0\n")
    (bin_ / "ip").chmod(0o755)
    r = subprocess.run(["bash", str(tmp_path / "fout.sh")], capture_output=True, text=True,
                       env={"PATH": f"{bin_}:{os.environ['PATH']}", "NPM_IP": "", "LC_ALL": "C.UTF-8"})
    assert r.returncode != 0 and _env(etc) == [] and not (etc / "nginx").exists()
    v = _install(tmp_path)
    assert (v["BIJGEWERKT"], v["LAN_DICHT"], v["LAN_REDEN"]) == ("1", "0", "bijgewerkt")
    assert _env(etc) == ["HOMEPAGE_LAN_OPEN=1"] and _staat(etc)["reden"] == "bijgewerkt"


def test_nieuwe_installatie(tmp_path, etc):
    """Met NPM_IP: dicht. Zonder: de standaard is een gok en het LAN blijft open, ook bij de volgende update."""
    shutil.copy(DEPLOY / "homepage.env.example", etc / "homepage.env")
    v = _install(tmp_path, npm_ip="192.168.0.245")
    assert (v["NPM_GOK"], v["BIJGEWERKT"], v["LAN_DICHT"], v["LAN_STAAT"]) == ("", "", "1", "dicht")
    assert _env(etc) == ["HOMEPAGE_LAN_OPEN=0"]
    assert "HOMEPAGE_NPM_IP=192.168.0.245" in (etc / "homepage.env").read_text()

    shutil.copy(DEPLOY / "homepage.env.example", etc / "homepage.env")
    (etc / "nginx").unlink()
    v = _install(tmp_path)
    assert (v["NPM_GOK"], v["BIJGEWERKT"], v["LAN_DICHT"], v["LAN_REDEN"]) == ("1", "", "0", "npm-onbekend")
    assert _env(etc) == ["HOMEPAGE_LAN_OPEN=1"]
    v = _install(tmp_path)
    assert (v["NPM_GOK"], v["LAN_DICHT"], v["LAN_REDEN"]) == ("", "0", "npm-onbekend")


def test_heel_oude_installatie_zonder_npm_ip(tmp_path, etc):
    """Nog zonder HOMEPAGE_NPM_IP: het IP is een gok, één regel HOMEPAGE_LAN_OPEN=1."""
    (etc / "homepage.env").write_text(OUD.replace("HOMEPAGE_NPM_IP=192.168.0.245\n", ""))
    v = _install(tmp_path)
    assert (v["NPM_GOK"], v["LAN_DICHT"], v["LAN_REDEN"]) == ("1", "0", "npm-onbekend")
    assert _env(etc) == ["HOMEPAGE_LAN_OPEN=1"]


def test_extra_netwerken(tmp_path, etc):
    """Het netwerk van elk publiek IPv6-adres van de container, en HOMEPAGE_LAN_NETS: wat geen netwerk is of de
    container zelf bevat, met een waarschuwing overgeslagen; wat al privé is of er al staat, niet nog eens."""
    nets = ("2a02:1810:abcd:1200::/56 10.20.0.0/16,198.51.100.0/24  192.168.1.0/2 geen 127.0.0.0/24 ::/0 "
            "192.168.5.0/24 2a02::%eth0/64 10.20.0.0/16 2a02:1810:abcd:1234::/64 10.0.0.0/8;")
    (etc / "homepage.env").write_text(f'{OUD}HOMEPAGE_LAN_OPEN=0\nHOMEPAGE_LAN_NETS="{nets}"\n')
    v = _install(tmp_path)
    want = ["2a02:1810:abcd:1234::/64", "2a02:1810:abcd:1200::/56", "198.51.100.0/24"]
    assert v["LAN_NETS"] == " ".join(want)
    assert v["LAN_GEO"] == "".join(f"{n} lan; " for n in want)
    assert _staat(etc)["netten"] == " ".join(want) and v["LAN_DICHT"] == "1"
    for bad in ("192.168.1.0/2 is geen netwerk", "geen is geen netwerk", "127.0.0.0/24 bevat de container zelf",
                "::/0 bevat de container zelf", "2a02::%eth0/64 is geen netwerk", "10.0.0.0/8; is geen netwerk"):
        assert f"!! HOMEPAGE_LAN_NETS: {bad}" in v["uitvoer"], bad
    assert v["uitvoer"].count("!! ") == 6
    if NGINX:
        # Zo aanvaardt nginx het in de geo $homepage_peer.
        conf = render(tmp_path / "nginx", 18080, 18000, lan_nets=v["LAN_GEO"])
        r = subprocess.run([NGINX, "-t", "-p", str(tmp_path / "nginx"), "-c", str(conf)], capture_output=True,
                           text=True)
        assert r.returncode == 0 and "warn" not in r.stderr, r.stderr


@pytest.mark.parametrize("rc", [0, 1])
def test_geen_extra_netwerken(tmp_path, etc, rc):
    """Geen publiek IPv6-adres (of ip faalt) en geen HOMEPAGE_LAN_NETS: niets extra, en install.sh gaat gewoon door."""
    (etc / "homepage.env").write_text(f"{OUD}HOMEPAGE_LAN_OPEN=0\n")
    v = _install(tmp_path, ip6="", ip_rc=rc)
    assert (v["LAN_NETS"], v["LAN_GEO"], v["LAN_DICHT"]) == ("", "", "1")
    assert "!! " not in v["uitvoer"] and _staat(etc)["netten"] == ""
