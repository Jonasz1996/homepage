#!/usr/bin/env bash
# Installeert of werkt homepage bij in een Debian 12/13 LXC-container.
# Meestal via deploy/bootstrap.sh (haalt eerst de code op). Rechtstreeks, als root:
#   bash /opt/homepage/deploy/install.sh
# Opnieuw uitvoeren werkt alles bij; bestaande sleutels en data blijven staan.
#
# Bij een update worden de bibliotheken (een venv per requirements.lock) en de frontend (in frontend/dist.new) gebouwd
# terwijl de vorige versie nog draait. Pas daarna: diensten stoppen, kopie van de database, overschakelen, database
# bijwerken, diensten starten. Mislukt er tot en met het bijwerken van de database iets, dan komt de vorige versie
# terug (code, venv en frontend) en is de database niet veranderd.

# Alles staat tussen { en }: zo leest bash het hele script in voor het begint. Bij een fout zet het script de vorige
# versie van de code terug, ook van dit bestand; bash mag daarna niet verder lezen in dat andere bestand.
{
set -euo pipefail

APP_DIR=/opt/homepage
CONF_DIR=/etc/homepage
BK=/var/backups/homepage
LOG_DIR=/var/log/homepage
# Het certificaat voor https rechtstreeks op de container, en waar de sleutel van zijn CA even staat (in het geheugen;
# zie certificaat).
TLS_DIR=/etc/ssl/homepage
TLS_TMPFS=/dev/shm
# NPM_IP: het IP van Nginx Proxy Manager. Wordt bij de eerste keer bewaard in homepage.env en daarna daar gelezen.
NPM_IP="${NPM_IP:-$(sed -n 's/^HOMEPAGE_NPM_IP=//p' "$CONF_DIR/homepage.env" 2>/dev/null | tail -1 || true)}"
# Niet opgegeven en nog niet bewaard: dan is de standaard een gok, en blijft het LAN open (zie nginx hieronder).
NPM_GOK=""
[ -n "$NPM_IP" ] || { NPM_IP=192.168.0.245; NPM_GOK=1; }

say() { printf '\n\033[1;37m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

# Hoe ver de update is: dat bepaalt wat er bij een fout teruggezet wordt (zie bij_fout).
TERUG_NAAR="" GESTOPT="" GEWISSELD="" KLAAR="" REDEN="" VENV_NIEUW="" VENV_OUD="" VERSIE="" DUMP=""
ONDERBROKEN="" UITSTEL="" INSTALL_LOG="" TEE_PID=""
afbreken() { REDEN=$1; exit 1; }

# Het log afsluiten (zie hieronder bij het begin): de uitvoer weer rechtstreeks naar de terminal, en wachten tot tee
# alles geschreven heeft (hoogstens 5 s), zodat wie install.sh aanriep (bootstrap.sh, homepage-terugzetten) pas daarna
# verder schrijft.
# shellcheck disable=SC2317  # loopt via trap, dat ziet shellcheck niet
log_dicht() {
  [ -n "$TEE_PID" ] || return 0
  exec 1>&3 2>&4 3>&- 4>&-
  for _ in $(seq 50); do kill -0 "$TEE_PID" 2>/dev/null || break; sleep 0.1; done
  TEE_PID=""
}

# Onderbroken (Ctrl+C, de SSH-verbinding valt weg, kill): net als een fout, zodat bij_fout terugzet en de diensten weer
# start. Zonder dit stopt bash meteen en ziet de EXIT-trap $? = 0: dan bleven de diensten stilstaan.
# Tijdens het overschakelen en het bijwerken van de database (UITSTEL) pas als dat af is: lukt de migratie toch nog,
# dan moet de nieuwe versie blijven, en niet de vorige code op de nieuwe database.
# shellcheck disable=SC2317  # loopt via trap, dat ziet shellcheck niet
onderbroken() { REDEN="Onderbroken."; ONDERBROKEN=$1; [ -n "$UITSTEL" ] || exit "$1"; }

# Eén venv per requirements.lock en Python-versie (.venv-<hash>), .venv wijst naar de actieve. Bouwen kan dus terwijl
# alles draait, en een oudere versie vindt bij terugzetten haar eigen bibliotheken terug. Het merkteken .klaar komt er
# pas als pip helemaal gelukt is; zonder wordt de venv opnieuw gebouwd.
bouw_venv() {
  local lock="$APP_DIR/backend/requirements.lock" d
  VENV_NIEUW=".venv-$({ cat "$lock"; python3 --version; } | sha256sum | cut -c1-12)"
  d="$APP_DIR/$VENV_NIEUW"
  if [ -f "$d/.klaar" ]; then
    echo "Bibliotheken: $VENV_NIEUW bestaat al."
    return
  fi
  rm -rf "$d"
  python3 -m venv "$d"
  "$d/bin/pip" install -q --upgrade pip
  # Precies wat in de lock staat, niets anders; pip check controleert dat er niets ontbreekt.
  "$d/bin/pip" install -q --no-deps -r "$lock"
  "$d/bin/pip" check
  touch "$d/.klaar"
  echo "Bibliotheken: $VENV_NIEUW gebouwd."
}

# .venv in één keer naar een andere venv laten wijzen.
zet_venv() { ln -sfn "$1" "$APP_DIR/.venv.tmp" && mv -Tf "$APP_DIR/.venv.tmp" "$APP_DIR/.venv"; }

# Overschakelen op de nieuwe venv en frontend, met de diensten gestopt. De vorige blijven staan om naar terug te gaan.
wissel() {
  rm -rf "$APP_DIR/frontend/dist.vorige"
  GEWISSELD=1
  if [ -L "$APP_DIR/.venv" ]; then
    VENV_OUD=$(readlink "$APP_DIR/.venv")
  elif [ -d "$APP_DIR/.venv" ]; then
    # Van voor de venv per lock: een gewone map.
    rm -rf "$APP_DIR/.venv-vorige"
    mv "$APP_DIR/.venv" "$APP_DIR/.venv-vorige"
    VENV_OUD=.venv-vorige
  fi
  zet_venv "$VENV_NIEUW"
  [ ! -d "$APP_DIR/frontend/dist" ] || mv "$APP_DIR/frontend/dist" "$APP_DIR/frontend/dist.vorige"
  mv "$APP_DIR/frontend/dist.new" "$APP_DIR/frontend/dist"
}

# shellcheck disable=SC2317  # loopt via bij_fout (trap), dat ziet shellcheck niet
wissel_terug() {
  local f="$APP_DIR/frontend"
  if [ "$VENV_OUD" = .venv-vorige ]; then
    rm -f "$APP_DIR/.venv"
    mv "$APP_DIR/.venv-vorige" "$APP_DIR/.venv"
  elif [ -n "$VENV_OUD" ]; then
    zet_venv "$VENV_OUD"
  fi
  if [ -d "$f/dist.vorige" ]; then
    [ ! -d "$f/dist" ] || { rm -rf "$f/dist.new"; mv "$f/dist" "$f/dist.new"; }
    mv "$f/dist.vorige" "$f/dist"
  fi
}

# Bij een fout: terug naar wat er draaide. Tot en met het bijwerken van de database kan dat helemaal, want alle
# migraties lopen samen in één transactie (alembic/env.py): mislukt er één, dan is de database niet veranderd.
# Bij homepage-terugzetten niet: de database is dan al teruggezet, terugzetten.sh zegt wat er nu moet.
# shellcheck disable=SC2317  # loopt via trap, dat ziet shellcheck niet
bij_fout() {
  local rc=$?
  # Het terugzetten zelf niet onderbreken: nog een Ctrl+C, of een pipe (| tee) die al weg is.
  trap '' INT HUP TERM PIPE
  trap - EXIT
  set +e
  # Onderbroken terwijl certificaat bezig was: de sleutel van de CA mag niet blijven liggen.
  [ -z "${TLS_DIR:-}" ] || rm -rf "$TLS_DIR"/.nieuw.* "${TLS_TMPFS:-/dev/shm}"/homepage-ca.*
  [ "$rc" -ne 0 ] || { log_dicht; exit 0; }
  printf '\n\033[1;31m!! %s\033[0m\n' "${REDEN:-Er ging iets mis, zie hierboven.}"
  [ -z "$INSTALL_LOG" ] || warn "Alles van deze keer staat ook in $INSTALL_LOG."
  [ -z "${HOMEPAGE_TERUGZETTEN:-}" ] || { log_dicht; exit "$rc"; }
  if [ -z "$KLAAR" ]; then
    [ -z "$GEWISSELD" ] || wissel_terug
    [ -z "$TERUG_NAAR" ] || git -C "$APP_DIR" checkout -q -f --detach "$TERUG_NAAR" \
      || warn "De code kon niet terug naar ${TERUG_NAAR:0:7}."
    # Er is niets bijgewerkt, dus ook niets terug te zetten: homepage-terugzetten blijft bij de vorige update.
    [ -z "$DUMP" ] || rm -f "$DUMP" "$DUMP.tmp" "$DUMP.versie"
  fi
  [ -z "$GESTOPT" ] || systemctl start homepage-api homepage-worker homepage-syslog
  if [ -n "$KLAAR" ]; then
    warn "De database is al bijgewerkt, dus versie $VERSIE blijft staan. Los de fout op en voer het opnieuw uit."
    [ -z "$DUMP" ] || [ ! -f "$DUMP.versie" ] || warn "Of terug naar de vorige versie: homepage-terugzetten."
  elif [ -n "$TERUG_NAAR" ]; then
    warn "Update afgebroken: ${PREV_VERSIE:-de vorige versie} blijft draaien en de database is niet veranderd."
  else
    warn "Afgebroken, de database is niet veranderd. Opnieuw uitvoeren mag."
  fi
  log_dicht
  exit "$rc"
}

# Een installatie van voor HOMEPAGE_LAN_OPEN (homepage.env zonder die regel): het vorige script schreef altijd een
# HOMEPAGE_NPM_IP weg, ook de standaard als er geen opgegeven was. Dat IP is dus niet nagekeken en het LAN blijft open
# (HOMEPAGE_LAN_OPEN=1), anders sloot een verkeerd IP je bij deze update buiten. Dichtzetten (0) doe je zelf, als het
# dashboard via NPM werkt. Zet BIJGEWERKT; de regel komt pas in homepage.env als de uitleg in $CONF_DIR/nginx staat
# (op het einde van de stap nginx): mislukt de update daarvoor, dan ziet de volgende poging nog altijd een installatie
# van daarvoor.
lan_bijgewerkt() {
  BIJGEWERKT=""
  grep -q '^HOMEPAGE_LAN_OPEN=' "$CONF_DIR/homepage.env" || BIJGEWERKT=1
}

# Wat nginx het LAN toelaat (__LAN_DICHT__ in deploy/nginx-map.conf), met HOMEPAGE_LAN_OPEN uit homepage.env (al
# ingelezen). Zet LAN_OPEN, LAN_DICHT, en voor /etc/homepage/nginx LAN_STAAT en LAN_REDEN.
lan_keuze() {
  local vorige
  LAN_OPEN="" LAN_DICHT=1 LAN_STAAT=dicht LAN_REDEN=""
  case "${HOMEPAGE_LAN_OPEN:-0}" in 1|true|yes|ja|aan) LAN_OPEN=1 ;; esac
  # Was het IP van NPM een gok, of is het niet nagekeken (BIJGEWERKT): altijd open.
  [ -z "$NPM_GOK$BIJGEWERKT" ] || LAN_OPEN=1
  [ -n "$LAN_OPEN" ] || return 0
  LAN_DICHT=0 LAN_STAAT=open LAN_REDEN=lan-open
  if [ -n "$NPM_GOK" ]; then LAN_REDEN=npm-onbekend
  elif [ -n "$BIJGEWERKT" ]; then LAN_REDEN=bijgewerkt
  else
    # Zette dit script het LAN eerder zelf open, dan blijft die reden staan tot jij het dichtzet.
    vorige=$(sed -n 's/^reden=//p' "$CONF_DIR/nginx" 2>/dev/null || true)
    case "$vorige" in npm-onbekend|bijgewerkt) LAN_REDEN=$vorige ;; esac
  fi
}

# Wat voor nginx ook LAN is (__LAN_NETS__ in deploy/nginx-map.conf), naast de privé-adressen: het netwerk van elk
# globaal IPv6-adres van de container (toestellen op hetzelfde LAN met een publiek IPv6-adres) en HOMEPAGE_LAN_NETS
# uit homepage.env (al ingelezen). Wat geen netwerk is of de container zelf (127.0.0.0/8, ::1) bevat, slaat het over
# met een waarschuwing; wat al privé is, telt al. Zet LAN_NETS (de netwerken) en LAN_GEO (de regels voor nginx).
lan_netwerken() {
  local eigen uit regel
  eigen=$(ip -6 -o addr show scope global 2>/dev/null | awk '{print $4}' || true)
  uit=$(python3 -I - "${HOMEPAGE_LAN_NETS:-}" "$eigen" <<'PY'
import ipaddress
import re
import sys

ZELF = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "::1/128")]
PRIVE = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
                                           "fc00::/7", "fe80::/10")]
nets = []
for bron, waarde in ([("container", a) for a in sys.argv[2].split()]
                     + [("HOMEPAGE_LAN_NETS", a) for a in re.split(r"[\s,]+", sys.argv[1]) if a]):
    try:
        # Van de container: het netwerk van het adres. Zelf opgegeven: precies een netwerk (een tikfout als
        # 192.168.1.0/2 zou anders een kwart van het internet zijn).
        net = ipaddress.ip_interface(waarde).network if bron == "container" else ipaddress.ip_network(waarde)
        # Alleen cijfers, punten en dubbele punten (geen %zone): het komt zo in de configuratie van nginx.
        if not re.fullmatch(r"[0-9a-f.:]+/[0-9]+", str(net)):
            raise ValueError
    except ValueError:
        print(f"{bron}: {waarde} is geen netwerk zoals 2a02:1810:abcd:1200::/56 of 198.51.100.0/24, overgeslagen.")
        continue
    if any(net.overlaps(z) for z in ZELF):
        print(f"{bron}: {waarde} bevat de container zelf (127.0.0.0/8 of ::1), overgeslagen.")
        continue
    if net not in nets and not any(net.version == p.version and net.subnet_of(p) for p in PRIVE):
        nets.append(net)
for net in nets:
    print("net", net)
PY
)
  LAN_NETS="" LAN_GEO=""
  while IFS= read -r regel; do
    case "$regel" in
      "net "*) LAN_NETS+="${LAN_NETS:+ }${regel#net }" LAN_GEO+="${regel#net } lan; " ;;
      ?*) warn "$regel" ;;
    esac
  done <<< "$uit"
}

# Liggen in $TLS_DIR een certificaat, zijn sleutel en de CA die het ondertekende, en is het nog geldig?
certificaat_past() {
  local pub
  [ -s "$TLS_DIR/homepage.crt" ] && [ -s "$TLS_DIR/homepage.key" ] && [ -s "$TLS_DIR/homepage-ca.crt" ] \
    && openssl verify -CAfile "$TLS_DIR/homepage-ca.crt" -purpose sslserver "$TLS_DIR/homepage.crt" >/dev/null 2>&1 \
    && pub=$(openssl x509 -in "$TLS_DIR/homepage.crt" -noout -pubkey 2>/dev/null) && [ -n "$pub" ] \
    && [ "$pub" = "$(openssl pkey -in "$TLS_DIR/homepage.key" -pubout 2>/dev/null)" ]
}

# De drie nieuwe bestanden uit map $1 in $TLS_DIR zetten. Een Ctrl+C of een SSH-verbinding die wegvalt tussen twee mv's
# in liet anders een sleutel naast een ander certificaat staan, en daarmee start nginx niet meer, ook niet op poort 80.
certificaat_zetten() {
  local rc oud
  oud=$(trap -p INT HUP TERM)
  trap '' INT HUP TERM
  mv -f "$1/homepage.key" "$TLS_DIR/homepage.key" && mv -f "$1/homepage.crt" "$TLS_DIR/homepage.crt" \
    && mv -f "$1/homepage-ca.crt" "$TLS_DIR/homepage-ca.crt"
  rc=$?
  trap - INT HUP TERM
  eval "$oud"
  return "$rc"
}

# Het certificaat voor https rechtstreeks op de container (poort 443, deploy/nginx-tls.conf): een eigen CA en een
# servercertificaat, allebei 9999 dagen geldig, in $TLS_DIR. Het geldt voor de naam van de container, localhost,
# 127.0.0.1, ::1 en elk IPv4-adres van de container (geen IPv6: dat voorvoegsel kan veranderen). De CA mag alleen voor
# die adressen en die namen tekenen (nameConstraints; bij een naam ook voor namen eronder, zoals iets.<naam>), en haar
# sleutel bestaat alleen in het geheugen ($TLS_TMPFS) tot het certificaat ondertekend is. Zo kan niemand er een
# certificaat voor een andere site mee maken: homepage-ca.crt vertrouwen op je toestellen is alleen dit dashboard
# vertrouwen. Een nieuw certificaat, met een nieuwe CA
# die je opnieuw importeert, alleen als een van die namen of adressen ontbreekt (bv. een nieuw IP), het binnen 30 dagen
# verloopt, of een bestand ontbreekt of niet past.
# Zet TLS_OK (1: nginx kan https), TLS_NIEUW (1: net gemaakt), TLS_REDEN (waarom nieuw, als bijzin: "omdat ..."),
# TLS_FOUT (waarom het mislukte), TLS_VORIG (1: er was al een, die je misschien al importeerde) en TLS_VORIG_SHA1 (de
# vingerafdruk van de vorige CA, zoals Windows ze toont). Geeft 1 als maken mislukte; een vorig certificaat dat nog
# past, blijft dan staan (TLS_OK=1).
# Altijd als `certificaat || ...`: set -e geldt dan niet in de functie, dus elke stap kijkt zelf na.
certificaat() {
  local naam tmp ca cnf i=0 host=homepage
  local dns=(localhost) ips=(127.0.0.1 ::1)
  TLS_OK="" TLS_NIEUW="" TLS_REDEN="" TLS_FOUT="" TLS_VORIG="" TLS_VORIG_SHA1=""
  for naam in homepage.crt homepage.key homepage-ca.crt; do
    [ ! -e "$TLS_DIR/$naam" ] || TLS_VORIG=1
  done
  # Een naam (geen IP: alleen cijfers kan ook een naam zijn, maar niet in een certificaat naast IP's).
  naam=$(hostname 2>/dev/null || true)
  if [[ $naam =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ && $naam =~ [A-Za-z] && $naam != localhost ]]; then
    host=$naam
    dns+=("$naam")
  fi
  for naam in $(hostname -I 2>/dev/null || true); do
    if [[ $naam =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ && $naam != 127.* && " ${ips[*]} " != *" $naam "* ]]; then
      ips+=("$naam")
    fi
  done
  # Wat er nog ligt van een keer die onderbroken werd, met misschien de sleutel van een CA.
  rm -rf "$TLS_DIR"/.nieuw.* "$TLS_TMPFS"/homepage-ca.*
  if ! certificaat_past; then
    if [ -n "$TLS_VORIG" ]; then TLS_REDEN="het vorige niet meer paste"; else TLS_REDEN="er nog geen was"; fi
  elif ! openssl x509 -in "$TLS_DIR/homepage.crt" -noout -checkend 2592000 >/dev/null 2>&1 \
       || ! openssl x509 -in "$TLS_DIR/homepage-ca.crt" -noout -checkend 2592000 >/dev/null 2>&1; then
    TLS_REDEN="het vorige binnen 30 dagen verloopt"
  else
    # Alleen een uitdrukkelijk "NOT": andere uitvoer (een andere versie van openssl) mag niet bij elke update een
    # nieuwe CA maken.
    for naam in "${dns[@]}"; do
      case "$(openssl x509 -in "$TLS_DIR/homepage.crt" -noout -checkhost "$naam" 2>&1)" in
        *"does NOT match"*) TLS_REDEN="$naam niet in het vorige stond"; break ;;
      esac
    done
    for naam in "${ips[@]}"; do
      [ -z "$TLS_REDEN" ] || break
      case "$(openssl x509 -in "$TLS_DIR/homepage.crt" -noout -checkip "$naam" 2>&1)" in
        *"does NOT match"*) TLS_REDEN="$naam niet in het vorige stond" ;;
      esac
    done
  fi
  if [ -z "$TLS_REDEN" ]; then
    TLS_OK=1
    return 0
  fi
  if [ -s "$TLS_DIR/homepage-ca.crt" ]; then
    TLS_VORIG_SHA1=$(openssl x509 -in "$TLS_DIR/homepage-ca.crt" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//')
  fi

  # Alles in een map naast de bestanden (mv is dan één stap), de sleutel van de CA in het geheugen (tmpfs): zo komt ze
  # nooit op de schijf. Kan dat niet, dan naast de rest; ze is hoe dan ook weg zodra het certificaat ondertekend is.
  if ! install -d -m 755 "$TLS_DIR" || ! tmp=$(mktemp -d "$TLS_DIR/.nieuw.XXXXXX"); then
    TLS_FOUT="$TLS_DIR niet beschrijfbaar"
    if certificaat_past; then TLS_OK=1; fi
    return 1
  fi
  ca=$(mktemp -d "$TLS_TMPFS/homepage-ca.XXXXXX" 2>/dev/null) || ca=$tmp
  cnf="$tmp/openssl.cnf"
  {
    printf '[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = homepage\n'
    printf '[homepage_ca]\nbasicConstraints = critical, CA:TRUE, pathlen:0\n'
    printf 'keyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n'
    printf 'nameConstraints = critical, @homepage_grenzen\n[homepage_grenzen]\n'
    for naam in "${dns[@]}"; do i=$((i + 1)); printf 'permitted;DNS.%d = %s\n' "$i" "$naam"; done
    for naam in "${ips[@]}"; do
      i=$((i + 1))
      if [[ $naam == *:* ]]; then printf 'permitted;IP.%d = %s/ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n' "$i" "$naam"
      else printf 'permitted;IP.%d = %s/255.255.255.255\n' "$i" "$naam"; fi
    done
    printf '[homepage_server]\nbasicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature\n'
    printf 'extendedKeyUsage = serverAuth\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n'
    printf 'subjectAltName = @homepage_namen\n[homepage_namen]\n'
    for naam in "${dns[@]}"; do i=$((i + 1)); printf 'DNS.%d = %s\n' "$i" "$naam"; done
    for naam in "${ips[@]}"; do i=$((i + 1)); printf 'IP.%d = %s\n' "$i" "$naam"; done
  } > "$cnf"
  # Sleutels alleen voor root (umask 077). Datum en tijd in de naam van de CA: zo zie je bij het importeren welke de
  # nieuwe is, ook na twee op één dag. Een naam (CN) mag hoogstens 64 tekens hebben: van een lange hostname de eerste
  # 32.
  if ( umask 077 \
       && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$ca/ca.key" \
       && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$tmp/homepage.key" \
       && openssl req -x509 -new -config "$cnf" -extensions homepage_ca -key "$ca/ca.key" -sha256 -days 9999 \
            -set_serial "0x$(openssl rand -hex 16)" -subj "/O=homepage/CN=homepage CA ${host:0:32} $(date '+%F %T')" \
            -out "$tmp/homepage-ca.crt" \
       && openssl req -new -config "$cnf" -key "$tmp/homepage.key" -subj "/O=homepage/CN=$host" \
            -out "$tmp/homepage.csr" \
       && openssl x509 -req -in "$tmp/homepage.csr" -CA "$tmp/homepage-ca.crt" -CAkey "$ca/ca.key" -sha256 \
            -days 9999 -set_serial "0x$(openssl rand -hex 16)" -extfile "$cnf" -extensions homepage_server \
            -out "$tmp/homepage.crt" ) > "$tmp/uitvoer" 2>&1 \
     && rm -f "$ca/ca.key" \
     && openssl verify -x509_strict -CAfile "$tmp/homepage-ca.crt" -purpose sslserver "$tmp/homepage.crt" \
          >> "$tmp/uitvoer" 2>&1 \
     && chmod 644 "$tmp/homepage-ca.crt" "$tmp/homepage.crt" && chmod 600 "$tmp/homepage.key" \
     && certificaat_zetten "$tmp"; then
    TLS_OK=1 TLS_NIEUW=1
  else
    TLS_FOUT=$(tail -n 3 "$tmp/uitvoer" 2>/dev/null | tr '\n' ' ')
    if certificaat_past; then TLS_OK=1; fi
  fi
  rm -rf "$tmp" "$ca"
  [ -n "$TLS_NIEUW" ]
}

# Luistert er al iets anders dan deze nginx op poort 443? Schrijft wat (of "een ander programma" als ss het niet zegt),
# of niets. nginx -t merkt dat niet, en een reload zou dan stil de oude configuratie houden; na een herstart zou nginx
# helemaal niet meer starten, ook niet op poort 80. Van deze nginx is een socket als zijn master (/run/nginx.pid) erbij
# staat: een andere nginx (of openresty) telt als een ander programma. Zonder ss: niets.
poort_443_bezet() {
  local lijn wie master
  command -v ss >/dev/null 2>&1 || return 0
  master=$(cat /run/nginx.pid 2>/dev/null || true)
  while IFS= read -r lijn; do
    [ -n "$lijn" ] || continue
    if [[ $master =~ ^[0-9]+$ && $lijn == *"pid=$master,"* ]]; then continue; fi
    wie=""
    case "$lijn" in *'(("'*) wie=${lijn#*'(("'}; wie=${wie%%\"*} ;; esac
    printf '%s\n' "${wie:-een ander programma}"
    return 0
  done < <(ss -Hltnp 'sport = :443' 2>/dev/null || true)
}

# Na een nieuwe CA (certificaat met TLS_NIEUW en TLS_VORIG): wie de vorige vertrouwde, moet de nieuwe importeren.
nieuwe_ca_melden() {
  warn "Nieuw certificaat voor https, met een nieuwe CA, omdat $TLS_REDEN. Had je de vorige CA ergens\
 geïmporteerd${TLS_VORIG_SHA1:+ (vingerafdruk SHA-1 $TLS_VORIG_SHA1)}, verwijder die daar en importeer de nieuwe:\
 $TLS_DIR/homepage-ca.crt."
}

# Gebruikt homepage (HOMEPAGE_DATABASE_URL, al ingelezen) de PostgreSQL die dit script beheert: op deze machine, via
# de socket of localhost, op de poort waar psql als postgres op uitkomt? Schrijft 1 of niets.
db_lokaal() {
  HOMEPAGE_PG_POORT=$(runuser -u postgres -- psql -XAtq -c "SHOW port") python3 -I - <<'PY'
import os
from urllib.parse import parse_qs, urlsplit

u = urlsplit(os.environ.get("HOMEPAGE_DATABASE_URL") or "postgresql+asyncpg://homepage@/homepage")
q = parse_qs(u.query)
hosts = [h for h in [u.hostname or "", *q.get("host", [])] if h]
try:
    port = u.port or int(q.get("port", ["5432"])[0])
except ValueError:
    port = None
lokaal = all(h.startswith("/") or h in ("localhost", "127.0.0.1", "::1") for h in hosts)
print("1" if lokaal and str(port) == os.environ["HOMEPAGE_PG_POORT"] else "")
PY
}

# Genoeg verbindingen in PostgreSQL voor de drie diensten: hun pools samen (HOMEPAGE_DB_POOL_API, _WORKER en _SYSLOG uit
# homepage.env, al ingelezen; standaard 20 + 40 + 5, zie pool_max in backend/app/db.py) plus VERBINDINGEN_MARGE voor
# pg_dump, de migraties, psql en de test van de back-up. Wat PostgreSQL voor superusers achterhoudt
# (superuser_reserved_connections, reserved_connections), krijgt homepage niet. Te weinig: max_connections hoger
# (ALTER SYSTEM, PostgreSQL herstart), maar alleen op de PostgreSQL van dit script (db_lokaal); anders een
# waarschuwing. Nooit lager.
VERBINDINGEN_MARGE=10
db_verbindingen() {
  local n pools=0 max res nodig nieuw auto
  for n in "${HOMEPAGE_DB_POOL_API:-20}" "${HOMEPAGE_DB_POOL_WORKER:-40}" "${HOMEPAGE_DB_POOL_SYSLOG:-5}"; do
    case "$n" in
      ''|*[!0-9]*) warn "HOMEPAGE_DB_POOL_*=$n in $CONF_DIR/homepage.env is geen getal: max_connections niet nagekeken."
                   return 0 ;;
    esac
    n=$((10#$n))
    pools=$((pools + (n > 0 ? n : 1)))
  done
  if ! read -r max res < <(runuser -u postgres -- psql -XAtq -F ' ' -c "SELECT current_setting('max_connections'),
      current_setting('superuser_reserved_connections')::int
      + coalesce(current_setting('reserved_connections', true), '0')::int") \
     || ! [[ "$max" =~ ^[0-9]+$ && "$res" =~ ^[0-9]+$ ]]; then
    warn "max_connections van PostgreSQL niet te lezen: niet nagekeken."
    return 0
  fi
  nodig=$((pools + VERBINDINGEN_MARGE + res))
  if [ "$max" -ge "$nodig" ]; then
    echo "max_connections $max: genoeg voor de diensten ($pools) en $VERBINDINGEN_MARGE extra."
    return 0
  fi
  nieuw=$(( (nodig + 9) / 10 * 10 ))
  if [ -z "$(db_lokaal)" ]; then
    warn "De diensten openen samen tot $pools verbindingen met de database (HOMEPAGE_DB_POOL_* in $CONF_DIR/homepage.env),\
 max_connections is $max: zet het op die server op minstens $nieuw, of verklein de pools."
    return 0
  fi
  echo "max_connections van $max naar $nieuw: de diensten openen samen tot $pools verbindingen (HOMEPAGE_DB_POOL_*)."
  # Wat ALTER SYSTEM verandert, staat in postgresql.auto.conf: eerst een kopie, om terug te kunnen.
  auto="$(runuser -u postgres -- psql -XAtq -c "SHOW data_directory")/postgresql.auto.conf"
  if ! cp -p "$auto" "$auto.homepage-vorige"; then
    warn "max_connections niet aangepast ($auto niet te kopiëren): zet het zelf op minstens $nieuw."
    return 0
  fi
  if ! runuser -u postgres -- psql -XAtq -c "ALTER SYSTEM SET max_connections = $nieuw"; then
    rm -f "$auto.homepage-vorige"
    warn "max_connections niet aangepast (zie hierboven): zet het zelf op minstens $nieuw."
    return 0
  fi
  if systemctl restart postgresql && pg_klaar; then
    rm -f "$auto.homepage-vorige"
  else
    # Start PostgreSQL er niet mee (bv. te weinig gedeeld geheugen): terug zoals het was.
    mv -f "$auto.homepage-vorige" "$auto"
    systemctl restart postgresql || true
    pg_klaar || true
    warn "PostgreSQL startte niet met max_connections = $nieuw en staat weer op $max. Verklein de pools\
 (HOMEPAGE_DB_POOL_* in $CONF_DIR/homepage.env), of kijk na waarom: journalctl -u 'postgresql*' -n 50."
  fi
}

# pg_dump van <database> naar <bestand>, eerst naar <bestand>.tmp. De diensten staan dan stil, de achtergrondtaken van
# TimescaleDB (comprimeren, opruimen) niet: vervangen ze een chunk net als pg_dump begint, dan stopt het met "relation
# ... does not exist". Dat is pech met het moment, dus nog eens, tot 3 keer (zoals homepage-backup.sh). Elke andere
# fout meteen.
kopie_maken() {
  local db=$1 f=$2 poging fout
  for poging in 1 2 3; do
    if fout=$(runuser -u postgres -- pg_dump -Fc -f "$f.tmp" "$db" 2>&1); then
      [ -z "$fout" ] || printf '%s\n' "$fout" >&2
      mv "$f.tmp" "$f"
      return
    fi
    case "$fout" in
      *'relation "'*'" does not exist'*|*"could not open relation with OID"*|*"cache lookup failed for relation"*) ;;
      *) break ;;
    esac
    if [ "$poging" -lt 3 ]; then
      printf '%s\nEen tabel veranderde tijdens de kopie (TimescaleDB), opnieuw.\n' "$fout" >&2
      sleep "${KOPIE_WACHT:-5}"
    fi
  done
  printf '%s\n' "$fout" >&2
  rm -f "$f.tmp"
  return 1
}

# Wacht tot PostgreSQL verbindingen aanneemt (hoogstens 30 s).
pg_klaar() {
  for _ in $(seq 30); do
    runuser -u postgres -- psql -XAtq -c "SELECT 1" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

# Draaien de diensten na het herstarten? De API: antwoordt /api/ping (hoogstens 20 s). De worker en de
# syslog-ontvanger: actief, en minstens 10 s na de start nog altijd zonder herstart. Met Restart=always (RestartSec=5)
# staat een proces dat telkens meteen crasht tussen twee pogingen even op "activating", maar soms net op "active":
# NRestarts telt dan wel op. Wat niet draait: de opdracht om te zien waarom. Draait de API niet, dan mislukt de
# installatie (bootstrap.sh en homepage-terugzetten zien dat); de worker en de syslog-ontvanger geven een waarschuwing.
diensten_nakijken() {
  local start=$SECONDS d api="" wacht
  local -A n0
  for d in homepage-worker homepage-syslog; do
    n0[$d]=$(systemctl show -p NRestarts --value "$d" 2>/dev/null || true)
  done
  for _ in $(seq 20); do
    if curl -fsS http://127.0.0.1/api/ping >/dev/null 2>&1; then api=1; break; fi
    sleep 1
  done
  wacht=$((10 - (SECONDS - start)))
  [ "$wacht" -le 0 ] || sleep "$wacht"
  for d in homepage-worker homepage-syslog; do
    if [ "$(systemctl is-active "$d" 2>/dev/null)" = active ] \
       && [ "$(systemctl show -p NRestarts --value "$d" 2>/dev/null || true)" = "${n0[$d]}" ]; then
      echo "$d draait."
    else
      warn "$d draait niet (of herstart telkens opnieuw): journalctl -u $d -n 100 --no-pager"
    fi
  done
  if [ -n "$api" ]; then
    echo "API draait."
  else
    afbreken "De API reageert niet ($(systemctl is-active homepage-api 2>/dev/null || true)):\
 journalctl -u homepage-api -n 100 --no-pager (alles samen: homepage-diagnose)."
  fi
}

[ "$(id -u)" -eq 0 ] || { echo "Voer uit als root."; exit 1; }
[ -d "$APP_DIR/backend" ] || { echo "Verwacht de repository in $APP_DIR."; exit 1; }
# Alles wat het script schrijft, komt ook in $LOG_DIR/install-<datum>.log: een mislukte update is zo achteraf na te
# lezen (homepage-diagnose neemt het nieuwste mee). De 10 nieuwste blijven. Alleen de uitvoer gaat via tee: vragen
# lezen nog altijd van de terminal, en de exitcode blijft die van het script zelf. tee negeert Ctrl+C en een
# wegvallende SSH-verbinding: wat er dan gebeurt, beslist het script zelf (onderbroken), en het log loopt door. Het
# log bestaat al voor tee start (alleen voor root: de setup-code staat erin), zodat het opruimen het meetelt.
if install -d -m 750 "$LOG_DIR" 2>/dev/null; then
  INSTALL_LOG="$LOG_DIR/install-$(date +%Y%m%d-%H%M%S).log"
  install -m 600 /dev/null "$INSTALL_LOG"
  exec 3>&1 4>&2
  exec > >(trap '' INT HUP TERM; exec tee -a "$INSTALL_LOG") 2>&1
  TEE_PID=$!
  trap log_dicht EXIT
  find "$LOG_DIR" -maxdepth 1 -name 'install-*.log' | sort -r | tail -n +11 | xargs -r rm -f
fi
# shellcheck source=/dev/null
. /etc/os-release
case "$VERSION_CODENAME" in
  bookworm|trixie) ;;
  *) warn "Getest op Debian 12 (bookworm) en 13 (trixie), dit is $PRETTY_NAME." ;;
esac

# Welke versie draaide er tot nu toe: daar gaat een mislukte update naar terug (bootstrap.sh heeft de nieuwe code al
# opgehaald), en homepage-terugzetten ook.
PREV_COMMIT=$(sed -n 's/^commit=//p' "$CONF_DIR/versie" 2>/dev/null || true)
PREV_VERSIE=$(sed -n 's/^versie=//p' "$CONF_DIR/versie" 2>/dev/null || true)
if [ -z "$PREV_COMMIT" ] && [ -n "${HOMEPAGE_PREV_COMMIT:-}" ]; then
  PREV_COMMIT=$HOMEPAGE_PREV_COMMIT
  PREV_VERSIE=$(git -C "$APP_DIR" describe --tags --always "$PREV_COMMIT" 2>/dev/null || true)
fi
NOW_COMMIT=$(git -C "$APP_DIR" rev-parse HEAD 2>/dev/null || true)
if [ -z "${HOMEPAGE_TERUGZETTEN:-}" ] && [ -n "$PREV_COMMIT" ] && [ "$PREV_COMMIT" != "$NOW_COMMIT" ]; then
  TERUG_NAAR=$PREV_COMMIT
fi
trap bij_fout EXIT
trap 'onderbroken 129' HUP
trap 'onderbroken 130' INT
trap 'onderbroken 143' TERM

say "Pakketten installeren"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q postgresql nginx python3-venv python3-dev build-essential nodejs npm \
  curl gnupg ca-certificates openssl iputils-ping

PG_VER=$(pg_config --version 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)
[ -n "$PG_VER" ] || PG_VER=$(find /usr/lib/postgresql -mindepth 1 -maxdepth 1 -printf "%f\n" | sort -n | tail -1)

say "TimescaleDB installeren (nodig vanaf fase 3, monitoring)"
if ! dpkg -s "timescaledb-2-postgresql-$PG_VER" >/dev/null 2>&1; then
  if curl -fsSL https://packagecloud.io/timescale/timescaledb/gpgkey | gpg --dearmor --yes -o /usr/share/keyrings/timescaledb.gpg \
     && echo "deb [signed-by=/usr/share/keyrings/timescaledb.gpg] https://packagecloud.io/timescale/timescaledb/debian/ $VERSION_CODENAME main" \
        > /etc/apt/sources.list.d/timescaledb.list \
     && apt-get update -q \
     && apt-get install -y -q "timescaledb-2-postgresql-$PG_VER"; then
    timescaledb-tune --quiet --yes >/dev/null || true
    systemctl restart postgresql
  else
    rm -f /etc/apt/sources.list.d/timescaledb.list
    warn "TimescaleDB kon niet geïnstalleerd worden. Alles werkt en blijft even lang bewaard (losse checks 90 dagen, per uur opgeteld 400 dagen, metingen 180 dagen); het dashboard ruimt dan zelf op, alleen zonder compressie: de database wordt groter."
  fi
fi

say "Gebruiker en database"
id homepage >/dev/null 2>&1 || useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin homepage
systemctl enable --now postgresql
runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='homepage'" | grep -q 1 \
  || runuser -u postgres -- createuser homepage
runuser -u postgres -- psql -tAc "SELECT 1 FROM pg_database WHERE datname='homepage'" | grep -q 1 \
  || runuser -u postgres -- createdb -O homepage homepage
if dpkg -s "timescaledb-2-postgresql-$PG_VER" >/dev/null 2>&1; then
  runuser -u postgres -- psql -d homepage -qc "CREATE EXTENSION IF NOT EXISTS timescaledb" || true
fi

say "Configuratie in $CONF_DIR"
install -d -m 750 -o root -g homepage "$CONF_DIR"
if [ ! -f "$CONF_DIR/secret.key" ]; then
  # Fernet-sleutel: 32 willekeurige bytes, urlsafe base64.
  head -c 32 /dev/urandom | base64 | tr '+/' '-_' > "$CONF_DIR/secret.key"
  chown root:homepage "$CONF_DIR/secret.key"; chmod 640 "$CONF_DIR/secret.key"
fi
if [ ! -f "$CONF_DIR/setup-token" ]; then
  openssl rand -hex 12 > "$CONF_DIR/setup-token"
  chown root:homepage "$CONF_DIR/setup-token"; chmod 640 "$CONF_DIR/setup-token"
fi
if [ ! -f "$CONF_DIR/homepage.env" ]; then
  install -m 640 -o root -g homepage "$APP_DIR/deploy/homepage.env.example" "$CONF_DIR/homepage.env"
fi

# Oudere installaties: "true" of "false" wordt "auto" (Secure via HTTPS, maar testen op http://IP werkt ook).
sed -i -E 's/^HOMEPAGE_COOKIE_SECURE=(true|false)$/HOMEPAGE_COOKIE_SECURE=auto/' "$CONF_DIR/homepage.env"

# Ping-checks draaien als gewone gebruiker: ICMP-sockets toelaten (ook in een unprivileged LXC).
echo 'net.ipv4.ping_group_range = 0 2147483647' > /etc/sysctl.d/60-homepage-ping.conf
sysctl -q -w net.ipv4.ping_group_range="0 2147483647" 2>/dev/null || warn "ping_group_range niet gezet; ping-checks kunnen falen"

# NPM-IP bewaren zodat een volgende update het niet terugzet naar de standaard.
if grep -q '^HOMEPAGE_NPM_IP=' "$CONF_DIR/homepage.env"; then
  sed -i "s/^HOMEPAGE_NPM_IP=.*/HOMEPAGE_NPM_IP=$NPM_IP/" "$CONF_DIR/homepage.env"
else
  echo "HOMEPAGE_NPM_IP=$NPM_IP" >> "$CONF_DIR/homepage.env"
fi
# Was het IP van NPM een gok, dan blijft het LAN open, ook na volgende updates: anders sloot een verkeerd IP je bij
# de volgende update buiten. Dichtzetten (HOMEPAGE_LAN_OPEN=0) doe je zelf, als het dashboard via NPM werkt.
if [ -n "$NPM_GOK" ]; then
  if grep -q '^HOMEPAGE_LAN_OPEN=' "$CONF_DIR/homepage.env"; then
    sed -i "s/^HOMEPAGE_LAN_OPEN=.*/HOMEPAGE_LAN_OPEN=1/" "$CONF_DIR/homepage.env"
  else
    echo "HOMEPAGE_LAN_OPEN=1" >> "$CONF_DIR/homepage.env"
  fi
fi

# Map voor de dagelijkse back-up: postgres schrijft, de worker (groep homepage) leest om ze te controleren.
install -d -m 750 -o postgres -g homepage /var/backups/homepage

# IP van deze container voor de rsyslog-configuratie op andere machines (fase 6).
if ! grep -q '^HOMEPAGE_SYSLOG_TARGET=' "$CONF_DIR/homepage.env"; then
  echo "HOMEPAGE_SYSLOG_TARGET=$(hostname -I | awk '{print $1}')" >> "$CONF_DIR/homepage.env"
fi

# Eerst bouwen terwijl de vorige versie nog draait, pas dan overschakelen: mislukt de build, dan blijft alles zoals het was.
say "Backend (Python)"
bouw_venv
# Van vroeger, toen de backend zelf in de venv geïnstalleerd werd. De diensten lezen de code uit backend/.
rm -rf "$APP_DIR/backend/build" "$APP_DIR/backend/homepage.egg-info"
chown -R root:root "$APP_DIR"

say "Frontend bouwen"
# In dist.new: nginx serveert intussen nog dist.
(cd "$APP_DIR/frontend" && npm ci --no-audit --no-fund --loglevel=error \
  && npm run build --silent -- --outDir dist.new --emptyOutDir)

set -a
# shellcheck source=/dev/null
. "$CONF_DIR/homepage.env"
set +a
say "Database bijwerken"
if [ -n "${HOMEPAGE_TERUGZETTEN:-}" ]; then
  echo "Terugzetten: de database is al teruggezet, geen nieuwe kopie."
elif runuser -u postgres -- psql -d homepage -tAc "SELECT 1 FROM alembic_version" 2>/dev/null | grep -q 1; then
  # Bestaande installatie: eerst een kopie, zodat een mislukte migratie terug te draaien is.
  # Dezelfde versie opnieuw (bv. na een fout na het bijwerken van de database): die staat al op deze versie en
  # verandert niet, dus geen kopie. Zo blijft de kopie van de echte update die waar homepage-terugzetten naartoe gaat.
  ZELFDE=""
  if [ -n "$PREV_COMMIT" ] && [ "$PREV_COMMIT" = "$NOW_COMMIT" ]; then
    ZELFDE=1
    echo "Dezelfde versie opnieuw: de database verandert niet, geen kopie nodig."
  else
    # Er blijven 2 kopieën van voor een update staan: straks deze, en de nieuwste die bij een update hoort (met de
    # versie ernaast, of al teruggezet). De rest eerst weg, dan is er meer plaats.
    KEEP=$(find "$BK" -maxdepth 1 -name 'voor-update-*.dump' -printf '%T@ %p\n' | sort -rn | cut -d' ' -f2- \
      | while read -r f; do if [ -f "$f.versie" ] || [ -f "$f.teruggezet" ]; then echo "$f"; break; fi; done)
    [ -n "$KEEP" ] || KEEP=$(find "$BK" -maxdepth 1 -name 'voor-update-*.dump' -printf '%T@ %p\n' | sort -rn \
      | head -1 | cut -d' ' -f2-)
    find "$BK" -maxdepth 1 -name 'voor-update-*.dump' | while read -r f; do
      [ "$f" = "$KEEP" ] || rm -f "$f" "$f.versie" "$f.teruggezet" "$f.bezig"
    done
    # De dagelijkse kopieën: de 5 nieuwste, zoals homepage-backup.sh (vroeger bleven ze 14 dagen staan).
    find "$BK" -maxdepth 1 -name 'homepage-????-??-??.dump' | sort -r | tail -n +6 | xargs -r rm -f
    # Plaats genoeg voor de kopie? Anders afbreken voor er iets stilvalt. Geschat: de gegevens zonder de indexen
    # (die gaan niet mee in een kopie) plus 64 MB. Een kopie (pg_dump -Fc, gecomprimeerd) is meestal kleiner.
    NODIG=$(runuser -u postgres -- psql -d homepage -tAc "SELECT pg_database_size(current_database())
      - coalesce((SELECT sum(pg_relation_size(oid)) FROM pg_class WHERE relkind = 'i'), 0) + 64 * 1024 * 1024")
    VRIJ=$(df --output=avail -B1 "$BK" | tail -1 | tr -d ' ')
    if [ "$VRIJ" -lt "$NODIG" ]; then
      afbreken "Te weinig plaats in $BK voor een kopie van de database: $((VRIJ >> 20)) MB vrij, ongeveer \
$((NODIG >> 20)) MB nodig. Wat plaats inneemt: du -sh $BK/* /var/lib/postgresql"
    fi
  fi
  # Stil tijdens de kopie en de migratie: wat de diensten daartussen nog schrijven, zou anders verloren gaan.
  echo "Diensten stoppen."
  GESTOPT=1
  systemctl stop homepage-api homepage-worker homepage-syslog
  if [ -z "$ZELFDE" ]; then
    DUMP="$BK/voor-update-$(date +%Y%m%d-%H%M%S).dump"
    if ! kopie_maken homepage "$DUMP"; then
      afbreken "Kopie van de database mislukt."
    fi
    echo "Kopie van de database: $DUMP"
    # Naast de kopie: welke versie erbij hoort (onbekend bij een update van een heel oude installatie), en voor
    # homepage-terugzetten de versie van TimescaleDB (de extensie moet in dezelfde versie terugkomen) en hoe groot de
    # database was (zoveel plaats vraagt het terugzetten). Leeg als het niet te lezen is: dan schat terugzetten zelf.
    if [ -n "$PREV_COMMIT" ]; then
      TSV=$(runuser -u postgres -- psql -XAtq -d homepage \
        -c "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'" || true)
      GROOTTE=$(runuser -u postgres -- psql -XAtq -d homepage -c "SELECT pg_database_size(current_database())" || true)
      printf 'commit=%s\nversie=%s\ntimescaledb=%s\ngrootte=%s\n' "$PREV_COMMIT" "${PREV_VERSIE:-${PREV_COMMIT:0:7}}" \
        "$TSV" "$GROOTTE" > "$DUMP.versie"
    fi
  fi
fi
# Onderbreken pas na het onthouden van de versie (zie onderbroken). De migratie zelf stopt wel bij Ctrl+C: dan is de
# database niet veranderd en zet bij_fout alles terug.
UITSTEL=1
wissel
if ! (cd "$APP_DIR/backend" && runuser -u homepage -- env HOMEPAGE_DATABASE_URL="$HOMEPAGE_DATABASE_URL" \
  "$APP_DIR/.venv/bin/alembic" upgrade head); then
  afbreken "Database bijwerken mislukt."
fi
KLAAR=1
# Vanaf hier blijft deze versie staan, ook als er nog iets mislukt (nginx, de diensten): bij_fout raadt dan
# homepage-terugzetten aan. Dus meteen de commando's om te herstellen van deze versie, niet pas bij Services: tot dan
# was het dat van de vorige versie (bij een update van voor homepage-dumpinfo één dat bij een grote database stopt als
# die al weg is).
# Een update terugdraaien: vorige versie plus de kopie van de database van vlak voor die update.
install -m 755 "$APP_DIR/deploy/terugzetten.sh" /usr/local/sbin/homepage-terugzetten
# Welke fouten van pg_restore tellen (ook voor de maandelijkse test van de back-up).
install -m 755 "$APP_DIR/deploy/herstelfouten.sh" /usr/local/sbin/homepage-herstelfouten
# Of een dump TimescaleDB nodig heeft: ook voor homepage-terugzetten en de test van de back-up.
install -m 755 "$APP_DIR/deploy/dumpinfo.sh" /usr/local/sbin/homepage-dumpinfo
# Alles in één tekstbestand bij een probleem, ook als het dashboard zelf niet start.
install -m 755 "$APP_DIR/deploy/diagnose.sh" /usr/local/sbin/homepage-diagnose

# Vanaf hier draait de nieuwe versie. Wat er nu draait: het dashboard toont het (en wat er nieuw is), een volgende
# update en homepage-terugzetten gebruiken het.
VERSIE=$(git -C "$APP_DIR" describe --tags --always 2>/dev/null || echo onbekend)
KANAAL="${HOMEPAGE_KANAAL:-$(sed -n 's/^kanaal=//p' "$CONF_DIR/versie" 2>/dev/null || true)}"
printf 'versie=%s\ncommit=%s\nkanaal=%s\ndatum=%s\n' "$VERSIE" "$NOW_COMMIT" "${KANAAL:-nieuwste}" "$(date -Iseconds)" \
  > "$CONF_DIR/versie"
chgrp homepage "$CONF_DIR/versie" && chmod 640 "$CONF_DIR/versie"
UITSTEL=""
[ -z "$ONDERBROKEN" ] || exit "$ONDERBROKEN"
# Alleen de actieve venv en die van daarvoor blijven staan (om terug te zetten).
for d in "$APP_DIR"/.venv-*; do
  [ -d "$d" ] || continue
  case "${d##*/}" in "$VENV_NIEUW"|"$VENV_OUD") ;; *) rm -rf "$d" ;; esac
done

say "nginx"
# Alleen NPM en de container zelf, van het LAN alleen push-monitors, webhooks en /api/healthz (deploy/nginx-map.conf).
# HOMEPAGE_LAN_OPEN=1 in homepage.env (hierboven ingelezen): het hele LAN mag alles, om op http://IP te testen.
# Was het IP van NPM een gok of niet nagekeken: altijd open (lan_bijgewerkt, lan_keuze).
lan_bijgewerkt
lan_keuze
lan_netwerken
[ -z "$LAN_NETS" ] || echo "Ook LAN voor nginx: $LAN_NETS"
NPM_IP_RE="${NPM_IP//./\\\\.}"
sed "s/__NPM_IP_RE__/$NPM_IP_RE/; s/__LAN_DICHT__/$LAN_DICHT/; s#__LAN_NETS__#$LAN_GEO#" \
  "$APP_DIR/deploy/nginx-map.conf" > /etc/nginx/conf.d/homepage-map.conf
install -D -m 644 "$APP_DIR/deploy/nginx-headers.conf" /etc/nginx/snippets/homepage-headers.conf
# Ook https op poort 443, met een eigen certificaat van 9999 dagen (zie certificaat). Zonder certificaat alleen http
# zoals vroeger: dan is homepage-tls.conf leeg.
# Een nieuwe CA meteen melden, niet pas op het einde: mislukt er daarna nog iets, dan zegt de volgende keer het niet
# meer (het certificaat past dan).
if certificaat; then
  [ -z "$TLS_NIEUW" ] || [ -z "$TLS_VORIG" ] || nieuwe_ca_melden
elif [ -n "$TLS_OK" ]; then
  warn "Een nieuw certificaat voor https was nodig omdat $TLS_REDEN, maar het lukte niet\
 (${TLS_FOUT:-onbekende fout}). Het vorige blijft in gebruik."
else
  warn "Geen certificaat voor https (${TLS_FOUT:-onbekende fout}): nginx luistert alleen op http (poort 80). Wijst\
 NPM naar https://<IP van de container>:443, zet het dan terug op http en poort 80."
fi
# HTTPS_AAN: nginx luistert echt op 443 (een certificaat, en de poort is vrij).
HTTPS_AAN="" TLS_BEZET=""
[ -z "$TLS_OK" ] || TLS_BEZET=$(poort_443_bezet)
if [ -n "$TLS_BEZET" ]; then
  warn "Poort 443 is al in gebruik door $TLS_BEZET: nginx luistert daarom alleen op http (poort 80). Het certificaat\
 staat klaar in $TLS_DIR. Maak poort 443 vrij en voer dit script opnieuw uit voor https."
fi
if [ -n "$TLS_OK" ] && [ -z "$TLS_BEZET" ]; then
  install -m 644 "$APP_DIR/deploy/nginx-tls.conf" /etc/nginx/snippets/homepage-tls.conf
  HTTPS_AAN=1
else
  : > /etc/nginx/snippets/homepage-tls.conf
fi
sed "s/__NPM_IP__/$NPM_IP/" "$APP_DIR/deploy/nginx.conf" > /etc/nginx/sites-available/homepage
# Zonder IPv6 in de container kan nginx niet op [::] luisteren.
[ -e /proc/net/if_inet6 ] || sed -i '/listen \[::\]/d' /etc/nginx/sites-available/homepage \
  /etc/nginx/snippets/homepage-tls.conf
ln -sf /etc/nginx/sites-available/homepage /etc/nginx/sites-enabled/homepage
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl reload nginx || systemctl restart nginx
# Wat nginx nu toelaat, voor de instellingen in het dashboard (rij "Dashboard alleen via NPM").
printf 'lan=%s\nreden=%s\nnpm=%s\nnetten=%s\ndatum=%s\n' "$LAN_STAAT" "$LAN_REDEN" "$NPM_IP" "$LAN_NETS" \
  "$(date -Iseconds)" > "$CONF_DIR/nginx"
chgrp homepage "$CONF_DIR/nginx" && chmod 640 "$CONF_DIR/nginx"
[ -z "$BIJGEWERKT" ] || echo "HOMEPAGE_LAN_OPEN=1" >> "$CONF_DIR/homepage.env"

say "Services"
install -m 644 "$APP_DIR/deploy/homepage-api.service" "$APP_DIR/deploy/homepage-worker.service" \
  "$APP_DIR/deploy/homepage-syslog.service" /etc/systemd/system/
install -m 644 "$APP_DIR/deploy/homepage-backup.service" "$APP_DIR/deploy/homepage-backup.timer" /etc/systemd/system/
install -m 755 "$APP_DIR/deploy/homepage-backup.sh" /usr/local/sbin/homepage-backup
# Elke 1e van de maand de nieuwste back-up terugzetten in een testdatabase (die daarna weer weg is), als postgres.
# Welke fouten van pg_restore tellen, staat in homepage-herstelfouten (hierboven, na het bijwerken van de database):
# homepage-terugzetten gebruikt het ook.
install -m 644 "$APP_DIR/deploy/homepage-backuptest.service" "$APP_DIR/deploy/homepage-backuptest.timer" \
  /etc/systemd/system/
install -m 755 "$APP_DIR/deploy/homepage-backuptest.sh" /usr/local/sbin/homepage-backuptest
systemctl daemon-reload
systemctl enable --now homepage-backup.timer homepage-backuptest.timer
systemctl enable homepage-api homepage-worker homepage-syslog
db_verbindingen
systemctl restart homepage-api homepage-worker homepage-syslog
diensten_nakijken

IP=$(hostname -I | awk '{print $1}')
say "Klaar (versie $VERSIE, ${KANAAL:-nieuwste})"
cat <<EOF
Dashboard: open het via zijn naam in Nginx Proxy Manager (bv. https://home.jbogaert.be): een HTTPS-host naar
http://$IP:80 met "Websockets Support" aan.
EOF
if [ -n "$HTTPS_AAN" ]; then
  TLS_TOT=$(openssl x509 -in "$TLS_DIR/homepage.crt" -noout -enddate 2>/dev/null | sed 's/^notAfter=//' || true)
  TLS_TOT=$(date -d "$TLS_TOT" +%F 2>/dev/null || echo "$TLS_TOT")
  TLS_SHA256=$(openssl x509 -in "$TLS_DIR/homepage-ca.crt" -noout -fingerprint -sha256 2>/dev/null \
    | sed 's/^.*=//' || true)
  TLS_SHA1=$(openssl x509 -in "$TLS_DIR/homepage-ca.crt" -noout -fingerprint -sha1 2>/dev/null | sed 's/^.*=//' \
    || true)
  cat <<EOF
https: nginx luistert ook op poort 443, met een eigen certificaat dat geldig is tot $TLS_TOT. In NPM mag de host
dus ook naar https://$IP:443 wijzen (schema https; laat in de firewall van de container dan ook 443 vanaf NPM toe).
Geen waarschuwing in je browser of in Zabbix: vertrouw daar de CA (importeren als vertrouwde basis-CA):
$TLS_DIR/homepage-ca.crt, of download het thuis via NPM (niet via Cloudflare) op
https://<naam van het dashboard>/homepage-ca.crt.
Vingerafdruk van de CA, vergelijk ze bij het importeren:
  SHA-256 $TLS_SHA256
  SHA-1   $TLS_SHA1 (zo toont Windows de vingerafdruk)
EOF
  [ -z "$TLS_NIEUW" ] || [ -z "$TLS_VORIG" ] || nieuwe_ca_melden
fi
if [ -n "$LAN_OPEN" ]; then
  cat <<EOF
Rechtstreeks op http://$IP kan nu ook vanaf het hele LAN (HOMEPAGE_LAN_OPEN=1): je wachtwoord en sessiecookie
gaan dan onversleuteld over het netwerk, dus alleen om te testen${HTTPS_AAN:+, en liever op https://$IP}. Werkt het
via NPM, zet dan HOMEPAGE_LAN_OPEN=0 in $CONF_DIR/homepage.env en voer dit script opnieuw uit:
bash $APP_DIR/deploy/install.sh
EOF
else
  cat <<EOF
Rechtstreeks op http://$IP${HTTPS_AAN:+ of https://$IP} werkt alleen vanuit de container zelf: nginx laat alleen NPM
($NPM_IP) binnen, en van het LAN alleen push-monitors, webhooks en /api/healthz (Zabbix). Krijg je ook via NPM een
403, dan klopt HOMEPAGE_NPM_IP in $CONF_DIR/homepage.env niet: zet het juiste IP en voer dit script opnieuw uit.
Eerst testen zonder NPM: zet HOMEPAGE_LAN_OPEN=1 in $CONF_DIR/homepage.env en voer dit script opnieuw uit:
bash $APP_DIR/deploy/install.sh
EOF
fi
if [ -n "$NPM_GOK" ]; then
  warn "Het IP van Nginx Proxy Manager was niet opgegeven: de standaard $NPM_IP staat nu in $CONF_DIR/homepage.env\
 (HOMEPAGE_NPM_IP). Daarom blijft het LAN open (HOMEPAGE_LAN_OPEN=1), zodat een verkeerd IP je niet buitensluit.\
 Kijk HOMEPAGE_NPM_IP na en zet HOMEPAGE_LAN_OPEN=0 zodra het dashboard via NPM werkt."
elif [ -n "$BIJGEWERKT" ]; then
  warn "Bijgewerkt van een versie zonder deze regel: het LAN blijft open (HOMEPAGE_LAN_OPEN=1 staat nu in\
 $CONF_DIR/homepage.env), want HOMEPAGE_NPM_IP=$NPM_IP is nog niet nagekeken. Open het dashboard via zijn naam in\
 NPM; werkt dat, zet dan HOMEPAGE_LAN_OPEN=0 en voer dit script opnieuw uit."
fi
cat <<EOF
Bijwerken: hetzelfde bootstrap-commando opnieuw uitvoeren.
Werkt iets niet meer na een update: homepage-terugzetten (vorige versie plus de database van daarvoor).
Wat er misloopt, in één bestand om te delen: homepage-diagnose.
EOF
# Nog geen account (ook bij een tweede keer uitvoeren): de setup-code tonen.
USERS=$(runuser -u postgres -- psql -d homepage -tAc "SELECT count(*) FROM users" 2>/dev/null || echo 0)
if [ "${USERS:-0}" = 0 ] && [ -f "$CONF_DIR/setup-token" ]; then
  echo
  echo "Setup-code voor het eerste account: $(cat "$CONF_DIR/setup-token")"
  echo "(ook in $CONF_DIR/setup-token)"
fi
echo
echo "Bewaar een kopie van $CONF_DIR/secret.key op een veilige plek: zonder die sleutel zijn opgeslagen wachtwoorden en API-sleutels onleesbaar."
exit
}
