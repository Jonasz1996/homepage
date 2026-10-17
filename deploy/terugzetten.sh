#!/usr/bin/env bash
# Draait de laatste update van homepage terug: de vorige versie van de code, met de database zoals ze vlak
# voor die update was (de kopie die install.sh voor elke update maakt). Als root in de container:
#   homepage-terugzetten           toont wat er gebeurt en vraagt bevestiging
#   homepage-terugzetten --lijst   toont de kopieën die er zijn
#   homepage-terugzetten --ja      zonder vragen (voor scripts)
# Wat sinds die update in het dashboard veranderde (tegels, meldingen, metingen) gaat verloren. Voor het
# terugzetten wordt de huidige database nog bewaard als voor-terugzetten-*.dump.
#
# Wat kan mislukken, wordt eerst nagekeken terwijl alles nog draait (voorbereiden): is de kopie helemaal leesbaar,
# heeft ze TimescaleDB nodig en is die versie hier geïnstalleerd, is er plaats genoeg. Stopt het daarna toch, dan
# zegt bij_fout hoe het er dan bij staat en wat je kan doen; zolang de database van nu er nog is, starten de diensten
# weer.

# Alles tussen { en }: bash leest het hele script in voor het begint. install.sh van de oude versie zet onderweg haar
# eigen homepage-terugzetten op deze plaats.
{
set -euo pipefail

APP_DIR=/opt/homepage
CONF_DIR=/etc/homepage
BK=/var/backups/homepage
DB=homepage
EIGENAAR=homepage
LOG=/tmp/homepage-terugzetten.log
HERSTELFOUTEN=/usr/local/sbin/homepage-herstelfouten
DUMPINFO=/usr/local/sbin/homepage-dumpinfo

say() { printf '\n\033[1;37m==> %s\033[0m\n' "$*"; }
# shellcheck disable=SC2317  # alleen in bij_fout (trap), dat ziet shellcheck niet
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

# Als postgres (met runuser: sudo staat niet in de container). q: in de database van homepage, qp: in de database
# postgres, die er altijd is (ook als die van homepage al weg is).
pg() { runuser -u postgres -- "$@"; }
q() { pg psql -XAtq -v ON_ERROR_STOP=1 -d "$DB" "$@"; }
qp() { pg psql -XAtq -v ON_ERROR_STOP=1 -d postgres "$@"; }
datamap() { qp -c "SHOW data_directory"; }

# Kopieën van voor een update met hun versie ernaast, nieuwste eerst.
copies() { find "$BK" -maxdepth 1 -name 'voor-update-*.dump' -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-; }

# Hoe ver het terugzetten is, voor bij_fout: gestopt (de diensten staan stil, de database is nog die van nu), weg (de
# database van nu is weg of maar half teruggezet), terug (de database is teruggezet, de code nog niet helemaal).
STAP="" REDEN=""
afbreken() { REDEN=$1; exit 1; }
# shellcheck disable=SC2317  # loopt via trap, dat ziet shellcheck niet
onderbroken() { REDEN="Onderbroken."; exit "$1"; }

# Is er in map $1 minstens $2 bytes vrij? Anders stoppen, voor er iets verandert.
plaats() {
  local vrij
  vrij=$(df --output=avail -B1 "$1" | tail -1 | tr -d ' ')
  if [ "$vrij" -lt "$2" ]; then
    echo "Te weinig plaats in $1: $((vrij >> 20)) MB vrij, ongeveer $(($2 >> 20)) MB nodig voor een kopie van de"
    echo "database van nu en de teruggezette database. Er is niets veranderd. Wat plaats inneemt:"
    echo "du -sh $BK/* /var/lib/postgresql"
    exit 1
  fi
}

# Alles nakijken wat het terugzetten nodig heeft, terwijl alles nog draait: er verandert niets. Stopt met een melding
# als iets niet klopt. Zet TS (de versie van TimescaleDB voor de kopie, leeg zonder) en TS_NU (die van de database van
# nu, voor de kopie die straks bewaard wordt).
voorbereiden() {
  local info e wel proef kopie nu groot wal terug pgdata
  echo "Kopie nakijken: $DUMP"
  # Helemaal lezen, ook de gegevens: een afgebroken kopie valt zo op voor de database van nu weg is.
  if ! info=$(pg "$DUMPINFO" "$DUMP") || ! pg pg_restore -f /dev/null "$DUMP"; then
    echo "De kopie is onleesbaar (zie hierboven). Er is niets veranderd."
    exit 1
  fi
  TS_NU=$(q -c "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'" 2>/dev/null || true)
  TS=""
  if [ "$info" = timescaledb ]; then
    # Met dezelfde versie als toen: anders passen de tabellen van TimescaleDB zelf niet bij wat in de kopie staat.
    # install.sh schrijft ze naast de kopie. Bij een kopie van daarvoor: die van de database van nu, want een update
    # verandert ze niet (dat doet alleen ALTER EXTENSION timescaledb UPDATE, en homepage doet dat nooit).
    TS=$(sed -n 's/^timescaledb=//p' "$DUMP.versie" | tail -1)
    [ -n "$TS" ] || TS=$TS_NU
    if [ -z "$TS" ]; then
      echo "De kopie heeft TimescaleDB nodig, maar welke versie is niet bekend: niet in $DUMP.versie, en de database"
      echo "van nu heeft geen TimescaleDB. Zet de versie van toen als regel timescaledb=<versie> in $DUMP.versie."
      exit 1
    fi
    case "$TS" in
      *[!0-9A-Za-z.-]*) echo "Geen geldige versie van TimescaleDB in $DUMP.versie: $TS"; exit 1 ;;
    esac
    # Zonder TimescaleDB in shared_preload_libraries lukt CREATE EXTENSION niet (en kan de verbinding crashen).
    case ",$(qp -c "SHOW shared_preload_libraries" | tr -d ' ')," in
      *,timescaledb,*) ;;
      *) echo "De kopie heeft TimescaleDB nodig, maar PostgreSQL laadt het niet (shared_preload_libraries). Er is"
         echo "niets veranderd."
         exit 1 ;;
    esac
    # Zoals straks bij het terugzetten, maar in een lege database die meteen weer weg is: is die versie hier
    # geïnstalleerd?
    proef="${DB}_terugzetten_proef"
    pg dropdb --if-exists --force "$proef"
    pg createdb "$proef"
    if ! e=$(pg psql -XAtq -v ON_ERROR_STOP=1 -d "$proef" -c "CREATE EXTENSION timescaledb VERSION '$TS'" 2>&1); then
      pg dropdb --if-exists --force "$proef" || true
      wel=$(qp -c "SELECT string_agg(version, ', ' ORDER BY version) FROM pg_available_extension_versions
                   WHERE name = 'timescaledb'" 2>/dev/null || true)
      echo "De kopie heeft TimescaleDB $TS nodig (die versie draaide bij de update), en die is hier niet"
      echo "geïnstalleerd (${wel:+wel: $wel}${wel:-TimescaleDB staat hier helemaal niet}). PostgreSQL zegt: ${e##*ERROR:  }"
      echo "Installeer eerst die versie, bij Timescale het pakket timescaledb-2-$TS-postgresql-$(qp -c \
"SELECT current_setting('server_version_num')::int / 10000"), en voer homepage-terugzetten opnieuw uit."
      echo "Er is niets veranderd."
      exit 1
    fi
    pg dropdb --force "$proef"
  fi

  # Plaats. Eerst komt er een kopie van de database van nu bij (geschat zoals bij een update: de gegevens zonder de
  # indexen, plus 64 MB). Daarna gaat de database van nu weg en komt de kopie terug: ongeveer zo groot als de
  # database toen was (grootte= naast de kopie; bij een kopie van daarvoor: zoals nu, en minstens de kopie zelf), plus
  # hoogstens max_wal_size aan WAL. Een vorige poging bewaarde de database al: dan geen nieuwe kopie.
  kopie=0
  if [ -z "$SAFE" ] && ! kopie=$(q -c "SELECT pg_database_size(current_database())
      - coalesce((SELECT sum(pg_relation_size(oid)) FROM pg_class WHERE relkind = 'i'), 0) + 64 * 1024 * 1024"); then
    echo "De database $DB is niet bereikbaar (zie hierboven): er kan geen kopie van gemaakt worden. Er is niets veranderd."
    exit 1
  fi
  nu=$(q -c "SELECT pg_database_size(current_database())" 2>/dev/null || echo 0)
  groot=$(sed -n 's/^grootte=//p' "$DUMP.versie" | tail -1)
  case "$groot" in
    ''|*[!0-9]*) groot=$(stat -c %s "$DUMP"); [ "$nu" -le "$groot" ] || groot=$nu ;;
  esac
  wal=$(qp -c "SELECT pg_size_bytes(current_setting('max_wal_size'))")
  terug=$(( (groot > nu ? groot - nu : 0) + wal ))
  pgdata=$(datamap)
  if [ "$(stat -c %d "$BK")" = "$(stat -c %d "$pgdata")" ]; then
    plaats "$BK" $((kopie + terug))
  else
    plaats "$BK" "$kopie"
    plaats "$pgdata" "$terug"
  fi
}

# De database van nu bewaren als voor-terugzetten-*.dump, met haar versies ernaast (om ze zelf terug te zetten, zie
# herstel_uitleg). Deed een vorige poging dat al (SAFE), dan is de database al (deels) teruggezet: die kopie is de
# goede.
bewaren() {
  local f
  if [ -n "$SAFE" ]; then
    echo "Al bewaard bij een vorige poging: $SAFE"
    return
  fi
  SAFE="$BK/voor-terugzetten-$(date +%Y%m%d-%H%M%S).dump"
  pg sh -c "pg_dump -Fc '$DB' > '$SAFE.tmp' && mv '$SAFE.tmp' '$SAFE'"
  printf 'commit=%s\nversie=%s\ntimescaledb=%s\n' "$NU_COMMIT" "$NU" "$TS_NU" > "$SAFE.versie"
  echo "$SAFE"
  # Alleen deze kopie blijft staan.
  find "$BK" -maxdepth 1 -name 'voor-terugzetten-*.dump' ! -path "$SAFE" | while read -r f; do
    rm -f "$f" "$f.versie"
  done
}

# De database van nu weg en de kopie terugzetten, zoals de maandelijkse test van de back-up: met TimescaleDB eerst de
# extensie in de versie van de kopie en timescaledb_pre_restore(), dan pg_restore, dan timescaledb_post_restore().
db_terugzetten() {
  local fouten=""
  # Voor een volgende poging, als deze halverwege stopt: welke kopie van de database van nu de goede is, en welke
  # versie van TimescaleDB bij de kopie hoort (de database van nu, waar die anders uit komt, is dan weg).
  echo "$SAFE" > "$DUMP.bezig"
  if [ -n "$TS" ] && ! grep -q '^timescaledb=.' "$DUMP.versie"; then
    echo "timescaledb=$TS" >> "$DUMP.versie"
  fi
  STAP=weg
  pg dropdb --force --if-exists "$DB"
  pg createdb -O "$EIGENAAR" "$DB"
  if [ -n "$TS" ]; then
    q -c "CREATE EXTENSION timescaledb VERSION '$TS'" -c "SELECT timescaledb_pre_restore()" >/dev/null \
      || afbreken "TimescaleDB $TS klaarzetten mislukt."
  fi
  # pg_restore gaat door na een fout. Welke fouten tellen, zegt homepage-herstelfouten, zoals bij de maandelijkse test
  # van de back-up: alleen meldingen over de extensie timescaledb zelf ("bestaat al") zijn normaal. Een tabel waarvan de
  # gegevens niet teruggezet konden worden, is wel een fout: dan ontbreekt er iets, ook al is alembic_version er.
  pg pg_restore -d "$DB" "$DUMP" 2> "$LOG" || true
  if [ -n "$TS" ]; then
    q -c "SELECT timescaledb_post_restore()" >/dev/null || afbreken "timescaledb_post_restore() mislukt."
  fi
  if ! fouten=$("$HERSTELFOUTEN" "$LOG") || [ "$(q -c "SELECT 1 FROM alembic_version LIMIT 1" 2>/dev/null)" != 1 ]; then
    [ -z "$fouten" ] || printf '%s\n' "$fouten"
    afbreken "De database kon niet (volledig) teruggezet worden (alles in $LOG)."
  fi
}

# Hoe je de database van voor het terugzetten zelf terugzet: dezelfde stappen als db_terugzetten.
# shellcheck disable=SC2317  # loopt via bij_fout (trap), dat ziet shellcheck niet
herstel_uitleg() {
  local ts commit
  ts=$(sed -n 's/^timescaledb=//p' "$SAFE.versie" 2>/dev/null | tail -1 || true)
  commit=$(sed -n 's/^commit=//p' "$SAFE.versie" 2>/dev/null | tail -1 || true)
  echo "  runuser -u postgres -- dropdb --force --if-exists $DB"
  echo "  runuser -u postgres -- createdb -O $EIGENAAR $DB"
  [ -z "$ts" ] || echo "  runuser -u postgres -- psql -X -d $DB -c \"CREATE EXTENSION timescaledb VERSION '$ts'\"" \
    "-c \"SELECT timescaledb_pre_restore()\""
  echo "  runuser -u postgres -- pg_restore -d $DB $SAFE 2> /root/pg_restore.log"
  [ -z "$ts" ] || echo "  runuser -u postgres -- psql -X -d $DB -c \"SELECT timescaledb_post_restore()\""
  echo "  homepage-herstelfouten /root/pg_restore.log    # zonder uitvoer: in orde"
  # Een vorige poging zette de code al terug: bij die database hoort de code van toen.
  if [ -n "$commit" ] && [ "$(git -C "$APP_DIR" rev-parse HEAD 2>/dev/null || true)" != "$commit" ]; then
    echo "  git -C $APP_DIR checkout -q -f --detach $commit && bash $APP_DIR/deploy/install.sh"
  else
    echo "  systemctl start homepage-api homepage-worker homepage-syslog"
  fi
}

# Bij een fout of onderbreking na het stoppen van de diensten: zeggen hoe het er nu bij staat en wat je kan doen.
# Zolang de database van nu er nog is (gestopt), starten de diensten weer.
# shellcheck disable=SC2317  # loopt via trap, dat ziet shellcheck niet
bij_fout() {
  local rc=$? code
  # Het opruimen zelf niet onderbreken.
  trap '' INT HUP TERM PIPE
  trap - EXIT
  set +e
  [ "$rc" -ne 0 ] || exit 0
  printf '\n\033[1;31m!! %s\033[0m\n' "${REDEN:-Er ging iets mis, zie hierboven.}"
  case "$STAP" in
    gestopt)
      rm -f "$SAFE.tmp"
      systemctl start homepage-api homepage-worker homepage-syslog
      warn "Er is niets veranderd: de database en de code zijn nog die van $NU, de diensten draaien weer."
      ;;
    weg)
      warn "De database $DB is weg of maar half teruggezet, de diensten staan stil. De database van voor het"
      warn "terugzetten ($NU) staat in $SAFE."
      warn "Opnieuw proberen: homepage-terugzetten (het gaat verder met die kopie). Of zelf terug naar hoe het was:"
      herstel_uitleg
      ;;
    terug)
      if [ "$(git -C "$APP_DIR" rev-parse HEAD 2>/dev/null)" = "$COMMIT" ]; then code="de code ook"; else code="de code nog niet"; fi
      warn "De database staat al op $VERSIE, $code. Los de fout hierboven op en voer homepage-terugzetten opnieuw uit."
      warn "De database van daarvoor ($NU): $SAFE. Hoe de diensten erbij staan: homepage-diagnose."
      ;;
  esac
  [ "$STAP" = terug ] || warn "Alles samen in één bestand, om te delen: homepage-diagnose."
  exit "$rc"
}

# Het terugzetten zelf, na voorbereiden en de bevestiging.
uitvoeren() {
  trap bij_fout EXIT
  trap 'onderbroken 129' HUP
  trap 'onderbroken 130' INT
  trap 'onderbroken 143' TERM

  say "Diensten stoppen"
  # Een vorige poging veranderde de database al: die is dan niet meer die van nu.
  if [ -n "$SAFE" ]; then STAP=weg; else STAP=gestopt; fi
  systemctl stop homepage-api homepage-worker homepage-syslog

  say "Huidige database bewaren"
  bewaren

  say "Database terugzetten"
  db_terugzetten
  STAP=terug

  say "Code terugzetten naar $VERSIE"
  git -C "$APP_DIR" checkout -q -f --detach "$COMMIT"
  # Een versie van voor requirements.lock kent alleen een gewone map .venv en installeert daar zelf in. Ze krijgt haar
  # venv van toen terug (of maakt een nieuwe); de venvs per lock (.venv-<hash>) blijven zo zoals ze zijn.
  if [ -L "$APP_DIR/.venv" ] && ! git -C "$APP_DIR" cat-file -e "$COMMIT:backend/requirements.lock" 2>/dev/null; then
    rm -f "$APP_DIR/.venv"
    [ ! -d "$APP_DIR/.venv-vorige" ] || mv "$APP_DIR/.venv-vorige" "$APP_DIR/.venv"
  fi

  # install.sh van die versie neemt haar eigen bibliotheken (de venv van toen als die er nog is), bouwt de frontend en
  # start de diensten; de database is al goed.
  export HOMEPAGE_TERUGZETTEN=1 HOMEPAGE_KANAAL="${KANAAL:-nieuwste}"
  bash "$APP_DIR/deploy/install.sh" || afbreken "Terugzetten niet afgewerkt: install.sh van $VERSIE mislukte."
  # De kopie hoort nu bij de draaiende versie: niet nog eens naar terugzetten.
  mv "$DUMP.versie" "$DUMP.teruggezet"
  rm -f "$DUMP.bezig"
  STAP=""
}

[ "$(id -u)" -eq 0 ] || { echo "Voer uit als root."; exit 1; }

if [ "${1:-}" = "--lijst" ]; then
  echo "Nu: $(sed -n 's/^versie=//p' "$CONF_DIR/versie" 2>/dev/null || echo onbekend)"
  copies | while read -r f; do
    v=$(sed -n 's/^versie=//p' "$f.versie" 2>/dev/null || true)
    printf '%s  %s\n' "$(date -r "$f" '+%Y-%m-%d %H:%M')" "${v:-(geen versie bekend, niet terug te zetten)}"
  done
  exit 0
fi

# De nieuwste kopie die bij een update hoort: met de versie ernaast, of al teruggezet. Een kopie zonder (van een update
# van een heel oude installatie) slaan we over.
DUMP=$(copies | while read -r f; do if [ -f "$f.versie" ] || [ -f "$f.teruggezet" ]; then echo "$f"; break; fi; done)
[ -n "$DUMP" ] || DUMP=$(copies | head -1)
[ -n "$DUMP" ] || { echo "Geen kopie van voor een update gevonden in $BK."; exit 1; }
if [ -f "$DUMP.teruggezet" ]; then
  echo "De laatste update is al teruggedraaid. Nog verder terug kan niet met dit commando."
  exit 1
fi
if [ ! -f "$DUMP.versie" ]; then
  echo "De laatste kopie ($DUMP) heeft geen versie ernaast: die update gebeurde voor homepage-terugzetten bestond,"
  echo "of er werd dezelfde versie opnieuw geïnstalleerd. Terugzetten kan vanaf de volgende update."
  exit 1
fi
COMMIT=$(sed -n 's/^commit=//p' "$DUMP.versie")
VERSIE=$(sed -n 's/^versie=//p' "$DUMP.versie")
NU=$(sed -n 's/^versie=//p' "$CONF_DIR/versie" 2>/dev/null || echo onbekend)
NU_COMMIT=$(sed -n 's/^commit=//p' "$CONF_DIR/versie" 2>/dev/null || true)
KANAAL=$(sed -n 's/^kanaal=//p' "$CONF_DIR/versie" 2>/dev/null || true)
git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true
git -C "$APP_DIR" cat-file -e "$COMMIT^{commit}" 2>/dev/null \
  || git -C "$APP_DIR" fetch -q origin "$COMMIT" 2>/dev/null \
  || { echo "Versie $VERSIE ($COMMIT) niet gevonden in $APP_DIR."; exit 1; }

# Een vorige poging stopte halverwege: de database is dan al (deels) teruggezet, de kopie van toen is de goede.
SAFE=$(cat "$DUMP.bezig" 2>/dev/null || true)
if [ -n "$SAFE" ] && [ ! -f "$SAFE" ]; then SAFE=""; fi
voorbereiden

cat <<EOF
Nu geïnstalleerd:  $NU
Terug naar:        $VERSIE (${COMMIT:0:7})
Database van:      $(date -r "$DUMP" '+%Y-%m-%d %H:%M'), vlak voor de update${TS:+, met TimescaleDB $TS}
Wat sinds die update in het dashboard veranderde, gaat verloren. De huidige database wordt eerst nog bewaard.
EOF
[ -z "$SAFE" ] || echo "Een vorige poging stopte halverwege; de database van daarvoor staat al in $SAFE."
if [ "${1:-}" != "--ja" ]; then
  read -r -p "Typ 'terug' om door te gaan: " ok
  [ "$ok" = terug ] || { echo "Niets veranderd."; exit 1; }
fi

uitvoeren
echo
echo "Teruggezet naar $VERSIE. Het bootstrap-commando installeert later weer de nieuwste versie van je kanaal."
exit
}
