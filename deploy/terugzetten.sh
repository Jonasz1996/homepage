#!/usr/bin/env bash
# Draait de laatste update van homepage terug: de vorige versie van de code, met de database zoals ze vlak
# voor die update was (de kopie die install.sh voor elke update maakt). Als root in de container:
#   homepage-terugzetten           toont wat er gebeurt en vraagt bevestiging
#   homepage-terugzetten --lijst   toont de kopieën die er zijn
#   homepage-terugzetten --ja      zonder vragen (voor scripts)
# Wat sinds die update in het dashboard veranderde (tegels, meldingen, metingen) gaat verloren. Voor het
# terugzetten wordt de huidige database nog bewaard als voor-terugzetten-*.dump.
set -euo pipefail

APP_DIR=/opt/homepage
CONF_DIR=/etc/homepage
BK=/var/backups/homepage

say() { printf '\n\033[1;37m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Voer uit als root."; exit 1; }

# Kopieën van voor een update met hun versie ernaast, nieuwste eerst.
copies() { find "$BK" -maxdepth 1 -name 'voor-update-*.dump' -printf '%T@ %p\n' 2>/dev/null | sort -rn | cut -d' ' -f2-; }

if [ "${1:-}" = "--lijst" ]; then
  echo "Nu: $(sed -n 's/^versie=//p' "$CONF_DIR/versie" 2>/dev/null || echo onbekend)"
  copies | while read -r f; do
    v=$(sed -n 's/^versie=//p' "$f.versie" 2>/dev/null || true)
    printf '%s  %s\n' "$(date -r "$f" '+%Y-%m-%d %H:%M')" "${v:-(geen versie bekend, niet terug te zetten)}"
  done
  exit 0
fi

DUMP=$(copies | head -1)
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
KANAAL=$(sed -n 's/^kanaal=//p' "$CONF_DIR/versie" 2>/dev/null || true)
git config --global --add safe.directory "$APP_DIR" 2>/dev/null || true
git -C "$APP_DIR" cat-file -e "$COMMIT^{commit}" 2>/dev/null \
  || git -C "$APP_DIR" fetch -q origin "$COMMIT" 2>/dev/null \
  || { echo "Versie $VERSIE ($COMMIT) niet gevonden in $APP_DIR."; exit 1; }

cat <<EOF
Nu geïnstalleerd:  $NU
Terug naar:        $VERSIE (${COMMIT:0:7})
Database van:      $(date -r "$DUMP" '+%Y-%m-%d %H:%M'), vlak voor de update
Wat sinds die update in het dashboard veranderde, gaat verloren. De huidige database wordt eerst nog bewaard.
EOF
if [ "${1:-}" != "--ja" ]; then
  read -r -p "Typ 'terug' om door te gaan: " ok
  [ "$ok" = terug ] || { echo "Niets veranderd."; exit 1; }
fi

say "Diensten stoppen"
systemctl stop homepage-api homepage-worker homepage-syslog

say "Huidige database bewaren"
SAFE="$BK/voor-terugzetten-$(date +%Y%m%d-%H%M%S).dump"
runuser -u postgres -- sh -c "pg_dump -Fc homepage > '$SAFE.tmp' && mv '$SAFE.tmp' '$SAFE'"
echo "$SAFE"
find "$BK" -name 'voor-terugzetten-*.dump' -printf '%T@ %p\n' | sort -rn | tail -n +4 | cut -d' ' -f2- | xargs -r rm -f

say "Database terugzetten"
runuser -u postgres -- dropdb --force homepage
runuser -u postgres -- createdb -O homepage homepage
TS=""
if runuser -u postgres -- pg_restore -l "$DUMP" | grep -q 'EXTENSION.*timescaledb'; then
  TS=1
  runuser -u postgres -- psql -d homepage -qc "CREATE EXTENSION IF NOT EXISTS timescaledb" -c "SELECT timescaledb_pre_restore()" >/dev/null
fi
# Meldingen over de extensie zelf ("bestaat al") zijn normaal; of het gelukt is, blijkt uit alembic_version.
runuser -u postgres -- pg_restore -d homepage "$DUMP" 2> /tmp/homepage-terugzetten.log || true
[ -z "$TS" ] || runuser -u postgres -- psql -d homepage -qc "SELECT timescaledb_post_restore()" >/dev/null
if ! runuser -u postgres -- psql -d homepage -tAc "SELECT 1 FROM alembic_version" | grep -q 1; then
  warn "De database kon niet teruggezet worden (zie /tmp/homepage-terugzetten.log)."
  warn "De database van voor het terugzetten staat nog in $SAFE (terugzetten met pg_restore, zoals in de README)."
  exit 1
fi

say "Code terugzetten naar $VERSIE"
git -C "$APP_DIR" checkout -q -f --detach "$COMMIT"

# install.sh van die versie bouwt alles opnieuw en start de diensten; de database is al goed.
export HOMEPAGE_TERUGZETTEN=1 HOMEPAGE_KANAAL="${KANAAL:-nieuwste}"
bash "$APP_DIR/deploy/install.sh"
# De kopie hoort nu bij de draaiende versie: niet nog eens naar terugzetten.
mv "$DUMP.versie" "$DUMP.teruggezet"
echo
echo "Teruggezet naar $VERSIE. Het bootstrap-commando installeert later weer de nieuwste versie van je kanaal."
