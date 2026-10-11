#!/bin/sh
# Test van de eigen back-up: de nieuwste nachtelijke dump echt terugzetten in een aparte database, nakijken en die
# database weer weggooien. homepage-backuptest.timer start dit op de 1e van de maand om 04:15 (na de back-up van 03:30)
# als gebruiker postgres; met de hand: systemctl start homepage-backuptest. De echte database blijft ongemoeid.
# Zoals bij een echte ramp (LEESMIJ.txt bij de kopie buiten de container): lege database, met TimescaleDB eerst
# timescaledb_pre_restore(), dan pg_restore, dan timescaledb_post_restore(). Daarna: geen fouten van pg_restore (zoals
# homepage-herstelfouten ze telt), alembic_version is er, er is een gebruiker, en elke tabel is te tellen.
# Het resultaat komt in $BK/backuptest (ok=1, 0 of overgeslagen), wat pg_restore schreef in $BK/backuptest.log. De
# worker leest het en toont het in hw → homepage zelf, en onder ! als het mislukt. Het script zelf eindigt altijd met 0:
# de dienst hoeft niet op "failed" te staan voor iets wat het dashboard al meldt.
# Om te testen: BACKUP_DIR, BACKUPTEST_DB, BACKUPTEST_MAX_PCT, BACKUPTEST_TIMEOUT, BACKUPTEST_DF_PATH, HERSTELFOUTEN en
# de gewone PostgreSQL-variabelen (PGDATABASE, PGHOST, PGPORT).
set -u

BK=${BACKUP_DIR:-/var/backups/homepage}
LIVE=${PGDATABASE:-homepage}
TEST=${BACKUPTEST_DB:-${LIVE}_backuptest}
# Zo vol mag de schijf hoogstens worden met de testdatabase erbij. De schijfbewaker van de worker ruimt vanaf 75%
# logregels op en vindt het pas onder 70% weer goed: de test mag daar nooit de oorzaak van zijn.
MAXPCT=${BACKUPTEST_MAX_PCT:-70}
# Zo lang mogen terugzetten en nakijken samen duren, in seconden (homepage-backuptest.service geeft iets meer).
LIMIT=${BACKUPTEST_TIMEOUT:-3600}
HF=${HERSTELFOUTEN:-/usr/local/sbin/homepage-herstelfouten}
OUT="$BK/backuptest"
LOG="$BK/backuptest.log"
# Elke opdracht hieronder zegt zelf over welke database het gaat.
unset PGDATABASE

if [ -z "$TEST" ] || [ "$TEST" = "$LIVE" ]; then
  echo "De testdatabase moet een andere zijn dan $LIVE (BACKUPTEST_DB)." >&2
  exit 2
fi
case "$MAXPCT$LIMIT" in
  *[!0-9]*) echo "BACKUPTEST_MAX_PCT en BACKUPTEST_TIMEOUT zijn gehele getallen." >&2; exit 2 ;;
esac

START=$(date +%s)
AT=$(date -u +%Y-%m-%dT%H:%M:%S+00:00)
DUMP="" ALEMBIC="" TABELLEN="" TSV="" PGV=""

q() { psql -XAtq -v ON_ERROR_STOP=1 "$@"; }
# Hoeveel seconden er nog over zijn (minstens 1).
left() {
  l=$((LIMIT - ($(date +%s) - START)))
  [ "$l" -gt 0 ] || l=1
  echo "$l"
}
te_lang() {
  if [ "$LIMIT" -ge 120 ]; then echo "duurde langer dan $((LIMIT / 60)) min"; else echo "duurde langer dan $LIMIT s"; fi
}

# Altijd op het einde: de testdatabase weg, dan het resultaat wegschrijven, in één keer (de worker leest nooit een
# half bestand). Lukt het weggooien niet, dan is de test mislukt: de kopie neemt plaats in.
klaar() {
  trap - EXIT INT TERM HUP
  ok=$1 why=$2
  if ! e=$(dropdb --if-exists --force "$TEST" 2>&1); then
    ok=0
    why="${why:+$why; }testdatabase $TEST niet verwijderd: $e"
  fi
  why=$(printf '%s' "$why" | tr '\n\t' '  ' | cut -c1-300)
  {
    echo "at=$AT"
    echo "dump=$DUMP"
    echo "ok=$ok"
    echo "why=$why"
    echo "seconden=$(($(date +%s) - START))"
    echo "alembic=$ALEMBIC"
    echo "tabellen=$TABELLEN"
    echo "timescaledb=$TSV"
    echo "postgresql=$PGV"
  } > "$OUT.tmp" && mv "$OUT.tmp" "$OUT"
  exit 0
}
trap 'dropdb --if-exists --force "$TEST" 2>/dev/null' EXIT
# Gestopt (systemctl stop, of de tijdslimiet van de dienst): toch opruimen en zeggen wat er gebeurde.
trap 'klaar 0 "afgebroken"' INT TERM HUP

# Van een vorige test die halverwege stopte.
dropdb --if-exists --force "$TEST" 2>/dev/null

D=$(find "$BK" -maxdepth 1 -name 'homepage-????-??-??.dump' | sort -r | head -1)
[ -n "$D" ] || klaar overgeslagen "nog geen nachtelijke dump in $BK"
DUMP=${D##*/}
if ! PGV=$(q -d "$LIVE" -c "SHOW server_version" 2>&1); then
  e=$PGV PGV=""
  klaar 0 "PostgreSQL niet bereikbaar: $e"
fi
PGV=${PGV%% *}

# Plaats: de testdatabase wordt ongeveer zo groot als de echte zonder de logregels (die gaan niet mee in de dump), plus
# hoogstens max_wal_size aan WAL tijdens het terugzetten. Met TimescaleDB staan de logregels in de chunks.
LOGS="pg_total_relation_size(to_regclass('public.log_entries'))"
if [ "$(q -d "$LIVE" -c "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'")" = 1 ]; then
  LOGS="(SELECT hypertable_size(format('%I.%I', hypertable_schema, hypertable_name)::regclass)
           FROM timescaledb_information.hypertables WHERE hypertable_schema = 'public' AND hypertable_name = 'log_entries'),
         $LOGS"
fi
NEED=$(q -d "$LIVE" -c "SELECT pg_database_size(current_database()) - coalesce($LOGS, 0)
  + pg_size_bytes(current_setting('max_wal_size'))") || klaar 0 "grootte van de database niet te bepalen"
WHERE=${BACKUPTEST_DF_PATH:-$(q -d "$LIVE" -c "SHOW data_directory")}
PCT=$(df -Pk "$WHERE" 2>/dev/null | awk -v need="$NEED" 'NR == 2 && $2 > 0 { printf "%d", ($3 * 1024 + need) * 100 / ($2 * 1024) }')
[ -n "$PCT" ] || klaar overgeslagen "de schijf van $WHERE is niet te meten"
if [ "$PCT" -ge "$MAXPCT" ]; then
  klaar overgeslagen "te weinig plaats: ongeveer $((NEED >> 20)) MB nodig, de schijf zou dan $PCT% vol zijn (hoogstens \
$MAXPCT%: vanaf 75% ruimt de schijfbewaker logregels op)"
fi

# Terugzetten, met dezelfde eigenaar als de echte database.
OWNER=$(q -d "$LIVE" -c "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()")
if ! e=$(createdb -O "${OWNER:-postgres}" "$TEST" 2>&1); then
  klaar 0 "testdatabase aanmaken mislukt: $e"
fi
TS=""
if pg_restore -l "$D" 2>/dev/null | grep -q 'EXTENSION.*timescaledb'; then
  TS=1
  if ! e=$(q -d "$TEST" -c "CREATE EXTENSION IF NOT EXISTS timescaledb" -c "SELECT timescaledb_pre_restore()" 2>&1); then
    klaar 0 "TimescaleDB klaarzetten mislukt: $e"
  fi
fi
timeout "$(left)" pg_restore -d "$TEST" "$D" 2> "$LOG"
rc=$?
[ "$rc" -ne 124 ] || klaar 0 "terugzetten $(te_lang)"
# 1: pg_restore ging verder na een fout; welke fouten tellen, zegt homepage-herstelfouten. Iets anders: het stopte.
[ "$rc" -le 1 ] || klaar 0 "pg_restore stopte (code $rc), zie $LOG"
if [ -n "$TS" ] && ! e=$(q -d "$TEST" -c "SELECT timescaledb_post_restore()" 2>&1); then
  klaar 0 "timescaledb_post_restore mislukt: $e"
fi
if ! fouten=$(sh "$HF" "$LOG"); then
  klaar 0 "pg_restore: $(printf '%s\n' "$fouten" | head -1) (alles in $LOG)"
fi

# Nakijken.
TSV=$(q -d "$TEST" -c "SELECT extversion FROM pg_extension WHERE extname = 'timescaledb'" 2>/dev/null)
ALEMBIC=$(q -d "$TEST" -c "SELECT version_num FROM alembic_version" 2>/dev/null)
[ -n "$ALEMBIC" ] || klaar 0 "geen alembic_version in de teruggezette database"
# Elke tabel tellen, de hypertables ook over hun (gecomprimeerde) chunks heen: zo blijkt dat alles leesbaar is.
if ! t=$(timeout "$(left)" psql -XAtq -v ON_ERROR_STOP=1 -F : -R , -d "$TEST" -c "
    SELECT table_name, (xpath('/row/c/text()', query_to_xml(format('SELECT count(*) AS c FROM %I.%I', table_schema,
           table_name), false, true, '')))[1]::text
      FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1" 2>&1); then
  [ -n "$t" ] || t=$(te_lang)
  klaar 0 "tabellen tellen mislukt: $t"
fi
TABELLEN=$t
# Een kopie zonder gebruiker: dan kan niemand meer inloggen (behalve als de echte database er ook nog geen heeft).
USERS=$(q -d "$TEST" -c "SELECT count(*) FROM users" 2>/dev/null)
if [ "${USERS:-0}" = 0 ] && [ "$(q -d "$LIVE" -c "SELECT count(*) FROM users" 2>/dev/null)" != 0 ]; then
  klaar 0 "geen enkele gebruiker in de teruggezette database"
fi
klaar 1 ""
