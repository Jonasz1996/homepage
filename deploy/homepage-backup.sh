#!/bin/sh
# Dagelijkse back-up van de database. homepage-backup.service start dit om 03:30 als gebruiker postgres; het mag
# alleen in /var/backups/homepage schrijven. De logregels gaan niet mee: ze zijn het grootste deel van de database
# en na het terugzetten heb je ze niet nodig (de tabel log_entries is er wel, leeg). De 5 nieuwste dumps blijven.
# Om te testen: BACKUP_DIR, BACKUPTEST_DB en de gewone PostgreSQL-variabelen (PGDATABASE, PGHOST, PGPORT).
set -eu

BK=${BACKUP_DIR:-/var/backups/homepage}
KEEP=5
export PGDATABASE="${PGDATABASE:-homepage}"
F="$BK/homepage-$(date +%F).dump"

# Een testdatabase van de maandelijkse test die bleef staan (de container viel uit tijdens de test): weg, anders
# neemt hij tot de volgende test plaats in. Alleen als systemd zegt dat de test nu niet loopt.
T=${BACKUPTEST_DB:-${PGDATABASE}_backuptest}
case "$(systemctl is-active homepage-backuptest 2>/dev/null)" in
  inactive|failed) dropdb --if-exists --force "$T" 2>/dev/null || true ;;
esac

# De dump zelf, als functie: bij een tweede poging opnieuw de lijst van de chunks (die kan intussen veranderd zijn).
dump() {
  set -- --exclude-table-data=public.log_entries
  # Met TimescaleDB staan de rijen van log_entries in de chunks, en na compressie in een aparte relatie per chunk. Die
  # allemaal overslaan, elk met zijn exacte naam. Waar TimescaleDB de gecomprimeerde relatie bijhoudt, verschilt per
  # versie: tot 2.28 in chunk.compressed_chunk_id (namen als compress_hyper_2_9_chunk), vanaf 2.19 ook en vanaf 2.29
  # alleen in compression_settings.compress_relid (nieuwe heten _hyper_1_1_chunk_compressed; die van voor een update
  # van de extensie houden hun oude naam, zonder gecomprimeerde hypertable in de catalogus). to_jsonb leest alleen de
  # kolommen die deze versie heeft.
  if [ "$(psql -XAtq -c "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'")" = 1 ]; then
    rels=$(psql -XAtq -c "
      WITH ch AS (
        SELECT show_chunks(format('%I.%I', hypertable_schema, hypertable_name)::regclass) AS rel
          FROM timescaledb_information.hypertables
         WHERE hypertable_schema = 'public' AND hypertable_name = 'log_entries'
      ), cat AS (
        SELECT to_jsonb(x) AS j FROM _timescaledb_catalog.chunk x
      ), rels AS (
        SELECT rel FROM ch
        UNION
        SELECT to_regclass(s.j ->> 'compress_relid')
          FROM (SELECT to_jsonb(x) AS j FROM _timescaledb_catalog.compression_settings x) s
          JOIN ch ON to_regclass(s.j ->> 'relid') = ch.rel
        UNION
        SELECT to_regclass(quote_ident(cc.j ->> 'schema_name') || '.' || quote_ident(cc.j ->> 'table_name'))
          FROM cat c JOIN cat cc ON cc.j -> 'id' = c.j -> 'compressed_chunk_id'
          JOIN ch ON to_regclass(quote_ident(c.j ->> 'schema_name') || '.' || quote_ident(c.j ->> 'table_name')) = ch.rel
      )
      SELECT format('%I.%I', n.nspname, r.relname)
        FROM rels JOIN pg_class r ON r.oid = rels.rel JOIN pg_namespace n ON n.oid = r.relnamespace") || return 1
    while read -r p; do
      if [ -n "$p" ]; then
        set -- "$@" "--exclude-table-data=$p"
      fi
    done <<EOF
$rels
EOF
  fi
  pg_dump -Fc "$@" -f "$F.tmp"
}

# Eerst naar een tijdelijk bestand: een mislukte tweede run op dezelfde dag overschrijft de goede dump niet, en een
# halve dump blijft niet op de schijf staan.
trap 'rm -f "$F.tmp"' EXIT
# De achtergrondtaken van TimescaleDB (comprimeren, opruimen) lopen door tijdens de dump. Vervangen ze een chunk
# tussen de lijst van pg_dump en zijn LOCK TABLE, dan stopt pg_dump met "relation ... does not exist". Dat is
# alleen pech met het moment: dan nog eens, tot 3 keer. Elke andere fout meteen.
poging=1
until fout=$(dump 2>&1); do
  case "$fout" in
    *'relation "'*'" does not exist'*|*"could not open relation with OID"*|*"cache lookup failed for relation"*) ;;
    *) poging=3 ;;
  esac
  if [ "$poging" -ge 3 ]; then
    printf '%s\n' "$fout" >&2
    exit 1
  fi
  printf '%s\nEen tabel veranderde tijdens de dump (TimescaleDB), opnieuw.\n' "$fout" >&2
  poging=$((poging + 1))
  sleep "${BACKUP_WACHT:-10}"
done
[ -z "$fout" ] || printf '%s\n' "$fout" >&2
mv "$F.tmp" "$F"

# De 5 nieuwste houden, op de datum in de naam (niet op wijzigingstijd: een gekopieerde dump is niet nieuwer).
find "$BK" -maxdepth 1 -name 'homepage-????-??-??.dump' | sort -r | tail -n +$((KEEP + 1)) | xargs -r rm -f
