#!/bin/sh
# Dagelijkse back-up van de database. homepage-backup.service start dit om 03:30 als gebruiker postgres; het mag
# alleen in /var/backups/homepage schrijven. De logregels gaan niet mee: ze zijn het grootste deel van de database
# en na het terugzetten heb je ze niet nodig (de tabel log_entries is er wel, leeg). De 5 nieuwste dumps blijven.
# Om te testen: BACKUP_DIR en de gewone PostgreSQL-variabelen (PGDATABASE, PGHOST, PGPORT).
set -eu

BK=${BACKUP_DIR:-/var/backups/homepage}
KEEP=5
export PGDATABASE="${PGDATABASE:-homepage}"
F="$BK/homepage-$(date +%F).dump"

set -- --exclude-table-data=public.log_entries
# Met TimescaleDB staat de inhoud van log_entries in de chunks van de hypertable, en na compressie in de chunks van
# de gecomprimeerde hypertable. Die ook overslaan; de catalogus van TimescaleDB zegt welke ids ze hebben.
if [ "$(psql -XAtq -c "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'")" = 1 ]; then
  pats=$(psql -XAtq -c "
    SELECT format('%s._hyper_%s_*_chunk', h.associated_schema_name, h.id)
      FROM _timescaledb_catalog.hypertable h WHERE h.schema_name = 'public' AND h.table_name = 'log_entries'
    UNION ALL
    SELECT format('%s.compress_hyper_%s_*_chunk', c.associated_schema_name, c.id)
      FROM _timescaledb_catalog.hypertable h JOIN _timescaledb_catalog.hypertable c ON c.id = h.compressed_hypertable_id
     WHERE h.schema_name = 'public' AND h.table_name = 'log_entries'")
  while read -r p; do
    if [ -n "$p" ]; then
      set -- "$@" "--exclude-table-data=$p"
    fi
  done <<EOF
$pats
EOF
fi

# Eerst naar een tijdelijk bestand: een mislukte tweede run op dezelfde dag overschrijft de goede dump niet, en een
# halve dump blijft niet op de schijf staan.
trap 'rm -f "$F.tmp"' EXIT
pg_dump -Fc "$@" -f "$F.tmp"
mv "$F.tmp" "$F"

# De 5 nieuwste houden, op de datum in de naam (niet op wijzigingstijd: een gekopieerde dump is niet nieuwer).
find "$BK" -maxdepth 1 -name 'homepage-????-??-??.dump' | sort -r | tail -n +$((KEEP + 1)) | xargs -r rm -f
