#!/bin/sh
# Welke fouten van pg_restore tellen. Samen gebruikt door de maandelijkse test van de back-up (homepage-backuptest) en
# door homepage-terugzetten: wat de test goedkeurt, keurt het terugzetten ook goed, en omgekeerd.
#   homepage-herstelfouten LOG   schrijft de fouten die tellen (hoogstens 20), en eindigt met 1 als er zijn
# LOG is wat pg_restore op stderr schreef. Elke fout telt, behalve die over de extensie timescaledb zelf: het
# terugzetten maakt die eerst zelf aan (voor timescaledb_pre_restore), dus "bestaat al" of "geen eigenaar" daarover is
# normaal. Of het om de extensie gaat, zegt de regel "Command was:" eronder. Gegevens van een tabel die niet
# teruggezet konden worden ("COPY failed") tellen altijd: die tabel is dan leeg of half.
set -u

[ -r "${1:-}" ] || { echo "gebruik: $0 <log van pg_restore>" >&2; exit 2; }

awk '
  function flush(cmd) {
    if (fout == "") return
    if (fout !~ /COPY failed/ && cmd ~ /^Command was: (CREATE|COMMENT ON) EXTENSION (IF NOT EXISTS )?"?timescaledb"?[ ;]/) {
      fout = ""
      return
    }
    n++
    if (n <= 20) {
      sub(/^pg_restore: (error: )?/, "", fout)
      print fout
    }
    fout = ""
  }
  # Een fout: "pg_restore: error: ..." (vanaf PostgreSQL 12) of "pg_restore: [archiver (db)] ..." (ouder).
  /^pg_restore: (error:|\[archiver)/ { flush(""); fout = $0; next }
  /^Command was: / { flush($0); next }
  END {
    flush("")
    if (n > 20) print "… en nog " n - 20 " fouten"
    exit (n > 0 ? 1 : 0)
  }
' "$1"
