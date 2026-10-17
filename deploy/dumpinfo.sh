#!/bin/sh
# Wat er in een dump (pg_dump -Fc) zit, zonder database. Samen gebruikt door homepage-terugzetten en de maandelijkse
# test van de back-up (homepage-backuptest): ze beslissen zo op dezelfde manier of er TimescaleDB nodig is.
#   homepage-dumpinfo DUMP   schrijft "timescaledb" als de dump de extensie timescaledb bevat, anders niets. Eindigt
#                            met 1 als de inhoudstafel onleesbaar is (pg_restore zegt waarom, op stderr)
# De inhoudstafel (pg_restore -l) wordt eerst helemaal gelezen, pas dan wordt er gezocht. Rechtstreeks in grep -q
# lukt dat niet altijd: grep stopt bij de eerste regel die past, pg_restore krijgt dan SIGPIPE zodra de tafel groter
# is dan de buffer van de pipe (64 kB: een database met een paar duizend chunks van TimescaleDB), en met pipefail
# (bash) mislukt de hele test, ook al zit de extensie erin.
set -u

[ -n "${1:-}" ] || { echo "gebruik: $0 <dump>" >&2; exit 2; }
[ -r "$1" ] || { echo "$1 is niet te lezen" >&2; exit 1; }
toc=$(pg_restore -l "$1") || exit 1
# Een regel voor de extensie: "2; 3079 16385 EXTENSION - timescaledb ". Commentaar begint met ";"; COMMENT ON
# EXTENSION heeft COMMENT als vierde veld.
printf '%s\n' "$toc" | awk '$4 == "EXTENSION" && $5 == "-" && $6 == "timescaledb" { ts = 1 }
                            END { if (ts) print "timescaledb" }'
