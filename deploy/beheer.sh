#!/usr/bin/env bash
# Beheer van het dashboard vanaf de commandoregel, als root in de container (backend/app/beheer.py). Voor als je niet
# meer binnen raakt of alles wil wissen zonder browser:
#   homepage-beheer gebruikers
#   homepage-beheer 2fa-reset [naam]     2FA-app kwijt: 2FA uit, alle sessies weg, daarna opnieuw instellen
#   homepage-beheer wachtwoord [naam]    wachtwoord vergeten
#   homepage-beheer fabrieksreset        alles wissen, terug naar de eerste start (vraagt WIS ALLES)
#
# Werkt op een gewone installatie (homepage-api, /opt/homepage, /etc/homepage) en op een node van een homepage-cluster
# van ClusterForge (cf-homepage-api): het neemt gebruiker, map, instellingen en Python over van de dienst van de API,
# zodat het met dezelfde database en dezelfde secret.key werkt. Daar staat het niet in /usr/local/sbin; start het dan
# rechtstreeks uit de code: bash <map van de homepage>/deploy/beheer.sh ...
# Om te testen: BEHEER_UNIT (welke dienst).
set -eu

[ "$(id -u)" -eq 0 ] || { echo "Voer uit als root (in de container: pct enter <CTID>)." >&2; exit 1; }

UNIT=${BEHEER_UNIT:-}
if [ -z "$UNIT" ]; then
  for u in homepage-api cf-homepage-api; do
    if [ -n "$(systemctl show -p FragmentPath --value "$u" 2>/dev/null)" ]; then UNIT=$u; break; fi
  done
fi
[ -n "$UNIT" ] || { echo "Geen dienst homepage-api of cf-homepage-api gevonden op deze machine." >&2; exit 1; }

USR=$(systemctl show -p User --value "$UNIT")
WD=$(systemctl show -p WorkingDirectory --value "$UNIT")
# ExecStart: { path=/opt/homepage/.venv/bin/uvicorn ; argv[]=... }: de Python naast uvicorn.
EXE=$(systemctl show -p ExecStart --value "$UNIT" | sed -n 's/.*path=\([^ ;]*\).*/\1/p' | head -n1)
PY="$(dirname "${EXE:-/opt/homepage/.venv/bin/uvicorn}")/python"
[ -x "$PY" ] || { echo "Python van de homepage niet gevonden ($PY)." >&2; exit 1; }
[ -d "$WD/app" ] || WD="$(dirname "$(dirname "$(dirname "$PY")")")/backend"
[ -d "$WD/app" ] || { echo "De code van de homepage niet gevonden ($WD)." >&2; exit 1; }

# Dezelfde instellingen als de API: eerst Environment=, dan de EnvironmentFile's.
while IFS= read -r kv; do
  if [ -n "$kv" ]; then export "${kv?}"; fi
done < <(systemctl show -p Environment --value "$UNIT" | tr ' ' '\n')
while IFS= read -r f; do
  f=${f#-}
  # shellcheck disable=SC1090
  if [ -n "$f" ] && [ -r "$f" ]; then set -a; . "$f"; set +a; fi
done < <(systemctl show -p EnvironmentFiles --value "$UNIT" | sed 's/ (ignore_errors=[a-z]*)//g' | tr ' ' '\n')

cd "$WD"
rc=0
if [ -n "$USR" ] && [ "$USR" != root ]; then
  runuser -u "$USR" -- "$PY" -m app.beheer "$@" || rc=$?
else
  "$PY" -m app.beheer "$@" || rc=$?
fi

# Na een fabrieksreset: de API en de worker opnieuw starten, zodat niets van vroeger in hun geheugen blijft.
if [ "$rc" -eq 0 ] && [ "${1:-}" = fabrieksreset ]; then
  for u in "$UNIT" "${UNIT%-api}-worker"; do
    systemctl try-restart "$u" 2>/dev/null || true
  done
fi
exit "$rc"
