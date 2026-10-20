#!/usr/bin/env bash
# Alles over deze installatie in één tekstbestand, om bij een foutmelding te voegen. Werkt ook als het dashboard zelf
# niet start (de diagnose in het dashboard, ! → diagnose ↓, dan niet). Als root in de container:
#   homepage-diagnose   schrijft /root/homepage-diagnose-<datum>.txt en toont waar
# Erin: de versies, de diensten (systemctl status en de laatste 100 regels van journald, ook van postgresql en nginx),
# of /api/ping en /api/healthz antwoorden, schijf en geheugen, PostgreSQL (bereikbaar, max_connections en hoeveel
# verbindingen er open zijn, alembic_version), de nieuwste back-ups en kopieën van voor een update, en het laatste log
# van install.sh. Het verandert niets.
#
# Geheimen. secret.key en setup-token komen er nooit in, van homepage.env alleen de waarden van sleutels die niet op
# een geheim lijken (met SECRET, KEY, TOKEN of PASS erin). Alles gaat daarna door maskeren: die geheimen zelf, letterlijk,
# waar ze ook opduiken (vanaf 6 tekens), een privésleutel over meerdere regels, en wat op een token, sleutel of
# wachtwoord lijkt (de patronen van backend/app/masking.py, voor zover sed dat per regel kan). Wat er dan nog kan
# instaan: de geheimen die het dashboard in de database bewaart (wachtwoorden en API-sleutels van tegels; dit script
# kent ze niet, de diagnose in het dashboard wel), een geheim dat anders gecodeerd is (url-gecodeerd, base64) of over
# twee regels loopt, en een token zonder herkenbare naam of vorm (een los woord in een logregel). IP-adressen en
# namen staan er ook in: kijk het bestand na voor je het deelt.
# Om te testen: DIAGNOSE_DIR (waar het bestand komt), DIAGNOSE_CONF, DIAGNOSE_APP, DIAGNOSE_BK, DIAGNOSE_LOGS,
# DIAGNOSE_URL (via nginx), DIAGNOSE_API (rechtstreeks) en de gewone PostgreSQL-variabelen (PGDATABASE, PGHOST, PGPORT).
set -u

UIT=${DIAGNOSE_DIR:-/root}
CONF=${DIAGNOSE_CONF:-/etc/homepage}
APP=${DIAGNOSE_APP:-/opt/homepage}
BK=${DIAGNOSE_BK:-/var/backups/homepage}
LOGS=${DIAGNOSE_LOGS:-/var/log/homepage}
URL=${DIAGNOSE_URL:-http://127.0.0.1}
API=${DIAGNOSE_API:-http://127.0.0.1:8000}
DB=${PGDATABASE:-homepage}
REGELS=100
export PGCONNECT_TIMEOUT=5

kop() { printf '\n===== %s =====\n' "$*"; }
# Een opdracht met wat ze schreef (ook op stderr), hoogstens 20 s, en haar code als ze mislukt.
doe() {
  local rc
  printf '$ %s\n' "$*"
  timeout 20 "$@" 2>&1
  rc=$?
  [ "$rc" -eq 0 ] || echo "(code $rc)"
}
# Een vraag aan PostgreSQL, als postgres (runuser: sudo staat niet in de container).
sql() { doe runuser -u postgres -- psql -X -d "${2:-$DB}" -c "$1"; }
# Lijkt de naam van een instelling op die van een geheim?
geheim() { [[ ${1^^} =~ SECRET|KEY|TOKEN|PASS ]]; }

# De geheimen die dit script kent, één per regel: secret.key, setup-token, en van homepage.env de waarden van
# sleutels die op een geheim lijken (zonder aanhalingstekens).
bekend() {
  local f regel k v
  for f in "$CONF/secret.key" "$CONF/setup-token"; do
    [ -r "$f" ] && { tr -d '\r' < "$f"; echo; }
  done
  [ -r "$CONF/homepage.env" ] || return 0
  while IFS= read -r regel || [ -n "$regel" ]; do
    case "$regel" in \#*|'') continue ;; esac
    k=${regel%%=*} v=${regel#*=}
    v=${v#\"} v=${v%\"} v=${v#\'} v=${v%\'}
    if geheim "$k"; then printf '%s\n' "$v"; fi
  done < "$CONF/homepage.env"
}

# homepage.env zonder de waarden van wat op een geheim lijkt.
instellingen() {
  local regel k
  while IFS= read -r regel || [ -n "$regel" ]; do
    case "$regel" in \#*|'') continue ;; esac
    k=${regel%%=*}
    if ! geheim "$k"; then
      printf '%s\n' "$regel"
    elif [ -z "${regel#*=}" ]; then
      # Zonder "=": anders maskeert maskeren ook dit.
      printf '%s (leeg)\n' "$k"
    else
      printf '%s=***\n' "$k"
    fi
  done < "$CONF/homepage.env"
}

# Eerst de bekende geheimen letterlijk (awk, index: geen reguliere expressies) en een privésleutel over meerdere
# regels (tot de regel met END, hoogstens 200 regels), dan de patronen per regel.
# shellcheck disable=SC2016  # awk, geen shell
MASK_AWK='
BEGIN {
  n = split(ENVIRON["DIAGNOSE_BEKEND"], t, "\n")
  for (i = 1; i <= n; i++) if (length(t[i]) >= 6) k[++m] = t[i]
  # Langste eerst: een korter geheim dat in een langer zit, laat zo niets van het langere staan.
  for (i = 2; i <= m; i++) { v = k[i]; for (j = i - 1; j >= 1 && length(k[j]) < length(v); j--) k[j + 1] = k[j]; k[j + 1] = v }
}
{
  s = $0
  for (i = 1; i <= m; i++) {
    uit = ""
    while ((p = index(s, k[i])) > 0) { uit = uit substr(s, 1, p - 1) "***"; s = substr(s, p + length(k[i])) }
    s = uit s
  }
  if (sleutel) {
    if (s ~ /-----END [A-Z0-9 ]*PRIVATE KEY-----/) {
      sub(/.*-----END [A-Z0-9 ]*PRIVATE KEY-----/, "-----END PRIVATE KEY-----", s)
      sleutel = 0
      print s
    } else if (++weg > 200) {
      sleutel = 0
      print "*** (privésleutel zonder einde: tot hier weggelaten)"
    }
    next
  }
  if (s ~ /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/ && s !~ /-----END [A-Z0-9 ]*PRIVATE KEY-----/) {
    sub(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*/, "-----BEGIN PRIVATE KEY----- ***", s)
    sleutel = 1
    weg = 0
  }
  print s
}'
# Zoals backend/app/masking.py (PATTERNS), in GNU sed: een sleutel op één regel, tokens van Proxmox en PBS,
# Authorization- en Cookie-headers, Bearer/Basic, een wachtwoord in een url, ?token=, ?key= en co., het token van een
# push-monitor of webhook, iets versleuteld met Fernet, een JWT, de sessiecookie, en naam=waarde of "naam": "waarde" voor
# namen met password, secret, token, api_key, private_key of psk erin.
MASK_SED=$(cat <<'SED'
s/-----BEGIN ([A-Z0-9 ]*)PRIVATE KEY-----.*-----END [A-Z0-9 ]*PRIVATE KEY-----/-----BEGIN \1PRIVATE KEY----- *** -----END \1PRIVATE KEY-----/g
s/(PVEAPIToken=[^=[:space:]"',;]+=)[^[:space:]"',;]+/\1***/g
s/(PBSAPIToken=[^:[:space:]"',;]+:)[^[:space:]"',;]+/\1***/g
s/\b(authorization|proxy-authorization|x-api-key|api-key|x-auth-token|cookie|set-cookie)("?'?[[:space:]]*[:=][[:space:]]*"?'?)[^"']+/\1\2***/Ig
s#\b(bearer|basic)[[:space:]]+[A-Za-z0-9._~+/=-]{12,}#\1 ***#Ig
s#\b([a-z][a-z0-9+.-]{0,30}://)([^/[:space:]@:"']{0,200}):[^/[:space:]@"']{1,500}@#\1\2:***@#Ig
s/([?&;][A-Za-z0-9_.-]{0,40}(passw(or)?d|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|psk)[A-Za-z0-9_.-]{0,40}=)[^&[:space:]"'#]+/\1***/Ig
s/([?&;](key|auth|sig|signature|session|sid|code)=)[^&[:space:]"'#]+/\1***/Ig
s#(/api/(push|hooks)/)[A-Za-z0-9_-]{16,}#\1***#g
s/gAAAAA[A-Za-z0-9_=-]{20,}/***/g
s/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}/***/g
s/(hp_session=)[^;[:space:]"']+/\1***/g
s/\b([A-Za-z0-9_.-]{0,40}(passw(or)?d|passwd|secret|token|api[_-]?key|apikey|private[_-]?key|psk)[A-Za-z0-9_.-]{0,40})("?'?[[:space:]]*[:=][[:space:]]*)("[^"]*"|'[^']*'|[^[:space:]"',;&}]+)/\1\4***/Ig
SED
)
maskeren() { DIAGNOSE_BEKEND="$BEKEND" awk "$MASK_AWK" | sed -E -e "$MASK_SED"; }

verslag() {
  local d f
  echo "homepage-diagnose, $(date -Iseconds), $(hostname)"
  [ "$(id -u)" -eq 0 ] || echo "!! Niet als root: journald, $CONF en PostgreSQL ontbreken (deels)."

  kop "Versies"
  if [ -r "$CONF/versie" ]; then cat "$CONF/versie"; else echo "(geen $CONF/versie)"; fi
  doe git -C "$APP" log -1 --format='%H %cI %s'
  doe git -C "$APP" status --short
  echo ".venv -> $(readlink "$APP/.venv" 2>/dev/null || echo '(geen verwijzing)')"
  doe "$APP/.venv/bin/python" --version
  doe python3 --version
  doe node --version
  doe npm --version
  doe psql --version
  sql "SELECT version()"
  sql "SELECT extname, extversion FROM pg_extension WHERE extname = 'timescaledb'"
  # shellcheck disable=SC2016  # het formaat van dpkg-query, geen shell
  doe dpkg-query -W -f '${Package} ${Version}\n' 'postgresql-[0-9]*' 'timescaledb*'
  # shellcheck source=/dev/null
  echo "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-}"), kernel $(uname -r)"

  kop "Diensten"
  for d in homepage-api homepage-worker homepage-syslog postgresql nginx; do
    doe systemctl status --no-pager --lines=0 "$d"
    doe systemctl show -p ActiveState -p SubState -p NRestarts -p ExecMainStatus -p ActiveEnterTimestamp "$d"
  done
  doe systemctl list-timers --no-pager 'homepage-*'

  kop "API"
  doe curl -sS -m 5 -w ' (HTTP %{http_code})\n' "$URL/api/ping"
  doe curl -sS -m 5 -w ' (HTTP %{http_code})\n' "$URL/api/healthz"
  # Rechtstreeks, zonder nginx: zo blijkt of het aan nginx ligt.
  doe curl -sS -m 5 -w ' (HTTP %{http_code})\n' "$API/api/ping"
  doe nginx -t

  kop "Schijf en geheugen"
  for d in / "$BK" /var/lib/postgresql /mnt/homepage-backup; do
    [ -e "$d" ] && doe df -h "$d"
  done
  doe free -m
  doe uptime
  echo '$ ps -eo pid,user,rss,etime,args --sort=-rss | head -n 15'
  ps -eo pid,user,rss,etime,args --sort=-rss 2>&1 | head -n 15

  kop "PostgreSQL"
  doe pg_isready
  sql "SHOW max_connections"
  sql "SELECT current_setting('superuser_reserved_connections') AS superuser_reserved"
  sql "SELECT count(*) AS verbindingen FROM pg_stat_activity WHERE backend_type = 'client backend'"
  sql "SELECT usename, application_name, state, count(*) FROM pg_stat_activity WHERE backend_type = 'client backend'
       GROUP BY 1, 2, 3 ORDER BY 4 DESC"
  sql "SELECT version_num FROM alembic_version"
  sql "SELECT pg_size_pretty(pg_database_size(current_database())) AS grootte"

  kop "Back-ups ($BK)"
  doe ls -lt --time-style=long-iso "$BK"
  for f in "$BK"/voor-update-*.dump.versie "$BK"/voor-update-*.dump.teruggezet "$BK"/voor-update-*.dump.bezig \
           "$BK"/voor-terugzetten-*.dump.versie "$BK"/backuptest; do
    [ -f "$f" ] || continue
    echo "--- $f"
    cat "$f"
  done
  [ -d /mnt/homepage-backup ] && doe ls -lt --time-style=long-iso /mnt/homepage-backup

  kop "Configuratie ($CONF)"
  doe ls -l "$CONF"
  for f in kanaal branch nginx; do
    [ -r "$CONF/$f" ] || continue
    echo "--- $f"
    cat "$CONF/$f"
  done
  if [ -r "$CONF/homepage.env" ]; then
    echo "--- homepage.env (wat op een geheim lijkt: ***)"
    instellingen
  fi

  kop "Laatste install-log"
  f=$(find "$LOGS" -maxdepth 1 -name 'install-*.log' 2>/dev/null | sort | tail -1)
  if [ -n "$f" ]; then
    echo "$f (de laatste 200 regels)"
    tail -n 200 "$f" | sed 's/\x1b\[[0-9;]*m//g'
  else
    echo "(geen in $LOGS)"
  fi

  for d in homepage-api homepage-worker homepage-syslog nginx; do
    kop "journald: $d (laatste $REGELS regels)"
    doe journalctl -u "$d" -n "$REGELS" --no-pager -o short-iso
  done
  kop "journald: postgresql (laatste $REGELS regels)"
  doe journalctl -u postgresql -u 'postgresql@*' -n "$REGELS" --no-pager -o short-iso
  # Op Debian schrijft PostgreSQL zijn eigen log in /var/log/postgresql, nginx de fouten in /var/log/nginx.
  f=$(find /var/log/postgresql -maxdepth 1 -name 'postgresql-*.log' 2>/dev/null | sort | tail -1)
  [ -z "$f" ] || { echo "--- $f"; tail -n "$REGELS" "$f"; }
  [ -r /var/log/nginx/error.log ] && { echo "--- /var/log/nginx/error.log"; tail -n 50 /var/log/nginx/error.log; }
}

umask 077
BEKEND=$(bekend)
OUT="$UIT/homepage-diagnose-$(date +%Y%m%d-%H%M%S).txt"
if ! verslag 2>&1 | maskeren > "$OUT"; then
  echo "Schrijven naar $OUT lukte niet." >&2
  exit 1
fi
echo "$OUT"
echo "Kijk het na voor je het deelt: IP-adressen en namen staan erin, geheimen zijn gemaskeerd (***)."
