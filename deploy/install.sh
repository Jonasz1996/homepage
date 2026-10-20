#!/usr/bin/env bash
# Installeert of werkt homepage bij in een Debian 12/13 LXC-container.
# Meestal via deploy/bootstrap.sh (haalt eerst de code op). Rechtstreeks, als root:
#   bash /opt/homepage/deploy/install.sh
# Opnieuw uitvoeren werkt alles bij; bestaande sleutels en data blijven staan.
set -euo pipefail

APP_DIR=/opt/homepage
CONF_DIR=/etc/homepage
# NPM_IP: het IP van Nginx Proxy Manager. Wordt bij de eerste keer bewaard in homepage.env en daarna daar gelezen.
NPM_IP="${NPM_IP:-$(sed -n 's/^HOMEPAGE_NPM_IP=//p' "$CONF_DIR/homepage.env" 2>/dev/null | tail -1 || true)}"
NPM_IP="${NPM_IP:-192.168.0.245}"

say() { printf '\n\033[1;37m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m!! %s\033[0m\n' "$*"; }

[ "$(id -u)" -eq 0 ] || { echo "Voer uit als root."; exit 1; }
[ -d "$APP_DIR/backend" ] || { echo "Verwacht de repository in $APP_DIR."; exit 1; }
# shellcheck source=/dev/null
. /etc/os-release
case "$VERSION_CODENAME" in
  bookworm|trixie) ;;
  *) warn "Getest op Debian 12 (bookworm) en 13 (trixie), dit is $PRETTY_NAME." ;;
esac

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
    warn "TimescaleDB kon niet geïnstalleerd worden. Alles werkt, alleen ruimt de worker oude metingen dan zelf op (90 dagen)."
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

# Map voor de dagelijkse back-up: postgres schrijft, de worker (groep homepage) leest om ze te controleren.
install -d -m 750 -o postgres -g homepage /var/backups/homepage

# IP van deze container voor de rsyslog-configuratie op andere machines (fase 6).
if ! grep -q '^HOMEPAGE_SYSLOG_TARGET=' "$CONF_DIR/homepage.env"; then
  echo "HOMEPAGE_SYSLOG_TARGET=$(hostname -I | awk '{print $1}')" >> "$CONF_DIR/homepage.env"
fi

say "Backend (Python)"
[ -d "$APP_DIR/.venv" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q "$APP_DIR/backend"
chown -R root:root "$APP_DIR"

# Eerst bouwen, dan pas de database bijwerken: mislukt de build, dan blijft alles zoals het was.
say "Frontend bouwen"
(cd "$APP_DIR/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent)

set -a
# shellcheck source=/dev/null
. "$CONF_DIR/homepage.env"
set +a
say "Database bijwerken"
# Welke versie draaide er tot nu toe (voor homepage-terugzetten).
PREV_COMMIT=$(sed -n 's/^commit=//p' "$CONF_DIR/versie" 2>/dev/null || true)
PREV_VERSIE=$(sed -n 's/^versie=//p' "$CONF_DIR/versie" 2>/dev/null || true)
if [ -z "$PREV_COMMIT" ] && [ -n "${HOMEPAGE_PREV_COMMIT:-}" ]; then
  PREV_COMMIT=$HOMEPAGE_PREV_COMMIT
  PREV_VERSIE=$(git -C "$APP_DIR" describe --tags --always "$PREV_COMMIT" 2>/dev/null || true)
fi
NOW_COMMIT=$(git -C "$APP_DIR" rev-parse HEAD 2>/dev/null || true)
if [ -n "${HOMEPAGE_TERUGZETTEN:-}" ]; then
  echo "Terugzetten: de database is al teruggezet, geen nieuwe kopie."
elif runuser -u postgres -- psql -d homepage -tAc "SELECT 1 FROM alembic_version" 2>/dev/null | grep -q 1; then
  # Bestaande installatie: eerst een kopie, zodat een mislukte migratie terug te draaien is. De laatste 3 blijven staan.
  DUMP="/var/backups/homepage/voor-update-$(date +%Y%m%d-%H%M%S).dump"
  if runuser -u postgres -- sh -c "pg_dump -Fc homepage > '$DUMP.tmp' && mv '$DUMP.tmp' '$DUMP'"; then
    echo "Kopie van de database: $DUMP"
    # Naast de kopie: welke versie erbij hoort. Zonder andere versie (opnieuw dezelfde installeren) valt er niets terug te zetten.
    if [ -n "$PREV_COMMIT" ] && [ "$PREV_COMMIT" != "$NOW_COMMIT" ]; then
      printf 'commit=%s\nversie=%s\n' "$PREV_COMMIT" "${PREV_VERSIE:-${PREV_COMMIT:0:7}}" > "$DUMP.versie"
    fi
  else
    warn "Kopie van de database mislukt; toch verder."
  fi
  find /var/backups/homepage -name 'voor-update-*.dump' -printf '%T@ %p\n' | sort -rn | tail -n +4 | cut -d' ' -f2- \
    | while read -r f; do rm -f "$f" "$f.versie" "$f.teruggezet"; done
fi
(cd "$APP_DIR/backend" && runuser -u homepage -- env HOMEPAGE_DATABASE_URL="$HOMEPAGE_DATABASE_URL" \
  "$APP_DIR/.venv/bin/alembic" upgrade head)

say "nginx"
NPM_IP_RE="${NPM_IP//./\\\\.}"
sed "s/__NPM_IP_RE__/$NPM_IP_RE/" "$APP_DIR/deploy/nginx-map.conf" > /etc/nginx/conf.d/homepage-map.conf
install -D -m 644 "$APP_DIR/deploy/nginx-headers.conf" /etc/nginx/snippets/homepage-headers.conf
sed "s/__NPM_IP__/$NPM_IP/" "$APP_DIR/deploy/nginx.conf" > /etc/nginx/sites-available/homepage
# Zonder IPv6 in de container kan nginx niet op [::] luisteren.
[ -e /proc/net/if_inet6 ] || sed -i '/listen \[::\]/d' /etc/nginx/sites-available/homepage
ln -sf /etc/nginx/sites-available/homepage /etc/nginx/sites-enabled/homepage
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl reload nginx || systemctl restart nginx

say "Services"
# Een update terugdraaien: vorige versie plus de kopie van de database van vlak voor die update.
install -m 755 "$APP_DIR/deploy/terugzetten.sh" /usr/local/sbin/homepage-terugzetten
install -m 644 "$APP_DIR/deploy/homepage-api.service" "$APP_DIR/deploy/homepage-worker.service" \
  "$APP_DIR/deploy/homepage-syslog.service" /etc/systemd/system/
install -m 644 "$APP_DIR/deploy/homepage-backup.service" "$APP_DIR/deploy/homepage-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now homepage-backup.timer
systemctl enable homepage-api homepage-worker homepage-syslog
systemctl restart homepage-api homepage-worker homepage-syslog
API_OK=""
for _ in $(seq 20); do
  if curl -fsS http://127.0.0.1/api/ping >/dev/null 2>&1; then API_OK=1; break; fi
  sleep 1
done
if [ -n "$API_OK" ]; then
  echo "API draait."
else
  warn "API reageert niet: journalctl -u homepage-api"
fi

# Wat er nu draait: het dashboard toont het (en wat er nieuw is), homepage-terugzetten gebruikt het.
VERSIE=$(git -C "$APP_DIR" describe --tags --always 2>/dev/null || echo onbekend)
KANAAL="${HOMEPAGE_KANAAL:-$(sed -n 's/^kanaal=//p' "$CONF_DIR/versie" 2>/dev/null || true)}"
printf 'versie=%s\ncommit=%s\nkanaal=%s\ndatum=%s\n' "$VERSIE" "$NOW_COMMIT" "${KANAAL:-nieuwste}" "$(date -Iseconds)" \
  > "$CONF_DIR/versie"
chgrp homepage "$CONF_DIR/versie" && chmod 640 "$CONF_DIR/versie"

IP=$(hostname -I | awk '{print $1}')
say "Klaar (versie $VERSIE, ${KANAAL:-nieuwste})"
cat <<EOF
Dashboard: http://$IP
Testen kan meteen op dat adres. Voor gebruik van buitenaf: in Nginx Proxy Manager een HTTPS-host
(bv. home.jbogaert.be) naar http://$IP:80 met "Websockets Support" aan.
Bijwerken: hetzelfde bootstrap-commando opnieuw uitvoeren.
Werkt iets niet meer na een update: homepage-terugzetten (vorige versie plus de database van daarvoor).
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
