#!/usr/bin/env bash
# Installeert of werkt homepage bij in een Debian 12/13 LXC-container.
# Gebruik (als root):
#   apt install -y git && git clone https://github.com/Jonasz1996/homepage /opt/homepage
#   bash /opt/homepage/deploy/install.sh
# Opnieuw uitvoeren na een `git pull` werkt alles bij; bestaande sleutels en data blijven staan.
set -euo pipefail

APP_DIR=/opt/homepage
CONF_DIR=/etc/homepage
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
    warn "TimescaleDB kon niet geïnstalleerd worden. Het dashboard werkt, maar fase 3 heeft het nodig."
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
NEW_TOKEN=""
if [ ! -f "$CONF_DIR/setup-token" ]; then
  NEW_TOKEN=$(openssl rand -hex 12)
  echo "$NEW_TOKEN" > "$CONF_DIR/setup-token"
  chown root:homepage "$CONF_DIR/setup-token"; chmod 640 "$CONF_DIR/setup-token"
fi
if [ ! -f "$CONF_DIR/homepage.env" ]; then
  install -m 640 -o root -g homepage "$APP_DIR/deploy/homepage.env.example" "$CONF_DIR/homepage.env"
fi

say "Backend (Python)"
[ -d "$APP_DIR/.venv" ] || python3 -m venv "$APP_DIR/.venv"
"$APP_DIR/.venv/bin/pip" install -q --upgrade pip
"$APP_DIR/.venv/bin/pip" install -q "$APP_DIR/backend"
chown -R root:root "$APP_DIR"
set -a
# shellcheck source=/dev/null
. "$CONF_DIR/homepage.env"
set +a
(cd "$APP_DIR/backend" && runuser -u homepage -- env HOMEPAGE_DATABASE_URL="$HOMEPAGE_DATABASE_URL" \
  "$APP_DIR/.venv/bin/alembic" upgrade head)

say "Frontend bouwen"
(cd "$APP_DIR/frontend" && npm ci --no-audit --no-fund --loglevel=error && npm run build --silent)

say "nginx"
install -m 644 "$APP_DIR/deploy/nginx-map.conf" /etc/nginx/conf.d/homepage-map.conf
sed "s/__NPM_IP__/$NPM_IP/" "$APP_DIR/deploy/nginx.conf" > /etc/nginx/sites-available/homepage
ln -sf /etc/nginx/sites-available/homepage /etc/nginx/sites-enabled/homepage
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl enable nginx
systemctl reload nginx || systemctl restart nginx

say "Services"
install -m 644 "$APP_DIR/deploy/homepage-api.service" "$APP_DIR/deploy/homepage-worker.service" /etc/systemd/system/
install -m 644 "$APP_DIR/deploy/homepage-backup.service" "$APP_DIR/deploy/homepage-backup.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now homepage-backup.timer
systemctl enable homepage-api homepage-worker
systemctl restart homepage-api homepage-worker
sleep 2
if curl -fsS http://127.0.0.1/api/health >/dev/null; then
  echo "API draait."
else
  warn "API reageert niet: journalctl -u homepage-api"
fi

IP=$(hostname -I | awk '{print $1}')
say "Klaar"
cat <<EOF
Dashboard: http://$IP (zet er in Nginx Proxy Manager een HTTPS-host voor, bv. home.jbogaert.be)

Inloggen werkt alleen via HTTPS (veilige cookie). Wil je eerst rechtstreeks via http://$IP testen,
zet dan HOMEPAGE_COOKIE_SECURE=false in $CONF_DIR/homepage.env en voer
'systemctl restart homepage-api' uit. Zet het daarna terug op true.
EOF
if [ -n "$NEW_TOKEN" ]; then
  echo
  echo "Setup-code voor het eerste account: $NEW_TOKEN"
  echo "(ook in $CONF_DIR/setup-token)"
fi
echo
echo "Bewaar een kopie van $CONF_DIR/secret.key op een veilige plek: zonder die sleutel zijn opgeslagen wachtwoorden en API-sleutels onleesbaar."
