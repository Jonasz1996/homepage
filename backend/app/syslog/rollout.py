"""rsyslog op andere machines instellen zodat ze hun logs naar het dashboard sturen.

Draait via de opgeslagen SSH-host (zie routers/ssh.py). Op een Proxmox-node kan het script
ook alle draaiende containers meenemen via `pct push` en `pct exec`.
"""

import shlex

# Draait op de machine zelf (Debian/Ubuntu, Alpine of Fedora/RHEL). Argumenten: doel-IP en poort.
CLIENT = r'''set -e
T="$1"; P="$2"
if ! command -v rsyslogd >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get install -y -q rsyslog >/dev/null 2>&1 || { apt-get update -q >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get install -y -q rsyslog >/dev/null; }
  elif command -v apk >/dev/null 2>&1; then apk add -q rsyslog
  elif command -v dnf >/dev/null 2>&1; then dnf install -y -q rsyslog
  else echo "FOUT $(hostname): geen apt, apk of dnf"; exit 1; fi
fi
mkdir -p /etc/rsyslog.d
cat > /etc/rsyslog.d/90-homepage.conf <<HPCONF
# Beheerd door homepage: alle logs naar het dashboard, via TCP met een wachtrij als het dashboard even weg is.
*.* action(type="omfwd" target="$T" port="$P" protocol="tcp" action.resumeRetryCount="-1"
           queue.type="linkedList" queue.size="20000" queue.filename="homepage_fwd" queue.saveOnShutdown="on")
HPCONF
if [ -d /run/systemd/system ]; then
  mkdir -p /etc/systemd/journald.conf.d
  printf '[Journal]\nForwardToSyslog=yes\n' > /etc/systemd/journald.conf.d/homepage.conf
  systemctl restart systemd-journald
  systemctl enable rsyslog >/dev/null 2>&1 || true
  systemctl restart rsyslog
elif command -v rc-service >/dev/null 2>&1; then
  rc-update add rsyslog default >/dev/null 2>&1 || true
  rc-service rsyslog restart >/dev/null
else
  service rsyslog restart
fi
logger -t homepage "rsyslog ingesteld door het dashboard"
echo "ok $(hostname)"
'''

# Draait op de SSH-host; schrijft CLIENT weg en voert het uit, eventueel ook in alle containers.
WRAPPER = r'''set -u
cat > /tmp/hp-rsyslog.sh <<'HPSCRIPT'
__CLIENT__
HPSCRIPT
# Dit script komt via stdin binnen (sh -s): commando's krijgen /dev/null als stdin, anders eten ze de rest op.
sh /tmp/hp-rsyslog.sh __TARGET__ __PORT__ </dev/null || echo "FOUT op $(hostname)"
if [ "__CONTAINERS__" = 1 ]; then
  if ! command -v pct >/dev/null 2>&1; then echo "geen Proxmox-node (pct ontbreekt), containers overgeslagen"; exit 0; fi
  for id in $(pct list </dev/null | awk 'NR>1 && $2=="running" {print $1}'); do
    echo "--- CT $id"
    pct push "$id" /tmp/hp-rsyslog.sh /tmp/hp-rsyslog.sh && pct exec "$id" -- sh /tmp/hp-rsyslog.sh __TARGET__ __PORT__ </dev/null || echo "FOUT in CT $id"
  done
fi
rm -f /tmp/hp-rsyslog.sh
'''


def build(target: str, port: int, containers: bool) -> str:
    return (WRAPPER.replace("__CLIENT__", CLIENT.strip())
            .replace("__TARGET__", shlex.quote(target))
            .replace("__PORT__", str(int(port)))
            .replace("__CONTAINERS__", "1" if containers else "0"))


def manual(target: str, port: int) -> str:
    """Wat je zelf als root op een machine plakt."""
    return (f"cat > /tmp/hp-rsyslog.sh <<'HPSCRIPT'\n{CLIENT.strip()}\nHPSCRIPT\n"
            f"sh /tmp/hp-rsyslog.sh {shlex.quote(target)} {int(port)}")
