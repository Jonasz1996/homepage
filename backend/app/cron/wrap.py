"""Een cronjob "bewaken": de regel laten lopen via /usr/local/bin/hp-cron.

De wrapper voert het commando gewoon uit (cron mailt de uitvoer zoals altijd), maar meldt via syslog ook
het begin, het einde, de exitcode en de laatste uitvoer ("@@RUN {...}" met tag hp-cron), en elke regel
uitvoer ("[id] ...") zodat je live kan meekijken. De scanner leest die runs uit de journal; staat rsyslog
naar het dashboard aan, dan komen ze ook in de logviewer.

Aan- en uitzetten past alleen die ene regel aan; eerst gaat er een kopie naar /var/backups/hp-cron/.
"""

import base64
import re
import shlex

from .probe import WRAPPER, unwrap, wrap

HP_CRON = r"""#!/bin/sh
# hp-cron: voert een cronjob uit en meldt begin, einde, exitcode en uitvoer aan het homepage-dashboard (syslog).
# Gebruik: hp-cron <id> '<commando>'. Geïnstalleerd door het dashboard; weghalen kan via "bewaken uit".
ID="$1"; shift
CMD="$*"
DIR=/var/lib/hp-cron
mkdir -p "$DIR" 2>/dev/null
LOG="$DIR/$ID.log"; RCF="$DIR/$ID.rc"
START=$(date +%s)
logger -t hp-cron -- "@@START {\"id\":\"$ID\",\"start\":$START}" 2>/dev/null
{ sh -c "$CMD" 2>&1; echo $? > "$RCF"; } | tee "$LOG" | awk -v id="$ID" '{ print "[" id "] " $0; fflush() }' | logger -t hp-cron 2>/dev/null
RC=$(cat "$RCF" 2>/dev/null || echo 1)
END=$(date +%s)
OUT=$(tail -c 3000 "$LOG" 2>/dev/null | base64 | tr -d '\n')
logger -t hp-cron -- "@@RUN {\"id\":\"$ID\",\"start\":$START,\"end\":$END,\"rc\":$RC,\"out\":\"$OUT\"}" 2>/dev/null
cat "$LOG"
exit "$RC"
"""

USER_DIRS = ("/var/spool/cron/crontabs/", "/etc/crontabs/", "/var/spool/cron/")


class WrapError(Exception):
    pass


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def install_script() -> str:
    return (f"mkdir -p /usr/local/bin && echo {_b64(HP_CRON)} | base64 -d > {WRAPPER}.new && "
            f"chmod 755 {WRAPPER}.new && mv {WRAPPER}.new {WRAPPER} && echo @@OK")


def is_user_crontab(path: str) -> bool:
    return path.startswith(USER_DIRS)


def read_script(path: str, user: str) -> str:
    if is_user_crontab(path):
        return f"crontab -l -u {shlex.quote(user)} 2>/dev/null; echo '@@END'"
    return f"cat {shlex.quote(path)} && echo '@@END'"


def write_script(path: str, user: str, content: str) -> str:
    b = _b64(content)
    bk = "/var/backups/hp-cron/" + re.sub(r"[^\w.-]", "_", path.strip("/")) + ".$(date +%Y%m%d-%H%M%S)"
    if is_user_crontab(path):
        u = shlex.quote(user)
        return (f"mkdir -p /var/backups/hp-cron; crontab -l -u {u} > {bk} 2>/dev/null; "
                f"echo {b} | base64 -d | crontab -u {u} - && echo @@OK")
    q = shlex.quote(path)
    # Tijdelijk bestand met een punt in de naam: cron negeert dat in /etc/cron.d.
    return (f"mkdir -p /var/backups/hp-cron; cp -p {q} {bk}; "
            f"echo {b} | base64 -d > {q}.hp-new && chmod --reference={q} {q}.hp-new 2>/dev/null; "
            f"chown --reference={q} {q}.hp-new 2>/dev/null; mv {q}.hp-new {q} && echo @@OK")


_UNESCAPED_PCT = re.compile(r"(?<!\\)%")


def rewrite(content: str, rawline: str, raw_command: str, wid: str, on: bool) -> tuple[str, str, str]:
    """De ene regel vervangen; weigert als hij er niet precies één keer (ongewijzigd) in staat.
    Geeft (nieuwe inhoud, nieuwe regel, nieuw commando) terug."""
    lines = content.split("\n")
    hits = [i for i, line in enumerate(lines) if line.rstrip() == rawline.rstrip()]
    if len(hits) != 1:
        raise WrapError("De regel is ondertussen veranderd op de machine. Scan opnieuw en probeer nog eens.")
    line = lines[hits[0]].rstrip()
    if not line.endswith(raw_command):
        raise WrapError("Kon het commando in de regel niet terugvinden.")
    command, current = unwrap(raw_command)
    if on:
        if current:
            return content, line, raw_command
        if _UNESCAPED_PCT.search(command):
            raise WrapError("Deze regel gebruikt % als invoer voor het commando; die kan niet bewaakt worden.")
        new = wrap(command, wid)
    else:
        if not current:
            return content, line, raw_command
        new = command
    lines[hits[0]] = line[: len(line) - len(raw_command)] + new
    return "\n".join(lines), lines[hits[0]], new
