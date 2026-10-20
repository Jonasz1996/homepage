"""SSH-sleutel van het dashboard vastzetten op het dashboard zelf.

Het dashboard zet `from="<IP>"` voor zijn sleutel in ~/.ssh/authorized_keys van elke machine. Een gestolen sleutel
werkt dan alleen nog vanaf de dashboard-container. Het IP is wat de machine zelf als afzender ziet (SSH_CLIENT),
dus ook achter een router tussen de VLAN's klopt het.

Zo gaat het per machine:
1. inloggen, authorized_keys lezen (via readlink: op een Proxmox-node is het een link naar /etc/pve/priv, gedeeld
   door de hele cluster) en de regel met onze sleutel aanpassen;
2. het oude bestand bewaren als ~/.ssh/authorized_keys.homepage-bak en het nieuwe in hetzelfde bestand schrijven
   (cat >, zodat een link en de rechten blijven), alleen als het bestand intussen niet veranderde;
3. met een tweede verbinding nagaan of het dashboard er nog in kan. Lukt dat niet, dan zet de eerste verbinding het
   oude bestand terug.
"""

import asyncio
import hashlib
import re
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone

import asyncssh
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AppState, SshHost
from .ssh_exec import SshFail, connect
from .ssh_login import Login, login_for

STATE_KEY = "ssh_pin"
PARALLEL = 4
TIMEOUT = 30
FROM_RE = re.compile(r'(^|,)from="[^"]*"')
BAK = "$HOME/.ssh/authorized_keys.homepage-bak"

READ = r'''f="$HOME/.ssh/authorized_keys"
[ -e "$f" ] || { echo "GEEN"; exit 0; }
real=$(readlink -f "$f")
echo "${SSH_CLIENT%% *}"
echo "$real"
cat "$real"'''

# $1 = echte pad, $2 = sha256 van het bestand zoals we het lazen, $3 = lengte van het nieuwe bestand.
WRITE = r'''set -e
real="$1"; tmp="$HOME/.ssh/.authorized_keys.homepage-nieuw"
umask 077
cat > "$tmp"
[ "$(wc -c < "$tmp" | tr -d ' ')" = "$3" ] || { rm -f "$tmp"; echo "ONVOLLEDIG"; exit 1; }
[ "$(sha256sum "$real" | cut -d' ' -f1)" = "$2" ] || { rm -f "$tmp"; echo "VERANDERD"; exit 1; }
cp -p "$real" "$HOME/.ssh/authorized_keys.homepage-bak"
cat "$tmp" > "$real"
rm -f "$tmp"
echo OK'''

RESTORE = r'''cat "$HOME/.ssh/authorized_keys.homepage-bak" > "$1" && echo OK'''


@dataclass
class KeyLine:
    options: str
    rest: str  # "ssh-ed25519 AAAA... commentaar"


def _split(line: str, blob: str) -> KeyLine | None:
    """Opties en sleutel van een regel met deze sleutel, of None."""
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    pos = s.find(" " + blob)
    if pos < 0:
        return None
    head = s[:pos].rstrip()  # opties + sleuteltype
    if " " in head or "\t" in head:
        # Opties kunnen tussen aanhalingstekens spaties bevatten: het sleuteltype is het laatste woord.
        cut = max(head.rfind(" "), head.rfind("\t"))
        options, keytype = head[:cut].strip(), head[cut + 1:]
    else:
        options, keytype = "", head
    return KeyLine(options, f"{keytype} {s[pos + 1:]}")


def pinned_from(text: str, blob: str) -> list[str | None]:
    """Voor elke regel met deze sleutel: de waarde van from= (of None)."""
    out = []
    for line in text.splitlines():
        kl = _split(line, blob)
        if kl:
            m = re.search(r'(?:^|,)from="([^"]*)"', kl.options)
            out.append(m.group(1) if m else None)
    return out


def rewrite(text: str, blob: str, ip: str | None) -> tuple[str, int]:
    """Zet from="ip" (of haalt from= weg als ip None is) op elke regel met deze sleutel. (nieuwe tekst, aantal)."""
    lines, n = [], 0
    for line in text.splitlines():
        kl = _split(line, blob)
        if kl is None:
            lines.append(line)
            continue
        opts = FROM_RE.sub("", kl.options).lstrip(",")
        if ip:
            opts = f'from="{ip}"' + (f",{opts}" if opts else "")
        lines.append(f"{opts} {kl.rest}" if opts else kl.rest)
        n += 1
    return "\n".join(lines) + ("\n" if text.endswith("\n") or not text else ""), n


def blob_of(key: asyncssh.SSHKey) -> str:
    return key.export_public_key().decode().split()[1]


async def _sh(conn, script: str, *args: str, stdin: str | None = None) -> tuple[int, str]:
    """Als de loginnaam zelf, zonder sudo: het gaat om zijn eigen authorized_keys."""
    cmd = "sh -c " + shlex.quote(script) + " homepage " + " ".join(shlex.quote(a) for a in args)
    try:
        r = await asyncio.wait_for(conn.run(cmd, input=stdin, check=False), TIMEOUT)
    except asyncio.TimeoutError as e:
        raise SshFail("Geen antwoord binnen 30 s") from e
    except (OSError, asyncssh.Error) as e:
        raise SshFail(f"SSH-fout: {e}") from e
    return int(r.exit_status or 0), str(r.stdout or "")


async def _read(conn) -> tuple[str | None, str, str]:
    """(afzender-IP zoals de machine het ziet, pad, inhoud); pad None = geen authorized_keys."""
    code, out = await _sh(conn, READ)
    if out.startswith("GEEN"):
        return None, "", ""
    ip, _, rest = out.partition("\n")
    real, _, text = rest.partition("\n")
    return ip.strip() or None, real.strip(), text


def _covers(value: str | None, ip: str | None) -> bool:
    return bool(value and ip and ip in [x.strip() for x in value.split(",")])


def _host_status(blob: str, ip: str | None, real: str | None, text: str) -> dict:
    if real is None:
        return {"state": "geen", "text": "geen authorized_keys (aanmelden met wachtwoord?)"}
    froms = pinned_from(text, blob)
    if not froms:
        return {"state": "geen", "text": "sleutel staat niet in authorized_keys (aanmelden met wachtwoord?)", "path": real}
    if all(_covers(f, ip) for f in froms):
        return {"state": "vast", "text": f"alleen vanaf {', '.join(sorted(set(froms)))}", "ip": ip, "path": real}
    if all(f for f in froms):
        return {"state": "anders", "text": f"vast op {', '.join(sorted(set(froms)))}, het dashboard komt binnen als {ip}",
                "ip": ip, "path": real}
    return {"state": "los", "text": "werkt vanaf elk IP", "ip": ip, "path": real}


async def check(h: SshHost, login: Login) -> dict:
    if login.key is None:
        return {"state": "geen", "text": "geen sleutel: deze host gebruikt een wachtwoord"}
    blob = blob_of(login.key)
    async with connect(h, login) as conn:
        ip, real, text = await _read(conn)
    return _host_status(blob, ip, real, text)


async def _verify(h: SshHost, login: Login) -> bool:
    try:
        async with connect(h, login) as conn:
            await asyncio.wait_for(conn.run("true", check=False), TIMEOUT)
        return True
    except (SshFail, asyncio.TimeoutError, OSError, asyncssh.Error):
        return False


async def change(h: SshHost, login: Login, pin: bool, also: set[str] | frozenset = frozenset()) -> dict:
    """Vastzetten (pin) of losmaken, met controle en terugzetten als het dashboard er daarna niet meer in kan.
    also: IP's waarmee het dashboard bij andere machines binnenkomt. Meestal hetzelfde ene IP, maar een gedeeld
    bestand (cluster) moet voor alle nodes kloppen."""
    if login.key is None:
        return {"state": "geen", "text": "geen sleutel: deze host gebruikt een wachtwoord"}
    blob = blob_of(login.key)
    async with connect(h, login) as conn:
        for _ in range(3):  # een gedeeld bestand kan net door een andere node aangepast zijn: opnieuw lezen
            ip, real, text = await _read(conn)
            before = _host_status(blob, ip, real, text)
            if before["state"] == "geen":
                return before
            if not ip:
                return {**before, "error": "De machine geeft niet door van welk IP het dashboard komt (SSH_CLIENT)"}
            if before["state"] == ("vast" if pin else "los"):
                return before
            new, n = rewrite(text, blob, ",".join(sorted({ip, *also})) if pin else None)
            sha = hashlib.sha256(text.encode()).hexdigest()
            code, out = await _sh(conn, WRITE, real, sha, str(len(new.encode())), stdin=new)
            if "VERANDERD" not in out:
                break
        if code or "OK" not in out:
            why = "het bestand veranderde telkens tijdens het aanpassen" if "VERANDERD" in out else out.strip()[:200] or f"code {code}"
            return {**before, "error": f"Niet aangepast: {why}"}
        if not await _verify(h, login):
            await _sh(conn, RESTORE, real)
            return {**before, "error": f"Teruggezet: daarna kon het dashboard niet meer aanmelden vanaf {ip}"}
    return {**_host_status(blob, ip, real, new), "changed": n}


async def save(db: AsyncSession, results: dict[int, dict]) -> dict:
    st = await db.get(AppState, STATE_KEY)
    if st is None:
        st = AppState(key=STATE_KEY, value={})
        db.add(st)
    now = datetime.now(timezone.utc).isoformat()
    hosts = dict((st.value or {}).get("hosts") or {})
    for hid, r in results.items():
        hosts[str(hid)] = {**r, "at": now}
    st.value = {"hosts": hosts, "checked_at": now}
    return st.value


async def seen_ips(db: AsyncSession) -> set[str]:
    """IP's waarmee het dashboard bij de machines binnenkomt (uit de laatste controles)."""
    st = await db.get(AppState, STATE_KEY)
    return {r["ip"] for r in ((st.value or {}).get("hosts") or {}).values() if r.get("ip")} if st else set()


async def run_all(db: AsyncSession, hosts: list[SshHost], fn) -> dict[int, dict]:
    """fn(h, login) voor elke host, een paar tegelijk. Een fout bij één host stopt de rest niet.
    De logins eerst ophalen: de databasesessie mag niet door meerdere taken tegelijk gebruikt worden."""
    logins = [(h, await login_for(db, h)) for h in hosts]
    sem = asyncio.Semaphore(PARALLEL)

    async def one(h: SshHost, login: Login) -> tuple[int, dict]:
        async with sem:
            try:
                return h.id, await fn(h, login)
            except SshFail as e:
                return h.id, {"state": "fout", "text": str(e)}

    return dict(await asyncio.gather(*(one(h, lg) for h, lg in logins)))


async def all_hosts(db: AsyncSession, ids: list[int] | None = None) -> list[SshHost]:
    q = select(SshHost).order_by(SshHost.position, SshHost.id)
    if ids is not None:
        q = q.where(SshHost.id.in_(ids))
    return list((await db.execute(q)).scalars())
