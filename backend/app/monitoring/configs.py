"""Configuratiewijzigingen opvolgen: elke nacht een kopie van de belangrijke configuratie, met een diff per dag.

Bronnen:
- OPNsense: config.xml via de API;
- Nginx Proxy Manager: de proxy hosts, redirections en streams als JSON;
- Proxmox: de .conf van elke VM en container (wat `qm config` / `pct config` toont);
- bestanden of mappen die je zelf kiest op een SSH-host (bv. /etc/nginx), als root gelezen.

Een nieuwe versie wordt alleen bewaard als ze verschilt; dan komt er een regel op de tijdlijn en een melding.
De inhoud staat versleuteld in de database. In de diff worden wachtwoorden en sleutels uit OPNsense gemaskeerd.
"""

import difflib
import hashlib
import json
import logging
import re
import shlex
from datetime import datetime, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import event, notify
from ..integrations import IntegrationError, build
from ..models import AppState, ConfigVersion, Service, SshHost
from ..security import decrypt, encrypt
from ..ssh_exec import SshFail, connect, run
from ..ssh_login import defaults, login_for
from .checks import HttpClients

log = logging.getLogger("homepage.configs")

SETTINGS_KEY = "config_settings"
LAST_KEY = "config_last"
DEFAULTS = {"hour": 2, "opnsense": True, "npm": True, "pve": True, "files": []}
MAX_SIZE = 2_000_000
KEEP_VERSIONS = 90
MAX_FILES = 300
PATH_RE = re.compile(r"^/[A-Za-z0-9._/@+\-]{1,200}$")
SECRET_TAGS = ("password", "passwd", "secret", "apikey", "api_key", "key", "prv", "private-key", "pre-shared-key", "psk",
               "auth_pass", "bcrypt-hash", "sha512-hash", "otp_seed", "ldap_bindpw", "privkey", "authorizedkeys",
               "radius_secret", "shared_secret", "pass", "token")
_SECRET = re.compile(r"<(" + "|".join(re.escape(t) for t in SECRET_TAGS) + r")>([^<]+)</\1>", re.I)
_JSON_SECRET = re.compile(r'("(?:password|secret|token|api_key|key)"\s*:\s*)"[^"]*"', re.I)
# Velden van NPM die bij elke aanvraag veranderen of niets zeggen.
NPM_NOISE = {"created_on", "modified_on", "owner", "owner_user_id", "certificate", "access_list"}

READ_FILES = r"""
for p in "$@"; do
  if [ -d "$p" ]; then
    find "$p" -xdev -type f -size -256k 2>/dev/null | sort | head -n {MAX}
  elif [ -f "$p" ]; then
    echo "$p"
  else
    echo "@@MISSING $p"
  fi
done | while IFS= read -r f; do
  case "$f" in @@MISSING*) echo "$f"; continue;; esac
  if grep -Iq . "$f" 2>/dev/null || [ ! -s "$f" ]; then
    echo "@@F $f"; cat "$f"; echo
  fi
done
"""


async def settings(db: AsyncSession) -> dict:
    st = await db.get(AppState, SETTINGS_KEY)
    return {**DEFAULTS, **(st.value if st else {})}


def mask(text: str) -> str:
    text = _SECRET.sub(lambda m: f"<{m[1]}>•••</{m[1]}>", text)
    return _JSON_SECRET.sub(lambda m: m[1] + '"•••"', text)


def _npm_text(hosts: dict[str, list]) -> str:
    def clean(x):
        if isinstance(x, dict):
            return {k: clean(v) for k, v in x.items() if k not in NPM_NOISE}
        if isinstance(x, list):
            return [clean(v) for v in x]
        return x
    out = {kind: sorted((clean(h) for h in items), key=lambda h: h.get("id") or 0) for kind, items in hosts.items()}
    return json.dumps(out, indent=1, sort_keys=True, ensure_ascii=False) + "\n"


def pve_text(cfg: dict) -> str:
    return "".join(f"{k}: {cfg[k]}\n" for k in sorted(cfg) if k != "digest")


async def from_opnsense(svc: Service, http: HttpClients) -> list[tuple]:
    return [(f"opnsense:{svc.id}", f"{svc.name} · config.xml", "opnsense", await build(svc, http).config_xml())]


async def from_npm(svc: Service, http: HttpClients) -> list[tuple]:
    npm = build(svc, http)
    hosts = {"proxy-hosts": await npm.get("/nginx/proxy-hosts") or []}
    for kind in ("redirection-hosts", "streams", "dead-hosts"):
        try:
            hosts[kind] = await npm.get(f"/nginx/{kind}") or []
        except IntegrationError:
            pass
    return [(f"npm:{svc.id}", f"{svc.name} · proxy hosts", "npm", _npm_text(hosts))]


async def from_proxmox(svc: Service, http: HttpClients, seen: set) -> list[tuple]:
    px = build(svc, http)
    out = []
    for g in await px.resources():
        if g.get("type") not in ("qemu", "lxc") or g.get("template") or g.get("vmid") in seen:
            continue
        seen.add(g.get("vmid"))
        cfg = await px.get(f"/nodes/{g['node']}/{g['type']}/{g['vmid']}/config")
        if isinstance(cfg, dict):
            label = f"{'VM' if g['type'] == 'qemu' else 'CT'} {g['vmid']} {g.get('name') or ''}".strip()
            out.append((f"pve:{svc.id}:{g['vmid']}", f"{label} · {g['vmid']}.conf", "pve", pve_text(cfg)))
    return out


def parse_files(text: str) -> tuple[dict[str, str], list[str]]:
    files: dict[str, list[str]] = {}
    missing, cur = [], None
    for line in text.split("\n"):
        if line.startswith("@@MISSING "):
            missing.append(line[10:])
            cur = None
        elif line.startswith("@@F "):
            cur = line[4:]
            files[cur] = []
        elif cur is not None:
            files[cur].append(line)
    # Elk bestand eindigt met de echo erachter: die lege regel weer weg.
    return {k: "\n".join(v[:-1] if v and v[-1] == "" else v) for k, v in files.items()}, missing


async def from_files(db: AsyncSession, h: SshHost, paths: list[str]) -> list[tuple]:
    login = await login_for(db, h, await defaults(db))
    script = READ_FILES.replace("{MAX}", str(MAX_FILES)) + "\n"
    args = " ".join(shlex.quote(p) for p in paths)
    async with connect(h, login) as conn:
        rc, out, err = await run(conn, f"set -- {args}\n{script}", login, timeout=300)
    files, missing = parse_files(out)
    res = [(f"file:{h.id}:{p}", f"{h.name}:{p}", "file", c) for p, c in files.items()]
    for p in missing:
        log.info("%s:%s bestaat niet", h.name, p)
    return res


async def gather(db: AsyncSession, http: HttpClients, cfg: dict) -> tuple[list[tuple], list[dict]]:
    items, errors = [], []
    types = [t for t, on in (("opnsense", cfg["opnsense"]), ("npm", cfg["npm"]), ("proxmox", cfg["pve"])) if on]
    seen: set = set()
    for svc in (await db.execute(select(Service).where(Service.type.in_(types)).order_by(Service.id))).scalars():
        try:
            if svc.type == "opnsense":
                items += await from_opnsense(svc, http)
            elif svc.type == "npm":
                items += await from_npm(svc, http)
            else:
                items += await from_proxmox(svc, http, seen)
        except IntegrationError as e:
            errors.append({"source": svc.name, "error": str(e)})
    by_host: dict[int, list[str]] = {}
    for f in cfg["files"]:
        by_host.setdefault(int(f["host_id"]), []).append(f["path"])
    for hid, paths in by_host.items():
        h = await db.get(SshHost, hid)
        if h is None:
            continue
        try:
            items += await from_files(db, h, paths)
        except SshFail as e:
            errors.append({"source": h.name, "error": str(e)})
    return items, errors


def counts(old: str, new: str) -> tuple[int, int]:
    added = removed = 0
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            removed += 1
    return added, removed


async def latest(db: AsyncSession, item: str) -> ConfigVersion | None:
    return (await db.execute(select(ConfigVersion).where(ConfigVersion.item == item)
                             .order_by(ConfigVersion.ts.desc(), ConfigVersion.id.desc()).limit(1))).scalar_one_or_none()


async def store(db: AsyncSession, item: str, name: str, kind: str, content: str,
                now: datetime) -> tuple[ConfigVersion | None, bool]:
    """Nieuwe versie als ze verschilt: (versie of None als ongewijzigd, of het de eerste is)."""
    if len(content) > MAX_SIZE:
        content = content[:MAX_SIZE]
    sha = hashlib.sha256(content.encode()).hexdigest()
    prev = await latest(db, item)
    if prev and prev.sha == sha:
        return None, False
    added, removed = counts(decrypt(prev.content), content) if prev else (len(content.splitlines()), 0)
    v = ConfigVersion(item=item, name=name[:300], kind=kind, ts=now, sha=sha, size=len(content), added=added,
                      removed=removed, content=encrypt(content))
    db.add(v)
    await db.flush()
    # Niet eindeloos bijhouden.
    ids = (await db.execute(select(ConfigVersion.id).where(ConfigVersion.item == item)
                            .order_by(ConfigVersion.ts.desc(), ConfigVersion.id.desc()).offset(KEEP_VERSIONS))).scalars().all()
    if ids:
        await db.execute(delete(ConfigVersion).where(ConfigVersion.id.in_(ids)))
    return v, prev is None


async def run_configs(db: AsyncSession, http: HttpClients) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    cfg = await settings(db)
    items, errors = await gather(db, http, cfg)
    changed = []
    for item, name, kind, content in items:
        v, first = await store(db, item, name, kind, content, now)
        if v is not None and not first:
            changed.append(v)
            event(db, "wijziging", f"Configuratie gewijzigd: {name}", f"+{v.added} −{v.removed} regels",
                  level="info", data={"config": v.id})
    if changed:
        lines = [f"{v.name}: +{v.added} −{v.removed}" for v in changed[:15]]
        notify(db, f"{len(changed)} configuratie{'s' if len(changed) != 1 else ''} gewijzigd", "\n".join(lines),
               level="info", source="config")
    value = {"at": now.isoformat(), "date": datetime.now().date().isoformat(), "items": len(items),
             "changed": len(changed), "errors": errors}
    st = await db.get(AppState, LAST_KEY)
    if st:
        st.value = value
    else:
        db.add(AppState(key=LAST_KEY, value=value))
    return value


async def due(db: AsyncSession, now: datetime | None = None) -> bool:
    """Elke nacht op het ingestelde uur, één keer per dag."""
    now = now or datetime.now().astimezone()
    cfg = await settings(db)
    st = await db.get(AppState, LAST_KEY)
    return now.hour == int(cfg["hour"]) and not (st and st.value.get("date") == now.date().isoformat())


async def overview(db: AsyncSession) -> list[dict]:
    sub = (select(ConfigVersion.item, func.max(ConfigVersion.ts).label("ts"), func.count().label("n"))
           .group_by(ConfigVersion.item).subquery())
    rows = (await db.execute(select(ConfigVersion, sub.c.n).join(
        sub, (ConfigVersion.item == sub.c.item) & (ConfigVersion.ts == sub.c.ts)).order_by(ConfigVersion.kind,
                                                                                            ConfigVersion.name))).all()
    out, seen = [], set()
    for v, n in rows:
        if v.item in seen:
            continue
        seen.add(v.item)
        out.append({"item": v.item, "name": v.name, "kind": v.kind, "ts": v.ts, "versions": n, "id": v.id,
                    "added": v.added if n > 1 else 0, "removed": v.removed if n > 1 else 0, "size": v.size})
    return out


def diff(old: str | None, new: str, old_label: str, new_label: str) -> str:
    return "\n".join(difflib.unified_diff(mask(old or "").splitlines(), mask(new).splitlines(), old_label, new_label,
                                          lineterm="", n=3))

