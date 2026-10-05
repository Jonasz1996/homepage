"""Twee PBS'en die elkaar aanvullen: de PBS die de back-ups van Proxmox krijgt (bron), en een tweede die er elke nacht
een kopie van ophaalt (doel, een sync-job van het type pull). Zo staat elke back-up op twee machines.

Het dashboard stelt de richting, datastores en het uur voor, toont de commando's om zelf te plakken en kan ze ook zelf
via SSH uitvoeren (recent ingelogd, nooit van buitenaf, in het auditlog).
"""

import re
from collections import Counter

import asyncssh
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import ssh_exec
from ..models import SshHost
from ..ssh_login import login_for

USER = "homepage-sync@pbs"
SAFE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9._-]{0,31}$")
HOST = re.compile(r"^[A-Za-z0-9.:-]{1,253}$")
TIME = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
FP = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){31}$")
SECRET = re.compile(r'"value"\s*:\s*"([^"]+)"')


def slug(name: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", (name or "").lower()).strip("-")[:24] or "pbs"


def gb(n: int | None) -> str:
    return "?" if n is None else f"{n / 1e12:.1f} TB" if n >= 1e12 else f"{n / 1e9:.0f} GB"


def links(pbs: list[dict]) -> list[dict]:
    """Bestaande syncs tussen gekende PBS'en: {from, to, job, on}."""
    by_host = {p["host"]: p for p in pbs if p.get("host")}
    out = []
    for p in pbs:
        remotes = {r["name"]: r.get("host") for r in p.get("remotes") or []}
        for j in p.get("syncs") or []:
            other = by_host.get(remotes.get(j.get("remote")))
            name = other["name"] if other else (j.get("remote") or "?")
            src, dst = (p["name"], name) if j.get("direction") == "push" else (name, p["name"])
            out.append({"from": src, "to": dst, "job": j.get("id"), "on": p["name"], "store": j.get("store"),
                        "remote_store": j.get("remote_store"), "schedule": j.get("schedule"),
                        "last_state": j.get("last_state"), "known": bool(other)})
    return out


def pick_time(schedules: list[str | None]) -> str:
    """Een uur waarop geen back-up start en de laatste minstens 2 uur bezig is: liefst vroeg in de ochtend."""
    starts = []
    for s in schedules:
        for h, m in re.findall(r"\b(\d{1,2}):(\d{2})\b", s or ""):
            starts.append(int(h) * 60 + int(m))
        if s and not starts and re.search(r"\bdaily\b", s):
            starts.append(0)
    for h in (6, 7, 5, 8, 4, 9, 3, 10, 12, 14, 16, 18, 20, 22, 2, 1, 0):
        if all((h * 60 - t) % 1440 >= 120 for t in starts):
            return f"{h:02d}:00"
    return "06:00"


def propose(value: dict | None) -> dict:
    """Wat er bestaat en wat het dashboard voorstelt."""
    value = value or {}
    pbs = [p for p in value.get("pbs") or [] if not p.get("error") and p.get("stores")]
    existing = links(value.get("pbs") or [])
    if len(pbs) < 2:
        return {"state": "te-weinig", "links": existing, "pbs": [p["name"] for p in pbs]}
    jobs = [j for c in value.get("clusters") or [] for j in c.get("jobs") or [] if j.get("pbs") and j.get("enabled")]
    hits = Counter(j.get("server") for j in jobs)
    # Bron: de PBS waar de back-upjobs van Proxmox naartoe schrijven (anders die met de meeste back-ups).
    src = max(pbs, key=lambda p: (hits.get(p["host"], 0), sum(s["groups"] for s in p["stores"])))
    rest = [p for p in pbs if p is not src]
    dst = max(rest, key=lambda p: max((s.get("avail") or 0) for s in p["stores"]))
    src_stores = Counter(j.get("datastore") for j in jobs if j.get("server") == src["host"])
    names = {s["store"] for s in src["stores"]}
    src_store = next((s for s, _ in src_stores.most_common() if s in names), None) \
        or max(src["stores"], key=lambda s: s["groups"])["store"]
    dst_store = max(dst["stores"], key=lambda s: s.get("avail") or 0)["store"]
    plan = {"source_id": src["service_id"], "target_id": dst["service_id"], "host": src["host"] or "",
            "port": src.get("port") or 8007, "src_store": src_store, "dst_store": dst_store,
            "schedule": pick_time([j.get("schedule") for j in jobs]), "fingerprint": src.get("fingerprint") or ""}
    done = [x for x in existing if x["from"] == src["name"] and x["to"] == dst["name"]]
    return {"state": "bestaat" if done else "voorstel", "links": existing, "plan": plan,
            "pbs": [{"service_id": p["service_id"], "name": p["name"], "host": p["host"],
                     "stores": [s["store"] for s in p["stores"]]} for p in pbs]}


def check(value: dict | None, plan: dict) -> dict:
    """Controle van een (aangepast) plan: geldige namen, en past de bron op het doel."""
    pbs = {p["service_id"]: p for p in (value or {}).get("pbs") or [] if not p.get("error")}
    src, dst = pbs.get(plan.get("source_id")), pbs.get(plan.get("target_id"))
    if not src or not dst or src is dst:
        raise ValueError("Kies twee verschillende PBS'en")
    s = next((x for x in src["stores"] if x["store"] == plan.get("src_store")), None)
    d = next((x for x in dst["stores"] if x["store"] == plan.get("dst_store")), None)
    if not s or not d or not SAFE.match(s["store"]) or not SAFE.match(d["store"]):
        raise ValueError("Onbekende datastore")
    if not HOST.match(plan.get("host") or ""):
        raise ValueError("Geen geldig adres voor de bron")
    if not TIME.match(plan.get("schedule") or ""):
        raise ValueError("Uur als 06:00")
    if plan.get("fingerprint") and not FP.match(plan["fingerprint"]):
        raise ValueError("Vingerafdruk ziet er niet goed uit (32 paren hex, met :)")
    port = int(plan.get("port") or 8007)
    if not 0 < port < 65536:
        raise ValueError("Poort tussen 1 en 65535")
    notes = []
    need, room = s.get("used"), d.get("avail")
    level = "ok"
    if need is not None and room is not None:
        if room < need:
            level = "err"
            notes.append(f"Past waarschijnlijk niet: {gb(need)} op {src['name']}, maar {gb(room)} vrij op {dst['name']}.")
        elif room < need * 1.3:
            level = "warn"
            notes.append(f"Krap: {gb(need)} op {src['name']}, {gb(room)} vrij op {dst['name']}.")
        else:
            notes.append(f"Past: {gb(need)} op {src['name']}, {gb(room)} vrij op {dst['name']}.")
    if port != 8007:
        notes.append(f"Poort {port}: loopt het adres via Nginx Proxy Manager, vul dan het IP van {src['name']} in "
                     "met poort 8007.")
    return {"level": level, "notes": notes, "src": src, "dst": dst,
            "plan": {**plan, "port": port, "remote": slug(src["name"]), "token": slug(dst["name"]),
                     "job": f"{slug(src['name'])}-naar-{slug(dst['name'])}"[:32]}}


def commands(c: dict) -> dict:
    """De commando's om zelf te plakken, per machine."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    tok = f"{USER}!{p['token']}"
    fp = p.get("fingerprint") or "<vingerafdruk van stap 1>"
    return {
        "source": [
            f"proxmox-backup-manager user create {USER} --comment 'sync naar {dst['name']}'",
            f"proxmox-backup-manager user generate-token {USER} {p['token']}",
            f"proxmox-backup-manager acl update /datastore/{p['src_store']} DatastoreReader --auth-id {USER}",
            f"proxmox-backup-manager acl update /datastore/{p['src_store']} DatastoreReader --auth-id '{tok}'",
        ] + ([] if p.get("fingerprint") else ["proxmox-backup-manager cert info | grep -i fingerprint"]),
        "target": [
            f"proxmox-backup-manager remote create {p['remote']} --host {p['host']} --port {p['port']} "
            f"--auth-id '{tok}' --password '<geheim uit stap 1>' --fingerprint '{fp}'",
            f"proxmox-backup-manager sync-job create {p['job']} --store {p['dst_store']} --remote {p['remote']} "
            f"--remote-store {p['src_store']} --schedule '{p['schedule']}' --remove-vanished false "
            f"--comment 'kopie van {src['name']}'",
        ],
    }


def _source_script(p: dict, dst_name: str) -> str:
    return f"""set -e
U='{USER}'; T='{p['token']}'; S='{p['src_store']}'
proxmox-backup-manager user list --output-format json | grep -q "$U" || \\
  proxmox-backup-manager user create "$U" --comment 'sync naar {slug(dst_name)}, door de homepage'
proxmox-backup-manager user delete-token "$U" "$T" >/dev/null 2>&1 || true
proxmox-backup-manager user generate-token "$U" "$T" --output-format json
proxmox-backup-manager acl update "/datastore/$S" DatastoreReader --auth-id "$U"
proxmox-backup-manager acl update "/datastore/$S" DatastoreReader --auth-id "$U!$T"
"""


def _target_script(p: dict, src_name: str) -> str:
    return f"""set -e
IFS= read -r PW
R='{p['remote']}'; J='{p['job']}'
ARGS="--host {p['host']} --port {p['port']} --auth-id {USER}!{p['token']} --fingerprint {p['fingerprint']}"
if proxmox-backup-manager remote list --output-format json | grep -q "\\"$R\\""; then
  proxmox-backup-manager remote update "$R" $ARGS --password "$PW"
else
  proxmox-backup-manager remote create "$R" $ARGS --password "$PW"
fi
if proxmox-backup-manager sync-job list --output-format json | grep -q "\\"$J\\""; then
  echo "sync-job $J bestond al"
else
  proxmox-backup-manager sync-job create "$J" --store '{p['dst_store']}' --remote "$R" --remote-store '{p['src_store']}' \\
    --schedule '{p['schedule']}' --remove-vanished false --comment 'kopie van {slug(src_name)}, door de homepage'
fi
echo klaar
"""


async def ssh_host(db: AsyncSession, p: dict) -> SshHost | None:
    """De SSH-host van een PBS-tegel: gekoppeld aan de tegel, hetzelfde adres of dezelfde naam."""
    conds = [SshHost.service_id == p["service_id"], SshHost.name.ilike(p["name"])]
    if p.get("host"):
        conds.append(SshHost.host == p["host"])
    hosts = list((await db.execute(select(SshHost).where(or_(*conds)).order_by(SshHost.id))).scalars())
    rank = lambda h: (h.service_id != p["service_id"], h.name.lower() != p["name"].lower(), h.host != p.get("host"))  # noqa: E731
    return min(hosts, key=rank) if hosts else None


async def _run(db: AsyncSession, h: SshHost, script: str, stdin: str | None = None) -> tuple[int, str]:
    login = await login_for(db, h)
    async with ssh_exec.connect(h, login) as conn:
        try:
            # Zonder invoer: stdin meteen dicht, zodat niets blijft wachten op een toetsenbord.
            io = {"input": stdin} if stdin is not None else {"stdin": asyncssh.DEVNULL}
            r = await conn.run(ssh_exec.command(script, login), check=False, timeout=120, **io)
        except (OSError, asyncssh.Error) as e:
            raise ssh_exec.SshFail(f"SSH-fout: {e}") from e
    return int(r.exit_status or 0), f"{r.stdout or ''}{r.stderr or ''}"


async def hosts(db: AsyncSession, c: dict) -> tuple[SshHost, SshHost]:
    """De SSH-hosts van bron en doel, of een ValueError die zegt wat er ontbreekt."""
    src, dst = c["src"], c["dst"]
    if not c["plan"].get("fingerprint"):
        raise ValueError(f"Vingerafdruk van {src['name']} onbekend: vul ze in (stap 1, cert info)")
    hs, hd = await ssh_host(db, src), await ssh_host(db, dst)
    missing = [x["name"] for x, h in ((src, hs), (dst, hd)) if not h]
    if missing:
        raise ValueError(f"Geen SSH-host voor {' en '.join(missing)}: voeg die toe in de terminal en open er één keer "
                         "een terminal naar")
    return hs, hd


async def create(db: AsyncSession, c: dict, hs: SshHost, hd: SshHost) -> list[str]:
    """Uitvoeren op beide PBS'en. Geeft het verloop terug (zonder het geheim)."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    log = [f"$ op {src['name']} ({hs.host}): gebruiker {USER}, token {p['token']}, leesrecht op {p['src_store']}"]
    code, out = await _run(db, hs, _source_script(p, dst["name"]))
    m = SECRET.search(out)
    if code or not m:
        masked = SECRET.sub('"value":"…"', out)
        raise ssh_exec.SshFail(f"Op {src['name']} mislukt (exit {code}): {masked[-600:]}")
    log.append("  token aangemaakt")
    log.append(f"$ op {dst['name']} ({hd.host}): remote {p['remote']} en sync-job {p['job']} om {p['schedule']}")
    code, out = await _run(db, hd, _target_script(p, src["name"]), stdin=m.group(1) + "\n")
    if code:
        raise ssh_exec.SshFail(f"Op {dst['name']} mislukt (exit {code}): {out[-600:]}")
    log.extend(f"  {line}" for line in out.strip().splitlines()[-6:])
    return log
