"""Twee PBS'en die elkaar aanvullen: de PBS die de back-ups van Proxmox krijgt (bron), en een tweede die er elke nacht
een kopie van ophaalt (doel, een sync-job van het type pull). Zo staat elke back-up op twee machines.

Het dashboard stelt de richting, datastores en het uur voor, toont de commando's om zelf te plakken en kan ze ook zelf
via SSH uitvoeren (recent ingelogd, in het auditlog; van buitenaf alleen als de terminal daar openstaat).

De proef toont wat die knop zou doen, met dezelfde scripts: wat iets verandert, gaat daarin via doe(), dat in de proef
alleen afdrukt wat het zou uitvoeren. De controles die alleen lezen (bestaan de gebruiker, het token, de remote en de
sync-job al?) lopen in de proef echt, zodat ze dezelfde weg neemt als de echte run.
"""

import re
import shlex
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone

import asyncssh
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import proef, ssh_exec
from ..masking import mask
from ..models import SshHost
from ..ssh_login import Login, login_for

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


def _starts(schedules: list[str | None]) -> list[int]:
    """Wanneer de back-ups starten, in minuten na middernacht."""
    starts = []
    for s in schedules:
        for h, m in re.findall(r"\b(\d{1,2}):(\d{2})\b", s or ""):
            starts.append(int(h) * 60 + int(m))
        if s and not starts and re.search(r"\bdaily\b", s):
            starts.append(0)
    return starts


def _jobs(value: dict) -> list[dict]:
    """De back-upjobs van Proxmox die aan staan en naar een PBS schrijven."""
    return [j for c in value.get("clusters") or [] for j in c.get("jobs") or [] if j.get("pbs") and j.get("enabled")]


def pick_time(schedules: list[str | None]) -> str:
    """Een uur waarop geen back-up start en de laatste minstens 2 uur bezig is: liefst vroeg in de ochtend."""
    starts = _starts(schedules)
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
    jobs = _jobs(value)
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


# --- De scripts: één bron voor de echte run, de proef en het plan ---------------------------------------------------
#
# Een script is een rij stappen: een commando dat iets verandert (altijd via doe), of een controle die alleen leest,
# met wat er dan gebeurt. Elke controle schrijft "check: ...", in het echt en in de proef: met "let op: " als de run
# iets raakt dat er al was, met "fout: " als hij niet verder kan.

PLACEHOLDER = "<geheim uit stap 1>"
_DOE = 'doe() { "$@"; }'
# In de proef: tonen in plaats van uitvoeren, met aanhalingstekens zoals shlex.join ze zet (zoals in het plan).
_DOE_PROEF = r"""doe() {
  printf '+'
  for a in "$@"; do
    case $a in
      ''|*[!A-Za-z0-9_@%+=:,./-]*) printf " '%s'" "$a" ;;
      *) printf ' %s' "$a" ;;
    esac
  done
  printf '\n'
}"""
_TOOL = ('command -v proxmox-backup-manager >/dev/null || '
         '{ echo "check: fout: proxmox-backup-manager niet gevonden, is dit wel een PBS?"; exit 1; }')


@dataclass(frozen=True)
class _If:
    """Een controle die alleen leest, en wat er gebeurt als ze lukt (then) of niet (otherwise)."""
    key: str
    test: str
    yes: str
    no: str
    then: tuple[str, ...] = ()
    otherwise: tuple[str, ...] = ()
    # Als de controle lukt, raakt de run iets dat er al was: wat er dan mee gebeurt.
    note: str | None = None

    def said(self, yes: bool) -> str:
        if not yes:
            return self.no
        return f"let op: {self.yes}: {self.note}" if self.note else self.yes


def _source(p: dict, dst_name: str) -> tuple[dict, list]:
    """Op de bron: een gebruiker die alleen mag lezen, met een token voor het doel."""
    env = {"U": USER, "T": p["token"], "S": p["src_store"]}
    return env, [
        _If("gebruiker", 'proxmox-backup-manager user list --output-format json | grep -q "$U"',
            "gebruiker $U bestaat al", "gebruiker $U bestaat nog niet",
            otherwise=(f"proxmox-backup-manager user create \"$U\" --comment 'sync naar {slug(dst_name)}, door de "
                       "homepage'",)),
        # Het geheim van een bestaand token toont PBS niet meer: vervangen is de enige manier om het te krijgen.
        _If("token", 'proxmox-backup-manager user list-tokens "$U" --output-format json 2>/dev/null '
                     '| grep -q "\\"$U!$T\\""',
            "token $U!$T bestaat al", "token $U!$T bestaat nog niet",
            then=('proxmox-backup-manager user delete-token "$U" "$T"',),
            note="wordt vervangen, een sync die het oude gebruikt werkt pas weer na stap 2"),
        'proxmox-backup-manager user generate-token "$U" "$T" --output-format json',
        'proxmox-backup-manager acl update "/datastore/$S" DatastoreReader --auth-id "$U"',
        'proxmox-backup-manager acl update "/datastore/$S" DatastoreReader --auth-id "$U!$T"',
    ]


def _target(p: dict, src_name: str) -> tuple[dict, list]:
    """Op het doel: de bron als remote (met het geheim uit stap 1, via stdin in $PW) en de sync-job."""
    env = {"R": p["remote"], "J": p["job"]}
    args = (f"--host '{p['host']}' --port '{p['port']}' --auth-id '{USER}!{p['token']}' "
            f"--fingerprint '{p.get('fingerprint') or ''}' --password \"$PW\"")
    return env, [
        _If("remote", 'proxmox-backup-manager remote list --output-format json | grep -q "\\"$R\\""',
            "remote $R bestaat al", "remote $R bestaat nog niet",
            then=(f'proxmox-backup-manager remote update "$R" {args}',),
            otherwise=(f'proxmox-backup-manager remote create "$R" {args}',),
            note="wordt overschreven met dit adres en het nieuwe token"),
        _If("sync-job", 'proxmox-backup-manager sync-job list --output-format json | grep -q "\\"$J\\""',
            "sync-job $J bestaat al", "sync-job $J bestaat nog niet",
            otherwise=(f"proxmox-backup-manager sync-job create \"$J\" --store '{p['dst_store']}' --remote \"$R\" "
                       f"--remote-store '{p['src_store']}' --schedule '{p['schedule']}' --remove-vanished false "
                       f"--comment 'kopie van {slug(src_name)}, door de homepage'",),
            note="blijft zoals hij is, uur en datastores worden niet aangepast"),
    ]


def _script(env: dict, items: list, proef: bool, stdin: str | None = None) -> str:
    lines = ["set -e", _DOE_PROEF if proef else _DOE, _TOOL, "; ".join(f"{k}={shlex.quote(v)}" for k, v in env.items())]
    if stdin:
        # Het geheim komt via stdin, nooit in het commando. De proef heeft er geen en vraagt er ook geen.
        lines.append(f"{stdin}={shlex.quote(PLACEHOLDER)}" if proef else f"IFS= read -r {stdin}")
    for it in items:
        if isinstance(it, str):
            lines.append(f"doe {it}")
            continue
        lines += [f"if {it.test}; then", f'  echo "check: {it.said(True)}"', *(f"  doe {c}" for c in it.then),
                  "else", f'  echo "check: {it.said(False)}"', *(f"  doe {c}" for c in it.otherwise), "fi"]
    return "\n".join([*lines, "echo klaar"]) + "\n"


def _source_script(p: dict, dst_name: str, proef: bool = False) -> str:
    return _script(*_source(p, dst_name), proef)


def _target_script(p: dict, src_name: str, proef: bool = False) -> str:
    return _script(*_target(p, src_name), proef, stdin="PW")


def _fill(text: str, env: dict) -> str:
    """$X invullen zoals de shell (de waarden zijn nagekeken: geen aanhalingstekens, spaties of $)."""
    return re.sub(r"\$(\w+)", lambda m: env[m.group(1)], text)


def _line(cmd: str, env: dict) -> str:
    """Een commando met de echte waarden, zoals doe() het in de proef afdrukt."""
    return shlex.join(shlex.split(_fill(cmd, env)))


def _would(env: dict, items: list) -> list[str]:
    """Wat een script zou veranderen; wat van een controle afhangt, staat er met die voorwaarde bij."""
    out = []
    for it in items:
        if isinstance(it, str):
            out.append(_line(it, env))
            continue
        for cond, cmds in ((it.yes, it.then), (it.no, it.otherwise)):
            out += [f"{_line(c, env)}   # als: {_fill(cond, env)}" for c in cmds]
    return out


def _read(out: str) -> tuple[list[str], list[str]]:
    """Uit de uitvoer van een script: de controles ("check: ...") en, in de proef, wat het zou doen ("+ ...")."""
    lines = out.splitlines()
    return [x[7:] for x in lines if x.startswith("check: ")], [x[2:] for x in lines if x.startswith("+ ")]


def _said(out: str, env: dict, items: list, key: str) -> bool | None:
    """Wat een controle zei: True (bestond al), False (nog niet), None (het script kwam er niet)."""
    it = next(i for i in items if isinstance(i, _If) and i.key == key)
    found = _read(out)[0]
    return True if _fill(it.said(True), env) in found else False if _fill(it.said(False), env) in found else None


def _clean(out: str, secret: str | None = None) -> str:
    """Uitvoer zonder geheimen: het token-geheim zelf (als we het kennen), elke "value" en wat op een geheim lijkt."""
    return mask(SECRET.sub('"value":"…"', out), [secret] if secret else [])


# --- SSH-hosts en voorcontrole --------------------------------------------------------------------------------------

async def ssh_host(db: AsyncSession, p: dict) -> SshHost | None:
    """De SSH-host van een PBS-tegel: gekoppeld aan de tegel, hetzelfde adres of dezelfde naam."""
    conds = [SshHost.service_id == p["service_id"], SshHost.name.ilike(p["name"])]
    if p.get("host"):
        conds.append(SshHost.host == p["host"])
    hosts = list((await db.execute(select(SshHost).where(or_(*conds)).order_by(SshHost.id))).scalars())
    rank = lambda h: (h.service_id != p["service_id"], h.name.lower() != p["name"].lower(), h.host != p.get("host"))  # noqa: E731
    return min(hosts, key=rank) if hosts else None


def matched_by(h: SshHost, p: dict) -> str:
    """Waarop ssh_host deze host koos, in dezelfde volgorde."""
    if h.service_id == p["service_id"]:
        return "gekoppeld aan de tegel"
    if h.name.lower() == p["name"].lower():
        return "dezelfde naam als de tegel"
    if h.host == p.get("host"):
        return "hetzelfde adres als de tegel"
    return f"naam lijkt op {p['name']}"


async def _run(db: AsyncSession, h: SshHost, script: str, stdin: str | None = None) -> tuple[int, str]:
    login = await login_for(db, h)
    # Geen transactie open tijdens SSH (tot twee minuten): de verbinding gaat terug naar de pool.
    await db.commit()
    async with ssh_exec.connect(h, login) as conn:
        try:
            # Zonder invoer: stdin meteen dicht, zodat niets blijft wachten op een toetsenbord.
            io = {"input": stdin} if stdin is not None else {"stdin": asyncssh.DEVNULL}
            r = await conn.run(ssh_exec.command(script, login), check=False, timeout=120, **io)
        except (OSError, asyncssh.Error) as e:
            raise ssh_exec.SshFail(f"SSH-fout: {e}") from e
    return int(r.exit_status or 0), f"{r.stdout or ''}{r.stderr or ''}"


def blocked(c: dict, hs: SshHost | None, hd: SshHost | None) -> list[str]:
    """Waarom de echte run zou weigeren, nog voor er iets op een PBS gebeurt (leeg: hij mag). De proef geeft precies
    deze punten een ✕ (preflight)."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    why = []
    if not p.get("fingerprint"):
        why.append(f"Vingerafdruk van {src['name']} onbekend: vul ze in (stap 1, cert info)")
    if c["level"] == "err":
        why.append(c["notes"][0])
    missing = [x["name"] for x, h in ((src, hs), (dst, hd)) if not h]
    if missing:
        why.append(f"Geen SSH-host voor {' en '.join(missing)}: voeg die toe in de terminal en open er één keer "
                   "een terminal naar")
    unpinned = [h.name for h in (hs, hd) if h and not h.host_key]
    if unpinned:
        why.append(f"Hostsleutel van {' en '.join(unpinned)} nog niet bevestigd: open er één keer een terminal naar")
    return why


def _hhmm(m: int) -> str:
    return f"{m // 60:02d}:{m % 60:02d}"


def _ago(seconds: float) -> str:
    m = max(0, int(seconds // 60))
    return f"{m} min" if m < 120 else f"{m // 60} u" if m < 2880 else f"{m // 1440} dagen"


def preflight(c: dict, value: dict, hs: SshHost | None, hd: SshHost | None, ls: Login | None, ld: Login | None,
              predict: bool = True, now: datetime | None = None) -> list[dict]:
    """Wat vooraf na te gaan is, zonder SSH: het plan, de vingerafdruk, het uur tegenover de back-ups, de plaats, de
    SSH-hosts (en waarop ze gevonden zijn), de hostsleutels, de login en hoe vers de gegevens van de PBS'en zijn.
    predict: ook zeggen of de remote en de sync-job al bestaan, volgens die gegevens (de controle via SSH weet het
    zeker). Een ✕ hier is precies een reden uit blocked()."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    now = now or datetime.now(timezone.utc)
    out = [proef.check(f"{src['name']} → {dst['name']}", True,
                       f"datastore {p['src_store']} → {p['dst_store']}, remote {p['remote']}, sync-job {p['job']}")]

    fp, seen = p.get("fingerprint") or "", src.get("fingerprint") or ""
    what = f"Vingerafdruk van {src['name']}"
    if not fp:
        out.append(proef.check(what, False, "onbekend: vul ze in (stap 1, cert info)"))
    elif seen and seen.lower() != fp.lower():
        out.append(proef.check(what, None, "wijkt af van het certificaat dat de PBS-tegel nu toont"))
    else:
        out.append(proef.check(what, True, "zelfde als het certificaat van de PBS-tegel" if seen else "ingevuld"))

    # Dezelfde back-upjobs en starturen als pick_time().
    starts = sorted(set(_starts([j.get("schedule") for j in _jobs(value)])))
    at = int(p["schedule"][:2]) * 60 + int(p["schedule"][3:])
    what = f"Elke dag om {p['schedule']}"
    if starts:
        last = min(starts, key=lambda t: (at - t) % 1440)
        gap = (at - last) % 1440
        detail = (f"{gap // 60} u {gap % 60:02d} na de back-up van {_hhmm(last)} (back-ups naar een PBS starten om "
                  f"{', '.join(_hhmm(t) for t in starts)})")
        out.append(proef.check(what, True, detail) if gap >= 120 else
                   proef.check(what, None, f"minder dan 2 uur: {detail}, die is misschien nog bezig"))
    else:
        out.append(proef.check(what, None, "geen back-upjob naar een PBS met een vast uur gevonden"))

    space = next((n for n in c["notes"] if n.startswith(("Past", "Krap"))), None)
    out.append(proef.check(f"Plaats op {dst['name']}", {"ok": True, "warn": None, "err": False}[c["level"]] if space
                           else None, space or "onbekend: de PBS'en gaven geen gebruik door"))

    for tile, h, login in ((src, hs, ls), (dst, hd, ld)):
        what = f"SSH-host voor {tile['name']}"
        if not h:
            out.append(proef.check(what, False, "geen gevonden: voeg die toe in de terminal (gekoppeld aan de tegel, "
                                                "met dezelfde naam of met hetzelfde adres)"))
            continue
        out.append(proef.check(what, True, f"{proef.ssh_machine(h, login)}, gevonden op {matched_by(h, tile)}"))
        out.append(proef.check(f"Hostsleutel van {h.name}", bool(h.host_key),
                               "bevestigd" if h.host_key else "nog niet bevestigd: open er één keer een terminal naar"))
        user = login.username if login else (h.username or "root")
        out.append(proef.check(f"Aanmelden op {h.name}", True if user == "root" else None,
                               "als root" if user == "root"
                               else f"als {user} met sudo -n: lukt alleen als sudo daar zonder wachtwoord mag"))

    what = "Gegevens van de PBS'en"
    if value.get("at"):
        t = datetime.fromisoformat(value["at"])
        age = (now - (t if t.tzinfo else t.replace(tzinfo=timezone.utc))).total_seconds()
        out.append(proef.check(what, True if age < 2 * 3600 else None, f"van {_ago(age)} geleden"))
    else:
        out.append(proef.check(what, None, "nog niet opgehaald"))

    if predict:
        notes = {i.key: i.note for i in _target(p, src["name"])[1] if isinstance(i, _If)}
        names = {r.get("name") for r in dst.get("remotes") or []}
        ids = {j.get("id") for j in dst.get("syncs") or []}
        for what, have, note in ((f"Remote {p['remote']} op {dst['name']}", p["remote"] in names, notes["remote"]),
                                 (f"Sync-job {p['job']} op {dst['name']}", p["job"] in ids, notes["sync-job"])):
            if have:
                out.append(proef.check(what, True, f"bestaat al volgens de laatste gegevens: {note}"))
            elif names or ids:
                out.append(proef.check(what, True, "bestaat nog niet volgens de laatste gegevens"))
            else:
                # Zonder RemoteAudit op het token van de tegel houdt PBS remotes en sync-jobs verborgen.
                out.append(proef.check(what, None, "onzeker: de PBS-tegel ziet geen remotes of sync-jobs (geen "
                                                   "RemoteAudit, of er zijn er nog geen); de controle via SSH weet het"))
    return out


# --- Het plan, de proef en de echte run -----------------------------------------------------------------------------

def steps(c: dict, hs: SshHost | None, hd: SshHost | None, ls: Login | None, ld: Login | None) -> list[dict]:
    """De echte run als plan, per machine in volgorde: eerst de bron, dan het doel (alleen als de bron lukt). call: wat
    er zou veranderen, met de echte waarden; script: het volledige commando zoals het via SSH vertrekt."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    tok, pbm = f"{USER}!{p['token']}", "proxmox-backup-manager"
    se, si = _source(p, dst["name"])
    te, ti = _target(p, src["name"])
    undo_src = [shlex.join([pbm, "acl", "update", f"/datastore/{p['src_store']}", "DatastoreReader", "--auth-id", a,
                            "--delete", "true"]) for a in (tok, USER)]
    undo_src += [shlex.join([pbm, "user", "delete-token", USER, p["token"]]), shlex.join([pbm, "user", "remove", USER])]
    undo_dst = [shlex.join([pbm, "sync-job", "remove", p["job"]]), shlex.join([pbm, "remote", "remove", p["remote"]])]

    def one(tile: dict, h: SshHost | None, login: Login | None, script: str, calls: list[str], **kw) -> dict:
        if not h or not login:
            return proef.step(f"{tile['name']}: geen SSH-host", "ssh", "\n".join(calls), script=script, **kw)
        return proef.step(f"{tile['name']}: {proef.ssh_machine(h, login)}", "ssh", "\n".join(calls),
                          who=proef.ssh_who(login), script=ssh_exec.command(script, login), **kw)

    return [
        one(src, hs, ls, _source_script(p, dst["name"]), _would(se, si),
            on_fail=f"De run stopt: op {dst['name']} verandert niets. Op {src['name']} blijft wat al gebeurd is: de "
                    f"gebruiker {USER}, en een bestaand token {tok} is dan misschien al vervangen.",
            note="terugdraaien (alleen wat de run nieuw maakte): " + " ; ".join(undo_src)),
        one(dst, hd, ld, _target_script(p, src["name"]), _would({**te, "PW": PLACEHOLDER}, ti),
            when="als stap 1 lukt", data={"stdin": "het geheim uit stap 1, niet in het commando"},
            on_fail=f"Op {src['name']} staan dan de gebruiker, het nieuwe token en het leesrecht al; op {dst['name']} "
                    f"is de remote {p['remote']} misschien al aangemaakt of overschreven. Opnieuw uitvoeren mag: het "
                    "token wordt dan opnieuw gemaakt.",
            note="terugdraaien (alleen wat de run nieuw maakte): " + " ; ".join(undo_dst)),
    ]


def _rest(out: str) -> str:
    return "\n".join(x for x in out.splitlines() if not x.startswith(("check: ", "+ ")) and x != "klaar")[-300:]


def proef_plan(c: dict, value: dict, hs: SshHost | None, hd: SshHost | None, ls: Login | None, ld: Login | None,
               ran: list[dict] | None = None, now: datetime | None = None) -> dict:
    """Het plan van de proef. ran: de uitkomst van de controle via SSH (proef_run); zonder: wat vooraf te zien is."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    st = steps(c, hs, hd, ls, ld)
    checks = preflight(c, value, hs, hd, ls, ld, predict=not ran, now=now)
    warnings, skipped = [], []
    if why := blocked(c, hs, hd):
        warnings.append("De echte knop zou nu weigeren, nog voor er iets op een PBS gebeurt: " + "; ".join(why))
    for i, (tile, r) in enumerate(zip((src, dst), ran or [])):
        if r["error"]:
            checks.append(proef.check(f"Controle op {tile['name']}", False, r["error"]))
            continue
        found, would = _read(r["out"])
        for line in found:
            text = line.removeprefix("fout: ").removeprefix("let op: ")
            checks.append(proef.check(f"Op {tile['name']}: {text}", not line.startswith("fout: ")))
            if line.startswith("let op: "):
                warnings.append(f"Op {tile['name']}: {text}")
        if not r["code"]:
            # Wat de echte run op deze machine zou uitvoeren, in plaats van alle mogelijkheden.
            st[i]["call"] = "\n".join(would) or "niets"
        elif not any(x.startswith("fout: ") for x in found):
            checks.append(proef.check(f"Controle op {tile['name']}", False,
                                      f"het script stopte met exit {r['code']}: {_rest(r['out'])}"))
    if ran and (ran[0]["error"] or ran[0]["code"]):
        skipped.append(proef.skip(f"Stap 2 op {dst['name']}", f"in het echt stopt de run al op {src['name']}; de "
                                                             f"controle op {dst['name']} liep toch, ter informatie"))
    after = [f"melding en tijdlijn: PBS-sync ingesteld: {src['name']} → {dst['name']}",
             "de back-updekking opnieuw ophalen (alleen lezen)",
             f"{dst['name']} haalt zelf elke dag om {p['schedule']} een kopie op; zet er ook een prune-job bij"]
    return proef.plan(f"PBS-sync instellen: {src['name']} → {dst['name']}, elke dag om {p['schedule']}", st,
                      checks=checks, skipped=skipped, after=after, warnings=warnings, controle=bool(ran))


async def proef_run(db: AsyncSession, c: dict, hs: SshHost, hd: SshHost) -> list[dict]:
    """De controle: de proefscripts op beide PBS'en, via dezelfde SSH als de echte run. Ze lezen alleen; wat zou
    veranderen, drukken ze af. Ook na een fout op de bron kijken we op het doel (in het echt stopt de run daar)."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    out = []
    for h, script in ((hs, _source_script(p, dst["name"], proef=True)),
                      (hd, _target_script(p, src["name"], proef=True))):
        try:
            code, text = await _run(db, h, script)
            out.append({"code": code, "out": _clean(text), "error": None})
        except ssh_exec.SshFail as e:
            out.append({"code": None, "out": "", "error": _clean(str(e))})
    return out


def proef_log(c: dict, hs: SshHost, hd: SshHost, ran: list[dict]) -> list[str]:
    """Het verloop van de controle, in dezelfde vorm als dat van de echte run."""
    log = []
    for tile, h, r in zip((c["src"], c["dst"]), (hs, hd), ran):
        log.append(f"$ proef op {tile['name']} ({h.host}): alleen lezen, + is wat de echte run zou uitvoeren")
        log.extend(f"  {x}" for x in ([r["error"]] if r["error"] else r["out"].strip().splitlines()))
        if r["code"]:
            log.append(f"  (exit {r['code']})")
    return log


async def create(db: AsyncSession, c: dict, hs: SshHost, hd: SshHost) -> dict:
    """Uitvoeren op beide PBS'en. Geeft het verloop terug (zonder het geheim) en of de sync-job al bestond."""
    p, src, dst = c["plan"], c["src"], c["dst"]
    log = [f"$ op {src['name']} ({hs.host}): gebruiker {USER}, token {p['token']}, leesrecht op {p['src_store']}"]
    code, out = await _run(db, hs, _source_script(p, dst["name"]))
    m = SECRET.search(out)
    if code or not m:
        raise ssh_exec.SshFail(f"Op {src['name']} mislukt (exit {code}): {_clean(out)[-600:]}")
    secret = m.group(1)
    log.extend(f"  check: {x}" for x in _read(_clean(out, secret))[0])
    log.append("  token aangemaakt")
    log.append(f"$ op {dst['name']} ({hd.host}): remote {p['remote']} en sync-job {p['job']} om {p['schedule']}")
    code, raw = await _run(db, hd, _target_script(p, src["name"]), stdin=secret + "\n")
    # Ook hier gemaskeerd: het script drukt het geheim niet af, een foutmelding van PBS zou het wel kunnen.
    out = _clean(raw, secret)
    if code:
        raise ssh_exec.SshFail(f"Op {dst['name']} mislukt (exit {code}): {out[-600:]}")
    log.extend(f"  {line}" for line in out.strip().splitlines()[-8:])
    return {"log": log, "job_existed": bool(_said(raw, *_target(p, src["name"]), "sync-job"))}
