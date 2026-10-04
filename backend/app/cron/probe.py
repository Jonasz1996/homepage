"""Wat er op een machine gepland staat, in één SSH-ronde.

PROBE draait als root (of via sudo -n) met `sh -s` en drukt blokken af die met "@@" beginnen: crontabs,
/etc/cron.d, systemd-timers met hun laatste run, de cronlog van het laatste etmaal, runs van de wrapper
(hp-cron) en op een Proxmox- of PBS-machine ook de back-up-, replicatie-, sync-, verify-, prune- en
GC-jobs met hun taken. Op een Proxmox-node gaat hetzelfde script ook in elke draaiende container.
parse() maakt daar jobs en runs van; links.py zoekt daarna waar elke job aan komt.
"""

import base64
import hashlib
import json
import re
import shlex
from datetime import datetime, timezone

from . import links
from .schedule import BadSchedule, parse_calendar, parse_cron, parse_duration

WRAPPER = "/usr/local/bin/hp-cron"
LOG_HOURS = 26

PROBE = r"""
tz=$(cat /etc/timezone 2>/dev/null | head -1)
[ -z "$tz" ] && tz=$(readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##')
[ -z "$tz" ] && command -v timedatectl >/dev/null 2>&1 && tz=$(timedatectl show -p Timezone --value 2>/dev/null </dev/null)
echo "@@META $(hostname 2>/dev/null) ${tz:-UTC} $(date +%s)"
for f in /etc/crontab /etc/cron.d/* /etc/anacrontab; do
  [ -f "$f" ] || continue
  echo "@@FILE $f"; cat "$f" 2>/dev/null; echo
done
for f in /var/spool/cron/crontabs/* /var/spool/cron/* /etc/crontabs/*; do
  [ -f "$f" ] || continue
  echo "@@USER $(basename "$f") $f"; cat "$f" 2>/dev/null; echo
done
for d in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/periodic/15min /etc/periodic/hourly /etc/periodic/daily /etc/periodic/weekly /etc/periodic/monthly; do
  [ -d "$d" ] || continue
  echo "@@PERIODIC $d $(ls -1 "$d" 2>/dev/null | grep -v '^\.' | tr '\n' ' ')"
done
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
  TS=--timestamp=unix
  systemctl show $TS -p Id init.scope >/dev/null 2>&1 </dev/null || TS=
  for t in $(systemctl list-units --type=timer --all --no-legend --plain 2>/dev/null </dev/null | awk '{print $1}'); do
    u=$(systemctl show -p Unit --value "$t" 2>/dev/null </dev/null)
    echo "@@TIMER $t $u"
    systemctl show $TS -p Description,TimersCalendar,TimersMonotonic,NextElapseUSecRealtime,LastTriggerUSec,ActiveState,UnitFileState "$t" 2>/dev/null </dev/null
    systemctl show $TS -p ExecStart,Result,ExecMainStatus,ExecMainStartTimestamp,ExecMainExitTimestamp,User,InvocationID,FragmentPath "$u" 2>/dev/null </dev/null | sed 's/^/U./'
    case "$u" in apt-daily*|e2scrub*|fstrim*|logrotate*|man-db*|systemd-*|dpkg-db-backup*|phpsessionclean*|motd-news*|plocate*|mlocate*|sysstat*|fwupd*|snapd*|ua-*|update-notifier*) continue;; esac
    inv=$(systemctl show -p InvocationID --value "$u" 2>/dev/null </dev/null)
    if [ -n "$inv" ] && command -v journalctl >/dev/null 2>&1; then
      echo "@@OUT $u"; journalctl -q --no-pager _SYSTEMD_INVOCATION_ID="$inv" -o cat -n 40 2>/dev/null </dev/null
    fi
  done
fi
if command -v journalctl >/dev/null 2>&1; then
  echo "@@CRONLOG"
  journalctl -q --no-pager -t CRON -t cron -t crond -t CROND --since "-{HOURS}h" -o short-unix 2>/dev/null </dev/null | grep -F ' CMD (' | tail -n 4000
  echo "@@WRAPLOG"
  journalctl -q --no-pager -t hp-cron --since "-{HOURS}h" -o cat 2>/dev/null </dev/null | grep '^@@RUN ' | tail -n 2000
fi
if command -v pvesh >/dev/null 2>&1; then
  n=$(hostname -s 2>/dev/null || hostname)
  echo "@@PVE $n"
  for p in "backup /cluster/backup" "replication /cluster/replication" "storage /storage" "status /cluster/status" "resources /cluster/resources --type vm" "repstatus /nodes/$n/replication" "tasks /nodes/$n/tasks --typefilter vzdump --limit 60"; do
    set -- $p; k=$1; shift
    echo "@@J $k"; timeout 30 pvesh get "$@" --output-format json 2>/dev/null </dev/null; echo
  done
fi
if command -v proxmox-backup-manager >/dev/null 2>&1; then
  echo "@@PBS $(hostname -s 2>/dev/null || hostname)"
  for k in sync-job verify-job prune-job datastore remote; do
    echo "@@J pbs-$k"; timeout 30 proxmox-backup-manager $k list --output-format json 2>/dev/null </dev/null; echo
  done
  echo "@@J pbs-tasks"; timeout 30 proxmox-backup-manager task list --all --limit 300 --output-format json 2>/dev/null </dev/null; echo
fi
""".replace("{HOURS}", str(LOG_HOURS))


def script(skip_cts: set[int], containers: bool = True) -> str:
    """Het script voor een machine; op een Proxmox-node ook in elke draaiende container (behalve die we al
    rechtstreeks via SSH scannen)."""
    p = shlex.quote(PROBE)
    out = f"P={p}\necho '@@HOST'\nsh -c \"$P\" </dev/null\n"
    if containers:
        skip = " " + " ".join(str(i) for i in sorted(skip_cts)) + " "
        out += (
            f"SKIP='{skip}'\n"
            "if command -v pct >/dev/null 2>&1; then\n"
            "  for id in $(pct list 2>/dev/null </dev/null | awk 'NR>1 && $2==\"running\" {print $1}'); do\n"
            "    case \"$SKIP\" in *\" $id \"*) continue;; esac\n"
            "    echo \"@@CT $id $(pct config \"$id\" 2>/dev/null </dev/null | sed -n 's/^hostname: //p')\"\n"
            "    timeout 90 pct exec \"$id\" -- sh -c \"$P\" 2>/dev/null </dev/null\n"
            "  done\n"
            "fi\n"
        )
    return out


def split_machines(text: str) -> list[tuple[str, str | None, str]]:
    """("host", None, uitvoer) en ("ct", "105 web", uitvoer)."""
    parts: list[tuple[str, str | None, list[str]]] = []
    for line in text.splitlines():
        if line.startswith("@@HOST"):
            parts.append(("host", None, []))
        elif line.startswith("@@CT "):
            parts.append(("ct", line[5:].strip(), []))
        elif parts:
            parts[-1][2].append(line)
    return [(k, n, "\n".join(lines)) for k, n, lines in parts]


def _blocks(text: str) -> list[tuple[str, str, list[str]]]:
    out: list[tuple[str, str, list[str]]] = []
    for line in text.splitlines():
        if line.startswith("@@"):
            tag, _, rest = line[2:].partition(" ")
            out.append((tag, rest, []))
        elif out:
            out[-1][2].append(line)
    return out


def h(*parts: str) -> str:
    return hashlib.sha1("\x1f".join(parts).encode()).hexdigest()[:16]


def wid_for(key: str) -> str:
    return hashlib.sha1(key.encode()).hexdigest()[:10]


# --- Cronregels -------------------------------------------------------------------

_ENV = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*\s*=")
SYSTEM_CROND = {"e2scrub_all", "php", "sysstat", "popularity-contest", "anacron", "mdadm", "zfsutils-linux",
                "john", ".placeholder", "pveupdate", "vzdump", "debian-sa1", "mailman", "ntpdate", "certbot",
                "proxmox-backup-daily-update", "pve-daily-update"}
_WRAPPED = re.compile(r"^" + re.escape(WRAPPER) + r" ([0-9a-f]{6,16}) '(.*)'$", re.S)


def unwrap(command: str) -> tuple[str, str | None]:
    """"/usr/local/bin/hp-cron abc123 'echo it'\''s'" → ("echo it's", "abc123")."""
    m = _WRAPPED.match(command.strip())
    if not m:
        return command, None
    return m.group(2).replace("'\\''", "'"), m.group(1)


def wrap(command: str, wid: str) -> str:
    return f"{WRAPPER} {wid} '" + command.replace("'", "'\\''") + "'"


def cron_lines(text: str, with_user: bool) -> list[dict]:
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or _ENV.match(s):
            continue
        parts = s.split(None, 1 + (1 if with_user else 0)) if s.startswith("@") else s.split(None, 5 + (1 if with_user else 0))
        need = (2 if s.startswith("@") else 6) + (1 if with_user else 0)
        if len(parts) < need:
            continue
        if s.startswith("@"):
            sched, rest = parts[0], parts[1:]
        else:
            sched, rest = " ".join(parts[:5]), parts[5:]
        user = rest[0] if with_user else ""
        command = rest[-1]
        out.append({"line": n, "raw": line, "schedule": sched, "user": user, "command": command})
    return out


_SKIP_SEG = re.compile(r"^(cd|test|\[|sleep|export|true|:|source|\.)(\s|$)")


def _cron_name(command: str) -> str:
    c, _ = unwrap(command)
    if m := re.search(r"run-parts\s+(?:--\S+\s+)*(\S+)", c):
        return m.group(1).rstrip("/;").split("/")[-1]
    segs = [x for x in re.split(r"\s*(?:&&|\|\||;)\s*", c) if x.strip()]
    c = next((x for x in segs if not _SKIP_SEG.match(x.strip())), segs[-1] if segs else c)
    c = re.sub(r"\s*(\d?>>?|<|\|).*$", "", c).strip()
    words = shlex.split(c, posix=True) if c.count("'") % 2 == 0 and c.count('"') % 2 == 0 else c.split()
    words = [w for w in words if not _ENV.match(w) and w not in ("sudo", "nice", "ionice", "timeout", "flock", "-n", "-c")]
    if not words:
        return c[:60]
    exe = words[0].split("/")[-1]
    if exe in ("sh", "bash", "python", "python3", "perl", "php", "node", "ruby"):
        arg = next((w for w in words[1:] if not w.startswith("-")), None)
        if arg:
            exe = arg.split("/")[-1]
    return exe[:60]


def _sched_ok(kind: str, sched: str) -> tuple[str, str]:
    """(sched_type, schedule) en of we hem kunnen uitrekenen."""
    if sched.lower() == "@reboot":
        return "reboot", sched
    try:
        (parse_cron if kind == "cron" else parse_calendar)(sched)
        return kind, sched
    except BadSchedule:
        return "none", sched


# --- systemd ------------------------------------------------------------------------

def _ts(value: str | None) -> datetime | None:
    if not value or value in ("n/a", "0"):
        return None
    v = value.strip()
    if v.startswith("@") and v[1:].replace(".", "").isdigit():
        return datetime.fromtimestamp(float(v[1:]), timezone.utc)
    # Oudere systemd zonder --timestamp=unix: "Sat 2026-10-04 03:00:00 CEST" → als lokale tijd lezen lukt niet
    # betrouwbaar zonder de afkorting; die waarde laten we weg.
    return None


def _exec_cmd(execstart: str) -> str:
    m = re.search(r"argv\[\]=(.*?) ;", execstart or "")
    return (m.group(1) if m else execstart or "").strip()


def _calendar(prop: str) -> list[str]:
    return [m.strip() for m in re.findall(r"OnCalendar=([^;]+?)\s*;", prop or "")]


def _monotonic(prop: str) -> float | None:
    m = re.search(r"On(?:UnitActive|UnitInactive|Boot|Startup)(?:USec|Sec)=([^;]+?)\s*;", prop or "")
    return parse_duration(m.group(1)) if m else None


SYSTEM_TIMER = re.compile(r"^(apt-daily|e2scrub|fstrim|logrotate|man-db|systemd-|dpkg-db-backup|phpsessionclean|"
                          r"motd-news|plocate|mlocate|sysstat|fwupd|snapd|ua-|update-notifier|pve-daily-update|"
                          r"proxmox-backup-daily-update|proxmox-boot|pve-ha|zfs-|certbot|anacron|exim4|"
                          r"apt-listbugs|unattended)")


def _kv(lines: list[str]) -> dict[str, str]:
    out = {}
    for line in lines:
        k, sep, v = line.partition("=")
        if sep:
            out[k] = v
    return out


# --- Parser ---------------------------------------------------------------------------

def _json(lines: list[str]):
    text = "\n".join(lines).strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        return None


def parse(text: str, tkey: str) -> dict:
    """Uitvoer van PROBE voor één machine → {"meta", "jobs", "runs", "log_ok", "pve", "pbs"}."""
    meta = {"hostname": "", "tz": "UTC", "now": None}
    jobs: list[dict] = []
    runs: list[dict] = []
    periodic: dict[str, list[str]] = {}
    cronlog: list[tuple[datetime, str, str]] = []
    log_seen = False
    timers: dict[str, dict] = {}
    outs: dict[str, str] = {}
    pve: dict = {}
    pbs: dict = {}
    section = None

    for tag, rest, body in _blocks(text):
        if tag == "META":
            bits = rest.split()
            if bits:
                meta["hostname"] = bits[0]
            if len(bits) > 1:
                meta["tz"] = bits[1]
            if len(bits) > 2 and bits[2].isdigit():
                meta["now"] = int(bits[2])
        elif tag == "FILE":
            path = rest.strip()
            name = path.split("/")[-1]
            system_file = path.startswith("/etc/cron.d/") and name in SYSTEM_CROND
            if path == "/etc/anacrontab":
                continue
            for c in cron_lines("\n".join(body), with_user=True):
                jobs.append(_cron_job(tkey, path, c, system_file))
        elif tag == "USER":
            user, _, path = rest.partition(" ")
            for c in cron_lines("\n".join(body), with_user=False):
                c["user"] = user
                jobs.append(_cron_job(tkey, path.strip(), c, False))
        elif tag == "PERIODIC":
            d, _, names = rest.partition(" ")
            periodic[d] = names.split()
        elif tag == "TIMER":
            unit_t, _, unit = rest.partition(" ")
            kv = _kv(body)
            timers[unit_t] = {"unit": unit.strip(), "t": {k: v for k, v in kv.items() if not k.startswith("U.")},
                              "u": {k[2:]: v for k, v in kv.items() if k.startswith("U.")}}
        elif tag == "OUT":
            outs[rest.strip()] = "\n".join(body).strip()
        elif tag == "CRONLOG":
            log_seen = True
            for line in body:
                m = re.match(r"^(\d+(?:\.\d+)?)\s+\S+\s+\S+?:\s+\((\S+)\)\s+CMD\s+\((.*)\)\s*$", line)
                if m:
                    cronlog.append((datetime.fromtimestamp(float(m.group(1)), timezone.utc), m.group(2), m.group(3)))
        elif tag == "WRAPLOG":
            pass
        elif tag == "RUN":
            # Elke run van de wrapper staat op een eigen regel "@@RUN {...}" onder @@WRAPLOG.
            try:
                r = json.loads(rest)
            except ValueError:
                continue
            if isinstance(r, dict) and r.get("id") and str(r.get("start", "")).isdigit():
                runs.append({"wid": str(r["id"]), "started_at": datetime.fromtimestamp(int(r["start"]), timezone.utc),
                             "ended_at": datetime.fromtimestamp(int(r["end"]), timezone.utc)
                             if str(r.get("end", "")).isdigit() else None,
                             "exit_code": int(r["rc"]) if str(r.get("rc", "")).lstrip("-").isdigit() else None,
                             "output": _b64(r.get("out"))})
        elif tag == "PVE":
            section = pve
            pve["node"] = rest.strip()
        elif tag == "PBS":
            section = pbs
            pbs["node"] = rest.strip()
        elif tag == "J" and section is not None:
            section[rest.strip()] = _json(body)

    for j in jobs:
        j["system"] = j["system"] or "run-parts" in j["command"]
        if "run-parts" in j["command"]:
            m = re.search(r"run-parts\s+(?:--\S+\s+)*(/\S+)", j["command"])
            if m:
                d = m.group(1).rstrip("/").rstrip(";")
                j["extra"]["scripts"] = periodic.get(d, [])
                j["name"] = d.split("/")[-1] + (f" ({len(periodic.get(d, []))} scripts)" if d in periodic else "")

    for unit_t, t in timers.items():
        jobs.append(_timer_job(tkey, unit_t, t, outs.get(t["unit"])))

    if pve:
        jobs.extend(pve_jobs(pve))
    if pbs:
        jobs.extend(pbs_jobs(pbs))

    for j in jobs:
        j.setdefault("targets", links.extract(j))

    return {"meta": meta, "jobs": jobs, "runs": runs, "cronlog": cronlog, "log_ok": log_seen and bool(cronlog),
            "pve": pve, "pbs": pbs}


def _b64(s) -> str | None:
    if not s:
        return None
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except (ValueError, TypeError):
        return None


def _cron_job(tkey: str, path: str, c: dict, system: bool) -> dict:
    command, wid = unwrap(c["command"])
    stype, sched = _sched_ok("cron", c["schedule"])
    key = f"{tkey}:{h('cron', path, c['user'], c['schedule'], command)}"
    return {"key": key, "kind": "cron", "source": path, "user": c["user"] or "root", "schedule": sched,
            "sched_type": stype, "command": command, "raw": c["command"], "name": _cron_name(command),
            "enabled": True, "system": system, "wid": wid, "monitored": bool(wid),
            "extra": {"line": c["line"], "rawline": c["raw"]}}


def _timer_job(tkey: str, unit_t: str, t: dict, out: str | None) -> dict:
    tv, uv = t["t"], t["u"]
    cal = _calendar(tv.get("TimersCalendar", ""))
    mono = _monotonic(tv.get("TimersMonotonic", ""))
    if cal:
        stype, sched = _sched_ok("calendar", cal[0])
    elif mono:
        stype, sched = "interval", str(int(mono))
    else:
        stype, sched = "none", ""
    status_code = uv.get("ExecMainStatus")
    result = uv.get("Result")
    last_run = _ts(tv.get("LastTriggerUSec"))
    status = None
    if last_run:
        status = "ok" if result == "success" and status_code in (None, "", "0") else "fout"
    started, ended = _ts(uv.get("ExecMainStartTimestamp")), _ts(uv.get("ExecMainExitTimestamp"))
    name = unit_t.removesuffix(".timer")
    return {"key": f"{tkey}:{h('timer', unit_t)}", "kind": "timer", "source": unit_t, "user": uv.get("User") or "root",
            "schedule": sched, "sched_type": stype, "command": _exec_cmd(uv.get("ExecStart", "")), "raw": "",
            "name": name, "enabled": tv.get("UnitFileState") not in ("disabled", "masked") and tv.get("ActiveState") == "active",
            "system": bool(SYSTEM_TIMER.match(name)), "wid": None, "monitored": False,
            "next_run_at": _ts(tv.get("NextElapseUSecRealtime")), "last_run_at": last_run, "last_status": status,
            "last_exit": int(status_code) if (status_code or "").lstrip("-").isdigit() else None,
            "last_duration": (ended - started).total_seconds() if started and ended and ended >= started else None,
            "extra": {"unit": t["unit"], "description": tv.get("Description", ""), "calendars": cal,
                      "fragment": uv.get("FragmentPath", ""), "output": out or None,
                      "started": started.isoformat() if started else None, "ended": ended.isoformat() if ended else None}}


# --- Proxmox VE --------------------------------------------------------------------------

def _cluster_id(pve: dict) -> str:
    for s in pve.get("status") or []:
        if s.get("type") == "cluster" and s.get("name"):
            return s["name"]
    return pve.get("node") or "pve"


def _task_status(s: str | None) -> str | None:
    if not s:
        return "bezig"
    return "ok" if s == "OK" or s.startswith("WARNINGS") else "fout"


def pve_jobs(pve: dict) -> list[dict]:
    cid = _cluster_id(pve)
    node = pve.get("node") or ""
    storages = {s.get("storage"): s for s in pve.get("storage") or [] if isinstance(s, dict)}
    guests = {int(r["vmid"]): r for r in pve.get("resources") or [] if isinstance(r, dict) and r.get("vmid")}
    tasks = [t for t in pve.get("tasks") or [] if isinstance(t, dict)]
    out = []
    for b in pve.get("backup") or []:
        if not isinstance(b, dict) or not b.get("id"):
            continue
        st = storages.get(b.get("storage"), {})
        vmids = [int(v) for v in str(b.get("vmid") or "").split(",") if v.strip().isdigit()]
        what = "alle VM's en CT's" if b.get("all") else ", ".join(
            f"{v} {guests.get(v, {}).get('name', '')}".strip() for v in vmids[:12]) or "selectie"
        stype, sched = _sched_ok("calendar", b.get("schedule") or (f"{b.get('dow', '')} {b.get('starttime', '')}".strip()))
        out.append({
            "key": f"pve:{cid}:backup:{b['id']}", "kind": "pve-backup", "source": f"jobs.cfg {b['id']}", "user": "root",
            "schedule": sched, "sched_type": stype,
            "command": f"vzdump {('--all' if b.get('all') else ' '.join(map(str, vmids)))} --storage {b.get('storage', '?')}"
                       f" --mode {b.get('mode', 'snapshot')}",
            "raw": "", "name": b.get("comment") or f"back-up naar {b.get('storage', '?')}",
            "enabled": str(b.get("enabled", 1)) not in ("0", "false"), "system": False, "wid": None, "monitored": False,
            "cluster": True,
            "extra": {"storage": b.get("storage"), "storage_type": st.get("type"), "server": st.get("server"),
                      "datastore": st.get("datastore") or st.get("export") or st.get("path"), "node": b.get("node"),
                      "vmids": vmids, "all": bool(b.get("all")), "what": what, "mode": b.get("mode"),
                      "nodes_seen": [node]},
            "targets": links.storage_target(b.get("storage"), st),
            "pve_tasks": [{"node": t.get("node") or node, "started_at": datetime.fromtimestamp(int(t["starttime"]), timezone.utc),
                           "ended_at": datetime.fromtimestamp(int(t["endtime"]), timezone.utc) if t.get("endtime") else None,
                           "status": _task_status(t.get("status")), "output": t.get("status"), "vmid": t.get("id")}
                          for t in tasks if t.get("starttime")],
        })
    rep = {r.get("id"): r for r in pve.get("repstatus") or [] if isinstance(r, dict)}
    for r in pve.get("replication") or []:
        if not isinstance(r, dict) or not r.get("id"):
            continue
        guest = int(r.get("guest") or str(r["id"]).split("-")[0] or 0)
        s = rep.get(r["id"], {})
        stype, sched = _sched_ok("calendar", r.get("schedule") or "*/15")
        last = s.get("last_sync")
        job = {
            "key": f"pve:{cid}:repl:{r['id']}", "kind": "pve-repl", "source": f"replication.cfg {r['id']}", "user": "root",
            "schedule": sched, "sched_type": stype, "command": f"pvesr run --id {r['id']}", "raw": "",
            "name": f"replicatie {guest} {guests.get(guest, {}).get('name', '')} → {r.get('target')}".strip(),
            "enabled": not r.get("disable"), "system": False, "wid": None, "monitored": False, "cluster": True,
            "extra": {"guest": guest, "target": r.get("target"), "source_node": r.get("source") or guests.get(guest, {}).get("node"),
                      "rate": r.get("rate"), "fail_count": s.get("fail_count"), "error": s.get("error")},
            "targets": [{"type": "node", "ref": r.get("target"), "label": f"node {r.get('target')}", "via": "zfs-replicatie"}],
        }
        if s:
            job["last_run_at"] = datetime.fromtimestamp(int(last), timezone.utc) if last else None
            job["next_run_at"] = datetime.fromtimestamp(int(s["next_sync"]), timezone.utc) if s.get("next_sync") else None
            job["last_status"] = "fout" if s.get("fail_count") or s.get("error") else ("ok" if last else None)
            job["last_duration"] = s.get("duration")
        out.append(job)
    return out


# --- Proxmox Backup Server ------------------------------------------------------------------

def _pbs_task_match(tasks: list[dict], wtype: str, ident: str) -> list[dict]:
    hits = []
    for t in tasks:
        if t.get("worker_type") != wtype:
            continue
        wid = str(t.get("worker_id") or "")
        if wid == ident or wid.endswith(":" + ident):
            hits.append(t)
    return hits


def pbs_jobs(pbs: dict) -> list[dict]:
    node = pbs.get("node") or "pbs"
    tasks = [t for t in pbs.get("pbs-tasks") or [] if isinstance(t, dict)]
    remotes = {r.get("name"): r for r in pbs.get("pbs-remote") or [] if isinstance(r, dict)}
    out = []

    def job(kind, ident, sched, name, command, targets, wtype, wident, extra):
        stype, sched = _sched_ok("calendar", sched) if sched else ("none", "")
        tl = [{"started_at": datetime.fromtimestamp(int(t["starttime"]), timezone.utc),
               "ended_at": datetime.fromtimestamp(int(t["endtime"]), timezone.utc) if t.get("endtime") else None,
               "status": _task_status(t.get("status")), "output": t.get("status")}
              for t in _pbs_task_match(tasks, wtype, wident) if t.get("starttime")]
        out.append({"key": f"pbs:{node}:{kind}:{ident}", "kind": kind, "source": f"{kind} {ident}", "user": "root",
                    "schedule": sched, "sched_type": stype, "command": command, "raw": "", "name": name,
                    "enabled": bool(sched), "system": False, "wid": None, "monitored": False, "extra": extra,
                    "targets": targets, "pbs_tasks": tl})

    for s in pbs.get("pbs-sync-job") or []:
        if not isinstance(s, dict) or not s.get("id"):
            continue
        r = remotes.get(s.get("remote"), {})
        push = s.get("sync-direction") == "push"
        rlabel = f"{r.get('host') or s.get('remote')}/{s.get('remote-store')}"
        job("pbs-sync", s["id"], s.get("schedule"),
            f"sync {'naar' if push else 'van'} {s.get('remote') or 'lokaal'}:{s.get('remote-store')} {'←' if push else '→'} {s.get('store')}",
            f"proxmox-backup-manager pull {s.get('remote')} {s.get('remote-store')} {s.get('store')}",
            [{"type": "pbs", "ref": r.get("host") or s.get("remote") or "", "label": rlabel, "via": "pbs-sync",
              "dir": "out" if push else "in", "datastore": s.get("remote-store")}] if s.get("remote") else [],
            "syncjob", s["id"], {"store": s.get("store"), "remote": s.get("remote"), "remote_store": s.get("remote-store"),
                                 "remote_host": r.get("host"), "direction": "push" if push else "pull"})
    for v in pbs.get("pbs-verify-job") or []:
        if isinstance(v, dict) and v.get("id"):
            job("pbs-verify", v["id"], v.get("schedule"), f"verify {v.get('store')}", f"verify {v.get('store')}",
                [{"type": "datastore", "ref": f"{node}/{v.get('store')}", "label": f"datastore {v.get('store')}", "via": "verify"}],
                "verificationjob", v["id"], {"store": v.get("store")})
    for p in pbs.get("pbs-prune-job") or []:
        if isinstance(p, dict) and p.get("id"):
            job("pbs-prune", p["id"], p.get("schedule"), f"prune {p.get('store')}", f"prune {p.get('store')}",
                [{"type": "datastore", "ref": f"{node}/{p.get('store')}", "label": f"datastore {p.get('store')}", "via": "prune"}],
                "prunejob", p["id"], {"store": p.get("store")})
    for d in pbs.get("pbs-datastore") or []:
        if not isinstance(d, dict) or not d.get("name"):
            continue
        if d.get("gc-schedule"):
            job("pbs-gc", d["name"], d.get("gc-schedule"), f"garbage collection {d['name']}", f"gc {d['name']}",
                [{"type": "datastore", "ref": f"{node}/{d['name']}", "label": f"datastore {d['name']}", "via": "gc"}],
                "garbage_collection", d["name"], {"store": d["name"], "path": d.get("path")})
        if d.get("prune-schedule"):
            job("pbs-prune", f"{d['name']}-oud", d.get("prune-schedule"), f"prune {d['name']}", f"prune {d['name']}",
                [{"type": "datastore", "ref": f"{node}/{d['name']}", "label": f"datastore {d['name']}", "via": "prune"}],
                "prune", d["name"], {"store": d["name"]})
    return out


# --- Scripts die een job aanroept: tweede ronde, om ook daarin naar doelen te zoeken -------------

_SCRIPT = re.compile(r"(?<![\w/])(/(?:root|home|opt|srv|usr/local|etc/cron\.[a-z]+|etc/periodic/\w+|var/lib|scripts?)/[\w./@+-]+)")


def script_paths(jobs: list[dict]) -> list[str]:
    seen: list[str] = []
    for j in jobs:
        if j["kind"] not in ("cron", "timer"):
            continue
        for p in _SCRIPT.findall(j["command"]):
            if p not in seen and not p.startswith(WRAPPER):
                seen.append(p)
        for name in j.get("extra", {}).get("scripts", [])[:40]:
            m = re.search(r"run-parts\s+(?:--\S+\s+)*(/\S+)", j["command"])
            if m and not j["system"]:
                p = f"{m.group(1).rstrip('/')}/{name}"
                if p not in seen:
                    seen.append(p)
    return seen[:80]


def read_scripts(paths: list[str]) -> str:
    q = " ".join(shlex.quote(p) for p in paths)
    return (f"for f in {q}; do\n"
            "  [ -f \"$f\" ] || continue\n"
            "  case \"$(head -c 4 \"$f\" 2>/dev/null)\" in *ELF*) continue;; esac\n"
            "  echo \"@@SCRIPT $f\"; head -c 40000 \"$f\" 2>/dev/null; echo\n"
            "done\n")


def parse_scripts(text: str) -> dict[str, str]:
    return {rest.strip(): "\n".join(body) for tag, rest, body in _blocks(text) if tag == "SCRIPT"}
