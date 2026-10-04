"""Waar een job aan komt: doelen uit het commando (en de scripts die het aanroept), Proxmox-opslag en
PBS-remotes. Daarna koppelen we die doelen aan de machines die we kennen, zodat je ziet wat waarheen synct,
en zoeken we jobs die tegelijk op dezelfde opslag of machine inhakken.
"""

import re
import shlex
from datetime import datetime, timedelta

SYNC_TOOLS = {"rsync", "scp", "sftp", "rclone", "borg", "restic", "syncoid", "zfs", "proxmox-backup-client", "lftp",
              "unison", "kopia", "rdiff-backup", "duplicity", "pg_dump", "pg_dumpall", "mysqldump", "mariadb-dump",
              "tar", "cp", "mount", "ssh", "curl", "wget", "vzdump", "pct", "qm", "wakeonlan", "etherwake"}
COPY_TOOLS = {"rsync", "scp", "rclone", "cp", "unison", "lftp", "rdiff-backup", "duplicity"}
HEAVY_VIA = {"rsync", "scp", "rclone", "borg", "restic", "syncoid", "zfs", "proxmox-backup-client", "rdiff-backup",
             "duplicity", "kopia", "vzdump", "pbs-sync", "verify", "gc", "prune", "zfs-replicatie", "pg_dump",
             "mysqldump", "tar", "unison", "lftp"}
LOCAL = {"localhost", "127.0.0.1", "0.0.0.0", "::1", ""}
PING_HOSTS = re.compile(r"(hc-ping\.com|healthchecks|uptime-?kuma|cronitor|deadmanssnitch|betteruptime|/api/push/)", re.I)

_REMOTE = re.compile(r"^(?:([\w.+-]+)@)?([A-Za-z0-9][\w.-]*)::?(/|~|[\w.-]*$|[\w.-]+/)")
_URL = re.compile(r"https?://(?:[^@/\s]+@)?([\w.-]+)(?::(\d+))?(/[^\s'\"]*)?")
_PBS_REPO = re.compile(r"(?:--repository[ =]|PBS_REPOSITORY=)['\"]?(?:[^@\s'\"]+@[^@\s'\"]+@)?([\w.-]+):([\w-]+)")
_MNT_PVE = re.compile(r"/mnt/pve/([\w.-]+)")
_IP = re.compile(r"\b((?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3})\b")
_LOCAL_DEST = re.compile(r"^(/mnt/[\w.-]+|/media/[\w.-]+|/backup[\w.-]*|/srv/[\w.-]+|/data[\w.-]*)")
# Opties van ssh/rsync/scp die een waarde meekrijgen.
_OPT_ARG = {"-p", "-P", "-i", "-o", "-e", "-l", "-F", "-J", "-b", "-c", "-L", "-R", "-D", "-W", "--rsh", "--port",
            "--exclude", "--include", "--filter", "--log-file", "--password-file", "--config", "--bwlimit",
            "--timeout", "--max-size", "--min-size", "--partial-dir", "--backup-dir", "--suffix", "--compare-dest",
            "--link-dest", "--chown", "--chmod", "--transfers", "--checkers", "--exclude-from", "--include-from"}


def _segments(text: str) -> list[list[str]]:
    out = []
    for line in text.splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        for seg in re.split(r"\s*(?:&&|\|\||;|\|)\s*", line):
            try:
                words = shlex.split(seg, posix=True)
            except ValueError:
                words = seg.split()
            if words:
                out.append(words)
    return out


def _tool(words: list[str]) -> tuple[str | None, list[str]]:
    for i, w in enumerate(words):
        base = w.split("/")[-1]
        if base in ("sudo", "nice", "ionice", "timeout", "flock", "nohup", "env", "time") or "=" in w and i == 0:
            continue
        if base in SYNC_TOOLS:
            return base, words[i + 1:]
        if not w.startswith("-") and not re.fullmatch(r"\d+[smhd]?", w):
            return None, []
    return None, []


def _args(args: list[str]) -> list[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if a in _OPT_ARG:
                skip = True
            continue
        out.append(a)
    return out


def _t(type_: str, ref: str, label: str, via: str, **extra) -> dict:
    return {"type": type_, "ref": ref, "label": label, "via": via, **extra}


def from_text(text: str) -> list[dict]:
    found: list[dict] = []
    for words in _segments(text or ""):
        tool, rest = _tool(words)
        if not tool:
            continue
        for i, w in enumerate(words[:-1]):
            if w in (">", ">>", "-f", "--file", "-o", "--output") and (m := _LOCAL_DEST.match(words[i + 1])):
                found.append(_t("path", m.group(1), m.group(1), tool, dir="out"))
        args = _args([w for i, w in enumerate(rest) if w not in (">", ">>", "2>&1") and (i == 0 or rest[i - 1] not in (">", ">>"))])
        if tool in ("ssh",):
            if args:
                user, _, host = args[0].rpartition("@")
                if host not in LOCAL:
                    found.append(_t("host", host, host, "ssh"))
            continue
        if tool in ("curl", "wget"):
            for a in rest:
                if m := _URL.search(a):
                    host = m.group(1)
                    if PING_HOSTS.search(a):
                        found.append(_t("ping", host, f"heartbeat {host}", tool))
                    elif host not in LOCAL:
                        found.append(_t("web", host, host, tool))
            continue
        if tool == "proxmox-backup-client":
            for m in _PBS_REPO.finditer(" ".join(words)):
                found.append(_t("pbs", m.group(1), f"{m.group(1)}/{m.group(2)}", tool, datastore=m.group(2)))
            continue
        if tool in ("wakeonlan", "etherwake"):
            continue
        if tool in ("pct", "qm") and len(args) >= 2 and args[1].isdigit():
            found.append(_t("guest", args[1], f"{'CT' if tool == 'pct' else 'VM'} {args[1]}", f"{tool} {args[0]}"))
            continue
        if tool == "rclone":
            for i, a in enumerate(args[1:], 1):
                if m := _MNT_PVE.search(a):
                    found.append(_t("storage", m.group(1), f"storage {m.group(1)}", "rclone",
                                    dir="out" if i == len(args) - 1 else "in"))
                if m := re.match(r"^([A-Za-z][\w-]*):(.*)$", a):
                    found.append(_t("cloud", m.group(1), f"rclone {m.group(1)}:{m.group(2)[:40]}", "rclone",
                                    dir="out" if i == len(args) - 1 else "in"))
            continue
        for i, a in enumerate(args):
            last = i == len(args) - 1
            if m := _REMOTE.match(a):
                host = m.group(2)
                if host not in LOCAL and not host.lower().startswith(("http", "ftp")) and len(host) > 1:
                    found.append(_t("host", host, f"{host}:{a.split(':', 1)[1][:40]}", tool,
                                    dir="out" if last or tool not in COPY_TOOLS else "in"))
            elif m := _URL.search(a):
                found.append(_t("web", m.group(1), m.group(1), tool))
            elif last and tool in COPY_TOOLS | {"tar", "borg", "restic"} and (m := _LOCAL_DEST.match(a)):
                found.append(_t("path", m.group(1), m.group(1), tool, dir="out"))
            if m := _MNT_PVE.search(a):
                found.append(_t("storage", m.group(1), f"storage {m.group(1)}", tool,
                                dir="out" if last else "in"))
        if tool in ("borg", "restic", "kopia", "mount", "zfs", "syncoid"):
            for ip in _IP.findall(" ".join(rest)):
                found.append(_t("host", ip, ip, tool))
    # Dubbels weg, volgorde houden.
    seen, out = set(), []
    for f in found:
        k = (f["type"], f["ref"].lower())
        if k not in seen:
            seen.add(k)
            out.append(f)
    return out[:20]


def extract(job: dict) -> list[dict]:
    text = job.get("command", "")
    script = (job.get("extra") or {}).get("script")
    if script:
        text += "\n" + script
    return from_text(text)


def storage_target(name: str | None, st: dict) -> list[dict]:
    if not name:
        return []
    t = st.get("type")
    if t == "pbs" and st.get("server"):
        return [_t("pbs", st["server"], f"{st['server']}/{st.get('datastore', '?')}", "vzdump",
                   datastore=st.get("datastore"), storage=name)]
    if t in ("nfs", "cifs") and st.get("server"):
        share = st.get("export") or st.get("share") or ""
        return [_t("host", st["server"], f"{st['server']}:{share}", "vzdump", storage=name)]
    return [_t("storage", name, f"storage {name}" + (f" ({t})" if t else ""), "vzdump")]


# --- Koppelen aan bekende machines --------------------------------------------------------

class Resolver:
    """Zet een hostnaam of IP om naar een machine uit de scan (of None = buiten het dashboard)."""

    def __init__(self) -> None:
        self.by_name: dict[str, str] = {}

    def add(self, mid: str, *names: str | None) -> None:
        for n in names:
            if not n:
                continue
            n = n.lower().strip()
            self.by_name.setdefault(n, mid)
            short = n.split(".")[0]
            if not _IP.fullmatch(n):
                self.by_name.setdefault(short, mid)

    def find(self, ref: str | None) -> str | None:
        if not ref:
            return None
        r = ref.lower().strip()
        return self.by_name.get(r) or (None if _IP.fullmatch(r) else self.by_name.get(r.split(".")[0]))


def default_duration(kind: str, via: set[str]) -> float:
    return {"pve-backup": 1800, "pbs-verify": 3600, "pbs-gc": 1200, "pbs-sync": 1200, "pbs-prune": 120,
            "pve-repl": 60}.get(kind, 600 if via & HEAVY_VIA else 60)


def conflicts(occ: list[dict]) -> list[dict]:
    """Paren van zware jobs die elkaar in de tijd overlappen en dezelfde bron raken.
    occ: [{"job": id, "name", "start": dt, "end": dt, "res": set[str]}]."""
    occ = sorted(occ, key=lambda o: o["start"])
    out, seen = [], set()
    for i, a in enumerate(occ):
        for b in occ[i + 1:]:
            if b["start"] >= a["end"]:
                break
            if a["job"] == b["job"]:
                continue
            shared = a["res"] & b["res"]
            if not shared:
                continue
            k = (min(a["job"], b["job"]), max(a["job"], b["job"]))
            if k in seen:
                continue
            seen.add(k)
            out.append({"a": a["job"], "b": b["job"], "a_name": a["name"], "b_name": b["name"],
                        "at": max(a["start"], b["start"]), "overlap_s": (min(a["end"], b["end"]) - max(a["start"], b["start"])).total_seconds(),
                        "on": sorted(shared)[0]})
    return out[:50]


def busy_hours(occ: list[dict], start: datetime, hours: int) -> list[int]:
    """Hoeveel zware jobs er per uur lopen."""
    out = [0] * hours
    for o in occ:
        s = max(o["start"], start)
        e = min(o["end"], start + timedelta(hours=hours))
        i = int((s - start).total_seconds() // 3600)
        while i < hours and start + timedelta(hours=i) < e:
            out[i] += 1
            i += 1
    return out
