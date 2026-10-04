"""Schijven, ZFS, temperaturen en throttling van een fysieke machine, in één SSH-ronde (als root).

Containers en VM's slaan we over (systemd-detect-virt): hun schijven en sensoren zijn die van de node.
smartctl draait met -n standby, zodat een slapende harde schijf niet gewekt wordt.
"""

import json
import re
from datetime import datetime

PROBE = r"""
v=$(systemd-detect-virt 2>/dev/null); [ -z "$v" ] && v=none
[ -f /run/.containerenv ] || [ -f /.dockerenv ] && v=container
echo "@@VIRT $v"
[ "$v" = none ] || exit 0
echo "@@MODEL $(tr -d '\0' < /sys/firmware/devicetree/base/model 2>/dev/null)|$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null) $(cat /sys/class/dmi/id/product_name 2>/dev/null)"
echo "@@LSBLK"; lsblk -d -J -b -o NAME,MODEL,SERIAL,SIZE,ROTA,TYPE,TRAN 2>/dev/null
if command -v smartctl >/dev/null 2>&1; then
  for d in $(lsblk -d -n -o NAME,TYPE 2>/dev/null | awk '$2=="disk"{print $1}'); do
    case "$d" in zram*|loop*|mmcblk*boot*|rbd*|nbd*) continue;; esac
    echo "@@SMART $d"; timeout 30 smartctl -n standby -a -j "/dev/$d" 2>/dev/null </dev/null
  done
else
  echo "@@NOSMART"
fi
if command -v zpool >/dev/null 2>&1; then
  echo "@@ZLIST"; zpool list -H -p -o name,size,alloc,free,health,frag,cap 2>/dev/null </dev/null
  echo "@@ZSTATUS"; zpool status 2>/dev/null </dev/null
fi
echo "@@TEMPS"
for z in /sys/class/thermal/thermal_zone*; do
  [ -r "$z/temp" ] && echo "zone|$(cat "$z/type" 2>/dev/null)|$(cat "$z/temp" 2>/dev/null)"
done
for h in /sys/class/hwmon/hwmon*; do
  n=$(cat "$h/name" 2>/dev/null)
  for t in "$h"/temp*_input; do
    [ -r "$t" ] || continue
    l=$(cat "${t%_input}_label" 2>/dev/null)
    echo "hwmon|$n|${l:-$(basename "$t" _input)}|$(cat "$t" 2>/dev/null)"
  done
done
echo "@@THROTTLE"
if [ -r /sys/devices/platform/soc/soc:firmware/get_throttled ]; then
  cat /sys/devices/platform/soc/soc:firmware/get_throttled
elif command -v vcgencmd >/dev/null 2>&1; then
  vcgencmd get_throttled 2>/dev/null </dev/null | sed 's/.*=//'
fi
"""


def _blocks(text: str) -> list[tuple[str, str, list[str]]]:
    out: list[tuple[str, str, list[str]]] = []
    for line in text.splitlines():
        if line.startswith("@@"):
            tag, _, rest = line[2:].partition(" ")
            out.append((tag, rest, []))
        elif out:
            out[-1][2].append(line)
    return out


def _json(lines: list[str]):
    try:
        return json.loads("\n".join(lines)) if lines else None
    except ValueError:
        return None


# --- SMART ---------------------------------------------------------------------------

ATA = {5: "realloc", 187: "uncorrect", 197: "pending", 198: "offline_unc", 199: "crc"}
# Genormaliseerde waarde = resterende levensduur in %.
WEAR_LEFT = (177, 231, 233, 202, 169)


def smart(dev: str, d: dict | None, rota: bool | None = None) -> dict:
    out = {"dev": dev, "model": None, "serial": None, "size": None, "ssd": None, "protocol": None, "passed": None,
           "hours": None, "temp": None, "realloc": None, "pending": None, "uncorrect": None, "crc": None,
           "media_errors": None, "wear_used": None, "spare": None, "standby": False, "error": None}
    if not isinstance(d, dict):
        out["error"] = "smartctl gaf geen uitvoer"
        return out
    msgs = [m.get("string", "") for m in (d.get("smartctl") or {}).get("messages", []) if m.get("severity") == "error"]
    if (d.get("power_mode") or "").upper() in ("STANDBY", "SLEEP") or any("STANDBY" in m.upper() for m in msgs):
        out["standby"] = True
    out["model"] = d.get("model_name") or d.get("scsi_model_name")
    out["serial"] = d.get("serial_number")
    out["size"] = (d.get("user_capacity") or {}).get("bytes")
    rr = d.get("rotation_rate")
    out["ssd"] = rr == 0 if rr is not None else (None if rota is None else not rota)
    out["protocol"] = (d.get("device") or {}).get("protocol")
    if "smart_status" in d:
        out["passed"] = bool((d.get("smart_status") or {}).get("passed"))
    out["hours"] = (d.get("power_on_time") or {}).get("hours")
    out["temp"] = (d.get("temperature") or {}).get("current")
    for a in (d.get("ata_smart_attributes") or {}).get("table", []):
        aid = a.get("id")
        raw = (a.get("raw") or {}).get("value")
        if aid in ATA and isinstance(raw, int):
            # Bij sommige merken zitten er extra bits in de hoge bytes: alleen de onderste 32 bit tellen.
            out[ATA[aid]] = raw & 0xFFFFFFFF
        if aid in WEAR_LEFT and isinstance(a.get("value"), int) and out["ssd"] and out["wear_used"] is None:
            out["wear_used"] = max(0, 100 - a["value"])
    nv = d.get("nvme_smart_health_information_log")
    if isinstance(nv, dict):
        out["ssd"] = True
        out["wear_used"] = nv.get("percentage_used")
        out["media_errors"] = nv.get("media_errors")
        out["spare"] = nv.get("available_spare")
        if out["temp"] is None and nv.get("temperature"):
            out["temp"] = nv["temperature"]
        if nv.get("critical_warning"):
            out["passed"] = False
    if out["passed"] is None and not out["standby"] and msgs:
        out["error"] = msgs[0][:200]
    return out


def disk_level(d: dict) -> tuple[str, list[str]]:
    """("ok"|"warn"|"err"|"unknown", redenen)."""
    why: list[str] = []
    if d.get("passed") is False:
        why.append("SMART-test mislukt")
    for k, label in (("pending", "sectoren wachten op herallocatie"), ("uncorrect", "onherstelbare fouten"),
                     ("offline_unc", "onherstelbare sectoren"), ("media_errors", "mediafouten")):
        if d.get(k):
            why.append(f"{d[k]} {label}")
    if why:
        return "err", why
    if d.get("realloc"):
        why.append(f"{d['realloc']} sectoren vervangen")
    if (d.get("wear_used") or 0) >= 80:
        why.append(f"{d['wear_used']}% versleten")
    if d.get("spare") is not None and d["spare"] < 20:
        why.append(f"nog {d['spare']}% reserve")
    if why:
        return "warn", why
    if d.get("passed") is None and not d.get("standby"):
        return "unknown", [d.get("error") or "geen SMART-gegevens"]
    return "ok", []


# --- ZFS ---------------------------------------------------------------------------------

_SCAN = re.compile(r"scan:\s+scrub (repaired \S+ in \S+ with (\d+) errors on (.+)|in progress.*|canceled.*)")


def zfs(zlist: list[str], zstatus: list[str]) -> list[dict]:
    pools = {}
    for line in zlist:
        parts = line.split("\t")
        if len(parts) >= 7:
            name, size, alloc, free, health, frag, cap = parts[:7]
            pools[name] = {"name": name, "size": int(size) if size.isdigit() else None,
                           "alloc": int(alloc) if alloc.isdigit() else None, "health": health,
                           "frag": int(frag) if frag.isdigit() else None, "cap": int(cap) if cap.isdigit() else None,
                           "scrub_at": None, "scrub_errors": None, "scrubbing": False, "errors": None}
    current = None
    for line in zstatus:
        s = line.strip()
        if s.startswith("pool:"):
            current = pools.get(s[5:].strip())
        elif current is None:
            continue
        elif s.startswith("scan:"):
            m = _SCAN.search(s)
            if m and m.group(2):
                current["scrub_errors"] = int(m.group(2))
                try:
                    current["scrub_at"] = datetime.strptime(m.group(3).strip(), "%a %b %d %H:%M:%S %Y").isoformat()
                except ValueError:
                    pass
            elif m and "in progress" in s:
                current["scrubbing"] = True
        elif s.startswith("errors:"):
            current["errors"] = s[7:].strip()
    return list(pools.values())


def pool_level(p: dict, now: datetime) -> tuple[str, list[str]]:
    why = []
    if p.get("health") not in ("ONLINE", None):
        why.append(f"pool is {p['health']}")
    if p.get("scrub_errors"):
        why.append(f"laatste scrub vond {p['scrub_errors']} fouten")
    if p.get("errors") and not p["errors"].startswith("No known"):
        why.append(p["errors"])
    if why:
        return "err", why
    if (p.get("cap") or 0) >= 85:
        why.append(f"{p['cap']}% vol")
    if not p.get("scrub_at") and not p.get("scrubbing"):
        why.append("nog nooit gescrubd")
    elif p.get("scrub_at") and (now - datetime.fromisoformat(p["scrub_at"])).days > 35:
        why.append(f"laatste scrub {(now - datetime.fromisoformat(p['scrub_at'])).days} dagen geleden")
    return ("warn" if why else "ok"), why


# --- Temperaturen en throttling ----------------------------------------------------------------

CPU_HWMON = ("coretemp", "k10temp", "zenpower", "cpu_thermal", "cpu-thermal", "rpi_volt")


def temps(lines: list[str]) -> tuple[list[dict], float | None]:
    out: list[dict] = []
    for line in lines:
        parts = line.split("|")
        try:
            if parts[0] == "zone" and len(parts) == 3:
                out.append({"src": "zone", "chip": parts[1], "label": parts[1], "c": int(parts[2]) / 1000})
            elif parts[0] == "hwmon" and len(parts) == 4:
                out.append({"src": "hwmon", "chip": parts[1], "label": parts[2], "c": int(parts[3]) / 1000})
        except ValueError:
            continue
    out = [t for t in out if -40 < t["c"] < 150]
    cpu = None
    for t in out:
        if t["chip"] == "coretemp" and t["label"].lower().startswith("package"):
            cpu = max(cpu or -99, t["c"])
    if cpu is None:
        cand = [t["c"] for t in out if t["chip"] in ("k10temp", "zenpower") and t["label"] in ("Tctl", "Tdie")]
        cand = cand or [t["c"] for t in out if t["chip"] in ("coretemp",)]
        cand = cand or [t["c"] for t in out if re.search(r"cpu|x86_pkg|soc", t["chip"], re.I)]
        cpu = max(cand) if cand else None
    return out, cpu


THROTTLE_BITS = {0: "te lage spanning", 1: "frequentie begrensd", 2: "vertraagd (throttling)", 3: "temperatuurgrens"}


def throttle(lines: list[str]) -> dict | None:
    raw = "".join(lines).strip()
    if not raw:
        return None
    try:
        v = int(raw, 16)  # vcgencmd: "0x50005", sysfs: "50005", allebei hex
    except ValueError:
        return None
    now = [label for bit, label in THROTTLE_BITS.items() if v & (1 << bit)]
    past = [label for bit, label in THROTTLE_BITS.items() if v & (1 << (bit + 16))]
    return {"raw": hex(v), "now": now, "since_boot": past}


def parse(text: str) -> dict:
    out = {"virt": None, "model": None, "disks": [], "pools": [], "temps": [], "cpu_temp": None, "throttle": None,
           "smartctl": True}
    lsblk = {}
    zlist, zstatus = [], []
    for tag, rest, body in _blocks(text):
        if tag == "VIRT":
            out["virt"] = rest.strip()
        elif tag == "MODEL":
            a, _, b = rest.partition("|")
            out["model"] = (a.strip() or b.strip()) or None
        elif tag == "LSBLK":
            j = _json(body) or {}
            for b in j.get("blockdevices", []):
                lsblk[b.get("name")] = b
        elif tag == "SMART":
            dev = rest.strip()
            b = lsblk.get(dev, {})
            d = smart(dev, _json(body), b.get("rota") in (True, "1", 1) if "rota" in b else None)
            d["model"] = d["model"] or (b.get("model") or "").strip() or None
            d["serial"] = d["serial"] or (b.get("serial") or "").strip() or None
            d["size"] = d["size"] or (int(b["size"]) if str(b.get("size", "")).isdigit() else None)
            d["tran"] = b.get("tran")
            out["disks"].append(d)
        elif tag == "NOSMART":
            out["smartctl"] = False
        elif tag == "ZLIST":
            zlist = body
        elif tag == "ZSTATUS":
            zstatus = body
        elif tag == "TEMPS":
            out["temps"], out["cpu_temp"] = temps(body)
        elif tag == "THROTTLE":
            out["throttle"] = throttle(body)
    out["pools"] = zfs(zlist, zstatus)
    return out
