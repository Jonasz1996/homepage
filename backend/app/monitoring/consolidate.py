"""Voorstel om één node 's nachts uit te zetten: welke VM's en CT's naar welke andere node verhuizen zodat hij leeg is,
of dat past (piek-RAM van de laatste 7 dagen, 20% marge) en wat het bespaart. Alleen advies: het dashboard verhuist
zelf niets.

Een gast met passthrough (PCI, USB, een apparaat in een CT) kan niet mee; dan kan die node niet uit. Een node met een
andere architectuur (de Raspberry Pi) kan geen gasten van een x86-node draaien en omgekeerd.
"""

import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..integrations import IntegrationError, build
from ..models import Metric, Service
from .checks import HttpClients

HEADROOM = 0.8          # een doelnode mag tot 80% van zijn RAM en CPU vol
HOST_RESERVE = 2 << 30  # RAM voor Proxmox zelf
GUESS_WATTS = 25        # een oude HP-desktop in rust, als er geen meting is
PASSTHROUGH = re.compile(r"^(hostpci|usb)\d+$")
QEMU_DISK = re.compile(r"^(scsi|sata|virtio|ide|efidisk|tpmstate)\d+$")
LXC_DISK = re.compile(r"^(rootfs|mp\d+)$")
LXC_DEV = re.compile(r"^dev\d+$")


def _arch(status: dict) -> str:
    machine = ((status or {}).get("current-kernel") or {}).get("machine") or ""
    model = ((status or {}).get("cpuinfo") or {}).get("model") or ""
    return "arm" if machine in ("aarch64", "arm64") or re.search(r"cortex|arm", model, re.I) else "x86"


def disks(kind: str, conf: dict) -> list[tuple[str, str]]:
    """(sleutel, opslag of pad) van elke schijf; een pad (begint met /) is een bind mount."""
    out = []
    for k, v in (conf or {}).items():
        if not isinstance(v, str) or not (QEMU_DISK.match(k) if kind == "qemu" else LXC_DISK.match(k)):
            continue
        if "media=cdrom" in v or v.startswith("none"):
            continue
        first = v.split(",")[0]
        out.append((k, first if first.startswith("/") else first.split(":")[0]))
    return out


def command(g: dict, to: str, local: bool) -> str:
    if g["type"] == "qemu":
        return f"qm migrate {g['vmid']} {to}" + (" --online" if g["running"] else "") + \
            (" --with-local-disks" if local and g["running"] else "")
    return f"pct migrate {g['vmid']} {to}" + (" --restart" if g["running"] else "")


def place(movers: list[dict], room: dict[str, dict]) -> tuple[dict[int, str], str | None]:
    """Grootste eerst, telkens naar de doelnode met de meeste ruimte over. Geeft (vmid → node, of waarom niet)."""
    out = {}
    for g in sorted(movers, key=lambda g: (-g["need"], g["vmid"])):
        fits = [n for n, r in room.items() if r["mem"] >= g["need"] and r["cpu"] >= g["cpu"]]
        if not fits:
            best = max(room.values(), key=lambda r: r["mem"], default={"mem": 0})
            short = (g["need"] - max(best["mem"], 0)) / (1 << 30)
            return out, f"{g['name']} ({g['vmid']}) past nergens: {short:.1f} GB RAM tekort"
        to = max(fits, key=lambda n: (room[n]["mem"], n))
        room[to]["mem"] -= g["need"]
        room[to]["cpu"] -= g["cpu"]
        out[g["vmid"]] = to
    return out, None


async def _peaks(db: AsyncSession, now: datetime) -> dict[int, int]:
    """Hoogste RAM per vmid over 7 dagen (de naam van een meting is "node/vmid", ook na een verhuis)."""
    out: dict[int, int] = {}
    rows = await db.execute(select(Metric.name, func.max(Metric.mem)).where(
        Metric.kind == "guest", Metric.ts >= now - timedelta(days=7)).group_by(Metric.name))
    for name, mem in rows.all():
        vmid = name.rpartition("/")[2]
        if vmid.isdigit() and mem:
            out[int(vmid)] = max(out.get(int(vmid), 0), int(mem))
    return out


async def _power(db: AsyncSession, http: HttpClients, now: datetime) -> tuple[dict[str, float], float | None]:
    """Gemiddeld verbruik per Home Assistant-label over 7 dagen, en de prijs per kWh."""
    rows = await db.execute(select(Metric.name, func.avg(Metric.watts)).where(
        Metric.kind == "power", Metric.ts >= now - timedelta(days=7)).group_by(Metric.name))
    watts = {name.lower(): float(w) for name, w in rows.all() if w is not None}
    price = None
    for svc in (await db.execute(select(Service).where(Service.type == "homeassistant"))).scalars():
        try:
            price = build(svc, http).price
        except IntegrationError:
            continue
        if price is not None:
            break
    return watts, price


def _watts(node: str, watts: dict[str, float]) -> float | None:
    n = node.lower()
    return watts.get(n) or next((w for k, w in watts.items() if n in k), None)


async def propose(db: AsyncSession, http: HttpClients, hours: int = 8) -> dict:
    now = datetime.now(timezone.utc)
    svc = (await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars().first()
    if svc is None:
        return {"error": "Nog geen Proxmox-tegel", "candidates": []}
    px = build(svc, http)
    res = await px.get("/cluster/resources")
    storages = {s["storage"]: s for s in await px.get("/storage")}
    nodes = {r["node"]: r for r in res if r.get("type") == "node" and r.get("status") == "online"}
    arch = {}
    for n in nodes:
        try:
            arch[n] = _arch(await px.get(f"/nodes/{n}/status"))
        except IntegrationError:
            arch[n] = "x86"
    peaks = await _peaks(db, now)
    watts, price = await _power(db, http, now)
    guests = []
    for r in res:
        if r.get("type") not in ("qemu", "lxc") or r.get("template") or r.get("node") not in nodes:
            continue
        running = r.get("status") == "running"
        mem = max(peaks.get(int(r["vmid"]), 0), int(r.get("mem") or 0))
        guests.append({"vmid": int(r["vmid"]), "name": r.get("name") or str(r["vmid"]), "type": r["type"],
                       "node": r["node"], "running": running,
                       "need": min(mem, int(r.get("maxmem") or mem)) if running else 0,
                       "cpu": float(r.get("cpu") or 0) * float(r.get("maxcpu") or 1) if running else 0.0})
    on = defaultdict(list)
    for g in guests:
        on[g["node"]].append(g)

    out = []
    for name in sorted(nodes):
        others = [n for n in nodes if n != name and arch[n] == arch[name]]
        w = _watts(name, watts)
        cand = {"node": name, "arch": arch[name], "guests": len(on[name]), "watts": round(w or GUESS_WATTS, 1),
                "estimated": w is None, "moves": [], "blockers": [], "feasible": False, "why": None}
        cand["kwh_year"] = round(cand["watts"] * hours * 365 / 1000, 1)
        cand["eur_year"] = round(cand["kwh_year"] * price, 2) if price is not None else None
        if not others:
            cand["why"] = "geen andere node met dezelfde architectuur" if len(nodes) > 1 else "de enige node"
            out.append(cand)
            continue
        details = {}
        for g in on[name]:
            kind = "qemu" if g["type"] == "qemu" else "lxc"
            try:
                conf = await px.get(f"/nodes/{name}/{kind}/{g['vmid']}/config")
            except IntegrationError:
                conf = {}
            conf = conf if isinstance(conf, dict) else {}
            passthrough = [k for k in conf if PASSTHROUGH.match(k) or (kind == "lxc" and LXC_DEV.match(k))]
            ds = disks(kind, conf)
            local = sorted({s for _, s in ds if not s.startswith("/") and not (storages.get(s) or {}).get("shared")})
            binds = sorted({s for _, s in ds if s.startswith("/")})
            details[g["vmid"]] = (passthrough, local, binds)
            if passthrough:
                cand["blockers"].append(f"{g['name']} ({g['vmid']}): passthrough {', '.join(passthrough)}")
        if cand["blockers"]:
            cand["why"] = "passthrough kan niet verhuizen"
            out.append(cand)
            continue
        room = {}
        for n in others:
            used = sum(g["need"] for g in on[n]) + HOST_RESERVE
            room[n] = {"mem": int(nodes[n].get("maxmem") or 0) * HEADROOM - used,
                       "cpu": float(nodes[n].get("maxcpu") or 1) * HEADROOM
                       - float(nodes[n].get("cpu") or 0) * float(nodes[n].get("maxcpu") or 1)}
        where, why = place(on[name], room)
        if why:
            cand["why"] = why
            out.append(cand)
            continue
        for g in sorted(on[name], key=lambda g: g["vmid"]):
            to = where[g["vmid"]]
            _, local, binds = details[g["vmid"]]
            notes = [f"lokale schijf op {s}: de migratie kopieert ze" for s in local]
            notes += [f"opslag {s} bestaat niet op {to}" for s in local
                      if (storages.get(s) or {}).get("nodes") and to not in str(storages[s]["nodes"]).split(",")]
            notes += [f"bind mount {p}: die map moet ook op {to} bestaan" for p in binds]
            if not g["running"]:
                notes.append("staat uit")
            cand["moves"].append({"vmid": g["vmid"], "name": g["name"], "type": "VM" if g["type"] == "qemu" else "CT",
                                  "to": to, "need": g["need"], "notes": notes,
                                  "command": command(g, to, bool(local))})
        cand["feasible"] = True
        cand["after"] = {n: round(r["mem"] / (1 << 30), 1) for n, r in room.items()}
        out.append(cand)
    # Beste eerst: haalbaar, dan wie het meest verbruikt, dan wie het minst te verhuizen heeft.
    out.sort(key=lambda c: (not c["feasible"], -c["watts"], sum(m["need"] for m in c["moves"]), c["node"]))
    best = next((c["node"] for c in out if c["feasible"]), None)
    return {"error": None, "candidates": out, "best": best, "hours": hours, "price": price,
            "nodes": len(nodes), "quorum_left": len(nodes) - 1 > len(nodes) / 2}
