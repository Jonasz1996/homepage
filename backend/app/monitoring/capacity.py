"""Capaciteit: elke 10 minuten het gebruik uit Proxmox bewaren en voorspellen wanneer opslag vol loopt."""

import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import event, notify
from ..integrations import IntegrationError, build
from ..models import AppState, Metric, Service
from .checks import HttpClients

log = logging.getLogger("homepage.worker")

SAMPLE_EVERY = 600
TREND_DAYS = 7
# Melden als een opslag binnen zoveel dagen vol loopt; nog eens als het echt dringend wordt.
WARN_DAYS = (14, 3)


def _int(v) -> int | None:
    try:
        return int(v) if v is not None else None
    except (TypeError, ValueError):
        return None


def rows_from_resources(service_id: int, res: list[dict], ts: datetime) -> list[Metric]:
    out, seen = [], set()
    for r in res:
        t = r.get("type")
        if t == "node":
            if r.get("status") != "online":
                continue
            m = Metric(service_id=service_id, kind="node", name=str(r.get("node")), label=None, cpu=r.get("cpu"),
                       mem=_int(r.get("mem")), mem_total=_int(r.get("maxmem")),
                       disk=_int(r.get("disk")), disk_total=_int(r.get("maxdisk")))
        elif t in ("qemu", "lxc") and not r.get("template"):
            running = r.get("status") == "running"
            # Bij VM's meldt Proxmox geen schijfgebruik (alleen de agent weet dat), bij CT's wel.
            m = Metric(service_id=service_id, kind="guest", name=f"{r.get('node')}/{r.get('vmid')}",
                       label=f"{'VM' if t == 'qemu' else 'CT'} {r.get('vmid')} {r.get('name') or ''}".strip(),
                       cpu=r.get("cpu") if running else None, mem=_int(r.get("mem")) if running else None,
                       mem_total=_int(r.get("maxmem")),
                       disk=_int(r.get("disk")) if t == "lxc" and r.get("disk") else None,
                       disk_total=_int(r.get("maxdisk")))
        elif t == "storage" and r.get("maxdisk") and r.get("status", "available") == "available":
            name = r.get("storage") if r.get("shared") else f"{r.get('node')}/{r.get('storage')}"
            m = Metric(service_id=service_id, kind="storage", name=str(name), label=r.get("plugintype"),
                       disk=_int(r.get("disk")), disk_total=_int(r.get("maxdisk")))
        else:
            continue
        if (m.kind, m.name) in seen:
            continue
        seen.add((m.kind, m.name))
        m.ts = ts
        out.append(m)
    return out


async def sample(db: AsyncSession, clients: HttpClients, now: datetime | None = None) -> int:
    now = now or datetime.now(timezone.utc)
    n = 0
    for svc in (await db.execute(select(Service).where(Service.type == "proxmox"))).scalars().all():
        try:
            res = await build(svc, clients).resources()
        except IntegrationError as e:
            log.info("Proxmox %s niet bereikbaar voor capaciteit: %s", svc.name, e)
            continue
        rows = rows_from_resources(svc.id, res, now)
        db.add_all(rows)
        n += len(rows)
        await detect_restarts(db, svc, res, now)
    return n


def _guest_name(r: dict) -> str:
    return f"{'VM' if r.get('type') == 'qemu' else 'CT'} {r.get('vmid')} {r.get('name') or ''}".strip()


def _at(now: datetime, uptime: float) -> str:
    return (now - timedelta(seconds=uptime)).astimezone().strftime("%H:%M")


async def detect_restarts(db: AsyncSession, svc: Service, res: list[dict], now: datetime) -> None:
    """Herstarts van nodes en starten/stoppen van VM's/CT's op de tijdlijn zetten.

    Proxmox geeft de uptime mee: daalt die, dan is de machine herstart. Een herstarte node krijgt één
    melding, met de VM's/CT's die daarna opkwamen erbij (geen lawine van losse regels)."""
    key = f"uptime:{svc.id}"
    state = await db.get(AppState, key)
    prev = dict(state.value) if state else {}
    cur = dict(prev)
    online = {r.get("node") for r in res if r.get("type") == "node" and r.get("status") == "online"}
    rebooted: dict[str, int] = {}
    per_node: dict[str, list[str]] = defaultdict(list)
    singles: list[tuple[str, str, str]] = []
    for r in res:
        if r.get("type") == "node" and r.get("node") in online:
            k, up = f"n:{r.get('node')}", int(r.get("uptime") or 0)
            old = prev.get(k)
            if old and up < old[0]:
                rebooted[r["node"]] = up
            cur[k] = [up, 1]
    for r in res:
        t = r.get("type")
        if t in ("qemu", "lxc") and not r.get("template") and r.get("node") in online:
            k = f"g:{r.get('vmid')}"
            running = r.get("status") == "running"
            up = int(r.get("uptime") or 0) if running else 0
            old = prev.get(k)
            cur[k] = [up, int(running)]
            if not old:
                continue
            node_up = rebooted.get(r["node"])
            if running and (not old[1] or up < old[0] or (node_up is not None and up <= node_up)):
                what = "gestart" if not old[1] else "herstart"
                per_node[r["node"]].append(f"{_guest_name(r)} {what} om {_at(now, up)}")
            elif not running and old[1]:
                singles.append((r["node"], f"{_guest_name(r)} gestopt", "Op " + str(r.get("node")) + "."))
    for node, up in sorted(rebooted.items()):
        guests = per_node.pop(node, [])
        down = [t for n, t, _ in singles if n == node]
        body = f"Weer online sinds {_at(now, up)}."
        if guests:
            body += "\nDaarna opgestart:\n" + "\n".join(guests)
        if down:
            body += "\nNiet meer actief:\n" + "\n".join(t.removesuffix(" gestopt") for t in down)
        notify(db, f"Node {node} is herstart", body, level="warn", source="herstart", service_id=svc.id,
               data={"node": node, "uptime": up})
    for node, lines in per_node.items():
        for line in lines:
            title, _, at = line.rpartition(" om ")
            event(db, "herstart", title, f"Op {node}, om {at}.", service_id=svc.id)
    for node, title, body in singles:
        if node not in rebooted:
            event(db, "herstart", title, body, service_id=svc.id)
    if state:
        state.value = cur
    else:
        db.add(AppState(key=key, value=cur))


def forecast(points: list[tuple[float, float]], total: float | None) -> tuple[float | None, float | None]:
    """Lineaire trend (bytes per dag) en aantal dagen tot vol, of None als er niets te voorspellen valt."""
    if len(points) < 6 or not total:
        return None, None
    t0 = points[0][0]
    xs = [(t - t0) / 86400 for t, _ in points]
    ys = [y for _, y in points]
    if xs[-1] - xs[0] < 0.5:  # minstens 12 uur gegevens
        return None, None
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    var = sum((x - mx) ** 2 for x in xs)
    if not var:
        return None, None
    rate = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / var
    if rate <= 0:
        return rate, None
    now_val = my + rate * (xs[-1] - mx)
    return rate, max(0.0, (total - now_val) / rate)


async def storage_trends(db: AsyncSession, now: datetime | None = None) -> list[dict]:
    now = now or datetime.now(timezone.utc)
    stmt = (select(Metric.service_id, Metric.name, Metric.label, Metric.ts, Metric.disk, Metric.disk_total)
            .where(Metric.kind == "storage", Metric.ts >= now - timedelta(days=TREND_DAYS)).order_by(Metric.ts))
    series: dict[tuple[int, str], list] = defaultdict(list)
    for sid, name, label, ts, used, total in (await db.execute(stmt)).all():
        if used is not None:
            series[(sid, name)].append((ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc), used, total, label))
    out = []
    for (sid, name), pts in series.items():
        last = pts[-1]
        if last[0] < now - timedelta(minutes=45):
            continue  # opslag bestaat niet meer of node ligt plat
        # Alleen de trend sinds de laatste grote opkuis of vergroting telt.
        start = len(pts) - 1
        while start > 0 and pts[start - 1][2] == last[2] and pts[start - 1][1] - pts[start][1] < 0.1 * (last[2] or 0):
            start -= 1
        pts = pts[start:]
        rate, days = forecast([(p[0].timestamp(), p[1]) for p in pts], last[2])
        step = max(1, len(pts) // 60)
        out.append({"service_id": sid, "name": name, "type": last[3], "used": last[1], "total": last[2],
                    "rate_per_day": rate, "days_left": days,
                    "series": [[int(p[0].timestamp()), round(p[1] / p[2] * 100, 2) if p[2] else None]
                               for p in pts[::step]]})
    return sorted(out, key=lambda x: (x["days_left"] is None, x["days_left"] or 0, x["name"]))


async def check_forecasts(db: AsyncSession, now: datetime | None = None) -> None:
    names = {s.id: s.name for s in (await db.execute(select(Service))).scalars()}
    for t in await storage_trends(db, now):
        key = f"disk_full:{t['service_id']}:{t['name']}"[:100]
        state = await db.get(AppState, key)
        days = t["days_left"]
        level = next((w for w in reversed(WARN_DAYS) if days is not None and days <= w), None)
        if level is None:
            # Weer ruim genoeg (met wat speling, zodat een schommelende trend niet blijft melden).
            if state and (days is None or days > WARN_DAYS[0] * 1.5):
                await db.delete(state)
            continue
        if state and state.value.get("level", 999) <= level:
            continue
        pct = t["used"] / t["total"] * 100 if t["total"] else 0
        gb = (t["rate_per_day"] or 0) / 1e9
        when = "binnen een dag" if days < 1 else f"over {round(days)} dag{'en' if round(days) != 1 else ''}"
        notify(db, f"{t['name']} vol {when}",
               f"Nu {pct:.0f}% gebruikt, groeit ongeveer {gb:.1f} GB per dag ({names.get(t['service_id'], '?')}).",
               level="err" if level <= WARN_DAYS[-1] else "warn", source="capaciteit", service_id=t["service_id"])
        if state:
            state.value = {"level": level}
        else:
            db.add(AppState(key=key, value={"level": level}))
