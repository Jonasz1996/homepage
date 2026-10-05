"""Schijven, pools en temperaturen van alle fysieke machines ophalen, vergelijken met de vorige keer en melden
wat slechter werd. Temperaturen gaan ook in de tabel readings voor de grafiek."""

import asyncio
import hashlib
import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import job_lock
from ..deps import event, notify
from ..models import AppState, Reading, SshHost
from ..ssh_exec import SshFail, connect, run
from ..ssh_login import defaults, login_for
from . import probe

log = logging.getLogger("homepage.health")

HEALTH_EVERY = 10 * 60
STATE_KEY = "health"
SETTINGS_KEY = "health_settings"
DEFAULTS = {"cpu_warn": 85, "disk_warn": 55, "snapshot_days": 14, "domains": [], "offsite": False}
COUNTERS = {"realloc": "vervangen sectoren", "pending": "wachtende sectoren", "uncorrect": "onherstelbare fouten",
            "offline_unc": "onherstelbare sectoren", "media_errors": "mediafouten", "crc": "kabelfouten (CRC)"}
RANK = {"ok": 0, "unknown": 0, "warn": 1, "err": 2}
KEEP_READINGS = timedelta(days=30)


async def settings(db: AsyncSession) -> dict:
    st = await db.get(AppState, SETTINGS_KEY)
    return {**DEFAULTS, **(st.value if st else {})}


def _fp(h: SshHost) -> str:
    return hashlib.sha1((h.host_key or f"{h.host}:{h.port}").encode()).hexdigest()[:12]


async def probe_host(h: SshHost, login) -> dict:
    base = {"key": f"ssh:{h.id}", "name": h.name, "host_id": h.id, "host": h.host, "error": None}
    try:
        async with connect(h, login) as conn:
            rc, out, err = await run(conn, probe.PROBE, login, timeout=180)
    except SshFail as e:
        return {**base, "error": str(e)}
    if "@@VIRT" not in out:
        return {**base, "error": (err.strip().splitlines() or [f"exitcode {rc}"])[-1][:300]}
    return {**base, **probe.parse(out)}


def _disk_key(host_key: str, d: dict) -> str:
    return f"{d['serial']}" if d.get("serial") else f"{host_key}:{d['dev']}"


async def collect(db: AsyncSession) -> list[dict]:
    hosts = (await db.execute(select(SshHost).where(SshHost.host_key.is_not(None)).order_by(SshHost.id))).scalars().all()
    # Containers bereiken we via hun node; dezelfde machine twee keer in de lijst (zelfde hostsleutel): één keer.
    seen, todo = set(), []
    for h in hosts:
        if (h.source or "").split("/")[0].endswith(":lxc"):
            continue
        fp = _fp(h)
        if fp in seen:
            continue
        seen.add(fp)
        todo.append(h)
    d = await defaults(db)
    sem = asyncio.Semaphore(6)
    # Logins eerst na elkaar ophalen: één AsyncSession mag niet door parallelle taken gedeeld worden.
    logins = {}
    for h in todo:
        try:
            logins[h.id] = await login_for(db, h, d)
        except Exception as e:
            logins[h.id] = e

    async def one(h):
        login = logins[h.id]
        if isinstance(login, BaseException):
            raise login
        async with sem:
            return await probe_host(h, login)

    results = await asyncio.gather(*(one(h) for h in todo), return_exceptions=True)
    out = []
    for h, r in zip(todo, results):
        if isinstance(r, BaseException):
            log.warning("gezondheid van %s mislukt: %r", h.name, r)
            r = {"key": f"ssh:{h.id}", "name": h.name, "host_id": h.id, "host": h.host, "error": type(r).__name__}
        out.append(r)
    # Alleen fysieke machines (en wie niet bereikbaar was, zodat je dat ziet).
    return [m for m in out if m.get("error") or m.get("virt") == "none"]


def evaluate(m: dict, now: datetime) -> None:
    for d in m.get("disks", []):
        d["level"], d["why"] = probe.disk_level(d)
        d["key"] = _disk_key(m["key"], d)
    for p in m.get("pools", []):
        p["level"], p["why"] = probe.pool_level(p, now.replace(tzinfo=None))
    levels = [d["level"] for d in m.get("disks", [])] + [p["level"] for p in m.get("pools", [])]
    if (m.get("throttle") or {}).get("now"):
        levels.append("warn")
    m["level"] = "err" if m.get("error") else max(levels, key=lambda x: RANK[x], default="ok")


def compare(db: AsyncSession, old: dict, m: dict, cfg: dict) -> None:
    """Meldingen voor wat er slechter werd sinds de vorige keer."""
    if m.get("error"):
        return
    name = m["name"]
    old_disks = {d.get("key"): d for d in old.get("disks", [])}
    for d in m.get("disks", []):
        label = f"{d.get('model') or d['dev']} ({d['dev']})"
        prev = old_disks.get(d["key"])
        if prev is None:
            # Nieuwe schijf (of eerste ronde): meteen melden als er al iets mis is.
            if d["level"] in ("warn", "err"):
                notify(db, f"{name}: schijf {label} — {', '.join(d['why'])}", level=d["level"], source="hardware")
            continue
        grew = [f"{COUNTERS[k]} {prev.get(k) or 0} → {d[k]}" for k in COUNTERS
                if d.get(k) is not None and d[k] > (prev.get(k) or 0)]
        worse = RANK[d["level"]] > RANK.get(prev.get("level"), 0)
        wear = [t for t in (80, 90, 95) if (d.get("wear_used") or 0) >= t > (prev.get("wear_used") or 0)]
        if grew or worse or wear:
            lines = grew + ([f"{d['wear_used']}% versleten"] if wear else []) + ([] if grew else d["why"])
            notify(db, f"{name}: schijf {label} gaat achteruit", "\n".join(lines) or None,
                   level="err" if d["level"] == "err" else "warn", source="hardware")
        t, ot = d.get("temp"), prev.get("temp")
        if t is not None and t >= cfg["disk_warn"] and (ot is None or ot < cfg["disk_warn"]):
            notify(db, f"{name}: schijf {label} is {t} °C", f"grens {cfg['disk_warn']} °C", level="warn",
                   source="hardware")
    old_pools = {p["name"]: p for p in old.get("pools", [])}
    for p in m.get("pools", []):
        prev = old_pools.get(p["name"])
        if (prev and RANK[p["level"]] > RANK.get(prev.get("level"), 0)) or (not prev and p["level"] == "err"):
            notify(db, f"{name}: ZFS-pool {p['name']} — {', '.join(p['why'])}", level=p["level"], source="hardware")
        if prev and prev.get("scrub_at") != p.get("scrub_at") and p.get("scrub_at"):
            event(db, "gezondheid", f"{name}: scrub van {p['name']} klaar",
                  f"{p.get('scrub_errors') or 0} fouten", level="ok" if not p.get("scrub_errors") else "err")
    cpu, ocpu = m.get("cpu_temp"), old.get("cpu_temp")
    if cpu is not None and cpu >= cfg["cpu_warn"] and (ocpu is None or ocpu < cfg["cpu_warn"]):
        notify(db, f"{name}: processor is {cpu:.0f} °C", f"grens {cfg['cpu_warn']} °C", level="warn", source="hardware")
    thr, othr = (m.get("throttle") or {}).get("now") or [], (old.get("throttle") or {}).get("now") or []
    if thr and set(thr) - set(othr):
        notify(db, f"{name}: {', '.join(thr)}",
               "Een Raspberry Pi met te lage spanning heeft een betere voeding nodig (5 V / 5 A voor een Pi 5).",
               level="warn", source="hardware")


def readings(m: dict, now: datetime) -> list[Reading]:
    out = []
    if m.get("cpu_temp") is not None:
        out.append(Reading(target=m["key"], sensor="cpu", ts=now, value=round(m["cpu_temp"], 1)))
    for d in m.get("disks", []):
        if d.get("temp") is not None:
            out.append(Reading(target=m["key"], sensor=f"disk:{d['key']}"[:80], ts=now, value=float(d["temp"])))
    return out


async def run_health(db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    if not await job_lock(db, STATE_KEY):
        # Loopt al (worker of knop): de vorige stand teruggeven.
        state = await db.get(AppState, STATE_KEY)
        return state.value if state else {}
    cfg = await settings(db)
    state = await db.get(AppState, STATE_KEY)
    old = {h["key"]: h for h in (state.value.get("hosts", []) if state else [])}
    machines = await collect(db)
    for m in machines:
        evaluate(m, now)
        prev = old.get(m["key"], {})
        # Slapende schijf: laatste bekende gegevens houden.
        if not m.get("error"):
            prev_disks = {d.get("key"): d for d in prev.get("disks", [])}
            for i, d in enumerate(m.get("disks", [])):
                if d.get("standby") and d["key"] in prev_disks:
                    m["disks"][i] = {**prev_disks[d["key"]], "standby": True}
        compare(db, prev, m, cfg)
        for r in readings(m, now):
            await db.merge(r)  # twee scans in dezelfde seconde (knop en worker) overschrijven elkaar
    await db.execute(delete(Reading).where(Reading.ts < now - KEEP_READINGS))
    value = {"checked_at": now.isoformat(), "hosts": machines}
    if state:
        state.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value
