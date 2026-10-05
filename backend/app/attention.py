"""Aandacht (knop ! in de titelbalk): alles wat nu je aandacht vraagt, op één plek en gesorteerd op ernst.

Leest alleen wat de worker al bijhoudt, geen trage API's, zodat het venster meteen opent. Elk punt zegt welk venster
het oplost (fix); de frontend maakt er een knop van. "Negeren" verbergt een punt tot het verandert (sig) of weg is.
"""

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .health import domains as dom, scan as hw, security, selfcheck as sc, snapshots as snap
from .integrations import REGISTRY
from .integrations.zabbix import RED_FROM
from .models import AppState, CronJob, Device, MaintenanceWindow, Service, ServiceState, UpdateRun
from .monitoring import cluster, coverage, planned, restoretest, updates as upd, zabbix as zbx
from .monitoring.engine import MASS_KEY, active

ACK_KEY = "attention_ack"
RANK = {"err": 0, "warn": 1, "info": 2}
# Bij gelijke ernst: wat het meeste stuk kan maken eerst.
AREAS = ("services", "checks", "back-ups", "cluster", "hardware", "opslag", "netwerk", "homepage", "zabbix", "cron", "updates",
         "certificaten", "domeinen", "integraties", "beveiliging", "apparaten", "snapshots", "onderhoud")
CERT_DAYS = 14
MAX_PER_AREA = 8
UPDATE_RUN_DAYS = 7
PBS_KINDS = {"task": "laatste back-up mislukt", "verify": "verify mislukt", "late": "geen back-up in meer dan 26 uur"}
RUN_BAD = {"fout": "mislukt", "services_down": "zette services down", "terugdraaien_mislukt": "terugdraaien mislukt"}


def _aware(dt: datetime | None) -> datetime | None:
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc) if dt else None


def _days(n: int) -> str:
    return f"{n} dag{'en' if n != 1 else ''}"


def ago(delta: timedelta) -> str:
    m = int(delta.total_seconds() // 60)
    if m < 60:
        return f"{max(m, 1)} min"
    if m < 48 * 60:
        return f"{m // 60} uur"
    return _days(m // 1440)


def item(key: str, level: str, area: str, title: str, text: str = "", fix: dict | None = None, sig=None,
         since: datetime | str | None = None) -> dict:
    """sig: wat er moet veranderen voor een genegeerd punt terugkomt (standaard de titel)."""
    raw = f"{level}|{title if sig is None else sig}"
    return {"key": key, "level": level, "area": area, "title": title, "text": text, "fix": fix,
            "sig": hashlib.sha1(raw.encode()).hexdigest()[:12],
            "since": since.isoformat() if isinstance(since, datetime) else since}


async def _state(db: AsyncSession, key: str) -> dict:
    st = await db.get(AppState, key)
    return dict(st.value or {}) if st else {}


def _cap(items: list[dict], area: str, title: str, fix: dict | None, key: str | None = None) -> list[dict]:
    """Heel veel punten van één soort: de eerste tonen en de rest samenvatten."""
    if len(items) <= MAX_PER_AREA:
        return items
    rest = items[MAX_PER_AREA - 1:]
    level = min((i["level"] for i in rest), key=RANK.__getitem__)
    names = ", ".join(i["title"] for i in rest[:4]) + (" …" if len(rest) > 4 else "")
    return items[:MAX_PER_AREA - 1] + [item(f"{key or area}:meer", level, area, title.format(n=len(rest)), names, fix,
                                            sig=len(rest))]


async def services(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    """Services die down zijn (niet in onderhoud), gegroepeerd onder de verste ouder die ook down is. Ook checks die
    niet meer lopen, en (ter info) gepauzeerde checks, zodat je die niet vergeet."""
    svcs = {s.id: s for s in (await db.execute(select(Service))).scalars()}
    states = {s.service_id: s for s in (await db.execute(select(ServiceState))).scalars()
              if s.service_id in svcs and active(svcs[s.service_id].check)}
    ctx["names"] = {i: s.name for i, s in svcs.items()}
    ctx["integrated"] = {i for i, s in svcs.items() if s.type in REGISTRY or s.api_id}

    def chain(sid: int):
        seen, p = {sid}, svcs[sid].parent_id
        while p and p not in seen and p in svcs:
            seen.add(p)
            yield p
            p = svcs[p].parent_id

    def maint(sid: int) -> bool:
        return any((_aware(svcs[x].maintenance_until) or now) > now for x in [sid, *chain(sid)])

    down = {sid for sid, st in states.items() if st.status == "down" and not maint(sid)}
    ctx["down"] = down
    under: dict[int, list[str]] = {}
    roots = []
    for sid in sorted(down, key=lambda i: svcs[i].name.lower()):
        cause = None
        for a in chain(sid):
            if a in down:
                cause = a
        if cause:
            under.setdefault(cause, []).append(svcs[sid].name)
        else:
            roots.append(sid)
    out = []
    for sid in roots:
        st = states[sid]
        since = _aware(st.since)
        text = f"{st.last_error or 'reageert niet'} · al {ago(now - since)}"
        kids = under.get(sid, [])
        if kids:
            text += f". Ook down: {', '.join(kids[:5])}" + (f" en {len(kids) - 5} meer" if len(kids) > 5 else "")
        out.append(item(f"down:{sid}", "err", "services", f"{svcs[sid].name} is down", text,
                        {"window": "detail", "service_id": sid}, sig=f"down:{since.isoformat()}", since=since))
    stale = [item(f"stale:{sid}", "warn", "checks", f"De check van {svcs[sid].name} loopt niet meer",
                  "Er kwam geen resultaat meer binnen; de tegel staat op grijs. Kijk in hw naar de worker of op de "
                  "container: journalctl -u homepage-worker -n 50", {"window": "detail", "service_id": sid},
                  sig=f"stale:{_aware(st.last_check).isoformat() if st.last_check else ''}",
                  since=_aware(st.last_check))
             for sid, st in sorted(states.items(), key=lambda x: svcs[x[0]].name.lower())
             if st.stale and not maint(sid)]
    paused = [item(f"paused:{i}", "info", "checks", f"Check van {s.name} staat gepauzeerd",
                   "Zolang hij gepauzeerd is, merkt het dashboard niet als dit uitvalt.",
                   {"window": "detail", "service_id": i})
              for i, s in sorted(svcs.items(), key=lambda x: x[1].name.lower())
              if (s.check or {}).get("type") and (s.check or {}).get("paused")]
    certs = []
    for sid, st in states.items():
        exp = _aware(st.cert_expires_at)
        if not exp or maint(sid) or sid in down or svcs[sid].check.get("cert_notify") is False:
            continue
        days = (exp - now).total_seconds() / 86400
        if days > CERT_DAYS:
            continue
        level = "err" if days <= 3 else "warn"
        when = "is verlopen" if days < 0 else f"verloopt over {_days(int(days))}" if days >= 1 else "verloopt vandaag"
        certs.append(item(f"cert:{sid}", level, "certificaten", f"Certificaat van {svcs[sid].name} {when}",
                          f"Geldig tot {exp.astimezone().strftime('%d/%m/%Y %H:%M')}. NPM vernieuwt normaal 30 dagen op "
                          "voorhand: kijk in NPM waarom dat niet lukte.", {"window": "detail", "service_id": sid},
                          sig=level))
    return (_cap(out, "services", "Nog {n} services down", None)
            + _cap(stale, "checks", "Nog {n} checks lopen niet", None, key="stale")
            + _cap(paused, "checks", "Nog {n} checks gepauzeerd", None, key="paused") + certs)


async def cron_jobs(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    rows = (await db.execute(select(CronJob).where(
        CronJob.removed_at.is_(None), CronJob.system.is_(False), CronJob.muted.is_(False),
        CronJob.last_status.in_(("fout", "gemist"))).order_by(CronJob.last_status, CronJob.target_name))).scalars()
    out = []
    for j in rows:
        last = _aware(j.last_run_at)
        if j.last_status == "fout":
            text = f"Exitcode {j.last_exit}" if j.last_exit is not None else "Mislukt"
            text += f", {ago(now - last)} geleden" if last else ""
        else:
            text = "Liep niet op het geplande moment" + (f"; laatst {ago(now - last)} geleden" if last else "")
        out.append(item(f"cron:{j.id}", "err" if j.last_status == "fout" else "warn", "cron",
                        f"{j.alias or j.name} op {j.target_name}: {'mislukt' if j.last_status == 'fout' else 'niet gelopen'}",
                        text, {"window": "cron", "job": j.id}, sig=f"{j.last_status}:{last}", since=last))
    return _cap(out, "cron", "Nog {n} cronjobs met een probleem", {"window": "cron", "filter": "probleem"})


async def backups(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    out = []
    for svc in (await db.execute(select(Service).where(Service.type == "proxmoxbackupserver"))).scalars():
        st = await _state(db, f"pbs_problems:{svc.id}")
        probs = st.get("items") or {}
        for k in st.get("keys") or []:
            if k not in probs:  # oudere stand zonder teksten
                store, _, rest = k.partition(":")
                group, _, kind = rest.rpartition(":")
                probs[k] = f"{store}:{group}: {PBS_KINDS.get(kind, kind)}"
        if not probs:
            continue
        bad = any(not k.endswith(":late") for k in probs)
        lines = [probs[k] for k in sorted(probs)]
        out.append(item(f"pbs:{svc.id}", "err" if bad else "warn", "back-ups",
                        f"{svc.name}: {len(lines)} back-up{'s' if len(lines) != 1 else ''} met een probleem",
                        "; ".join(lines[:4]) + (f" en {len(lines) - 4} meer" if len(lines) > 4 else ""),
                        {"window": "detail", "service_id": svc.id}, sig=",".join(sorted(probs))))
    rt = await _state(db, restoretest.STATE_KEY)
    last = (rt.get("history") or [None])[0]
    if last and not last.get("ok"):
        what = f"{last.get('name') or 'CT'} ({last.get('source_vmid') or '?'})"
        out.append(item("restoretest", "err", "back-ups", f"Hersteltest mislukt: {what}",
                        f"Bij {last.get('step')}: {last.get('error')}", {"window": "restoretest"}, sig=rt.get("last_at"),
                        since=rt.get("last_at")))
    if last and last.get("cleanup_error"):
        out.append(item("restoretest:opruimen", "warn", "back-ups", f"Test-CT {last.get('vmid')} niet opgeruimd",
                        f"{last['cleanup_error']}. Verwijder hem zelf in Proxmox.", {"window": "restoretest"},
                        sig=rt.get("last_at")))
    return out + await backup_coverage(db)


async def backup_coverage(db: AsyncSession) -> list[dict]:
    """Per VM/CT zonder back-up of buiten elke job een punt; wie maar op één PBS staat, samen in één punt."""
    out, single = [], []
    fix = {"window": "health", "tab": "backups"}
    for c in (await _state(db, coverage.STATE_KEY)).get("clusters") or []:
        for r in c["rows"]:
            if r["level"] == "ok":
                continue
            if r["level"] == "warn" and r["pbs_count"] == 1 and r["jobs"]:
                single.append(r)
                continue
            what = f"{r['name']} ({r['type'].upper()} {r['vmid']})"
            out.append(item(f"cov:{r['vmid']}", r["level"], "back-ups", f"{what} {r['why']}",
                            "Staat uit, daarom niet rood." if r["stopped"] and r["level"] == "warn" else "", fix,
                            sig=r["why"]))
    if single:
        where = sorted({r["copies"][0]["pbs"] for r in single})
        what = "VM/CT's" if len(single) != 1 else "VM/CT"
        out.append(item("cov:single", "warn", "back-ups", f"{len(single)} {what} maar op één PBS",
                        f"Alleen op {', '.join(where)}. Een sync tussen je twee PBS'en zet ze in één keer dubbel.", fix,
                        sig=str(len(single))))
    return out


async def updates(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    out = []
    u = await _state(db, upd.KEY)
    targets = [t for t in u.get("targets") or [] if not t.get("error")]
    sec = [t for t in targets if t.get("security")]
    total = sum(t.get("count") or 0 for t in targets)
    if sec:
        n = sum(t["security"] for t in sec)
        out.append(item("updates", "warn", "updates", f"{n} beveiligingsupdate{'s' if n != 1 else ''} op "
                        f"{len(sec)} machine{'s' if len(sec) != 1 else ''}",
                        ", ".join(f"{t['name']} ({t['security']})" for t in sec[:6]) + (" …" if len(sec) > 6 else ""),
                        {"window": "updates"}, sig="security"))
    elif total:
        busy = [t for t in targets if t.get("count")]
        out.append(item("updates", "info", "updates", f"{total} update{'s' if total != 1 else ''} op "
                        f"{len(busy)} machine{'s' if len(busy) != 1 else ''}",
                        ", ".join(f"{t['name']} ({t['count']})" for t in busy[:6]) + (" …" if len(busy) > 6 else ""),
                        {"window": "updates"}, sig="updates"))
    runs = (await db.execute(select(UpdateRun).where(UpdateRun.created_at >= now - timedelta(days=UPDATE_RUN_DAYS))
                             .order_by(UpdateRun.created_at.desc()))).scalars()
    latest: dict[str, UpdateRun] = {}
    for r in runs:
        latest.setdefault(r.target, r)
    for r in latest.values():
        if r.status in RUN_BAD:
            out.append(item(f"update:{r.target}", "err", "updates", f"Update op {r.target_name} {RUN_BAD[r.status]}",
                            (r.error or "").strip().splitlines()[-1][:200] if r.error else "Bekijk de uitvoer in apt.",
                            {"window": "updates"}, sig=r.id, since=_aware(r.finished_at or r.created_at)))
        elif r.status == "ok" and r.reboot_needed:
            out.append(item(f"reboot:{r.target}", "info", "updates", f"{r.target_name} moet herstarten",
                            "Na de laatste updates (bv. een nieuwe kernel).", {"window": "updates"}, sig=r.id))
    return out


async def hardware(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    cfg = await hw.settings(db)
    out = []
    fix = {"window": "health", "tab": "schijven"}
    for h in (await _state(db, hw.STATE_KEY)).get("hosts") or []:
        name = h.get("name") or "?"
        if h.get("error"):
            out.append(item(f"hw:{h.get('key')}", "warn", "hardware", f"Hardwarecheck van {name} lukt niet",
                            str(h["error"]), fix, sig=h["error"]))
            continue
        for d in h.get("disks") or []:
            if d.get("level") in ("warn", "err"):
                why = ", ".join(d.get("why") or [])
                out.append(item(f"disk:{h.get('key')}:{d.get('dev')}", d["level"], "hardware",
                                f"{name}: schijf {d.get('model') or d.get('dev')}", why, fix, sig=why))
        for p in h.get("pools") or []:
            if p.get("level") in ("warn", "err"):
                why = ", ".join(p.get("why") or [])
                out.append(item(f"pool:{h.get('key')}:{p.get('name')}", p["level"], "hardware",
                                f"{name}: ZFS-pool {p.get('name')}", why, fix, sig=why))
        if (h.get("throttle") or {}).get("now"):
            out.append(item(f"throttle:{h.get('key')}", "warn", "hardware", f"{name} wordt afgeremd",
                            ", ".join(h["throttle"]["now"]), {"window": "health", "tab": "temperatuur"}))
        if h.get("cpu_temp") is not None and h["cpu_temp"] >= cfg["cpu_warn"]:
            out.append(item(f"hot:{h.get('key')}", "warn", "hardware", f"{name}: CPU {h['cpu_temp']:.0f} °C",
                            f"Boven je grens van {cfg['cpu_warn']} °C.", {"window": "health", "tab": "temperatuur"},
                            sig="hot"))
    old = [s for s in (await _state(db, snap.STATE_KEY)).get("items") or [] if (s.get("age_days") or 0) >= cfg["snapshot_days"]]
    if old:
        out.append(item("snapshots", "info", "snapshots", f"{len(old)} snapshot{'s' if len(old) != 1 else ''} ouder dan "
                        f"{_days(cfg['snapshot_days'])}",
                        ", ".join(f"{s.get('vmid')}/{s.get('name')} ({int(s['age_days'])} d)" for s in old[:4])
                        + (" …" if len(old) > 4 else ""), {"window": "health", "tab": "snapshots"}, sig=len(old)))
    for d in (await _state(db, dom.STATE_KEY)).get("items") or []:
        dl = d.get("days_left")
        if dl is None or dl > 30:
            continue
        level = "err" if dl <= 7 else "warn"
        out.append(item(f"domain:{d['name']}", level, "domeinen",
                        f"Domein {d['name']} {'is verlopen' if dl < 0 else f'verloopt over {_days(dl)}'}",
                        f"Vervaldatum {d.get('expires')}" + (f" bij {d['registrar']}" if d.get("registrar") else ""),
                        {"window": "health", "tab": "domeinen"}, sig=level))
    return _cap(out, "hardware", "Nog {n} hardwarepunten", fix)


async def homepage(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    fix = {"window": "health", "tab": "homepage"}
    out = []
    worker = sc.worker_status(await _state(db, sc.HEARTBEAT_KEY), now)
    if not worker["ok"]:
        out.append(item("worker", "err", "homepage", "De worker van het dashboard draait niet",
                        f"Zonder worker geen checks, meldingen of back-ups: {worker['why']}. "
                        "In de container: systemctl status homepage-worker.", fix))
    mass = await _state(db, MASS_KEY)
    if mass.get("since"):
        since = _aware(datetime.fromisoformat(mass["since"]))
        out.append(item("massastoring", "err", "homepage", "Het dashboard bereikt bijna niets",
                        f"Begon met {mass.get('failing')} van de {mass.get('total')} checks tegelijk mislukt, "
                        f"{ago(now - since)} geleden. Zolang dit duurt, komt er geen melding per service. Het stopt "
                        "vanzelf als minder dan 30% van de checks nog faalt.", {"window": "health", "tab": "homepage"},
                        sig=mass["since"], since=since))
    s = await _state(db, sc.STATE_KEY)
    if s.get("stale"):
        out.append(item("selfbackup", "err", "homepage", "Geen recente back-up van het dashboard",
                        "De nachtelijke kopie van de database ontbreekt.", fix))
    if (s.get("verified") or {}).get("ok") is False:
        out.append(item("selfverify", "err", "homepage", "De laatste back-up van het dashboard is onleesbaar",
                        str((s.get("verified") or {}).get("error") or ""), fix))
    off = s.get("offsite") or {}
    if off.get("enabled") and off.get("error"):
        out.append(item("offsite", "err", "homepage", "Kopie buiten de container mislukt", str(off["error"]), fix,
                        sig=off["error"]))
    if (s.get("alerts") or {}).get("disk"):
        out.append(item("selfdisk", "err", "homepage", "De schijf van de container is bijna vol",
                        "Ruim op of maak de schijf van de CT groter.", fix))
    return out


async def clusters(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    alerts = (await _state(db, cluster.STATE_KEY)).get("alerts") or {}
    return [item(f"cluster:{k}", a["level"], "cluster", a["text"], "", {"window": "health", "tab": "cluster"})
            for k, a in alerts.items()]


async def capacity(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    out = []
    names = ctx.get("names") or {}
    for st in (await db.execute(select(AppState).where(AppState.key.like("disk_full:%")))).scalars():
        sid, _, name = st.key.removeprefix("disk_full:").partition(":")
        days = (st.value or {}).get("level")
        if days is None:
            continue
        where = names.get(int(sid)) if sid.isdigit() else None
        out.append(item(f"full:{sid}:{name}", "err" if days <= 3 else "warn", "opslag",
                        f"{name} vol binnen {_days(days)}", f"Op {where}." if where else "", {"window": "capacity"}))
    return out


async def network(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    out = []
    fix = {"window": "net", "tab": "internet"}
    for st in (await db.execute(select(AppState).where(AppState.key.like("net_gw:%")))).scalars():
        v = st.value or {}
        if v.get("error"):
            out.append(item(st.key, "warn", "netwerk", "Gateways in OPNsense niet leesbaar", str(v["error"]), fix,
                            sig=v["error"]))
        for g in v.get("items") or []:
            if g.get("level") in ("warn", "err"):
                extra = [f"{g['loss_pct']:.0f}% verlies" if g.get("loss_pct") else "",
                         f"{g['delay_ms']:.0f} ms" if g.get("delay_ms") else ""]
                out.append(item(f"{st.key}:{g['name']}", g["level"], "netwerk",
                                f"{g['name']}: {'down' if g['level'] == 'err' else 'problemen'}",
                                ", ".join(x for x in [g.get("label") or "", *extra] if x), fix))
    for st in (await db.execute(select(AppState).where(AppState.key.like("net_tunnel:%")))).scalars():
        v = st.value or {}
        if v.get("error"):
            out.append(item(st.key, "warn", "netwerk", "Cloudflare-tunnels niet leesbaar", str(v["error"]), fix,
                            sig=v["error"]))
        for t in v.get("items") or []:
            if t.get("status") not in (None, "healthy"):
                level = "err" if t["status"] in ("down", "inactive") else "warn"
                out.append(item(f"{st.key}:{t['name']}", level, "netwerk", f"Tunnel {t['name']}: {t['status']}",
                                "Van buitenaf zijn je services misschien niet bereikbaar.", fix))
    new = list((await db.execute(select(Device).where(Device.known.is_(False)).order_by(Device.first_seen))).scalars())
    if new:
        names = ", ".join(d.name or d.hostname or d.vendor or d.ip or d.mac for d in new[:5])
        out.append(item("devices", "warn", "apparaten", f"{len(new)} nieuw{'e' if len(new) != 1 else ''} "
                        f"{'apparaten' if len(new) != 1 else 'apparaat'} op je netwerk", names + (" …" if len(new) > 5 else "")
                        + ". Ken je ze? Geef ze een naam of markeer ze als gekend.",
                        {"window": "net", "tab": "apparaten"}, sig=",".join(sorted(d.mac for d in new))))
    return out


async def zabbix(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    z = await _state(db, zbx.STATE_KEY)
    if not z:
        return []
    out = []
    if z.get("error"):
        out.append(item("zabbix", "warn", "zabbix", "Zabbix niet bereikbaar", str(z["error"]),
                        {"window": "detail", "service_id": z.get("service_id")}, sig=z["error"]))
    tile: dict[str, int] = {}
    for sid, rows in (z.get("map") or {}).items():
        for r in rows:
            if r.get("role") == "eigen" or r["id"] not in tile:
                tile[r["id"]] = int(sid)
    probs: dict[str, list[dict]] = {}
    for p in z.get("problems") or []:
        if p.get("severity", 0) >= RED_FROM:
            probs.setdefault(p["host_id"], []).append(p)
    down = ctx.get("down") or set()
    for h in z.get("hosts") or []:
        ps = probs.get(h["id"], [])
        sid = tile.get(h["id"])
        if not (h.get("down") or ps) or sid in down:
            continue  # een tegel die al down is, staat er al
        fix = {"window": "detail", "service_id": sid or z.get("service_id")}
        if h.get("down"):
            out.append(item(f"zbx:{h['id']}", "err", "zabbix", f"Zabbix: {h['name']} onbereikbaar",
                            "Zabbix krijgt geen gegevens meer van deze host.", fix))
        else:
            out.append(item(f"zbx:{h['id']}", "err", "zabbix", f"Zabbix: {h['name']}",
                            "; ".join(p["name"] for p in ps[:3]) + (f" en {len(ps) - 3} meer" if len(ps) > 3 else ""),
                            fix, sig=",".join(sorted(p["name"] for p in ps))))
    return _cap(out, "zabbix", "Nog {n} hosts met problemen in Zabbix", None)


async def safety(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    out = []
    for c in (await security.check_sessions(db), await security.check_outside(db)):
        if c["level"] in ("warn", "err"):
            out.append(item(f"sec:{c['key']}", c["level"], "beveiliging", c["title"], c["text"], c["fix"],
                            sig=len(c["items"]) if c["key"] == "sessions" else c["text"]))
    return out


async def maintenance(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    out = []
    for w in (await db.execute(select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True)))).scalars():
        span = planned.active(w, now)
        if span:
            out.append(item(f"maint:{w.id}", "info", "onderhoud", f"Onderhoud bezig: {w.name}",
                            f"Tot {span[1].astimezone().strftime('%H:%M')}; meldingen staan zolang uit.",
                            {"window": "planned"}, sig=span[0].isoformat()))
    return out


def integrations(errors: dict[int, str], ctx: dict) -> list[dict]:
    names, down = ctx.get("names") or {}, ctx.get("down") or set()
    out = [item(f"api:{sid}", "warn", "integraties", f"{names[sid]}: de API geeft een fout", err,
                {"window": "detail", "service_id": sid}, sig=err)
           for sid, err in sorted(errors.items(), key=lambda x: names.get(x[0], "").lower())
           if sid in (ctx.get("integrated") or set()) and sid not in down]
    return _cap(out, "integraties", "Nog {n} tegels waarvan de API een fout geeft", {"window": "api"})


SOURCES = (services, backups, clusters, hardware, capacity, network, homepage, zabbix, cron_jobs, updates, safety,
           maintenance)


async def collect(db: AsyncSession, errors: dict[int, str] | None = None) -> dict:
    """{items, ignored, counts, stale}: stale zijn genegeerde punten die er niet meer zijn (de router ruimt ze op)."""
    now = datetime.now(timezone.utc)
    ctx: dict = {}
    items: list[dict] = []
    for fn in SOURCES:
        items += await fn(db, now, ctx)
    items += integrations(errors or {}, ctx)
    items.sort(key=lambda i: (RANK[i["level"]], AREAS.index(i["area"]), i["title"].lower()))
    acks = (await _state(db, ACK_KEY)).get("items") or {}
    shown, hidden = [], []
    for i in items:
        a = acks.get(i["key"])
        if a and a.get("sig") == i["sig"]:
            hidden.append({**i, "ignored_at": a.get("at")})
        else:
            shown.append(i)
    keys = {i["key"] for i in items}
    counts = {lv: sum(1 for i in shown if i["level"] == lv) for lv in RANK}
    return {"items": shown, "ignored": hidden, "counts": counts, "at": now.isoformat(),
            "stale": [k for k in acks if k not in keys]}
