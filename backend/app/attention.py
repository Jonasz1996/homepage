"""Aandacht (knop ! in de titelbalk): alles wat nu je aandacht vraagt, op één plek en gesorteerd op ernst.

Leest alleen wat de worker al bijhoudt, geen trage API's, zodat het venster meteen opent. Elk punt zegt welk venster
het oplost (fix); de frontend maakt er een knop van. "Negeren" verbergt een punt tot het verandert (sig) of weg is.
"""

import hashlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from . import nieuweservice as ns
from .config import get_settings
from .health import domains as dom, scan as hw, security, selfcheck as sc, snapshots as snap
from .integrations import REGISTRY
from .integrations.zabbix import RED_FROM
from .models import AppState, CronJob, Device, MaintenanceWindow, Service, ServiceState, UpdateRun
from .monitoring import cluster, coverage, devices, planned, restoretest, rollup, updates as upd, zabbix as zbx
from .monitoring.engine import KEEP_CHECKS_DAYS, MASS_KEY, active
from .syslog import server as rxs

ACK_KEY = "attention_ack"
RANK = {"err": 0, "warn": 1, "info": 2}
# Bij gelijke ernst: wat het meeste stuk kan maken eerst.
AREAS = ("services", "checks", "back-ups", "cluster", "hardware", "opslag", "netwerk", "homepage", "zabbix", "cron", "updates",
         "certificaten", "domeinen", "integraties", "beveiliging", "apparaten", "snapshots", "onderhoud")
CERT_DAYS = 14
MAX_PER_AREA = 8
UPDATE_RUN_DAYS = 7
# Onderhoud met de hand (niet gepland) dat nog zo lang loopt, of voor zoveel services tegelijk: opvallen in "!".
# Onderhoud zet de meldingen en zelfherstel uit, ook van alles wat ervan afhangt.
MAINT_LONG = timedelta(hours=24)
MAINT_MANY = 10
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
    # Het moment van die test zelf: last_at schuift ook op bij een proef en bij het aanzetten.
    at = (last or {}).get("at") or rt.get("last_at")
    if last and not last.get("ok"):
        what = f"{last.get('name') or 'CT'} ({last.get('source_vmid') or '?'})"
        out.append(item("restoretest", "err", "back-ups", f"Hersteltest mislukt: {what}",
                        f"Bij {last.get('step')}: {last.get('error')}", {"window": "restoretest"}, sig=at, since=at))
    if last and last.get("cleanup_error"):
        out.append(item("restoretest:opruimen", "warn", "back-ups", f"Test-CT {last.get('vmid')} niet opgeruimd",
                        f"{last['cleanup_error']}. Verwijder hem zelf in Proxmox.", {"window": "restoretest"},
                        sig=at))
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


def _n(n: int) -> str:
    """1234 → 1.234"""
    return f"{n:,}".replace(",", ".")


LOSS_WHY = {
    rxs.FULL: f"De database was onbereikbaar en de wachtrij van de syslog-ontvanger ({_n(rxs.QUEUE_MAX)} regels) zat "
              "vol: nieuwe regels van apparaten die via UDP sturen (router, switch, NAS) vielen weg. Machines die via "
              "TCP sturen (rsyslog uitgerold vanuit het dashboard) houden hun regels dan zelf vast.",
    rxs.REJECTED: "De database weigerde ze (of ze waren onleesbaar); waarom staat in de logregels van de "
                  "syslog-ontvanger (diagnose).",
    rxs.STOPPED: "Bij het stoppen van de syslog-ontvanger (herstart of update) raakte de wachtrij niet op tijd leeg: "
                 "de database was onbereikbaar of traag.",
}


def syslog_items(rx: dict | None, fix: dict) -> list[dict]:
    """De syslog-ontvanger: draait hij, en raakten er logregels niet in de database? Oranje en zonder push: de
    logregels zelf zijn geen storing, en een herstart van PostgreSQL 's nachts is geen reden om iemand te wekken."""
    if rx is None:
        return []
    out = []
    if not rx["ok"]:
        out.append(item("syslog", "warn", "homepage", "De syslog-ontvanger draait niet",
                        f"{rx['why'][:1].upper()}{rx['why'][1:]}. Zonder ontvanger komen er geen logregels binnen en "
                        "werken de meldingsregels niet. Draait hij wel, dan kan hij misschien niet in de database "
                        "schrijven (schijf vol?). In de container: systemctl status homepage-syslog.", fix))
    loss = rx.get("loss")
    if loss:
        n = loss["n"]
        # Bij een volle wachtrij of een te trage stop was de database de oorzaak.
        err = (rx.get("last_error") or {}).get("error") if loss.get("why") in (rxs.FULL, rxs.STOPPED) else None
        out.append(item("syslog:verlies", "warn", "homepage", f"{_n(n)} logregel{'s' if n != 1 else ''} niet bewaard",
                        LOSS_WHY.get(loss.get("why"), "") + (f" Laatste fout van de database: {err}" if err else ""),
                        fix, sig=loss["since"], since=loss["since"]))
    return out


async def homepage(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    fix = {"window": "health", "tab": "homepage"}
    out = []
    worker = sc.worker_status(await _state(db, sc.HEARTBEAT_KEY), now)
    if not worker["ok"]:
        out.append(item("worker", "err", "homepage", "De worker van het dashboard draait niet",
                        f"Zonder worker geen checks, meldingen of back-ups: {worker['why']}. "
                        "In de container: systemctl status homepage-worker.", fix))
    hourly = await rollup.lag(db, now)
    # Draait de worker niet, dan zegt het punt hierboven al genoeg.
    if hourly["late"] and worker["ok"]:
        behind = timedelta(hours=hourly["behind_h"])
        left = KEEP_CHECKS_DAYS - behind.days
        loss = (f"Blijft dit zo, dan verdwijnen over {_days(left)} de eerste checks voor goed en krijgt de "
                "jaargrafiek een gat." if left > 0 else "Er verdwijnen nu al checks voor goed: de jaargrafiek krijgt "
                "een gat.")
        out.append(item("uurtotalen", "warn", "homepage",
                        f"De worker telt de checks al {ago(behind)} niet meer per uur op" if hourly["until"]
                        else "De worker telt de checks niet per uur op",
                        "De grafiek en de uptime over 7 dagen tot een jaar en het weekrapport halen die uren nu uit "
                        f"de losse checks. Met TimescaleDB worden losse checks na {KEEP_CHECKS_DAYS} dagen gewist, ook "
                        f"als ze nog niet opgeteld zijn. {loss} Zonder TimescaleDB wacht het opruimen, maar groeit de "
                        "database. In de container: journalctl -u homepage-worker | grep uurtotalen.", fix,
                        # Negeren geldt een week; daarna (of als het weer even lukte) komt het terug.
                        sig=f"{hourly['until']}|{behind.days // 7}"))
    out.extend(syslog_items(sc.syslog_status(await _state(db, rxs.STATE_KEY), now), fix))
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
                        str((s.get("verified") or {}).get("why") or ""), fix))
    out += _restore(s.get("restore") or {}, now, fix)
    off = s.get("offsite") or {}
    if off.get("enabled") and off.get("error"):
        out.append(item("offsite", "err", "homepage", "Kopie buiten de container mislukt", str(off["error"]), fix,
                        sig=off["error"]))
    if off.get("enabled") and off.get("key_stale"):
        out.append(item("offsite-sleutel", "err", "homepage", "De sleutel in de kopie buiten de container is verouderd",
                        sc.KEY_STALE, fix))
    if not (await hw.settings(db)).get("offsite"):
        # Geen kopie buiten de container: een voorstel. Oranje als er ook nergens een kopie van secret.key is (dan zijn
        # de geheimen in elke back-up onleesbaar als de container wegvalt), anders ter info.
        level = "info" if (await security.check_secret_key(db))["level"] == "ok" else "warn"
        out.append(item("offsite-voorstel", level, "homepage", "Back-up van het dashboard staat alleen in de container",
                        "Valt de container of zijn node weg, dan zijn de back-ups en secret.key mee weg"
                        + (", en zonder secret.key zijn de opgeslagen wachtwoorden en API-sleutels onleesbaar"
                           if level == "warn" else "")
                        + f". Koppel een NAS-share, PBS-opslag of USB-schijf op {get_settings().offsite_dir} en zet "
                        "de kopie buiten de container aan, met een wachtzin voor de sleutel. Zit deze CT al in een "
                        "back-up van PBS, dan staan de dumps en secret.key daar ook in en mag je dit negeren.", fix,
                        sig=level))
    disk = sc.disk_alert(s)
    if disk:
        pct = max((d.get("pct") or 0 for d in s.get("disks") or []), default=0)
        out.append(item("selfdisk", disk, "homepage", f"De schijf van de container is {pct:.0f}% vol",
                        sc.DISK_FULL if disk == "err" else
                        f"Boven {sc.DISK_WARN}% ruimt het dashboard zelf de oudste logregels op (de laatste 3 dagen "
                        "blijven). Helpt dat niet, ruim dan op of maak de schijf van de CT groter.", fix, sig=disk))
    return out


def _restore(r: dict, now: datetime, fix: dict) -> list[dict]:
    """De maandelijkse test van de back-up (terugzetten in een testdatabase): mislukt, overgeslagen, of al te lang
    niet gelukt (de timer loopt niet, of de test was er nog nooit)."""
    if r.get("status") == "fout":
        return [item("selfrestore", "err", "homepage", "De back-up van het dashboard lukt niet terug te zetten",
                     f"{r.get('dump') or 'De nieuwste dump'}: {r.get('why') or 'onbekende fout'}. " +
                     (f"Wat pg_restore schreef, staat in {sc.RESTORE_LOG} bij de back-ups. " if r.get("log") else "") +
                     f"Opnieuw proberen: {sc.RESTORE_RUN}.", fix,
                     sig=r.get("at"), since=r.get("at"))]
    since = r.get("last_ok") or r.get("missing_since")
    days = (now - _aware(datetime.fromisoformat(since))).days if since else 0
    if days > sc.RESTORE_STALE.days:
        skipped = f"De laatste keer overgeslagen: {r.get('why')}. " if r.get("status") == "overgeslagen" else ""
        return [item("selfrestore", "warn", "homepage",
                     f"De back-up van het dashboard is al {_days(days)} niet op een testdatabase teruggezet",
                     f"{skipped}Dat gebeurt elke 1e van de maand om 04:15 (homepage-backuptest.timer). Op de "
                     f"container: {sc.RESTORE_RUN}", fix, sig=since)]
    if r.get("status") == "overgeslagen":
        return [item("selfrestore", "warn", "homepage", "Test van de back-up van het dashboard overgeslagen",
                     str(r.get("why") or ""), fix, sig=r.get("at"))]
    return []


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
        # Genegeerd komt het alleen terug als er een echt nieuw onbekend apparaat bijkomt, niet als je er een als
        # gekend markeert of er een opgeruimd wordt (refresh houdt bij wanneer het laatste bijkwam).
        last_new = (await _state(db, devices.STATE_KEY)).get("last_new")
        out.append(item("devices", "warn", "apparaten", f"{len(new)} nieuw{'e' if len(new) != 1 else ''} "
                        f"{'apparaten' if len(new) != 1 else 'apparaat'} op je netwerk", names + (" …" if len(new) > 5 else "")
                        + ". Ken je ze? Geef ze een naam of markeer ze als gekend.",
                        {"window": "net", "tab": "apparaten"}, sig=f"nieuw sinds {last_new or '-'}"))
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
    plan: dict[int, datetime] = {}  # service → einde van het geplande venster dat nu loopt
    for w in (await db.execute(select(MaintenanceWindow).where(MaintenanceWindow.enabled.is_(True)))).scalars():
        span = planned.active(w, now)
        if span:
            out.append(item(f"maint:{w.id}", "info", "onderhoud", f"Onderhoud bezig: {w.name}",
                            f"Tot {span[1].astimezone().strftime('%H:%M')}; meldingen staan zolang uit.",
                            {"window": "planned"}, sig=span[0].isoformat()))
            for s in await planned.targets(db, w):
                plan[s.id] = max(plan.get(s.id, span[1]), span[1])
    return out + adhoc_maintenance(list((await db.execute(select(Service).where(
        Service.maintenance_until > now))).scalars()), plan, now)


def adhoc_maintenance(svcs: list[Service], plan: dict[int, datetime], now: datetime) -> list[dict]:
    """Onderhoud met de hand (de knoppen in de tegel of bij de groep) dat nog meer dan een dag loopt, of voor veel
    services tegelijk. Wat een gepland venster zette, staat al hierboven. Zo valt een week onderhoud op honderd tegels
    op, ook als niemand naar de tegels kijkt. De knop opent de tegel: daar staat "onderhoud stoppen"."""
    def until(s: Service) -> datetime:
        return _aware(s.maintenance_until)

    hand = sorted((s for s in svcs if until(s) > now and not (s.id in plan and until(s) <= plan[s.id])),
                  key=lambda s: (until(s), s.name.lower()))
    if len(hand) > MAINT_MANY:
        last = hand[-1]
        names = ", ".join(s.name for s in hand[:5]) + f" en {len(hand) - 5} meer"
        return [item("maint:veel", "warn", "onderhoud", f"{len(hand)} services in onderhoud",
                     f"Met de hand, tot uiterlijk {until(last).astimezone().strftime('%d/%m %H:%M')}: {names}. Zolang "
                     "komen er geen meldingen over, en zelfherstel staat uit. Stoppen: in de tegel, of met ⏸ bij de "
                     "groep (0 minuten).", {"window": "detail", "service_id": last.id},
                     sig=f"{len(hand)}:{until(last).isoformat()}")]
    # Per tegel, of per groep die samen in onderhoud ging (zelfde einde).
    long: dict[tuple, list[Service]] = {}
    for s in hand:
        if until(s) - now > MAINT_LONG:
            long.setdefault((s.group_id, until(s)), []).append(s)
    out = []
    for (_, end), ss in long.items():
        what = ss[0].name if len(ss) == 1 else (f"{len(ss)} services ({', '.join(s.name for s in ss[:4])}"
                                                + (" …)" if len(ss) > 4 else ")"))
        out.append(item(f"maint:hand:{ss[0].id}", "warn", "onderhoud",
                        f"{what} in onderhoud tot {end.astimezone().strftime('%d/%m %H:%M')}",
                        f"Nog {ago(end - now)}, met de hand gezet. Zolang komen er geen meldingen over, ook niet over "
                        "wat ervan afhangt, en zelfherstel staat uit.",
                        {"window": "detail", "service_id": ss[0].id}, sig=end.isoformat()))
    return out


async def new_services(db: AsyncSession, now: datetime, ctx: dict) -> list[dict]:
    """Een nieuwe service (of opruimen) die halverwege stopte: wat al gemaakt of weg is, blijft zo tot je het ongedaan
    maakt of afwerkt. Een run die niets achterliet, staat alleen in de geschiedenis."""
    out = []
    for raw in ns.runs_of(await _state(db, ns.STATE_KEY)):
        r = ns.effective(raw)
        if r.get("status") not in ("gestopt", "onderbroken") or r.get("undone_by"):
            continue
        steps = r.get("steps") or []
        if not (r.get("created") or r.get("removed") or any(s.get("status") == "onbekend" for s in steps)):
            continue
        nr = next((s.get("nr") for s in steps if s.get("status") in ("fout", "onbekend")), "?")
        fqdn = r.get("fqdn") or "?"
        if r.get("kind") == "maken":
            title, rest = f"Nieuwe service {fqdn} half gemaakt", f"Al gemaakt: {ns._labels(r.get('created') or [])}."
        else:
            what = "Opruimen van" if r.get("kind") == "opruimen" else "Ongedaan maken van"
            title, rest = f"{what} {fqdn} gestopt", f"Al verwijderd: {ns._labels(r.get('removed') or [])}."
        out.append(item(f"ns:{r['id']}", "warn", "services", title, f"Gestopt bij stap {nr}: {r.get('error')}. {rest}",
                        {"window": "nieuweservice", "tab": "geschiedenis"}, sig=r["status"], since=r.get("updated_at")))
    return out


def integrations(errors: dict[int, str], ctx: dict) -> list[dict]:
    names, down = ctx.get("names") or {}, ctx.get("down") or set()
    out = [item(f"api:{sid}", "warn", "integraties", f"{names[sid]}: de API geeft een fout", err,
                {"window": "detail", "service_id": sid}, sig=err)
           for sid, err in sorted(errors.items(), key=lambda x: names.get(x[0], "").lower())
           if sid in (ctx.get("integrated") or set()) and sid not in down]
    return _cap(out, "integraties", "Nog {n} tegels waarvan de API een fout geeft", {"window": "api"})


SOURCES = (services, backups, clusters, hardware, capacity, network, homepage, zabbix, cron_jobs, updates, safety,
           maintenance, new_services)


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
