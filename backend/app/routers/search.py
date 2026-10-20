"""Overal zoeken (Ctrl+K): notities, cronjobs, SSH-hosts, apparaten, configuratiebestanden en de laatste logregels.
Een IP- of MAC-adres zoekt ook op wat erbij hoort: welk apparaat, welke SSH-host en cronjobs, welke services en
welke NPM-hosts ernaar doorsturen.
"""

import ipaddress
import json
import re
import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import current_user
from ..models import ConfigVersion, CronJob, Device, LogEntry, Service, SshHost, User
from ..monitoring.configs import mask
from ..security import decrypt

router = APIRouter(prefix="/api", tags=["search"])

PER_GROUP = 6
LOG_HOURS = 24
_MAC = re.compile(r"^[0-9a-f]{2}([:-]?[0-9a-f]{2}){5}$", re.I)
# Gedecrypteerde configs kort bewaren: zoeken gebeurt per toetsaanslag.
_cache: dict[int, tuple[float, str]] = {}
CACHE_SECONDS = 120


def _like(word: str) -> str:
    return "%" + word.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _all(cols, words: list[str]):
    """Elk woord moet in minstens één van de kolommen staan."""
    return [or_(*[c.ilike(_like(w), escape="\\") for c in cols]) for w in words]


def _snippet(text: str, words: list[str], width: int = 140) -> str | None:
    """De eerste regel waarin alle woorden staan; een gewone regel gaat voor op een titel."""
    hits = []
    for raw in text.splitlines():
        line = raw.strip()
        low = line.lower()
        if all(w in low for w in words):
            hits.append((line.startswith("#"), line.lstrip("#>-* "), low))
    if not hits:
        return None
    _, line, low = min(hits, key=lambda h: h[0])
    start = max(0, line.lower().find(words[0]) - 40)
    return ("…" if start else "") + line[start:start + width]


def _norm_mac(q: str) -> str:
    h = re.sub(r"[^0-9a-f]", "", q.lower())
    return ":".join(h[i:i + 2] for i in range(0, 12, 2))


def _ip(q: str) -> str | None:
    try:
        return str(ipaddress.ip_address(q))
    except ValueError:
        return None


async def _configs(db: AsyncSession) -> list[ConfigVersion]:
    """Laatste versie per configuratie."""
    latest = (select(ConfigVersion.item, func.max(ConfigVersion.id).label("vid"))
              .group_by(ConfigVersion.item).subquery())
    return list((await db.execute(select(ConfigVersion).join(latest, ConfigVersion.id == latest.c.vid)
                                  .order_by(ConfigVersion.name))).scalars())


def _content(v: ConfigVersion) -> str:
    now = time.monotonic()
    hit = _cache.get(v.id)
    if hit and now - hit[0] < CACHE_SECONDS:
        return hit[1]
    for k in [k for k, (t, _) in _cache.items() if now - t > CACHE_SECONDS]:
        _cache.pop(k, None)
    body = mask(decrypt(v.content))
    _cache[v.id] = (now, body)
    return body


def _npm_to(versions: list[ConfigVersion], ip: str) -> list[dict]:
    """NPM-hosts die naar dit IP doorsturen (uit de laatste nachtelijke kopie van NPM)."""
    out = []
    for v in versions:
        if v.kind != "npm":
            continue
        try:
            data = json.loads(_content(v))
        except ValueError:
            continue
        for kind, hosts in data.items():
            for h in hosts if isinstance(hosts, list) else []:
                if isinstance(h, dict) and str(h.get("forward_host") or "").strip() == ip:
                    names = h.get("domain_names") or []
                    out.append({"title": ", ".join(names) or f"host {h.get('id')}",
                                "sub": f"{kind.replace('_', ' ')} → {ip}:{h.get('forward_port') or ''}".rstrip(":"),
                                "url": f"https://{names[0]}" if names else None})
    return out


@router.get("/search")
async def search(q: str = Query(min_length=2, max_length=100), user: User = Depends(current_user),
                 db: AsyncSession = Depends(get_db)):
    q = q.strip()
    words = [w.lower() for w in q.split()[:5]]
    if not words:
        return {"groups": [], "service_ids": []}
    ip = _ip(q)
    mac = _norm_mac(q) if _MAC.match(q) else None
    groups: list[dict] = []
    service_ids: set[int] = set()

    def group(kind: str, label: str, items: list[dict]) -> None:
        if items:
            groups.append({"kind": kind, "label": label, "items": items[:PER_GROUP], "more": max(0, len(items) - PER_GROUP)})

    # IP of MAC: eerst het apparaat, zodat een MAC ook zijn IP oplevert (en omgekeerd).
    devices: list[Device] = []
    if mac:
        devices = list((await db.execute(select(Device).where(Device.mac == mac))).scalars())
        ip = ip or next((d.ip for d in devices if d.ip), None)
    elif ip:
        devices = list((await db.execute(select(Device).where(Device.ip == ip))).scalars())
    if not devices:
        devices = list((await db.execute(select(Device).where(*_all(
            [Device.name, Device.hostname, Device.ip, Device.mac, Device.vendor, Device.note], words))
            .order_by(Device.name.is_(None), Device.name, Device.ip).limit(PER_GROUP + 10))).scalars())

    # SSH-hosts: bij een IP exact, anders op naam, adres en map.
    hcond = [SshHost.host == ip] if ip else _all([SshHost.name, SshHost.host, SshHost.folder], words)
    hosts = list((await db.execute(select(SshHost).where(*hcond).order_by(SshHost.folder, SshHost.name)
                                   .limit(PER_GROUP + 10))).scalars())

    # Services: een IP in de url, het checkdoel of de instellingen. (Naam en notities zoekt het dashboard zelf al.)
    if ip:
        for s in (await db.execute(select(Service.id, Service.url, Service.check, Service.config))).all():
            blob = f"{s.url or ''} {json.dumps(s.check or {})} {json.dumps(s.config or {})}"
            if re.search(rf"(?<![\d.]){re.escape(ip)}(?![\d])", blob):
                service_ids.add(s.id)
        for h in hosts:
            if h.service_id:
                service_ids.add(h.service_id)

    if ip or mac:
        what = []
        for d in devices:
            what.append({"kind": "device", "mac": d.mac, "title": d.name or d.hostname or d.mac,
                         "sub": " · ".join(x for x in (d.ip, d.mac, d.vendor, d.intf) if x)})
        for h in hosts:
            what.append({"kind": "host", "host_id": h.id, "title": h.name,
                         "sub": f"SSH {h.username}@{h.host}" + (f" · {h.folder}" if h.folder else "")})
        npm = _npm_to(await _configs(db), ip) if ip else []
        what += [{"kind": "npm", **n} for n in npm]
        if what:
            groups.append({"kind": "lookup", "label": f"wat is {ip or mac}", "items": what, "more": 0})
    else:
        group("device", "apparaten", [{"mac": d.mac, "title": d.name or d.hostname or d.mac,
                                        "sub": " · ".join(x for x in (d.ip, d.mac, d.vendor) if x)} for d in devices])
        group("host", "SSH-hosts", [{"host_id": h.id, "title": h.name,
                                     "sub": f"{h.username}@{h.host}" + (f" · {h.folder}" if h.folder else "")}
                                    for h in hosts])

    # Notities van services: met de regel waarin het staat.
    if not ip and not mac:
        rows = (await db.execute(select(Service.id, Service.name, Service.notes)
                                 .where(Service.notes.is_not(None), *_all([Service.notes], words))
                                 .order_by(Service.name).limit(PER_GROUP + 10))).all()
        group("note", "notities", [{"service_id": r.id, "title": r.name, "sub": _snippet(r.notes, words) or ""}
                                   for r in rows])

    # Cronjobs: op naam, commando, machine en schema; bij een IP alle jobs van die machine.
    ccond = ([CronJob.host_id.in_([h.id for h in hosts])] if ip and hosts else
             [CronJob.command.ilike(_like(ip), escape="\\")] if ip else
             _all([CronJob.name, CronJob.alias, CronJob.command, CronJob.target_name, CronJob.schedule], words))
    if not mac or hosts:
        jobs = list((await db.execute(select(CronJob).where(CronJob.removed_at.is_(None), *ccond)
                                      .order_by(CronJob.target_name, CronJob.name).limit(PER_GROUP + 20))).scalars())
        group("cron", "cronjobs", [{"job_id": j.id, "title": j.alias or j.name or j.command[:80],
                                    "sub": f"{j.target_name} · {j.schedule}" + (" · uit" if not j.enabled else ""),
                                    "status": j.last_status} for j in jobs])

    # Configuratiebestanden: op naam, en in de inhoud (gemaskeerd; eigen bestanden alleen op naam, want die
    # tonen vraagt een recente 2FA).
    if not mac:
        items = []
        for v in await _configs(db):
            if all(w in v.name.lower() for w in words):
                items.append({"item": v.item, "title": v.name, "sub": f"{v.kind} · {v.ts:%d/%m %H:%M}"})
            elif v.kind != "file":
                hit = _snippet(_content(v), words)
                if hit:
                    items.append({"item": v.item, "title": v.name, "sub": hit})
        group("config", "configuratie", items)

    # De laatste logregels.
    since = datetime.now(timezone.utc) - timedelta(hours=LOG_HOURS)
    lcond = [LogEntry.msg.ilike(_like(ip or mac or ""), escape="\\")] if ip or mac else _all([LogEntry.msg], words)
    try:
        if db.bind.dialect.name == "postgresql":
            # Een zeldzaam woord kan een dag aan logregels doorlopen: dan liever geen logregels dan een trage zoekbalk.
            await db.execute(text("SET LOCAL statement_timeout = '2s'"))
        logs = (await db.execute(select(LogEntry).where(LogEntry.ts >= since, *lcond)
                                 .order_by(LogEntry.ts.desc()).limit(PER_GROUP))).scalars().all()
    except DBAPIError:
        await db.rollback()
        logs = []
    group("log", f"logregels (laatste {LOG_HOURS} u)", [
        {"host": e.host, "title": e.msg[:200], "sub": f"{e.host}{' · ' + e.app if e.app else ''}", "ts": e.ts,
         "severity": e.severity} for e in logs])

    return {"groups": groups, "service_ids": sorted(service_ids), "ip": ip, "mac": mac}
