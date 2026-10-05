"""Zabbix bij elke tegel: welke Zabbix-hosts horen bij een service, en staan die groen of rood.

Elke minuut haalt de worker de hosts en open problemen op uit de eerste Zabbix (een tegel of API van soort zabbix)
en koppelt ze aan de services. Een service krijgt:
- zijn eigen hosts: met hetzelfde IP of dezelfde DNS-naam als de url of het checkdoel (een domein achter NPM via het
  doorstuuradres uit de nachtelijke kopie van NPM), of met dezelfde naam als de tegel of de eerste naam van de url;
- de hosts van de node waarop hij draait: de map van de SSH-host met dat IP (⟳ pve zet daar de node), en wat
  "draait op" (parent) aan hosts heeft.
Met "zabbix" in de instellingen van de tegel kies je zelf ("pve50, plex"), of zet je het uit ("-").
Rood = een host is onbereikbaar of heeft een probleem van ernst "gemiddeld" of hoger.
"""

import ipaddress
import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..integrations import IntegrationError, build
from ..integrations.zabbix import RED_FROM
from ..models import Service, SshHost
from .checks import HttpClients

log = logging.getLogger("homepage.zabbix")

STATE_KEY = "zabbix"
EVERY = 60


def norm(text: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def host_of(value: str | None) -> str | None:
    if not value:
        return None
    v = value if "//" in value else f"x://{value}"
    try:
        return (urlsplit(v).hostname or "").lower() or None
    except ValueError:
        return None


def is_ip(h: str | None) -> bool:
    try:
        ipaddress.ip_address(h or "")
        return True
    except ValueError:
        return False


def zabbix_service(services: list[Service]) -> Service | None:
    return next((s for s in services if s.type == "zabbix"), None)


def assign(services: list[Service], hosts: list[dict], npm: dict[str, str], ssh: list[SshHost]) -> dict[int, list[dict]]:
    """service_id → [{"id": hostid, "role": "eigen" | "node"}]."""
    by_ip: dict[str, set[str]] = {}
    by_name: dict[str, set[str]] = {}
    for h in hosts:
        for a in h["ips"] + h["dns"]:
            by_ip.setdefault(a.lower(), set()).add(h["id"])
        for n in (h["host"], h["name"]):
            if norm(n):
                by_name.setdefault(norm(n), set()).add(h["id"])
    node_of_ip = {s.host: s.folder for s in ssh if s.folder and is_ip(s.host)}
    own: dict[int, set[str]] = {}
    nodes: dict[int, set[str]] = {}
    manual: dict[int, bool] = {}
    for s in services:
        if s.type == "zabbix":
            continue
        pick = str((s.config or {}).get("zabbix") or "").strip()
        if pick:
            manual[s.id] = True
            own[s.id] = set() if pick == "-" else {hid for n in pick.split(",") for hid in by_name.get(norm(n), set())}
            nodes[s.id] = set()
            continue
        api = s.__dict__.get("api") if s.api_id else None
        addrs = {a for a in (host_of(s.url), host_of((s.check or {}).get("target")), host_of((s.config or {}).get("url")),
                             host_of(api.url if api else None)) if a}
        addrs |= {npm[a] for a in list(addrs) if a in npm}
        names = {norm(s.name)} | {norm(a.split(".")[0]) for a in addrs if not is_ip(a)}
        mine = {hid for a in addrs for hid in by_ip.get(a, set())}
        mine |= {hid for n in names if n for hid in by_name.get(n, set())}
        own[s.id] = mine
        nodes[s.id] = {hid for a in addrs if a in node_of_ip for hid in by_name.get(norm(node_of_ip[a]), set())}
    # Wat "draait op" heeft, telt mee als node (keten na keten, zonder kringen).
    parent = {s.id: s.parent_id for s in services}
    out: dict[int, list[dict]] = {}
    for sid in own:
        extra, seen, cur = set(nodes[sid]), {sid}, parent.get(sid)
        while cur and cur not in seen and not manual.get(sid):
            seen.add(cur)
            extra |= own.get(cur, set()) | nodes.get(cur, set())
            cur = parent.get(cur)
        rows = [{"id": h, "role": "eigen"} for h in sorted(own[sid])]
        rows += [{"id": h, "role": "node"} for h in sorted(extra - own[sid])]
        if rows:
            out[sid] = rows
    return out


def host_level(h: dict, problems: list[dict]) -> str:
    if h.get("down") or any(p["severity"] >= RED_FROM for p in problems):
        return "err"
    return "ok"


def status(value: dict) -> dict:
    """Wat de tegels nodig hebben: per service rood of groen, met de hosts en hun problemen."""
    hosts = {h["id"]: h for h in value.get("hosts") or []}
    probs: dict[str, list] = {}
    for p in value.get("problems") or []:
        probs.setdefault(p["host_id"], []).append(p)
    out = {}
    for sid, rows in (value.get("map") or {}).items():
        items = []
        for r in rows:
            h = hosts.get(r["id"])
            if not h:
                continue
            ps = probs.get(h["id"], [])
            items.append({"id": h["id"], "name": h["name"], "role": r["role"], "level": host_level(h, ps), "down": h["down"],
                          "problems": [{"name": p["name"], "severity": p["severity"]} for p in ps[:5]]})
        if items:
            out[sid] = {"level": "err" if any(i["level"] == "err" for i in items) else "ok", "hosts": items}
    return out


async def _npm(db: AsyncSession) -> dict[str, str]:
    from ..routers.netmap import _npm_hosts
    return await _npm_hosts(db)


async def run_zabbix(db: AsyncSession, http: HttpClients) -> dict:
    services = list((await db.execute(select(Service).order_by(Service.id))).scalars())
    zsvc = zabbix_service(services)
    st = await ensure_state(db, STATE_KEY, {})
    if zsvc is None:
        if st.value:
            st.value = {}
            await db.commit()
        return {"skipped": True}
    ssh = list((await db.execute(select(SshHost))).scalars())
    npm = await _npm(db)
    await db.close()  # geen verbinding vasthouden terwijl Zabbix antwoordt
    now = datetime.now(timezone.utc).isoformat()
    try:
        z = build(zsvc, http)
        hosts = await z.hosts()
        problems = await z.problems()
        value = {"at": now, "service_id": zsvc.id, "url": z.base, "error": None, "hosts": hosts, "problems": problems,
                 "map": {str(k): v for k, v in assign(services, hosts, npm, ssh).items()}}
    except IntegrationError as e:
        # De vorige stand houden, met de fout erbij: de tegels worden niet ineens allemaal grijs.
        value = {**(st.value or {}), "at": now, "service_id": zsvc.id, "error": str(e)}
    st = await ensure_state(db, STATE_KEY, {})
    st.value = value
    await db.commit()
    return {"hosts": len(value.get("hosts") or []), "error": value.get("error")}
