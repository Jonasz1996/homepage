"""Netwerkkaart: internet → OPNsense → Proxmox-nodes → CT/VM → services, met NPM ertussen en live kleuren.

Een service komt bij een CT/VM terecht via (in die volgorde): "draait op" (parent), het IP in de url of het checkdoel
(IP's van CT's en VM's uit de SSH-import van Proxmox), de NPM-host van zijn domein (doorsturen naar dat IP of die
naam), of een CT/VM met dezelfde naam.
"""

import ipaddress
import json
import re
import time
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import get_db
from ..deps import current_user
from ..integrations import IntegrationError, build
from ..models import ConfigVersion, Service, ServiceState, SshHost, User
from ..security import decrypt
from .integrations import clients

router = APIRouter(prefix="/api", tags=["netmap"])

CACHE_SECONDS = 30
_cache: dict[int, tuple[float, list]] = {}
_SRC = re.compile(r"^pve:(\d+):(lxc|qemu)/(\d+)$")


def _host(value: str | None) -> str | None:
    if not value:
        return None
    v = value if "//" in value else f"x://{value}"
    try:
        return (urlsplit(v).hostname or "").lower() or None
    except ValueError:
        return None


def _is_ip(h: str | None) -> bool:
    try:
        ipaddress.ip_address(h or "")
        return True
    except ValueError:
        return False


async def _resources(svc: Service) -> list[dict]:
    hit = _cache.get(svc.id)
    if hit and time.monotonic() - hit[0] < CACHE_SECONDS:
        return hit[1]
    res = await build(svc, clients).resources()
    _cache[svc.id] = (time.monotonic(), res)
    return res


async def _npm_hosts(db: AsyncSession) -> dict[str, str]:
    """domein → doorstuuradres, uit de laatste nachtelijke kopie van NPM."""
    latest = (select(ConfigVersion.item, func.max(ConfigVersion.id).label("vid"))
              .where(ConfigVersion.kind == "npm").group_by(ConfigVersion.item).subquery())
    out: dict[str, str] = {}
    for v in (await db.execute(select(ConfigVersion).join(latest, ConfigVersion.id == latest.c.vid))).scalars():
        try:
            data = json.loads(decrypt(v.content))
        except ValueError:
            continue
        hosts = [h for v in (data.values() if isinstance(data, dict) else []) if isinstance(v, list)
                 for h in v if isinstance(h, dict)]
        for h in hosts:
            fwd = str(h.get("forward_host") or "").strip().lower()
            for d in h.get("domain_names") or []:
                if fwd:
                    out[str(d).lower()] = fwd
    return out


@router.get("/netmap")
async def netmap(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    services = list((await db.execute(select(Service).order_by(Service.position, Service.id))).scalars())
    states = {s.service_id: s for s in (await db.execute(select(ServiceState))).scalars()}
    hosts = list((await db.execute(select(SshHost).where(SshHost.source.is_not(None)))).scalars())
    npm = await _npm_hosts(db)
    await db.close()  # geen databaseverbinding vasthouden terwijl Proxmox antwoordt

    def status(sid: int | None) -> str:
        st = states.get(sid)
        return st.status if st else "unknown"

    # Nodes en gasten uit alle Proxmox-tegels (meerdere tegels naar dezelfde cluster: één keer).
    nodes: dict[str, dict] = {}
    guests: dict[str, dict] = {}
    errors = []
    for svc in (s for s in services if s.type == "proxmox"):
        try:
            res = await _resources(svc)
        except IntegrationError as e:
            errors.append(f"{svc.name}: {e}")
            continue
        for r in res:
            if r.get("type") == "node" and r["node"] not in nodes:
                nodes[r["node"]] = {"id": f"node:{r['node']}", "name": r["node"], "status": r.get("status"),
                                    "cpu": r.get("cpu"), "mem": r.get("mem"), "maxmem": r.get("maxmem"),
                                    "service_id": svc.id}
            elif r.get("type") in ("lxc", "qemu") and not r.get("template"):
                gid = f"{r['type']}/{r['vmid']}"
                guests.setdefault(gid, {"id": gid, "vmid": r["vmid"], "type": r["type"], "name": r.get("name") or gid,
                                        "node": r.get("node"), "status": r.get("status"), "ip": None,
                                        "pve_service_id": svc.id})
    for h in hosts:
        m = _SRC.match(h.source or "")
        if m and f"{m[2]}/{m[3]}" in guests and _is_ip(h.host):
            guests[f"{m[2]}/{m[3]}"]["ip"] = h.host
    by_ip = {g["ip"]: g["id"] for g in guests.values() if g["ip"]}
    by_name = {}
    for g in guests.values():
        by_name.setdefault(str(g["name"]).lower(), g["id"])
    # Een Proxmox-tegel voor één node (instelling node, of de tegel heet zoals de node).
    node_svc = {}
    for s in services:
        if s.type == "proxmox":
            n = (s.config or {}).get("node") or s.name
            if n in nodes:
                node_svc[s.id] = n

    def resolve(h: str | None) -> tuple[str | None, str | None]:
        if not h:
            return None, None
        if h in by_ip:
            return by_ip[h], "ip"
        if h in by_name:
            return by_name[h], "naam"
        first = h.split(".")[0]
        if not _is_ip(h) and first in by_name:
            return by_name[first], "naam"
        return None, None

    placed: dict[int, dict] = {}
    for s in services:
        if s.type in ("proxmox", "opnsense", "npm"):
            continue
        guest = how = None
        via_npm = False
        api = s.__dict__.get("api") if s.api_id else None
        for h in (_host(s.url), _host((s.check or {}).get("target")), _host((s.config or {}).get("url")),
                  _host(api.url if api else None)):
            if h and h in npm:
                guest, _ = resolve(npm[h])
                if guest:
                    via_npm, how = True, f"NPM → {npm[h]}"
                    break
            guest, how = resolve(h)
            if guest:
                break
        placed[s.id] = {"id": s.id, "name": s.name, "status": status(s.id), "guest": guest, "how": how,
                        "via_npm": via_npm or (_host(s.url) in npm), "parent_id": s.parent_id, "icon": s.icon,
                        "url": s.url}
    # "Draait op" gaat voor: een service op een andere service komt bij diens CT/VM; op een Proxmox-tegel bij die node.
    for p in placed.values():
        par = p["parent_id"]
        if par in placed and placed[par]["guest"]:
            p["guest"], p["how"] = placed[par]["guest"], f"draait op {placed[par]['name']}"
        elif par in node_svc:
            p["guest"], p["node"], p["how"] = None, node_svc[par], "draait op de node"
    for p in placed.values():
        p.setdefault("node", guests[p["guest"]]["node"] if p["guest"] else None)

    infra = {t: [{"id": s.id, "name": s.name, "status": status(s.id)} for s in services if s.type == t]
             for t in ("opnsense", "npm")}
    return {"nodes": sorted(nodes.values(), key=lambda n: n["name"]),
            "guests": sorted(guests.values(), key=lambda g: g["vmid"]),
            "services": list(placed.values()), "opnsense": infra["opnsense"], "npm": infra["npm"],
            "npm_hosts": len(npm), "errors": errors}
