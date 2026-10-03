"""SSH-hosts automatisch ophalen uit Proxmox: alle nodes, containers en VM's met hun IP-adres.

Per Proxmox-service: de nodes uit /cluster/status, containers via /lxc/{id}/interfaces (of de config als
de container uit staat) en VM's via de QEMU guest agent. Elke gevonden machine krijgt een vaste herkomst
("pve:<service>:<soort>/<id>"), zodat een volgende ronde het IP bijwerkt in plaats van een dubbele host
te maken. Hosts die zo binnenkomen gebruiken de standaard login uit de terminal, tenzij je ze aanpast.
"""

import asyncio
import ipaddress
import logging
import re

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .integrations import IntegrationError, build
from .models import AppState, Service, SshHost
from .ssh_login import DEFAULTS_KEY

log = logging.getLogger("homepage.ssh")

SYNC_EVERY = 30 * 60
# Interfaces die niets zeggen over hoe je de machine bereikt.
_SKIP_IF = re.compile(r"^(lo|docker\d*|br-|veth|virbr|cni|flannel|cali|tailscale|wg|zt|kube)")
_CONF_IP = re.compile(r"(?:^|,)ip=([0-9.]+)(?:/\d+)?(?:,|$)")


def pick_ipv4(addrs: list[tuple[str, str]]) -> str | None:
    """Eerste bruikbare IPv4 uit (interface, adres): geen loopback, link-local of Docker-bridge."""
    for iface, addr in addrs:
        if _SKIP_IF.match(iface or ""):
            continue
        try:
            ip = ipaddress.ip_address(addr.split("/")[0])
        except ValueError:
            continue
        if ip.version == 4 and not (ip.is_loopback or ip.is_link_local or ip.is_unspecified):
            return str(ip)
    return None


async def _guest_ip(integ, node: str, kind: str, vmid: int, running: bool) -> tuple[str | None, str | None]:
    """(IP, reden als er geen is)."""
    try:
        if kind == "lxc":
            if running:
                ifs = await integ.get(f"/nodes/{node}/lxc/{vmid}/interfaces")
                ip = pick_ipv4([(i.get("name", ""), i.get("inet") or "") for i in ifs or []])
                if ip:
                    return ip, None
            conf = await integ.get(f"/nodes/{node}/lxc/{vmid}/config")
            for k, v in (conf or {}).items():
                if k.startswith("net") and isinstance(v, str):
                    m = _CONF_IP.search(v)
                    if m:
                        return m.group(1), None
            return None, "uit, en DHCP" if not running else "geen IPv4"
        if not running:
            return None, "staat uit"
        data = await integ.get(f"/nodes/{node}/qemu/{vmid}/agent/network-get-interfaces")
        result = data.get("result", []) if isinstance(data, dict) else []
        addrs = [(i.get("name", ""), a.get("ip-address", "")) for i in result for a in i.get("ip-addresses") or []
                 if a.get("ip-address-type") == "ipv4"]
        ip = pick_ipv4(addrs)
        return ip, None if ip else "geen IPv4 van de guest agent"
    except IntegrationError as e:
        text = str(e)
        if kind == "qemu" and ("500" in text or "agent" in text.lower()):
            return None, "geen QEMU guest agent"
        if "403" in text:
            return None, "geen rechten (VM.Audit, voor VM's ook VM.GuestAgent.Audit of VM.Monitor)"
        return None, text[:120]


async def discover(db: AsyncSession, clients) -> dict:
    """Alle machines uit alle Proxmox-services. Dubbels (dezelfde node via cluster en node-tegel) eruit."""
    services = (await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars().all()
    existing = {h.source: h for h in (await db.execute(select(SshHost).where(SshHost.source.is_not(None)))).scalars()}
    by_addr = {(h.host, h.port) for h in (await db.execute(select(SshHost))).scalars()}
    items, errors, seen = [], [], set()
    sem = asyncio.Semaphore(8)

    for svc in services:
        integ = build(svc, clients)
        try:
            res = await integ.resources()
            status = await integ.get("/cluster/status")
        except IntegrationError as e:
            errors.append({"service": svc.name, "error": str(e)})
            continue
        node_ip = {s.get("name"): s.get("ip") for s in status or [] if s.get("type") == "node"}
        for r in res:
            if r.get("type") != "node":
                continue
            node = r.get("node")
            key = ("node", node)
            if key in seen:
                continue
            seen.add(key)
            ip = node_ip.get(node)
            items.append({"source": f"pve:{svc.id}:node/{node}", "kind": "node", "name": node, "node": node,
                          "host": ip, "folder": node, "status": r.get("status"),
                          "why": None if ip else "geen IP in /cluster/status"})

        guests = [r for r in res if r.get("type") in ("lxc", "qemu") and not r.get("template")]

        async def one(g, svc=svc, integ=integ):
            async with sem:
                ip, why = await _guest_ip(integ, g["node"], g["type"], g["vmid"], g.get("status") == "running")
            return {"source": f"pve:{svc.id}:{g['type']}/{g['vmid']}", "kind": g["type"], "vmid": g["vmid"],
                    "name": g.get("name") or f"{g['type']}-{g['vmid']}", "node": g["node"], "host": ip,
                    "folder": g["node"], "status": g.get("status"), "why": why}

        # Zelfde vmid via twee services (cluster en losse node): één keer.
        have = {i.get("vmid") for i in items if i.get("vmid") is not None}
        items.extend(await asyncio.gather(*(one(g) for g in guests if g["vmid"] not in have)))

    for i in items:
        h = existing.get(i["source"])
        i["host_id"] = h.id if h else None
        i["known"] = bool(h) or (i["host"], 22) in by_addr
    items.sort(key=lambda i: (i["folder"], i["kind"] != "node", i["name"].lower()))
    return {"items": items, "errors": errors}


async def apply(db: AsyncSession, items: list[dict], add_new: bool = True) -> dict:
    """Gevonden machines toevoegen of het IP van eerder opgehaalde hosts bijwerken."""
    added = updated = 0
    for i in items:
        if not i.get("host"):
            continue
        h = (await db.execute(select(SshHost).where(SshHost.source == i["source"]))).scalar_one_or_none()
        if h:
            if h.host != i["host"]:
                h.host = i["host"]
                updated += 1
            continue
        if not add_new:
            continue
        clash = (await db.execute(select(SshHost).where(SshHost.host == i["host"], SshHost.port == 22))).scalars().first()
        if clash:
            # Al zelf toegevoegd: alleen de herkomst en map erbij zetten, zodat het IP voortaan meegaat.
            if clash.source is None:
                clash.source = i["source"]
                clash.folder = clash.folder or i["folder"]
            continue
        db.add(SshHost(name=i["name"][:80], host=i["host"], port=22, username="", folder=i["folder"][:80],
                       source=i["source"]))
        added += 1
    await db.flush()
    return {"added": added, "updated": updated}


async def auto_sync(db: AsyncSession, clients) -> dict | None:
    """Worker: als "automatisch bijhouden" aan staat, nieuwe machines toevoegen en IP's bijwerken."""
    st = await db.get(AppState, DEFAULTS_KEY)
    if not st or not (st.value or {}).get("auto_sync"):
        return None
    found = await discover(db, clients)
    return await apply(db, found["items"], add_new=True)
