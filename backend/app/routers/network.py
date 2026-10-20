"""Internet en stroom: WAN, tunnels, publiek IP, Wake-on-LAN en verbruik per node."""

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..db import get_db
from ..deps import audit, current_user, event, recent_auth
from ..models import AppState, Service, ServiceState, User
from ..monitoring import ports
from ..monitoring.network import power_overview, watch_gateways, watch_public_ip, watch_tunnels
from .. import wol
from .integrations import clients

router = APIRouter(prefix="/api", tags=["network"])


async def _overview(db: AsyncSession) -> dict:
    services = {s.id: s for s in (await db.execute(select(Service))).scalars()}
    states = {st.key: st.value for st in (await db.execute(
        select(AppState).where(AppState.key.like("net_%") | (AppState.key == "public_ip")))).scalars()}

    def per(prefix: str, kind: str) -> list[dict]:
        out = []
        for sid, s in services.items():
            if s.type != kind:
                continue
            v = states.get(f"{prefix}:{sid}", {})
            out.append({"service_id": sid, "service": s.name, "items": v.get("items", []), "error": v.get("error"),
                        "checked_at": v.get("checked_at")})
        return out

    wake = []
    for s in services.values():
        mac = wol.normalize_mac(str((s.config or {}).get("mac") or ""))
        if mac:
            st = await db.get(ServiceState, s.id)
            wake.append({"service_id": s.id, "name": s.name, "mac": mac,
                         "status": "unknown" if st is None or st.stale else st.status})
    ip = states.get("public_ip", {})
    return {"public_ip": {k: ip.get(k) for k in ("ip", "since", "checked_at", "error", "history")},
            "gateways": per("net_gw", "opnsense"), "tunnels": per("net_tunnel", "cloudflared"),
            "wol": sorted(wake, key=lambda w: w["name"].lower())}


@router.get("/network")
async def network(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await _overview(db)


@router.post("/network/refresh")
async def refresh_network(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    await watch_gateways(db, clients)
    await watch_tunnels(db, clients)
    await watch_public_ip(db, clients)
    await db.commit()
    return await _overview(db)


@router.get("/network/ports")
async def port_list(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Welke IP's en poorten het dashboard gebruikt: voor de firewallregel tussen de VLAN's."""
    return await ports.overview(db)


@router.post("/services/{service_id}/wol", dependencies=[outside.guard("acties")])
async def wake(service_id: int, request: Request, user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    s = await db.get(Service, service_id)
    if s is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Service niet gevonden")
    cfg = s.config or {}
    mac = wol.normalize_mac(str(cfg.get("mac") or ""))
    if mac is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Geen geldig MAC-adres ingesteld bij deze service")
    broadcast = str(cfg.get("wol_broadcast") or "255.255.255.255")
    try:
        wol.send(mac, broadcast)
    except OSError as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Versturen mislukt: {e.strerror or e}") from e
    await audit(db, request, user, "wol", service=s.name, mac=mac)
    event(db, "actie", f"{s.name}: Wake-on-LAN verstuurd", f"Magic packet naar {mac} via {broadcast}.", service_id=s.id)
    await db.commit()
    return {"ok": True, "message": f"Wekker verstuurd naar {s.name} ({mac})"}


@router.get("/power")
async def power(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return await power_overview(db, clients)
