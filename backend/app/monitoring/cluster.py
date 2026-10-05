"""Clusterstatus van Proxmox: quorum, welke nodes corosync ziet, HA-resources en replicatie-jobs.
Een melding zodra de cluster zijn quorum verliest, een node wegvalt, een HA-resource in "error" staat of een
replicatie mislukt, en opnieuw als het weer in orde is.
"""

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import notify
from ..integrations import IntegrationError, build
from ..models import AppState, Service
from .checks import HttpClients

log = logging.getLogger("homepage.cluster")

STATE_KEY = "cluster"
CLUSTER_EVERY = 120
HA_BAD = {"error", "fence", "freeze", "recovery"}


async def fetch(svc: Service, http: HttpClients) -> dict:
    px = build(svc, http)
    status = await px.get("/cluster/status")
    head = next((x for x in status if x.get("type") == "cluster"), None)
    nodes = [{"name": x.get("name"), "online": bool(x.get("online")), "ip": x.get("ip"), "id": x.get("nodeid")}
             for x in status if x.get("type") == "node"]
    out = {"service_id": svc.id, "service": svc.name, "cluster": head.get("name") if head else None,
           "quorate": bool(head.get("quorate")) if head else None, "nodes": sorted(nodes, key=lambda n: n["name"] or ""),
           "ha": [], "replication": [], "error": None}
    if head:
        try:
            for x in await px.get("/cluster/ha/status/current"):
                if x.get("type") == "service":
                    out["ha"].append({"sid": x.get("sid"), "state": x.get("state"), "node": x.get("node"),
                                      "status": x.get("status")})
        except IntegrationError as e:
            out["ha_error"] = str(e)
    for n in nodes:
        if not n["online"]:
            continue
        try:
            for r in await px.get(f"/nodes/{n['name']}/replication"):
                out["replication"].append({"id": r.get("id"), "guest": r.get("guest"), "target": r.get("target"),
                                           "node": n["name"], "last_sync": r.get("last_sync"),
                                           "fail_count": r.get("fail_count") or 0, "error": r.get("error")})
        except IntegrationError:
            # Geen replicatie of geen rechten: geen probleem voor de rest.
            pass
    return out


def problems(c: dict) -> dict[str, tuple[str, str]]:
    """Wat er nu mis is, per sleutel: (ernst, tekst). Een sleutel die verdwijnt = weer in orde."""
    name = c.get("cluster") or c.get("service")
    out = {}
    if c.get("error"):
        out["api"] = ("warn", f"{c['service']}: {c['error']}")
        return out
    if c.get("quorate") is False:
        out["quorum"] = ("err", f"Cluster {name} heeft geen quorum meer")
    if c.get("cluster"):
        for n in c.get("nodes", []):
            if not n["online"]:
                out[f"node:{n['name']}"] = ("err", f"Node {n['name']} is weg uit cluster {name}")
    for h in c.get("ha", []):
        if h.get("state") in HA_BAD:
            out[f"ha:{h['sid']}"] = ("err", f"HA-resource {h['sid']} staat in {h['state']}")
    for r in c.get("replication", []):
        if r["fail_count"]:
            out[f"repl:{r['node']}/{r['id']}"] = ("warn" if r["fail_count"] < 3 else "err",
                                      f"Replicatie {r['id']} ({r['node']} → {r['target']}) mislukt {r['fail_count']}×")
    return out


OK_TEXT = {"quorum": "Cluster {name} heeft weer quorum", "node": "Node {key} is terug in cluster {name}",
           "ha": "HA-resource {key} is weer in orde", "repl": "Replicatie {key} lukt weer",
           "api": "Clusterstatus van {name} is weer leesbaar"}


async def run_cluster(db: AsyncSession, http: HttpClients) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    st = await db.get(AppState, STATE_KEY)
    prev = dict(st.value) if st else {}
    alerts: dict = dict(prev.get("alerts") or {})
    items, seen = [], set()
    for svc in (await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars():
        try:
            c = await fetch(svc, http)
        except IntegrationError as e:
            c = {"service_id": svc.id, "service": svc.name, "cluster": None, "quorate": None, "nodes": [], "ha": [],
                 "replication": [], "error": str(e)}
        # Meerdere tegels naar dezelfde cluster: maar één keer tonen en melden.
        if c.get("cluster") and c["cluster"] in seen:
            continue
        if c.get("cluster"):
            seen.add(c["cluster"])
        items.append(c)
    now_bad: dict = {}
    for c in items:
        scope = c.get("cluster") or f"svc{c['service_id']}"
        for key, (level, text) in problems(c).items():
            now_bad[f"{scope}|{key}"] = {"level": level, "text": text, "service_id": c["service_id"],
                                         "name": c.get("cluster") or c.get("service")}
    for k, v in now_bad.items():
        old = alerts.get(k)
        if not old or (old["level"] == "warn" and v["level"] == "err"):
            notify(db, v["text"], None, level=v["level"], source="cluster", service_id=v["service_id"])
    for k, v in alerts.items():
        if k not in now_bad:
            kind, _, key = k.split("|", 1)[1].partition(":")
            notify(db, OK_TEXT[kind].format(name=v["name"], key=key), None, level="ok", source="cluster",
                   service_id=v.get("service_id"))
    value = {"at": now.isoformat(), "items": items, "alerts": now_bad}
    if st:
        st.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value


def summary(state: dict) -> dict:
    alerts = (state or {}).get("alerts") or {}
    return {"err": sum(1 for a in alerts.values() if a["level"] == "err"),
            "warn": sum(1 for a in alerts.values() if a["level"] == "warn"),
            "problems": [a["text"] for a in alerts.values()]}
