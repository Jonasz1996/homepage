"""Clusterstatus van Proxmox: quorum, welke nodes corosync ziet, HA-resources, replicatie-jobs, de Proxmox-versie
per node en de QDevice. Een melding zodra de cluster zijn quorum verliest, een node wegvalt, een HA-resource in "error"
staat, een replicatie mislukt, nodes een andere Proxmox-versie draaien of de QDevice wegvalt, en opnieuw als het weer
in orde is. Een even aantal stemmen zonder QDevice is alleen een tip (aandacht, ter info), geen melding.
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


def _release(v: str | None) -> str | None:
    """'8.2.4' → '8.2': verschil in de laatste cijfers is gewoon een update die nog moet gebeuren."""
    return ".".join(v.split(".")[:2]) if v else None


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
    if head:
        try:
            votes = {x.get("name") or x.get("node"): int(x.get("quorum_votes") or 1)
                     for x in await px.get("/cluster/config/nodes")}
        except (IntegrationError, TypeError, ValueError):
            votes = {}
        for n in nodes:
            n["votes"] = votes.get(n["name"], 1)
        try:
            # Leeg als deze node geen QDevice heeft; anders de status van corosync-qdevice.
            q = await px.get("/cluster/config/qdevice")
            out["qdevice"] = {"host": q.get("QNetd host"), "state": q.get("State"), "algorithm": q.get("Algorithm")} \
                if isinstance(q, dict) and q else {}
        except IntegrationError:
            out["qdevice"] = None
    for n in nodes:
        if not n["online"]:
            continue
        try:
            v = await px.get(f"/nodes/{n['name']}/version")
            n["version"] = v.get("version") if isinstance(v, dict) else None
        except IntegrationError:
            pass
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
    out.update(_versions(c, name))
    out.update(_votes(c, name))
    return out


def _versions(c: dict, name: str) -> dict:
    vers = {n["name"]: n["version"] for n in c.get("nodes", []) if n.get("version")}
    if len(vers) < 2 or len(set(vers.values())) == 1:
        return {}
    listing = ", ".join(f"{k} {v}" for k, v in sorted(vers.items()))
    if len({_release(v) for v in vers.values()}) > 1:
        return {"version:mix": ("warn", f"Nodes van cluster {name} draaien verschillende Proxmox-versies: {listing}")}
    return {"version:patch": ("info", f"Niet alle nodes van cluster {name} zijn even ver bijgewerkt: {listing}")}


def _votes(c: dict, name: str) -> dict:
    """Een even aantal stemmen: valt de helft weg, dan heeft geen enkele helft quorum. Een QDevice is de extra stem."""
    q = c.get("qdevice")
    if not c.get("cluster") or q is None:
        return {}
    if q:
        if (q.get("state") or "").lower() != "connected":
            return {"qdevice:state": ("warn", f"QDevice van cluster {name} ({q.get('host') or '?'}) is niet verbonden: "
                                              f"{q.get('state') or 'onbekend'}")}
        return {}
    total = sum(n.get("votes", 1) for n in c.get("nodes", []))
    if total >= 2 and total % 2 == 0:
        return {"qdevice:none": ("info", f"Cluster {name} heeft {total} stemmen en geen QDevice: vallen er {total // 2} "
                                         f"nodes uit, dan stopt de hele cluster")}
    return {}


OK_TEXT = {"quorum": "Cluster {name} heeft weer quorum", "node": "Node {key} is terug in cluster {name}",
           "ha": "HA-resource {key} is weer in orde", "repl": "Replicatie {key} lukt weer",
           "api": "Clusterstatus van {name} is weer leesbaar",
           "version": "Alle nodes van cluster {name} draaien weer dezelfde Proxmox-versie",
           "qdevice": "QDevice van cluster {name} is weer verbonden"}


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
        if v["level"] == "info":
            continue
        if not old or old["level"] == "info" or (old["level"] == "warn" and v["level"] == "err"):
            notify(db, v["text"], None, level=v["level"], source="cluster", service_id=v["service_id"])
    for k, v in alerts.items():
        if k not in now_bad and v["level"] != "info":
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
            "problems": [a["text"] for a in alerts.values() if a["level"] != "info"]}
