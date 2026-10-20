"""Back-updekking per VM/CT: in welke back-upjob van Proxmox hij zit, op hoeveel PBS'en er een kopie staat, hoe oud
de nieuwste is en wanneer hij voor het laatst met de hersteltest is teruggezet.

Rood: in geen enkele back-upjob (dan komen er ook geen nieuwe back-ups) of op geen enkele PBS. Oranje: maar op één
PBS, of de job schrijft naar opslag die geen PBS is. Groen: op twee of meer PBS'en.
Een gestopte VM/CT krijgt hooguit oranje: die verandert niet, dus een gemiste back-up is minder dringend.

Ook per PBS: datastores, sync-jobs en remotes. Daarmee stelt het dashboard een sync tussen twee PBS'en voor
(zie routers/backups.py).
"""

import logging
import re
from datetime import datetime, timezone
from urllib.parse import quote, urlsplit

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..integrations import IntegrationError, build
from ..integrations.base import ago
from ..models import AppState, Service
from . import restoretest
from .checks import HttpClients

log = logging.getLogger("homepage.coverage")

STATE_KEY = "coverage"
KIND = {"lxc": "ct", "qemu": "vm"}
RANK = {"err": 0, "warn": 1, "ok": 2}


def _ids(value) -> set[int]:
    return {int(x) for x in re.findall(r"\d+", str(value or ""))}


def _on(value) -> bool:
    return value not in (0, "0", False, "false", None)


def covers(job: dict, g: dict) -> bool:
    """Valt deze VM/CT onder deze back-upjob van Proxmox?"""
    if not _on(job.get("enabled", 1)):
        return False
    if job.get("node") and job["node"] != g["node"]:
        return False
    if _on(job.get("all", 0)):
        return g["vmid"] not in _ids(job.get("exclude"))
    if job.get("pool"):
        return g.get("pool") == job["pool"]
    return g["vmid"] in _ids(job.get("vmid"))


def host_of(url: str | None) -> str | None:
    return urlsplit(url or "").hostname


async def _pve(svc: Service, http: HttpClients) -> dict:
    px = build(svc, http)
    res = await px.get("/cluster/resources")
    nodes = sorted(r["node"] for r in res if r.get("type") == "node")
    guests = [{"vmid": int(r["vmid"]), "name": r.get("name") or str(r["vmid"]), "type": KIND[r["type"]],
               "node": r.get("node"), "status": r.get("status"), "pool": r.get("pool")}
              for r in res if r.get("type") in KIND and not r.get("template") and r.get("vmid") is not None]
    jobs = await px.get("/cluster/backup")
    try:
        storages = {s["storage"]: s for s in await px.get("/storage")}
    except IntegrationError:
        storages = {}
    return {"service_id": svc.id, "service": svc.name, "nodes": nodes, "guests": guests, "storages": storages,
            "jobs": [{"id": j.get("id"), "storage": j.get("storage"), "schedule": j.get("schedule") or j.get("starttime"),
                      "enabled": _on(j.get("enabled", 1)), "all": _on(j.get("all", 0)), "node": j.get("node"),
                      "pool": j.get("pool"), "vmid": j.get("vmid"), "exclude": j.get("exclude"),
                      "comment": j.get("comment")} for j in jobs]}


async def _namespaces(pbs, store: str) -> list[str]:
    try:
        found = {n.get("ns") or "" for n in await pbs.get(f"/admin/datastore/{quote(store)}/namespace")}
    except IntegrationError:
        return [""]
    return sorted(found | {""})


async def _pbs(svc: Service, http: HttpClients) -> dict:
    pbs = build(svc, http)
    out = {"service_id": svc.id, "name": svc.name, "host": host_of(pbs.base), "port": urlsplit(pbs.base).port,
           "stores": [], "groups": [], "syncs": [], "remotes": [], "fingerprint": None, "error": None}
    for s in await pbs.stores():
        store = s.get("store")
        n = 0
        for ns in await _namespaces(pbs, store):
            path = f"/admin/datastore/{quote(store)}/groups" + (f"?ns={quote(ns)}" if ns else "")
            for g in await pbs.get(path):
                n += 1
                out["groups"].append({"store": store, "ns": ns, "type": g.get("backup-type"), "id": str(g.get("backup-id")),
                                      "last": g.get("last-backup"), "count": g.get("backup-count"),
                                      "comment": g.get("comment")})
        out["stores"].append({"store": store, "used": s.get("used"), "total": s.get("total"), "avail": s.get("avail"),
                              "groups": n})
    # Sync-jobs en remotes: zonder Remote.Audit op het token blijven die leeg (PBS filtert ze dan weg).
    seen = set()
    for q in ("", "?sync-direction=push"):
        try:
            for j in await pbs.get("/admin/sync" + q):
                if j.get("id") in seen:
                    continue
                seen.add(j.get("id"))
                out["syncs"].append({"id": j.get("id"), "store": j.get("store"), "remote": j.get("remote"),
                                     "remote_store": j.get("remote-store"), "schedule": j.get("schedule"),
                                     "direction": "push" if q else (j.get("sync-direction") or "pull"),
                                     "last_state": (j.get("last-run-state") or None)})
        except IntegrationError:
            pass
    try:
        out["remotes"] = [{"name": r.get("name"), "host": r.get("host")} for r in await pbs.get("/config/remote")]
    except IntegrationError:
        pass
    try:
        certs = await pbs.get("/nodes/localhost/certificates/info")
        cert = next((c for c in certs if c.get("filename") == "proxy.pem"), certs[0] if certs else None)
        out["fingerprint"] = cert.get("fingerprint") if cert else None
    except (IntegrationError, AttributeError):
        pass
    return out


def _restores(value: dict | None) -> dict[int, dict]:
    last: dict[int, dict] = {}
    for h in (value or {}).get("history") or []:
        v = h.get("source_vmid")
        if v and v not in last:
            last[int(v)] = {"at": h.get("at"), "ok": bool(h.get("ok"))}
    return last


def guest_rows(pve: dict, pbs: list[dict], restores: dict[int, dict]) -> list[dict]:
    """Per VM/CT: jobs, kopieën per PBS, nieuwste back-up en het oordeel."""
    copies: dict[tuple[str, int], list[dict]] = {}
    for p in pbs:
        if p.get("error"):
            continue
        best: dict[tuple[str, int], dict] = {}
        for g in p["groups"]:
            if g["type"] not in ("ct", "vm") or not g["id"].isdigit():
                continue
            key = (g["type"], int(g["id"]))
            if key not in best or (g["last"] or 0) > (best[key]["last"] or 0):
                best[key] = g
        for key, g in best.items():
            copies.setdefault(key, []).append({"pbs": p["name"], "service_id": p["service_id"], "store": g["store"],
                                               "ns": g["ns"], "age": ago(g["last"]), "count": g["count"]})
    pbs_ok = any(not p.get("error") for p in pbs)
    stores = pve["storages"]
    rows = []
    for g in pve["guests"]:
        jobs = [j for j in pve["jobs"] if covers(j, g)]
        mine = sorted(copies.get((g["type"], g["vmid"]), []), key=lambda c: c["pbs"])
        ages = [c["age"] for c in mine if c["age"] is not None]
        to_pbs = [j for j in jobs if (stores.get(j["storage"]) or {}).get("type") == "pbs"]
        n = len({c["pbs"] for c in mine})
        if not jobs:
            level, why = "err", "zit in geen enkele back-upjob" + (", oude back-up blijft staan" if n else "")
        elif pbs_ok and not n:
            level, why = "err", "staat op geen enkele PBS" if to_pbs else f"back-up naar {jobs[0]['storage']}, op geen PBS"
        elif not pbs_ok:
            level, why = ("ok", "in een back-upjob") if to_pbs else ("warn", f"back-up naar {jobs[0]['storage']}, geen PBS")
        elif n == 1:
            level, why = "warn", f"maar één kopie, op {mine[0]['pbs']}"
        else:
            level, why = "ok", f"{n} kopieën"
        stopped = g["status"] != "running"
        if stopped and level == "err":
            level = "warn"
        rows.append({**g, "jobs": [j["id"] for j in jobs], "copies": mine, "pbs_count": n,
                     "newest": min(ages) if ages else None, "restore": restores.get(g["vmid"]) if g["type"] == "ct" else None,
                     "level": level, "why": why, "stopped": stopped})
    rows.sort(key=lambda r: (RANK[r["level"]], r["vmid"]))
    return rows


async def run_coverage(db: AsyncSession, http: HttpClients) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    svcs = list((await db.execute(select(Service).where(Service.type.in_(("proxmox", "proxmoxbackupserver")))
                                  .order_by(Service.id))).scalars())
    pves, seen_nodes = [], set()
    for svc in (s for s in svcs if s.type == "proxmox"):
        try:
            c = await _pve(svc, http)
        except IntegrationError as e:
            pves.append({"service_id": svc.id, "service": svc.name, "error": str(e), "nodes": [], "guests": [],
                         "jobs": [], "storages": {}})
            continue
        # Meerdere tegels naar dezelfde cluster: één keer.
        key = frozenset(c["nodes"])
        if key in seen_nodes:
            continue
        seen_nodes.add(key)
        pves.append(c)
    pbs, seen_hosts = [], set()
    for svc in (s for s in svcs if s.type == "proxmoxbackupserver"):
        try:
            p = await _pbs(svc, http)
        except IntegrationError as e:
            p = {"service_id": svc.id, "name": svc.name, "host": None, "port": None, "stores": [], "groups": [],
                 "syncs": [], "remotes": [], "error": str(e)}
        # Twee tegels naar dezelfde PBS tellen als één.
        if p["host"] and (p["host"], p["port"]) in seen_hosts:
            continue
        seen_hosts.add((p["host"], p["port"]))
        pbs.append(p)
    rt = await db.get(AppState, restoretest.STATE_KEY)
    restores = _restores(rt.value if rt else None)
    clusters = []
    for c in pves:
        rows = guest_rows(c, pbs, restores) if not c.get("error") else []
        clusters.append({"service_id": c["service_id"], "service": c["service"], "error": c.get("error"),
                         "nodes": c["nodes"], "rows": rows,
                         "jobs": [{k: j[k] for k in ("id", "storage", "schedule", "enabled", "all", "node", "pool",
                                                     "comment")}
                                  | {"pbs": (c["storages"].get(j["storage"]) or {}).get("type") == "pbs",
                                     "server": (c["storages"].get(j["storage"]) or {}).get("server"),
                                     "datastore": (c["storages"].get(j["storage"]) or {}).get("datastore")}
                                  for j in c["jobs"]]})
    value = {"at": now.isoformat(), "clusters": clusters,
             "pbs": [{k: v for k, v in p.items() if k != "groups"} for p in pbs]}
    st = await ensure_state(db, STATE_KEY, {})
    st.value = value
    return value


def counts(value: dict | None) -> dict:
    rows = [r for c in (value or {}).get("clusters") or [] for r in c["rows"]]
    return {"err": sum(1 for r in rows if r["level"] == "err"), "warn": sum(1 for r in rows if r["level"] == "warn"),
            "ok": sum(1 for r in rows if r["level"] == "ok"), "total": len(rows)}
