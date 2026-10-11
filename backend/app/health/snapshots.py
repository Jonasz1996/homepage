"""Vergeten snapshots: alle snapshots van VM's en containers via de Proxmox-API, met hun leeftijd.

Een snapshot die blijft staan houdt oude blokken vast en laat de opslag stilletjes vollopen. Lezen kan met de
PVEAuditor-rol; verwijderen vraagt VM.Snapshot op het token. De proef (delete_plan) toont dezelfde call als
delete_snapshot, zonder hem te doen.
"""

import asyncio
import logging
import re
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import proef
from ..deps import notify
from ..integrations import IntegrationError, build
from ..integrations.proxmox import NODE_RE
from ..models import AppState, Service, UpdateRun
from ..monitoring.upgrade import SNAP_PREFIX

log = logging.getLogger("homepage.health")

SNAPSHOTS_EVERY = 6 * 3600
STATE_KEY = "snapshots"
SNAP_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,39}$")


async def _guest_snaps(px, g: dict, sem: asyncio.Semaphore) -> list[dict]:
    path = f"/nodes/{g['node']}/{g['type']}/{g['vmid']}/snapshot"
    async with sem:
        rows = await px.get(path)
    out = []
    for s in rows or []:
        if s.get("name") == "current" or not s.get("name"):
            continue
        out.append({"name": s["name"], "description": (s.get("description") or "").strip()[:300] or None,
                    "snaptime": s.get("snaptime"), "vmstate": bool(s.get("vmstate")), "parent": s.get("parent")})
    return out


async def collect(db: AsyncSession, http, now: datetime) -> dict:
    items, errors, seen = [], [], set()
    sem = asyncio.Semaphore(8)
    for svc in (await db.execute(select(Service).where(Service.type == "proxmox").order_by(Service.id))).scalars():
        px = build(svc, http)
        try:
            res = await px.resources()
        except IntegrationError as e:
            errors.append({"service": svc.name, "error": str(e)})
            continue
        guests = [r for r in res if r.get("type") in ("qemu", "lxc") and not r.get("template")
                  and (r.get("node"), r.get("vmid")) not in seen]
        seen.update((g.get("node"), g.get("vmid")) for g in guests)
        results = await asyncio.gather(*(_guest_snaps(px, g, sem) for g in guests), return_exceptions=True)
        for g, r in zip(guests, results):
            if isinstance(r, BaseException):
                errors.append({"service": svc.name, "guest": g.get("vmid"), "error": str(r)[:200]})
                continue
            for s in r:
                age = None
                if s["snaptime"]:
                    age = (now - datetime.fromtimestamp(int(s["snaptime"]), timezone.utc)).total_seconds() / 86400
                items.append({**s, "service_id": svc.id, "service": svc.name, "node": g["node"], "type": g["type"],
                              "vmid": g["vmid"], "guest": g.get("name") or str(g["vmid"]),
                              "age_days": round(age, 1) if age is not None else None})
    items.sort(key=lambda s: -(s["age_days"] or 0))
    return {"items": items, "errors": errors}


def _key(s: dict) -> str:
    return f"{s['node']}/{s['vmid']}/{s['name']}"


async def run_snapshots(db: AsyncSession, http, days: int) -> dict:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    data = await collect(db, http, now)
    state = await db.get(AppState, STATE_KEY)
    warned = set(state.value.get("warned", [])) if state else set()
    old = [s for s in data["items"] if (s["age_days"] or 0) >= days]
    new = [s for s in old if _key(s) not in warned]
    if new:
        lines = [f"{s['guest']} ({s['vmid']}) · {s['name']} · {int(s['age_days'])} dagen" for s in new[:15]]
        if len(new) > 15:
            lines.append(f"… en nog {len(new) - 15}")
        notify(db, f"{len(new)} snapshot{'s' if len(new) != 1 else ''} ouder dan {days} dagen",
               "\n".join(lines) + "\nOude snapshots houden schijfruimte vast.", level="warn", source="snapshots")
    # Alleen bijhouden wat nog bestaat, zodat een opnieuw gemaakte snapshot met dezelfde naam weer meldt.
    value = {"checked_at": now.isoformat(), **data, "warned": sorted(_key(s) for s in old)}
    if state:
        state.value = value
    else:
        db.add(AppState(key=STATE_KEY, value=value))
    return value


def delete_call(node: str, kind: str, vmid: int, name: str) -> tuple[str, str]:
    """De call die een snapshot verwijdert, na de controle van de invoer: dezelfde voor het echte werk en de proef."""
    if not (isinstance(node, str) and NODE_RE.match(node)) or kind not in ("qemu", "lxc") or not SNAP_RE.match(name):
        raise IntegrationError("Ongeldige node, type of snapshotnaam")
    return "DELETE", f"/api2/json/nodes/{node}/{kind}/{int(vmid)}/snapshot/{name}"


async def delete_snapshot(svc: Service, http, node: str, kind: str, vmid: int, name: str) -> str:
    method, path = delete_call(node, kind, vmid, name)
    px = build(svc, http)
    upid = await px.request(method, path, headers=px.headers(write=True))
    return (upid or {}).get("data") or ""


def _holds(snap: dict | None, node: str, kind: str, vmid: int, name: str) -> bool:
    """Is dit de snapshot van een update-run (UpdateRun.snapshot), en bewaart die run hem nog? Een pct-snapshot is
    altijd van een CT; zijn node is de naam van de SSH-host van de node."""
    if not snap or snap.get("name") != name or snap.get("removed_at"):
        return False
    t = "lxc" if snap.get("kind") == "pct" else snap.get("type")
    same_node = not snap.get("node") or str(snap["node"]).lower() == node.lower()
    return t == kind and int(snap.get("vmid") or 0) == int(vmid) and same_node


async def held_by(db: AsyncSession, node: str, kind: str, vmid: int, name: str) -> list[UpdateRun]:
    """De update-runs die deze snapshot nog bewaren om terug te draaien (alleen de eigen hp-upd-snapshots)."""
    if not name.startswith(SNAP_PREFIX):
        return []
    rows = (await db.execute(select(UpdateRun).where(UpdateRun.snapshot["name"].as_string() == name))).scalars().all()
    return [r for r in rows if _holds(r.snapshot, node, kind, vmid, name)]


async def mark_removed(db: AsyncSession, node: str, kind: str, vmid: int, name: str) -> list[int]:
    """Na verwijderen via hw: de run biedt terugdraaien niet meer aan, en het opruimen na keep_days slaat hem over."""
    ids = []
    for r in await held_by(db, node, kind, vmid, name):
        r.snapshot = {**r.snapshot, "removed_at": datetime.now(timezone.utc).isoformat()}
        ids.append(r.id)
    return ids


async def _snapshot_rights(svc: Service, http) -> dict:
    """VM.Snapshot op het actietoken, met dezelfde rechtencheck als de instellingen-checklist."""
    from ..setupcheck import _privs  # setupcheck importeert de health-modules zelf
    try:
        integ = build(svc, http)  # een eigen object: _privs zet er het actietoken in
    except IntegrationError as e:
        return proef.check("VM.Snapshot (actietoken)", None, str(e))
    what = "VM.Snapshot (actietoken)" if integ.split else "VM.Snapshot (het enige token)"
    _, act, err = await _privs(integ)
    if act is None:
        return proef.check(what, None, f"niet op te vragen ({(err or 'geen antwoord').removeprefix('actietoken: ')})")
    if "VM.Snapshot" in act:
        return proef.check(what, True, "aanwezig")
    return proef.check(what, False, "ontbreekt: Proxmox zou weigeren (HTTP 403)")


async def delete_plan(svc: Service, http, node: str, kind: str, vmid: int, name: str, held: list[dict],
                      now: datetime | None = None) -> dict:
    """Wat verwijderen zou doen: dezelfde controle en call als delete_snapshot, plus wat er nu staat (alleen lezen).
    held: de runs uit held_by, vooraf gelezen, zodat er geen sessie open blijft tijdens de calls naar Proxmox."""
    method, path = delete_call(node, kind, vmid, name)
    px = build(svc, http)
    now = now or datetime.now(timezone.utc).replace(microsecond=0)
    guest = f"{'VM' if kind == 'qemu' else 'CT'} {int(vmid)}"
    what = f"snapshot {name} van {guest} bestaat"
    checks, warnings = [], []
    try:
        rows = await px.get(f"/nodes/{node}/{kind}/{int(vmid)}/snapshot")
    except IntegrationError as e:
        checks.append(proef.check(what, None, f"niet na te gaan: {e}"))
    else:
        s = next((r for r in rows or [] if r.get("name") == name), None)
        if s is None:
            checks.append(proef.check(what, False, "niet (meer) gevonden: Proxmox zou een fout geven"))
        else:
            bits = []
            if s.get("snaptime"):
                age = (now - datetime.fromtimestamp(int(s["snaptime"]), timezone.utc)).total_seconds() / 86400
                bits.append(f"{int(age)} dagen oud")
            bits.append("met RAM-toestand, die verdwijnt mee" if s.get("vmstate") else "zonder RAM-toestand")
            kids = [r["name"] for r in rows if r.get("parent") == name and r.get("name") not in (None, "current")]
            bits.append(f"snapshots erna: {', '.join(kids)}" if kids else "geen snapshots erna")
            checks.append(proef.check(what, True, ", ".join(bits)))
    checks.append(await _snapshot_rights(svc, http))
    for r in held:
        warnings.append(f"Update-run #{r['id']} ({r['target']}, {r['status']}) houdt deze snapshot bij om naar terug te "
                        "draaien: dat kan daarna niet meer.")
    step = proef.step(f"{node} via tegel {svc.name}", "proxmox-api", f"{method} {path}",
                      who=proef.api_who(px.token_id(write=True)), wait="niet: de Proxmox-taak loopt verder op de node",
                      on_fail="een foutmelding, en de snapshot blijft in de lijst")
    after = ["de rij verdwijnt meteen uit de lijst", "in het auditlog: snapshot verwijderd"]
    after += [f"update-run #{r['id']}: terugdraaien wordt niet meer aangeboden" for r in held]
    return proef.plan(f"Snapshot {name} van {guest} op {node} zou verwijderd worden", [step], checks=checks,
                      after=after, warnings=warnings, now=now)
