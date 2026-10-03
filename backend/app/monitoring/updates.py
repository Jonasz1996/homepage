"""Updates-overzicht: openstaande pakketupdates per node, container en machine, en verouderde Docker-images.

Bronnen:
- Proxmox VE en PBS: de eigen API (/nodes/<node>/apt/update), geen SSH nodig.
- SSH-hosts met "updates opvolgen": apt of apk via SSH; op een Proxmox-node desgewenst ook in elke
  draaiende container via `pct exec`.
- Portainer: per container of er een nieuwer image is.

Het resultaat staat in AppState "updates"; zakt het aantal, dan komt er een regel op de tijdlijn.
"""

import asyncio
import logging
import re
import shlex
from datetime import datetime, timezone

import asyncssh
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..deps import event
from ..integrations import IntegrationError, build
from ..models import AppState, Service, SshHost, SshKey
from ..security import decrypt
from .checks import HttpClients

log = logging.getLogger("homepage.worker")

UPDATES_EVERY = 6 * 3600
KEY = "updates"
MAX_PACKAGES = 300
SSH_TIMEOUT = 900

# Draait op de machine zelf en in elke container: pakketlijst verversen (als root) en tonen wat kan.
PROBE = r"""
if command -v apt-get >/dev/null 2>&1; then
  [ "$(id -u)" = 0 ] && timeout 180 apt-get update -qq >/dev/null 2>&1
  LC_ALL=C apt list --upgradable 2>/dev/null | grep upgradable
elif command -v apk >/dev/null 2>&1; then
  [ "$(id -u)" = 0 ] && timeout 120 apk update -q >/dev/null 2>&1
  apk list -u 2>/dev/null
else
  echo "@@NOPKG"
fi
"""


def script(containers: bool) -> str:
    p = shlex.quote(PROBE)
    # Het script komt via stdin binnen (sh -s): elk commando krijgt /dev/null als stdin, anders eet het de rest op.
    out = f"P={p}\necho '@@HOST'\nsh -c \"$P\" </dev/null\n"
    if containers:
        out += (
            "if command -v pct >/dev/null 2>&1; then\n"
            "  for id in $(pct list 2>/dev/null </dev/null | awk 'NR>1 && $2==\"running\" {print $1}'); do\n"
            "    echo \"@@CT $id $(pct config \"$id\" 2>/dev/null </dev/null | sed -n 's/^hostname: //p')\"\n"
            "    timeout 300 pct exec \"$id\" -- sh -c \"$P\" 2>/dev/null </dev/null\n"
            "  done\n"
            "fi\n"
        )
    return out


APT_RE = re.compile(r"^(?P<n>[^/\s]+)/(?P<suite>\S+)\s+(?P<to>\S+)\s+\S+\s+\[upgradable from: (?P<from>[^\]]+)\]")
APK_RE = re.compile(r"^(?P<pkg>\S+)\s.*\[upgradable from: (?P<from>[^\]]+)\]")


def parse_packages(lines: list[str]) -> list[dict] | None:
    """Pakketten uit `apt list --upgradable` of `apk list -u`. None = geen pakketbeheer gevonden."""
    out = []
    for line in lines:
        line = line.strip()
        if line == "@@NOPKG":
            return None
        if m := APT_RE.match(line):
            out.append({"n": m["n"], "from": m["from"], "to": m["to"], "sec": "security" in m["suite"]})
        elif m := APK_RE.match(line):
            # apk: "musl-1.2.4-r3 x86_64 {musl} ..." → naam zonder versie
            pkg = m["pkg"]
            name = re.sub(r"-\d[^-]*-r\d+$", "", pkg)
            out.append({"n": name, "from": m["from"].removeprefix(name + "-"), "to": pkg.removeprefix(name + "-"),
                        "sec": False})
    return out


def parse_output(text: str) -> list[tuple[str, str | None, list[dict] | None]]:
    """Splitst de uitvoer van script() in (soort, naam, pakketten): ("host", None, ...) en ("ct", "101 web", ...)."""
    parts: list[tuple[str, str | None, list[str]]] = []
    for line in text.splitlines():
        if line.startswith("@@HOST"):
            parts.append(("host", None, []))
        elif line.startswith("@@CT "):
            parts.append(("ct", line[5:].strip(), []))
        elif parts:
            parts[-1][2].append(line)
    return [(kind, name, parse_packages(lines)) for kind, name, lines in parts]


def target(key: str, name: str, kind: str, service_id: int | None, packages: list[dict] | None = None,
           error: str | None = None, **extra) -> dict:
    pk = packages or []
    return {"key": key, "name": name, "kind": kind, "service_id": service_id, "count": len(pk),
            "security": sum(1 for p in pk if p.get("sec")), "packages": pk[:MAX_PACKAGES], "error": error,
            "checked_at": datetime.now(timezone.utc).isoformat(), **extra}


def _api_packages(rows: list[dict]) -> list[dict]:
    return [{"n": r.get("Package"), "from": r.get("OldVersion"), "to": r.get("Version"),
             "sec": "security" in str(r.get("Origin", "")).lower() or "security" in str(r.get("Section", "")).lower()}
            for r in rows or [] if r.get("Package")]


async def from_proxmox(svc: Service, clients: HttpClients) -> list[dict]:
    integ = build(svc, clients)
    try:
        nodes = [r.get("node") for r in await integ.resources() if r.get("type") == "node" and r.get("status") == "online"]
    except IntegrationError as e:
        return [target(f"pve:{svc.id}", svc.name, "node", svc.id, error=str(e))]
    out = []
    for node in sorted(nodes):
        try:
            rows = await integ.get(f"/nodes/{node}/apt/update")
            out.append(target(f"pve:{svc.id}:{node}", node, "node", svc.id, _api_packages(rows)))
        except IntegrationError as e:
            msg = str(e)
            if "Geweigerd" in msg:
                msg = "Het API-token mag de updates niet lezen (recht Sys.Modify op /nodes nodig)"
            out.append(target(f"pve:{svc.id}:{node}", node, "node", svc.id, error=msg))
    return out


async def from_pbs(svc: Service, clients: HttpClients) -> list[dict]:
    try:
        rows = await build(svc, clients).get("/nodes/localhost/apt/update")
        return [target(f"pbs:{svc.id}", svc.name, "pbs", svc.id, _api_packages(rows))]
    except IntegrationError as e:
        msg = str(e)
        if "Geweigerd" in msg:
            msg = "Het API-token mag de updates niet lezen (recht Sys.Audit op /system nodig)"
        return [target(f"pbs:{svc.id}", svc.name, "pbs", svc.id, error=msg)]


async def from_portainer(svc: Service, clients: HttpClients) -> list[dict]:
    integ = build(svc, clients)
    out = []
    try:
        envs = [e for e in await integ.envs() if e.get("Status") == 1]
    except IntegrationError as e:
        return [target(f"docker:{svc.id}", svc.name, "docker", svc.id, error=str(e))]
    sem = asyncio.Semaphore(4)
    for env in envs:
        name = env.get("Name") or f"omgeving {env.get('Id')}"
        try:
            containers = [c for c in await integ.containers(env["Id"]) if c.get("State") == "running"][:80]
        except IntegrationError as e:
            out.append(target(f"docker:{svc.id}:{env.get('Id')}", name, "docker", svc.id, error=str(e)))
            continue

        async def status(c: dict) -> str | None:
            async with sem:
                try:
                    r = await integ.get(f"/docker/{env['Id']}/containers/{c.get('Id')}/image_status")
                    return str((r or {}).get("Status") or "")
                except IntegrationError:
                    return None

        states = await asyncio.gather(*(status(c) for c in containers))
        if containers and all(s is None for s in states):
            out.append(target(f"docker:{svc.id}:{env.get('Id')}", name, "docker", svc.id,
                              error="Portainer meldt geen image-status (nodig: Portainer 2.20 of nieuwer)"))
            continue
        old = [{"n": (c.get("Names") or ["/?"])[0].lstrip("/"), "to": c.get("Image"), "sec": False}
               for c, s in zip(containers, states) if s == "outdated"]
        out.append(target(f"docker:{svc.id}:{env.get('Id')}", name, "docker", svc.id, old))
    return out


async def from_ssh(h: SshHost, private_key: str | None) -> list[dict]:
    key = f"ssh:{h.id}"
    if not h.host_key:
        return [target(key, h.name, "host", h.service_id,
                       error="Open eerst één keer een terminal naar deze host om de hostsleutel te bevestigen")]
    client_key = asyncssh.import_private_key(decrypt(private_key)) if private_key else None
    command = "sh -s" if h.username == "root" else "sudo -n sh -s"
    try:
        async with asyncio.timeout(SSH_TIMEOUT):
            async with asyncssh.connect(
                h.host, port=h.port, username=h.username,
                known_hosts=([asyncssh.import_public_key(h.host_key)], [], []),
                client_keys=[client_key] if client_key else None,
                password=decrypt(h.password) if h.password else None,
                agent_path=None, config=None, connect_timeout=10,
            ) as conn:
                result = await conn.run(command, input=script(h.updates == "cts"), check=False)
    except asyncssh.HostKeyNotVerifiable:
        return [target(key, h.name, "host", h.service_id, error="Hostsleutel klopt niet meer, verbinding geweigerd")]
    except (OSError, asyncssh.Error, TimeoutError) as e:
        return [target(key, h.name, "host", h.service_id, error=f"SSH mislukt: {getattr(e, 'reason', None) or e}")]
    out = []
    for kind, name, packages in parse_output(str(result.stdout or "")):
        if kind == "host":
            out.append(target(key, h.name, "host", h.service_id, packages,
                              error="Geen apt of apk gevonden" if packages is None else None))
        elif packages is not None:
            vmid, _, hostname = (name or "").partition(" ")
            out.append(target(f"{key}:ct:{vmid}", hostname or f"CT {vmid}", "ct", None, packages,
                              vmid=vmid, node=h.name))
    if not out:
        out.append(target(key, h.name, "host", h.service_id, error=(str(result.stderr or "") or "Geen uitvoer")[-300:]))
    return out


async def collect(db: AsyncSession, clients: HttpClients) -> list[dict]:
    services = (await db.execute(select(Service).where(
        Service.type.in_(("proxmox", "proxmoxbackupserver", "portainer"))))).scalars().all()
    hosts = (await db.execute(select(SshHost).where(SshHost.updates.in_(("host", "cts"))))).scalars().all()
    keys = {k.id: k.private_key for k in (await db.execute(select(SshKey))).scalars()}
    fetch = {"proxmox": from_proxmox, "proxmoxbackupserver": from_pbs, "portainer": from_portainer}
    jobs = [fetch[s.type](s, clients) for s in services] + [from_ssh(h, keys.get(h.key_id)) for h in hosts]
    names = [s.name for s in services] + [h.name for h in hosts]
    out: list[dict] = []
    seen_nodes: set[str] = set()
    for name, r in zip(names, await asyncio.gather(*jobs, return_exceptions=True)):
        if isinstance(r, BaseException):
            log.warning("updates van %s mislukt: %s", name, r)
            out.append(target(f"err:{name}", name, "host", None, error=type(r).__name__))
            continue
        for t in r:
            # Meerdere Proxmox-tegels op dezelfde cluster: elke node maar één keer.
            if t["kind"] == "node" and not t["error"]:
                if t["name"] in seen_nodes:
                    continue
                seen_nodes.add(t["name"])
            out.append(t)
    return out


def record_changes(db: AsyncSession, old: dict[str, dict], new: list[dict]) -> None:
    """Minder updates dan vorige keer = er is bijgewerkt: één regel op de tijdlijn per machine."""
    for t in new:
        before = old.get(t["key"])
        if not before or t["error"] or before.get("error") or t["count"] >= before.get("count", 0):
            continue
        n = before["count"] - t["count"]
        if t["kind"] == "docker":
            title = f"{t['name']}: {n} container{'s' if n > 1 else ''} op een nieuw image"
        else:
            title = f"{t['name']}: {n} update{'s' if n > 1 else ''} geïnstalleerd"
        gone = {p["n"] for p in before.get("packages", [])} - {p["n"] for p in t["packages"]}
        body = ", ".join(sorted(gone)[:25]) + (" …" if len(gone) > 25 else "") if gone else None
        event(db, "updates", title, body, level="ok", service_id=t.get("service_id"), data={"count": n})


async def run_updates(db: AsyncSession, clients: HttpClients) -> dict:
    state = await db.get(AppState, KEY)
    old = {t["key"]: t for t in (state.value.get("targets", []) if state else [])}
    new = await collect(db, clients)
    record_changes(db, old, new)
    value = {"checked_at": datetime.now(timezone.utc).isoformat(), "targets": new}
    state = await db.get(AppState, KEY)
    if state:
        state.value = value
    else:
        db.add(AppState(key=KEY, value=value))
    return value
