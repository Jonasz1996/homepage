"""Zelfherstel: "als Plex 3 checks na elkaar down is, herstart CT 105", met een limiet per uur.

Acties:
- een actie van een integratie, dezelfde als de knoppen in het mini dashboard (Proxmox: herstart of start een
  VM/CT, Portainer: herstart een container, ...). Een herstart van een uitgeschakelde VM/CT wordt een start.
- via SSH: `systemctl restart <unit>` of `docker restart <container>` op een host uit de terminal.
"""

import logging
import re
import shlex
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..deps import event, notify
from ..integrations import IntegrationError, build
from ..models import HealRule, Service, ServiceState, SshHost
from ..ssh_exec import SshFail, connect, run
from ..ssh_login import defaults, login_for
from .checks import HttpClients

log = logging.getLogger("homepage.heal")

COOLDOWN = timedelta(minutes=10)
NAME_RE = re.compile(r"^[A-Za-z0-9@._:\-]{1,120}$")
SSH_OPS = {"systemctl": "systemctl restart {}", "docker": "docker restart {}"}


def describe(action: dict) -> str:
    if action.get("kind") == "ssh":
        return f"{'herstart dienst' if action.get('op') == 'systemctl' else 'herstart container'} {action.get('name')}" + (
            f" op {action['host_name']}" if action.get("host_name") else "")
    return action.get("label") or action.get("action") or "actie"


async def validate(db: AsyncSession, action: dict) -> dict:
    """Controleert een actie en geeft een opgeschoonde versie terug. Gooit ValueError."""
    kind = action.get("kind")
    if kind == "integration":
        svc = await db.get(Service, int(action.get("service_id") or 0))
        if svc is None:
            raise ValueError("Tegel voor de actie niet gevonden")
        from ..integrations import REGISTRY
        cls = REGISTRY.get(svc.type)
        if cls is None or action.get("action") not in cls.actions:
            raise ValueError(f"{svc.name} kent de actie '{action.get('action')}' niet")
        params = action.get("params") or {}
        if not isinstance(params, dict) or len(str(params)) > 500:
            raise ValueError("Ongeldige parameters")
        return {"kind": kind, "service_id": svc.id, "service": svc.name, "action": action["action"], "params": params,
                "label": str(action.get("label") or action["action"])[:120]}
    if kind == "ssh":
        h = await db.get(SshHost, int(action.get("host_id") or 0))
        if h is None:
            raise ValueError("SSH-host niet gevonden")
        if action.get("op") not in SSH_OPS:
            raise ValueError("Kies systemctl of docker")
        name = str(action.get("name") or "")
        if not NAME_RE.match(name):
            raise ValueError("Ongeldige naam van dienst of container")
        return {"kind": kind, "host_id": h.id, "host_name": h.name, "op": action["op"], "name": name}
    raise ValueError("Onbekend soort actie")


async def prepare(db: AsyncSession, action: dict, http: HttpClients) -> Callable[[], Awaitable[str]]:
    """Leest uit de database wat de actie nodig heeft en geeft een functie terug die ze uitvoert zonder de database,
    zodat de sessie niet open blijft tijdens een trage herstart. Gooit IntegrationError of SshFail."""
    if action["kind"] == "integration":
        svc = await db.get(Service, action["service_id"])
        if svc is None:
            raise IntegrationError("De tegel van deze actie bestaat niet meer")
        integ = build(svc, http)
        stype = svc.type

        async def go_integration() -> str:
            act, params = action["action"], dict(action.get("params") or {})
            if stype == "proxmox" and act in ("reboot", "shutdown") and params.get("vmid"):
                # Een herstart van iets dat uit staat lukt niet: dan starten we het.
                for r in await integ.resources():
                    if r.get("vmid") == int(params["vmid"]) and r.get("status") != "running":
                        act = "start"
            return await integ.action(act, params)
        return go_integration
    h = await db.get(SshHost, action["host_id"])
    if h is None:
        raise SshFail("De SSH-host van deze actie bestaat niet meer")
    login = await login_for(db, h, await defaults(db))
    cmd = SSH_OPS[action["op"]].format(shlex.quote(action["name"]))

    async def go_ssh() -> str:
        async with connect(h, login) as conn:
            rc, out, err = await run(conn, cmd, login, timeout=180)
        if rc != 0:
            raise SshFail((err or out).strip().splitlines()[-1][:200] if (err or out).strip() else f"exitcode {rc}")
        return f"{cmd} op {h.name}"
    return go_ssh


async def perform(db: AsyncSession, action: dict, http: HttpClients) -> str:
    """Voert de actie uit en geeft een korte beschrijving terug. Gooit IntegrationError of SshFail."""
    return await (await prepare(db, action, http))()


async def check(maker: async_sessionmaker, service_id: int, http: HttpClients,
                now: datetime | None = None) -> str | None:
    """Na elke check van een service die faalt: moet er een regel afgaan? Geeft het resultaat terug.

    In drie stappen, zodat er geen databaseverbinding vastgehouden wordt tijdens de herstart zelf: beslissen en
    voorbereiden, uitvoeren, resultaat wegschrijven."""
    now = now or datetime.now(timezone.utc)
    todo: list[tuple[int, dict, Callable[[], Awaitable[str]] | Exception]] = []
    async with maker() as db:
        state = await db.get(ServiceState, service_id)
        if state is None or not state.fail_count or state.quiet:
            # quiet: iets waar deze service van afhangt ligt plat; herstarten helpt dan niet.
            return None
        rules = (await db.execute(select(HealRule).where(HealRule.service_id == service_id,
                                                         HealRule.enabled.is_(True)))).scalars().all()
        svc = await db.get(Service, service_id)
        name, fails = svc.name, state.fail_count
        result = None
        for rule in rules:
            if state.fail_count < rule.after:
                continue
            last = rule.last_at.replace(tzinfo=rule.last_at.tzinfo or timezone.utc) if rule.last_at else None
            if last and now - last < COOLDOWN:
                continue
            fired = [t for t in (rule.fired or []) if now - datetime.fromisoformat(t) < timedelta(hours=1)]
            if len(fired) >= rule.max_per_hour:
                if not (rule.last_result or "").startswith("limiet"):
                    rule.last_result = f"limiet bereikt: al {len(fired)}× het afgelopen uur"
                    notify(db, f"Zelfherstel voor {svc.name} gepauzeerd",
                           f"Al {len(fired)}× geprobeerd het afgelopen uur ({describe(rule.action)}); kijk het zelf na.",
                           level="err", source="herstel", service_id=service_id)
                continue
            rule.fired = fired + [now.isoformat()]
            rule.last_at = now
            try:
                go = await prepare(db, rule.action, http)
            except (IntegrationError, SshFail, OSError, ValueError) as e:
                go = e
            todo.append((rule.id, dict(rule.action), go))
        await db.commit()
    if not todo:
        return result

    done = []
    for rule_id, action, go in todo:
        try:
            if isinstance(go, Exception):
                raise go
            done.append((rule_id, action, f"ok: {await go()}", None))
        except (IntegrationError, SshFail, OSError, ValueError) as e:
            done.append((rule_id, action, f"mislukt: {e}", e))

    async with maker() as db:
        for rule_id, action, res, err in done:
            rule = await db.get(HealRule, rule_id)
            if rule is not None:
                rule.last_result = res
            if err is None:
                notify(db, f"Zelfherstel: {name} was {fails}× down", f"{describe(action)} — {res[4:]}",
                       level="warn", source="herstel", service_id=service_id,
                       data={"rule": rule_id, "action": describe(action)})
            else:
                notify(db, f"Zelfherstel voor {name} mislukt", f"{describe(action)}: {err}", level="err",
                       source="herstel", service_id=service_id)
            result = res
        await db.commit()
    return result


async def test_rule(db: AsyncSession, rule: HealRule, http: HttpClients) -> str:
    msg = await perform(db, rule.action, http)
    event(db, "actie", f"Zelfherstel getest: {describe(rule.action)}", msg, level="info", service_id=rule.service_id)
    return msg
