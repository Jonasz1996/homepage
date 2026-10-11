"""Zelfherstel: "als Plex 3 checks na elkaar down is, herstart CT 105", met een limiet per uur.

Acties:
- een actie van een integratie, dezelfde als de knoppen in het mini dashboard (Proxmox: herstart of start een
  VM/CT, Portainer: herstart een container, ...). Een herstart van een uitgeschakelde VM/CT wordt een start.
- via SSH: `systemctl restart <unit>` of `docker restart <container>` op een host uit de terminal.

Proefmodus: plan_rule() toont wat een regel zou doen (welke machine, welke call of welk commando, als wie) en welke
voorwaarden nu wel of niet voldaan zijn. De stappen komen uit dezelfde prepare() die de actie echt uitvoert, de
voorwaarden uit dezelfde gates() die check() gebruikt. Een regel op "alleen proef" gaat automatisch af zoals altijd
(zelfde wachttijd en limiet), maar zet alleen op de tijdlijn wat hij zou doen: geen actie, geen melding.
"""

import logging
import math
import re
import shlex
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .. import proef
from ..deps import event, notify
from ..integrations import Integration, IntegrationError, build
from ..integrations.adguard import AdGuard
from ..integrations.portainer import Portainer
from ..integrations.proxmox import Proxmox
from ..models import HealRule, Service, ServiceState, SshHost
from ..ssh_exec import SshFail, command, connect, run
from ..ssh_login import Login, defaults, login_for
from .checks import HttpClients
from .engine import in_maintenance

log = logging.getLogger("homepage.heal")

COOLDOWN = timedelta(minutes=10)
NAME_RE = re.compile(r"^[A-Za-z0-9@._:\-]{1,120}$")
SSH_OPS = {"systemctl": "systemctl restart {}", "docker": "docker restart {}"}
# Voor de proef: alleen kijken hoe de dienst of container er nu bij staat.
SSH_STATUS = {"systemctl": "systemctl is-active {}", "docker": "docker inspect -f '{{{{.State.Status}}}}' {}"}
SSH_TIMEOUT = 180
PROBE_TIMEOUT = 30
# De voorwaarde "niet te vaak": wie die niet haalt, staat op pauze (met één melding, zie check()).
LIMIT = "limiet"
# Fouten bij het voorbereiden of uitvoeren die we als "mislukt" tonen.
ERRORS = (IntegrationError, SshFail, OSError, ValueError)


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


@dataclass
class Gates:
    """De voorwaarden van check() voor één regel, als proef-checks in dezelfde volgorde."""

    checks: list[dict]
    # De eerste voorwaarde die niet voldaan is; None: de regel gaat nu af.
    blocked: str | None
    # Wanneer de regel het afgelopen uur afging.
    fired: list[str]


def _minutes(d: timedelta) -> int:
    return max(1, math.ceil(d.total_seconds() / 60))


def gates(rule: HealRule, fail_count: int, quiet: bool, maintenance: bool, now: datetime) -> Gates:
    """Gaat de regel nu af? Zonder database en zonder netwerk: check() beslist hiermee, en de proef toont hetzelfde."""
    fired = [t for t in (rule.fired or []) if now - datetime.fromisoformat(t) < timedelta(hours=1)]
    last = rule.last_at.replace(tzinfo=rule.last_at.tzinfo or timezone.utc) if rule.last_at else None
    left = COOLDOWN - (now - last) if last else timedelta(0)
    items = [
        ("down", fail_count > 0, "service faalt",
         f"{fail_count}× na elkaar mislukt" if fail_count else "de laatste check lukte"),
        # quiet: iets waar deze service van afhangt ligt plat (of een massastoring); herstarten helpt dan niet.
        ("stil", not quiet, "niets waar ze van afhangt ligt plat",
         "iets waar ze van afhangt ligt plat, of er is een massastoring" if quiet else None),
        # Onderhoud (gepland of met de hand): de storing telt niet, dus ook niet ingrijpen.
        ("onderhoud", not maintenance, "niet in onderhoud",
         "deze service of iets waar ze van afhangt is in onderhoud" if maintenance else None),
        ("uit", bool(rule.enabled), "regel staat aan", None if rule.enabled else "de regel staat uit"),
        ("na", fail_count >= rule.after, f"{rule.after}× na elkaar down", f"nu {fail_count}×"),
        ("wachttijd", left <= timedelta(0), f"minstens {int(COOLDOWN.total_seconds() // 60)} min ertussen",
         f"nog {_minutes(left)} min" if left > timedelta(0)
         else f"vorige keer {int((now - last).total_seconds() // 60)} min geleden" if last else "nog niet afgegaan"),
        (LIMIT, len(fired) < rule.max_per_hour, f"hoogstens {rule.max_per_hour}× per uur",
         f"{len(fired)}× het afgelopen uur"),
    ]
    blocked = next((key for key, ok, *_ in items if not ok), None)
    return Gates([proef.check(what, ok, detail) for _, ok, what, detail in items], blocked, fired)


@dataclass
class Prepared:
    """Een actie klaar om uit te voeren. steps (voor de proef) en go (het echte werk) komen uit dezelfde waarden, zodat
    de proef niet kan afwijken van wat er gebeurt. probe kijkt alleen (de stand via de API of via SSH): extra checks,
    en de stappen opnieuw als de stand de actie verandert (een herstart van iets dat uit staat wordt een start)."""

    steps: list[dict]
    checks: list[dict]
    go: Callable[[], Awaitable[str]]
    probe: Callable[[], Awaitable[tuple[list[dict], list[dict] | None]]]


async def proxmox_act(integ: Proxmox, act: str, params: dict) -> tuple[str, dict | None]:
    """Een herstart (of afsluiten) van een VM/CT die uit staat lukt niet: dan starten we hem. Leest de stand via de
    API (alleen lezen). Geeft de actie terug, en de VM/CT zoals Proxmox hem kent (None: niet gevonden)."""
    vmid = int(params["vmid"])
    guest = next((r for r in await integ.resources() if r.get("vmid") == vmid), None)
    if act in ("reboot", "shutdown") and guest is not None and guest.get("status") != "running":
        act = "start"
    return act, guest


def _api_who(integ: Integration, write: bool) -> str:
    """Als wie de call gaat, zonder geheim: het token-ID bij Proxmox, de gebruiker bij AdGuard."""
    if isinstance(integ, Proxmox):
        return proef.api_who(integ.token_id(write))
    if isinstance(integ, AdGuard):
        return f"gebruiker {integ.secrets.get('username') or '?'}"
    return "API-sleutel"


def _api_steps(integ: Integration, machine: str, act: str, params: dict, decides: bool,
               final: str | None) -> list[dict]:
    """De calls van go_integration(), uit dezelfde bouwstenen (action_request, resources_request).
    final: de actie na het lezen van de stand; None: nog niet gelezen, dan beide mogelijkheden."""
    via = f"{integ.name}-api" if f"{integ.name}-api" in proef.VIA else "api"
    who = _api_who(integ, write=True)

    def call(a: str, **kw) -> dict:
        method, path, body = integ.action_request(a, params)
        return proef.step(machine, via, f"{method} {integ.base}{path}", who=who, data=body, **kw)

    first = call(act)
    if not decides:
        return [first]
    vmid = int(params["vmid"])
    method, path = integ.resources_request()
    out = [proef.step(machine, via, f"{method} {integ.base}{path}", who=_api_who(integ, write=False),
                      note=f"alleen lezen: draait {vmid}? Een {act} van iets dat uit staat wordt een start")]
    if final is None:
        out += [call(act, when=f"als {vmid} draait"), call("start", when=f"als {vmid} uit staat")]
    else:
        out.append(call(final, note=f"{vmid} staat uit: start in plaats van {act}" if final != act else None))
    return out


async def _probe_api(integ: Integration, act: str, params: dict, decides: bool,
                     steps: Callable[[str | None], list[dict]]) -> tuple[list[dict], list[dict] | None]:
    """Alleen lezen: bestaat het doel nog, en welke actie zou het dan precies worden."""
    try:
        if isinstance(integ, Proxmox) and params.get("vmid"):
            final, guest = await proxmox_act(integ, act, params)
            vmid, node = int(params["vmid"]), params.get("node")
            if guest is None:
                return [proef.check(f"VM/CT {vmid} bestaat", False, "niet gevonden in de Proxmox-API "
                                    "(verwijderd, of een node die niet meetelt?)")], None
            out = [proef.check(f"{'VM' if guest.get('type') == 'qemu' else 'CT'} {vmid} ({guest.get('name') or '?'})",
                               True, f"staat nu {guest.get('status') or '?'} op {guest.get('node') or '?'}")]
            if node and guest.get("node") and guest["node"] != node:
                out.append(proef.check("juiste node", False, f"{vmid} staat op {guest['node']}, de regel stuurt "
                                                             f"naar {node}: maak de regel opnieuw"))
            if final == "start" and guest.get("status") == "running":
                out.append(proef.check("start", False, f"{vmid} draait al: Proxmox weigert dan een start"))
            return out, steps(final) if decides else None
        if isinstance(integ, Portainer):
            try:
                info = await integ.inspect(params)
            except IntegrationError as e:
                if "HTTP 404" not in str(e):
                    raise
                return [proef.check(f"container {params.get('name') or ''}".strip(), False,
                                    f"id {integ.target(params)[1][:12]} bestaat niet meer: een container die opnieuw "
                                    "gemaakt is (update, compose) krijgt een ander id; maak de regel opnieuw")], None
            return [proef.check(f"container {str(info.get('Name') or params.get('name') or '').lstrip('/')}".strip(),
                                True, f"staat nu {(info.get('State') or {}).get('Status') or '?'}")], None
    except ERRORS as e:
        return [proef.check("de stand lezen", False, str(e))], None
    return [], None


def _last(text: str) -> str:
    return text.strip().splitlines()[-1][:200] if text.strip() else ""


async def _probe_ssh(h: SshHost, login: Login, op: str, name: str) -> list[dict]:
    """Alleen kijken: aanmelden, sudo zonder wachtwoord (wie geen root is) en de stand van de dienst of container."""
    status = SSH_STATUS[op].format(shlex.quote(name))
    out: list[dict] = []
    try:
        async with connect(h, login) as conn:
            out.append(proef.check(f"SSH naar {h.name}", True, f"aangemeld als {login.username}"))
            if login.username != "root":
                # Hetzelfde "sudo -n sh -c" als het echte commando, met een commando dat niets doet.
                rc, o, e = await run(conn, "true", login, timeout=PROBE_TIMEOUT)
                out.append(proef.check("sudo -n zonder wachtwoord", rc == 0,
                                       None if rc == 0 else _last(e) or _last(o) or f"exitcode {rc}"))
            rc, o, e = await run(conn, status, login, timeout=PROBE_TIMEOUT)
            said = _last(o) or _last(e)
            if rc == 0:
                out.append(proef.check(f"nu: {status}", True, said or "ok"))
            elif op == "systemctl" and said in ("inactive", "failed", "activating", "deactivating", "reloading"):
                out.append(proef.check(f"nu: {status}", None, f"{said}: de herstart zet hem weer aan"))
            else:
                out.append(proef.check(f"nu: {status}", False, said or f"exitcode {rc}"))
    except SshFail as e:
        out.append(proef.check(f"SSH naar {h.name}" if not out else "de stand lezen", False, str(e)))
    return out


async def prepare(db: AsyncSession, action: dict, http: HttpClients) -> Prepared:
    """Leest uit de database wat de actie nodig heeft en geeft de stappen (voor de proef) en een functie die ze
    uitvoert zonder de database, zodat de sessie niet open blijft tijdens een trage herstart. Doet zelf geen netwerk.
    Gooit IntegrationError of SshFail."""
    if action["kind"] == "integration":
        svc = await db.get(Service, action["service_id"])
        if svc is None:
            raise IntegrationError("De tegel van deze actie bestaat niet meer")
        integ = build(svc, http)
        act, params = action["action"], dict(action.get("params") or {})
        # Een herstart van iets dat uit staat lukt niet: dan starten we het (de stand lezen we vlak ervoor).
        decides = isinstance(integ, Proxmox) and act in ("reboot", "shutdown") and bool(params.get("vmid"))
        machine = f"{svc.name} ({integ.base})"

        def steps(final: str | None = None) -> list[dict]:
            return _api_steps(integ, machine, act, params, decides, final)

        async def go_integration() -> str:
            final = (await proxmox_act(integ, act, params))[0] if decides else act
            return await integ.action(final, params)

        async def probe() -> tuple[list[dict], list[dict] | None]:
            return await _probe_api(integ, act, params, decides, steps)
        return Prepared(steps(), [], go_integration, probe)
    h = await db.get(SshHost, action["host_id"])
    if h is None:
        raise SshFail("De SSH-host van deze actie bestaat niet meer")
    login = await login_for(db, h, await defaults(db))
    cmd = SSH_OPS[action["op"]].format(shlex.quote(action["name"]))
    # Precies wat run() verstuurt (met sudo -n voor wie geen root is).
    step = proef.step(proef.ssh_machine(h, login), "ssh", command(cmd, login), who=proef.ssh_who(login),
                      wait=f"hoogstens {SSH_TIMEOUT // 60} min",
                      on_fail="exitcode niet 0: de regel meldt de laatste regel van de foutmelding")
    checks = [proef.check("hostsleutel bevestigd", bool(h.host_key),
                          None if h.host_key else "open één keer een terminal naar deze host"),
              proef.check(f"aanmelden als {login.username}", True if login.key or login.password else None,
                          "met sleutel" if login.key else "met wachtwoord" if login.password
                          else "geen sleutel of wachtwoord ingesteld (⚙ standaard in de terminal)")]

    async def go_ssh() -> str:
        async with connect(h, login) as conn:
            rc, out, err = await run(conn, cmd, login, timeout=SSH_TIMEOUT)
        if rc != 0:
            raise SshFail((err or out).strip().splitlines()[-1][:200] if (err or out).strip() else f"exitcode {rc}")
        return f"{cmd} op {h.name}"

    async def probe() -> tuple[list[dict], list[dict] | None]:
        return await _probe_ssh(h, login, action["op"], action["name"]), None
    return Prepared([step], checks, go_ssh, probe)


def rule_plan(rule: HealRule, name: str, g: Gates, prep: Prepared | Exception, now: datetime,
              probed: list[dict] | None = None, steps: list[dict] | None = None) -> dict:
    """Het plan van een regel: de voorwaarden, de stappen uit prepare() (dezelfde waarden als de echte uitvoering)
    en wat erna volgt. probed/steps: wat de probe las, en de stappen zoals ze daarna zijn."""
    checks = list(g.checks)
    if isinstance(prep, Exception):
        checks.append(proef.check("actie voorbereiden", False, str(prep)))
        steps = []
    else:
        checks += prep.checks + (probed or [])
        steps = prep.steps if steps is None else steps
    warnings = []
    if g.blocked:
        c = next(c for c in g.checks if c["ok"] is False)
        warnings.append(f"Nu zou de regel niet afgaan: {c['what']}" + (f" ({c['detail']})" if c["detail"] else "")
                        + ". De stappen zijn wat ze doet als ze afgaat.")
    if rule.dry_run:
        warnings.append("Alleen proef: ook automatisch voert deze regel niets uit, ze zet alleen op de tijdlijn wat ze "
                        "zou doen.")
    after = [f"melding \"Zelfherstel: {name} was …× down\" of \"Zelfherstel voor {name} mislukt\"",
             f"telt mee voor hoogstens {rule.max_per_hour}× per uur, met minstens "
             f"{int(COOLDOWN.total_seconds() // 60)} min ertussen"]
    return proef.plan(f"Zelfherstel voor {name}: {describe(rule.action)}", steps, checks=checks, after=after,
                      warnings=warnings, now=now, rule=rule.id, would_fire=g.blocked is None)


def _limit_plan(rule: HealRule, name: str, g: Gates, now: datetime) -> dict:
    return proef.plan(f"Zelfherstel voor {name} gepauzeerd", [], checks=g.checks, now=now, rule=rule.id,
                      skipped=[proef.skip(describe(rule.action), f"al {len(g.fired)}× geprobeerd het afgelopen uur")],
                      after=[f"een echte regel stuurt nu één foutmelding \"Zelfherstel voor {name} gepauzeerd\""])


async def plan_rule(db: AsyncSession, rule: HealRule, http: HttpClients, probe: bool = True,
                    now: datetime | None = None) -> dict:
    """Proef: wat zou deze regel doen, en zou ze nu afgaan? Voert de actie nooit uit en schrijft niets weg (ook de
    regel zelf niet). probe: ook de stand lezen (de Proxmox-API, de container in Portainer, of de dienst via SSH),
    alleen lezen; de transactie is dan al afgesloten."""
    now = now or datetime.now(timezone.utc)
    svc = await db.get(Service, rule.service_id)
    state = await db.get(ServiceState, rule.service_id)
    maint = svc is not None and await in_maintenance(db, svc, now)
    g = gates(rule, state.fail_count if state else 0, bool(state and state.quiet), maint, now)
    try:
        prep: Prepared | Exception = await prepare(db, rule.action, http)
    except ERRORS as e:
        prep = e
    # Geen transactie open tijdens het kijken op de machine (via SSH tot een halve minuut).
    await db.commit()
    probed, steps = [], None
    if probe and isinstance(prep, Prepared):
        probed, steps = await prep.probe()
    return rule_plan(rule, svc.name if svc else "?", g, prep, now, probed, steps)


async def check(maker: async_sessionmaker, service_id: int, http: HttpClients,
                now: datetime | None = None) -> str | None:
    """Na elke check van een service die faalt: moet er een regel afgaan? Geeft het resultaat terug.

    In drie stappen, zodat er geen databaseverbinding vastgehouden wordt tijdens de herstart zelf: beslissen en
    voorbereiden, uitvoeren, resultaat wegschrijven. Een regel op alleen proef beslist en telt mee zoals altijd, maar
    zet in de eerste stap alleen op de tijdlijn wat hij zou doen."""
    now = now or datetime.now(timezone.utc)
    todo: list[tuple[int, dict, Callable[[], Awaitable[str]] | Exception]] = []
    async with maker() as db:
        state = await db.get(ServiceState, service_id)
        if state is None or not state.fail_count or state.quiet:
            # Snel weg (gates() kijkt hetzelfde na): geen storing, of iets waar deze service van afhangt ligt plat.
            return None
        rules = (await db.execute(select(HealRule).where(HealRule.service_id == service_id,
                                                         HealRule.enabled.is_(True))
                                  .order_by(HealRule.id))).scalars().all()
        if not rules:
            return None
        svc = await db.get(Service, service_id)
        name, fails = svc.name, state.fail_count
        maint = await in_maintenance(db, svc, now)
        result = None
        for rule in rules:
            g = gates(rule, fails, state.quiet, maint, now)
            if g.blocked == LIMIT:
                if not (rule.last_result or "").startswith("limiet"):
                    rule.last_result = (f"limiet bereikt{' (proef)' if rule.dry_run else ''}: "
                                        f"al {len(g.fired)}× het afgelopen uur")
                    if rule.dry_run:
                        proef.record(db, "actie", f"Zelfherstel voor {name} gepauzeerd",
                                     _limit_plan(rule, name, g, now), service_id)
                    else:
                        notify(db, f"Zelfherstel voor {name} gepauzeerd",
                               f"Al {len(g.fired)}× geprobeerd het afgelopen uur ({describe(rule.action)}); "
                               "kijk het zelf na.", level="err", source="herstel", service_id=service_id)
                continue
            if g.blocked:
                continue
            rule.fired = g.fired + [now.isoformat()]
            rule.last_at = now
            try:
                prep: Prepared | Exception = await prepare(db, rule.action, http)
            except ERRORS as e:
                prep = e
            if rule.dry_run:
                # Alleen proef: zelfde voorwaarden en dezelfde telling (zo zie je ook de wachttijd en de limiet), maar
                # niets uitvoeren en niets melden.
                what = describe(rule.action)
                rule.last_result = (f"proef: {what} zou mislukken: {prep}" if isinstance(prep, Exception)
                                    else f"proef: {what}, niet uitgevoerd (zie de tijdlijn)")
                proef.record(db, "actie", f"Zelfherstel: {name} was {fails}× down",
                             rule_plan(rule, name, g, prep, now), service_id)
                result = rule.last_result
                continue
            todo.append((rule.id, dict(rule.action), prep if isinstance(prep, Exception) else prep.go))
        await db.commit()
    if not todo:
        return result

    done = []
    for rule_id, action, go in todo:
        try:
            if isinstance(go, Exception):
                raise go
            done.append((rule_id, action, f"ok: {await go()}", None))
        except ERRORS as e:
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
    """De knop "nu testen": de actie echt uitvoeren, los van de voorwaarden en de limiet (ook bij alleen proef)."""
    prep = await prepare(db, rule.action, http)
    # Geen transactie open tijdens de herstart zelf (via SSH tot drie minuten).
    await db.commit()
    msg = await prep.go()
    event(db, "actie", f"Zelfherstel getest: {describe(rule.action)}", msg, level="info", service_id=rule.service_id)
    return msg
