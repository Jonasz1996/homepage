"""Instellingen-checklist (aandacht → instellingen): per functie of ze werkt, half ingesteld is of nog niet.

Veel functies werken pas als Jonas iets invult: een token, een webhook, een MAC-adres. Per rij: state ok, half of
none, wat er ontbreekt (todo) en welk venster het oplost (fix). optional: "nog niet" is dan geen probleem.
"""

import asyncio
import hashlib
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy import distinct, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .health import scan as hw, security
from .integrations import IntegrationError, build
from .models import AppState, CronJob, LogEntry, PushMonitor, Service, ServiceState, SshHost, WebhookSource
from .monitoring import (cluster, configs, coverage, devices, pbssync, restoretest, routes, upgrade, watchdog, webpush,
                         zabbix as zbx)
from .monitoring.engine import active
from .ssh_login import defaults as ssh_defaults
from .ssh_pin import STATE_KEY as PIN_KEY

PUSH_URL = re.compile(r"/api/push/([A-Za-z0-9_-]{16,})")
GROUPS = (("proxmox", "Proxmox en back-ups"), ("netwerk", "Netwerk"), ("monitoring", "Monitoring en meldingen"),
          ("ssh", "SSH, cron, updates en logs"), ("beveiliging", "Beveiliging"))
PRIV_TIMEOUT = 8
READ_PRIVS = ("Sys.Audit", "VM.Audit", "Datastore.Audit")
# Wat elke functie van het actietoken (of het enige token) vraagt.
ACT_PRIVS = (
    ("VM's aan- en uitzetten", ("VM.PowerMgmt",)),
    ("de lijst met updates", ("Sys.Modify",)),
    ("een snapshot voor updates en snapshots verwijderen", ("VM.Snapshot", "VM.Snapshot.Rollback")),
)
RESTORE_PRIVS = ("VM.Allocate", "VM.Config.Disk", "VM.Config.Network", "VM.Config.Options", "Datastore.AllocateSpace")


def row(key: str, group: str, title: str, state: str, text: str, todo: list[str] | None = None,
        fix: dict | None = None, optional: bool = False) -> dict:
    return {"key": key, "group": group, "title": title, "state": state, "text": text, "todo": todo or [], "fix": fix,
            "optional": optional}


async def _state(db: AsyncSession, key: str) -> dict:
    st = await db.get(AppState, key)
    return dict(st.value or {}) if st else {}


def _local(dt: datetime) -> str:
    return dt.replace(tzinfo=dt.tzinfo or timezone.utc).astimezone().strftime("%d/%m %H:%M")


def _list(names: list[str], n: int = 4) -> str:
    return ", ".join(names[:n]) + (f" en {len(names) - n} meer" if len(names) > n else "")


def _errors(svcs: list[Service], results: dict[int, dict]) -> list[str]:
    return [f"{s.name}: {results[s.id]['error']}" for s in svcs if "error" in (results.get(s.id) or {})]


def _integration(key: str, group: str, title: str, svcs: list[Service], results: dict[int, dict], none_text: str,
                 todo: list[str], ok_text: str, optional: bool = False, extra: list[str] | None = None) -> dict:
    """Een rij voor een integratie: nog geen tegel, een tegel waarvan de API een fout geeft, of in orde."""
    if not svcs:
        return row(key, group, title, "none", none_text, todo, {"window": "api"}, optional)
    errs = _errors(svcs, results) + (extra or [])
    fix = {"window": "detail", "service_id": svcs[0].id}
    if errs:
        return row(key, group, title, "half", "Ingesteld, maar niet alles werkt.", errs, fix, optional)
    return row(key, group, title, "ok", ok_text, fix=fix, optional=optional)


async def _privs(integ) -> tuple[set | None, set | None, str | None]:
    """(rechten van het leestoken, van het actietoken, fout). Met één token zijn beide hetzelfde."""
    try:
        read = await asyncio.wait_for(security._privs(integ), PRIV_TIMEOUT)
    except (IntegrationError, asyncio.TimeoutError) as e:
        return None, None, str(e) or "geen antwoord"
    if not integ.split:
        return read, read, None
    integ.secrets = {**integ.secrets, "username": integ.secrets["action_username"],
                     "password": integ.secrets["action_password"]}
    try:
        return read, await asyncio.wait_for(security._privs(integ), PRIV_TIMEOUT), None
    except (IntegrationError, asyncio.TimeoutError) as e:
        return read, None, f"actietoken: {e or 'geen antwoord'}"


async def proxmox(db: AsyncSession, clients, svcs: list[Service], results: dict[int, dict], restore_on: bool) -> dict:
    title = "Proxmox VE"
    if not svcs:
        return row("proxmox", "proxmox", title, "none", "Nog geen Proxmox-tegel of -API.",
                   ["Maak op een node een token aan (README → Proxmox-token) en zet het in API-beheer, of maak een "
                    "tegel van type proxmox."], {"window": "api"})
    todo = _errors(svcs, results)
    tokens = await security.proxmox_tokens(db, clients)
    split = any(i.split for _, i in tokens)
    for name, integ in tokens:
        read, act, err = await _privs(integ)
        if err:
            todo.append(f"{name}: rechten niet op te vragen ({err})")
            continue
        if read is not None and (miss := [p for p in READ_PRIVS if p not in read]):
            todo.append(f"{name}: het leestoken mist {', '.join(miss)} (geef het de rol PVEAuditor)")
        if act is None:
            continue
        for what, need in ACT_PRIVS + ((("de hersteltest", RESTORE_PRIVS),) if restore_on else ()):
            if miss := [p for p in need if p not in act]:
                todo.append(f"{name}: {what} kan niet, {'het actietoken' if integ.split else 'het token'} mist "
                            f"{', '.join(miss)}")
    if not tokens:
        todo.append("Er staat nog geen token op de tegel: vul username en password in (README).")
    elif not split and not todo:
        todo.append("Tip: een apart actietoken, zodat een gelekt leestoken niets kan uitzetten (README → Twee "
                    "Proxmox-tokens).")
        return row("proxmox", "proxmox", title, "ok", "Werkt, met één token voor alles.", todo, {"window": "api"})
    if todo:
        return row("proxmox", "proxmox", title, "half", "Werkt deels.", todo, {"window": "api"})
    return row("proxmox", "proxmox", title, "ok", "Werkt: leestoken voor monitoring, actietoken voor acties.",
               fix={"window": "api"})


async def restore(db: AsyncSession) -> dict:
    rt = await _state(db, restoretest.STATE_KEY)
    cfg = restoretest.settings(rt)
    title, fix = "Hersteltest van back-ups", {"window": "restoretest"}
    if not cfg["enabled"]:
        return row("restoretest", "proxmox", title, "none", "Staat uit: niemand kijkt na of je back-ups ook echt "
                   "terug te zetten zijn.", ["Zet hem aan in het venster hersteltest (Ctrl+K → hersteltest). Het "
                   "actietoken heeft dan extra rechten nodig (README)."], fix, optional=True)
    last = (rt.get("history") or [None])[0]
    when = f"elke maand op dag {cfg['day']} om {int(cfg['hour']):02d}:00"
    if last and not last.get("ok"):
        return row("restoretest", "proxmox", title, "half", f"Aan ({when}), maar de laatste test mislukte.",
                   [f"Bij {last.get('step')}: {last.get('error')}"], fix, optional=True)
    return row("restoretest", "proxmox", title, "ok", f"Aan, {when}; " + ("laatste test geslaagd." if last else
               "nog niet gelopen. Probeer ▶ nu testen."), fix=fix, optional=True)


async def homelab_rows(db: AsyncSession, has_pbs: bool) -> list[dict]:
    """Twee PBS'en die elkaar aanvullen, en een QDevice bij een even aantal stemmen."""
    out = []
    fix = {"window": "health", "tab": "backups"}
    cov = await _state(db, coverage.STATE_KEY)
    title = "PBS-sync: elke back-up op twee machines"
    if has_pbs and not cov.get("at"):
        out.append(row("pbssync", "proxmox", title, "half", "Nog niet bekeken: de worker doet dat elk half uur.",
                       ["Of open hw → back-ups en druk op ⟳ nu."], fix))
    elif has_pbs:
        prop = pbssync.propose(cov)
        if prop["state"] == "bestaat" or (prop["state"] == "te-weinig" and prop["links"]):
            out.append(row("pbssync", "proxmox", title, "ok", "; ".join(f"{x['from']} → {x['to']} ({x['schedule'] or 'geen uur'})"
                                                                         for x in prop["links"]) + ".", fix=fix))
        elif prop["state"] == "voorstel":
            p = prop["plan"]
            names = {x["service_id"]: x["name"] for x in prop["pbs"]}
            out.append(row("pbssync", "proxmox", title, "half", "Twee PBS'en, maar geen sync: elke back-up staat maar op "
                           "één machine.", [f"hw → back-ups: {names.get(p['target_id'])} laat elke nacht om {p['schedule']} een "
                           f"kopie ophalen van {names.get(p['source_id'])}. Commando's om te plakken, of één knop via SSH."],
                           fix))
        else:
            out.append(row("pbssync", "proxmox", title, "none", "Er werkt maar één PBS-tegel, dus geen tweede kopie.",
                           ["Voeg je tweede PBS toe als tegel (type proxmoxbackupserver), daarna stelt hw → back-ups de "
                            "sync voor."], fix))
    for c in (await _state(db, cluster.STATE_KEY)).get("items") or []:
        q = c.get("qdevice")
        if not c.get("cluster") or q is None:
            continue
        votes = sum(n.get("votes", 1) for n in c.get("nodes") or [])
        title, cfix = f"QDevice voor cluster {c['cluster']}", {"window": "health", "tab": "cluster"}
        if q and (q.get("state") or "").lower() == "connected":
            out.append(row(f"qdevice:{c['cluster']}", "proxmox", title, "ok", f"Verbonden met {q.get('host')}: "
                           f"{votes + 1} stemmen.", fix=cfix))
        elif q:
            out.append(row(f"qdevice:{c['cluster']}", "proxmox", title, "half", f"Ingesteld maar {q.get('state')}.",
                           [f"Kijk op {q.get('host') or 'de QDevice-machine'} of corosync-qnetd draait "
                            "(systemctl status corosync-qnetd)."], cfix))
        elif votes % 2 == 0:
            out.append(row(f"qdevice:{c['cluster']}", "proxmox", title, "half", f"{votes} stemmen: vallen er {votes // 2} "
                           "nodes uit, dan stopt de hele cluster.", ["hw → cluster legt uit hoe je een QDevice op de "
                           "PBS-Pi zet (drie commando's)."], cfix))
    return out


async def opnsense(db: AsyncSession, svcs: list[Service], results: dict[int, dict]) -> dict:
    extra = []
    names = {s.name for s in svcs}
    for e in (await _state(db, devices.STATE_KEY)).get("errors") or []:
        if e.get("source") in names:
            extra.append(f"apparaten: {e['error']} (recht Diagnostics: ARP Table en Services: DHCP: Leases)")
    for e in (await _state(db, configs.LAST_KEY)).get("errors") or []:
        if e.get("source") in names:
            extra.append(f"config-kopie: {e['error']} (recht Diagnostics: Configuration History)")
    for s in svcs:
        if err := (await _state(db, f"net_gw:{s.id}")).get("error"):
            extra.append(f"gateways: {err}")
    return _integration("opnsense", "netwerk", "OPNsense", svcs, results,
                        "Nog geen OPNsense-tegel: geen WAN-status, geen apparaten op je netwerk en geen kopie van "
                        "config.xml.", ["Maak in OPNsense een API-sleutel (System → Access → Users → API keys) met de "
                                        "rechten uit de README, en zet die in API-beheer."],
                        "WAN, apparaten en de kopie van config.xml werken.", extra=extra)


async def wake(db: AsyncSession, svcs: list[Service]) -> dict:
    title = "Wake-on-LAN"
    macs = [s for s in svcs if (s.config or {}).get("mac")]
    nodes = {n["name"].lower() for c in (await _state(db, cluster.STATE_KEY)).get("items") or []
             for n in c.get("nodes") or []}
    missing = [s for s in svcs if s.name.lower() in nodes and not (s.config or {}).get("mac")]
    todo = [f"Geen MAC-adres bij: {_list([s.name for s in missing])}. ✎ bewerken → tegel → MAC-adres."] if missing else []
    if not macs:
        fix = {"window": "edit", "service_id": missing[0].id} if missing else None
        return row("wol", "netwerk", title, "none", "Nog geen tegel met een MAC-adres.", todo or
                   ["✎ bewerken → tegel → MAC-adres, dan kan je die machine vanop het dashboard aanzetten."], fix,
                   optional=True)
    if missing:
        return row("wol", "netwerk", title, "half", f"{len(macs)} machine{'s' if len(macs) != 1 else ''} te wekken.",
                   todo, {"window": "edit", "service_id": missing[0].id}, optional=True)
    return row("wol", "netwerk", title, "ok", f"{len(macs)} machine{'s' if len(macs) != 1 else ''} te wekken.",
               fix={"window": "net", "tab": "internet"}, optional=True)


async def home_assistant(db: AsyncSession, clients, svcs: list[Service], results: dict[int, dict]) -> dict:
    extra = []
    nodes = sorted({n["name"] for c in (await _state(db, cluster.STATE_KEY)).get("items") or []
                    for n in c.get("nodes") or []})
    for s in svcs:
        try:
            integ = build(s, clients)
        except IntegrationError as e:
            extra.append(f"{s.name}: {e}")
            continue
        have = {str(k).lower() for k in (integ.config.get("nodes") or {})}
        if not have:
            extra.append(f"{s.name}: nog geen power-sensor per node (nodes in de instellingen van de tegel)")
        elif miss := [n for n in nodes if n.lower() not in have]:
            extra.append(f"{s.name}: geen sensor voor {_list(miss)}")
        if integ.price is None:
            extra.append(f"{s.name}: geen prijs per kWh (price), dus geen kosten")
    return _integration("homeassistant", "monitoring", "Home Assistant (stroom)", svcs, results,
                        "Nog geen Home Assistant-tegel: geen stroomverbruik en kosten per node.",
                        ["Long-lived token in Home Assistant (profiel → Beveiliging) en per node een power-sensor "
                         "(README)."], "Stroomverbruik en kosten per node werken.", optional=True, extra=extra)


async def zabbix_row(db: AsyncSession, svcs: list[Service], results: dict[int, dict]) -> dict:
    z = await _state(db, zbx.STATE_KEY)
    extra = []
    if svcs and z.get("error"):
        extra.append(f"Zabbix: {z['error']}")
    elif svcs and not z.get("hosts"):
        extra.append("Nog geen hosts opgehaald: de worker doet dat elke minuut.")
    hosts, tiles = len(z.get("hosts") or []), len(z.get("map") or {})
    return _integration("zabbix", "monitoring", "Zabbix", svcs, results, "Nog geen Zabbix-tegel.",
                        ["Maak in Zabbix een API-token (Users → API tokens) voor een gebruiker die alle hosts mag "
                         "lezen, en een API of tegel van type zabbix met het geheim token."],
                        f"{hosts} hosts, gekoppeld aan {tiles} tegel{'s' if tiles != 1 else ''}.", extra=extra)


async def checks_row(db: AsyncSession, svcs: list[Service]) -> dict:
    """Het dashboard vervangt Uptime Kuma: heeft elke tegel een check, en kijkt die naar het juiste?"""
    title, key = "Checks op je tegels (in plaats van Uptime Kuma)", "monitoring:dekking"
    running = [s for s in svcs if active(s.check)]
    states = {st.service_id: st for st in (await db.execute(select(ServiceState))).scalars()}
    todo = []
    bare = [s for s in svcs if s.url and not (s.check or {}).get("type")]
    if bare:
        todo.append(f"{len(bare)} tegel{'s' if len(bare) != 1 else ''} met een adres maar zonder check: "
                    f"{_list([s.name for s in bare], 6)}. ✎ bewerken → tegel → Monitoring.")
    paused = [s.name for s in svcs if (s.check or {}).get("type") and (s.check or {}).get("paused")]
    if paused:
        todo.append(f"Gepauzeerd: {_list(paused, 6)}.")
    for s in running:
        st = states.get(s.id)
        if st and st.stale:
            todo.append(f"{s.name}: de check loopt niet meer (journalctl -u homepage-worker).")
        elif st and st.redirected_to and not s.check.get("same_host"):
            todo.append(f"{s.name}: verwijst door naar {st.redirected_to}, dus de check ziet de loginpagina en niet "
                        "de app. Check een pad zonder login (bv. /api/health), of vink 'down als hij doorverwijst' aan.")
    monitors = {m.service_id: m for m in (await db.execute(select(PushMonitor))).scalars()}
    for s in running:
        if s.check.get("type") != "push":
            continue
        if s.id not in monitors:
            todo.append(f"{s.name}: push-check zonder adres. Klik de tegel open en kies push-adres maken.")
        elif not monitors[s.id].last_at:
            todo.append(f"{s.name}: nog geen signaal ontvangen. Pas het adres aan in je script en laat het één keer lopen.")
    # Cronjobs die nog een push-adres aanroepen dat het dashboard niet kent: meestal nog dat van Uptime Kuma.
    known = {m.token_hash for m in monitors.values()}
    for j in (await db.execute(select(CronJob).where(CronJob.removed_at.is_(None), CronJob.enabled.is_(True),
                                                     CronJob.command.contains("/api/push/")))).scalars():
        tokens = PUSH_URL.findall(j.command or "")
        if tokens and not any(hashlib.sha256(t.encode()).hexdigest() in known for t in tokens):
            todo.append(f"Cronjob {j.alias or j.name} op {j.target_name} roept een push-adres aan dat het dashboard "
                        "niet kent (nog van Uptime Kuma?). Maak een push-check en vervang het adres.")
    kuma = [w for w in (await db.execute(select(WebhookSource).where(WebhookSource.kind == "uptimekuma"))).scalars()
            if w.enabled and w.last_at and datetime.now(timezone.utc) - w.last_at.replace(tzinfo=w.last_at.tzinfo
                                                                                      or timezone.utc) < timedelta(days=7)]
    if kuma:
        todo.append(f"Uptime Kuma stuurt nog meldingen (webhook {kuma[0].name}, laatst {_local(kuma[0].last_at)}): "
                    "zet Kuma pas uit als alles hier staat (README → Uptime Kuma uitzetten).")
    first = bare[0] if bare else next((s for s in running if states.get(s.id) and (
        states[s.id].stale or states[s.id].redirected_to)), None)
    fix = {"window": "edit", "service_id": first.id} if first else None
    if not running:
        return row(key, "monitoring", title, "none", "Nog geen enkele tegel met een check: niets merkt het als een "
                   "service uitvalt.", todo or ["✎ bewerken → tegel → Monitoring: kies een check."], fix)
    text = f"{len(running)} check{'s' if len(running) != 1 else ''} lopen."
    return row(key, "monitoring", title, "half" if todo else "ok", text, todo[:8], fix)


async def routes_row(db: AsyncSession, npm: list[Service]) -> dict:
    """Gaan de checks rechtstreeks naar de server achter NPM (zonder DNS), en zo niet, wat houdt ze tegen?"""
    title, key = "Checks rechtstreeks, zonder DNS", "monitoring:rechtstreeks"
    fix = {"window": "detail", "service_id": npm[0].id}
    o = await routes.overview(db)
    if not o["enabled"]:
        return row(key, "monitoring", title, "none", "Uitgezet op de NPM-tegel: elke check vraagt DNS en gaat door NPM.",
                   ["Klik de NPM-tegel open → rechtstreeks → aanzetten."], fix, optional=True)
    if not o["at"]:
        return row(key, "monitoring", title, "half", "De proxy hosts zijn nog niet opgehaald: de worker doet dat elke "
                   "5 minuten.", fix=fix)
    todo = [f"NPM: {e}" for e in o["errors"]]
    walled = [b for b in o["blocked"] if not b["refused"]]
    refused = [b for b in o["blocked"] if b["refused"]]
    if walled:
        tiles = [t for b in walled for t in b["tiles"]]
        todo.append(f"{len(tiles)} tegel{'s' if len(tiles) != 1 else ''} gaan nog door NPM omdat het dashboard de "
                    f"server niet bereikt: {_list([b['endpoint'] for b in walled], 6)}. Laat in OPNsense het "
                    "dashboard naar die poorten toe (net → firewall), en klik dan op de NPM-tegel → rechtstreeks → "
                    "nu vernieuwen.")
        fix = {"window": "net", "tab": "firewall"}
    if refused:
        todo.append(f"{_list([b['endpoint'] for b in refused], 6)} weigert de verbinding (de server antwoordt, maar "
                    "niets luistert op die poort): staat de service uit, of luistert ze op een andere poort dan in "
                    "NPM? Tot dan gaan die checks door NPM.")
    if not any(active(s.check) for s in npm):
        todo.append("De NPM-tegel heeft zelf geen check: valt NPM uit, dan zie je dat niet meer op je andere tegels. "
                    "✎ bewerken → NPM-tegel → Monitoring: een http-check op het adres van NPM.")
    c = o["counts"]
    text = (f"{c['direct']} check{'s' if c['direct'] != 1 else ''} rechtstreeks naar de server, {c['npm']} via NPM "
            f"zonder DNS, {c['naam']} via de naam." if o["rows"] else "Geen enkele check op een naam die NPM kent.")
    return row(key, "monitoring", title, "half" if todo else "ok", text, todo[:8], fix)


async def watcher_row(db: AsyncSession) -> dict:
    """Ziet iemand het als de hele container uitvalt? Dat kan alleen iets buiten het dashboard: Zabbix."""
    title, fix = "Iemand die het dashboard zelf bewaakt", {"window": "health", "tab": "homepage"}
    seen = await _state(db, watchdog.SEEN_KEY)
    at = datetime.fromisoformat(seen["at"]) if seen.get("at") else None
    how = ["Zet in Zabbix een web-scenario op http://<IP van de container>/api/healthz met statuscode 200 (503 = "
           "worker of checks staan stil), en een trigger als het mislukt (README → Uptime Kuma vervangen)."]
    if not at:
        return row("wachter", "monitoring", title, "none", "Niets vraagt /api/healthz op: valt de hele container uit, "
                   "dan krijg je geen enkele melding.", how, fix)
    if datetime.now(timezone.utc) - at > timedelta(minutes=15):
        return row("wachter", "monitoring", title, "half", f"Laatst opgevraagd op {_local(at)}: staat de bewaking in "
                   "Zabbix nog aan?", how, fix)
    return row("wachter", "monitoring", title, "ok", f"{seen.get('ip') or 'Iets'} vraagt /api/healthz op, laatst om "
               f"{_local(at)}.", fix=fix)


async def webpush_row(db: AsyncSession) -> dict:
    title, fix = "Meldingen op je gsm", {"window": "webpush"}
    st = await webpush.status(db)
    if not st["devices"]:
        return row("webpush", "monitoring", title, "none", "Nog geen toestel: storingen zie je alleen als je het "
                   "dashboard open hebt.", ["🔔 → gsm → Dit toestel meldingen laten krijgen, op je gsm (iPhone: eerst "
                   "op het beginscherm zetten)."], fix)
    n = st["devices"]
    text = f"{n} toestel{'len' if n != 1 else ''}" + (f", laatst afgeleverd {_local(st['last_ok'])}." if st["last_ok"]
                                                       else ".")
    if st["failing"]:
        return row("webpush", "monitoring", title, "half", text, [f"Afleveren mislukt op {_list(st['failing'])}: "
                   "zet het daar opnieuw aan (🔔 → gsm)."], fix)
    return row("webpush", "monitoring", title, "ok", text, fix=fix)


async def hardware(db: AsyncSession) -> dict:
    hosts = (await _state(db, hw.STATE_KEY)).get("hosts") or []
    title, fix = "Schijven en temperatuur", {"window": "health", "tab": "schijven"}
    if not hosts:
        return row("hardware", "monitoring", title, "none", "Nog niets gelezen: SMART, ZFS en temperaturen komen via SSH.",
                   ["Zet ⚙ standaard in de terminal op root met een sleutel, open elke node één keer en kies dan "
                    "hw → schijven → ⟳."], fix)
    bad = [f"{h.get('name')}: {h['error']}" for h in hosts if h.get("error")]
    if bad:
        return row("hardware", "monitoring", title, "half", f"{len(hosts) - len(bad)} van {len(hosts)} machines gelezen.",
                   bad[:6], fix)
    return row("hardware", "monitoring", title, "ok", f"{len(hosts)} machines: SMART, ZFS en temperatuur.", fix=fix)


async def domain_row(db: AsyncSession, cfg: dict) -> dict:
    title, fix = "Domeinen", {"window": "health", "tab": "domeinen"}
    if not cfg.get("domains"):
        return row("domains", "monitoring", title, "none", "Nog geen domeinen: je krijgt geen melding voor ze verlopen.",
                   ["Voeg ze toe onder hw → domeinen."], fix, optional=True)
    items = (await _state(db, "domains")).get("items") or []
    blind = [d["name"] for d in items if not d.get("expires")]
    if blind:
        return row("domains", "monitoring", title, "half", f"{len(cfg['domains'])} domeinen gevolgd.",
                   [f"Geen vervaldatum voor {_list(blind)} (.be geeft die niet vrij): vul ze zelf in onder hw → domeinen."],
                   fix, optional=True)
    return row("domains", "monitoring", title, "ok", f"{len(cfg['domains'])} domeinen gevolgd.", fix=fix, optional=True)


async def webhooks(db: AsyncSession) -> list[dict]:
    srcs = list((await db.execute(select(WebhookSource))).scalars())
    out = []
    spec = (("proxmox", "Meldingen van Proxmox", "Proxmox VE 8.3 of nieuwer: Datacenter → Notifications", False),
            ("pbs", "Meldingen van PBS", "PBS 3.3 of nieuwer: Configuration → Notifications", False),
            ("homeassistant", "Meldingen van Home Assistant", "een automatisering in Home Assistant", True))
    for kind, title, where, optional in spec:
        mine = [s for s in srcs if s.kind == kind]
        fix = {"window": "webhooks"}
        if not mine:
            out.append(row(f"webhook:{kind}", "monitoring", title, "none", "Nog geen webhook.",
                           [f"Maak er een onder meldingen → webhooks; het venster toont wat je invult in {where}."],
                           fix, optional))
            continue
        todo = [f"{s.name}: staat uit" for s in mine if not s.enabled]
        todo += [f"{s.name}: {s.last_error}" for s in mine if s.last_error]
        todo += [f"{s.name}: nog niets ontvangen; stuur een testmelding vanuit {where.split(':')[0]}" for s in mine
                 if s.enabled and not s.count]
        last = max((s.last_at for s in mine if s.last_at), default=None)
        if todo:
            out.append(row(f"webhook:{kind}", "monitoring", title, "half", "Aangemaakt, maar niet alles komt binnen.",
                           todo, fix, optional))
        else:
            out.append(row(f"webhook:{kind}", "monitoring", title, "ok",
                           f"Laatste melding op {_local(last)}." if last else "Werkt.", fix=fix,
                           optional=optional))
    return out


async def ssh_rows(db: AsyncSession, has_proxmox: bool) -> list[dict]:
    out = []
    d = await ssh_defaults(db)
    title = "SSH-standaardlogin"
    fix = {"window": "ssh-defaults"}
    if not d.get("key_id") and not d.get("password"):
        out.append(row("ssh_defaults", "ssh", title, "none", "Nog geen standaardlogin: cron, updates, logs en de "
                       "hardwarecheck kunnen nergens aanmelden.",
                       ["Terminal → ⚙ standaard: gebruiker root met een sleutel (maak er een met ssh-keygen in de "
                        "terminal)."], fix))
    elif (d.get("username") or "root") != "root":
        out.append(row("ssh_defaults", "ssh", title, "half", f"Gebruiker {d['username']}.",
                       ["Cron, updates en de hardwarecheck hebben root nodig: zet de standaardgebruiker op root."], fix))
    else:
        out.append(row("ssh_defaults", "ssh", title, "ok",
                       "root met een sleutel." if d.get("key_id") else "root met een wachtwoord (een sleutel is veiliger).",
                       fix=fix))
    hosts = list((await db.execute(select(SshHost).order_by(SshHost.name))).scalars())
    title = "Hosts in de terminal"
    if not hosts:
        out.append(row("ssh_hosts", "ssh", title, "none", "Nog geen hosts.",
                       ["Terminal → ⟳ pve haalt al je nodes, CT's en VM's op."], {"window": "ssh-discover"}))
    else:
        todo = []
        if has_proxmox and not any((h.source or "").startswith("pve:") for h in hosts):
            todo.append("Nog niet uit Proxmox opgehaald: terminal → ⟳ pve (dan kent de kaart ook de IP's van je CT's).")
        # CT's gaan via hun node (pct exec): die hebben geen eigen host key nodig.
        unknown = [h for h in hosts if not h.host_key and not (h.source or "").rsplit(":", 1)[-1].startswith("lxc/")]
        if unknown:
            todo.append(f"Nog nooit geopend, dus host key niet bevestigd: {_list([h.name for h in unknown], 6)}. Open ze "
                        "één keer in de terminal.")
        fix = {"window": "terminal", "host_id": unknown[0].id} if unknown else {"window": "ssh-discover"}
        out.append(row("ssh_hosts", "ssh", title, "half" if todo else "ok", f"{len(hosts)} hosts.", todo, fix))
    c = await _state(db, "cron")
    title, fix = "Cronjobs", {"window": "cron"}
    if not c.get("scanned_at"):
        out.append(row("cron", "ssh", title, "none", "Nog niet gescand.",
                       ["Werkt zodra de standaardlogin root is en de nodes een bevestigde host key hebben; de worker "
                        "scant elke 15 minuten."], fix))
    else:
        bad = [f"{t['name']}: {t['error']}" for t in c.get("targets") or [] if t.get("error")]
        jobs = (await db.execute(select(func.count()).select_from(CronJob).where(
            CronJob.removed_at.is_(None), CronJob.system.is_(False)))).scalar_one()
        n = len(c.get("targets") or [])
        out.append(row("cron", "ssh", title, "half" if bad else "ok", f"{jobs} jobs op {n} machines.", bad[:6], fix))
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    n = (await db.execute(select(func.count(distinct(LogEntry.host))).where(LogEntry.ts >= since))).scalar_one()
    title, fix = "Logs (rsyslog)", {"window": "logs-setup"}
    if not n:
        out.append(row("logs", "ssh", title, "none", "De laatste 24 uur kwamen er geen logs binnen.",
                       ["Logs → machines toevoegen rolt rsyslog uit via SSH."], fix))
    else:
        out.append(row("logs", "ssh", title, "ok", f"Logs van {n} machine{'s' if n != 1 else ''} de laatste 24 uur.",
                       fix={"window": "logs"}))
    up = await upgrade.settings(db)
    out.append(row("autoupdates", "ssh", "Nachtelijke beveiligingsupdates", "ok" if up.get("auto") else "none",
                   f"Aan, om {int(up.get('hour', 4)):02d}:00, met een snapshot vooraf." if up.get("auto") else
                   "Staat uit: je installeert updates zelf via apt.",
                   [] if up.get("auto") else ["Aanzetten in apt → instellingen."], {"window": "updates"}, optional=True))
    return out


async def safety(db: AsyncSession, cfg: dict) -> list[dict]:
    out = []
    c = await security.check_2fa(db)
    out.append(row("2fa", "beveiliging", "2FA voor elk account", "ok" if c["level"] == "ok" else "half", c["text"],
                   fix={"window": "security", "tab": "sessions"}))
    c = await security.check_secret_key(db)
    out.append(row("secret", "beveiliging", "Kopie van secret.key", "ok" if c["level"] == "ok" else "none", c["text"],
                   fix={"window": "health", "tab": "beveiliging"}))
    c = await security.check_offsite(db)
    state = "none" if not cfg.get("offsite") else "ok" if c["level"] == "ok" else "half"
    out.append(row("offsite", "beveiliging", "Back-up buiten de container", state, c["text"],
                   fix={"window": "health", "tab": "homepage"}))
    c = await security.check_access(db)
    out.append(row("access", "beveiliging", "Slot voor het dashboard", "ok" if c["level"] == "ok" else "none", c["text"],
                   fix=c["fix"]))
    pin = await _state(db, PIN_KEY)
    res = [r.get("state") for r in (pin.get("hosts") or {}).values()]
    pinned, loose = res.count("vast"), res.count("los") + res.count("anders")
    c = await security.check_ssh_pin(db)
    state = "ok" if pinned and not loose else "half" if pinned else "none"
    out.append(row("sshpin", "beveiliging", "SSH-sleutel vastgezet op het dashboard", state, c["text"], fix=c["fix"]))
    c = await security.check_outside(db)
    out.append(row("outside", "beveiliging", "Van buitenaf", "half" if c["level"] == "warn" else "ok", c["text"],
                   fix={"window": "security", "tab": "outside"}))
    oidc = await _state(db, "oidc")
    out.append(row("authentik", "beveiliging", "Inloggen via Authentik", "ok" if oidc.get("enabled") else "none",
                   "Staat aan." if oidc.get("enabled") else "Inloggen gaat met je wachtwoord en 2FA.",
                   [] if oidc.get("enabled") else ["Optioneel: sleutel-icoon → authentik, met client id en secret."],
                   {"window": "security", "tab": "sso"}, optional=True))
    return out


async def run(db: AsyncSession, clients, results: dict[int, dict]) -> dict:
    svcs = list((await db.execute(select(Service).order_by(Service.name))).scalars())

    def of(kind: str) -> list[Service]:
        return [s for s in svcs if s.type == kind]

    cfg = await hw.settings(db)
    restore_on = restoretest.settings(await _state(db, restoretest.STATE_KEY))["enabled"]
    rows = [
        await proxmox(db, clients, of("proxmox"), results, restore_on),
        _integration("pbs", "proxmox", "Proxmox Backup Server", of("proxmoxbackupserver"), results,
                     "Nog geen PBS-tegel: back-ups, verify en sync worden niet gevolgd.",
                     ["Token in PBS (Configuration → Access Control → API Token) met de rol DatastoreAudit, in "
                      "API-beheer (README)."], "Back-ups, verify en sync worden gevolgd."),
        await restore(db),
        *await homelab_rows(db, bool(of("proxmoxbackupserver"))),
        await opnsense(db, of("opnsense"), results),
        _integration("npm", "netwerk", "Nginx Proxy Manager", of("npm"), results,
                     "Nog geen NPM-tegel: je proxy hosts kan je niet als tegels importeren en er is geen kopie van.",
                     ["Tegel of API van type npm met je NPM-login (een eigen gebruiker met alleen leesrechten)."],
                     "Proxy hosts, import en de nachtelijke kopie werken."),
        _integration("cloudflared", "netwerk", "Cloudflare-tunnels", of("cloudflared"), results,
                     "Nog geen Cloudflare-tegel: de status van je tunnels zie je niet.",
                     ["Cloudflare API-token met Account → Cloudflare Tunnel → Read, plus je account-id (README)."],
                     "De status van je tunnels wordt gevolgd.", optional=True,
                     extra=[e for s in of("cloudflared") if (e := (await _state(db, f"net_tunnel:{s.id}")).get("error"))]),
        _integration("adguard", "netwerk", "AdGuard Home", of("adguard"), results, "Nog geen AdGuard-tegel.",
                     ["Tegel of API van type adguard met je AdGuard-login."], "Werkt.", optional=True),
        await wake(db, svcs),
        await checks_row(db, svcs),
        *([await routes_row(db, of("npm"))] if of("npm") else []),
        await webpush_row(db),
        await watcher_row(db),
        await zabbix_row(db, of("zabbix"), results),
        await home_assistant(db, clients, of("homeassistant"), results),
        await hardware(db),
        await domain_row(db, cfg),
        *await webhooks(db),
        _integration("portainer", "monitoring", "Portainer", of("portainer"), results,
                     "Nog geen Portainer-tegel: geen containerlogs of image-updates.",
                     ["Tegel of API van type portainer met een access token (My account → Access tokens)."],
                     "Containers, logs en image-updates werken.", optional=True),
        *await ssh_rows(db, bool(of("proxmox"))),
        *await safety(db, cfg),
    ]
    groups = [{"key": k, "title": t, "rows": [r for r in rows if r["group"] == k]} for k, t in GROUPS]
    counts = {"ok": sum(1 for r in rows if r["state"] == "ok"),
              "half": sum(1 for r in rows if r["state"] == "half"),
              "none": sum(1 for r in rows if r["state"] == "none" and not r["optional"]),
              "optional": sum(1 for r in rows if r["state"] == "none" and r["optional"])}
    return {"groups": groups, "counts": counts, "checked_at": datetime.now(timezone.utc).isoformat()}
