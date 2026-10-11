"""Het noodplan als document: uit wat monitoring/noodplan.py bewaart, één lijst blokken, en twee kleine omzetters naar
HTML (het venster, afdrukken, de kopie op de share) en Markdown (dezelfde kopie als platte tekst, te lezen met less).

Puur: geen database, geen netwerk. Elke tekst gaat door html.escape; alleen http(s)-adressen worden een link. Geen
script, geen extern bestand. De teksten noemen nooit een geheim, alleen waar het staat. Schrijf nooit een naam die op
een geheim lijkt met meteen ":" of "=" erachter ("secret.key:", "token=", ...): de maskering zou het woord erna dan als
geheim vervangen. Zet zoiets in een tabelcel of schrijf "API-token <id>".

Blokken:
    ("h1" | "h2" | "h3", tekst, anker)   ("p" | "meta", inline)   ("ul" | "ol", [inline])
    ("table", koppen, rijen, klasse)     ("pre", tekst)            ("note", "info" | "warn" | "err", inline)
Een rij is een lijst cellen, of ("svc", inline): een rij over de hele breedte onder de vorige (diensten, gebonden).
Inline is tekst, Code, Bad, Link, of een lijst daarvan.
"""

import html
from datetime import datetime, timedelta

from ..health.selfcheck import readme as leesmij

HOUR = 6  # maandag vanaf 6 uur (lokale tijd)
DAYS = ("ma", "di", "wo", "do", "vr", "za", "zo")


class Code(str):
    """Inline code: <code> in HTML, `…` in Markdown."""


class Bad(str):
    """Rood en vet: <strong class="bad"> in HTML, **…** in Markdown."""


class Link(str):
    """Een http(s)-adres: <a href target=_blank rel=noopener noreferrer> in HTML, <…> in Markdown. Al het andere blijft
    gewone tekst. De tekst van de link is altijd het adres zelf: zo staat het ook op papier."""


CSS = """:root{color-scheme:light}
body{font:15px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color:#111;background:#fff;
margin:0 auto;max-width:960px;padding:16px}
h1{font-size:24px;margin:0 0 4px} h2{font-size:18px;margin:22px 0 8px;padding-bottom:3px;border-bottom:2px solid #111;
break-after:avoid} h3{font-size:15px;margin:16px 0 6px;break-after:avoid}
.meta{color:#444;font-size:13px;margin:2px 0}
.tbl{overflow-x:auto} table{border-collapse:collapse;width:100%;font-size:13px}
th,td{border:1px solid #bbb;padding:3px 5px;text-align:left;vertical-align:top} th{background:#eee}
thead{display:table-header-group} tr{break-inside:avoid} tr.svc td{color:#444;font-size:12px;border-top:0}
code,pre{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px} td code{word-break:break-all}
pre{white-space:pre-wrap;word-break:break-all;border:1px solid #bbb;padding:6px;background:#f6f6f6}
.bad{color:#b91c1c;font-weight:700}
.note{border-left:4px solid #888;padding:2px 8px;margin:8px 0} .note.warn{border-color:#b45309}
.note.err{border-color:#b91c1c;font-weight:600}
.bijlage{break-before:page}
@media screen and (max-width:640px){body{padding:12px;font-size:14px} table{font-size:12px}}
@page{size:A4;margin:12mm 11mm 14mm}
@media print{body{max-width:none;padding:0;font-size:10pt} table{font-size:8.5pt} code,pre{font-size:8pt}
.tbl{overflow:visible} th,td{overflow-wrap:anywhere} a{color:#000;text-decoration:none}
.bad{color:#000;text-decoration:underline}}"""


# --- tijden (lokale tijd, zoals op de klok bij Jonas) ---------------------------------------------------------------

def slot(now: datetime) -> datetime:
    """Het moment van het noodplan van deze week: maandag 6 uur, of die van vorige week als het nog niet zover is."""
    local = now.astimezone()
    monday = (local - timedelta(days=local.weekday())).replace(hour=HOUR, minute=0, second=0, microsecond=0,
                                                               tzinfo=None).astimezone()
    return monday if local >= monday else (monday.replace(tzinfo=None) - timedelta(days=7)).astimezone()


def next_slot(now: datetime) -> datetime:
    """De volgende maandag 6 uur (voor "volgende versie")."""
    return (slot(now).replace(tzinfo=None) + timedelta(days=7)).astimezone()


def _local(iso) -> datetime | None:
    if not iso:
        return None
    try:
        return (iso if isinstance(iso, datetime) else datetime.fromisoformat(str(iso))).astimezone()
    except ValueError:
        return None


def day(iso) -> str:
    """12/10"""
    t = _local(iso)
    return f"{t.day}/{t.month}" if t else "?"


def full(iso) -> str:
    """ma 12/10/2026 06:02"""
    t = _local(iso)
    return f"{DAYS[t.weekday()]} {t.day}/{t.month}/{t.year} {t:%H:%M}" if t else "?"


def when(iso) -> str:
    """12/10 01:00"""
    t = _local(iso)
    return f"{t.day}/{t.month} {t:%H:%M}" if t else "?"


def _gb(n) -> str:
    """Geheugen in bytes: 34359738368 → 32 GB."""
    return f"{round(n / 2 ** 30)} GB" if isinstance(n, (int, float)) and n > 0 else "?"


def _size(n) -> str:
    """Opslag in bytes: 812 GB, 1,8 TB."""
    if not isinstance(n, (int, float)):
        return "?"
    return f"{n / 1e12:.1f} TB".replace(".", ",") if n >= 1e12 else f"{n / 1e9:.0f} GB"


# --- hulp bij de gegevens ------------------------------------------------------------------------------------------

def label(g: dict) -> str:
    """CT 101 of VM 100."""
    return f"{'CT' if g.get('type') == 'lxc' else 'VM'} {g.get('vmid')}"


def where(g: dict | None) -> str | None:
    """CT 110 op pve52."""
    return f"{label(g)} op {g.get('node') or '?'}" if g else None


def guests(d: dict) -> list[dict]:
    return [g for c in d.get("clusters") or [] for g in c.get("guests") or []]


def by_role(d: dict, role: str) -> dict | None:
    return next((g for g in guests(d) if role in (g.get("roles") or [])), None)


def pbs_label(name: str | None) -> str:
    """PBS pi, maar geen "PBS PBS pi"."""
    name = name or "?"
    return name if "pbs" in name.lower() else f"PBS {name}"


def _join(parts: list, sep: str = ", ") -> list:
    out: list = []
    for i, p in enumerate(parts):
        if i:
            out.append(sep)
        out.append(p)
    return out


def _uncovered(g: dict) -> list[dict]:
    return [k for k in g.get("disks") or [] if not k.get("in_backup")]


# --- het document --------------------------------------------------------------------------------------------------

def blocks(value: dict, masked: list[str] | None = None) -> list[tuple]:
    """Het hele noodplan als blokken. masked: de soorten die de maskering vond (dan een opmerking bovenaan)."""
    d = value.get("data") or {}
    out = _header(value, d, masked)
    for part in (_first, _access, _nodes, _backups, _restore, _configs, _keys, _dashboard):
        out += part(value, d)
    at, secs = value.get("at"), value.get("seconds")
    srcs = ", ".join(f"{s.get('name')} ({'ok' if s.get('ok') else 'fout'})" for s in value.get("sources") or [])
    out.append(("meta", f"Gemaakt door het dashboard op {full(at)}" + (f" in {secs} s" if secs is not None else "")
                + ". Bronnen: " + (srcs or "geen Proxmox- of PBS-tegel") + "."))
    return out


def _header(value: dict, d: dict, masked: list[str] | None) -> list[tuple]:
    dash = d.get("dashboard") or {}
    at = value.get("at")
    nxt = next_slot(datetime.fromisoformat(at)) if at else None
    out = [("h1", "Noodplan homelab", "top"),
           ("meta", f"Gemaakt {full(at)} door het dashboard (versie {dash.get('versie') or '?'})."
                    + (f" Volgende versie: maandag {day(nxt)}." if nxt else "")
                    + " Er staan geen wachtwoorden of sleutels in, alleen waar ze staan.")]
    if dash.get("offsite_on"):
        out.append(("meta", f"Kopie: {dash.get('offsite_dir')}/noodplan.html en noodplan.md (elke maandag bijgewerkt)."))
    else:
        out.append(("meta", "Alleen in het dashboard: de kopie buiten de container staat uit."))
    for s in value.get("sources") or []:
        if s.get("ok"):
            continue
        text = f"{s.get('name')}: {s.get('error') or 'fout'}"
        if s.get("covered"):
            text += f" — dezelfde cluster staat er via {s['covered']}."
        elif s.get("from"):
            text += f" — dit deel komt uit het noodplan van {day(s['from'])}."
        else:
            text += " — nog nooit gelukt, dit deel ontbreekt."
        out.append(("note", "warn", text))
    if masked:
        out.append(("note", "warn", f"Er stond iets in dat op een geheim leek ({', '.join(masked)}); dat is vervangen "
                                    "door ***."))
    return out


def _first(value: dict, d: dict) -> list[tuple]:
    acc = d.get("access") or []
    items = []
    opn = [a for a in acc if a.get("kind") == "opnsense"]
    if opn:
        items.append(["Internet en netwerk: ", *_join([[a["name"], " op ", Link(a["url"]),
                                                         *([f" ({a['runs_on']})"] if a.get("runs_on") else [])]
                                                        for a in opn])])
    else:
        items.append("Internet en netwerk: geen OPNsense-tegel in het dashboard, je router staat niet in dit plan.")
    for c in d.get("clusters") or []:
        nodes = [[n["name"], " ", Link(f"https://{n['ip']}:8006")] if n.get("ip") else f"{n['name']} (IP onbekend)"
                 for n in c.get("nodes") or []]
        extra = [f"cluster {c['name']}"] if c.get("name") else []
        if c.get("qdevice"):
            extra.append(f"QDevice op {c['qdevice']}")
        items.append(["Proxmox: ", *_join(nodes), *([f" ({', '.join(extra)})"] if extra else [])])
    if not d.get("clusters"):
        items.append("Proxmox: geen Proxmox-tegel in het dashboard.")
    pbs = d.get("pbs") or []
    if pbs:
        items.append(["Back-ups: ", *_join([[f"{pbs_label(p['name'])} ", Link(p["url"]) if p.get("url") else "adres onbekend",
                                              f" ({p.get('runs_on') or 'eigen toestel'})"] for p in pbs])])
    for a in (a for a in acc if a.get("kind") == "npm"):
        items.append([f"Proxy: {a['name']} ", *([a["ip"], " "] if a.get("ip") else []),
                      *([f"({a['runs_on']}), "] if a.get("runs_on") else []), "beheer ", Link(a["url"])])
    dash = d.get("dashboard") or {}
    me = dash.get("guest")
    line = ["Dit dashboard: ", where(me) or "VM/CT onbekend", f", {dash.get('ip') or 'IP onbekend'}"]
    if dash.get("domains"):
        line += [", via NPM ", Link(f"https://{dash['domains'][0]}")]
    items.append(line)
    out = [("h2", "1. Eerst", "eerst"), ("p", "Wat je het eerst weer nodig hebt, in deze volgorde:"), ("ol", items)]
    boot = sorted((g for g in guests(d) if g.get("onboot")),
                  key=lambda g: (g.get("order") is None, g.get("order") or 0, g.get("vmid") or 0))
    if boot:
        out.append(("p", "Na een stroomuitval starten vanzelf, in deze volgorde: "
                    + ", ".join(f"{label(g)} {g.get('name') or ''} ({g.get('node')})".replace("  ", " ") for g in boot)
                    + ". De andere starten niet vanzelf."))
    elif guests(d):
        out.append(("p", "Geen enkele VM of CT start vanzelf met zijn node (autostart staat overal uit)."))
    return out


HOW = {"ip": "IP in de tegel", "npm": "rechtstreeks, zoals NPM het doorstuurt", "node": "IP van de node",
       "corosync": "corosync-IP (het IP van de webinterface is onbekend)", "vorig": "uit een vorig noodplan",
       "lan": "rechtstreeks (het LAN mag erbij)", "via_npm": "alleen via NPM (nginx laat het LAN niet rechtstreeks toe)",
       "onbekend": "onbekend: zet het IP in de tegel"}


def _how(a: dict, at) -> str:
    if a.get("how") == "dns":
        return f"DNS op {day(at)}"
    return HOW.get(a.get("how") or "onbekend", a.get("how") or "")


def _access(value: dict, d: dict) -> list[tuple]:
    rows = [[a.get("what") or "", Link(a["url"]) if a.get("url") else "", _how(a, value.get("at")),
             a.get("note") or ""] for a in d.get("access") or []]
    out = [("h2", "2. Toegang zonder DNS", "toegang"),
           ("p", "Als DNS of NPM plat ligt: elk systeem op zijn IP-adres. Een zelfondertekend certificaat geeft dan een "
                 "waarschuwing in de browser; die mag je hier wegklikken.")]
    out.append(("table", ["wat", "adres", "hoe", "let op"], rows, "toegang") if rows else
               ("p", "Nog geen tegels met een adres."))
    tunnels = d.get("tunnels") or []
    if tunnels:
        out.append(("p", "Van buitenaf: " + ", ".join(
            f"{t.get('service')} {t.get('name')} ({t.get('status')}, {t.get('connections') or 0} verbindingen)"
            for t in tunnels) + "."))
    else:
        out.append(("p", "Geen Cloudflare-tegel: hoe je van buitenaf binnenkomt (tunnel of poortdoorverwijzing naar NPM) "
                         "staat niet in het dashboard."))
    return out


def _node_title(n: dict) -> str:
    ip = n.get("ip")
    if not ip:
        ip_text = "IP onbekend"
    elif n.get("ip_from") == "corosync":
        ip_text = f"{ip} (corosync-IP)"
    elif n.get("ip_from") == "vorig":
        ip_text = f"{ip} (uit het noodplan van {day(n.get('ip_at'))})"
    elif n.get("corosync_ip") and n["corosync_ip"] != ip:
        ip_text = f"{ip} (corosync {n['corosync_ip']})"
    else:
        ip_text = ip
    return " · ".join([n.get("name") or "?", ip_text, n.get("arch") or "architectuur onbekend",
                       f"Proxmox {n['version']}" if n.get("version") else "Proxmox-versie onbekend",
                       "online" if n.get("online") else "offline"])


STATUS = {"running": "draait", "stopped": "staat uit", "paused": "gepauzeerd", "unknown": "status onbekend"}


def _disk(k: dict) -> list:
    if k.get("bind"):
        text = f"{k['key']} {'apparaat' if k.get('why') == 'apparaat' else 'bind'} {k['bind']}" + (
            f" op {k['mp']}" if k.get("mp") else "")
    else:
        text = " ".join(str(x) for x in (k.get("key"), k.get("storage"), k.get("size"), k.get("mp")) if x)
    return [text, " ", Bad("niet in de back-up")] if not k.get("in_backup") else [text]


def _ip_cell(g: dict) -> list:
    if g.get("ip"):
        return [f"{g['ip']} ({g.get('ip_from') or '?'})"]
    return [Bad("onbekend"), *([f" ({g['ip_why']})"] if g.get("ip_why") else [])]


def _nets(g: dict) -> str:
    nets = g.get("nets") or []
    parts = []
    for n in nets:
        bits = ([n.get("if")] if len(nets) > 1 else []) + [n.get("mac") or "MAC ?", n.get("bridge")]
        if n.get("tag"):
            bits.append(f"VLAN {n['tag']}")
        parts.append(" ".join(str(b) for b in bits if b))
    return "; ".join(parts) or "geen netwerkkaart"


def _backup_cell(g: dict) -> list:
    cov = g.get("coverage") or {}
    done = [f"{b.get('pbs')} {when(b.get('last'))}" for b in g.get("backups") or []]
    if cov.get("level") == "err":
        return [Bad("geen back-up!"), f" {cov.get('why') or ''}".rstrip(), *([" · ", " · ".join(done)] if done else [])]
    if done:
        return [" · ".join(done)]
    return [cov.get("why") or "onbekend (nog geen back-updekking opgehaald)"]


def _svc_row(g: dict) -> list:
    parts: list = []
    if g.get("services"):
        parts.append(["diensten: ", *_join([[s["name"], *([" (", Link(s["url"]), ")"] if s.get("url") else [])]
                                            for s in g["services"]])])
    roles = [ROLES.get(r.split(":")[0], r) + (f" {r.split(':', 1)[1]}" if ":" in r else "") for r in g.get("roles") or []]
    if roles:
        parts.append("dit is " + ", ".join(roles))
    for b in g.get("bound") or []:
        if b.get("node"):
            parts.append([Bad(f"gebonden aan {b['node']}"), f" ({b.get('what')})"])
        elif b.get("mapping"):
            parts.append(f"alleen op nodes met mapping {b['mapping']} ({b.get('what')})")
    if g.get("config_from") == "kopie":
        parts.append(f"configuratie uit de kopie van {day(g.get('config_at'))} (de node gaf geen antwoord)")
    elif not g.get("config_from"):
        parts.append(Bad("configuratie onbekend"))
    return _join(parts, " · ")


ROLES = {"dashboard": "het dashboard", "opnsense": "OPNsense", "npm": "NPM", "pbs": "PBS"}


def _nodes(value: dict, d: dict) -> list[tuple]:
    out = [("h2", "3. Nodes en wat erop draait", "nodes")]
    if not d.get("clusters"):
        out.append(("p", "Geen Proxmox-tegel in het dashboard: welke VM's en CT's er zijn, staat niet in dit plan."))
    for c in d.get("clusters") or []:
        head = [f"Cluster {c['name']}" if c.get("name") else "Losse node", f" (tegel {c.get('service')})"]
        if c.get("quorate") is False:
            head.append(", zonder quorum")
        out.append(("meta", head))
        if c.get("stale_from"):
            out.append(("note", "warn", f"Dit deel komt uit het noodplan van {day(c['stale_from'])}: de Proxmox-tegel gaf "
                                        "deze keer geen antwoord."))
        for n in c.get("nodes") or []:
            out.append(("h3", _node_title(n), f"node-{n.get('name')}"))
            meta = ([f"MAC {n['mac']} (Wake-on-LAN)"] if n.get("mac") else []) + (
                [n["cpu"]] if n.get("cpu") else []) + ([f"{n['cpus']} cpu"] if n.get("cpus") else []) + (
                [_gb(n["mem"])] if n.get("mem") else [])
            if meta:
                out.append(("meta", " · ".join(meta)))
            rows: list = []
            for g in sorted((g for g in c.get("guests") or [] if g.get("node") == n.get("name")),
                            key=lambda g: g.get("vmid") or 0):
                soort = ["CT" if g.get("type") == "lxc" else "VM", STATUS.get(g.get("status"), g.get("status") or "?")]
                if g.get("onboot"):
                    soort.append("autostart" + (f" {g['order']}" if g.get("order") is not None else ""))
                disks = _join([_disk(k) for k in g.get("disks") or []], "; ") or ["?"]
                rows.append([str(g.get("vmid")), g.get("name") or "", " · ".join(soort), _ip_cell(g), _nets(g), disks,
                             _backup_cell(g)])
                svc = _svc_row(g)
                if svc:
                    rows.append(("svc", svc))
            if rows:
                out.append(("table", ["ID", "naam", "soort", "IP", "MAC en netwerk", "schijven", "back-up"], rows,
                            "gasten"))
            else:
                out.append(("p", "Geen VM's of CT's op deze node."))
    return out


def _welke(j: dict) -> str:
    if not j.get("enabled", True):
        return "staat uit"
    ex = j.get("except") or []
    if j.get("all"):
        base = f"alle op {j['node']}" if j.get("node") else "alle"
        return base + (f" behalve {', '.join(str(v) for v in ex)}" if ex else "")
    if j.get("pool"):
        return f"pool {j['pool']} ({len(j.get('targets') or [])})"
    return ", ".join(str(v) for v in j.get("targets") or []) or "geen"


def _sync(p: dict, s: dict) -> str:
    host = next((r.get("host") for r in p.get("remotes") or [] if r.get("name") == s.get("remote")), None)
    other = f"{s.get('remote')}" + (f" ({host})" if host else "") + f", datastore {s.get('remote_store')}"
    if s.get("direction") == "push":
        return f"stuurt {s.get('store')} naar {other}, {s.get('schedule') or 'zonder schema'}"
    return f"haalt op van {other} naar {s.get('store')}, {s.get('schedule') or 'zonder schema'}"


def _encrypted(s: dict) -> str:
    e = s.get("encrypted")
    if e is None:
        return "onbekend"
    if e is False:
        return "nee"
    return ("ja" + (f", vingerafdruk {e}" if e not in (True, "ja", "1") else "")
            + (" (met master key)" if s.get("master_key") else ""))


def _backups(value: dict, d: dict) -> list[tuple]:
    out = [("h2", "4. Back-ups: waar ze staan", "backups")]
    pbs = d.get("pbs") or []
    if pbs:
        rows = []
        for p in pbs:
            stores = p.get("stores") or []
            used = "; ".join((f"{s.get('store')} " if len(stores) > 1 else "") + f"{_size(s.get('used'))} van "
                             f"{_size(s.get('total'))}" + (f", {s['groups']} groepen" if s.get("groups") is not None else "")
                             for s in stores)
            rows.append([p.get("name") or "", Link(p["url"]) if p.get("url") else "onbekend",
                         p.get("runs_on") or "eigen toestel",
                         "; ".join(f"{s.get('store')} ({s.get('path') or 'pad onbekend'})" for s in stores) or "?",
                         used or "?", "; ".join(_sync(p, s) for s in p.get("syncs") or []) or "geen"])
        out.append(("table", ["naam", "adres", "draait op", "datastore (pad)", "gebruikt", "sync"], rows, "pbs"))
        for p in pbs:
            if p.get("stale_from"):
                out.append(("note", "warn", f"{pbs_label(p.get('name'))}: uit het noodplan van {day(p['stale_from'])}."))
            if p.get("fingerprint"):
                out.append(("meta", f"{pbs_label(p.get('name'))}: TLS-vingerafdruk {p['fingerprint']}."))
            for s in p.get("stores") or []:
                if s.get("path"):
                    out.append(("p", [f"{pbs_label(p.get('name'))} opnieuw geïnstalleerd en de schijf met de datastore is er "
                                      f"nog: koppel die schijf weer op {s['path']} en ",
                                      Code(f"proxmox-backup-manager datastore create {s.get('store')} {s['path']} "
                                           "--reuse-datastore true"), " (PBS 3.3 of nieuwer)."]))
    else:
        out.append(("p", "Geen PBS-tegel in het dashboard: van de PBS'en zelf (datastores, paden, syncs) staat hier "
                         "niets. Welke opslag Proxmox gebruikt, staat hieronder."))
    for c in d.get("clusters") or []:
        jobs = c.get("jobs") or []
        if jobs:
            out.append(("h3", "Back-upjobs van Proxmox" + (f" (cluster {c['name']})" if c.get("name") else ""),
                        f"jobs-{c.get('key')}"))
            out.append(("table", ["job", "wanneer", "naar", "welke"], [
                [j.get("id") or "", j.get("schedule") or "", (j.get("storage") or "") + (
                    f" (PBS {j.get('server')}, datastore {j.get('datastore')})" if j.get("pbs") else ""), _welke(j)]
                for j in jobs], "jobs"))
        sto = c.get("pbs_storages") or []
        if sto:
            out.append(("h3", "PBS-opslag in Proxmox" + (f" (cluster {c['name']})" if c.get("name") else ""),
                        f"opslag-{c.get('key')}"))
            out.append(("table", ["opslag (ID)", "PBS", "datastore", "namespace", "versleuteld"], [
                [s.get("storage") + ("" if s.get("enabled", True) else " (staat uit)"), s.get("server") or "?",
                 s.get("datastore") or "?", s.get("namespace") or "—", _encrypted(s)] for s in sto], "opslag"))
    missing = [g for g in guests(d) if (g.get("coverage") or {}).get("level") == "err"]
    if missing:
        out.append(("note", "err", "Zonder back-up: " + ", ".join(
            f"{label(g)} {g.get('name') or ''} ({(g.get('coverage') or {}).get('why')})" for g in missing) + "."))
    return out


def _first_storage(d: dict) -> tuple[dict | None, dict | None]:
    """De eerste PBS-opslag in Proxmox en de eerste node met een IP, voor de stappen."""
    for c in d.get("clusters") or []:
        for s in c.get("pbs_storages") or []:
            node = next((n for n in c.get("nodes") or [] if n.get("ip") and n.get("online")), None)
            return s, node or next(iter(c.get("nodes") or []), None)
    c = next(iter(d.get("clusters") or []), {})
    return None, next((n for n in c.get("nodes") or [] if n.get("ip")), None)


def restore_command(g: dict, volid: str | None, storage: str | None) -> str:
    """CT: pct restore met --storage van de rootfs. VM: qmrestore zonder --storage: elke schijf gaat terug naar haar
    eigen opslag, zoals "From backup configuration" in de webinterface."""
    vmid = g.get("vmid")
    sub = "ct" if g.get("type") == "lxc" else "vm"
    vol = volid or f"{storage or '<PBS-opslag>'}:backup/{sub}/{vmid}/<tijd uit pvesm list>"
    if g.get("type") == "lxc":
        root = next((k.get("storage") for k in g.get("disks") or [] if k.get("key") == "rootfs"), None)
        return f"pct restore {vmid} {vol} --storage {root or '<opslag>'}"
    return f"qmrestore {vol} {vmid}"


def storage_note(g: dict) -> str | None:
    """pct restore zet alle volumes op --storage: een mount point in de back-up op een andere opslag dan de rootfs komt
    dus mee op die van de rootfs."""
    if g.get("type") != "lxc":
        return None
    root = next((k.get("storage") for k in g.get("disks") or [] if k.get("key") == "rootfs"), None)
    other = [k["key"] for k in g.get("disks") or []
             if k.get("key") != "rootfs" and k.get("in_backup") and k.get("storage") and k.get("storage") != root]
    if not other:
        return None
    return (f"pct restore zet alle volumes op --storage: {', '.join(other)} stond op een andere opslag dan de rootfs "
            "(zet het daarna terug met Move Volume)")


def pick_volid(g: dict, storage: str | None) -> tuple[str | None, str | None]:
    """(volid, opslag): die van de eerste PBS-opslag, anders een andere met een back-up van deze VM/CT."""
    vols = g.get("volids") or {}
    if storage and vols.get(storage):
        return vols[storage], storage
    for s, v in sorted(vols.items()):
        return v, s
    return None, storage


def _restore(value: dict, d: dict) -> list[tuple]:
    out = [("h2", "5. Een CT of VM terugzetten", "terugzetten")]
    sto, node = _first_storage(d)
    sid = sto.get("storage") if sto else "<PBS-opslag>"
    nip = node.get("ip") if node else None
    login = ["Meld je aan op de node: ", Link(f"https://{nip}:8006"), " (root@pam) of ", Code(f"ssh root@{nip}"), "."] \
        if nip else "Meld je aan op een node (webinterface op poort 8006, als root@pam, of met ssh als root)."
    add = (f"Nieuwe installatie: Datacenter → Storage → Add → Proxmox Backup Server met ID {sid} (dezelfde naam, anders "
           "kloppen de commando's hieronder niet)")
    if sto:
        add += (f", server {sto.get('server') or '?'}, datastore {sto.get('datastore') or '?'}"
                + (f", namespace {sto['namespace']}" if sto.get("namespace") else "")
                + f", gebruiker {sto.get('username') or '?'}"
                + (f", fingerprint {sto['fingerprint']}" if sto.get("fingerprint") else "")
                + (" en de encryptiesleutel (zie Sleutels)" if sto.get("encrypted") else ""))
    newest = max((b.get("last") for g in guests(d) for b in g.get("backups") or [] if b.get("last")), default=None)
    archs: dict[str, list[str]] = {}
    unknown = False
    for c in d.get("clusters") or []:
        for n in c.get("nodes") or []:
            if n.get("arch"):
                archs.setdefault(n["arch"], []).append(n["name"])
            else:
                unknown = True
    arch_text = "; ".join(f"{a} = {', '.join(ns)}" for a, ns in sorted(archs.items()))
    step5 = ["Terugzetten met het commando uit de tabel. Op een andere node kan dat ook, ",
             Bad("maar alleen op een node met dezelfde architectuur"),
             (f": {arch_text}" if arch_text else "") + "."]
    if unknown:
        step5 += [" Van een node is de architectuur onbekend: kijk ze na met ", Code("uname -m"), "."]
    step5.append(" Bestaat de opslag (bv. local-lvm) daar niet, kies er een met --storage. Een VM/CT die gebonden is "
                 "(PCI/USB-doorgifte) start alleen op zijn eigen node.")
    out.append(("ol", [
        login,
        ["Kijk of de PBS-opslag er is: ", Code("pvesm status"), f" toont {sid} als active. {add}."],
        ["Nieuwste back-up: ", Code(f"pvesm list {sid} --vmid <ID>"),
         f" (de tabel hieronder toont die van {day(newest)})." if newest else "."],
        ["Bestaat de CT/VM nog maar is hij stuk: eerst ", Code("pct stop <ID>"), " of ", Code("qm stop <ID>"),
         ", en zet ", Code("--force 1"), " achter het commando (dat overschrijft hem). Anders een vrij ID: ",
         Code("pvesh get /cluster/nextid"), "."],
        step5,
        ["Starten: ", Code("pct start <ID>"), " of ", Code("qm start <ID>"), ". MAC-adres en IP blijven die uit de "
         "back-up."],
        ["Wat ", Bad("niet in de back-up"), " zit (rood in de tabellen): bind mounts en apparaten van een CT, mount "
         "points zonder backup=1, VM-schijven met backup=0. Zet die inhoud apart terug, of maak de schijf leeg opnieuw "
         "aan."],
        f"Of in de webinterface: opslag {sid} → Backups → kies de nieuwste van het ID → Restore.",
    ]))
    multi = len(archs) > 1
    rows = []
    for c in d.get("clusters") or []:
        arch_of = {n.get("name"): n.get("arch") for n in c.get("nodes") or []}
        for g in sorted(c.get("guests") or [], key=lambda g: (g.get("node") or "", g.get("vmid") or 0)):
            volid, s = pick_volid(g, sto.get("storage") if sto else None)
            notes: list = []
            if (g.get("coverage") or {}).get("level") == "err":
                notes.append(Bad("geen back-up"))
            if miss := _uncovered(g):
                notes.append(Bad("niet in de back-up: " + ", ".join(k["key"] for k in miss)))
            if multi and arch_of.get(g.get("node")):
                notes.append(f"alleen op {arch_of[g['node']]}")
            for b in g.get("bound") or []:
                if b.get("node"):
                    notes.append(Bad(f"gebonden aan {b['node']}"))
                elif b.get("mapping"):
                    notes.append(f"mapping {b['mapping']} nodig")
            if note := storage_note(g):
                notes.append(note)
            if not g.get("config_from"):
                notes.append("configuratie onbekend")
            rows.append([g.get("node") or "", str(g.get("vmid")), g.get("name") or "", Code(restore_command(g, volid, s)),
                         _join(notes, "; ")])
    if rows:
        out.append(("table", ["node", "ID", "naam", "commando", "let op"], rows, "restore"))
    rt = d.get("restore_test")
    if rt and rt.get("at"):
        out.append(("p", f"De maandelijkse hersteltest zette laatst CT {rt.get('source_vmid')}"
                    + (f" ({rt['name']})" if rt.get("name") else "")
                    + f" terug op {day(rt['at'])}: {'gelukt' if rt.get('ok') else 'mislukt'}."))
    else:
        out.append(("p", "De maandelijkse hersteltest liep nog niet (Beheer → Hersteltest): niemand kijkt na of de "
                         "back-ups ook echt terug te zetten zijn."))
    return out


KINDS = {"opnsense": "OPNsense", "npm": "Nginx Proxy Manager", "pve": "Proxmox", "file": "eigen bestand"}


def _configs(value: dict, d: dict) -> list[tuple]:
    cfg = d.get("configs") or {}
    out = [("h2", "6. Configuratie van OPNsense en NPM", "configuratie")]
    rows = [[i.get("name") or KINDS.get(i.get("kind"), i.get("kind") or ""), when(i.get("ts")), str(i.get("versions")),
             "database van het dashboard, versleuteld"] for i in cfg.get("items") or []]
    if pve := cfg.get("pve"):
        rows.append([f"Proxmox: .conf van {pve.get('count')} VM's en CT's", when(pve.get("ts")), "per VM/CT",
                     "database van het dashboard, versleuteld"])
    if rows:
        out.append(("table", ["wat", "laatste kopie", "versies", "waar"], rows, "configs"))
    else:
        out.append(("p", "Nog geen kopieën: zet ze aan onder Beheer → Configuratiewijzigingen."))
    off = [KINDS[k] for k in ("opnsense", "npm", "pve") if (cfg.get("on") or {}).get(k) is False]
    if off:
        out.append(("note", "warn", "Geen kopie van: " + ", ".join(off) + " (staat uit)."))
    for e in (cfg.get("last") or {}).get("errors") or []:
        out.append(("note", "warn", f"Laatste kopie mislukt voor {e.get('source')}. {e.get('error')}"))
    hour = cfg.get("hour", 2)
    dash = d.get("dashboard") or {}
    where_dump = (f"dus ook in {dash.get('offsite_dir')}" if dash.get("offsite_on") else
                  f"in {dash.get('backup_dir') or 'de container'} (de kopie buiten de container staat uit)")
    out.append(("p", f"Elke nacht om {int(hour):02d}:00 bewaart het dashboard een kopie als er iets veranderde, "
                     "versleuteld in zijn database (tabel config_versions). Die database zit in elke nachtelijke dump, "
                     f"{where_dump}. Lezen kan alleen met het dashboard (Beheer → Configuratiewijzigingen → ↓, vraagt "
                     "2FA) of na het terugzetten van een dump met secret.key (sectie 8)."))
    out.append(("p", "OPNsense: installeer OPNsense opnieuw, dan System → Configuration → Backups → Restore met de "
                     "config.xml. OPNsense houdt zelf ook vorige versies bij onder System → Configuration → History."))
    npm = by_role(d, "npm")
    out.append(("p", "NPM: het dashboard bewaart de hosts als lijst, niet als back-up van NPM: zet bij voorkeur "
                + (f"{label(npm)} ({npm.get('name')})" if npm else "de VM/CT van NPM") + " terug uit PBS."))
    return out


def _keys(value: dict, d: dict) -> list[tuple]:
    dash = d.get("dashboard") or {}
    me = dash.get("guest")
    off = dash.get("offsite") or {}
    kfile = dash.get("secret_key_file") or "/etc/homepage/secret.key"
    if off.get("enabled") and off.get("key") and off.get("key_stale"):
        copy: object = Bad(f"verouderd: {off.get('dir')}/secret.key.enc hoort bij een oude secret.key — stel de "
                           "wachtzin opnieuw in (Gezondheid › homepage zelf)")
    elif off.get("enabled") and off.get("key"):
        copy = (f"versleuteld in {off.get('dir')}/secret.key.enc"
                + (f" (wachtzin ingesteld {day(dash['offsite_key_at'])})" if dash.get("offsite_key_at") else ""))
    elif dash.get("secret_saved_at"):
        copy = f"je bevestigde op {day(dash['secret_saved_at'])} dat je een kopie bewaarde"
    else:
        copy = Bad("geen kopie bekend")
    oidc = d.get("oidc") or {}
    login = "je gebruikersnaam, wachtwoord en 2FA-app" + (
        f"; Authentik op {oidc.get('ip') or oidc.get('host')}: ligt het plat, meld je dan aan met wachtwoord en 2FA"
        if oidc.get("enabled") else "")
    rows = [["secret.key", "wachtwoorden, API-sleutels en 2FA-geheimen in de database van het dashboard",
             f"{kfile} in " + (where(me) or "de container van het dashboard"), copy],
            ["wachtzin van secret.key.enc", "secret.key.enc openen",
             "nergens in het dashboard: alleen bij jou (je wachtwoordkluis)", "—"]]
    notes = []
    seen = set()
    for c in d.get("clusters") or []:
        for s in c.get("pbs_storages") or []:
            sid = s.get("storage")
            if sid in seen:
                continue
            seen.add(sid)
            enc = s.get("encrypted")
            if enc:
                rows.append([f"PBS-encryptiesleutel van opslag {sid}", f"back-ups op {sid} en hun sync-kopieën lezen",
                             f"/etc/pve/priv/storage/{sid}.enc op elke node van de cluster"
                             + (f" (vingerafdruk {enc})" if enc not in (True, "ja", "1") else ""),
                             Bad("maak een papieren kopie (hieronder)")])
                notes.append(("note", "err", [f"Valt de hele cluster weg, dan heb je een kopie van de sleutel van {sid} "
                                              "nodig. Maak er een papieren versie van op een node: ",
                                              Code(f"proxmox-backup-client key paperkey /etc/pve/priv/storage/{sid}.enc "
                                                   "--output-format text"), ", en bewaar die apart."]))
            else:
                rows.append([f"PBS-encryptiesleutel van opslag {sid}", "—",
                             "niet versleuteld" if enc is False else "versleuteling onbekend", "—"])
            rows.append([f"PBS-login van Proxmox ({sid})", "Proxmox aan de PBS koppelen",
                         f"/etc/pve/priv/storage/{sid}.pw, gebruiker {s.get('username') or '?'}", "in je wachtwoordkluis"])
    rows += [["Root-wachtwoorden van nodes, PBS en OPNsense", "aanmelden", "niet in het dashboard", "in je wachtwoordkluis"],
             ["API-tokens en -sleutels van de tegels", "het dashboard leest er Proxmox, PBS, OPNsense, NPM … mee",
              "versleuteld in de database van het dashboard (API-beheer)", "opnieuw maken: README, Fase 4"],
             ["SSH-sleutel van het dashboard", "de terminal en de scans", "privé deel versleuteld in de database",
              "de publieke sleutel staat in authorized_keys op elke host"],
             ["Aanmelden op het dashboard", login, "—", "2FA-app op je gsm"]]
    out = [("h2", "7. Sleutels: welke je nodig hebt en waar ze staan", "sleutels"),
           ("table", ["sleutel", "waarvoor", "waar", "kopie"], rows, "sleutels"), *notes]
    if isinstance(copy, Bad) and off.get("key_stale"):
        out.append(("note", "err", "secret.key.enc hoort bij een oude secret.key. Wie het opent, krijgt de oude sleutel "
                                   "en de wachtwoorden en API-sleutels in de back-ups van nu blijven onleesbaar. Stel de "
                                   "wachtzin opnieuw in (Gezondheid › homepage zelf) of bewaar secret.key in je "
                                   "wachtwoordkluis."))
    elif isinstance(copy, Bad):
        out.append(("note", "err", "Er is geen kopie van secret.key bekend: zonder dat bestand zijn de wachtwoorden en "
                                   "API-sleutels in elke back-up van het dashboard onleesbaar. Zet de kopie buiten de "
                                   "container aan (Gezondheid › homepage zelf) of bewaar het bestand in je "
                                   "wachtwoordkluis."))
    return out


RESTORE = {"ok": "gelukt", "fout": "mislukt", "overgeslagen": "overgeslagen"}


def _dashboard(value: dict, d: dict) -> list[tuple]:
    dash = d.get("dashboard") or {}
    me = dash.get("guest")
    dumps = dash.get("dumps") or []
    ver = dash.get("verified") or {}
    dump = (f"03:30 in {dash.get('backup_dir')}, de 5 nieuwste blijven"
            + (f"; nieuwste {dumps[0]['name']} van {day(dumps[0].get('at'))}" if dumps else "; nog geen")
            + (", leesbaar ✓" if ver.get("ok") else ", onleesbaar ✕" if ver.get("ok") is False else ""))
    rs = dash.get("restore") or {}
    test = (f"laatst {RESTORE.get(rs.get('status'), rs.get('status'))} op {day(rs.get('at'))}" if rs.get("at") else
            "nog geen") + (f"; laatst gelukt {day(rs['last_ok'])}" if rs.get("last_ok") and rs.get("status") != "ok" else "")
    off = dash.get("offsite") or {}
    if dash.get("offsite_on"):
        key = "✕ verouderd" if off.get("key") and off.get("key_stale") else "✓" if off.get("key") else "✕"
        copy = (f"{off.get('dir') or dash.get('offsite_dir')}: {off.get('count') or 0} dumps"
                + (f", nieuwste {off['latest']}" if off.get("latest") else "")
                + f", secret.key.enc {key}"
                + (f" ({off['error']})" if off.get("error") else ""))
    else:
        copy = "staat uit (Gezondheid › homepage zelf)"
    v = dash.get("versions") or {}
    db = (f"PostgreSQL {v['postgresql']}" + (f" met TimescaleDB {v['timescaledb']}" if v.get("timescaledb") else "")
          if v.get("postgresql") else "onbekend")
    addr = ", ".join(dash.get("domains") or []) or "geen naam in NPM"
    if dash.get("lan_open") and dash.get("ip"):
        addr += f"; rechtstreeks http://{dash['ip']} (het LAN mag erbij)"
    elif dash.get("lan_open") is False:
        addr += "; alleen via NPM"
    rows = [["container", where(me) or "onbekend"], ["IP", dash.get("ip") or "onbekend"], ["adres", addr],
            ["versie", f"{dash.get('versie') or '?'}" + (f" ({dash['kanaal']})" if dash.get("kanaal") else "")],
            ["nachtelijke dump", dump], ["maandelijkse test van de dump", test], ["kopie buiten de container", copy],
            ["database", db]]
    enter = [Code(f"pct enter {me.get('vmid')}"), f" op {me.get('node')}"] if me else ["de container"]
    scen = [
        ["Een update liep mis: in de container (", *enter, ") ", Code("homepage-terugzetten --lijst"), ", dan ",
         Code("homepage-terugzetten"), "."],
        f"De container is weg: zet {label(me) if me else 'de VM/CT van het dashboard'} terug uit PBS (sectie 5, het "
        "commando staat in de tabel)."
        + (f" Is PBS ook weg: een nieuwe container en de dump uit {dash.get('offsite_dir')} (hieronder)."
           if dash.get("offsite_on") else ""),
        ["Geen back-up van de CT: nieuwe Debian-container, ",
         Code("apt update && apt install -y curl && bash <(curl -fsSL "
              "https://raw.githubusercontent.com/Jonasz1996/homepage/nieuwste/deploy/bootstrap.sh)"),
         ", daarna:"],
    ]
    return [("h2", "8. Het dashboard zelf terugzetten", "dashboard"),
            ("table", ["wat", "hier"], rows, "kv"), ("ul", scen), ("pre", leesmij(v))]


# --- omzetten ------------------------------------------------------------------------------------------------------

def _esc(s) -> str:
    return html.escape(str(s), quote=True)


def _is_link(s: str) -> bool:
    return s.lower().startswith(("http://", "https://"))


def _h(x) -> str:
    if x is None:
        return ""
    if isinstance(x, (list, tuple)):
        return "".join(_h(i) for i in x)
    if isinstance(x, Code):
        return f"<code>{_esc(x)}</code>"
    if isinstance(x, Bad):
        return f'<strong class="bad">{_esc(x)}</strong>'
    if isinstance(x, Link) and _is_link(x):
        return f'<a href="{_esc(x)}" target="_blank" rel="noopener noreferrer">{_esc(x)}</a>'
    return _esc(x)


def to_html(bl: list[tuple], title: str) -> str:
    out = ['<!doctype html>\n<html lang="nl"><head><meta charset="utf-8">'
           '<meta name="viewport" content="width=device-width, initial-scale=1">'
           f"<title>{_esc(title)}</title><style>{CSS}</style></head><body>"]
    for b in bl:
        kind = b[0]
        if kind in ("h1", "h2", "h3"):
            out.append(f'<{kind} id="{_esc(b[2])}">{_h(b[1])}</{kind}>')
        elif kind == "p":
            out.append(f"<p>{_h(b[1])}</p>")
        elif kind == "meta":
            out.append(f'<p class="meta">{_h(b[1])}</p>')
        elif kind in ("ul", "ol"):
            out.append(f"<{kind}>" + "".join(f"<li>{_h(i)}</li>" for i in b[1]) + f"</{kind}>")
        elif kind == "note":
            out.append(f'<div class="note {_esc(b[1])}">{_h(b[2])}</div>')
        elif kind == "pre":
            out.append(f"<pre>{_esc(b[1])}</pre>")
        elif kind == "table":
            heads, rows, cls = b[1], b[2], b[3]
            body = []
            for r in rows:
                if isinstance(r, tuple) and r and r[0] == "svc":
                    body.append(f'<tr class="svc"><td colspan="{len(heads)}">{_h(r[1])}</td></tr>')
                else:
                    body.append("<tr>" + "".join(f"<td>{_h(c)}</td>" for c in r) + "</tr>")
            out.append(f'<div class="tbl"><table class="{_esc(cls)}"><thead><tr>'
                       + "".join(f"<th>{_esc(h)}</th>" for h in heads) + "</tr></thead><tbody>" + "".join(body)
                       + "</tbody></table></div>")
    out.append("</body></html>\n")
    return "".join(out)


def _m(x) -> str:
    if x is None:
        return ""
    if isinstance(x, (list, tuple)):
        return "".join(_m(i) for i in x)
    if isinstance(x, Code):
        return f"`` {x} ``" if "`" in x else f"`{x}`"
    if isinstance(x, Bad):
        return f"**{x}**"
    if isinstance(x, Link) and _is_link(x):
        return f"<{x}>"
    return str(x)


def _cell(x) -> str:
    return _m(x).replace("\n", " ").replace("|", "\\|")


def to_md(bl: list[tuple]) -> str:
    out: list[str] = []
    for b in bl:
        kind = b[0]
        if kind in ("h1", "h2", "h3"):
            out.append("#" * int(kind[1]) + " " + _m(b[1]))
        elif kind in ("p", "meta"):
            out.append(_m(b[1]))
        elif kind == "ul":
            out.append("\n".join(f"- {_m(i)}" for i in b[1]))
        elif kind == "ol":
            out.append("\n".join(f"{n}. {_m(i)}" for n, i in enumerate(b[1], 1)))
        elif kind == "note":
            out.append("> " + ("**Let op.** " if b[1] in ("warn", "err") else "") + _m(b[2]))
        elif kind == "pre":
            out.append("```\n" + b[1].rstrip("\n") + "\n```")
        elif kind == "table":
            heads, rows = b[1], b[2]
            lines = ["| " + " | ".join(_cell(h) for h in heads) + " |", "|" + "---|" * len(heads)]
            for r in rows:
                if isinstance(r, tuple) and r and r[0] == "svc":
                    cells = [""] * len(heads)
                    cells[min(1, len(heads) - 1)] = "↳ " + _cell(r[1])
                    lines.append("| " + " | ".join(cells) + " |")
                else:
                    lines.append("| " + " | ".join(_cell(c) for c in r) + " |")
            out.append("\n".join(lines))
    return "\n\n".join(out) + "\n"
