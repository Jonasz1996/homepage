"""Tegels die ClusterForge beheert (homepage-API v2).

Elke minuut vraagt de worker bij elke API van soort clusterforge (API-beheer) de indeling op
(/api/dashboard/v2/homepage/layout, met ETag: als er niets veranderde kost dat niets). Elke app wordt een tegel
van type clusterforge in de groep met dezelfde naam (zo nodig nieuw, op de eerste pagina).

Wat de homepage zelf rechtzet aan wat ClusterForge stuurt:
- naam: een titel die niets zegt ("302 Found", "Welcome to nginx!", een IP) wordt de hostnaam uit de link;
  "Authentik (Authentik)" wordt "Authentik", "Authentik (npm)" wordt "Authentik" als die naam nog vrij is;
- dubbels: twee tegels met hetzelfde publieke adres (bv. via het cluster en via NPM) worden één tegel;
- groep: "overig" (of geen groep) wordt een groep geraden uit naam, app en icoon (Jellyfin → Media,
  Gitea → Infrastructuur); pas als niets past blijft het "Overig";
- check: heeft de tegel een link, dan kijkt de homepage zelf of het doel antwoordt (http op die link). Zo staat
  een dood doel rood ("doel antwoordt niet"), ook als ClusterForge de app gezond vindt, en omgekeerd. Zonder link
  blijft het de api-check: rood zodra ClusterForge de app niet gezond vindt;
- Proxmox: is er een Proxmox-API (API-beheer) waar de node van de tegel in zit, dan hangt de tegel aan die API
  met die node (mini dashboard van Proxmox, cijfers van die node). Anders tonen tegels van dezelfde app de cijfers
  van de app maar één keer (op de eerste); de andere tonen alleen hun status.

Tegels die ClusterForge maakte staan herkenbaar in config.managed_by = "clusterforge", config.cf_key en
config.cf_api (de ClusterForge-API). Alleen die worden bijgewerkt en verwijderd; tegels die je zelf maakte blijft
de sync uit de buurt. Een check die je zelf aanpaste blijft staan. Met "sync": false in de API staat dit uit.
"""

import ipaddress
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..db import ensure_state
from ..integrations import IntegrationError, from_api
from ..models import ApiConnection, Group, Page, Service
from .checks import HttpClients

log = logging.getLogger("homepage.clusterforge")

EVERY = 60
STATE_KEY = "clusterforge"
MANAGED = "clusterforge"
# Sleutels in de config die de sync zelf zet (en dus ook weer weghaalt).
AUTO_KEYS = ("managed_by", "cf_key", "cf_api", "app", "node", "cf_zelfde", "cf_name", "cf_icon", "cf_weg", "cf_terug")
# Checks die de sync zelf zet: alleen die mag hij vervangen.
AUTO_CHECKS = ({"type": "api", "interval": 60}, {"type": "http", "interval": 60})

# --- naam, dubbels, groep ---------------------------------------------------------------

# Titels van een webpagina die niets over de app zeggen (de naam kwam uit de HTTP-titel).
_EMPTY_TITLE = re.compile(
    r"^\s*(\d{3}(\s.*)?|moved( permanently)?|found|see other|(temporary|permanent) redirect|redirect(ing|ion)?\.*|"
    r"object moved|document moved|not found|forbidden|unauthori[sz]ed|bad gateway|service unavailable|"
    r"gateway time-?out|welcome to nginx!?|nginx|apache2? (ubuntu |debian )?default page.*|it works!?|"
    r"index of .*|untitled( document)?|loading\.*|just a moment\.*|default (web )?page|test page.*)\s*$", re.I)
_SUFFIX = re.compile(r"^(.*?)\s*\(([^()]*)\)\s*$")

OVERIG = "Overig"
_OVERIG = {"", "overig", "overige", "other", "others", "misc", "diversen", "uncategorized", "ongecategoriseerd",
           "andere", "rest"}
# Groep raden: het eerste dat past wint. Woorden worden vergeleken met de stukjes van naam, app, icoon en link.
CATEGORIES: list[tuple[str, tuple[str, ...]]] = [
    ("Media", ("jellyfin", "plex", "emby", "kodi", "tautulli", "overseerr", "jellyseerr", "ombi", "navidrome",
               "airsonic", "subsonic", "audiobookshelf", "immich", "photoprism", "piwigo", "kavita", "komga",
               "calibre", "tdarr", "handbrake", "music", "muziek", "photos", "fotos", "video", "tv", "films")),
    ("Downloads", ("sonarr", "radarr", "lidarr", "readarr", "prowlarr", "bazarr", "jackett", "whisparr", "qbittorrent",
                   "transmission", "deluge", "sabnzbd", "nzbget", "flaresolverr", "autobrr", "pinchflat", "metube",
                   "jdownloader", "youtubedl", "ytdl")),
    ("Domotica", ("homeassistant", "hass", "zigbee2mqtt", "zigbee", "mqtt", "mosquitto", "nodered", "esphome",
                  "frigate", "scrypted", "domoticz", "openhab", "homebridge", "solar", "p1")),
    ("AI", ("ai", "ollama", "openwebui", "webui", "llm", "comfyui", "localai", "aiverslag", "whisper", "qwen")),
    ("Productiviteit", ("nextcloud", "paperless", "agenda", "calendar", "radicale", "baikal", "bookstack", "wiki",
                        "outline", "vikunja", "mealie", "tandoor", "firefly", "actual", "onlyoffice", "collabora",
                        "joplin", "trilium", "memos", "linkwarden", "wallabag", "freshrss", "miniflux", "hedgedoc",
                        "excalidraw", "docs", "notes", "office", "mail", "kanban", "wordpress", "ghost")),
    ("Beveiliging", ("authentik", "keycloak", "vaultwarden", "bitwarden", "vault", "vaultx", "crowdsec", "ldap",
                     "authelia", "wazuh")),
    ("Monitoring", ("zabbix", "grafana", "prometheus", "uptime", "kuma", "netdata", "influxdb", "loki", "syslog",
                    "graylog", "scrutiny", "glances", "beszel", "dozzle")),
    ("Netwerk", ("adguard", "pihole", "dns", "dhcp", "opnsense", "pfsense", "unifi", "omada", "router", "switch",
                 "wireguard", "tailscale", "headscale", "cloudflared", "npm", "nginx", "proxy", "traefik", "caddy",
                 "speedtest", "netbootxyz", "pxe", "ntp", "guest", "wifi")),
    ("Tools", ("gokapi", "semaphore", "syncthing", "qdirstat", "filebrowser", "sftpgo", "cronicle", "ittools",
               "stirling", "convertx", "cyberchef", "drawio", "pairdrop", "snapdrop", "privatebin", "shlink", "n8n",
               "code", "vscode", "jupyter")),
    ("Infrastructuur", ("proxmox", "pve", "pbs", "backup", "portainer", "docker", "registry", "gitea", "gitlab",
                        "forgejo", "git", "clusterforge", "homepage", "truenas", "nas", "samba", "minio", "postgres",
                        "mariadb", "mysql", "redis", "guacamole", "webmin", "cockpit", "smtp", "dashboard")),
]
# Hoe die groepen ook kunnen heten: bestaat er al een groep met zo'n naam, dan komt een nieuwe tegel daar (bv.
# "Downloads" bij jou "Tools", "Domotica" bij jou "Smart home"). Pas als er geen is, komt de groep zelf.
ALIASES: dict[str, tuple[str, ...]] = {
    "Media": ("media", "multimedia", "entertainment"),
    "Downloads": ("downloads", "tools", "hulpmiddelen"),
    "Domotica": ("domotica", "smart home", "smarthome", "home automation", "huis"),
    "AI": ("ai", "kunstmatige intelligentie"),
    "Productiviteit": ("productiviteit", "productivity", "kantoor", "apps"),
    "Beveiliging": ("beveiliging", "security", "infrastructuur"),
    "Monitoring": ("monitoring", "infrastructuur"),
    "Netwerk": ("netwerk", "network", "infrastructuur"),
    "Tools": ("tools", "hulpmiddelen", "productiviteit"),
    "Infrastructuur": ("infrastructuur", "infra", "infrastructure", "systeem"),
}
_COMPOUND = {"home-assistant": "homeassistant", "home assistant": "homeassistant", "node-red": "nodered",
             "open-webui": "openwebui", "open webui": "openwebui", "pi-hole": "pihole", "uptime-kuma": "kuma"}


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _host(href: str | None) -> str:
    try:
        return (urlsplit(href or "").hostname or "").lower()
    except ValueError:
        return ""


def address(href: str | None) -> str | None:
    """Het publieke adres van een tegel, om dubbels te vinden: host, poort en pad zonder schema of / op het einde."""
    try:
        p = urlsplit((href or "").strip())
        host = (p.hostname or "").lower()
        port = p.port
    except ValueError:
        return None
    if not host:
        return None
    if port in (80, 443):
        port = None
    return f"{host}{':' + str(port) if port else ''}{p.path.rstrip('/')}"


def name_from_href(href: str | None, slug: str) -> str | None:
    """Een naam uit de link: ai.jbogaert.be → AI, home-assistant.x → Home Assistant; een IP → de app."""
    host = _host(href)
    if not host:
        return None
    if _is_ip(host):
        if slug and not _is_ip(slug) and not re.fullmatch(r"[\d.:_-]+", slug):
            return _pretty(slug)
        try:
            port = urlsplit(href or "").port
        except ValueError:
            port = None
        return f"{host}:{port}" if port else host
    return _pretty(host.split(".")[0])


def _pretty(word: str) -> str:
    word = word.strip()
    if len(word) <= 2:
        return word.upper()
    return " ".join(w[:1].upper() + w[1:] for w in re.split(r"[-_ ]+", word) if w)


def clean_name(name: str, href: str | None, slug: str) -> str:
    """De naam van ClusterForge, tenzij die niets zegt; "X (X)" wordt X."""
    name = (name or "").strip()
    if not name or _EMPTY_TITLE.match(name) or _is_ip(name.split(":")[0]):
        name = name_from_href(href, slug) or name or slug
    m = _SUFFIX.match(name)
    if m and m.group(1) and m.group(1).strip().lower() == m.group(2).strip().lower():
        name = m.group(1).strip()
    return name[:80]


def _words(*texts: str | None) -> tuple[set[str], str]:
    joined = " ".join(t for t in texts if t).lower()
    for k, v in _COMPOUND.items():
        joined = joined.replace(k, v)
    return {w for w in re.split(r"[^a-z0-9]+", joined) if w}, joined


def guess_group(name: str, slug: str, icon: str | None, href: str | None) -> str | None:
    """De groep voor een tegel zonder echte groep, of None als niets past."""
    host = _host(href)
    words, joined = _words(name, slug, (icon or "").rsplit("/", 1)[-1].rsplit(".", 1)[0], "" if _is_ip(host) else host.split(".")[0])
    for cat, keys in CATEGORIES:
        for k in keys:
            if k in words or (len(k) >= 5 and k in joined):
                return cat
    return None


def _target(t: dict) -> str | None:
    """Het echte doel achter NPM als ClusterForge het meestuurt (host:poort), anders None."""
    for k in ("target", "upstream", "backend"):
        v = str(t.get(k) or "").strip()
        if re.fullmatch(r"\[?[\w.:-]+\]?:\d{1,5}", v):
            return v
    return None


def category_of(gname: str) -> str | None:
    g = gname.strip().lower()
    for cat, names in ALIASES.items():
        if g == cat.lower() or g == names[0]:
            return cat
    return None


def resolve_group(gname: str, groups: dict[str, "Group"]) -> "Group | None":
    """De bestaande groep voor deze naam: dezelfde naam, of een groep die je anders noemt (ALIASES)."""
    if gname.lower() in groups:
        return groups[gname.lower()]
    cat = category_of(gname)
    for alias in ALIASES.get(cat or "", ()):
        if alias in groups:
            return groups[alias]
    return None


def is_overig(gname: str | None) -> bool:
    return str(gname or "").strip().lower() in _OVERIG


def _npm_like(t: dict) -> bool:
    """Een tegel die via NPM binnenkwam (naam of sleutel zegt npm): bij een dubbel wint de andere."""
    text = f"{t.get('name') or ''} {t.get('key') or ''}".lower()
    return bool(re.search(r"(^|[^a-z])npm([^a-z]|$)", text))


def wanted(layout: dict) -> list[tuple[str, int, dict]]:
    """(groep, positie, tegel) in de volgorde van ClusterForge, zonder bewerkingen."""
    out = []
    for g in layout.get("groups") or []:
        for i, t in enumerate(g.get("tiles") or []):
            if t.get("key") and t.get("app") and not t.get("gone"):
                out.append((str(g.get("name") or "ClusterForge")[:80], i, t))
    return out


def prepare(layout: dict) -> list[dict]:
    """De tegels zoals de homepage ze maakt: naam rechtgezet, dubbels eruit, groep geraden, kopieën gemarkeerd.

    Geeft per tegel {key, group, pos, name, href, icon, description, slug, zelfde} terug."""
    raw = wanted(layout)
    groups_named = {g.lower(): g for g, _, _ in raw if not is_overig(g)}
    # Dubbels op publiek adres: de tegel die niet via NPM kwam wint, anders de eerste.
    best: dict[str, int] = {}
    for i, (_, _, t) in enumerate(raw):
        addr = address(t.get("href"))
        if not addr:
            continue
        j = best.get(addr)
        if j is None or (_npm_like(raw[j][2]) and not _npm_like(t)):
            best[addr] = i
    # Dubbels van dezelfde app (bv. de Docker-container op http://IP:poort én dezelfde app op zijn naam via NPM): de
    # tegel op een naam wint. Niet voor Proxmox/PBS, waar elke node zijn eigen tegel is.
    named = {str(t["app"]).lower() for _, _, t in raw if _host(t.get("href")) and not _is_ip(_host(t.get("href")))}
    out: list[dict] = []
    for i, (gname, pos, t) in enumerate(raw):
        addr = address(t.get("href"))
        if addr and best[addr] != i:
            continue
        host = _host(t.get("href"))
        if host and _is_ip(host) and str(t["app"]).lower() in named and not is_proxmox(str(t["app"]), t.get("icon")) \
                and "backup" not in str(t["app"]).lower() and "pbs" not in str(t["app"]).lower():
            continue
        slug = str(t["app"])
        href = (str(t.get("href") or "")[:500]) or None
        icon = (str(t.get("icon") or "")[:500]) or None
        name = clean_name(str(t.get("name") or slug), href, slug)
        if is_overig(gname):
            cat = guess_group(name, slug, icon, href)
            gname = groups_named.get(cat.lower(), cat) if cat else OVERIG
        out.append({"key": str(t["key"]), "group": gname[:80], "pos": pos, "name": name, "href": href, "icon": icon,
                    "raw_name": str(t.get("name") or ""), "target": _target(t),
                    "description": (str(t.get("description") or "")[:255]) or None, "slug": slug, "zelfde": None})
    out = _same_app(out, raw)
    # "Authentik (npm)" → "Authentik" en "Gokapi (Docker)" → "Gokapi" als die naam nog vrij is.
    taken = {o["name"].lower() for o in out}
    for o in out:
        m = _SUFFIX.match(o["name"])
        if m and m.group(2).strip().lower() in SOURCES and m.group(1).strip().lower() not in taken:
            taken.add(m.group(1).strip().lower())
            o["name"] = m.group(1).strip()
    # Meer tegels van dezelfde app: de cijfers van de app maar op de eerste.
    first: dict[str, str] = {}
    for o in out:
        if o["slug"] in first:
            o["zelfde"] = first[o["slug"]]
        else:
            first[o["slug"]] = o["name"]
    return out


# Waar ClusterForge een app vond; staat soms achter de naam ("Gokapi (Docker)") en verandert, net als de sleutel
# (readarr@npm → readarr@docker), terwijl het dezelfde app blijft.
SOURCES = {"npm", "docker", "lxc", "ct", "vm", "container", "dienst", "service", "systemd", "cluster"}


def base_name(name: str) -> str:
    m = _SUFFIX.match(name or "")
    if m and m.group(1).strip() and m.group(2).strip().lower() in SOURCES:
        return m.group(1).strip().lower()
    return (name or "").strip().lower()


def _named_host(href: str | None) -> str | None:
    h = _host(href)
    return h if h and not _is_ip(h) else None


def _same_app(out: list[dict], raw) -> list[dict]:
    """Eén tegel per app: dezelfde app (zelfde app-slug en naam zonder "(npm)"/"(Docker)") via NPM én via Docker wordt
    één tegel. Twee verschillende publieke namen blijven twee tegels (twee instanties). Proxmox/PBS nooit (elke node
    een tegel). De tegel op een publieke naam wint, dan die niet via NPM, dan de eerste."""
    npm = {str(t["key"]): _npm_like(t) for _, _, t in raw}
    groups: dict[tuple[str, str], list[int]] = {}
    for i, o in enumerate(out):
        slug = o["slug"].lower()
        if is_proxmox(slug, o["icon"]) or "backup" in slug or "pbs" in slug:
            continue
        groups.setdefault((slug, base_name(o["name"])), []).append(i)
    drop: set[int] = set()
    for idx in groups.values():
        if len(idx) < 2:
            continue
        hosts = {_named_host(out[i]["href"]) for i in idx} - {None}
        if len(hosts) > 1:
            continue
        keep = min(idx, key=lambda i: (_named_host(out[i]["href"]) is None, npm.get(out[i]["key"], False), i))
        drop |= set(idx) - {keep}
    return [o for i, o in enumerate(out) if i not in drop]


# --- Proxmox -----------------------------------------------------------------------------

def is_proxmox(slug: str, icon: str | None) -> bool:
    text = f"{slug} {(icon or '').rsplit('/', 1)[-1]}".lower()
    return ("proxmox" in text or re.search(r"(^|[^a-z])pve([^a-z]|$)", text) is not None) and "backup" not in text \
        and "pbs" not in text


async def proxmox_nodes(db: AsyncSession, http: HttpClients) -> list[tuple[int, list[dict]]]:
    """Per Proxmox-API in API-beheer: de nodes (naam en IP) uit /cluster/status. Een API die niet antwoordt telt niet."""
    out = []
    for conn in (await db.execute(select(ApiConnection).where(ApiConnection.kind == "proxmox"))).scalars().all():
        try:
            items = await from_api(conn, {}, http).get("/cluster/status")
        except (IntegrationError, httpx.HTTPError, ValueError) as e:
            log.info("Proxmox %s voor ClusterForge-tegels: %s", conn.name, e)
            continue
        nodes = [{"name": str(i.get("name")), "ip": str(i.get("ip") or "")} for i in items or []
                 if isinstance(i, dict) and i.get("type") == "node" and i.get("name")]
        if nodes:
            out.append((conn.id, nodes))
    return out


def match_node(tile: dict, pve: list[tuple[int, list[dict]]]) -> tuple[int, str] | None:
    """(API, node) waar deze Proxmox-tegel bij hoort: op IP, op naam, of op het nummer (proxmox50 ↔ pve50)."""
    host = _host(tile.get("href"))
    words, _ = _words(tile.get("name"), tile.get("description"), tile.get("key"), host)
    words.add(host)
    label = "" if _is_ip(host) else host.split(".")[0]
    for how in ("ip", "naam", "nummer"):
        hits = []
        for api_id, nodes in pve:
            for n in nodes:
                if how == "ip":
                    ok = bool(n["ip"]) and (n["ip"] == host or n["ip"] in (tile.get("description") or ""))
                elif how == "naam":
                    ok = n["name"].lower() in words
                else:
                    a, b = re.search(r"(\d+)$", n["name"]), re.search(r"(\d+)$", label)
                    ok = bool(a and b and a.group(1) == b.group(1))
                if ok:
                    hits.append((api_id, n["name"]))
        if len(hits) == 1:
            return hits[0]
        if hits:
            return None  # meer dan één node past: liever niets dan de verkeerde
    return None


# --- sync ----------------------------------------------------------------------------------

def is_managed(svc: Service, conn_id: int | None = None) -> bool:
    cfg = svc.config or {}
    return cfg.get("managed_by") == MANAGED and (conn_id is None or cfg.get("cf_api", svc.api_id) == conn_id)


def _own_check(check: dict | None) -> bool:
    """Is dit nog de check die de sync zette (dan mag hij hem vervangen)?"""
    if not check:
        return True
    return check in AUTO_CHECKS or (check.get("type") == "api" and bool(check.get("path")))


async def fetch_layout(conn: ApiConnection, http: HttpClients, etag: str | None) -> tuple[dict | None, str | None]:
    """De indeling, of (None, etag) als er niets veranderde."""
    integ = from_api(conn, {}, http)
    headers = integ.headers()
    if etag:
        headers["If-None-Match"] = etag
    url = (conn.url or "").rstrip("/") + "/api/dashboard/v2/homepage/layout"
    try:
        r = await integ.client.get(url, headers=headers)
    except httpx.HTTPError as e:
        raise IntegrationError(f"ClusterForge niet bereikbaar: {type(e).__name__}") from e
    if r.status_code == 304:
        return None, etag
    if r.status_code != 200:
        raise IntegrationError(f"ClusterForge antwoordt {r.status_code}")
    return r.json(), r.headers.get("ETag")


ARCHIVE = "Archief (weg in ClusterForge)"
_ARCHIVE_NAMES = ("archief", "opruimen")


def _archive_group(groups: list[Group]) -> Group | None:
    return next((g for g in groups if g.name.strip().lower().startswith(_ARCHIVE_NAMES)), None)


async def apply(db: AsyncSession, conn: ApiConnection, layout: dict,
                pve: list[tuple[int, list[dict]]] | None = None) -> dict:
    """Maakt, wijzigt en archiveert de beheerde tegels van deze verbinding. Geeft de aantallen terug.

    Jouw indeling wint: een bestaande tegel blijft in de groep waar hij staat, en een naam die je zelf gaf blijft.
    Alleen nieuwe tegels krijgen een groep (een bestaande als die past, ook als je ze anders noemde). Een app die weg
    is in ClusterForge gaat met een gepauzeerde check naar de ingeklapte groep Archief (telt niet als down); komt hij
    terug, dan gaat hij terug naar zijn groep. Echte dubbels (dezelfde sleutel, of dezelfde app via NPM en Docker)
    gaan weg."""
    services = (await db.execute(select(Service).order_by(Service.id))).scalars().all()
    groups = list((await db.execute(select(Group))).scalars().all())
    # Ook tegels van een ClusterForge-API die niet meer bestaat (verwijderd en opnieuw gemaakt, of teruggezet uit een
    # back-up): die neemt deze API over in plaats van er dubbels naast te zetten.
    alive = set((await db.execute(select(ApiConnection.id).where(ApiConnection.kind == "clusterforge"))).scalars())
    stats = {"added": 0, "updated": 0, "removed": 0, "archived": 0}
    by_key: dict[str, Service] = {}
    for s in services:
        if is_managed(s) and (is_managed(s, conn.id) or (s.config or {}).get("cf_api", s.api_id) not in alive):
            key = (s.config or {}).get("cf_key")
            if key in by_key:  # dezelfde sleutel twee keer (bv. een oude worker tijdens een update): de oudste blijft
                await db.delete(s)
                stats["removed"] += 1
                continue
            by_key[key] = s
    group_by_name = {g.name.lower(): g for g in groups}
    page = (await db.execute(select(Page).order_by(Page.position, Page.id).limit(1))).scalar_one_or_none()
    if page is None:
        page = Page(name="Home", position=0)
        db.add(page)
        await db.flush()
    tiles = prepare(layout)
    live = {str(t["key"]) for _, _, t in wanted(layout)}  # ook de dubbels die prepare eruit haalde
    # Veranderde de sleutel (readarr@npm → readarr@docker), dan dezelfde tegel houden (notities, icoon, plaats, check)
    # in plaats van een nieuwe naast de oude: een tegel waarvan de sleutel verdween, met dezelfde app en hetzelfde
    # adres of dezelfde naam, schuift door naar de nieuwe sleutel.
    want = {t["key"] for t in tiles}
    orphans = {k: s for k, s in by_key.items() if k not in want}
    for t in tiles:
        if t["key"] in by_key or not orphans:
            continue
        for k, s in list(orphans.items()):
            same_app = str((s.config or {}).get("app") or "").lower() == t["slug"].lower()
            same_addr = address(s.url) is not None and address(s.url) == address(t["href"])
            if same_app and (same_addr or base_name(s.name) == base_name(t["name"])):
                by_key[t["key"]] = s
                del orphans[k], by_key[k]
                break
    archive = _archive_group(groups)
    seen = set()
    for t in tiles:
        key = t["key"]
        seen.add(key)
        config: dict[str, Any] = {"managed_by": MANAGED, "cf_key": key, "cf_api": conn.id, "app": t["slug"],
                                  "cf_name": t["name"], "cf_icon": t["icon"]}
        kind, api_id = "clusterforge", conn.id
        node = match_node(t, pve) if pve and is_proxmox(t["slug"], t["icon"]) else None
        if node:
            kind, api_id = "proxmox", node[0]
            config["node"] = node[1]
        elif t["zelfde"]:
            config["cf_zelfde"] = t["zelfde"]
        # Met een link kijkt de homepage zelf of het doel antwoordt; stuurt ClusterForge het doel achter NPM mee, dan
        # rechtstreeks daarop (een doorverwijzing naar Authentik zegt niets over de app). Anders vraagt de api-check
        # het aan ClusterForge.
        check = ({"type": "tcp", "target": t["target"], "interval": 60} if t["target"] else
                 {"type": "http" if t["href"] else "api", "interval": 60})
        svc = by_key.get(key)
        if svc is None:
            group = resolve_group(t["group"], group_by_name)
            if group is None:
                group = Group(page_id=page.id, name=t["group"], position=1000 + len(group_by_name))
                db.add(group)
                await db.flush()
                group_by_name[t["group"].lower()] = group
            db.add(Service(type=kind, api_id=api_id, position=1000 + t["pos"], config=config, check=check,
                           name=t["name"], description=t["description"], url=t["href"], icon=t["icon"],
                           group_id=group.id))
            stats["added"] += 1
            continue
        old_cfg = svc.config or {}
        values: dict[str, Any] = {"description": t["description"], "url": t["href"], "type": kind, "api_id": api_id}
        # De naam alleen als de sync hem zette (en jij hem niet veranderde); bij een tegel van voor deze regel: als
        # het nog de naam van ClusterForge is ("302 Found", "Authentik (npm)").
        if svc.name == old_cfg.get("cf_name") or ("cf_name" not in old_cfg and svc.name in (t["raw_name"], t["name"])):
            values["name"] = t["name"]
        else:
            config["cf_name"] = old_cfg.get("cf_name") or svc.name
        if not svc.icon or svc.icon == old_cfg.get("cf_icon", svc.icon):
            values["icon"] = t["icon"]
        check_now = svc.check or {}
        if old_cfg.get("cf_weg"):  # terug in ClusterForge: uit het archief, terug naar zijn groep, check weer aan
            back = await db.get(Group, old_cfg.get("cf_terug")) if old_cfg.get("cf_terug") else None
            values["group_id"] = (back or resolve_group(t["group"], group_by_name) or svc.group).id
            check_now = {k: v for k, v in check_now.items() if k != "paused"}
        changed = False
        for k, v in values.items():
            if getattr(svc, k) != v:
                setattr(svc, k, v)
                changed = True
        cfg = {**{k: v for k, v in old_cfg.items() if k not in AUTO_KEYS}, **config}
        if cfg != svc.config:
            svc.config = cfg
            changed = True
        if _own_check(check_now) and check_now != check:
            check_now = check
        if check_now != (svc.check or {}):
            svc.check = check_now
            changed = True
        if changed:
            stats["updated"] += 1
    # Weg in ClusterForge (of niet meer in de indeling): niet wissen maar archiveren. Een dubbel die prepare eruit haalde
    # (dezelfde app staat er nog) mag wel weg.
    for key, svc in by_key.items():
        if key in seen:
            continue
        if key in live:
            await db.delete(svc)
            stats["removed"] += 1
            continue
        cfg = svc.config or {}
        if cfg.get("cf_weg"):
            continue
        if archive is None:
            archive = Group(page_id=page.id, name=ARCHIVE, position=2000, collapsed=True)
            db.add(archive)
            await db.flush()
            group_by_name[archive.name.lower()] = archive
        svc.config = {**cfg, "cf_weg": datetime.now(timezone.utc).date().isoformat(), "cf_terug": svc.group_id}
        if svc.check and svc.check.get("type"):
            svc.check = {**svc.check, "paused": True}
        svc.group_id = archive.id
        stats["archived"] += 1
    await db.flush()
    # Een groep "overig" die de sync ooit maakte (positie vanaf 1000) en nu leeg is: weg.
    for g in group_by_name.values():
        if is_overig(g.name) and g.position >= 1000:
            left = (await db.execute(select(Service.id).where(Service.group_id == g.id).limit(1))).first()
            if left is None:
                await db.delete(g)
    return stats


async def run_sync(db: AsyncSession, http: HttpClients) -> None:
    conns = (await db.execute(select(ApiConnection).where(ApiConnection.kind == "clusterforge"))).scalars().all()
    if not conns:
        return
    st = await ensure_state(db, STATE_KEY)
    state = dict(st.value or {})
    # Kwam er een Proxmox-API bij (of ging er een weg), dan de indeling opnieuw toepassen, ook zonder wijziging.
    pve_ids = sorted(c for c in (await db.execute(select(ApiConnection.id).where(ApiConnection.kind == "proxmox"))).scalars())
    pve: list[tuple[int, list[dict]]] | None = None
    for conn in conns:
        if str((conn.config or {}).get("sync", True)).lower() in ("false", "0", "nee", "no"):
            continue
        cur = dict(state.get(str(conn.id)) or {})
        etag = cur.get("etag") if cur.get("pve") == pve_ids and cur.get("regels") == RULES else None
        try:
            layout, etag = await fetch_layout(conn, http, etag)
        except IntegrationError as e:
            cur["error"] = str(e)
            state[str(conn.id)] = cur
            log.warning("ClusterForge %s: %s", conn.name, e)
            continue
        cur["error"] = None
        if layout is not None:
            if pve is None:
                pve = await proxmox_nodes(db, http) if pve_ids else []
            stats = await apply(db, conn, layout, pve)
            cur.update(etag=etag, version=layout.get("version"), last=stats, pve=pve_ids, regels=RULES)
            if any(stats.values()):
                log.info("ClusterForge %s: %s nieuw, %s bijgewerkt, %s weg", conn.name, stats["added"], stats["updated"],
                         stats["removed"])
        state[str(conn.id)] = cur
    st.value = state


# Versie van de regels hierboven: verandert ze, dan past de volgende ronde de indeling opnieuw toe (ook bij 304).
RULES = 5
