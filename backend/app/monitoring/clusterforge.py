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
AUTO_KEYS = ("managed_by", "cf_key", "cf_api", "app", "node", "cf_zelfde")
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
               "calibre", "tdarr", "handbrake", "music", "muziek", "photos", "fotos", "video", "tv", "films",
               "sonarr", "radarr", "lidarr", "readarr", "prowlarr", "bazarr", "jackett", "whisparr", "qbittorrent",
               "transmission", "deluge", "sabnzbd", "nzbget", "flaresolverr", "autobrr", "pinchflat", "metube")),
    ("Domotica", ("homeassistant", "hass", "zigbee2mqtt", "zigbee", "mqtt", "mosquitto", "nodered", "esphome",
                  "frigate", "scrypted", "domoticz", "openhab", "homebridge", "solar", "p1")),
    ("AI", ("ai", "ollama", "openwebui", "webui", "llm", "comfyui", "localai", "aiverslag", "whisper", "qwen")),
    ("Productiviteit", ("nextcloud", "paperless", "agenda", "calendar", "radicale", "baikal", "bookstack", "wiki",
                        "outline", "vikunja", "mealie", "tandoor", "firefly", "actual", "stirling", "convertx",
                        "onlyoffice", "collabora", "joplin", "trilium", "memos", "linkwarden", "wallabag", "freshrss",
                        "miniflux", "hedgedoc", "excalidraw", "n8n", "docs", "notes", "office", "mail", "kanban")),
    ("Infrastructuur", ("proxmox", "pve", "pbs", "backup", "npm", "nginx", "proxy", "traefik", "caddy", "adguard",
                        "pihole", "dns", "dhcp", "opnsense", "pfsense", "unifi", "omada", "router", "switch",
                        "authentik", "keycloak", "vaultwarden", "bitwarden", "vault", "vaultx", "gitea", "gitlab",
                        "forgejo", "git", "portainer", "docker", "registry", "clusterforge", "homepage", "zabbix",
                        "grafana", "prometheus", "uptime", "kuma", "netdata", "influxdb", "loki", "syslog",
                        "wireguard", "tailscale", "headscale", "cloudflared", "ldap", "guacamole", "webmin",
                        "cockpit", "minio", "truenas", "nas", "samba", "postgres", "mariadb", "mysql", "redis",
                        "crowdsec", "speedtest", "ntp", "smtp", "dashboard")),
]
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
            if t.get("key") and t.get("app"):
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
                    "description": (str(t.get("description") or "")[:255]) or None, "slug": slug, "zelfde": None})
    # "Authentik (npm)" → "Authentik" als die naam nog vrij is.
    taken = {o["name"].lower() for o in out}
    for o in out:
        m = _SUFFIX.match(o["name"])
        if m and m.group(2).strip().lower() == "npm" and m.group(1).strip().lower() not in taken:
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


async def apply(db: AsyncSession, conn: ApiConnection, layout: dict,
                pve: list[tuple[int, list[dict]]] | None = None) -> dict:
    """Maakt, wijzigt en verwijdert de beheerde tegels van deze verbinding. Geeft de aantallen terug."""
    services = (await db.execute(select(Service))).scalars().all()
    groups = (await db.execute(select(Group))).scalars().all()
    # Ook tegels van een ClusterForge-API die niet meer bestaat (verwijderd en opnieuw gemaakt, of teruggezet uit een
    # back-up): die neemt deze API over in plaats van er dubbels naast te zetten.
    alive = set((await db.execute(select(ApiConnection.id).where(ApiConnection.kind == "clusterforge"))).scalars())
    by_key = {}
    for s in services:
        if is_managed(s) and (is_managed(s, conn.id) or (s.config or {}).get("cf_api", s.api_id) not in alive):
            by_key.setdefault((s.config or {}).get("cf_key"), s)
    group_by_name = {g.name.lower(): g for g in groups}
    page = (await db.execute(select(Page).order_by(Page.position, Page.id).limit(1))).scalar_one_or_none()
    if page is None:
        page = Page(name="Home", position=0)
        db.add(page)
        await db.flush()
    stats = {"added": 0, "updated": 0, "removed": 0}
    seen = set()
    for t in prepare(layout):
        key = t["key"]
        seen.add(key)
        group = group_by_name.get(t["group"].lower())
        if group is None:
            group = Group(page_id=page.id, name=t["group"], position=1000 + len(group_by_name))
            db.add(group)
            await db.flush()
            group_by_name[t["group"].lower()] = group
        values: dict[str, Any] = {"name": t["name"], "description": t["description"], "url": t["href"],
                                  "icon": t["icon"], "group_id": group.id}
        config: dict[str, Any] = {"managed_by": MANAGED, "cf_key": key, "cf_api": conn.id, "app": t["slug"]}
        kind, api_id = "clusterforge", conn.id
        node = match_node(t, pve) if pve and is_proxmox(t["slug"], t["icon"]) else None
        if node:
            kind, api_id = "proxmox", node[0]
            config["node"] = node[1]
        elif t["zelfde"]:
            config["cf_zelfde"] = t["zelfde"]
        # Met een link kijkt de homepage zelf of het doel antwoordt; anders vraagt de api-check het aan ClusterForge.
        check = {"type": "http" if t["href"] else "api", "interval": 60}
        svc = by_key.get(key)
        if svc is None:
            db.add(Service(type=kind, api_id=api_id, position=1000 + t["pos"], config=config, check=check, **values))
            stats["added"] += 1
            continue
        changed = False
        for k, v in {**values, "type": kind, "api_id": api_id}.items():
            if getattr(svc, k) != v:
                setattr(svc, k, v)
                changed = True
        cfg = {**{k: v for k, v in (svc.config or {}).items() if k not in AUTO_KEYS}, **config}
        if cfg != svc.config:
            svc.config = cfg
            changed = True
        if _own_check(svc.check) and svc.check != check:
            svc.check = check
            changed = True
        if changed:
            stats["updated"] += 1
    for key, svc in by_key.items():
        if key not in seen:
            await db.delete(svc)
            stats["removed"] += 1
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
RULES = 3
