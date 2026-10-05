"""Sjablonen voor API-beheer: bekende apps met hun aanmelding en een paar nuttige calls, zodat een API voor
Radarr of Jellyfin alleen nog een sleutel nodig heeft. Ingebouwde integraties (Proxmox, ...) staan er ook in.

Een sjabloon wordt gekoppeld aan tegels waarvan de naam, het icoon of de eerste naam van het adres overeenkomt
met een van de "match"-woorden.
"""

import re
from urllib.parse import urlsplit

CATEGORIES = ("Proxmox en back-up", "Netwerk", "Media", "Downloads", "Smart home", "Monitoring",
              "Bestanden en foto's", "Docker", "Overig")

H = {"type": "header", "name": "X-Api-Key"}
JSON = {"Accept": "application/json"}


def f(label, path, fmt="auto", **kw):
    return {"label": label, "path": path, "format": fmt, **kw}


def c(name, path, fields=(), show="tile", **kw):
    return {"name": name, "method": kw.pop("method", "GET"), "path": path, "show": show, "fields": list(fields), **kw}


def _arr(v: str, search: str) -> list[dict]:
    """Sonarr, Radarr, Lidarr, Readarr: dezelfde API, andere versie."""
    return [
        c("wachtrij", f"/api/{v}/queue?pageSize=1", [f("wachtrij", "totalRecords")]),
        c("ontbrekend", f"/api/{v}/wanted/missing?pageSize=1", [f("ontbrekend", "totalRecords")]),
        c("gezondheid", f"/api/{v}/health", [f("meldingen", "*.type", "count", warn=1)]),
        c("wachtrij (lijst)", f"/api/{v}/queue?pageSize=25", show="detail",
          table={"path": "records", "columns": [f("titel", "title"), f("status", "status"), f("resterend", "sizeleft", "bytes"),
                                                  f("klaar", "estimatedCompletionTime", "date")]}),
        c("systeem", f"/api/{v}/system/status", [f("versie", "version"), f("gestart", "startTime", "date")], show="detail"),
        c("zoek ontbrekende", f"/api/{v}/command", method="POST", show="action",
          body='{"name": "' + search + '"}'),
    ]


TEMPLATES: dict[str, dict] = {
    # --- ingebouwd -------------------------------------------------------------
    "proxmox": {"label": "Proxmox VE", "category": "Proxmox en back-up", "kind": "proxmox", "match": ["proxmox", "pve"],
                "config": {"insecure": True}, "hint": "Adres: https://<IP van een node>:8006, token zoals in de README."},
    "pbs": {"label": "Proxmox Backup Server", "category": "Proxmox en back-up", "kind": "proxmoxbackupserver",
            "match": ["pbs", "backupserver"], "config": {"insecure": True}, "hint": "Adres: https://<IP>:8007."},
    "adguard": {"label": "AdGuard Home", "category": "Netwerk", "kind": "adguard", "match": ["adguard"]},
    "npm": {"label": "Nginx Proxy Manager", "category": "Netwerk", "kind": "npm", "match": ["npm", "nginxproxymanager"],
            "hint": "Adres: de beheerpoort, bv. http://192.168.0.245:81."},
    "opnsense": {"label": "OPNsense", "category": "Netwerk", "kind": "opnsense", "match": ["opnsense", "firewall"],
                 "config": {"insecure": True}},
    "portainer": {"label": "Portainer", "category": "Docker", "kind": "portainer", "match": ["portainer"]},
    "homeassistant": {"label": "Home Assistant", "category": "Smart home", "kind": "homeassistant",
                      "match": ["homeassistant", "hass", "ha"]},
    "cloudflared": {"label": "Cloudflare Tunnel", "category": "Netwerk", "kind": "cloudflared", "match": ["cloudflare", "cloudflared"],
                    "url": "https://api.cloudflare.com/client/v4"},
    # --- media -------------------------------------------------------------------
    "jellyfin": {"label": "Jellyfin / Emby", "category": "Media", "match": ["jellyfin", "emby"],
                 "auth": {"type": "header", "name": "X-Emby-Token"}, "secret": "API-sleutel (Dashboard → API-sleutels)",
                 "calls": [c("nu bezig", "/Sessions", [f("speelt nu", "*.NowPlayingItem", "count")]),
                           c("bibliotheek", "/Items/Counts", [f("films", "MovieCount"), f("series", "SeriesCount"),
                                                               f("afleveringen", "EpisodeCount")]),
                           c("sessies", "/Sessions", show="detail",
                             table={"path": "", "columns": [f("gebruiker", "UserName"), f("toestel", "DeviceName"),
                                                            f("speelt", "NowPlayingItem.Name"), f("laatst", "LastActivityDate", "date")]})]},
    "plex": {"label": "Plex", "category": "Media", "match": ["plex"], "auth": {"type": "query", "name": "X-Plex-Token"},
             "headers": JSON, "secret": "X-Plex-Token",
             "calls": [c("streams", "/status/sessions", [f("streams", "MediaContainer.size")]),
                       c("bibliotheken", "/library/sections", [f("bibliotheken", "MediaContainer.size")], show="detail",
                         table={"path": "MediaContainer.Directory", "columns": [f("naam", "title"), f("soort", "type"),
                                                                                 f("bijgewerkt", "updatedAt", "date")]})]},
    "tautulli": {"label": "Tautulli", "category": "Media", "match": ["tautulli"], "auth": {"type": "query", "name": "apikey"},
                 "secret": "API-sleutel (Settings → Web Interface)",
                 "calls": [c("activiteit", "/api/v2?cmd=get_activity", [
                     f("streams", "response.data.stream_count"), f("transcode", "response.data.stream_count_transcode"),
                     f("bandbreedte", "response.data.total_bandwidth", suffix=" kbps")])]},
    "overseerr": {"label": "Overseerr / Jellyseerr", "category": "Media", "match": ["overseerr", "jellyseerr", "seerr"],
                  "auth": H, "secret": "API-sleutel (Settings → General)",
                  "calls": [c("aanvragen", "/api/v1/request/count", [f("wachtend", "pending", warn=5), f("bezig", "processing"),
                                                                       f("beschikbaar", "available")])]},
    "audiobookshelf": {"label": "Audiobookshelf", "category": "Media", "match": ["audiobookshelf"],
                       "auth": {"type": "bearer"}, "secret": "API-token (Settings → Users → jouw gebruiker)",
                       "calls": [c("bibliotheken", "/api/libraries", [f("bibliotheken", "libraries", "count")])]},
    # --- downloads -----------------------------------------------------------------
    "sonarr": {"label": "Sonarr", "category": "Downloads", "match": ["sonarr"], "auth": H,
               "secret": "API-sleutel (Settings → General)", "calls": _arr("v3", "MissingEpisodeSearch")},
    "radarr": {"label": "Radarr", "category": "Downloads", "match": ["radarr"], "auth": H,
               "secret": "API-sleutel (Settings → General)", "calls": _arr("v3", "MissingMoviesSearch")},
    "lidarr": {"label": "Lidarr", "category": "Downloads", "match": ["lidarr"], "auth": H,
               "secret": "API-sleutel (Settings → General)", "calls": _arr("v1", "MissingAlbumSearch")},
    "readarr": {"label": "Readarr", "category": "Downloads", "match": ["readarr"], "auth": H,
                "secret": "API-sleutel (Settings → General)", "calls": _arr("v1", "MissingBookSearch")},
    "prowlarr": {"label": "Prowlarr", "category": "Downloads", "match": ["prowlarr"], "auth": H,
                 "secret": "API-sleutel (Settings → General)",
                 "calls": [c("indexers", "/api/v1/indexer", [f("indexers", "", "count")]),
                           c("gezondheid", "/api/v1/health", [f("meldingen", "*.type", "count", warn=1)])]},
    "bazarr": {"label": "Bazarr", "category": "Downloads", "match": ["bazarr"], "auth": {"type": "header", "name": "X-API-KEY"},
               "secret": "API-sleutel (Settings → General)",
               "calls": [c("ondertitels", "/api/badges", [f("afleveringen", "episodes"), f("films", "movies"),
                                                          f("providers", "providers", warn=1)])]},
    "sabnzbd": {"label": "SABnzbd", "category": "Downloads", "match": ["sabnzbd", "sab"], "auth": {"type": "query", "name": "apikey"},
                "secret": "API-sleutel (Config → General)",
                "calls": [c("wachtrij", "/api?mode=queue&output=json", [f("snelheid", "queue.speed", suffix="B/s"),
                                                                         f("resterend", "queue.sizeleft"),
                                                                         f("items", "queue.noofslots")])]},
    # --- netwerk ---------------------------------------------------------------------
    "pihole": {"label": "Pi-hole (v5)", "category": "Netwerk", "match": ["pihole"], "auth": {"type": "query", "name": "auth"},
               "secret": "API-token (Settings → API)",
               "calls": [c("samenvatting", "/admin/api.php?summaryRaw", [f("verzoeken", "dns_queries_today"),
                                                                        f("geblokkeerd", "ads_percentage_today", "percent"),
                                                                        f("status", "status")])]},
    "traefik": {"label": "Traefik", "category": "Netwerk", "match": ["traefik"], "auth": {"type": "none"},
                "calls": [c("overzicht", "/api/overview", [f("routers", "http.routers.total"),
                                                           f("fouten", "http.routers.errors", warn=1),
                                                           f("services", "http.services.total")])]},
    # --- monitoring ------------------------------------------------------------------
    "prometheus": {"label": "Prometheus", "category": "Monitoring", "match": ["prometheus"], "auth": {"type": "none"},
                   "calls": [c("targets", "/api/v1/targets?state=active", [
                       f("targets", "data.activeTargets", "count"),
                       f("down", "data.activeTargets.*.health", "count", equals="down", warn=1, err=3)])]},
    "grafana": {"label": "Grafana", "category": "Monitoring", "match": ["grafana"], "auth": {"type": "bearer"},
                "secret": "service account token (optioneel voor de health-check)",
                "calls": [c("gezondheid", "/api/health", [f("database", "database"), f("versie", "version")])]},
    "glances": {"label": "Glances", "category": "Monitoring", "match": ["glances"], "auth": {"type": "none"},
                "calls": [c("snel", "/api/4/quicklook", [f("cpu", "cpu", "percent", warn=80, err=95),
                                                         f("ram", "mem", "percent", warn=85, err=95),
                                                         f("swap", "swap", "percent", warn=50)])]},
    "healthchecks": {"label": "Healthchecks", "category": "Monitoring", "match": ["healthchecks", "hc"], "auth": H,
                     "secret": "API-sleutel (alleen lezen mag)",
                     "calls": [c("checks", "/api/v3/checks/", [f("checks", "checks", "count"),
                                                               f("down", "checks.*.status", "count", equals="down", err=1)])]},
    "changedetection": {"label": "changedetection.io", "category": "Monitoring", "match": ["changedetection"],
                        "auth": {"type": "header", "name": "x-api-key"}, "secret": "API-sleutel (Settings → API)",
                        "calls": [c("systeem", "/api/v1/systeminfo", [f("pagina's", "watch_count"), f("wachtrij", "queue_size")])]},
    "frigate": {"label": "Frigate", "category": "Smart home", "match": ["frigate"], "auth": {"type": "none"},
                "calls": [c("stats", "/api/stats", [f("detectie", "detection_fps", suffix=" fps"),
                                                    f("uptime", "service.uptime", "duration"),
                                                    f("versie", "service.version")])]},
    # --- bestanden en foto's -----------------------------------------------------------
    "immich": {"label": "Immich", "category": "Bestanden en foto's", "match": ["immich"],
               "auth": {"type": "header", "name": "x-api-key"}, "secret": "API-sleutel (Account → API Keys)",
               "calls": [c("statistieken", "/api/server/statistics", [f("foto's", "photos"), f("video's", "videos"),
                                                                      f("gebruikt", "usage", "bytes")])]},
    "nextcloud": {"label": "Nextcloud", "category": "Bestanden en foto's", "match": ["nextcloud"],
                  "auth": {"type": "basic"}, "headers": {"OCS-APIRequest": "true"},
                  "secret": "beheerder en een app-wachtwoord", "secrets": ["username", "password"],
                  "calls": [c("serverinfo", "/ocs/v2.php/apps/serverinfo/api/v1/info?format=json", [
                      f("vrij", "ocs.data.nextcloud.system.freespace", "bytes"),
                      f("actief 24u", "ocs.data.activeUsers.last24hours"),
                      f("bestanden", "ocs.data.nextcloud.storage.num_files")])]},
    "paperless": {"label": "Paperless-ngx", "category": "Bestanden en foto's", "match": ["paperless"],
                  "auth": {"type": "header", "name": "Authorization", "prefix": "Token "}, "secret": "API-token (profiel)",
                  "calls": [c("statistieken", "/api/statistics/", [f("documenten", "documents_total"),
                                                                   f("inbox", "documents_inbox", warn=10)])]},
    "syncthing": {"label": "Syncthing", "category": "Bestanden en foto's", "match": ["syncthing"],
                  "auth": {"type": "header", "name": "X-API-Key"}, "secret": "API-sleutel (Acties → Instellingen)",
                  "calls": [c("status", "/rest/system/status", [f("uptime", "uptime", "duration")]),
                            c("versie", "/rest/system/version", [f("versie", "version")], show="detail")]},
    # --- leeg --------------------------------------------------------------------------
    "rest": {"label": "Eigen API (leeg)", "category": "Overig", "match": [], "auth": {"type": "header", "name": "X-Api-Key"}},
}


def norm(text: str | None) -> str:
    return re.sub(r"[^a-z0-9]", "", (text or "").lower())


def words_of(service) -> set[str]:
    """Waarop een tegel herkend wordt: de naam, het icoon en de eerste naam van het adres."""
    host = (urlsplit(service.url or "").hostname or "").split(".")[0]
    icon = re.sub(r"\.(png|svg|webp)$", "", (service.icon or "").lower()).removeprefix("sh-").removeprefix("mdi-")
    return {w for w in (norm(service.name), norm(host), norm(icon)) if w}


def match(service) -> str | None:
    """Het sjabloon dat bij een tegel past, of None. Een exacte naam gaat voor een deel van de naam."""
    words = words_of(service)
    best = None
    for key, t in TEMPLATES.items():
        for m in t["match"]:
            if m in words:
                return key
            if len(m) >= 3 and any(m in w for w in words) and best is None:
                best = key
    return best


def public() -> list[dict]:
    """Voor de browser: wat nodig is om een sjabloon te kiezen en in te vullen."""
    from . import REGISTRY

    out = []
    for key, t in TEMPLATES.items():
        kind = t.get("kind", "rest")
        cls = REGISTRY[kind]
        secrets = t.get("secrets") or (list(cls.secret_help) if kind != "rest" else
                                       [] if (t.get("auth") or {}).get("type") == "none" else
                                       ["username", "password"] if (t.get("auth") or {}).get("type") == "basic" else ["token"])
        out.append({"key": key, "label": t["label"], "category": t["category"], "kind": kind, "hint": t.get("hint"),
                    "secret": t.get("secret"), "secrets": secrets, "secret_help": cls.secret_help if kind != "rest" else {},
                    "calls": len(t.get("calls") or []), "url": t.get("url")})
    return out
