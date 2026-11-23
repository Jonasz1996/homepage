"""ClusterForge: de HA-clusters van ClusterForge (status, nodes, VIP, databases, incidenten, updates, CrowdSec,
firewall) en het beveiligingsoverzicht (SOC), via de alleen-lezen dashboard-API van ClusterForge.

De API staat op /api/dashboard/v1 met een API-token (cfa_…, ClusterForge: Instellingen → Dashboard-API (homepage) →
Token maken). Ze kan alleen lezen; ClusterForge rekent de cijfers hoogstens elke 15 s opnieuw uit.

Eén tegel kan drie dingen tonen:
- zonder instelling `cluster`: alle clusters die het token mag zien (overzicht + tabel), met "tegels per cluster";
- met `cluster` (slug, naam of id): één cluster; de check van de tegel wordt rood zolang het niet in orde is;
- met `soc` = true: het beveiligingsoverzicht (alleen met een token voor alle clusters);
- met `node` (id of hostname): één node uit /nodes; de check wordt rood als de node offline of down is.
Tegels per node en een groep per cluster maakt en onderhoudt app/clusterforge_sync.py (ClusterForge beheert dan dat
deel van het dashboard).
"""

from typing import Any
from urllib.parse import quote, urlsplit

from .base import Integration, IntegrationError, cell, field

PREFIX = "/api/dashboard/v1"
# Homepage-API v2: één tegel per app die ClusterForge zelf herkent (monitoring/clusterforge.py maakt die tegels).
V2 = "/api/dashboard/v2"
APP_LEVEL = {"ok": None, "warn": "warn", "down": "err"}

STATUS_LEVEL = {"healthy": "ok", "degraded": "warn", "down": "err", "split_brain": "err"}
DB_LEVEL = {"ok": "ok", "degraded": "warn", "down": "err"}
# SOC: normaal en waakzaam zijn in orde, verhoogd en kritiek niet.
SOC_LEVEL = {"normaal": "ok", "waakzaam": None, "verhoogd": "warn", "kritiek": "err"}
INCIDENT_LEVEL = {"critical": "err", "high": "err", "low": "warn"}


def _true(v: Any) -> bool:
    return str(v).strip().lower() in ("1", "true", "ja", "yes", "on")


def status_level(c: dict) -> str | None:
    return STATUS_LEVEL.get(str(c.get("status") or ""))


def incident_level(c: dict) -> str | None:
    if not c.get("incidents_open"):
        return "ok"
    return INCIDENT_LEVEL.get(str(c.get("incidents_worst") or ""), "warn")


def updates_text(c: dict) -> str:
    n, sec = int(c.get("updates") or 0), int(c.get("updates_security") or 0)
    return f"{n} ({sec} beveiliging)" if sec else str(n)


def node_ok(n: dict) -> bool:
    """In orde: online en niet down. Een node in onderhoud is nooit rood."""
    if n.get("maintenance") or n.get("lifecycle") == "maintenance":
        return True
    return bool(n.get("online")) and n.get("status") not in ("down", "split_brain")


def node_level(n: dict) -> str | None:
    if not node_ok(n):
        return "err"
    return STATUS_LEVEL.get(str(n.get("status") or ""))


def app_value(value: Any, kind: str | None) -> Any:
    if value is None or value == "":
        return "—"
    if kind == "percent" and isinstance(value, (int, float)):
        return f"{value:.0f}%"
    if kind == "bytes" and isinstance(value, (int, float)):
        return {"bytes": value}
    if isinstance(value, bool):
        return "ja" if value else "nee"
    if isinstance(value, float):
        return round(value, 2)
    return value


def _empty_value(v: Any) -> bool:
    return v is None or (isinstance(v, str) and v.replace(" ", "") in ("", "0/0", "—", "-"))


def score_text(c: dict) -> str:
    if c.get("score") is None:
        return "—"
    return f"{c['score']} {c.get('grade') or ''}".strip()


class ClusterForge(Integration):
    name = "clusterforge"
    label = "ClusterForge"
    config_help = {
        "url": "http://<IP van ClusterForge>:8080 (rechtstreeks op IP, zonder /api)",
        "cluster": "optioneel: slug, naam of id van één cluster; leeg = alle clusters",
        "soc": "true voor het beveiligingsoverzicht (SOC) in plaats van de clusters",
        "node": "optioneel: id of hostname van één node (zet de beheerde sync zelf)",
        "app": "optioneel: één app uit ClusterForge (slug, bv. plex; zet de app-sync zelf)",
        "sync": "op een API van soort ClusterForge: false om geen app-tegels te laten beheren (standaard aan)",
        "link": "optioneel: adres waarmee je ClusterForge in de browser opent (bv. https://clusterforge.jbogaert.be); "
                "standaard het adres van de API",
        "insecure": "true bij https met een zelfondertekend certificaat",
    }
    secret_help = {"token": "API-token cfa_… (ClusterForge: Instellingen → Dashboard-API (homepage) → Token maken)"}
    call_prefix = PREFIX

    # --- aanmelding en calls ------------------------------------------------------

    def headers(self) -> dict:
        return {"Authorization": f"Bearer {self.need('token')[0]}", "Accept": "application/json"}

    async def call_auth(self) -> dict:
        return {"headers": self.headers()}

    def _error_detail(self, r) -> str | None:
        # ClusterForge geeft {"code": ..., "message": ...}: die zin zegt meer dan alleen de HTTP-status.
        try:
            msg = (r.json() or {}).get("message")
        except ValueError:
            return None
        return f"ClusterForge: {str(msg)[:200]} (HTTP {r.status_code})" if msg else None

    async def get(self, path: str) -> Any:
        return await self.request("GET", PREFIX + path, headers=self.headers())

    @property
    def cluster_key(self) -> str:
        return str(self.config.get("cluster") or "").strip()

    @property
    def app_key(self) -> str:
        return str(self.config.get("app") or "").strip()

    async def app(self, strict: bool = False) -> dict:
        data = await self.request("GET", f"{V2}/apps/{quote(self.app_key, safe='')}" + ("?strict=1" if strict else ""),
                                  headers=self.headers())
        if not isinstance(data, dict):
            raise IntegrationError("Onverwacht antwoord van ClusterForge")
        return data

    @staticmethod
    def app_fields(t: dict) -> list[dict]:
        # Een veld zonder inhoud (bv. "Nodes 0/0" bij een tegel via NPM) zegt niets: weg.
        out = [field(str(f.get("label"))[:30], app_value(f.get("value"), f.get("format")),
                     APP_LEVEL.get(f.get("level") or "ok")) for f in t.get("fields") or []
               if not _empty_value(f.get("value"))]
        return out[:8] or [field("status", t.get("status_label"), APP_LEVEL.get(t.get("status")))]

    def app_detail(self, t: dict) -> dict:
        sections = []
        for s in t.get("sections") or []:
            items = s.get("items") or []
            if s.get("type") == "table" and items:
                cols = list(items[0].keys())
                sections.append({"kind": "table", "title": s.get("title") or "", "columns": cols,
                                 "rows": [[cell(app_value(r.get(c), None)) for c in cols] for r in items]})
            else:
                sections.append({"kind": "kv", "title": s.get("title") or "",
                                 "items": [field(str(i.get("label")), app_value(i.get("value"), None)) for i in items]})
        if t.get("clusterforge_url"):
            sections.append({"kind": "kv", "title": "ClusterForge", "items": [field("beheer", self.link(t["clusterforge_url"]))]})
        return {"sections": sections or [{"kind": "kv", "title": t.get("name") or "app", "items": self.app_fields(t)}]}

    @property
    def node_key(self) -> str:
        return str(self.config.get("node") or "").strip()

    @property
    def soc_mode(self) -> bool:
        return _true(self.config.get("soc"))

    def link(self, url: str | None) -> str | None:
        """De link naar ClusterForge, met het adres uit `link` in plaats van het IP waarop de API gevraagd werd."""
        if not url:
            return None
        base = str(self.config.get("link") or "").strip().rstrip("/")
        if not base.lower().startswith(("http://", "https://")):
            return url
        p = urlsplit(url)
        return base + p.path + (f"?{p.query}" if p.query else "")

    async def overview(self) -> dict:
        data = await self.get("/")
        if not isinstance(data, dict) or "clusters" not in data:
            raise IntegrationError("Geen antwoord van de dashboard-API: klopt de url (http://<IP>:8080, zonder /api)?")
        return data

    async def cluster(self, key: str | None = None) -> dict:
        key = key or self.cluster_key
        data = await self.get("/clusters/" + quote(key, safe=""))
        if not isinstance(data, dict) or "status" not in data:
            raise IntegrationError("Geen antwoord van de dashboard-API: klopt de url (http://<IP>:8080, zonder /api)?")
        return data

    async def soc(self) -> dict:
        data = await self.get("/soc")
        if not isinstance(data, dict) or "level" not in data:
            raise IntegrationError("Geen beveiligingsoverzicht van ClusterForge")
        return data

    async def soc_or_none(self) -> dict | None:
        """Het SOC-overzicht als het token het mag zien (een token voor enkele clusters mag dat niet)."""
        try:
            return await self.soc()
        except IntegrationError:  # ook Forbidden: een token voor enkele clusters
            return None

    async def nodes(self) -> list[dict] | None:
        """Alle nodes die het token mag zien, of None als deze ClusterForge /nodes nog niet kent (HTTP 404)."""
        try:
            data = await self.get("/nodes")
        except IntegrationError as e:
            if "HTTP 404" in str(e):
                return None
            raise
        if isinstance(data, dict):  # ook goed als ClusterForge ze later in {"items": [...]} zet
            data = data.get("items") or data.get("nodes")
        if not isinstance(data, list):
            raise IntegrationError("Geen lijst van nodes van ClusterForge")
        return [n for n in data if isinstance(n, dict) and n.get("id")]

    async def node(self, key: str | None = None) -> dict:
        key = (key or self.node_key).lower()
        rows = await self.nodes()
        if rows is None:
            raise IntegrationError("Deze ClusterForge geeft nog geen nodes (/api/dashboard/v1/nodes): werk ClusterForge bij")
        for n in rows:
            if key in (str(n.get("id")).lower(), str(n.get("hostname") or "").lower()):
                return n
        raise IntegrationError(f"Node {key} niet gevonden in ClusterForge (of niet zichtbaar met dit token)")

    async def clusters(self) -> list[dict]:
        """Alle clusters die het token mag zien, voor "tegels per cluster"."""
        return (await self.overview()).get("clusters") or []

    # --- check van de tegel --------------------------------------------------------

    async def health(self) -> dict:
        """Voor de api-check: een fout (dus rood) zolang het cluster, de node of het SOC niet in orde is."""
        if self.app_key:
            return await self.app(strict=True)  # ClusterForge geeft zelf een fout als de app niet gezond is
        if self.node_key:
            n = await self.node()
            if not node_ok(n):
                why = n.get("status_reason") or ("offline" if not n.get("online") else "")
                raise IntegrationError(f"{n.get('hostname')}: {n.get('status_label') or n.get('status')}"
                                       f"{' · ' + why if why else ''}"[:200])
            return n
        if self.soc_mode:
            s = await self.soc()
            if not s.get("ok"):
                raise IntegrationError(f"SOC {s.get('level_label') or s.get('level')}: {s.get('reason') or 'niet in orde'}"[:200])
            return s
        if self.cluster_key:
            c = await self.cluster()
            if not c.get("ok"):
                why = "; ".join((c.get("problems") or [])[:2]) or c.get("status_reason") or ""
                raise IntegrationError(f"{c.get('name')}: {c.get('status_label') or c.get('status')}"
                                       f"{' · ' + why if why else ''}"[:200])
            return c
        o = await self.overview()
        bad = [c for c in o.get("clusters") or [] if c.get("status") in ("down", "split_brain")]
        if bad:
            raise IntegrationError("Down: " + ", ".join(f"{c.get('name')} ({c.get('status_label')})" for c in bad)[:200])
        return {k: v for k, v in o.items() if k != "clusters"}

    # --- tegel ---------------------------------------------------------------------

    @staticmethod
    def cluster_fields(c: dict) -> list[dict]:
        vip_level = "err" if c.get("vip") and not c.get("vip_owner") else None
        return [
            field("status", c.get("status_label") or c.get("status"), status_level(c)),
            field("nodes", c.get("nodes"), "err" if c.get("nodes_down") else "ok"),
            field("VIP", c.get("vip_owner") or ("geen node" if c.get("vip") else "—"), vip_level),
            field("database", c.get("db_label") or "—", DB_LEVEL.get(str(c.get("db") or ""))),
            field("incidenten", c.get("incidents_open") or 0, incident_level(c)),
            field("updates", updates_text(c), "warn" if c.get("updates_security") else None),
        ]

    @staticmethod
    def node_fields(n: dict) -> list[dict]:
        online = n.get("online")
        return [
            field("status", n.get("status_label") or n.get("status"), node_level(n)),
            field("online", "onderhoud" if n.get("maintenance") else "ja" if online else "nee",
                  None if n.get("maintenance") else "ok" if online else "err"),
            field("IP", n.get("primary_ip") or "—"),
            field("rol", n.get("role") or "—"),
            field("updates", updates_text(n), "warn" if n.get("updates_security") else None),
            field("herstart", "nodig" if n.get("reboot_required") else "nee", "warn" if n.get("reboot_required") else None),
        ]

    @staticmethod
    def soc_fields(s: dict) -> list[dict]:
        unprot = int(s.get("nodes_unprotected") or 0)
        return [
            field("niveau", s.get("level_label") or s.get("level"), SOC_LEVEL.get(str(s.get("level") or ""))),
            field("score", s.get("score")),
            field("aanvallen 24u", s.get("attacks_24h") or 0, "warn" if s.get("attacks_24h") else None),
            field("bans", s.get("active_bans") or 0),
            field("geblokkeerd 24u", s.get("blocked_24h") or 0),
            field("beschermd", s.get("protected") or "—", "warn" if unprot else "ok"),
        ]

    @staticmethod
    def overview_fields(o: dict) -> list[dict]:
        total, healthy = int(o.get("clusters_total") or 0), int(o.get("clusters_healthy") or 0)
        down, degraded = int(o.get("clusters_down") or 0), int(o.get("clusters_degraded") or 0)
        inc = int(o.get("incidents_open") or 0)
        offline = int(o.get("nodes_total") or 0) - int(o.get("nodes_online") or 0)
        worst = [c.get("incidents_worst") for c in o.get("clusters") or [] if c.get("incidents_open")]
        return [
            field("clusters", f"{healthy}/{total} gezond", "err" if down else "warn" if degraded else "ok" if total else None),
            field("nodes", o.get("nodes"), "err" if offline > 0 else "ok"),
            field("incidenten", inc, ("err" if {"critical", "high"} & set(worst) else "warn") if inc else "ok"),
            field("updates", updates_text(o), "warn" if o.get("updates_security") else None),
        ]

    async def summary(self) -> list[dict]:
        if self.app_key:
            fields = self.app_fields(await self.app())
            # Meer tegels van dezelfde app (monitoring/clusterforge.py): de cijfers staan op de eerste, hier alleen de status.
            return fields[:1] if self.config.get("cf_zelfde") else fields
        if self.node_key:
            return self.node_fields(await self.node())
        if self.soc_mode:
            return self.soc_fields(await self.soc())
        if self.cluster_key:
            return self.cluster_fields(await self.cluster())
        o = await self.overview()
        fields = self.overview_fields(o)
        s = await self.soc_or_none()
        if s is not None:
            fields.append(field("SOC", s.get("level_label") or s.get("level"), SOC_LEVEL.get(str(s.get("level") or ""))))
        return fields

    # --- mini dashboard ---------------------------------------------------------------

    def _cluster_row(self, c: dict) -> dict:
        vip = c.get("vip") or ""
        owner = c.get("vip_owner") or ""
        return {"cells": [
            cell(c.get("name"), href=self.link(c.get("url"))),
            cell(c.get("status_label") or c.get("status"), status_level(c)),
            cell(score_text(c)),
            cell(c.get("nodes"), "err" if c.get("nodes_down") else "ok"),
            cell(f"{vip} → {owner}" if vip and owner else f"{vip} → geen node" if vip else "—",
                 "err" if vip and not owner else None),
            cell(c.get("db_label") or "—", DB_LEVEL.get(str(c.get("db") or ""))),
            cell(c.get("incidents_open") or 0, incident_level(c)),
            cell(updates_text(c), "warn" if c.get("updates_security") else None),
            cell(c.get("reboot_required") or 0, "warn" if c.get("reboot_required") else None),
            cell(c.get("crowdsec") or "—"),
            cell(c.get("firewall") or "—"),
        ]}

    COLUMNS = ["cluster", "status", "score", "nodes", "VIP", "database", "incidenten", "updates", "herstart",
               "CrowdSec", "firewall"]

    def _soc_section(self, s: dict) -> dict:
        items = self.soc_fields(s) + [
            field("mislukte logins 24u", s.get("login_failures_24h") or 0, "warn" if s.get("login_failures_24h") else None),
            field("aandacht", s.get("attention") or 0, "warn" if s.get("attention") else "ok"),
        ]
        if s.get("reason"):
            items.append(field("reden", s.get("reason")))
        return {"kind": "kv", "title": "beveiliging (SOC)", "items": items, "href": self.link(s.get("url"))}

    async def detail(self) -> dict:
        if self.app_key:
            return self.app_detail(await self.app())
        if self.node_key:
            n = await self.node()
            px = n.get("proxmox") or {}
            items = self.node_fields(n) + [
                field("cluster", n.get("cluster_name") or "geen"),
                field("levensfase", n.get("lifecycle") or "—"),
                field("Proxmox", f"{px.get('type') or ''} {px.get('vmid') or ''} op {px.get('host')}".strip() if px else "—"),
                field("tags", ", ".join(n.get("tags") or []) or "—"),
            ]
            if n.get("status_reason"):
                items.append(field("reden", n.get("status_reason")))
            return {"sections": [{"kind": "kv", "title": n.get("hostname") or "node", "items": items,
                                  "href": self.link(n.get("url"))}]}
        if self.soc_mode:
            return {"sections": [self._soc_section(await self.soc())]}
        if self.cluster_key:
            c = await self.cluster()
            items = self.cluster_fields(c) + [
                field("score", score_text(c)),
                field("omgeving", c.get("environment") or "—"),
                field("type", c.get("type") or "—"),
                field("herstart nodig", c.get("reboot_required") or 0, "warn" if c.get("reboot_required") else None),
                field("CrowdSec", c.get("crowdsec") or "—"),
                field("bans", c.get("crowdsec_bans") or 0),
                field("firewall", c.get("firewall") or "—"),
                field("geblokkeerd 24u", c.get("firewall_blocked_24h") or 0),
            ]
            return {"sections": [
                {"kind": "kv", "title": c.get("name") or "cluster", "items": items, "href": self.link(c.get("url"))},
                {"kind": "table", "title": "wat er mis is", "columns": ["probleem"], "empty": "Niets: alles in orde.",
                 "rows": [[cell(p, "err" if not c.get("ok") else "warn")] for p in c.get("problems") or []]},
                {"kind": "table", "title": "VIP's", "columns": ["adres", "node"], "empty": "Geen VIP.",
                 "rows": [[cell(v.get("address")), cell(v.get("owner") or "geen node", None if v.get("owner") else "err")]
                          for v in c.get("vips") or []]},
            ]}
        o = await self.overview()
        cl = sorted(o.get("clusters") or [], key=lambda c: (c.get("ok", True), str(c.get("name") or "").lower()))
        sections = [
            {"kind": "kv", "title": "overzicht", "items": self.overview_fields(o)},
            {"kind": "table", "title": "clusters", "filter": True, "columns": self.COLUMNS,
             "empty": "Geen clusters (of het token mag er geen zien).", "rows": [self._cluster_row(c) for c in cl]},
            {"kind": "table", "title": "wat er mis is", "columns": ["cluster", "probleem"], "empty": "Niets: alles in orde.",
             "rows": [[cell(c.get("name"), href=self.link(c.get("url"))), cell(p, status_level(c) or "warn")]
                      for c in cl for p in c.get("problems") or []]},
        ]
        s = await self.soc_or_none()
        if s is not None:
            sections.append(self._soc_section(s))
        sections.append({"kind": "clusterforge-beheer", "title": "dashboard laten beheren door ClusterForge"})
        sections.append({"kind": "clusterforge-tiles", "title": "tegels per cluster"})
        return {"sections": sections}
