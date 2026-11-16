"""ClusterForge: de HA-clusters van ClusterForge (status, nodes, VIP, databases, incidenten, updates, CrowdSec,
firewall) en het beveiligingsoverzicht (SOC), via de alleen-lezen dashboard-API van ClusterForge.

De API staat op /api/dashboard/v1 met een API-token (cfa_…, ClusterForge: Instellingen → Dashboard-API (homepage) →
Token maken). Ze kan alleen lezen; ClusterForge rekent de cijfers hoogstens elke 15 s opnieuw uit.

Eén tegel kan drie dingen tonen:
- zonder instelling `cluster`: alle clusters die het token mag zien (overzicht + tabel), met "tegels per cluster";
- met `cluster` (slug, naam of id): één cluster; de check van de tegel wordt rood zolang het niet in orde is;
- met `soc` = true: het beveiligingsoverzicht (alleen met een token voor alle clusters).
"""

from typing import Any
from urllib.parse import quote, urlsplit

from .base import Integration, IntegrationError, cell, field

PREFIX = "/api/dashboard/v1"

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

    async def clusters(self) -> list[dict]:
        """Alle clusters die het token mag zien, voor "tegels per cluster"."""
        return (await self.overview()).get("clusters") or []

    # --- check van de tegel --------------------------------------------------------

    async def health(self) -> dict:
        """Voor de api-check: een fout (dus rood) zolang het cluster of het SOC niet in orde is."""
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
        sections.append({"kind": "clusterforge-tiles", "title": "tegels per cluster"})
        return {"sections": sections}
