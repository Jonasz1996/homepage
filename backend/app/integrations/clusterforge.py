"""ClusterForge (homepage-API v2): één API voor alles in het homelab.

ClusterForge herkent de apps zelf (container, dienst, cluster) en geeft per app één tegel met de stats van de app,
waar ze draait, en wat Zabbix, CrowdSec, OPNsense, NPM/Authentik en de agents erover weten. Met `app` toont de
tegel die app; zonder `app` het overzicht. De tegels zelf maakt monitoring/clusterforge.py vanzelf aan.
"""

from typing import Any

from .base import Integration, IntegrationError, cell, field

API = "/api/dashboard/v2"
LEVEL = {"ok": None, "warn": "warn", "down": "err"}


def fmt(value: Any, kind: str | None) -> Any:
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


class ClusterForge(Integration):
    name = "clusterforge"
    label = "ClusterForge"
    config_help = {
        "url": "http://192.168.113.153:8080 (adres van ClusterForge)",
        "app": "op een tegel: de app (slug uit ClusterForge, bv. plex); leeg = overzicht",
        "sync": "true (standaard): tegels vanzelf aanmaken, bijwerken en verwijderen zoals ClusterForge ze herkent",
    }
    secret_help = {"token": "API-token uit ClusterForge (Instellingen → Dashboard-API), cfa_…"}
    call_prefix = API

    async def call_auth(self) -> dict:
        return {"headers": self.headers()}

    def headers(self) -> dict:
        (token,) = self.need("token")
        return {"Authorization": f"Bearer {token}", "Accept": "application/json"}

    async def get(self, path: str) -> Any:
        return await self.request("GET", API + path, headers=self.headers())

    def app(self) -> str:
        return str(self.config.get("app") or "").strip()

    async def tile(self) -> dict:
        app = self.app()
        if not app:
            raise IntegrationError("Geen app gekozen")
        data = await self.get(f"/apps/{app}")
        if not isinstance(data, dict):
            raise IntegrationError("Onverwacht antwoord van ClusterForge")
        return data

    async def summary(self) -> list[dict]:
        if not self.app():
            o = await self.get("/")
            v = (o or {}).get("values") or {}
            return [
                field("apps", o.get("apps_label"), None if o.get("ok") else "warn"),
                field("clusters", f"{v.get('clusters_healthy', 0)}/{v.get('clusters_total', 0)}"),
                field("nodes", v.get("nodes")),
                field("incidenten", v.get("incidents"), "warn" if v.get("incidents") else None),
                field("updates", v.get("updates")),
                field("bans", v.get("crowdsec_bans")),
            ]
        t = await self.tile()
        out = [field(str(f.get("label"))[:30], fmt(f.get("value"), f.get("format")), LEVEL.get(f.get("level") or "ok"))
               for f in t.get("fields") or []]
        return out[:8] or [field("status", t.get("status_label"), LEVEL.get(t.get("status")))]

    async def detail(self) -> dict:
        if not self.app():
            return {"sections": [{"kind": "kv", "title": "overzicht", "items": await self.summary()}]}
        t = await self.tile()
        sections = []
        for s in t.get("sections") or []:
            items = s.get("items") or []
            if s.get("type") == "table" and items:
                cols = list(items[0].keys())
                sections.append({"kind": "table", "title": s.get("title") or "", "columns": cols,
                                 "rows": [[cell(fmt(r.get(c), None)) for c in cols] for r in items]})
            else:
                sections.append({"kind": "kv", "title": s.get("title") or "",
                                 "items": [field(str(i.get("label")), fmt(i.get("value"), None)) for i in items]})
        href = t.get("clusterforge_url")
        if href:
            sections.append({"kind": "kv", "title": "ClusterForge", "items": [field("beheer", href)]})
        return {"sections": sections}
