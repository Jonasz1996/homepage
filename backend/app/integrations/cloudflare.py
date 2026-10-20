"""Cloudflare Tunnel: status van je tunnels (cloudflared) via de Cloudflare-API."""

import re

import httpx

from .base import Integration, IntegrationError, cell, field

API = "https://api.cloudflare.com/client/v4"
ACCOUNT_RE = re.compile(r"^[0-9a-f]{32}$")
LEVEL = {"healthy": "ok", "degraded": "warn", "down": "err", "inactive": "muted"}


class CloudflareTunnel(Integration):
    name = "cloudflared"
    label = "Cloudflare Tunnel"
    config_help = {
        "account": "account-id (32 tekens, rechts op de overzichtspagina van je domein in Cloudflare)",
        "tunnel": "optioneel: naam van één tunnel, anders alle",
    }
    secret_help = {"token": "API-token met het recht Account → Cloudflare Tunnel → Read"}

    def __init__(self, url: str | None, config: dict, secrets: dict, client: httpx.AsyncClient):
        # De tegel mag naar het Cloudflare-dashboard linken; de API staat altijd op api.cloudflare.com.
        super().__init__(config.get("url") or API, config, secrets, client)

    async def tunnels(self) -> list[dict]:
        account = str(self.config.get("account") or "").strip().lower()
        if not ACCOUNT_RE.match(account):
            raise IntegrationError("Account-id ontbreekt of klopt niet (32 tekens)")
        token = self.need("token")[0]
        data = await self.request("GET", f"/accounts/{account}/cfd_tunnel?is_deleted=false&per_page=100",
                                  headers={"Authorization": f"Bearer {token}"}) or {}
        if not data.get("success", True):
            raise IntegrationError("Cloudflare weigerde het verzoek")
        only = str(self.config.get("tunnel") or "").strip()
        out = []
        for t in data.get("result") or []:
            if only and t.get("name") != only:
                continue
            conns = t.get("connections") or []
            status = str(t.get("status") or "inactive")
            out.append({"id": t.get("id"), "name": t.get("name"), "status": status, "level": LEVEL.get(status, "warn"),
                        "connections": len(conns), "colos": sorted({c.get("colo_name") for c in conns if c.get("colo_name")}),
                        "version": next((c.get("client_version") for c in conns if c.get("client_version")), None),
                        "since": t.get("conns_active_at")})
        return sorted(out, key=lambda t: t["name"] or "")

    async def summary(self) -> list[dict]:
        ts = await self.tunnels()
        healthy = sum(1 for t in ts if t["status"] == "healthy")
        out = [field("tunnels", f"{healthy}/{len(ts)}", "ok" if ts and healthy == len(ts) else "err" if ts else None),
               field("verbindingen", sum(t["connections"] for t in ts))]
        if len(ts) == 1:
            out.insert(0, field("status", ts[0]["status"], ts[0]["level"]))
        return out

    async def detail(self) -> dict:
        ts = await self.tunnels()
        return {"sections": [{"kind": "table", "title": "tunnels",
                              "columns": ["tunnel", "status", "verbindingen", "datacenters", "versie"],
                              "rows": [[cell(t["name"]), cell(t["status"], t["level"]), cell(t["connections"]),
                                        cell(", ".join(t["colos"]) or "—"), cell(t["version"] or "—")] for t in ts]}]}
