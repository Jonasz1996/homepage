"""AdGuard Home: DNS-verzoeken, blokkades en bescherming aan/uit."""

from .base import Integration, IntegrationError, cell, field


def _top(items: list) -> list[tuple[str, int]]:
    out = []
    for d in items or []:
        out.extend(d.items())
    return out[:10]


class AdGuard(Integration):
    name = "adguard"
    label = "AdGuard Home"
    config_help = {"url": "https://adguard.jbogaert.be"}
    secret_help = {"username": "gebruikersnaam", "password": "wachtwoord"}
    actions = {"protection"}

    def auth(self):
        return tuple(self.need("username", "password"))

    async def get(self, path: str):
        return await self.request("GET", "/control" + path, auth=self.auth()) or {}

    async def summary(self) -> list[dict]:
        stats = await self.get("/stats")
        status = await self.get("/status")
        q = stats.get("num_dns_queries") or 0
        blocked = stats.get("num_blocked_filtering") or 0
        on = status.get("protection_enabled", True)
        return [
            field("verzoeken", q),
            field("geblokkeerd", f"{blocked / q * 100:.1f}%" if q else "0%"),
            field("latency", f"{(stats.get('avg_processing_time') or 0) * 1000:.0f} ms"),
            field("bescherming", "aan" if on else "uit", "ok" if on else "err"),
        ]

    async def detail(self) -> dict:
        stats = await self.get("/stats")
        status = await self.get("/status")
        on = status.get("protection_enabled", True)
        return {"sections": [
            {"kind": "kv", "title": "overzicht", "items": await self.summary(),
             "actions": [{"id": "protection", "label": "bescherming uit" if on else "bescherming aan",
                          "params": {"enabled": not on}, "confirm": on, "danger": on}]},
            {"kind": "table", "title": "meest geblokkeerd", "columns": ["domein", "aantal"],
             "rows": [[cell(d), cell(n)] for d, n in _top(stats.get("top_blocked_domains"))]},
            {"kind": "table", "title": "meest actieve clients", "columns": ["client", "verzoeken"],
             "rows": [[cell(d), cell(n)] for d, n in _top(stats.get("top_clients"))]},
        ]}

    async def action(self, action: str, params: dict) -> str:
        if action != "protection" or not isinstance(params.get("enabled"), bool):
            raise IntegrationError("Onbekende actie")
        await self.request("POST", "/control/protection", auth=self.auth(), json={"enabled": params["enabled"]})
        return "Bescherming " + ("aangezet" if params["enabled"] else "uitgezet")
