"""Gemeenschappelijke basis voor integraties.

Een integratie levert drie dingen:
- summary(): een paar velden voor op de tegel ([{label, value, level}])
- detail():  secties voor het mini dashboard (kv, bars, table, code)
- action():  een actie zoals een VM herstarten; de API vraagt daarvoor eerst een recente 2FA-bevestiging
"""

import time
from typing import Any, ClassVar

import httpx

TIMEOUT = 8.0


class IntegrationError(Exception):
    """Fout die we zo aan de gebruiker tonen (geen stacktrace, geen geheimen)."""


def field(label: str, value: Any, level: str | None = None) -> dict:
    return {"label": label, "value": value, "level": level}


def cell(value: Any, level: str | None = None) -> dict:
    return {"v": value, "level": level}


def pct(part: float | None, total: float | None) -> float | None:
    if not total or part is None:
        return None
    return round(part / total * 100, 1)


def level_for(percent: float | None, warn: float = 80, err: float = 92) -> str | None:
    if percent is None:
        return None
    return "err" if percent >= err else "warn" if percent >= warn else "ok"


def ago(epoch: float | None) -> float | None:
    """Seconden geleden, of None."""
    return None if not epoch else max(0.0, time.time() - float(epoch))


class Integration:
    name: ClassVar[str]
    label: ClassVar[str]
    # Uitleg voor het formulier: welke instellingen en geheimen deze integratie verwacht.
    config_help: ClassVar[dict[str, str]] = {}
    secret_help: ClassVar[dict[str, str]] = {}
    actions: ClassVar[set[str]] = set()

    def __init__(self, url: str | None, config: dict, secrets: dict, client: httpx.AsyncClient):
        self.config = config or {}
        self.secrets = secrets or {}
        self.client = client
        base = (self.config.get("url") or url or "").strip().rstrip("/")
        if not base.lower().startswith(("http://", "https://")):
            raise IntegrationError("Geen geldige url in de instellingen (bv. https://pve.jbogaert.be)")
        self.base = base

    def need(self, *keys: str) -> list[str]:
        missing = [k for k in keys if not self.secrets.get(k)]
        if missing:
            raise IntegrationError(f"Geheim ontbreekt: {', '.join(missing)}")
        return [self.secrets[k] for k in keys]

    async def request(self, method: str, path: str, **kw) -> Any:
        try:
            r = await self.client.request(method, self.base + path, timeout=TIMEOUT, **kw)
        except httpx.TimeoutException as e:
            raise IntegrationError("Time-out") from e
        except httpx.HTTPError as e:
            raise IntegrationError(f"Niet bereikbaar: {type(e).__name__}") from e
        if r.status_code in (401, 403):
            raise IntegrationError(f"Geweigerd (HTTP {r.status_code}), controleer token of rechten")
        if r.status_code >= 400:
            raise IntegrationError(f"HTTP {r.status_code} op {path.split('?')[0]}")
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError as e:
            raise IntegrationError(f"Geen JSON op {path.split('?')[0]}") from e

    async def summary(self) -> list[dict]:
        raise NotImplementedError

    async def detail(self) -> dict:
        return {"sections": [{"kind": "kv", "title": "overzicht", "items": await self.summary()}]}

    async def action(self, action: str, params: dict) -> str:
        raise IntegrationError("Deze integratie heeft geen acties")

    async def quick_actions(self) -> list[dict]:
        """Acties voor de zoekbalk (Ctrl+K). Standaard: alle knoppen uit het mini dashboard."""
        if not self.actions:
            return []
        out = []
        for sec in (await self.detail()).get("sections", []):
            for a in sec.get("actions") or []:
                out.append({**a, "target": sec.get("title")})
            for row in sec.get("rows") or []:
                if not isinstance(row, dict) or not row.get("actions"):
                    continue
                parts = [str(c.get("v")) for c in row.get("cells", [])[:2]
                         if isinstance(c, dict) and isinstance(c.get("v"), (str, int)) and c.get("v") != "—"]
                for a in row["actions"]:
                    out.append({**a, "target": " ".join(parts)})
        return out
