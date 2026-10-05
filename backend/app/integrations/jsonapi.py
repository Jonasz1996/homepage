"""Eigen JSON-API: kies zelf welke velden op de tegel komen.

config: {"url": "...", "fields": [{"label": "temp", "path": "sensors.0.value", "suffix": " °C"}]}
Voor homepage.dev "customapi" werkt ook "mappings" met "field" in plaats van "path".
"""

import json
from typing import Any

from .base import Integration, IntegrationError, field


def lookup(data: Any, path: str) -> Any:
    for part in str(path).split("."):
        if isinstance(data, list):
            try:
                data = data[int(part)]
            except (ValueError, IndexError):
                return None
        elif isinstance(data, dict):
            data = data.get(part)
        else:
            return None
    return data


def fmt(value: Any, kind: str | None, suffix: str) -> Any:
    if value is None:
        return "—"
    if kind == "percent" and isinstance(value, (int, float)):
        return f"{value:.0f}%"
    if kind == "bytes" and isinstance(value, (int, float)):
        return {"bytes": value}
    if isinstance(value, float):
        value = round(value, 2)
    if isinstance(value, (dict, list)):
        value = "…"
    return f"{value}{suffix}" if suffix else value


class JsonApi(Integration):
    name = "json"
    label = "Eigen JSON-API"
    config_help = {
        "url": "https://api.voorbeeld.be/status",
        "fields": '[{"label": "temp", "path": "sensors.0.value", "suffix": " °C"}] (format: number, percent, bytes)',
        "headers": '{"Accept": "application/json"} (niet geheim)',
    }
    secret_help = {"token": "optioneel: Bearer-token", "username": "optioneel: basic auth", "password": "optioneel: basic auth"}

    async def call_auth(self) -> dict:
        headers = dict(self.config.get("headers") or {})
        auth = None
        if self.secrets.get("token"):
            headers["Authorization"] = f"Bearer {self.secrets['token']}"
        elif self.secrets.get("username"):
            auth = (self.secrets["username"], self.secrets.get("password", ""))
        return {"headers": headers, "auth": auth}

    async def fetch(self) -> Any:
        kw = await self.call_auth()
        method = str(self.config.get("method") or "GET").upper()
        if method not in ("GET", "POST"):
            raise IntegrationError("method moet GET of POST zijn")
        return await self.request(method, "", **kw)

    def mapping(self) -> list[dict]:
        rows = self.config.get("fields") or self.config.get("mappings") or []
        return [r for r in rows if isinstance(r, dict) and (r.get("path") or r.get("field"))][:8]

    async def summary(self) -> list[dict]:
        data = await self.fetch()
        rows = self.mapping()
        if not rows:
            raise IntegrationError("Stel 'fields' in om waarden te tonen")
        out = []
        for r in rows:
            path = r.get("path") or r.get("field")
            out.append(field(str(r.get("label") or path)[:30], fmt(lookup(data, path), r.get("format"), str(r.get("suffix") or ""))))
        return out

    async def detail(self) -> dict:
        data = await self.fetch()
        sections = []
        if self.mapping():
            sections.append({"kind": "kv", "title": "velden", "items": await self.summary()})
        sections.append({"kind": "code", "title": "antwoord", "text": json.dumps(data, indent=2, ensure_ascii=False)[:8000]})
        return {"sections": sections}


class CustomApi(JsonApi):
    name = "customapi"
    label = "Custom API (homepage.dev)"
