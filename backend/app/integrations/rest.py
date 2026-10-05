"""Eigen API (REST) uit API-beheer: adres, aanmelding en sleutels op de API, de rest zijn eigen calls.

config: {"auth": {"type": "none|bearer|header|query|basic", "name": "X-Api-Key", "prefix": ""},
         "headers": {"Accept": "application/json"}, "insecure": false}
secrets: {"token": "..."} of bij basic {"username": "...", "password": "..."}
"""

from . import calls
from .base import Integration, IntegrationError

AUTH_TYPES = ("none", "bearer", "header", "query", "basic")


class RestApi(Integration):
    name = "rest"
    label = "Eigen API"
    config_help = {
        "auth": '{"type": "header", "name": "X-Api-Key"} (none, bearer, header, query of basic)',
        "headers": '{"Accept": "application/json"} (niet geheim)',
    }
    secret_help = {"token": "API-sleutel of token", "username": "bij basic", "password": "bij basic"}

    async def call_auth(self) -> dict:
        a = self.config.get("auth") or {}
        kind = a.get("type") or "none"
        headers = {str(k): str(v) for k, v in (self.config.get("headers") or {}).items()}
        out: dict = {"headers": headers}
        if kind == "none":
            return out
        if kind == "basic":
            out["auth"] = (self.need("username")[0], self.secrets.get("password", ""))
            return out
        token = self.need("token")[0]
        name = str(a.get("name") or "").strip()
        if kind == "bearer":
            headers["Authorization"] = f"Bearer {token}"
        elif kind == "header":
            headers[name or "X-Api-Key"] = f"{a.get('prefix') or ''}{token}"
        elif kind == "query":
            out["params"] = {name or "apikey": token}
        else:
            raise IntegrationError(f"Onbekende aanmelding: {kind}")
        return out

    async def summary(self) -> list[dict]:
        if not any(c["show"] == "tile" and c["fields"] for c in self.calls):
            raise IntegrationError("Nog geen velden voor de tegel: voeg ze toe in API-beheer (api)")
        return await calls.tile_fields(self)

    async def detail(self) -> dict:
        sections = await calls.sections(self)
        if not sections:
            sections = [{"kind": "code", "title": "antwoord", "text": "Nog geen calls: voeg ze toe in API-beheer (api)."}]
        return {"sections": sections}

    async def action(self, action: str, params: dict) -> str:
        return await calls.action(self, action)
