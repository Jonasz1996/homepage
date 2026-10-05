"""Nginx Proxy Manager: proxy hosts, certificaten (vervaldatum) en import van hosts als tegels."""

import time
from datetime import datetime, timezone

from .base import Integration, IntegrationError, cell, field

# Tokens van NPM zijn standaard 1 dag geldig; we hergebruiken ze een uur.
_tokens: dict[tuple[str, str], tuple[str, float]] = {}


def days_left(expires_on: str | None) -> float | None:
    if not expires_on:
        return None
    try:
        dt = datetime.fromisoformat(str(expires_on).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return (dt - datetime.now(timezone.utc)).total_seconds() / 86400


def cert_level(days: float | None) -> str | None:
    if days is None:
        return None
    return "err" if days < 7 else "warn" if days < 21 else "ok"


def host_url(h: dict) -> str | None:
    names = h.get("domain_names") or []
    if not names or "*" in names[0]:
        return None
    return ("https://" if h.get("certificate_id") else "http://") + names[0]


class NginxProxyManager(Integration):
    name = "npm"
    label = "Nginx Proxy Manager"
    config_help = {"url": "http://192.168.0.245:81 (de beheerpoort van NPM)"}
    secret_help = {"username": "e-mailadres van de NPM-gebruiker", "password": "wachtwoord"}
    call_prefix = "/api"

    async def call_auth(self) -> dict:
        return {"headers": {"Authorization": f"Bearer {await self.token()}"}}

    async def token(self) -> str:
        user, secret = self.need("username", "password")
        key = (self.base, user)
        cached = _tokens.get(key)
        if cached and cached[1] > time.time():
            return cached[0]
        data = await self.request("POST", "/api/tokens", json={"identity": user, "secret": secret}) or {}
        if not data.get("token"):
            raise IntegrationError("Inloggen bij NPM mislukt")
        _tokens[key] = (data["token"], time.time() + 3600)
        return data["token"]

    async def get(self, path: str):
        return await self.request("GET", "/api" + path, headers={"Authorization": f"Bearer {await self.token()}"}) or []

    async def proxy_hosts(self) -> list[dict]:
        return await self.get("/nginx/proxy-hosts")

    async def certificates(self) -> list[dict]:
        return await self.get("/nginx/certificates")

    async def summary(self) -> list[dict]:
        hosts = await self.proxy_hosts()
        certs = await self.certificates()
        off = sum(1 for h in hosts if not h.get("enabled"))
        soonest = min((d for d in (days_left(c.get("expires_on")) for c in certs) if d is not None), default=None)
        out = [field("hosts", len(hosts)), field("uit", off, "warn" if off else None)]
        if soonest is not None:
            out.append(field("cert", f"{soonest:.0f} d", cert_level(soonest)))
        return out

    async def detail(self) -> dict:
        hosts = sorted(await self.proxy_hosts(), key=lambda h: (h.get("domain_names") or [""])[0])
        certs = await self.certificates()
        cert_rows = []
        for c in sorted(certs, key=lambda c: days_left(c.get("expires_on")) or 0):
            d = days_left(c.get("expires_on"))
            cert_rows.append([cell(c.get("nice_name") or ", ".join(c.get("domain_names") or [])),
                              cell(c.get("provider") or "—"),
                              cell(f"{d:.0f} dagen" if d is not None else "—", cert_level(d))])
        return {"sections": [
            {"kind": "table", "title": "certificaten", "columns": ["naam", "bron", "vervalt over"], "rows": cert_rows},
            {"kind": "table", "title": "proxy hosts", "filter": True, "columns": ["domein", "doel", "ssl", "actief"],
             "rows": [[cell(", ".join(h.get("domain_names") or [])),
                       cell(f"{h.get('forward_scheme')}://{h.get('forward_host')}:{h.get('forward_port')}"
                            if h.get("forward_host") else "—"),
                       cell("ja" if h.get("certificate_id") else "nee", "ok" if h.get("certificate_id") else "warn"),
                       cell("ja" if h.get("enabled") else "nee", None if h.get("enabled") else "muted")]
                      for h in hosts]},
            {"kind": "npm-import", "title": "importeren"},
        ]}
