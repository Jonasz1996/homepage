"""Cloudflare Tunnel: status van je tunnels (cloudflared) via de Cloudflare-API. Met een apart token (workers_token)
ook de Worker van de check van buitenaf zetten (monitoring/buitencheck.py)."""

import json
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
    secret_help = {
        "token": "API-token met het recht Account → Cloudflare Tunnel → Read",
        "workers_token": "optioneel: API-token met Account → Workers Scripts → Edit, voor de check van buitenaf (Netwerk → "
                         "check van buitenaf). Apart van het token hierboven; alleen nodig om de Worker te zetten.",
    }

    async def call_auth(self) -> dict:
        return {"headers": {"Authorization": f"Bearer {self.need('token')[0]}"}}

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

    # --- Workers (check van buitenaf) ----------------------------------------------------------------------------
    # Alleen met workers_token, nooit met het token voor de tunnels, en alleen naar api.cloudflare.com: een token dat
    # alle Workers van het account mag aanpassen, gaat zo nooit naar een ander adres.

    def _workers(self) -> tuple[str, dict]:
        if self.base != API:
            raise IntegrationError(f"Zet het adres van deze API op {API}")
        account = str(self.config.get("account") or "").strip().lower()
        if not ACCOUNT_RE.match(account):
            raise IntegrationError("Account-id ontbreekt of klopt niet (32 tekens)")
        return account, {"Authorization": f"Bearer {self.need('workers_token')[0]}"}

    async def _result(self, method: str, path: str, **kw):
        data = await self.request(method, path, **kw) or {}
        if not data.get("success", True):
            raise IntegrationError("Cloudflare weigerde het verzoek")
        return data.get("result")

    async def token_id(self) -> str | None:
        """Het ID van het workers_token (geen geheim), voor de proef en de auditlog. Een token van het account zelf
        (in plaats van een gebruiker) kent Cloudflare alleen onder het account."""
        account, auth = self._workers()
        try:
            res = await self._result("GET", "/user/tokens/verify", headers=auth)
        except IntegrationError as e:
            if not str(e).startswith("Geweigerd"):
                raise
            res = await self._result("GET", f"/accounts/{account}/tokens/verify", headers=auth)
        return (res or {}).get("id")

    async def worker_scripts(self) -> list[dict]:
        account, auth = self._workers()
        res = await self._result("GET", f"/accounts/{account}/workers/scripts", headers=auth)
        return [{"id": w.get("id"), "etag": w.get("etag"), "modified_on": w.get("modified_on")}
                for w in res or [] if isinstance(w, dict)]

    async def workers_subdomain(self) -> str | None:
        """De naam onder workers.dev (bv. jonas), of None als het account er nog geen koos."""
        account, auth = self._workers()
        try:
            res = await self._result("GET", f"/accounts/{account}/workers/subdomain", headers=auth)
        except IntegrationError as e:
            if str(e).startswith("HTTP 404"):
                return None
            raise
        return (res or {}).get("subdomain") or None

    async def run_worker_calls(self, calls: list[dict], secret: str, script: str
                               ) -> tuple[dict, IntegrationError | None]:
        """De calls van buitencheck.worker_calls na elkaar, precies zoals de proef ze toont, tot de eerste fout. upload:
        het script met zijn instellingen (multipart), met het echte geheim alleen in de verzonden metadata, in de plaats
        van de plaatshouder. Geeft ({soort: resultaat} van wat lukte (bij upload de etag), de eerste fout)."""
        _, auth = self._workers()
        done: dict = {}
        for c in calls:
            try:
                if c["kind"] == "upload":
                    meta = json.loads(json.dumps(c["data"]))
                    for b in meta.get("bindings") or []:
                        if b.get("name") == "HOMEPAGE_TOKEN":
                            b["text"] = secret
                    res = await self._result(c["method"], c["path"], headers=auth, files={
                        "metadata": (None, json.dumps(meta), "application/json"),
                        "worker.js": ("worker.js", script.encode(), "application/javascript+module")})
                    done["upload"] = (res or {}).get("etag")
                else:
                    await self._result(c["method"], c["path"], headers=auth, json=c["data"])
                    done[c["kind"]] = True
            except IntegrationError as e:
                return done, e
        return done, None
