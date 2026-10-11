"""Cloudflare: status van je tunnels (cloudflared), en DNS-records en tunnelregels voor een nieuwe service."""

import hashlib
import re
from urllib.parse import quote

import httpx

from ..masking import mask
from .base import Integration, IntegrationError, cell, field

API = "https://api.cloudflare.com/client/v4"
ACCOUNT_RE = re.compile(r"^[0-9a-f]{32}$")
ID_RE = re.compile(r"^[0-9a-f]{32}$")
TUNNEL_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
RECORD_FIELDS = ("id", "type", "name", "content", "proxied", "comment")
# (zone, vingerafdruk van het token) -> zone-id: verandert nooit.
_zones: dict[tuple[str, str], str] = {}
LEVEL = {"healthy": "ok", "degraded": "warn", "down": "err", "inactive": "muted"}


class CloudflareTunnel(Integration):
    name = "cloudflared"
    label = "Cloudflare Tunnel"
    config_help = {
        "account": "account-id (32 tekens, rechts op de overzichtspagina van je domein in Cloudflare)",
        "tunnel": "optioneel: naam van één tunnel, anders alle",
    }
    secret_help = {"token": "API-token met het recht Account → Cloudflare Tunnel → Read"}

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


def _hex(value: str, what: str) -> str:
    v = str(value or "").strip().lower()
    if not ID_RE.match(v):
        raise IntegrationError(f"Ongeldige {what}")
    return v


def _tunnel_path(account: str, tunnel_id: str) -> str:
    a = str(account or "").strip().lower()
    t = str(tunnel_id or "").strip().lower()
    if not ACCOUNT_RE.match(a):
        raise IntegrationError("Account-id ontbreekt of klopt niet (32 tekens)")
    if not TUNNEL_RE.match(t):
        raise IntegrationError("Ongeldige tunnel-id")
    return f"/accounts/{a}/cfd_tunnel/{t}/configurations"


def record_create_request(zone_id: str, rec: dict) -> tuple[str, str, dict]:
    return "POST", f"/zones/{_hex(zone_id, 'zone-id')}/dns_records", rec


def record_delete_request(zone_id: str, rec_id: str) -> tuple[str, str, None]:
    return "DELETE", f"/zones/{_hex(zone_id, 'zone-id')}/dns_records/{_hex(rec_id, 'record-id')}", None


def tunnel_put_request(account: str, tunnel_id: str, config: dict) -> tuple[str, str, dict]:
    """De hele configuratie terug (ingress, originRequest, warp-routing, ...): Cloudflare vervangt ze in één keer."""
    return "PUT", _tunnel_path(account, tunnel_id), {"config": config}


class CloudflareDns(Integration):
    """DNS-records van één zone, en de regels van een tunnel die Cloudflare zelf beheert. Alleen voor een nieuwe
    service (nieuweservice.py): met proef en auditlog."""

    name = "cloudflare"
    label = "Cloudflare DNS"
    config_help = {"zone": "je domein, bv. jbogaert.be",
                   "account": "optioneel: account-id (32 tekens), alleen nodig als je namen via een Cloudflare Tunnel lopen"}
    secret_help = {"token": "API-token: Zone → Zone → Read en Zone → DNS → Edit voor dit domein, "
                            "plus Account → Cloudflare Tunnel → Edit bij een tunnel (README)"}

    def __init__(self, url: str | None, config: dict, secrets: dict, client: httpx.AsyncClient):
        super().__init__(API, config, secrets, client)
        # base.py neemt config["url"], en from_api() zet die altijd: dit token mag alleen naar api.cloudflare.com.
        self.base = API

    async def call_auth(self) -> dict:
        return {"headers": {"Authorization": f"Bearer {self.need('token')[0]}"}}

    @property
    def zone(self) -> str:
        return str(self.config.get("zone") or "").strip().lower().rstrip(".")

    @property
    def account(self) -> str:
        return str(self.config.get("account") or "").strip().lower()

    async def _call(self, method: str, path: str, body: dict | None = None):
        data = await self.request(method, path, json=body, **await self.call_auth()) or {}
        if not data.get("success", True):
            raise self._failed(data) or IntegrationError("Cloudflare weigerde het verzoek")
        return data

    def _failed(self, data: dict) -> IntegrationError | None:
        errs = data.get("errors") if isinstance(data, dict) else None
        if not errs or not isinstance(errs[0], dict):
            return None
        e = errs[0]
        return IntegrationError(mask(f"Cloudflare: {e.get('message') or '?'} ({e.get('code') or '?'})")[:200])

    def _error_detail(self, r: httpx.Response) -> str | None:
        # {"success": false, "errors": [{"code": 81053, "message": "An A, AAAA, or CNAME record ..."}]}
        try:
            e = self._failed(r.json())
        except ValueError:
            return None
        return str(e) if e else None

    async def send(self, method: str, path: str, body: dict | None = None):
        return (await self._call(method, path, body)).get("result")

    async def zone_id(self) -> str:
        if not self.zone:
            raise IntegrationError("Zone ontbreekt in de instellingen (bv. jbogaert.be)")
        key = (self.zone, hashlib.sha256(self.need("token")[0].encode()).hexdigest()[:12])
        if key in _zones:
            return _zones[key]
        result = (await self._call("GET", f"/zones?name={quote(self.zone)}")).get("result") or []
        zid = str((result[0] if result else {}).get("id") or "")
        if not ID_RE.match(zid):
            raise IntegrationError(f"Zone {self.zone} niet gevonden met dit token")
        _zones[key] = zid
        return zid

    async def records(self, name: str | None = None) -> list[dict]:
        zid = await self.zone_id()
        out, page = [], 1
        while True:
            q = f"per_page=1000&page={page}" + (f"&name={quote(name)}" if name else "")
            data = await self._call("GET", f"/zones/{zid}/dns_records?{q}")
            out += [{k: r.get(k) for k in RECORD_FIELDS} for r in data.get("result") or [] if isinstance(r, dict)]
            if page >= int((data.get("result_info") or {}).get("total_pages") or 1) or page >= 50:
                return out
            page += 1

    async def record(self, rec_id: str) -> dict:
        zid = await self.zone_id()
        r = (await self._call("GET", f"/zones/{zid}/dns_records/{_hex(rec_id, 'record-id')}")).get("result") or {}
        return {k: r.get(k) for k in RECORD_FIELDS}

    async def tunnel_config(self, account: str, tunnel_id: str) -> dict:
        r = (await self._call("GET", _tunnel_path(account, tunnel_id))).get("result") or {}
        return {"version": r.get("version"), "source": r.get("source"), "config": r.get("config") or {}}

    async def summary(self) -> list[dict]:
        recs = await self.records()
        return [field("records", len(recs)), field("geproxied", sum(1 for r in recs if r.get("proxied")))]
