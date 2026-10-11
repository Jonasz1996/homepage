"""Cloudflare Tunnel: status van je tunnels (cloudflared) via de Cloudflare-API.

Voor Netwerk › publiek (monitoring/exposure.py) leest hetzelfde token ook je zones, DNS-records, alle tunnels met hun
instellingen, de apps van Cloudflare Access en "Always Use HTTPS". Alleen lezen (GET): het dashboard verandert niets
in Cloudflare.
"""

import asyncio
import re

import httpx

from .base import Integration, IntegrationError, cell, field

API = "https://api.cloudflare.com/client/v4"
ACCOUNT_RE = re.compile(r"^[0-9a-f]{32}$")
ZONE_RE = re.compile(r"^[0-9a-f]{32}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
LEVEL = {"healthy": "ok", "degraded": "warn", "down": "err", "inactive": "muted"}
# Alleen deze soorten apps van Cloudflare Access vragen een login op een hostnaam. Een bladwijzer, een SaaS-app, de
# app launcher, WARP, infrastructure, dash_sso of mcp beschermen geen naam.
ACCESS_TYPES = {"self_hosted", "ssh", "vnc", "rdp"}
# Een regel "e-mail eindigt op gmail.com": dan kan iedereen met zo'n adres binnen (eenmalige code).
PUBLIC_MAIL = {"gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
               "icloud.com", "me.com", "proton.me", "protonmail.com", "gmx.com", "gmx.net", "telenet.be", "skynet.be",
               "proximus.be"}
# Zwakste eerst: de zwakste regel van een app telt.
VERDICTS = ("bypass", "everyone", "public_mail", "login")
MAX_POLICY_FETCH = 50
# user:pass@ in de dienst van een tunnel (zoals integrationchecks._USERINFO: die module importeert de integraties).
_USERINFO = re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s@]*@")


def _name(value) -> str:
    """Een naam zoals we hem vergelijken: kleine letters, zonder punt op het einde, IDN als punycode (zoals
    routes._norm; die module importeert de integraties)."""
    name = str(value or "").strip().lower().rstrip(".")
    try:
        return name.encode("idna").decode("ascii")
    except UnicodeError:
        return name


def _host_path(uri: str) -> dict:
    """"app.jbogaert.be/admin" of "https://app.jbogaert.be" → {host, path}."""
    u = re.sub(r"^[a-z][a-z0-9+.-]*://", "", str(uri or "").strip(), flags=re.I)
    host, sep, path = u.partition("/")
    return {"host": _name(host.split(":")[0]), "path": ("/" + path) if sep and path else None}


def _kinds(rules) -> list[tuple[str, dict]]:
    """Regels als [{"everyone": {}}, {"email_domain": {"domain": "gmail.com"}}] → [(soort, waarde)]."""
    out = []
    for r in rules or []:
        if isinstance(r, dict):
            out += [(str(k), v if isinstance(v, dict) else {}) for k, v in r.items()]
    return out


def _policy_verdict(p: dict) -> str:
    decision = str(p.get("decision") or "")
    include, require = _kinds(p.get("include")), _kinds(p.get("require"))
    kinds = {k for k, _ in include}
    if decision in ("bypass", "non_identity") and "everyone" in kinds and not require:
        return "bypass"
    if decision != "allow" or not include or require:
        return "login"
    if kinds == {"everyone"}:
        return "everyone"
    if kinds == {"email_domain"} and all(_name(v.get("domain")) in PUBLIC_MAIL for _, v in include):
        return "public_mail"
    return "login"


def access_app(raw) -> dict | None:
    """Een app van Cloudflare Access teruggebracht tot wat Netwerk › publiek nodig heeft: naam, soort, hosts en het
    oordeel over de policies (bypass, everyone, public_mail of login). Regels, e-mailadressen, groepen en de AUD-tag
    gaan hier verloren: ze verlaten deze functie nooit."""
    if not isinstance(raw, dict) or raw.get("type") not in ACCESS_TYPES:
        return None
    uris = [d.get("uri") for d in raw.get("destinations") or []
            if isinstance(d, dict) and d.get("type") == "public" and d.get("uri")]
    if not uris and raw.get("domain"):
        uris = [raw["domain"]]
    hosts = [h for h in (_host_path(u) for u in uris) if h["host"]]
    # Zonder policies laat Access niemand binnen: dat telt als login.
    verdict = min((_policy_verdict(p) for p in raw.get("policies") or [] if isinstance(p, dict)),
                  key=VERDICTS.index, default="login")
    return {"name": str(raw.get("name") or "")[:100], "type": raw["type"], "hosts": hosts, "verdict": verdict}


class CloudflareTunnel(Integration):
    name = "cloudflared"
    label = "Cloudflare Tunnel"
    config_help = {
        "account": "account-id (32 tekens, rechts op de overzichtspagina van je domein in Cloudflare)",
        "tunnel": "optioneel: naam van één tunnel, anders alle",
        "zones": "optioneel: alleen deze zones voor Netwerk › publiek (bv. jbogaert.be), anders alle",
    }
    secret_help = {"token": "API-token met Account → Cloudflare Tunnel → Read; voor Netwerk › publiek ook Zone → Zone → "
                            "Read, Zone → DNS → Read en Account → Access: Apps and Policies → Read"}

    async def call_auth(self) -> dict:
        return {"headers": self._bearer()}

    def __init__(self, url: str | None, config: dict, secrets: dict, client: httpx.AsyncClient):
        # De tegel mag naar het Cloudflare-dashboard linken; de API staat altijd op api.cloudflare.com.
        super().__init__(config.get("url") or API, config, secrets, client)

    def _account(self) -> str:
        account = str(self.config.get("account") or "").strip().lower()
        if not ACCOUNT_RE.match(account):
            raise IntegrationError("Account-id ontbreekt of klopt niet (32 tekens)")
        return account

    def _bearer(self) -> dict:
        return {"Authorization": f"Bearer {self.need('token')[0]}"}

    def zone_names(self) -> list[str]:
        """De zones uit de instelling zones (komma-gescheiden of een lijst), leeg = alle."""
        raw = self.config.get("zones") or []
        items = raw.split(",") if isinstance(raw, str) else raw if isinstance(raw, list) else []
        return [n for n in (_name(x) for x in items) if n]

    async def _get_ok(self, path: str) -> dict:
        data = await self.request("GET", path, headers=self._bearer()) or {}
        if not isinstance(data, dict) or not data.get("success", True):
            raise IntegrationError("Cloudflare weigerde het verzoek")
        return data

    async def _all(self, path: str, per_page: int, max_pages: int = 20) -> list[dict]:
        """Alle pagina's van een lijst (page=1, 2, ... tot result_info.total_pages)."""
        out: list[dict] = []
        sep = "&" if "?" in path else "?"
        for page in range(1, max_pages + 1):
            data = await self._get_ok(f"{path}{sep}per_page={per_page}&page={page}")
            result = data.get("result") or []
            out += [x for x in result if isinstance(x, dict)]
            try:
                total = int((data.get("result_info") or {}).get("total_pages") or 0)
            except (TypeError, ValueError):
                total = 0
            if not result or (total and page >= total) or (not total and len(result) < per_page):
                break
        return out

    async def tunnels(self) -> list[dict]:
        account = self._account()
        data = await self._get_ok(f"/accounts/{account}/cfd_tunnel?is_deleted=false&per_page=100")
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

    # --- voor Netwerk › publiek (alleen lezen) ------------------------------------------------------------------

    async def zones(self) -> list[dict]:
        """De actieve zones die het token ziet: [{id, name}], beperkt tot de instelling zones als die er is."""
        want = set(self.zone_names())
        out = []
        for z in await self._all("/zones?status=active", 50):
            zid, name = str(z.get("id") or ""), _name(z.get("name"))
            if ZONE_RE.match(zid) and name and (not want or name in want):
                out.append({"id": zid, "name": name})
        return out

    async def dns_records(self, zone_id: str) -> list[dict]:
        """Elk record van de zone, alleen naam, soort, inhoud (bij A, AAAA en CNAME) en oranje wolk."""
        if not ZONE_RE.match(zone_id):
            raise IntegrationError("Ongeldige zone-id")
        out = []
        for r in await self._all(f"/zones/{zone_id}/dns_records", 500):
            kind = str(r.get("type") or "").upper()
            content = str(r.get("content") or "").strip()
            content = _name(content) if kind == "CNAME" else content.lower() if kind in ("A", "AAAA") else ""
            out.append({"name": _name(r.get("name")), "type": kind, "content": content, "proxied": bool(r.get("proxied"))})
        return out

    async def tunnel_list(self) -> list[dict]:
        """Alle tunnels van het account, ook verwijderde, zonder de filter van de tegel (instelling tunnel)."""
        out = []
        for t in await self._all(f"/accounts/{self._account()}/cfd_tunnel", 100):
            tid = str(t.get("id") or "").lower()
            if UUID_RE.match(tid):
                out.append({"id": tid, "name": str(t.get("name") or tid), "status": str(t.get("status") or "inactive"),
                            "deleted": bool(t.get("deleted_at"))})
        return out

    async def tunnel_config(self, tunnel_id: str) -> dict | None:
        """Waar de tunnel elke naam heen stuurt (ingress), voor een tunnel die in Cloudflare beheerd wordt. Van
        originRequest blijft alleen access.required over (er kunnen headers met geheimen in staan)."""
        if not UUID_RE.match(tunnel_id):
            raise IntegrationError("Ongeldige tunnel-id")
        res = (await self._get_ok(f"/accounts/{self._account()}/cfd_tunnel/{tunnel_id}/configurations")).get("result") or {}
        cfg = res.get("config") if isinstance(res.get("config"), dict) else None
        if res.get("source") == "local" or not cfg:
            return {"source": "local", "ingress": []}

        def required(o) -> bool | None:
            acc = (o or {}).get("access") if isinstance(o, dict) else None
            return bool(acc.get("required")) if isinstance(acc, dict) and "required" in acc else None

        default = required(cfg.get("originRequest"))
        ingress = []
        for rule in cfg.get("ingress") or []:
            if not isinstance(rule, dict):
                continue
            own = required(rule.get("originRequest"))
            ingress.append({"hostname": _name(rule.get("hostname")) or None, "path": str(rule.get("path") or "") or None,
                            "service": _USERINFO.sub(r"\1", str(rule.get("service") or ""))[:200],
                            "access_required": bool(default if own is None else own)})
        return {"source": "cloudflare", "ingress": ingress}

    async def access_apps(self, zone_id: str | None = None) -> list[dict]:
        """De apps van Cloudflare Access (van het account, of met zone_id de oude apps op zoneniveau), via access_app().
        Een lijst zonder de regels van de policies: die per app apart (hoogstens 50 apps)."""
        if zone_id is not None and not ZONE_RE.match(zone_id):
            raise IntegrationError("Ongeldige zone-id")
        base = f"/zones/{zone_id}/access/apps" if zone_id else f"/accounts/{self._account()}/access/apps"
        raw = await self._all(base, 100)
        todo = [a for a in raw if a.get("type") in ACCESS_TYPES and UUID_RE.match(str(a.get("id") or ""))
                and ("policies" not in a or any(isinstance(p, dict) and "include" not in p for p in a.get("policies") or []))]
        sem = asyncio.Semaphore(4)

        async def policies(a: dict) -> None:
            async with sem:
                a["policies"] = await self._all(f"{base}/{a['id']}/policies", 100)

        await asyncio.gather(*(policies(a) for a in todo[:MAX_POLICY_FETCH]))
        return [x for x in (access_app(a) for a in raw) if x]

    async def always_https(self, zone_id: str) -> bool | None:
        """Stuurt Cloudflare http door naar https voor de hele zone (Always Use HTTPS)?"""
        if not ZONE_RE.match(zone_id):
            raise IntegrationError("Ongeldige zone-id")
        value = ((await self._get_ok(f"/zones/{zone_id}/settings/always_use_https")).get("result") or {}).get("value")
        return None if value is None else value == "on"

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
