"""Nginx Proxy Manager: proxy hosts, certificaten (vervaldatum) en import van hosts als tegels.

Lezen gaat met de gewone NPM-gebruiker. Een nieuwe service maken of opruimen (nieuweservice.py) gebruikt een tweede
gebruiker (action_username), en alleen daar: eigen calls uit API-beheer en "uitproberen" blijven op de leesgebruiker.
"""

import ipaddress
import time
from datetime import datetime, timezone

import httpx

from ..masking import mask
from .base import TIMEOUT, Integration, IntegrationError, cell, field

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


# Netwerken die "alleen thuis" zijn: privé-adressen en Tailscale (CGNAT).
VPN_NETS = (ipaddress.ip_network("100.64.0.0/10"),)


def host_url(h: dict) -> str | None:
    names = h.get("domain_names") or []
    if not names or "*" in names[0]:
        return None
    return ("https://" if h.get("certificate_id") else "http://") + names[0]


class NginxProxyManager(Integration):
    name = "npm"
    label = "Nginx Proxy Manager"
    config_help = {"url": "http://192.168.0.245:81 (de beheerpoort van NPM)",
                   "npm_names": "optioneel: andere namen van NPM zoals cloudflared ze gebruikt (bv. npm, nginx-proxy-manager)",
                   "npm_ipv6": "optioneel: publieke IPv6-adressen van NPM (voor AAAA-records)"}
    secret_help = {"username": "e-mailadres van de NPM-gebruiker (alle items zichtbaar; View op proxy, redirection en 404 "
                               "hosts, access lists en certificaten)", "password": "wachtwoord",
                   "action_username": "optioneel: e-mail van een tweede NPM-gebruiker om proxy hosts te maken en te "
                                      "verwijderen (README)",
                   "action_password": "wachtwoord van die gebruiker"}
    call_prefix = "/api"

    async def call_auth(self) -> dict:
        return {"headers": {"Authorization": f"Bearer {await self.token()}"}}

    @property
    def split(self) -> bool:
        """Twee gebruikers: lezen (tegels, routes, kopie) en een aparte om hosts te maken (nieuwe service)."""
        return bool(self.secrets.get("action_username") and self.secrets.get("action_password"))

    def user(self, write: bool = False) -> str | None:
        """Welke gebruiker token(write) gebruikt, zonder wachtwoord: voor de proefmodus."""
        return self.secrets.get("action_username" if write and self.split else "username")

    async def token(self, write: bool = False) -> str:
        user, secret = self.need(*(("action_username", "action_password") if write and self.split
                                   else ("username", "password")))
        key = (self.base, user)
        cached = _tokens.get(key)
        if cached and cached[1] > time.time():
            return cached[0]
        data = await self.request("POST", "/api/tokens", json={"identity": user, "secret": secret}) or {}
        if not data.get("token"):
            raise IntegrationError("Inloggen bij NPM mislukt")
        _tokens[key] = (data["token"], time.time() + 3600)
        return data["token"]

    async def get(self, path: str, write: bool = False):
        return await self.request("GET", "/api" + path,
                                  headers={"Authorization": f"Bearer {await self.token(write)}"}) or []

    async def send(self, method: str, path: str, body: dict | None = None, *, timeout: float | None = None):
        """Een call die iets verandert, altijd als de schrijfgebruiker. Alleen voor nieuweservice.py (met proef en
        auditlog)."""
        return await self.request(method, "/api" + path, json=body,
                                  headers={"Authorization": f"Bearer {await self.token(True)}"},
                                  timeout=timeout or TIMEOUT)

    async def version(self) -> tuple[int, int, int] | None:
        """De versie van NPM (GET /api/ zonder login), of None."""
        try:
            v = ((await self.request("GET", "/api/")) or {}).get("version") or {}
            return int(v["major"]), int(v["minor"]), int(v.get("revision") or 0)
        except (KeyError, TypeError, ValueError, AttributeError):
            return None

    async def proxy_hosts(self, write: bool = False) -> list[dict]:
        return await self.get("/nginx/proxy-hosts", write)

    async def certificates(self, write: bool = False) -> list[dict]:
        return await self.get("/nginx/certificates", write)

    async def redirection_hosts(self, write: bool = False) -> list[dict]:
        return await self.get("/nginx/redirection-hosts", write)

    async def dead_hosts(self, write: bool = False) -> list[dict]:
        return await self.get("/nginx/dead-hosts", write)

    async def access_lists_raw(self, write: bool = False) -> list[dict]:
        """Zoals NPM ze geeft (voor een nieuwe service); access_lists() hieronder is de opgekuiste versie."""
        return await self.get("/nginx/access-lists?expand=clients,items", write)

    async def me(self, write: bool = False) -> dict:
        data = await self.get("/users/me?expand=permissions", write)
        return data if isinstance(data, dict) else {}

    def _error_detail(self, r: httpx.Response) -> str | None:
        # {"error": {"code": 400, "message": "data/meta must NOT have additional properties"}}
        try:
            msg = (r.json().get("error") or {}).get("message")
        except (ValueError, AttributeError):
            return None
        return mask(f"NPM: {msg}")[:200] if msg else None

    async def access_lists(self) -> list[dict]:
        """De access lists: per lijst satisfy any, het aantal gebruikers en de allow/deny-regels. Gebruikersnamen en
        wachtwoorden (of hun hint) blijven hier achter."""
        out = []
        for al in await self.get("/nginx/access-lists?expand=items,clients") or []:
            if not isinstance(al, dict) or al.get("id") is None:
                continue
            clients = [{"directive": str(c.get("directive") or "").lower(), "address": str(c.get("address") or "").strip()}
                       for c in al.get("clients") or [] if isinstance(c, dict)]
            out.append({"id": al["id"], "name": str(al.get("name") or "")[:100], "satisfy_any": bool(al.get("satisfy_any")),
                        "users": len([i for i in al.get("items") or [] if isinstance(i, dict)]), "clients": clients})
        return out

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
            {"kind": "npm-routes", "title": "rechtstreeks (checks zonder DNS)"},
            {"kind": "npm-import", "title": "importeren"},
        ]}


# --- bouwstenen voor de proef en het echte werk (nieuweservice.py) -------------------------------------------------

def host_create_request(body: dict) -> tuple[str, str, dict]:
    return "POST", "/nginx/proxy-hosts", body


def host_update_request(host_id: int, body: dict) -> tuple[str, str, dict]:
    return "PUT", f"/nginx/proxy-hosts/{int(host_id)}", body


def host_get_request(host_id: int) -> tuple[str, str, None]:
    return "GET", f"/nginx/proxy-hosts/{int(host_id)}", None


def host_delete_request(host_id: int) -> tuple[str, str, None]:
    return "DELETE", f"/nginx/proxy-hosts/{int(host_id)}", None


def cert_create_request(fqdn: str, version: tuple[int, int, int] | None, email: str | None) -> tuple[str, str, dict]:
    """Een certificaat van Let's Encrypt voor één naam. Vanaf NPM 2.13 neemt NPM het e-mailadres van de gebruiker
    die het aanvraagt en weigert het extra velden in meta; daarvoor moesten letsencrypt_email en _agree erbij."""
    if version is None:
        raise IntegrationError("NPM-versie onbekend")
    meta: dict = {"dns_challenge": False}
    if tuple(version[:2]) < (2, 13):
        meta.update({"letsencrypt_email": email or "", "letsencrypt_agree": True})
    return "POST", "/nginx/certificates", {"provider": "letsencrypt", "domain_names": [fqdn], "meta": meta}


def cert_delete_request(cert_id: int) -> tuple[str, str, None]:
    return "DELETE", f"/nginx/certificates/{int(cert_id)}", None


def nginx_failed(host: dict) -> str | None:
    """NPM antwoordt ook 2xx als nginx de configuratie weigert: dan staat het alleen in meta van de host."""
    meta = (host or {}).get("meta") or {}
    if meta.get("nginx_online") is False:
        return "NPM: nginx weigerde de configuratie: " + mask(str(meta.get("nginx_err") or "?"))[:200]
    return None


def can_write(me: dict, need_cert: bool) -> tuple[bool, str]:
    """Mag deze NPM-gebruiker proxy hosts maken (en certificaten aanvragen), en ziet hij alle hosts?"""
    if "admin" in (me.get("roles") or []):
        return True, "beheerder in NPM"
    p = me.get("permissions") or {}
    if p.get("visibility") != "all":
        return False, "ziet alleen zijn eigen hosts: zet Item Visibility op All Items"
    if p.get("proxy_hosts") != "manage":
        return False, "Proxy Hosts staat niet op Manage"
    if need_cert and p.get("certificates") != "manage":
        return False, "Certificates staat niet op Manage (nodig voor Let's Encrypt)"
    for key, label in (("certificates", "Certificates"), ("access_lists", "Access Lists"),
                       ("redirection_hosts", "Redirection Hosts"), ("dead_hosts", "404 Hosts")):
        if p.get(key, "hidden") == "hidden":
            return False, f"{label} staat op Hidden: zet minstens View"
    return True, "mag proxy hosts beheren en ziet alle hosts"


def _home_net(addr: str) -> bool:
    try:
        net = ipaddress.ip_network(addr.strip(), strict=False)
    except ValueError:
        return False
    if net.prefixlen == 0:
        return False
    return net.is_private or any(net.subnet_of(v) for v in VPN_NETS if v.version == net.version)


def lan_only(acl: dict) -> tuple[bool, str]:
    """Laat deze toegangslijst van NPM alleen het LAN en de VPN binnen? (ok, uitleg of het eerste probleem)"""
    clients = acl.get("clients") or []
    if not clients:
        return False, "heeft geen IP-regels"
    if acl.get("satisfy_any") and acl.get("items"):
        return False, "wachtwoord volstaat van overal (satisfy any)"
    allow = [c for c in clients if c.get("directive") == "allow"]
    if not allow:
        return False, "laat niemand toe"
    for c in allow:
        addr = str(c.get("address") or "").strip()
        if addr in ("all", "0.0.0.0/0", "::/0", "0.0.0.0", "::"):
            return False, f"laat {addr} toe"
        if not _home_net(addr):
            return False, f"laat {addr} toe (geen LAN- of VPN-adres)"
    return True, "alleen " + ", ".join(str(c.get("address")) for c in allow)


def public_cert(c: dict) -> dict:
    """Wat van een certificaat naar de browser mag: nooit meta (daar staan de DNS-sleutels van een DNS-challenge)."""
    return {k: c.get(k) for k in ("id", "nice_name", "domain_names", "provider", "expires_on")}
