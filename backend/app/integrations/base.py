"""Gemeenschappelijke basis voor integraties.

Een integratie levert drie dingen:
- summary(): een paar velden voor op de tegel ([{label, value, level}])
- detail():  secties voor het mini dashboard (kv, bars, table, code)
- action():  een actie zoals een VM herstarten; de API vraagt daarvoor eerst een recente 2FA-bevestiging
"""

import re
import time
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

import httpx

TIMEOUT = 8.0


class IntegrationError(Exception):
    """Fout die we zo aan de gebruiker tonen (geen stacktrace, geen geheimen)."""


# Netwerkfouten in gewone taal: "ConnectError" alleen zegt niemand iets.
_NET = (
    ("CERTIFICATE_VERIFY_FAILED", "certificaat niet vertrouwd: zet insecure op true (zelfondertekend certificaat)"),
    ("Name or service not known", "naam onbekend in DNS: klopt de url, en gebruikt de container je eigen DNS?"),
    ("nodename nor servname", "naam onbekend in DNS: klopt de url, en gebruikt de container je eigen DNS?"),
    ("Temporary failure in name resolution", "DNS geeft geen antwoord"),
    ("Connection refused", "verbinding geweigerd: draait de dienst op die poort?"),
    ("No route to host", "geen route naar host: firewall tussen de VLAN's?"),
    ("Network is unreachable", "netwerk onbereikbaar: firewall of routering"),
)
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.I | re.S)


def _net_reason(e: Exception) -> str:
    text = ""
    cur: BaseException | None = e
    for _ in range(6):  # httpx verpakt de echte oorzaak (ssl, socket) een paar lagen diep
        text += f" {cur}"
        cur = cur.__cause__ or cur.__context__
        if cur is None:
            break
    for needle, label in _NET:
        if needle in text:
            return label
    return type(e).__name__


def _page_hint(r: httpx.Response) -> str:
    m = _TITLE.search(r.content[:4000])
    title = m.group(1).decode(errors="replace").strip()[:60] if m else ""
    return f" (\"{title}\")" if title else ""


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
        base = (self.config.get("url") or url or "").strip()
        if not base.lower().startswith(("http://", "https://")):
            raise IntegrationError("Geen geldige url in de instellingen (bv. https://pve.jbogaert.be)")
        # Een url uit de adresbalk ("https://pve:8006/#v1:0:=node/...") of met ?query: alleen het basisadres houden,
        # anders belandt het API-pad achter de # en krijg je de webpagina in plaats van de API.
        parts = urlsplit(base)
        self.base = urlunsplit((parts.scheme, parts.netloc, parts.path, "", "")).rstrip("/")

    def need(self, *keys: str) -> list[str]:
        missing = [k for k in keys if not self.secrets.get(k)]
        if missing:
            raise IntegrationError(f"Geheim ontbreekt: {', '.join(missing)}")
        return [self.secrets[k] for k in keys]

    async def request(self, method: str, path: str, **kw) -> Any:
        r = await self._send(method, path, **kw)
        if not r.content:
            return None
        try:
            return r.json()
        except ValueError as e:
            raise IntegrationError(f"Geen API-antwoord op {path.split('?')[0]}: {self.base} gaf een webpagina{_page_hint(r)}. "
                                   "Klopt de url? Een NPM-standaardpagina of loginpagina komt niet door: "
                                   "gebruik rechtstreeks het adres van de API (bv. https://192.168.0.50:8006, insecure true).") from e

    async def text(self, method: str, path: str, **kw) -> str:
        """Zoals request, maar voor een bestand (bv. config.xml) in plaats van JSON."""
        return (await self._send(method, path, **kw)).text

    async def _send(self, method: str, path: str, **kw) -> httpx.Response:
        try:
            # Nooit volgen: anders gaan headers als X-API-Key mee naar een ander adres.
            r = await self.client.request(method, self.base + path, timeout=TIMEOUT, follow_redirects=False, **kw)
        except httpx.TimeoutException as e:
            raise IntegrationError("Time-out") from e
        except httpx.HTTPError as e:
            raise IntegrationError(f"Niet bereikbaar ({self.base}): {_net_reason(e)}") from e
        if r.status_code == 401:
            raise IntegrationError("Geweigerd (HTTP 401): API-token ontbreekt of is fout")
        if r.status_code == 403:
            raise IntegrationError("Geweigerd (HTTP 403): het token heeft te weinig rechten")
        if 300 <= r.status_code < 400:
            to = r.headers.get("location", "")
            raise IntegrationError(f"Doorgestuurd (HTTP {r.status_code}) naar {to[:120] or '?'}: zet die url in de instellingen, "
                                   "of rechtstreeks het adres van de API (bv. https://192.168.0.50:8006). "
                                   "Een login (Authentik) ervoor laat geen API-token door.")
        if r.status_code >= 400:
            raise IntegrationError(f"HTTP {r.status_code} op {path.split('?')[0]}")
        return r

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
