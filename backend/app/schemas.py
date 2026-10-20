import ipaddress
import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

CHECK_TYPES = ("http", "tcp", "ping", "dns", "push", "container", "api")
ACCEPT = re.compile(r"^\d{3}(-\d{3})?(,\d{3}(-\d{3})?)*$")
HEADER_NAME = re.compile(r"^[A-Za-z0-9-]{1,64}$")
# Wachtwoorden en sleutels horen niet in de check (die gaat naar de browser, de export en de versies):
# daarvoor is de check "API van de tegel", met de versleutelde sleutels van de tegel of uit API-beheer.
SECRET_HEADER = re.compile(r"auth|token|key|secret|cookie|session|pass", re.I)
CONTAINER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class CheckIn(BaseModel):
    """De instellingen van een check. Onbekende of foute waarden worden geweigerd: één kapotte check mocht vroeger
    de hele worker stilleggen."""

    model_config = ConfigDict(extra="forbid")

    type: Literal[CHECK_TYPES]
    target: str | None = Field(default=None, max_length=500)
    interval: int = Field(default=60, ge=15, le=86400)
    # Pas down na zoveel mislukte checks op rij (Kuma: retries + 1).
    down_after: int | None = Field(default=None, ge=1, le=10)
    # Bij twijfel (een mislukte check, nog niet down) sneller opnieuw kijken.
    retry_interval: int | None = Field(default=None, ge=15, le=86400)
    # Zolang down: elke zoveel uur een herinnering. 0 of leeg = nooit.
    remind_hours: int | None = Field(default=None, ge=0, le=168)
    # push = hier en op je gsm, centrum = alleen hier, uit = alleen op de tijdlijn.
    notify: Literal["push", "centrum", "uit"] | None = None
    cert_notify: bool | None = None
    paused: bool | None = None
    # false = via de naam (DNS en NPM) checken, ook als NPM het IP erachter kent (monitoring/routes.py).
    direct: bool | None = None
    # http
    insecure: bool | None = None
    keyword: str | None = Field(default=None, max_length=200)
    keyword_absent: bool | None = None
    json_path: str | None = Field(default=None, max_length=200)
    json_value: str | None = Field(default=None, max_length=200)
    accept: str | None = Field(default=None, max_length=200)
    follow_redirects: bool | None = None
    # Down als de pagina naar een andere host doorverwijst (meestal de loginpagina van Authentik).
    same_host: bool | None = None
    timeout: int | None = Field(default=None, ge=1, le=60)
    method: Literal["GET", "HEAD", "POST"] | None = None
    body: str | None = Field(default=None, max_length=4000)
    body_type: Literal["json", "form", "text"] | None = None
    headers: dict[str, str] | None = None
    # dns
    dns_server: str | None = Field(default=None, max_length=64)
    dns_port: int | None = Field(default=None, ge=1, le=65535)
    record: Literal["A", "AAAA"] | None = None
    expect: str | None = Field(default=None, max_length=255)
    # container (via de Portainer-tegel)
    portainer_id: int | None = None
    env: int | None = None
    container: str | None = Field(default=None, max_length=128)
    # api (de API van de tegel zelf, met zijn eigen sleutels)
    path: str | None = Field(default=None, max_length=500)

    @model_validator(mode="before")
    @classmethod
    def _legacy(cls, data):
        if isinstance(data, dict) and "expect_status" in data:
            data = dict(data)
            code = str(data.pop("expect_status") or "").strip()
            if code and not data.get("accept"):
                data["accept"] = code
        if isinstance(data, dict) and isinstance(data.get("json_value"), (int, float, bool)):
            data = {**data, "json_value": str(data["json_value"]).lower() if isinstance(data["json_value"], bool)
                    else str(data["json_value"])}
        return data

    @field_validator("target", "keyword", "json_path", "json_value", "body", "expect", "dns_server", "container",
                     "path", "accept")
    @classmethod
    def _strip(cls, v: str | None) -> str | None:
        return (v.strip() or None) if isinstance(v, str) else v

    @field_validator("accept")
    @classmethod
    def _accept(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.replace(" ", "")
        if not ACCEPT.match(v):
            raise ValueError("Statuscodes als 200 of 200-299,401")
        for part in v.split(","):
            lo, _, hi = part.partition("-")
            if not 100 <= int(lo) <= 599 or (hi and not int(lo) <= int(hi) <= 599):
                raise ValueError(f"Statuscode {part} klopt niet")
        return v

    @field_validator("headers")
    @classmethod
    def _headers(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if not v:
            return None
        if len(v) > 10:
            raise ValueError("Hoogstens 10 headers")
        for k, val in v.items():
            if not HEADER_NAME.match(k) or k.lower() in ("host", "content-length"):
                raise ValueError(f"Header {k!r} kan niet")
            if SECRET_HEADER.search(k):
                raise ValueError(f"Header {k} lijkt geheim: gebruik de check 'API van de tegel' met een sleutel")
            if len(val) > 500 or "\n" in val or "\r" in val:
                raise ValueError(f"Waarde van header {k} is te lang of heeft een regeleinde")
        return v

    @field_validator("dns_server")
    @classmethod
    def _dns_server(cls, v: str | None) -> str | None:
        if v:
            try:
                return str(ipaddress.ip_address(v))
            except ValueError:
                raise ValueError("DNS-server moet een IP-adres zijn") from None
        return v

    @field_validator("path")
    @classmethod
    def _path(cls, v: str | None) -> str | None:
        if v and (not v.startswith("/") or "://" in v or any(c.isspace() for c in v)):
            raise ValueError("Pad begint met / (bv. /api/v3/system/status)")
        return v

    @model_validator(mode="after")
    def _per_type(self):
        if self.type == "container":
            if not self.portainer_id or not self.container:
                raise ValueError("Kies een Portainer-tegel en een container")
            if not CONTAINER.match(self.container):
                raise ValueError("Containernaam klopt niet")
        if self.type == "tcp" and self.target:
            host, _, port = self.target.rpartition(":")
            if not host or not port.isdigit() or not 0 < int(port) < 65536:
                raise ValueError("Doel voor TCP is host:poort, bv. 192.168.0.10:22")
        if self.type in ("ping", "dns") and self.target and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:_\[\]-]*",
                                                                            self.target):
            raise ValueError("Doel is een hostnaam of IP-adres")
        if self.type == "http" and self.target and not self.target.lower().startswith(("http://", "https://")):
            raise ValueError("Doel voor HTTP begint met http:// of https://")
        if self.method == "HEAD" and (self.keyword or self.json_path):
            raise ValueError("Met HEAD komt er geen inhoud: kies GET om op een woord of JSON-veld te controleren")
        if self.type == "push" and self.interval < 60:
            raise ValueError("Een push-check verwacht hoogstens elke 60 s een signaal")
        if self.retry_interval and self.retry_interval > self.interval:
            self.retry_interval = None
        return self


def clean_check(check: dict | None) -> dict:
    """Een gecontroleerde check-dict om te bewaren, {} = geen check. Gooit ValueError bij foute waarden."""
    if not check or not check.get("type"):
        return {}
    try:
        return CheckIn.model_validate(check).model_dump(exclude_none=True)
    except ValidationError as e:
        err = e.errors()[0]
        where = ".".join(str(x) for x in err.get("loc", ()))
        msg = str(err.get("msg", "")).removeprefix("Value error, ")
        raise ValueError(f"check {where}: {msg}" if where else f"check: {msg}") from None


class PageIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    icon: str | None = Field(default=None, max_length=255)


class GroupIn(BaseModel):
    page_id: int
    name: str = Field(min_length=1, max_length=80)
    icon: str | None = Field(default=None, max_length=255)
    collapsed: bool = False


class ServiceIn(BaseModel):
    group_id: int
    name: str = Field(min_length=1, max_length=80)
    description: str | None = Field(default=None, max_length=255)
    url: str | None = Field(default=None, max_length=500)
    icon: str | None = Field(default=None, max_length=500)
    type: str = Field(default="link", max_length=40)
    check: dict = Field(default_factory=dict)
    config: dict = Field(default_factory=dict)
    # None = ongewijzigd laten. Een sleutel met lege waarde wordt verwijderd.
    secrets: dict[str, str | None] | None = None
    parent_id: int | None = None
    notes: str | None = Field(default=None, max_length=20000)
    # API uit API-beheer; zonder dit veld blijft de huidige keuze staan.
    api_id: int | None = None

    @field_validator("url")
    @classmethod
    def _url_scheme(cls, v: str | None) -> str | None:
        if v and not v.lower().startswith(("http://", "https://")):
            raise ValueError("URL moet met http:// of https:// beginnen")
        return v or None

    @field_validator("check", mode="before")
    @classmethod
    def _check(cls, v):
        if v is None:
            return {}
        if not isinstance(v, dict):
            raise ValueError("Check moet een object zijn")
        return clean_check(v)


class ServiceOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    group_id: int
    name: str
    description: str | None
    url: str | None
    icon: str | None
    position: int
    type: str
    check: dict
    config: dict
    parent_id: int | None = None
    maintenance_until: datetime | None = None
    notes: str | None = None
    api_id: int | None = None
    secret_keys: list[str] = []


class GroupOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    page_id: int
    name: str
    icon: str | None
    position: int
    collapsed: bool
    services: list[ServiceOut]


class PageOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    icon: str | None
    position: int
    groups: list[GroupOut]


class OrderIn(BaseModel):
    """Nieuwe volgorde na slepen. Groepen en services kunnen zo ook van ouder wisselen."""

    pages: list[int] | None = None
    groups: dict[int, list[int]] | None = None
    services: dict[int, list[int]] | None = None


class ImportIn(BaseModel):
    yaml: str = Field(max_length=2_000_000)
    page_id: int | None = None
    page_name: str | None = Field(default=None, max_length=80)
