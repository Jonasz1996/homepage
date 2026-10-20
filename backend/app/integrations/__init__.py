"""Register van alle integraties. Het type van een service kiest de integratie."""

from .adguard import AdGuard
from .cloudflare import CloudflareTunnel
from .homeassistant import HomeAssistant
from .base import Integration, IntegrationError
from .calls import call_dict
from .jsonapi import CustomApi, JsonApi
from .npm import NginxProxyManager
from .opnsense import OPNsense
from .pbs import ProxmoxBackupServer
from .portainer import Portainer
from .proxmox import Proxmox
from .rest import RestApi
from .zabbix import Zabbix

REGISTRY: dict[str, type[Integration]] = {
    cls.name: cls for cls in (Proxmox, ProxmoxBackupServer, AdGuard, NginxProxyManager, Portainer, OPNsense,
                                CloudflareTunnel, HomeAssistant, Zabbix, RestApi, JsonApi, CustomApi)
}

# Instellingen die van de API komen en die een tegel niet mag overschrijven (anders gaan de sleutels elders heen).
API_ONLY = ("url", "insecure", "auth", "headers")


def build(service, clients) -> Integration:
    """Integratie-object voor een service, met de gedeelde HTTP-clients (zie monitoring/checks.py).
    Hangt de tegel aan een API uit API-beheer, dan komen adres, sleutels en eigen calls van die API;
    de instellingen van de tegel (bv. node) vullen aan."""
    from ..security import decrypt_json

    # Alleen wat al geladen is (Service.api laadt altijd mee): nooit een query vanuit hier.
    api = service.__dict__.get("api") if getattr(service, "api_id", None) else None
    if getattr(service, "api_id", None) and api is None:
        raise IntegrationError("API niet gevonden: kies opnieuw een API voor deze tegel")
    if api is not None:
        return from_api(api, service.config, clients)
    cls = REGISTRY.get(service.type)
    if cls is None:
        raise IntegrationError(f"Geen integratie voor type '{service.type}'")
    config = service.config or {}
    return cls(service.url, config, decrypt_json(service.secrets), clients.get(bool(config.get("insecure"))))


def from_api(api, tile_config: dict | None, clients) -> Integration:
    """Integratie voor een API uit API-beheer, aangevuld met de instellingen van een tegel."""
    from ..security import decrypt_json

    cls = REGISTRY.get(api.kind)
    if cls is None:
        raise IntegrationError(f"Geen integratie voor type '{api.kind}'")
    tile = {k: v for k, v in (tile_config or {}).items() if k not in API_ONLY}
    config = {**(api.config or {}), **tile, "url": api.url}
    integ = cls(api.url, config, decrypt_json(api.secrets), clients.get(bool(config.get("insecure"))))
    integ.calls = [call_dict(c) for c in api.calls]
    return integ


__all__ = ["REGISTRY", "Integration", "IntegrationError", "build", "from_api"]
