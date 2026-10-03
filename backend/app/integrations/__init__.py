"""Register van alle integraties. Het type van een service kiest de integratie."""

from .adguard import AdGuard
from .cloudflare import CloudflareTunnel
from .homeassistant import HomeAssistant
from .base import Integration, IntegrationError
from .jsonapi import CustomApi, JsonApi
from .npm import NginxProxyManager
from .opnsense import OPNsense
from .pbs import ProxmoxBackupServer
from .portainer import Portainer
from .proxmox import Proxmox

REGISTRY: dict[str, type[Integration]] = {
    cls.name: cls for cls in (Proxmox, ProxmoxBackupServer, AdGuard, NginxProxyManager, Portainer, OPNsense,
                                CloudflareTunnel, HomeAssistant, JsonApi, CustomApi)
}



def build(service, clients) -> Integration:
    """Integratie-object voor een service, met de gedeelde HTTP-clients (zie monitoring/checks.py)."""
    from ..security import decrypt_json

    cls = REGISTRY.get(service.type)
    if cls is None:
        raise IntegrationError(f"Geen integratie voor type '{service.type}'")
    client = clients.get(bool((service.config or {}).get("insecure")))
    return cls(service.url, service.config or {}, decrypt_json(service.secrets), client)


__all__ = ["REGISTRY", "Integration", "IntegrationError", "build"]
