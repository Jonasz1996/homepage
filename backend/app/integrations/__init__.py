"""Register van alle integraties. Het type van een service kiest de integratie."""

from .adguard import AdGuard
from .base import Integration, IntegrationError
from .jsonapi import CustomApi, JsonApi
from .npm import NginxProxyManager
from .pbs import ProxmoxBackupServer
from .proxmox import Proxmox

REGISTRY: dict[str, type[Integration]] = {
    cls.name: cls for cls in (Proxmox, ProxmoxBackupServer, AdGuard, NginxProxyManager, JsonApi, CustomApi)
}

__all__ = ["REGISTRY", "Integration", "IntegrationError"]
