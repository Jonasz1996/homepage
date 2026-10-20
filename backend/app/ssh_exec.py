"""Commando's op een SSH-host uitvoeren (cronscanner, live meekijken, ...), met dezelfde login als de terminal.

Een container op een Proxmox-node bereiken we via die node: `pct exec <id> -- sh -c ...`.
"""

import asyncio
import shlex
from contextlib import asynccontextmanager

import asyncssh

from .models import SshHost
from .ssh_login import Login

CONNECT_TIMEOUT = 15


class SshFail(Exception):
    """Fout die we zo aan de gebruiker tonen."""


@asynccontextmanager
async def connect(h: SshHost, login: Login, keepalive: int | None = None):
    if not h.host_key:
        raise SshFail("Hostsleutel nog niet bevestigd: open één keer een terminal naar deze host")
    try:
        conn = await asyncio.wait_for(asyncssh.connect(
            h.host, port=h.port, username=login.username, keepalive_interval=keepalive or 0,
            known_hosts=([asyncssh.import_public_key(h.host_key)], [], []),
            client_keys=[login.key] if login.key else None, password=login.password,
            agent_path=None, config=None, preferred_auth="publickey,password,keyboard-interactive",
        ), CONNECT_TIMEOUT)
    except asyncssh.HostKeyNotVerifiable as e:
        raise SshFail("Hostsleutel klopt niet meer, verbinding geweigerd") from e
    except asyncssh.PermissionDenied as e:
        raise SshFail(f"Aanmelden als {login.username} geweigerd: controleer de standaard login (⚙ standaard)") from e
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
        raise SshFail(f"SSH naar {h.host} mislukt: {getattr(e, 'reason', None) or e or type(e).__name__}") from e
    async with conn:
        yield conn


def command(script: str, login: Login, vmid: int | None = None) -> str:
    inner = f"sh -c {shlex.quote(script)}"
    if vmid is not None:
        inner = f"pct exec {int(vmid)} -- {inner}"
    return inner if login.username == "root" else f"sudo -n {inner}"


async def run(conn, script: str, login: Login, vmid: int | None = None, timeout: float = 120) -> tuple[int, str, str]:
    try:
        r = await asyncio.wait_for(conn.run(command(script, login, vmid), check=False), timeout)
    except asyncio.TimeoutError as e:
        raise SshFail(f"Duurde langer dan {int(timeout)} s") from e
    except (OSError, asyncssh.Error) as e:
        raise SshFail(f"SSH-fout: {e}") from e
    return int(r.exit_status or 0), str(r.stdout or ""), str(r.stderr or "")
