"""Met welke gebruiker, sleutel en wachtwoord we op een SSH-host inloggen, en hoe we zeggen wat er misliep.

Een host met een eigen sleutel of wachtwoord gebruikt die. Anders geldt de standaard login uit de terminal
(⚙ standaard). Een lege gebruiker betekent: de standaard gebruiker (meestal root).
"""

import asyncio
import errno
import socket
from dataclasses import dataclass

import asyncssh
from sqlalchemy.ext.asyncio import AsyncSession

from .models import AppState, SshHost, SshKey
from .security import decrypt

DEFAULTS_KEY = "ssh_defaults"


@dataclass
class Login:
    username: str
    key: asyncssh.SSHKey | None
    password: str | None
    own: bool = False  # eigen sleutel of wachtwoord van de host, anders die uit ⚙ standaard


async def defaults(db: AsyncSession) -> dict:
    st = await db.get(AppState, DEFAULTS_KEY)
    return dict(st.value) if st else {}


async def login_for(db: AsyncSession, h: SshHost, d: dict | None = None) -> Login:
    d = await defaults(db) if d is None else d
    own = bool(h.key_id or h.password)
    key_id = h.key_id if own else d.get("key_id")
    enc_pw = h.password if own else d.get("password")
    key = None
    if key_id:
        k = await db.get(SshKey, key_id)
        key = asyncssh.import_private_key(decrypt(k.private_key)) if k else None
    return Login(h.username or d.get("username") or "root", key, decrypt(enc_pw) if enc_pw else None, own)


def methode(login: Login) -> str:
    """Waarmee we aanmelden, zoals de terminal het toont: "wachtwoord uit ⚙ standaard"."""
    if not (login.key or login.password):
        return "zonder wachtwoord of sleutel"
    how = "sleutel, daarna wachtwoord" if login.key and login.password else "sleutel" if login.key else "wachtwoord"
    return f"{how} {'van deze host' if login.own else 'uit ⚙ standaard'}"


def geweigerd(login: Login) -> str:
    """Wat je nakijkt als de host het aanmelden weigert."""
    if not (login.key or login.password):
        return (f"Aanmelden als {login.username} geweigerd: er is geen wachtwoord of sleutel ingesteld. "
                "Vul er een in onder ⚙ standaard of bij ✎ naast de host.")
    tips = []
    if login.password:
        tips.append("klopt het wachtwoord")
    if login.key:
        tips.append("staat de publieke sleutel in ~/.ssh/authorized_keys op de host")
    if login.password and login.username == "root":
        tips.append("laat sshd root met een wachtwoord toe (PermitRootLogin in /etc/ssh/sshd_config)")
    return f"Aanmelden als {login.username} geweigerd ({methode(login)}): {', '.join(tips)}?"


class TcpVolger(asyncssh.SSHClient):
    """Als client_factory: onthoudt of de TCP-verbinding er kwam. Dan antwoordt de server, ook als het aanmelden
    daarna te lang duurt, en is een time-out geen firewall."""

    def __init__(self):
        self.tcp = False

    def __call__(self):
        return self

    def connection_made(self, conn):
        self.tcp = True


def waarom(e: BaseException, host: str, port: int, timeout: float | None = None, antwoordt: bool = False) -> str:
    """Waarom een SSH-verbinding mislukte, leesbaar. Een time-out heeft zelf geen tekst."""
    within = f" binnen {timeout:g} s" if timeout else ""
    if isinstance(e, (TimeoutError, asyncio.TimeoutError)):
        if antwoordt:
            took = f"langer dan {timeout:g} s" if timeout else "te lang"
            return (f"{host}:{port} antwoordt, maar het aanmelden duurde {took}. Is de server traag of overbelast, "
                    "of wacht sshd op DNS (UseDNS) of PAM?")
        return (f"geen antwoord van {host}:{port}{within}. Staat de machine aan, draait SSH daar, en laat de firewall "
                f"(bv. OPNsense) de homepage door naar dat IP op poort {port}?")
    if isinstance(e, ConnectionRefusedError):
        return (f"{host}:{port} weigert de verbinding: daar draait geen SSH (of op een andere poort), of een firewall "
                "weigert de homepage")
    if isinstance(e, socket.gaierror):
        return f"de naam {host} is onbekend (DNS): gebruik het IP-adres"
    if isinstance(e, OSError) and e.errno in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.EHOSTDOWN):
        return f"{host} is niet bereikbaar (geen route): klopt het IP, en laat de firewall de homepage door?"
    return str(getattr(e, "reason", None) or str(e) or type(e).__name__)
