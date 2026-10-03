"""Met welke gebruiker, sleutel en wachtwoord we op een SSH-host inloggen.

Een host met een eigen sleutel of wachtwoord gebruikt die. Anders geldt de standaard login uit de terminal
(⚙ standaard). Een lege gebruiker betekent: de standaard gebruiker (meestal root).
"""

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
    return Login(h.username or d.get("username") or "root", key, decrypt(enc_pw) if enc_pw else None)
