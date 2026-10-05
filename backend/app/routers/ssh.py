"""SSH-terminal in de browser: sleutels, hosts en een WebSocket die een shell doorgeeft.

Een shell openen is het gevoeligste wat het dashboard kan, dus de WebSocket eist een
volledige sessie, een recente 2FA-bevestiging en een Origin van onze eigen site.
"""

import asyncio
import contextlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from .. import outside
from ..config import get_settings
from ..db import get_db
from ..deps import COOKIE, audit, current_user, recent_auth
from ..models import AppState, AuditLog, Service, Session, SshHost, SshKey, User
from ..monitoring.checks import HttpClients
from .. import ssh_pin
from ..ssh_discovery import apply, discover
from ..ssh_login import DEFAULTS_KEY, login_for
from ..security import encrypt, token_id

router = APIRouter(prefix="/api/ssh", tags=["ssh"])
log = logging.getLogger("homepage.ssh")

IDLE_SECONDS = 30 * 60
CONNECT_TIMEOUT = 10
KEEPALIVE = 30
SNIPPETS_KEY = "ssh_snippets"
clients = HttpClients()


# --- Sleutels ---------------------------------------------------------------

class KeyIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    # Leeg = nieuw ed25519-sleutelpaar maken.
    private_key: str | None = Field(default=None, max_length=20000)
    passphrase: str | None = Field(default=None, max_length=256)


def _key_out(k: SshKey) -> dict:
    pub = asyncssh.import_public_key(k.public_key)
    return {"id": k.id, "name": k.name, "public_key": k.public_key,
            "fingerprint": pub.get_fingerprint("sha256"), "created_at": k.created_at}


@router.get("/keys")
async def list_keys(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return [_key_out(k) for k in (await db.execute(select(SshKey).order_by(SshKey.id))).scalars()]


@router.post("/keys", status_code=201, dependencies=[outside.guard("terminal")])
async def create_key(data: KeyIn, request: Request, user: User = Depends(recent_auth),
                     db: AsyncSession = Depends(get_db)):
    try:
        if data.private_key and data.private_key.strip():
            key = asyncssh.import_private_key(data.private_key.strip(), data.passphrase or None)
        else:
            key = asyncssh.generate_private_key("ssh-ed25519", comment=f"homepage-{data.name}")
    except (asyncssh.KeyImportError, ValueError) as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Sleutel niet leesbaar: {e}") from e
    key.set_comment(f"homepage-{data.name}")
    k = SshKey(name=data.name, public_key=key.export_public_key().decode().strip(),
               private_key=encrypt(key.export_private_key().decode()))
    db.add(k)
    await audit(db, request, user, "ssh_key_added", name=data.name, imported=bool(data.private_key))
    await db.commit()
    return _key_out(k)


@router.delete("/keys/{key_id}", dependencies=[outside.guard("terminal")])
async def delete_key(key_id: int, request: Request, user: User = Depends(recent_auth),
                     db: AsyncSession = Depends(get_db)):
    k = await db.get(SshKey, key_id)
    if k is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Sleutel niet gevonden")
    await db.delete(k)
    await audit(db, request, user, "ssh_key_deleted", name=k.name)
    await db.commit()
    return {"ok": True}


# --- Hosts ------------------------------------------------------------------

def _clean_host(v: str) -> str:
    v = v.strip()
    if v.startswith("-") or any(c.isspace() for c in v):
        raise ValueError("Ongeldige host")
    return v


class HostIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=22, ge=1, le=65535)
    # Leeg = de standaard gebruiker (zie /api/ssh/defaults).
    username: str = Field(default="", max_length=64, pattern=r"^[A-Za-z0-9._@-]*$")
    key_id: int | None = None
    # None = ongewijzigd, "" = wissen.
    password: str | None = Field(default=None, max_length=256)
    service_id: int | None = None
    # Updates opvolgen: "" = niet, "host" = deze machine, "cts" = ook alle containers (Proxmox-node).
    updates: str = Field(default="", pattern="^(|host|cts)$")
    folder: str = Field(default="", max_length=80)

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return _clean_host(v)


def _host_out(h: SshHost) -> dict:
    fp = None
    if h.host_key:
        with contextlib.suppress(Exception):
            fp = asyncssh.import_public_key(h.host_key).get_fingerprint("sha256")
    return {"id": h.id, "name": h.name, "host": h.host, "port": h.port, "username": h.username,
            "key_id": h.key_id, "has_password": bool(h.password), "host_key_fingerprint": fp,
            "service_id": h.service_id, "last_used_at": h.last_used_at, "updates": h.updates or "",
            "folder": h.folder or "", "source": h.source,
            # Geen eigen sleutel of wachtwoord: de standaard login wordt gebruikt.
            "uses_defaults": not (h.key_id or h.password)}


async def _get_host(db: AsyncSession, host_id: int) -> SshHost:
    h = await db.get(SshHost, host_id)
    if h is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Host niet gevonden")
    return h


async def _check_refs(db: AsyncSession, data: HostIn) -> None:
    if data.key_id is not None and await db.get(SshKey, data.key_id) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sleutel bestaat niet")
    if data.service_id is not None and await db.get(Service, data.service_id) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Service bestaat niet")


@router.get("/hosts")
async def list_hosts(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    hosts = (await db.execute(select(SshHost).order_by(SshHost.position, SshHost.id))).scalars()
    return [_host_out(h) for h in hosts]


@router.post("/hosts", status_code=201, dependencies=[outside.guard("terminal")])
async def create_host(data: HostIn, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    await _check_refs(db, data)
    pos = (await db.execute(select(func.coalesce(func.max(SshHost.position), -1)))).scalar_one() + 1
    h = SshHost(**data.model_dump(exclude={"password"}), position=pos,
                password=encrypt(data.password) if data.password else None)
    db.add(h)
    await audit(db, request, user, "ssh_host_added", name=h.name, host=h.host)
    await db.commit()
    return _host_out(h)


@router.patch("/hosts/{host_id}", dependencies=[outside.guard("terminal")])
async def update_host(host_id: int, data: HostIn, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    h = await _get_host(db, host_id)
    await _check_refs(db, data)
    if (data.host, data.port) != (h.host, h.port):
        h.host_key = None  # andere machine: hostsleutel opnieuw laten bevestigen
    for k, v in data.model_dump(exclude={"password"}).items():
        setattr(h, k, v)
    if data.password is not None:
        h.password = encrypt(data.password) if data.password else None
    await audit(db, request, user, "ssh_host_changed", name=h.name)
    await db.commit()
    return _host_out(h)


@router.delete("/hosts/{host_id}", dependencies=[outside.guard("terminal")])
async def delete_host(host_id: int, request: Request, user: User = Depends(recent_auth),
                      db: AsyncSession = Depends(get_db)):
    h = await _get_host(db, host_id)
    await db.delete(h)
    await audit(db, request, user, "ssh_host_deleted", name=h.name)
    await db.commit()
    return {"ok": True}


@router.post("/hosts/{host_id}/forget-hostkey", dependencies=[outside.guard("terminal")])
async def forget_hostkey(host_id: int, request: Request, user: User = Depends(recent_auth),
                         db: AsyncSession = Depends(get_db)):
    h = await _get_host(db, host_id)
    h.host_key = None
    await audit(db, request, user, "ssh_hostkey_forgotten", name=h.name)
    await db.commit()
    return {"ok": True}


@router.get("/ready", dependencies=[outside.guard("terminal")])
async def ready(user: User = Depends(recent_auth)):
    """De frontend vraagt dit vóór het openen van een terminal; 403 = eerst 2FA bevestigen."""
    return {"ok": True}


# --- Standaard login, snippets en hosts uit Proxmox ------------------------------

async def _defaults(db: AsyncSession) -> dict:
    st = await db.get(AppState, DEFAULTS_KEY)
    return dict(st.value) if st else {}


async def _save_state(db: AsyncSession, key: str, value) -> None:
    st = await db.get(AppState, key)
    if st:
        st.value = value
    else:
        db.add(AppState(key=key, value=value))


def _defaults_out(d: dict) -> dict:
    return {"username": d.get("username") or "root", "has_password": bool(d.get("password")),
            "key_id": d.get("key_id"), "auto_sync": bool(d.get("auto_sync"))}


class DefaultsIn(BaseModel):
    username: str = Field(default="root", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._@-]+$")
    # None = ongewijzigd, "" = wissen.
    password: str | None = Field(default=None, max_length=256)
    key_id: int | None = None
    auto_sync: bool = False


@router.get("/defaults")
async def get_defaults(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    return _defaults_out(await _defaults(db))


@router.put("/defaults", dependencies=[outside.guard("terminal")])
async def put_defaults(data: DefaultsIn, request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    if data.key_id is not None and await db.get(SshKey, data.key_id) is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Sleutel bestaat niet")
    d = await _defaults(db)
    d.update(username=data.username, key_id=data.key_id, auto_sync=data.auto_sync)
    if data.password is not None:
        d["password"] = encrypt(data.password) if data.password else None
    await _save_state(db, DEFAULTS_KEY, d)
    await audit(db, request, user, "ssh_defaults_changed", username=data.username,
                password_changed=data.password is not None, auto_sync=data.auto_sync)
    await db.commit()
    return _defaults_out(d)


class Snippet(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    command: str = Field(min_length=1, max_length=4000)
    # Enter erachter sturen (meteen uitvoeren) of alleen typen.
    run: bool = True


@router.get("/snippets")
async def get_snippets(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, SNIPPETS_KEY)
    return st.value if st else []


@router.put("/snippets", dependencies=[outside.guard("terminal")])
async def put_snippets(data: list[Snippet], request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    if len(data) > 100:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Maximaal 100 snippets")
    value = [x.model_dump() for x in data]
    await _save_state(db, SNIPPETS_KEY, value)
    await audit(db, request, user, "ssh_snippets_changed", count=len(value))
    await db.commit()
    return value


@router.post("/discover")
async def discover_hosts(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Alle nodes, containers en VM's uit de Proxmox-tegels, met hun IP en of ze al in de lijst staan."""
    return await discover(db, clients)


class ImportItem(BaseModel):
    source: str = Field(pattern=r"^pve:\d+:(node|lxc|qemu)/[A-Za-z0-9.-]{1,63}$")
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=255)
    folder: str = Field(default="", max_length=80)
    kind: str = Field(pattern="^(node|lxc|qemu)$")

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return _clean_host(v)


@router.post("/import", dependencies=[outside.guard("terminal")])
async def import_hosts(items: list[ImportItem], request: Request, user: User = Depends(recent_auth),
                       db: AsyncSession = Depends(get_db)):
    if len(items) > 1000:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Te veel hosts in één keer")
    result = await apply(db, [i.model_dump() for i in items])
    await audit(db, request, user, "ssh_hosts_imported", **result)
    await db.commit()
    return result


# --- Sleutel vastzetten op het dashboard (from= in authorized_keys) -------------------

@router.get("/pin")
async def pin_status(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    st = await db.get(AppState, ssh_pin.STATE_KEY)
    return st.value if st else {"hosts": {}, "checked_at": None}


def _no_hostkey(hosts: list[SshHost]) -> dict[int, dict]:
    return {h.id: {"state": "fout", "text": "hostsleutel nog niet bevestigd: open één keer een terminal naar deze host"}
            for h in hosts if not h.host_key}


@router.post("/pin/check", dependencies=[outside.guard("terminal")])
async def pin_check(user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Per host: staat de sleutel van het dashboard vast op het IP van het dashboard?"""
    hosts = await ssh_pin.all_hosts(db)
    res = await ssh_pin.run_all(db, [h for h in hosts if h.host_key], ssh_pin.check)
    value = await ssh_pin.save(db, {**_no_hostkey(hosts), **res})
    await db.commit()
    return value


class PinIn(BaseModel):
    host_ids: list[int] = Field(min_length=1, max_length=1000)
    pin: bool = True


@router.post("/pin", dependencies=[outside.guard("terminal")])
async def pin_change(data: PinIn, request: Request, user: User = Depends(recent_auth),
                     db: AsyncSession = Depends(get_db)):
    hosts = await ssh_pin.all_hosts(db, data.host_ids)
    also = await ssh_pin.seen_ips(db) if data.pin else set()
    res = await ssh_pin.run_all(db, [h for h in hosts if h.host_key],
                                lambda h, login: ssh_pin.change(h, login, data.pin, also))
    res = {**_no_hostkey(hosts), **res}
    value = await ssh_pin.save(db, res)
    names = {h.id: h.name for h in hosts}
    await audit(db, request, user, "ssh_pin" if data.pin else "ssh_unpin",
                changed=[names[i] for i, r in res.items() if r.get("changed")],
                errors=[names[i] for i, r in res.items() if r.get("error") or r["state"] == "fout"])
    await db.commit()
    return {**value, "results": {str(k): r for k, r in res.items()}}


# --- WebSocket ----------------------------------------------------------------

async def _ws_user(ws: WebSocket, db: AsyncSession, reauth: bool = True) -> tuple[User | None, str]:
    origin = ws.headers.get("origin")
    if not origin or urlsplit(origin).netloc != ws.headers.get("host"):
        return None, "Verkeerde origin"
    token = ws.cookies.get(COOKIE)
    sess = await db.get(Session, token_id(token)) if token else None
    now = datetime.now(timezone.utc)
    aware = lambda dt: dt.replace(tzinfo=dt.tzinfo or timezone.utc)  # noqa: E731
    if sess is None or aware(sess.expires_at) < now or not (sess.mfa_ok and sess.user.totp_enabled):
        return None, "Niet ingelogd"
    if reauth and now - aware(sess.auth_at) > timedelta(minutes=get_settings().reauth_minutes):
        return None, "reauth_required"
    return sess.user, ""


async def _send(ws: WebSocket, **msg) -> None:
    await ws.send_text(json.dumps(msg))


SESSION_CHECK = 60
REVOKED = "Je sessie is afgemeld (elders uitgelogd of wachtwoord gewijzigd): verbinding gesloten"


async def watch_session(ws: WebSocket, db: AsyncSession) -> None:
    """Loopt zolang de sessie bestaat; keert terug zodra ze ingetrokken of verlopen is.
    Naast de pompen van een WebSocket starten: wie afgemeld wordt, houdt geen open shell over."""
    token = ws.cookies.get(COOKIE)
    sid = token_id(token) if token else ""
    while True:
        await asyncio.sleep(SESSION_CHECK)
        expires = (await db.execute(select(Session.expires_at).where(Session.id == sid))).scalar_one_or_none()
        await db.commit()
        if expires is None or expires.replace(tzinfo=expires.tzinfo or timezone.utc) < datetime.now(timezone.utc):
            with contextlib.suppress(Exception):
                await _send(ws, t="error", m=REVOKED)
            return


@router.websocket("/ws/{host_id}")
async def terminal(ws: WebSocket, host_id: int, cols: int = 100, rows: int = 30,
                   db: AsyncSession = Depends(get_db)):
    await ws.accept()
    user, why = await _ws_user(ws, db)
    if user is None:
        await _send(ws, t="error", m=why)
        await ws.close(4401)
        return
    if why := await outside.blocked(ws, db, "terminal"):
        await _send(ws, t="error", m=why)
        await ws.close(4403)
        return
    h = await db.get(SshHost, host_id)
    if h is None:
        await _send(ws, t="error", m="Host niet gevonden")
        await ws.close(4404)
        return

    ip = ws.client.host if ws.client else None
    try:
        # Eerste keer: hostsleutel tonen en laten bevestigen (zoals ssh het zelf vraagt).
        if not h.host_key:
            await _send(ws, t="status", m=f"Hostsleutel ophalen van {h.host}:{h.port}…")
            server_key = await asyncio.wait_for(asyncssh.get_server_host_key(h.host, h.port), CONNECT_TIMEOUT)
            await _send(ws, t="hostkey", fp=server_key.get_fingerprint("sha256"), alg=server_key.get_algorithm())
            answer = json.loads(await asyncio.wait_for(ws.receive_text(), 120))
            if answer.get("t") != "accept":
                await _send(ws, t="error", m="Hostsleutel niet aanvaard")
                await ws.close()
                return
            h.host_key = server_key.export_public_key().decode().strip()
            db.add(AuditLog(user_id=user.id, action="ssh_hostkey_accepted", ip=ip,
                            detail={"name": h.name, "fp": server_key.get_fingerprint("sha256")}))
            await db.commit()

        # Eigen sleutel of wachtwoord van de host; anders de standaard login. Gebruiker leeg = standaard.
        login = await login_for(db, h)
        await _send(ws, t="status", m=f"Verbinden met {login.username}@{h.host}…")
        conn = await asyncio.wait_for(asyncssh.connect(
            h.host, port=h.port, username=login.username, keepalive_interval=KEEPALIVE,
            known_hosts=([asyncssh.import_public_key(h.host_key)], [], []),
            client_keys=[login.key] if login.key else None, password=login.password,
            agent_path=None, config=None, preferred_auth="publickey,password,keyboard-interactive",
        ), CONNECT_TIMEOUT)
    except asyncssh.HostKeyNotVerifiable:
        db.add(AuditLog(user_id=user.id, action="ssh_hostkey_mismatch", ip=ip, detail={"name": h.name}))
        await db.commit()
        await _send(ws, t="error", m="De hostsleutel is veranderd! Verbinding geweigerd. Herinstalleerde je de "
                                     "server, vergeet dan de oude sleutel bij deze host.")
        await ws.close()
        return
    except asyncssh.PermissionDenied:
        await _send(ws, t="error", m="Aanmelden geweigerd: controleer gebruiker, sleutel of wachtwoord")
        await ws.close()
        return
    except (OSError, asyncio.TimeoutError, asyncssh.Error) as e:
        await _send(ws, t="error", m=f"Verbinden mislukt: {getattr(e, 'reason', None) or e or type(e).__name__}")
        await ws.close()
        return
    except WebSocketDisconnect:
        return

    started = time.monotonic()
    h.last_used_at = datetime.now(timezone.utc)
    db.add(AuditLog(user_id=user.id, action="ssh_open", ip=ip, detail={"name": h.name, "host": h.host}))
    await db.commit()

    async with conn:
        proc = await conn.create_process(term_type="xterm-256color", term_size=(max(10, cols), max(4, rows)),
                                         encoding=None, stderr=asyncssh.STDOUT)
        await _send(ws, t="ready")

        async def ssh_to_ws():
            while True:
                data = await proc.stdout.read(65536)
                if not data:
                    break
                await ws.send_bytes(data)

        async def ws_to_ssh():
            while True:
                msg = await asyncio.wait_for(ws.receive(), IDLE_SECONDS)
                if msg["type"] == "websocket.disconnect":
                    break
                if msg.get("bytes") is not None:
                    proc.stdin.write(msg["bytes"])
                elif msg.get("text"):
                    with contextlib.suppress(ValueError, KeyError, TypeError):
                        m = json.loads(msg["text"])
                        if m.get("t") == "r":
                            proc.change_terminal_size(max(10, int(m["c"])), max(4, int(m["r"])))

        watch = asyncio.create_task(watch_session(ws, db))
        tasks = [asyncio.create_task(ssh_to_ws()), asyncio.create_task(ws_to_ssh()), watch]
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for t in pending:
            t.cancel()
        idle = any(isinstance(t.exception(), asyncio.TimeoutError) for t in done if not t.cancelled())
        proc.close()

    db.add(AuditLog(user_id=user.id, action="ssh_close", ip=ip,
                    detail={"name": h.name, "seconds": round(time.monotonic() - started)}))
    await db.commit()
    with contextlib.suppress(Exception):
        await _send(ws, t="closed", m=REVOKED if watch in done else
                    "Afgemeld wegens 30 minuten inactiviteit" if idle else "Verbinding gesloten")
        await ws.close()
