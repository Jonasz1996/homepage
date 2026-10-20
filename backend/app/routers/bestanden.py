"""Bestanden naast de terminal (zoals WinSCP): zie bestanden.py.

Openen vraagt wat een terminal vraagt: van buitenaf de functie terminal (outside.guard) en een recente 2FA
(recent_auth). Wat daarna komt, hoort bij dat venster: een geheime id, gebonden aan de gebruiker en de browsersessie
die het opende. Elk verzoek kijkt opnieuw of de sessie nog bestaat en of de terminal van hier nog mag.

Een download is een gewone link (zodat de browser hem zelf opslaat, ook een groot bestand): de link komt van een
POST met de header van de frontend, werkt één keer, 60 seconden, alleen vanaf hetzelfde IP en zolang de browsersessie
bestaat.
"""

import asyncio
import posixpath
import time
from datetime import datetime, timezone

import asyncssh
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.ext.asyncio import AsyncSession

from .. import bestanden, outside, ssh_exec
from ..bestanden import check_name, check_path, check_rel, op
from ..db import get_db
from ..deps import audit, client_ip, current_session, current_user, recent_auth
from ..models import Session, SshHost, User
from ..zonderlogin import TRANSIENT_PREFIX
from ..ssh_login import waarom

router = APIRouter(prefix="/api/ssh", tags=["bestanden"])
GUARD = [outside.guard("terminal")]
HOSTKEY_CHANGED = ("De hostsleutel is veranderd! Verbinding geweigerd. Herinstalleerde je de server, vergeet dan de "
                   "oude sleutel bij deze host (✎ in de terminal).")


class PathIn(BaseModel):
    path: str = Field(min_length=1, max_length=4096)

    @field_validator("path")
    @classmethod
    def _path(cls, v: str) -> str:
        return check_path(v)


class MkdirIn(PathIn):
    parents: bool = False


class RenameIn(PathIn):
    to: str = Field(min_length=1, max_length=4096)
    overwrite: bool = False

    @field_validator("to")
    @classmethod
    def _to(cls, v: str) -> str:
        return check_path(v)


class DeleteIn(BaseModel):
    paths: list[str] = Field(min_length=1, max_length=1000)
    recursive: bool = False

    @field_validator("paths")
    @classmethod
    def _paths(cls, v: list[str]) -> list[str]:
        return [check_path(p) for p in v]


class ChmodIn(PathIn):
    mode: str = Field(pattern=r"^[0-7]{3,4}$")


class WriteIn(PathIn):
    text: str = Field(max_length=bestanden.EDIT_MAX)
    eol: str = Field(default="lf", pattern="^(lf|crlf)$")
    # None = nieuw bestand; anders wat read gaf, om te zien of het intussen gewijzigd is.
    mtime: int | None = None
    size: int | None = None
    force: bool = False


class NamesIn(BaseModel):
    dir: str = Field(min_length=1, max_length=4096)
    names: list[str] = Field(min_length=1, max_length=1000)

    @field_validator("dir")
    @classmethod
    def _dir(cls, v: str) -> str:
        return check_path(v)

    @field_validator("names")
    @classmethod
    def _names(cls, v: list[str]) -> list[str]:
        return [check_name(n) for n in v]


class UploadIn(BaseModel):
    dir: str = Field(min_length=1, max_length=4096)
    # Naam, of een pad onder dir als je een map uploadt ("foto's/2024/a.jpg").
    name: str = Field(min_length=1, max_length=4096)
    size: int = Field(ge=0, le=1 << 50)
    # Laatst gewijzigd op de pc (seconden), om over te nemen.
    mtime: float | None = Field(default=None, ge=0, le=1 << 40)
    overwrite: bool = False
    # Kleinere stukken dan bestanden.CHUNK (een proxy ertussen met een kleinere limiet).
    chunk: int | None = Field(default=None, ge=bestanden.MIN_CHUNK, le=bestanden.CHUNK)

    @field_validator("dir")
    @classmethod
    def _dir(cls, v: str) -> str:
        return check_path(v)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        check_rel(v)
        return v


class HostkeyIn(BaseModel):
    fp: str = Field(min_length=1, max_length=200)


async def _host(db: AsyncSession, host_id: int) -> SshHost:
    h = await db.get(SshHost, host_id)
    if h is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Host niet gevonden")
    return h


async def _server_key(h: SshHost) -> asyncssh.SSHKey:
    try:
        return await asyncio.wait_for(asyncssh.get_server_host_key(h.host, h.port), ssh_exec.CONNECT_TIMEOUT)
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"Verbinden mislukt: {waarom(e, h.host, h.port, ssh_exec.CONNECT_TIMEOUT)}") from e


async def _client(db: AsyncSession, s: bestanden.FileSession, request: Request,
                  user: User | None) -> asyncssh.SFTPClient:
    """De verbinding, of opnieuw verbinden. Een andere hostsleutel dan bevestigd: in het auditlog en het venster dicht,
    zoals bij openen (412: de frontend opent dan niet stil opnieuw)."""
    try:
        return await bestanden.client(db, s)
    except ssh_exec.SshFail as e:
        if isinstance(e.__cause__, asyncssh.HostKeyNotVerifiable):
            err = await bestanden.close_changed(s, HOSTKEY_CHANGED)
            await audit(db, request, user, "ssh_hostkey_mismatch", name=s.name, via="bestanden")
            await db.commit()
            raise err from e
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e


async def _use(fs: str, db: AsyncSession, sess: Session, user: User,
               request: Request) -> tuple[bestanden.FileSession, asyncssh.SFTPClient]:
    s = bestanden.get(fs, user.id, sess.id)
    return s, await _client(db, s, request, user)


# --- Openen ------------------------------------------------------------------------------------------------------

@router.post("/hosts/{host_id}/files", dependencies=GUARD)
async def open_files(host_id: int, request: Request, sess: Session = Depends(current_session),
                     user: User = Depends(recent_auth), db: AsyncSession = Depends(get_db)):
    """Een bestandenvenster openen. Eerste keer naar deze host: eerst de hostsleutel laten bevestigen (zoals de
    terminal), dan {"hostkey": ...} en nog geen venster."""
    h = await _host(db, host_id)
    if not h.host_key:
        key = await _server_key(h)
        return {"hostkey": {"fp": key.get_fingerprint("sha256"), "alg": key.get_algorithm()}}
    try:
        s = await bestanden.open_session(db, h, user.id, sess.id)
    except ssh_exec.SshFail as e:
        if isinstance(e.__cause__, asyncssh.HostKeyNotVerifiable):
            await audit(db, request, user, "ssh_hostkey_mismatch", name=h.name, via="bestanden")
            await db.commit()
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, HOSTKEY_CHANGED) from e
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(e)) from e
    h.last_used_at = datetime.now(timezone.utc)
    await audit(db, request, user, "sftp_open", name=h.name, host=h.host, login=s.username)
    await db.commit()
    return {"id": s.id, "home": bestanden.txt(s.home), "user": s.username, "name": h.name, "host": h.host,
            "chunk": bestanden.CHUNK, "edit_max": bestanden.EDIT_MAX}


@router.post("/hosts/{host_id}/files/hostkey", dependencies=GUARD)
async def accept_hostkey(host_id: int, data: HostkeyIn, request: Request, user: User = Depends(recent_auth),
                         db: AsyncSession = Depends(get_db)):
    """De hostsleutel aanvaarden die open_files toonde. De server moet nog altijd dezelfde tonen."""
    h = await _host(db, host_id)
    if h.host_key:
        return {"ok": True}
    key = await _server_key(h)
    if key.get_fingerprint("sha256") != data.fp:
        raise HTTPException(status.HTTP_409_CONFLICT, "De server toont nu een andere hostsleutel: kijk opnieuw")
    h.host_key = key.export_public_key().decode().strip()
    await audit(db, request, user, "ssh_hostkey_accepted", name=h.name, fp=data.fp, via="bestanden")
    await db.commit()
    return {"ok": True}


@router.post("/files/{fs}/close")
async def close_files(fs: str, sess: Session = Depends(current_session), user: User = Depends(current_user)):
    s = bestanden.SESSIONS.get(fs)
    if s is not None and s.user_id == user.id and s.sess_id == sess.id:
        await bestanden.close_session(s)
    return {"ok": True}


# --- Kijken en bewerken ------------------------------------------------------------------------------------------

@router.post("/files/{fs}/list", dependencies=GUARD)
async def list_dir(fs: str, data: PathIn, request: Request, sess: Session = Depends(current_session),
                   user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s, sftp = await _use(fs, db, sess, user, request)
    async with op(s, data.path):
        return await bestanden.list_dir(sftp, data.path)


@router.post("/files/{fs}/read", dependencies=GUARD)
async def read_file(fs: str, data: PathIn, request: Request, sess: Session = Depends(current_session),
                    user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s, sftp = await _use(fs, db, sess, user, request)
    async with op(s, data.path):
        out = await bestanden.read_text(sftp, data.path)
    await audit(db, request, user, "sftp_read", name=s.name, path=bestanden.txt(data.path), size=out["size"])
    await db.commit()
    return out


@router.post("/files/{fs}/write", dependencies=GUARD)
async def write_file(fs: str, data: WriteIn, request: Request, sess: Session = Depends(current_session),
                     user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s, sftp = await _use(fs, db, sess, user, request)
    async with op(s, data.path):
        out = await bestanden.write_text(sftp, data.path, data.text, data.eol, data.mtime, data.size, data.force,
                                         s.name)
    await audit(db, request, user, "sftp_edit", name=s.name, path=bestanden.txt(data.path), size=out["size"],
                new=data.mtime is None, forced=data.force)
    await db.commit()
    return out


@router.post("/files/{fs}/mkdir", dependencies=GUARD)
async def make_dir(fs: str, data: MkdirIn, request: Request, sess: Session = Depends(current_session),
                   user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s, sftp = await _use(fs, db, sess, user, request)
    async with op(s, data.path):
        if data.parents:
            await sftp.makedirs(data.path, exist_ok=True)
        else:
            # SFTP 3 zegt bij een bestaande map alleen "Failure".
            if await bestanden.lstat_or_none(sftp, data.path) is not None:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"{bestanden.txt(posixpath.basename(data.path))} bestaat al")
            await sftp.mkdir(data.path)
    await audit(db, request, user, "sftp_mkdir", name=s.name, path=bestanden.txt(data.path))
    await db.commit()
    return {"ok": True}


@router.post("/files/{fs}/rename", dependencies=GUARD)
async def rename(fs: str, data: RenameIn, request: Request, sess: Session = Depends(current_session),
                 user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Hernoemen, of verplaatsen naar een andere map (een volledig pad als nieuwe naam)."""
    s, sftp = await _use(fs, db, sess, user, request)
    if data.path == "/":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "/ kan je niet hernoemen")
    if data.to == data.path:
        return {"ok": True}
    async with op(s, data.path):
        await sftp.lstat(data.path)
        if await bestanden.lstat_or_none(sftp, data.to) is not None:
            if not data.overwrite:
                raise HTTPException(status.HTTP_409_CONFLICT,
                                    f"{bestanden.txt(posixpath.basename(data.to))} bestaat al")
            await sftp.posix_rename(data.path, data.to)
        else:
            await sftp.rename(data.path, data.to)
    await audit(db, request, user, "sftp_rename", name=s.name, path=bestanden.txt(data.path),
                to=bestanden.txt(data.to), overwrite=data.overwrite)
    await db.commit()
    return {"ok": True}


@router.post("/files/{fs}/delete", dependencies=GUARD)
async def delete(fs: str, data: DeleteIn, request: Request, sess: Session = Depends(current_session),
                 user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Verwijderen. Een map met inhoud alleen met recursive (de frontend vraagt het eerst)."""
    s, sftp = await _use(fs, db, sess, user, request)
    done: list[str] = []
    removed = [0]  # in de mappen: bestanden en mappen die al weg zijn
    failed: dict = {}
    try:
        for p in data.paths:
            if p == "/":
                raise HTTPException(status.HTTP_400_BAD_REQUEST, "/ verwijderen gaat niet")
            try:
                async with op(s, p):
                    a = await sftp.lstat(p)
                    if bestanden.kind(a.permissions) == "dir":
                        if await sftp.realpath(p) == "/":
                            raise HTTPException(status.HTTP_400_BAD_REQUEST, "/ verwijderen gaat niet")
                        if data.recursive:
                            await bestanden.remove_tree(sftp, p, removed)
                        elif [n for n in await sftp.readdir(p) if n.filename not in (".", "..")]:
                            raise HTTPException(status.HTTP_409_CONFLICT,
                                                f"{bestanden.txt(posixpath.basename(p))} is een map met inhoud")
                        else:
                            await sftp.rmdir(p)
                    else:
                        await sftp.remove(p)
            except HTTPException as e:
                # Een map die half weg is, hoort ook in het auditlog.
                failed = {"failed": bestanden.txt(p), "error": str(e.detail)}
                raise
            done.append(bestanden.txt(p))
    finally:
        if done or removed[0] or failed:
            await audit(db, request, user, "sftp_delete", name=s.name, paths=done[:100], count=len(done),
                        recursive=data.recursive, **({"items": removed[0]} if data.recursive else {}), **failed)
            await db.commit()
    return {"deleted": len(done)}


@router.post("/files/{fs}/chmod", dependencies=GUARD)
async def chmod(fs: str, data: ChmodIn, request: Request, sess: Session = Depends(current_session),
                user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s, sftp = await _use(fs, db, sess, user, request)
    async with op(s, data.path):
        await sftp.chmod(data.path, int(data.mode, 8))
    await audit(db, request, user, "sftp_chmod", name=s.name, path=bestanden.txt(data.path), mode=data.mode)
    await db.commit()
    return {"ok": True}


# --- Downloaden --------------------------------------------------------------------------------------------------

@router.post("/files/{fs}/download", dependencies=GUARD)
async def prepare_download(fs: str, data: NamesIn, request: Request, sess: Session = Depends(current_session),
                           user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Een link voor de browser: één bestand zoals het is, een map of meerdere als zip."""
    s, sftp = await _use(fs, db, sess, user, request)
    first = posixpath.join(data.dir, data.names[0])
    async with op(s, first):
        a = await sftp.stat(first)
        single = len(data.names) == 1 and bestanden.kind(a.permissions) == "file"
        if not single:
            for n in data.names[1:]:
                async with op(s, posixpath.join(data.dir, n)):
                    await sftp.lstat(posixpath.join(data.dir, n))
    if single:
        filename = data.names[0]
    elif len(data.names) == 1:
        filename = f"{data.names[0]}.zip"
    else:
        filename = f"{posixpath.basename(data.dir) or s.name}.zip"
    token = bestanden.add_download(bestanden.Download(session=s.id, user_id=user.id, sess_id=sess.id,
                                                      ip=client_ip(request), dir=data.dir, names=data.names,
                                                      zip=not single, filename=filename))
    await audit(db, request, user, "sftp_download", name=s.name, dir=bestanden.txt(data.dir),
                names=[bestanden.txt(n) for n in data.names[:50]], count=len(data.names), zip=not single,
                **({"size": a.size or 0} if single else {}))
    await db.commit()
    return {"url": f"/api/ssh/files/dl/{token}", "name": bestanden.txt(filename), "zip": not single}


@router.get("/files/dl/{token}", dependencies=GUARD)
async def download(token: str, request: Request, db: AsyncSession = Depends(get_db)):
    """De link uit prepare_download. Geen header van de frontend nodig (een gewone link): het token is de toegang."""
    d = bestanden.DOWNLOADS.pop(token, None)
    if d is None or d.expires < time.monotonic() or d.ip != client_ip(request):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Deze downloadlink is verlopen of al gebruikt: download opnieuw")
    s = bestanden.SESSIONS.get(d.session)
    if s is None or s.user_id != d.user_id:
        raise bestanden.gone()
    if not d.sess_id.startswith(TRANSIENT_PREFIX):
        # Intussen afgemeld, de sessie ingetrokken of verlopen.
        row = await db.get(Session, d.sess_id)
        until = row and row.expires_at.replace(tzinfo=row.expires_at.tzinfo or timezone.utc)
        if row is None or until < datetime.now(timezone.utc):
            raise bestanden.gone()
    sftp = await _client(db, s, request, await db.get(User, d.user_id))
    headers = {"Content-Disposition": bestanden.disposition(d.filename), "Cache-Control": "no-store",
               "X-Content-Type-Options": "nosniff"}
    if d.zip:
        # De databaseverbinding niet vasthouden zolang de download loopt (dat kan uren zijn).
        await db.close()
        return StreamingResponse(bestanden.zip_stream(s, sftp, d.dir, d.names), media_type="application/zip",
                                 headers=headers)
    path = posixpath.join(d.dir, d.names[0])
    async with op(s, path):
        a = await sftp.stat(path)
        if bestanden.kind(a.permissions) != "file":
            raise HTTPException(status.HTTP_400_BAD_REQUEST, "Geen gewoon bestand meer")
        # Nu al openen: geen toegang geeft dan een leesbare fout in plaats van een afgebroken download.
        f = await sftp.open(path, "rb")
    size = a.size or 0
    await db.close()
    return StreamingResponse(bestanden.file_stream(s, f, size), media_type="application/octet-stream",
                             headers={**headers, "Content-Length": str(size)})


# --- Uploaden ----------------------------------------------------------------------------------------------------

def _upload(s: bestanden.FileSession, uid: str) -> bestanden.Upload:
    u = s.uploads.get(uid)
    if u is None:
        raise HTTPException(status.HTTP_410_GONE, "Deze upload bestaat niet meer (afgebroken of 10 minuten stil)")
    return u


@router.post("/files/{fs}/upload", dependencies=GUARD)
async def upload_start(fs: str, data: UploadIn, request: Request, sess: Session = Depends(current_session),
                       user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    """Een upload beginnen. Bestaat het bestand al en is overwrite uit: {"exists": ...} (de frontend vraagt het)."""
    s, sftp = await _use(fs, db, sess, user, request)
    async with op(s, posixpath.join(data.dir, data.name)):
        out = await bestanden.upload_start(s, sftp, data.dir, data.name, data.size, data.mtime, data.overwrite,
                                           data.chunk)
    if made := out.pop("made", None):
        # Een map uploaden: de mappen staan er al, ook als de upload daarna niet afloopt.
        await audit(db, request, user, "sftp_mkdir", name=s.name, path=bestanden.txt(made), via="upload")
        await db.commit()
    return out


@router.put("/files/{fs}/upload/{uid}/{index}", dependencies=GUARD)
async def upload_chunk(fs: str, uid: str, index: int, request: Request, sess: Session = Depends(current_session),
                       user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s, sftp = await _use(fs, db, sess, user, request)
    u = _upload(s, uid)
    if int(request.headers.get("content-length") or 0) > bestanden.CHUNK:
        raise HTTPException(413, "Stuk te groot")
    body = await request.body()
    try:
        async with op(s, u.rel):
            return await bestanden.upload_chunk(s, sftp, u, index, body)
    except HTTPException as e:
        if e.status_code == status.HTTP_400_BAD_REQUEST and "mislukt" in str(e.detail):
            raise HTTPException(e.status_code, f"{e.detail}. Is de schijf vol?") from e
        raise


@router.post("/files/{fs}/upload/{uid}/finish", dependencies=GUARD)
async def upload_finish(fs: str, uid: str, request: Request, sess: Session = Depends(current_session),
                        user: User = Depends(current_user), db: AsyncSession = Depends(get_db)):
    s, sftp = await _use(fs, db, sess, user, request)
    u = _upload(s, uid)
    async with op(s, u.rel):
        out = await bestanden.upload_finish(s, sftp, u)
    await audit(db, request, user, "sftp_upload", name=s.name, path=bestanden.txt(u.final), size=u.size,
                overwrite=u.overwrite)
    await db.commit()
    return out


@router.delete("/files/{fs}/upload/{uid}", dependencies=GUARD)
async def upload_cancel(fs: str, uid: str, sess: Session = Depends(current_session),
                        user: User = Depends(current_user)):
    s = bestanden.get(fs, user.id, sess.id)
    u = s.uploads.get(uid)
    if u is not None:
        await bestanden.abort_upload(s, u)
    return {"ok": True}
