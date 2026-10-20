"""Bestanden op een SSH-host: bladeren, uploaden, downloaden en kleine bestanden bewerken, zoals WinSCP.

Met dezelfde login en hostsleutel als de terminal (ssh_login.login_for, ssh_exec.open_conn), over SFTP. Alles gebeurt
als die gebruiker, zonder sudo: wat de terminal als root mag, mag hier ook, wat een gewone gebruiker niet mag, mag hier
niet.

Een bestandenvenster is een sessie, zoals een terminal: openen vraagt een recente 2FA (routers/bestanden.open_files),
daarna loopt ze tot ze 30 minuten niet gebruikt is, de browsersessie afgemeld is of het tabblad sluit. De SSH-verbinding
eronder sluit na 5 minuten stilte en komt bij het volgende verzoek vanzelf terug. Alles staat in het geheugen van de API
(één proces): na een herstart open je het venster opnieuw.

Uploaden gaat in stukken van 3 MiB: dat past onder de limiet van nginx (4 MB), van NPM en van Cloudflare (100 MB per
verzoek), en elk stuk toont voortgang. Weigert een proxy ertussen een stuk als te groot (413), dan vraagt de frontend
kleinere stukken. Een upload schrijft naar een verborgen tijdelijk bestand naast het doel en
hernoemt het pas als alles er is: een afgebroken upload laat het oude bestand staan. Bewerken doet hetzelfde.

Een map of meerdere bestanden downloaden geeft een zip, die de API al lezend maakt (niets op de host of in de container
tussenbewaard). Symlinks naar mappen volgt de zip niet (lussen); wat niet mee kon, staat in NIET-MEEGENOMEN.txt erin.
Valt de verbinding weg tijdens een download, dan breekt de download af (de browser meldt het): nooit een zip die
volledig lijkt maar het niet is.

Wat loopt (een verzoek of een download), houdt de verbinding open: de opruimer en het sluiten van het tabblad wachten
erop. Afmelden of een sessie intrekken (routers/auth) sluit wel meteen.
"""

import asyncio
import contextlib
import logging
import posixpath
import re
import secrets
import stat as st
import time
import zipfile
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from urllib.parse import quote

import asyncssh
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from . import ssh_exec
from .models import SshHost
from .ssh_login import login_for

log = logging.getLogger("homepage.bestanden")

IDLE = 30 * 60  # zoals de terminal: zo lang niet gebruikt, dan dicht
CONN_IDLE = 5 * 60  # de SSH-verbinding eronder
UPLOAD_IDLE = 10 * 60  # een upload waarvan zo lang geen stuk kwam, wordt afgebroken
CHUNK = 3 * 1024 * 1024  # onder client_max_body_size 4m van nginx
MIN_CHUNK = 64 * 1024  # een proxy ertussen met een kleinere limiet: de frontend vraagt dan kleinere stukken
EDIT_MAX = 1024 * 1024
LIST_MAX = 10_000  # zoveel items van een map tonen; verder lezen we niet (een map met miljoenen bestanden)
LINKS_MAX = 500  # zoveel symlinks per map volgen we om te zien of ze naar een map wijzen
DL_TTL = 60
READ_BLOCK = 1024 * 1024
MAX_PER_USER = 20
ZIP_MAX = 100_000  # items in één zip: elk item kost geheugen tot de zip af is
SKIPPED_MAX = 1000  # regels in NIET-MEEGENOMEN.txt
SWEEP_EVERY = 30
KEEPALIVE = 30
PART = re.compile(r"^\..+\.homepage-[0-9a-f]{8}\.part$")
# De verbinding is weg (een zip breekt dan af, in plaats van "niet meegenomen" voor al de rest).
LOST = (asyncssh.SFTPConnectionLost, asyncssh.SFTPNoConnection)
GONE = "Dit bestandenvenster is verlopen (30 minuten niet gebruikt, of de API herstartte): open het opnieuw"


def txt(s: str) -> str:
    """Leesbaar en geldig voor JSON: een naam die geen UTF-8 is (surrogateescape), met vervangtekens."""
    return s.encode("utf-8", "surrogateescape").decode("utf-8", "replace")


def odd(s: str) -> bool:
    """Een naam die geen geldige UTF-8 is: tonen gaat, iets mee doen niet (we kunnen hem niet terugsturen)."""
    return any("\udc80" <= c <= "\udcff" for c in s)


def check_path(p: str) -> str:
    """Een absoluut pad op de host. Dubbele slashes en een slash achteraan weg; .. laten we staan (symlinks)."""
    if not p.startswith("/") or "\0" in p or len(p.encode("utf-8", "surrogateescape")) > 4096:
        raise ValueError("Ongeldig pad: begin bij / (bv. /etc)")
    return re.sub("/+", "/", p).rstrip("/") or "/"


def check_name(n: str) -> str:
    if n in ("", ".", "..") or "/" in n or "\0" in n or len(n.encode("utf-8", "surrogateescape")) > 255:
        raise ValueError(f"Ongeldige naam: {n!r}")
    return n


def check_rel(rel: str) -> list[str]:
    """Een pad onder de huidige map (uploaden van een map: "foto's/2024/a.jpg")."""
    parts = rel.split("/")
    for p in parts:
        check_name(p)
    return parts


def gone(msg: str = GONE) -> HTTPException:
    return HTTPException(status.HTTP_410_GONE, msg)


def changed(msg: str) -> HTTPException:
    """De host of zijn login veranderde sinds het venster openging. 412 en niet 410: de frontend opent dan niet stil
    opnieuw (en doet de vraag niet nog eens als een andere gebruiker), je verbindt zelf opnieuw."""
    return HTTPException(status.HTTP_412_PRECONDITION_FAILED, msg)


def disposition(name: str) -> str:
    """Content-Disposition met de echte naam (RFC 6266), en een ASCII-naam voor oude browsers."""
    plain = "".join(c if 32 <= ord(c) < 127 and c not in '"\\;' else "_" for c in name) or "download"
    return f"attachment; filename=\"{plain}\"; filename*=UTF-8''{quote(txt(name), safe='')}"


# --- Sessies ----------------------------------------------------------------------------------------------------

@dataclass(eq=False)
class Upload:
    id: str
    final: str  # het doel
    tmp: str  # verborgen bestand ernaast, tot alles er is
    size: int
    chunk: int
    chunks: int
    overwrite: bool
    mtime: float | None  # laatst gewijzigd op de pc
    old: asyncssh.SFTPAttrs | None  # het bestand dat overschreven wordt: rechten en eigenaar overnemen
    rel: str
    file: asyncssh.SFTPClientFile | None = None
    got: set[int] = field(default_factory=set)
    used: float = field(default_factory=time.monotonic)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


@dataclass(eq=False)
class FileSession:
    id: str
    host_id: int
    user_id: int
    sess_id: str  # de browsersessie die het venster opende (zonder login: zonder-login:<gebruiker>)
    name: str
    where: tuple  # (host, port, hostsleutel): wijzigt de host (✎), dan opnieuw openen
    username: str = ""
    home: str = "/"
    used: float = field(default_factory=time.monotonic)
    conn: asyncssh.SSHClientConnection | None = None
    sftp: asyncssh.SFTPClient | None = None
    conn_used: float = 0.0
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    uploads: dict[str, Upload] = field(default_factory=dict)
    busy: int = 0  # verzoeken en downloads die nu lopen: de verbinding niet onder hun voeten sluiten
    closing: bool = False  # gesloten terwijl er nog iets liep: de verbinding sluit als dat klaar is
    closed: bool = False  # het venster is dicht: een verbinding die nog aan het opkomen was, meteen weer sluiten

    def touch(self) -> None:
        self.used = self.conn_used = time.monotonic()


@dataclass(eq=False)
class Download:
    session: str
    user_id: int
    sess_id: str  # de browsersessie: afgemeld, dan werkt de link niet meer
    ip: str | None
    dir: str
    names: list[str]
    zip: bool
    filename: str
    expires: float = field(default_factory=lambda: time.monotonic() + DL_TTL)


SESSIONS: dict[str, FileSession] = {}
DOWNLOADS: dict[str, Download] = {}
# Vensters die dicht gingen omdat de host of zijn login veranderde: (tot, gebruiker, browsersessie, uitleg). Elk later
# verzoek van dat venster krijgt dezelfde uitleg (412), niet "verlopen" (410, waarop de frontend stil opnieuw opent).
CHANGED: dict[str, tuple[float, int, str, str]] = {}
# Vensters die nog aan het openen zijn (verbinden met een trage host): afmelden of intrekken sluit ook die.
OPENING: set[FileSession] = set()
# Tijdelijke .part-bestanden die we niet konden weghalen (de verbinding was al weg), per host: bij de volgende
# verbinding met die host alsnog.
LEFTOVER: dict[int, set[str]] = {}
_sweeper: asyncio.Task | None = None


def _drop_conn(s: FileSession) -> None:
    for u in s.uploads.values():
        u.file = None  # de handle hoort bij de verbinding
    if s.conn is not None:
        s.conn.close()
    s.conn = s.sftp = None


def _alive(s: FileSession) -> bool:
    return s.sftp is not None and s.conn is not None and not s.conn.is_closed()


async def _connect(h: SshHost, login) -> tuple[asyncssh.SSHClientConnection, asyncssh.SFTPClient]:
    conn = await ssh_exec.open_conn(h, login, KEEPALIVE)
    try:
        sftp = await asyncio.wait_for(conn.start_sftp_client(path_errors="surrogateescape"), ssh_exec.CONNECT_TIMEOUT)
    except (OSError, asyncssh.Error, asyncio.TimeoutError) as e:
        conn.close()
        raise ssh_exec.SshFail(
            f"Aanmelden op {h.host} lukte, maar SFTP niet ({str(e) or type(e).__name__}): staat er een regel "
            "'Subsystem sftp' in /etc/ssh/sshd_config, en is sftp-server er (openssh-sftp-server)?") from e
    return conn, sftp


async def _clean_leftovers(host_id: int, sftp: asyncssh.SFTPClient) -> None:
    """Wat een vorige sessie op deze host liet staan (zie LEFTOVER). Valt de verbinding weer weg: de volgende keer."""
    for tmp in LEFTOVER.pop(host_id, set()):
        if not PART.match(posixpath.basename(tmp)):
            continue
        try:
            await asyncio.wait_for(sftp.remove(tmp), ssh_exec.CONNECT_TIMEOUT)
        except (*LOST, OSError, asyncio.TimeoutError):
            LEFTOVER.setdefault(host_id, set()).add(tmp)
        except asyncssh.Error:
            pass  # al weg, of geen recht: niets meer aan te doen


async def open_session(db: AsyncSession, h: SshHost, user_id: int, sess_id: str) -> FileSession:
    """Verbinden en de sessie bewaren. Gooit ssh_exec.SshFail."""
    s = FileSession(id=secrets.token_urlsafe(18), host_id=h.id, user_id=user_id, sess_id=sess_id, name=h.name,
                    where=(h.host, h.port, h.host_key))
    login = await login_for(db, h)
    s.username = login.username
    OPENING.add(s)
    try:
        s.conn, s.sftp = await _connect(h, login)
        s.touch()
        await _clean_leftovers(s.host_id, s.sftp)
        try:
            s.home = await s.sftp.realpath(".")
        except (OSError, asyncssh.Error):
            s.home = "/"
        mine = sorted((x for x in SESSIONS.values() if x.user_id == user_id), key=lambda x: x.used)
        for old in mine[:max(0, len(mine) - MAX_PER_USER + 1)]:
            await close_session(old)
        if s.closed:
            # Afgemeld (of de sessie ingetrokken) terwijl het nog verbond.
            raise gone("Intussen afgemeld: het venster is niet geopend")
        SESSIONS[s.id] = s
    except BaseException:
        _drop_conn(s)
        raise
    finally:
        OPENING.discard(s)
    _ensure_sweeper()
    return s


def get(fs: str, user_id: int, sess_id: str) -> FileSession:
    s = SESSIONS.get(fs)
    if s is None or s.user_id != user_id or s.sess_id != sess_id:
        why = CHANGED.get(fs)
        if s is None and why and why[0] > time.monotonic() and why[1:3] == (user_id, sess_id):
            raise changed(why[3])
        raise gone()
    s.used = time.monotonic()
    return s


def _closed(s: FileSession) -> HTTPException:
    """Voor een verzoek naar een venster dat intussen dicht ging: waarom, als de host veranderde (412), anders 410."""
    why = CHANGED.get(s.id)
    return changed(why[3]) if why and why[0] > time.monotonic() else gone()


async def client(db: AsyncSession, s: FileSession) -> asyncssh.SFTPClient:
    """De SFTP-client van deze sessie; na 5 minuten stilte of een verbroken verbinding eerst opnieuw verbinden."""
    async with s.lock:
        if s.closed:
            # Dicht terwijl dit verzoek op de lock wachtte (een ander verzoek zag een andere hostsleutel, afgemeld):
            # niet opnieuw aanmelden op de host.
            raise _closed(s)
        if _alive(s):
            s.touch()
            return s.sftp
        _drop_conn(s)
        h = await db.get(SshHost, s.host_id)
        if h is None:
            raise await close_changed(s, "Deze host staat niet meer in de terminal")
        if (h.host, h.port, h.host_key) != s.where:
            raise await close_changed(s, "De host is intussen gewijzigd (adres, poort of hostsleutel): verbind "
                                         "opnieuw")
        login = await login_for(db, h)
        if login.username != s.username:
            # Nooit stil als een andere gebruiker verder (bv. root in plaats van backup): zelf opnieuw verbinden.
            raise await close_changed(s, f"De login van {s.name} is intussen gewijzigd ({s.username} werd "
                                         f"{login.username}): verbind opnieuw")
        conn, sftp = await _connect(h, login)
        if s.closed:
            # Intussen dicht (tabblad gesloten, afgemeld): deze verbinding hoort bij niemand meer.
            conn.close()
            raise _closed(s)
        s.conn, s.sftp = conn, sftp
        s.touch()
        await _clean_leftovers(s.host_id, sftp)
        if s.closed:
            raise _closed(s)  # close_session sloot de verbinding al
        return sftp


async def _remove_part(s: FileSession, u: Upload) -> None:
    """Het tijdelijke bestand van een upload weg; is de verbinding al weg, dan bij de volgende (LEFTOVER)."""
    f, u.file = u.file, None
    if not _alive(s):
        LEFTOVER.setdefault(s.host_id, set()).add(u.tmp)
        return
    try:
        if f is not None:
            with contextlib.suppress(OSError, asyncssh.Error, asyncio.TimeoutError):
                await asyncio.wait_for(f.close(), ssh_exec.CONNECT_TIMEOUT)
        await asyncio.wait_for(s.sftp.remove(u.tmp), ssh_exec.CONNECT_TIMEOUT)
    except asyncssh.SFTPNoSuchFile:
        pass
    except (OSError, asyncssh.Error, asyncio.TimeoutError):
        LEFTOVER.setdefault(s.host_id, set()).add(u.tmp)


async def abort_upload(s: FileSession, u: Upload) -> None:
    s.uploads.pop(u.id, None)
    await _remove_part(s, u)


async def close_session(s: FileSession, stop: bool = False) -> None:
    """Het venster dicht. Loopt er nog een download of verzoek, dan sluit de verbinding pas als dat klaar is, tenzij
    stop (afgemeld, sessie ingetrokken): dan meteen, en wat nog loopt, breekt af."""
    SESSIONS.pop(s.id, None)
    s.closed = True
    for t, d in list(DOWNLOADS.items()):
        if d.session == s.id:
            DOWNLOADS.pop(t, None)
    for u in list(s.uploads.values()):
        await abort_upload(s, u)
    if s.busy and not stop:
        s.closing = True
    else:
        _drop_conn(s)


async def close_changed(s: FileSession, why: str) -> HTTPException:
    """Het venster dicht omdat de host veranderde; dit venster antwoordt voortaan met why (zie CHANGED)."""
    now = time.monotonic()
    for k in [k for k, v in CHANGED.items() if v[0] <= now]:
        del CHANGED[k]
    CHANGED[s.id] = (now + IDLE, s.user_id, s.sess_id, why)
    await close_session(s)
    return changed(why)


async def close_where(match) -> None:
    """Alle vensters waarvoor match(sessie) waar is meteen dicht (afmelden, een sessie intrekken), ook wie nog opent."""
    for s in [x for x in (*SESSIONS.values(), *OPENING) if match(x)]:
        await close_session(s, stop=True)


@contextlib.contextmanager
def working(s: FileSession):
    """Rond alles wat de verbinding gebruikt: zolang het loopt, sluit niemand ze."""
    s.busy += 1
    try:
        yield
    finally:
        s.busy -= 1
        s.touch()
        if (s.closing or s.closed) and not s.busy:
            _drop_conn(s)


async def sweep() -> None:
    now = time.monotonic()
    for t, d in list(DOWNLOADS.items()):
        if d.expires < now:
            DOWNLOADS.pop(t, None)
    for s in list(SESSIONS.values()):
        for u in list(s.uploads.values()):
            if now - u.used > UPLOAD_IDLE:
                await abort_upload(s, u)
        if s.busy:
            # Een download of een groot verzoek (een map met veel bestanden verwijderen) loopt nog.
            continue
        if now - s.used > IDLE:
            await close_session(s)
        elif s.conn is not None and not s.uploads and now - s.conn_used > CONN_IDLE:
            _drop_conn(s)


async def _sweep_loop() -> None:
    while SESSIONS or DOWNLOADS:
        await asyncio.sleep(SWEEP_EVERY)
        try:
            await sweep()
        except Exception:
            log.exception("bestandensessies opruimen mislukt")


def _ensure_sweeper() -> None:
    global _sweeper
    loop = asyncio.get_running_loop()
    if _sweeper is None or _sweeper.done() or _sweeper.get_loop() is not loop:
        _sweeper = loop.create_task(_sweep_loop())


async def close_all() -> None:
    """Bij het stoppen van de API (en in de tests)."""
    global _sweeper
    for s in [*SESSIONS.values(), *OPENING]:
        await close_session(s, stop=True)
    DOWNLOADS.clear()
    CHANGED.clear()
    LEFTOVER.clear()
    if _sweeper is not None and not _sweeper.done():
        _sweeper.cancel()
        with contextlib.suppress(asyncio.CancelledError, RuntimeError):
            await _sweeper
    _sweeper = None


# --- Fouten -----------------------------------------------------------------------------------------------------

@contextlib.asynccontextmanager
async def op(s: FileSession, path: str):
    """SFTP-fouten als leesbare HTTP-fouten. Een verbroken verbinding komt bij het volgende verzoek terug."""
    what = txt(path)
    try:
        with working(s):
            yield
    except HTTPException:
        raise
    except (asyncssh.SFTPNoSuchFile, asyncssh.SFTPNoSuchPath) as e:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{what} bestaat niet (meer)") from e
    except asyncssh.SFTPPermissionDenied as e:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Geen toegang tot {what} als {s.username}") from e
    except asyncssh.SFTPFileAlreadyExists as e:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{what} bestaat al") from e
    except asyncssh.SFTPDirNotEmpty as e:
        raise HTTPException(status.HTTP_409_CONFLICT, f"{what} is niet leeg") from e
    except (asyncssh.SFTPNoSpaceOnFilesystem, asyncssh.SFTPQuotaExceeded) as e:
        raise HTTPException(status.HTTP_507_INSUFFICIENT_STORAGE, f"Geen plaats meer op {s.name}") from e
    except asyncssh.SFTPOpUnsupported as e:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{s.name} kan dat niet over SFTP ({e.reason})") from e
    except ValueError as e:
        # Een ongeldige naam (check_name), of een bestand dat intussen gesloten is.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(e)) from e
    except (asyncssh.SFTPConnectionLost, asyncssh.SFTPNoConnection) as e:
        _drop_conn(s)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Verbinding met {s.name} verbroken: probeer opnieuw") from e
    except asyncssh.SFTPError as e:
        # SFTP versie 3 (OpenSSH) zegt bij de meeste fouten alleen "Failure": een volle schijf, een map die niet leeg
        # is, een bestand dat al bestaat.
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"{what}: mislukt ({e.reason or 'Failure'})") from e
    except (OSError, asyncssh.Error) as e:
        _drop_conn(s)
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"Verbinding met {s.name} verbroken: probeer opnieuw") from e


async def lstat_or_none(sftp: asyncssh.SFTPClient, path: str) -> asyncssh.SFTPAttrs | None:
    try:
        return await sftp.lstat(path)
    except (asyncssh.SFTPNoSuchFile, asyncssh.SFTPNoSuchPath):
        return None


# --- Een map bekijken -------------------------------------------------------------------------------------------

def kind(mode: int | None) -> str:
    if mode is None:
        return "other"
    if st.S_ISDIR(mode):
        return "dir"
    if st.S_ISREG(mode):
        return "file"
    if st.S_ISLNK(mode):
        return "link"
    return "other"


def _owner(n: asyncssh.SFTPName) -> tuple[str, str]:
    """Eigenaar en groep: de namen uit de ls-regel van de server (OpenSSH), anders de nummers."""
    parts = str(n.longname or "").split(None, 8)
    if len(parts) >= 9 and parts[0][:1] in "-dlcbps":
        return txt(parts[2]), txt(parts[3])
    a = n.attrs
    return ("" if a.uid is None else str(a.uid)), ("" if a.gid is None else str(a.gid))


def entry(name: str, a: asyncssh.SFTPAttrs, owner: str = "", group: str = "") -> dict:
    mode = a.permissions
    return {"name": txt(name), "odd": odd(name), "type": kind(mode), "size": a.size or 0, "mtime": a.mtime,
            "mode": None if mode is None else mode & 0o7777, "perms": "" if mode is None else st.filemode(mode),
            "owner": owner or ("" if a.uid is None else str(a.uid)),
            "group": group or ("" if a.gid is None else str(a.gid))}


async def list_dir(sftp: asyncssh.SFTPClient, path: str) -> dict:
    real = await sftp.realpath(path)
    names, more = [], False
    async with contextlib.aclosing(sftp.scandir(real)) as it:
        async for n in it:
            if n.filename in (".", ".."):
                continue
            if len(names) == LIST_MAX:
                more = True
                break
            names.append(n)
    entries, links = [], []
    for n in names:
        e = entry(n.filename, n.attrs, *_owner(n))
        entries.append(e)
        if e["type"] == "link" and len(links) < LINKS_MAX:
            links.append((e, posixpath.join(real, n.filename)))
    sem = asyncio.Semaphore(32)

    async def follow(e: dict, full: str) -> None:
        async with sem:
            with contextlib.suppress(asyncssh.SFTPError):
                e["target"] = txt(await sftp.readlink(full))
            try:
                t = await sftp.stat(full)
            except asyncssh.SFTPError:
                e["broken"] = True
                return
        e["to"] = kind(t.permissions)

    await asyncio.gather(*(follow(e, full) for e, full in links))
    free = None
    with contextlib.suppress(asyncssh.SFTPError):
        v = await sftp.statvfs(real)
        free = v.bavail * (v.frsize or v.bsize)
    # Wijst het pad (via een symlink) naar een map waarvan de naam geen UTF-8 is, dan blijft de map het pad zoals
    # gevraagd: anders maakt een upload "hier" een nieuwe map met vervangtekens in de naam.
    return {"path": txt(path if odd(real) else real), "odd": odd(real), "entries": entries,
            "count": len(names), "truncated": more, "free": free}


# --- Bewerken ---------------------------------------------------------------------------------------------------

async def read_text(sftp: asyncssh.SFTPClient, path: str) -> dict:
    a = await sftp.stat(path)
    if kind(a.permissions) != "file":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Geen gewoon bestand")
    if (a.size or 0) > EDIT_MAX:
        raise HTTPException(413,
                            "Te groot om hier te bewerken (meer dan 1 MB): download het")
    async with sftp.open(path, "rb") as f:
        data = await f.read(EDIT_MAX + 1)
    if len(data) > EDIT_MAX:
        raise HTTPException(413,
                            "Te groot om hier te bewerken (meer dan 1 MB): download het")
    try:
        if b"\0" in data:
            raise UnicodeDecodeError("utf-8", data, 0, 1, "nul")
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, "Geen tekstbestand (of geen UTF-8): download het")
    # Een tekstvak in de browser maakt van elke regeleinde \n: Windows-regeleindes zetten we bij het bewaren terug.
    # Gemengd: wat het meest voorkomt (de editor zegt het, want bewaren maakt ze dan allemaal gelijk).
    crlf = text.count("\r\n")
    lf = text.count("\n") - crlf
    return {"text": text.replace("\r\n", "\n"), "eol": "crlf" if crlf > lf else "lf", "mixed": bool(crlf and lf),
            "mtime": a.mtime, "size": a.size or 0, "mode": None if a.permissions is None else a.permissions & 0o7777}


def _part_name(name: str) -> str:
    base = name
    while len(base.encode("utf-8", "surrogateescape")) > 200:
        base = base[:-1]
    return f".{base}.homepage-{secrets.token_hex(4)}.part"


async def _keep_attrs(sftp: asyncssh.SFTPClient, path: str, old: asyncssh.SFTPAttrs | None) -> None:
    """Rechten en (als root) eigenaar van het oude bestand op het nieuwe zetten."""
    if old is None:
        return
    if old.uid is not None and old.gid is not None:
        # Alleen root mag een andere eigenaar zetten; lukt het niet, dan blijft het de gebruiker van de login, maar
        # de groep mag elke eigenaar zetten naar een groep waar hij in zit (app:app 0660, bewerkt door jonas uit de
        # groep app: de dienst app kan zijn bestand nog lezen). Eerst de eigenaar: chown wist setuid en setgid, die
        # chmod daarna terugzet.
        try:
            await sftp.chown(path, old.uid, old.gid)
        except asyncssh.SFTPError:
            with contextlib.suppress(asyncssh.SFTPError):
                mine = await sftp.lstat(path)
                if mine.uid is not None and mine.gid != old.gid:
                    await sftp.chown(path, mine.uid, old.gid)
    if old.permissions is not None:
        await sftp.chmod(path, old.permissions & 0o7777)


# Het tijdelijke bestand naast een bestaand bestand: alleen voor de login leesbaar tot de rechten van het oude erop
# staan (anders staat de nieuwe inhoud van een geheim 0600-bestand even leesbaar voor iedereen).
PRIVATE = asyncssh.SFTPAttrs(permissions=0o600)


async def _replace(sftp: asyncssh.SFTPClient, tmp: str, final: str) -> None:
    """tmp wordt final, in één keer (posix-rename van OpenSSH); kan de server dat niet, eerst het oude weg."""
    try:
        await sftp.posix_rename(tmp, final)
    except asyncssh.SFTPOpUnsupported:
        with contextlib.suppress(asyncssh.SFTPNoSuchFile):
            await sftp.remove(final)
        await sftp.rename(tmp, final)


async def write_text(sftp: asyncssh.SFTPClient, path: str, text: str, eol: str, mtime: int | None,
                     size: int | None, force: bool, host: str) -> dict:
    data = (text.replace("\r\n", "\n").replace("\n", "\r\n") if eol == "crlf" else text).encode("utf-8")
    if len(data) > EDIT_MAX:
        raise HTTPException(413, "Te groot om hier te bewaren (meer dan 1 MB)")
    if mtime is None:
        # Nieuw bestand.
        if await lstat_or_none(sftp, path) is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{txt(posixpath.basename(path))} bestaat al")
        async with sftp.open(path, "xb") as f:
            await f.write(data)
        a = await sftp.stat(path)
        return {"mtime": a.mtime, "size": a.size or 0}
    # Een symlink: het bestand waar hij naar wijst.
    final = await sftp.realpath(path)
    a = await sftp.stat(final)
    if kind(a.permissions) != "file":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Geen gewoon bestand")
    if not force and (a.mtime != mtime or (a.size or 0) != size):
        raise HTTPException(status.HTTP_409_CONFLICT, f"Het bestand is intussen gewijzigd op {host}")
    tmp = posixpath.join(posixpath.dirname(final), _part_name(posixpath.basename(final)))
    try:
        f = await sftp.open(tmp, "xb", PRIVATE)
    except asyncssh.SFTPPermissionDenied:
        # Geen schrijfrecht in de map (wel op het bestand): dan rechtstreeks in het bestand.
        async with sftp.open(final, "wb") as f:
            await f.write(data)
    else:
        try:
            async with f:
                await f.write(data)
            await _keep_attrs(sftp, tmp, a)
            await _replace(sftp, tmp, final)
        except BaseException:
            with contextlib.suppress(OSError, asyncssh.Error):
                await sftp.remove(tmp)
            raise
    a = await sftp.stat(final)
    return {"mtime": a.mtime, "size": a.size or 0}


# --- Uploaden ---------------------------------------------------------------------------------------------------

async def upload_start(s: FileSession, sftp: asyncssh.SFTPClient, base: str, rel: str, size: int,
                       mtime: float | None, overwrite: bool, chunk: int | None = None) -> dict:
    parts = check_rel(rel)
    target_dir = posixpath.join(base, *parts[:-1])
    made = None
    if parts[:-1] and await lstat_or_none(sftp, target_dir) is None:
        # Een map uploaden: de bovenste map die er nog niet was, voor het auditlog.
        for i in range(1, len(parts)):
            made = posixpath.join(base, *parts[:i])
            if await lstat_or_none(sftp, made) is None:
                break
        await sftp.makedirs(target_dir, exist_ok=True)
    final = posixpath.join(target_dir, parts[-1])
    old = await lstat_or_none(sftp, final)
    if old is not None and kind(old.permissions) == "link":
        # Een symlink: naar het bestand waar hij naar wijst (zoals cp), niet de link vervangen.
        try:
            final = await sftp.realpath(final)
            old = await sftp.stat(final)
        except asyncssh.SFTPError:
            raise HTTPException(status.HTTP_409_CONFLICT, f"{txt(rel)} is een symlink die nergens naar wijst")
        target_dir = posixpath.dirname(final)
    if old is not None:
        if kind(old.permissions) != "file":
            raise HTTPException(status.HTTP_409_CONFLICT, f"Er staat al een map of iets anders met de naam {txt(rel)}")
        if not overwrite:
            return {"exists": {"size": old.size or 0, "mtime": old.mtime}}
    with contextlib.suppress(asyncssh.SFTPError):
        v = await sftp.statvfs(target_dir)
        free = v.bavail * (v.frsize or v.bsize)
        if size > free:
            raise HTTPException(status.HTTP_507_INSUFFICIENT_STORAGE,
                                f"Niet genoeg plaats op {s.name}: {size} bytes nodig, {free} vrij")
    tmp = posixpath.join(target_dir, _part_name(posixpath.basename(final)))
    chunk = min(CHUNK, max(MIN_CHUNK, chunk)) if chunk else CHUNK
    u = Upload(id=secrets.token_urlsafe(12), final=final, tmp=tmp, size=size, chunk=chunk, chunks=-(-size // chunk),
               overwrite=old is not None, mtime=mtime, old=old, rel=rel)
    u.file = await sftp.open(tmp, "xb", PRIVATE if old is not None else asyncssh.SFTPAttrs())
    s.uploads[u.id] = u
    return {"id": u.id, "chunks": u.chunks, "chunk": u.chunk, "made": made}


async def upload_chunk(s: FileSession, sftp: asyncssh.SFTPClient, u: Upload, index: int, data: bytes) -> dict:
    if not 0 <= index < u.chunks:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Dat stuk hoort niet bij deze upload")
    want = u.chunk if index < u.chunks - 1 else u.size - u.chunk * (u.chunks - 1)
    if len(data) != want:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, f"Stuk {index} is {len(data)} bytes, verwacht {want}")
    u.used = time.monotonic()
    if index not in u.got:
        async with u.lock:
            if u.file is None:
                # Na een nieuwe verbinding: verder schrijven in hetzelfde tijdelijke bestand.
                u.file = await sftp.open(u.tmp, "r+b")
        await u.file.write(data, index * u.chunk)
        u.got.add(index)
    return {"got": len(u.got), "chunks": u.chunks}


async def upload_finish(s: FileSession, sftp: asyncssh.SFTPClient, u: Upload) -> dict:
    async with u.lock:
        if len(u.got) != u.chunks:
            raise HTTPException(status.HTTP_409_CONFLICT, f"Nog niet alles ontvangen ({len(u.got)} van {u.chunks})")
        s.uploads.pop(u.id, None)
        try:
            if u.file is not None:
                f, u.file = u.file, None
                await f.close()
            elif u.chunks == 0 and await lstat_or_none(sftp, u.tmp) is None:
                await (await sftp.open(u.tmp, "xb", PRIVATE if u.old is not None else asyncssh.SFTPAttrs())).close()
            await _keep_attrs(sftp, u.tmp, u.old)
            if u.mtime is not None:
                await sftp.utime(u.tmp, (u.mtime, u.mtime))
            if u.overwrite:
                await _replace(sftp, u.tmp, u.final)
            else:
                if await lstat_or_none(sftp, u.final) is not None:
                    raise HTTPException(status.HTTP_409_CONFLICT,
                                        f"Er staat intussen een {txt(u.rel)}: probeer opnieuw")
                await sftp.rename(u.tmp, u.final)
        except BaseException:
            await _remove_part(s, u)
            raise
        a = await sftp.lstat(u.final)
    return entry(posixpath.basename(u.final), a)


# --- Verwijderen -------------------------------------------------------------------------------------------------

async def remove_tree(sftp: asyncssh.SFTPClient, path: str, removed: list[int]) -> None:
    """Een map met alles erin weg. Niet sftp.rmtree: die weigert namen met een backslash (systemd-units) en loopt na
    een fout nog door op de achtergrond. Hier stopt het bij de eerste fout; removed[0] telt wat al weg is."""
    names = [n for n in await sftp.readdir(path) if n.filename not in (".", "..")]
    files = []
    for n in names:
        p = posixpath.join(path, n.filename)
        if kind(n.attrs.permissions) == "dir":
            await remove_tree(sftp, p, removed)
        else:
            files.append(p)
    for i in range(0, len(files), 32):
        # Een paar tegelijk (sneller over een trage lijn), en altijd wachten tot ze allemaal klaar zijn.
        done = await asyncio.gather(*(sftp.remove(p) for p in files[i:i + 32]), return_exceptions=True)
        removed[0] += sum(1 for r in done if not isinstance(r, BaseException))
        if err := next((r for r in done if isinstance(r, BaseException)), None):
            raise err
    await sftp.rmdir(path)
    removed[0] += 1


# --- Downloaden -------------------------------------------------------------------------------------------------

def add_download(d: Download) -> str:
    token = secrets.token_urlsafe(24)
    DOWNLOADS[token] = d
    return token


async def file_stream(s: FileSession, f: asyncssh.SFTPClientFile, size: int) -> AsyncIterator[bytes]:
    """Het (al geopende) bestand in stukken, tot de grootte van bij het begin (wat erna bijkomt, valt erbuiten). Een
    leesfout breekt de download af: de browser ziet dat er minder kwam dan Content-Length."""
    off = 0
    with working(s):
        try:
            while off < size:
                data = await f.read(min(READ_BLOCK, size - off), off)
                if not data:
                    break
                off += len(data)
                s.touch()
                yield data
        finally:
            with contextlib.suppress(OSError, asyncssh.Error):
                await f.close()


class _Sink:
    """Waar zipfile naartoe schrijft; de download haalt telkens op wat klaarstaat."""

    def __init__(self) -> None:
        self.parts: list[bytes] = []

    def write(self, b) -> int:
        self.parts.append(bytes(b))
        return len(b)

    def flush(self) -> None:
        pass

    def take(self) -> bytes:
        out = b"".join(self.parts)
        self.parts.clear()
        return out


def _zip_time(mtime: float | None) -> tuple:
    t = time.localtime(mtime or 0)
    if t.tm_year < 1980:
        return (1980, 1, 1, 0, 0, 0)
    return tuple(t[:6]) if t.tm_year <= 2107 else (2107, 12, 31, 23, 59, 58)


class _Skipped(list):
    """NIET-MEEGENOMEN.txt, met een grens: daarna alleen nog tellen."""

    more = 0

    def append(self, line: str) -> None:
        if len(self) < SKIPPED_MAX:
            super().append(line)
        else:
            self.more += 1


async def _walk(sftp: asyncssh.SFTPClient, full: str, arc: str, skipped: list[str]):
    """(soort, pad, naam in de zip, attrs) van alles onder een map. Symlinks naar mappen volgen we niet."""
    try:
        names = await sftp.readdir(full)
    except LOST:
        raise
    except asyncssh.SFTPError as e:
        skipped.append(f"{arc}/  (map niet leesbaar: {e.reason or 'Failure'})")
        return
    for n in sorted(names, key=lambda x: x.filename):
        if n.filename in (".", ".."):
            continue
        p, a = posixpath.join(full, n.filename), f"{arc}/{txt(n.filename)}"
        k = kind(n.attrs.permissions)
        if k == "link":
            try:
                t = await sftp.stat(p)
            except LOST:
                raise
            except asyncssh.SFTPError:
                skipped.append(f"{a}  (symlink die nergens naar wijst)")
                continue
            if kind(t.permissions) != "file":
                skipped.append(f"{a}  (symlink naar {'een map' if kind(t.permissions) == 'dir' else 'iets anders'})")
                continue
            k, n.attrs = "file", t
        if k == "dir":
            yield "dir", p, a, n.attrs
            async for x in _walk(sftp, p, a, skipped):
                yield x
        elif k == "file":
            yield "file", p, a, n.attrs
        else:
            skipped.append(f"{a}  (geen gewoon bestand)")


async def zip_stream(s: FileSession, sftp: asyncssh.SFTPClient, base: str, names: list[str]) -> AsyncIterator[bytes]:
    with working(s):
        async with contextlib.aclosing(_zip(s, sftp, base, names)) as parts:
            async for out in parts:
                yield out


async def _add(zf: zipfile.ZipFile, sink: _Sink, s: FileSession, sftp: asyncssh.SFTPClient, k: str, p: str, arc: str,
               a: asyncssh.SFTPAttrs, skipped: list[str]) -> AsyncIterator[bytes]:
    """Eén map of bestand in de zip, en wat er al klaarstaat voor de browser."""
    s.touch()
    if k == "dir":
        zi = zipfile.ZipInfo(arc + "/", _zip_time(a.mtime))
        zi.external_attr = ((a.permissions or 0o40755) & 0xFFFF) << 16 | 0x10
        zi.file_size = zi.compress_size = zi.CRC = 0
        zf.mkdir(zi)
        yield sink.take()
        return
    zi = zipfile.ZipInfo(arc, _zip_time(a.mtime))
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.external_attr = ((a.permissions or 0o100644) & 0xFFFF) << 16
    try:
        f = await sftp.open(p, "rb")
    except LOST:
        raise
    except asyncssh.SFTPError as e:
        skipped.append(f"{arc}  ({e.reason or 'niet leesbaar'})")
        return
    off = 0
    try:
        # Meer dan 1 GiB: zip64 (het bestand kan groeien terwijl we lezen).
        w = zf.open(zi, "w", force_zip64=(a.size or 0) > 1 << 30)
        try:
            while True:
                try:
                    data = await f.read(READ_BLOCK, off)
                except LOST:
                    raise
                except asyncssh.SFTPError as e:
                    skipped.append(f"{arc}  (onvolledig: lezen stopte na {off} bytes, {e.reason or 'Failure'})")
                    break
                if not data:
                    break
                off += len(data)
                # Inpakken in een thread: de API blijft intussen antwoorden.
                await asyncio.to_thread(w.write, data)
                s.touch()
                if out := sink.take():
                    yield out
        finally:
            await asyncio.to_thread(w.close)
    finally:
        with contextlib.suppress(OSError, asyncssh.Error):
            await f.close()
    if out := sink.take():
        yield out


async def _zip(s: FileSession, sftp: asyncssh.SFTPClient, base: str, names: list[str]) -> AsyncIterator[bytes]:
    sink = _Sink()
    zf = zipfile.ZipFile(sink, "w", zipfile.ZIP_DEFLATED, compresslevel=1)
    skipped = _Skipped()
    count = 0

    async def items():
        for name in names:
            p = posixpath.join(base, name)
            try:
                a = await sftp.stat(p)
            except LOST:
                raise
            except asyncssh.SFTPError as e:
                skipped.append(f"{txt(name)}  ({e.reason or 'niet leesbaar'})")
                continue
            if kind(a.permissions) == "dir":
                yield "dir", p, txt(name), a
                async for x in _walk(sftp, p, txt(name), skipped):
                    yield x
            elif kind(a.permissions) == "file":
                yield "file", p, txt(name), a
            else:
                skipped.append(f"{txt(name)}  (geen gewoon bestand)")

    async with contextlib.aclosing(items()) as walk:
        async for x in walk:
            count += 1
            if count > ZIP_MAX:
                list.append(skipped, f"... en de rest: een zip heeft hier hoogstens {ZIP_MAX} items. Download de "
                            "mappen apart, of maak de zip op de host zelf (tar of zip in de terminal).")
                break
            async with contextlib.aclosing(_add(zf, sink, s, sftp, *x, skipped)) as parts:
                async for out in parts:
                    yield out
    if skipped:
        more = f"\n... en nog {skipped.more}\n" if skipped.more else ""
        zf.writestr("NIET-MEEGENOMEN.txt", "Deze bestanden en mappen zitten niet in de zip:\n\n"
                    + "\n".join(skipped) + "\n" + more)
    zf.close()
    if out := sink.take():
        yield out
