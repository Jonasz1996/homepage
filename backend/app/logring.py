"""De laatste logregels van elk proces in het geheugen, voor de diagnose-export (knop onder !).

De gebruiker homepage mag journalctl niet lezen (hij zit niet in systemd-journal of adm), dus houdt elk proces zelf
zijn laatste regels bij: de API, de worker en de syslog-ontvanger. Elke regel wordt meteen gemaskeerd met de
patronen uit masking.py (tokens, wachtwoorden in urls, headers, ...). De geheimen die het dashboard zelf bewaart,
maskeert de diagnose pas bij het downloaden: hier is geen database.

De worker (bij zijn hartslag) en de syslog-ontvanger zetten hun regels elke minuut in AppState "logs:<rol>", alleen
als er iets bijkwam. De API leest zijn eigen ring rechtstreeks.
"""

import asyncio
import logging
import os
import re
import sys
from collections import deque
from collections.abc import Sequence
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from .masking import cut_after, cut_before, mask
from .models import AppState

log = logging.getLogger("homepage.logring")

KEEP = 500
# Zoveel regels gaan naar de database en in de diagnose.
EXPORT = 200
# Een traceback kan lang zijn; de rest staat nog in journald.
MAX_MSG = 4000
FLUSH_EVERY = 60
FORMAT = "%(levelname)s %(name)s: %(message)s"
# Op INFO loggen deze elke aanvraag, met de url (en dus soms ?apikey=...) of de gebruiker waarmee SSH inlogt.
QUIET = ("httpx", "asyncssh")


def state_key(role: str) -> str:
    return f"logs:{role}"


# Een stuk tekst zonder spatie dat zo lang is, is een blob (base64, compacte JSON, ...). Het patroon voor key=value in
# masking.py doet daar kwadratisch lang over (seconden voor een paar duizend tekens), en een geheim erin herkent het
# toch niet: de blob gaat eruit, alleen zijn lengte blijft.
LONG = re.compile(r"\S{500,}")
_UPTO_SPACE = re.compile(r"(?s).*\s")
_WORD = re.compile(r"\S*")


def after(text: str, i: int, known: Sequence[str] = ()) -> str:
    """text vanaf positie i, zonder een stuk van een geheim aan de snede (dat valt er helemaal af) en zonder een half
    woord: een afgekapt token herkent het maskeren niet meer."""
    j = cut_after(text, i, known)
    if j and not text[j - 1].isspace():
        # Het halve woord gaat weg. Was dat (een stuk van) de naam van een geheim, dan de waarde ook.
        j = cut_after(text, _WORD.match(text, j).end(), known)
    return text[j:]


def cut(text: str, n: int, known: Sequence[str] = ()) -> str:
    """Het begin en (vooral, bij een traceback) het einde, samen hoogstens n tekens. Een geheim dat over een snede
    loopt valt er helemaal af: zonder zijn naam ("password:", "Bearer ") herkent het maskeren de rest niet meer.
    known: bekende geheimen die ook niet half mogen blijven staan."""
    if len(text) <= n:
        return text
    k = n // 4
    head = _UPTO_SPACE.match(text[:cut_before(text, k, known)])
    tail = after(text, len(text) - (n - k - 3), known)
    return f"{head.group(0).rstrip() if head else ''} … {tail.lstrip()}"


def bound(text: str, n: int, known: Sequence[str] = ()) -> str:
    """Klaar om te maskeren: elke blob vervangen door zijn lengte, en hoogstens n tekens."""
    return cut(LONG.sub(lambda m: f"[{len(m.group())} tekens]", text), n, known)


class RingHandler(logging.Handler):
    def __init__(self, size: int = KEEP) -> None:
        super().__init__(logging.INFO)
        self.lines: deque[dict] = deque(maxlen=size)
        # Hoeveel regels er ooit bijkwamen: zo weet flush() of er iets nieuws is.
        self.total = 0
        # Alleen de tekst, met de traceback erachter; tijd, niveau en naam staan apart.
        self.setFormatter(logging.Formatter("%(message)s"))

    def emit(self, record: logging.LogRecord) -> None:
        try:
            # Begrensd, dan gemaskeerd, dan afgekapt: zo blijft het maskeren snel en komt er geen half geheim in.
            # Zonder NUL: PostgreSQL weigert \u0000 in JSONB, en dan zou flush() blijven mislukken.
            msg = cut(mask(bound(self.format(record).replace("\x00", ""), 3 * MAX_MSG)), MAX_MSG)
            ts = datetime.fromtimestamp(record.created, timezone.utc).isoformat(timespec="milliseconds")
            self.lines.append({"ts": ts, "level": record.levelname, "name": record.name, "msg": msg})
            self.total += 1
        except Exception:  # noqa: BLE001 - loggen mag nooit zelf een fout geven
            self.handleError(record)

    def tail(self, n: int = EXPORT) -> list[dict]:
        return list(self.lines)[-n:]


class _Stderr(logging.StreamHandler):
    """Naar stderr (journald), zoals logging.lastResort: altijd naar wat sys.stderr nu is."""

    def __init__(self) -> None:
        logging.Handler.__init__(self)

    @property
    def stream(self):
        return sys.stderr


_ring: RingHandler | None = None
_started: str | None = None
_flushed: dict[str, int] = {}


def install(role: str) -> RingHandler:
    """Bij het starten van een proces (api, worker of syslog). Twee keer oproepen kan geen kwaad.

    De API zelf heeft geen logconfiguratie: uvicorn regelt alleen zijn eigen loggers, en wat homepage.* meldt kwam
    in journald via logging.lastResort. Die valt weg zodra de root-logger een handler heeft, dus krijgt de API hier
    een eigen handler naar stderr. De fouten bij een verzoek (een traceback van "uvicorn.error") gaan niet langs de
    root-logger: de ring hangt daar apart aan."""
    global _ring, _started
    root = logging.getLogger()
    if _ring is None:
        _ring = RingHandler()
        _started = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    if _ring not in root.handlers:
        root.addHandler(_ring)
    if root.getEffectiveLevel() > logging.INFO:
        root.setLevel(logging.INFO)
    for name in QUIET:
        logging.getLogger(name).setLevel(logging.WARNING)
    if role == "api":
        if not any(isinstance(h, _Stderr) for h in root.handlers):
            h = _Stderr()
            h.setFormatter(logging.Formatter(FORMAT))
            root.addHandler(h)
        uv = logging.getLogger("uvicorn.error")
        # Alleen als uvicorn zijn loggers afschermt (zoals in productie); anders komt elke regel er twee keer in.
        if not logging.getLogger("uvicorn").propagate and _ring not in uv.handlers:
            uv.addHandler(_ring)
    return _ring


def lines(n: int = EXPORT) -> list[dict]:
    """De laatste regels van dit proces (leeg als install() niet liep, zoals in de tests)."""
    return _ring.tail(n) if _ring else []


def started() -> str | None:
    return _started


async def flush(db: AsyncSession, role: str) -> bool:
    """De laatste regels in AppState "logs:<rol>", alleen als er sinds de vorige keer iets bijkwam.
    Geeft terug of er iets te bewaren was; de oproeper commit."""
    if _ring is None or _ring.total == _flushed.get(role, 0):
        return False
    value = {"at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(), "pid": os.getpid(),
             "started": _started, "lines": _ring.tail()}
    st = await db.get(AppState, state_key(role))
    if st:
        st.value = value
    else:
        db.add(AppState(key=state_key(role), value=value))
    _flushed[role] = _ring.total
    return True


async def flush_loop(maker: async_sessionmaker, role: str, every: int = FLUSH_EVERY) -> None:
    """Voor een proces zonder hartslag (de syslog-ontvanger): elke minuut flush()."""
    while True:
        await asyncio.sleep(every)
        try:
            async with maker() as db:
                if await flush(db, role):
                    await db.commit()
        except Exception:  # noqa: BLE001 - de ontvanger moet blijven draaien
            log.exception("eigen logregels bewaren mislukt")
