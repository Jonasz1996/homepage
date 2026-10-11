import asyncio
import hashlib
import hmac
import json
import secrets
import time
from collections import deque
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from functools import lru_cache

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from cryptography.fernet import Fernet

from .config import get_settings

_hasher = PasswordHasher()
# Gebruikt bij een onbekende gebruikersnaam zodat het antwoord even lang duurt.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, InvalidHashError):
        return False


# argon2 rekent zo'n 70 ms met 64 MiB per wachtwoord. Niet op de event loop (die bedient ook de terminals en de rest
# van het dashboard), en in een eigen kleine pool: ook bij een aanval rekenen er hoogstens twee tegelijk.
_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="argon2")
# Zoveel wachtwoordcontroles mogen tegelijk wachten. Wie daarna komt, krijgt meteen "even te druk", zonder te rekenen.
MAX_PENDING = 8
# Bekende toestellen (zie DEVICE_COOKIE) mogen er nog zoveel bij: wie de wachtrij vult met verzoeken zonder geldig
# toestelcookie, houdt de eigenaar zo niet buiten. Elk toestel heeft zijn eigen strenge teller.
KNOWN_EXTRA = 4
_pending = 0


@contextmanager
def password_slot(known: bool = False) -> Iterator[bool]:
    """Een plaats in de wachtrij voor argon2 (False: vol). Neem ze vóór de eerste await, net als de limieten: dan
    kunnen verzoeken tegelijk niet allemaal dezelfde laatste vrije plaats zien. known: met een geldig toestelcookie."""
    global _pending
    if _pending >= MAX_PENDING + (KNOWN_EXTRA if known else 0):
        yield False
        return
    _pending += 1
    try:
        yield True
    finally:
        _pending -= 1


async def verify_password_async(password_hash: str | None, password: str) -> bool:
    return await asyncio.get_running_loop().run_in_executor(_pool, verify_password, password_hash, password)


async def hash_password_async(password: str) -> str:
    return await asyncio.get_running_loop().run_in_executor(_pool, hash_password, password)


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@lru_cache
def _fernet() -> Fernet:
    return Fernet(get_settings().secret_key_file.read_bytes().strip())


def encrypt(value: str) -> str:
    return _fernet().encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _fernet().decrypt(value.encode()).decode()


def encrypt_json(data: dict) -> str | None:
    return encrypt(json.dumps(data)) if data else None


def decrypt_json(value: str | None) -> dict:
    return json.loads(decrypt(value)) if value else {}


def check_setup_token(given: str) -> bool:
    path = get_settings().setup_token_file
    try:
        expected = path.read_text().strip()
    except OSError:
        return False
    return bool(expected) and hmac.compare_digest(expected, given.strip())


# --- Bekende toestellen -------------------------------------------------------------
# Na een login met 2FA krijgt het toestel een cookie voor een jaar. Daarop geldt de limiet per gebruikersnaam niet (die
# kan iedereen vullen met foute wachtwoorden), zie routers/auth.py. Wachtwoord en 2FA blijven nodig: het cookie kiest
# alleen welke teller geldt.
DEVICE_COOKIE = "hp_device"
DEVICE_DAYS = 365


def _device_bind(password_hash: str) -> str:
    """Hangt het toestelcookie aan het huidige wachtwoord: een nieuw wachtwoord (een nieuwe hash, met nieuw zout)
    maakt alle bekende toestellen weer onbekend."""
    return hashlib.sha256(b"hp_device\0" + password_hash.encode()).hexdigest()[:32]


def session_device(session_id: str) -> str:
    """Een vast toestel-ID voor een sessie zonder (geldig) toestelcookie: wie een sessie steelt en het cookie telkens
    wist, krijgt zo steeds hetzelfde toestel, met één strenge teller, en niet eindeloos nieuwe. Met "s:" ervoor (geen
    teken van token_urlsafe): bij de volgende echte login krijgt het toestel een eigen ID (from_session)."""
    return "s:" + hashlib.sha256(b"hp_device-sessie\0" + session_id.encode()).hexdigest()[:16]


def from_session(device: str | None) -> bool:
    """Komt dit toestel-ID van session_device? Wie dezelfde sessie heeft (ook wie ze stal), kan het ook krijgen."""
    return bool(device) and device.startswith("s:")


def device_token(user_id: int, username: str, password_hash: str, device: str | None = None) -> str:
    """Versleuteld en ondertekend met de Fernet-sleutel, zoals het state-cookie van Authentik."""
    return encrypt(json.dumps({"u": user_id, "n": username.lower(), "d": device or secrets.token_urlsafe(12),
                               "p": _device_bind(password_hash), "t": int(time.time())}))


def read_device(raw: str | None) -> dict | None:
    """Het toestelcookie, als het van ons komt en niet ouder is dan een jaar. Zonder database, dus vóór de eerste
    await te gebruiken. Of het nog bij de gebruiker en zijn huidige wachtwoord hoort, zegt device_ok."""
    if not raw or len(raw) > 2000:
        return None
    try:
        d = json.loads(_fernet().decrypt(raw.encode(), ttl=DEVICE_DAYS * 86400))
    except Exception:  # noqa: BLE001 - vervalst, verlopen of onleesbaar: gewoon een onbekend toestel
        return None
    if not (isinstance(d, dict) and all(isinstance(d.get(k), int) for k in "ut")
            and all(isinstance(d.get(k), str) for k in "ndp")):
        return None
    return d


def device_ok(dev: dict | None, user) -> bool:
    return bool(dev and user is not None and dev["u"] == user.id and dev["n"] == user.username.lower()
                and hmac.compare_digest(dev["p"], _device_bind(user.password_hash)))


class LoginLimiter:
    """Telt mislukte pogingen per sleutel (IP, gebruikersnaam, ...) in een glijdend venster."""

    # Boven zoveel sleutels wordt alles opgeruimd wat buiten het venster valt. Blijven het er te veel (een aanval met
    # telkens een ander IP of een andere naam), dan vallen de sleutels met de minste pogingen weg.
    MAX_KEYS = 10_000

    def __init__(self) -> None:
        self._fails: dict[str, deque[float]] = {}
        # Sleutel → tot wanneer ze dicht is, voor vergrendelingen die al gemeld zijn (zie newly_locked).
        self._locked: dict[str, float] = {}

    @staticmethod
    def _window() -> float:
        return get_settings().login_window_minutes * 60

    def _prune(self, key: str, now: float) -> int:
        q = self._fails.get(key)
        if q is None:
            return 0
        window = self._window()
        while q and q[0] < now - window:
            q.popleft()
        if not q:
            del self._fails[key]
        return len(q)

    def _sweep(self, now: float) -> None:
        for k in list(self._fails):
            self._prune(k, now)
        if len(self._fails) > self.MAX_KEYS * 3 // 4:
            # Tot de helft: zo komt het volgende opruimen pas na een paar duizend nieuwe sleutels.
            drop = sorted(self._fails, key=lambda k: (len(self._fails[k]), self._fails[k][-1]))
            for k in drop[:len(self._fails) - self.MAX_KEYS // 2]:
                del self._fails[k]
        window = self._window()
        self._locked = {k: t for k, t in self._locked.items() if t + window >= now}

    def blocked(self, *keys: str, limit: int | None = None) -> bool:
        now = time.monotonic()
        limit = limit or get_settings().login_max_failures
        return any(self._prune(k, now) >= limit for k in keys)

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        for k in keys:
            self._prune(k, now)
            self._fails.setdefault(k, deque()).append(now)
        if len(self._fails) > self.MAX_KEYS:
            self._sweep(now)

    def undo(self, *keys: str) -> None:
        """Een poging die vooraf als mislukt geteld werd, toch niet meetellen (het wachtwoord klopte)."""
        for k in keys:
            q = self._fails.get(k)
            if q:
                q.pop()
            if q is not None and not q:
                del self._fails[k]

    def reset(self, *keys: str) -> None:
        for k in keys:
            self._fails.pop(k, None)
            self._locked.pop(k, None)

    def clear(self) -> None:
        self._fails.clear()
        self._locked.clear()

    def locked_for(self, key: str, limit: int) -> float:
        """Hoeveel seconden de sleutel nog dicht is (0: open)."""
        now = time.monotonic()
        n = self._prune(key, now)
        return self._fails[key][n - limit] + self._window() - now if n >= limit else 0.0

    def newly_locked(self, key: str, limit: int) -> float:
        """Zoals locked_for, maar alleen de eerste keer per vergrendeling, om ze één keer te melden. Gaat de sleutel
        binnen een venster na het einde opnieuw dicht (een aanval die doorgaat), dan is het nog dezelfde."""
        secs = self.locked_for(key, limit)
        if not secs:
            return 0.0
        now = time.monotonic()
        prev = self._locked.get(key)
        self._locked[key] = max(prev or 0.0, now + secs)
        return 0.0 if prev is not None and now <= prev + self._window() else secs


# Per gebruikersnaam veel ruimer dan per IP: deze teller kan iedereen vullen met foute wachtwoorden. Is ze vol, dan
# moeten alleen nieuwe toestellen wachten; bekende toestellen tellen apart (zie DEVICE_COOKIE).
USER_FAILURE_FACTOR = 6


limiter = LoginLimiter()
