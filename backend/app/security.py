import hashlib
import hmac
import json
import secrets
import time
from collections import defaultdict, deque
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


class LoginLimiter:
    """Telt mislukte logins per IP en per gebruikersnaam in een glijdend venster."""

    def __init__(self) -> None:
        self._fails: dict[str, deque[float]] = defaultdict(deque)

    def _prune(self, key: str, now: float) -> deque[float]:
        window = get_settings().login_window_minutes * 60
        q = self._fails[key]
        while q and q[0] < now - window:
            q.popleft()
        return q

    def blocked(self, *keys: str) -> bool:
        now = time.monotonic()
        limit = get_settings().login_max_failures
        return any(len(self._prune(k, now)) >= limit for k in keys)

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        for k in keys:
            self._prune(k, now).append(now)

    def reset(self, *keys: str) -> None:
        for k in keys:
            self._fails.pop(k, None)


limiter = LoginLimiter()
