from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Instellingen, gelezen uit omgevingsvariabelen met prefix HOMEPAGE_
    (in productie uit /etc/homepage/homepage.env)."""

    model_config = SettingsConfigDict(env_prefix="HOMEPAGE_", env_file=None)

    database_url: str = "postgresql+asyncpg://homepage@/homepage"
    # Fernet-sleutel voor secrets (API-sleutels, TOTP, later SSH-sleutels).
    secret_key_file: Path = Path("/etc/homepage/secret.key")
    # Eenmalige code om het eerste account aan te maken.
    setup_token_file: Path = Path("/etc/homepage/setup-token")
    cookie_secure: bool = True
    session_days: int = 14
    # Na zoveel minuten moet je voor gevoelige acties opnieuw bevestigen.
    reauth_minutes: int = 15
    login_max_failures: int = 5
    login_window_minutes: int = 15
    revisions_keep: int = 200
    site_name: str = "homepage"


@lru_cache
def get_settings() -> Settings:
    return Settings()
