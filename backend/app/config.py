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
    # "auto": Secure-cookie alleen als het verzoek via HTTPS binnenkwam (achter NPM altijd), zodat
    # testen op http://IP ook werkt. "true" of "false" dwingt het af.
    cookie_secure: str = "auto"
    session_days: int = 14
    # Na zoveel minuten moet je voor gevoelige acties opnieuw bevestigen.
    reauth_minutes: int = 15
    login_max_failures: int = 5
    login_window_minutes: int = 15
    revisions_keep: int = 200
    site_name: str = "homepage"
    # Syslog-ontvanger (fase 6).
    syslog_bind: str = "0.0.0.0"
    syslog_port: int = 514
    # Alleen berichten van deze netwerken aannemen (komma-gescheiden).
    syslog_allow: str = "192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.0/8"
    # Zonder TimescaleDB: zo lang bewaren. Met TimescaleDB geldt het beleid uit de migratie (30 dagen).
    syslog_keep_days: int = 30
    # IP van deze container zoals de andere machines het zien; install.sh vult dit in.
    syslog_target: str = ""


@lru_cache
def get_settings() -> Settings:
    return Settings()
