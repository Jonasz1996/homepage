from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Instellingen, gelezen uit omgevingsvariabelen met prefix HOMEPAGE_
    (in productie uit /etc/homepage/homepage.env)."""

    model_config = SettingsConfigDict(env_prefix="HOMEPAGE_", env_file=None)

    database_url: str = "postgresql+asyncpg://homepage@/homepage"
    # Maximaal aantal databaseverbindingen per proces. Samen ruim onder max_connections (100) van PostgreSQL, zodat
    # psql, pg_dump en de hersteltest er nog bij kunnen. Uitleg bij pool_max in db.py.
    db_pool_api: int = 20
    db_pool_worker: int = 40
    db_pool_syslog: int = 5
    # Een query die langer loopt dan zoveel seconden breekt PostgreSQL af (0 = geen limiet).
    db_statement_timeout: int = 60
    # Een transactie die zoveel seconden stilligt, sluit PostgreSQL af: een vangnet voor een taak die een
    # transactie vergeet af te sluiten (0 = geen limiet).
    db_idle_in_transaction_timeout: int = 900
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
    # Verlies van de syslog-ontvanger dat bij het stoppen niet meer in de database raakte (database weg), tot de
    # volgende start. De map maakt systemd aan (StateDirectory in homepage-syslog.service).
    syslog_state_file: Path = Path("/var/lib/homepage-syslog/verlies.json")
    # IP van Nginx Proxy Manager (install.sh vraagt het); voor de firewall-lijst in net.
    npm_ip: str = ""
    # Wat nginx rechtstreeks toelaat (install.sh schrijft het): alleen NPM, of het hele LAN (HOMEPAGE_LAN_OPEN=1).
    nginx_file: Path = Path("/etc/homepage/nginx")
    # Elke 5 minuten het publieke IP opvragen bij Cloudflare (1.1.1.1), melding als het verandert.
    public_ip_check: bool = True
    # Zelfcontrole: waar de dagelijkse pg_dump staat, en een gemounte map (NAS, PBS, USB) voor de kopie buiten de
    # container. De worker mag alleen in die map schrijven (ReadWritePaths in homepage-worker.service).
    backup_dir: Path = Path("/var/backups/homepage")
    # Welke versie er draait (install.sh schrijft het): voor "wat is er nieuw" en homepage-terugzetten.
    version_file: Path = Path("/etc/homepage/versie")
    offsite_dir: Path = Path("/mnt/homepage-backup")
    # Waar de worker de API bereikt, om te merken dat die niet meer antwoordt.
    api_url: str = "http://127.0.0.1:8000"
    # De API kijkt elke minuut of de worker leeft (en stuurt dan zelf de meldingen naar de gsm). Uit in de tests.
    watchdog: bool = True


@lru_cache
def get_settings() -> Settings:
    return Settings()
