from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, SmallInteger, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql.expression import false as sa_false
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# JSONB op PostgreSQL, gewone JSON elders (tests draaien op SQLite).
Json = JSON().with_variant(JSONB(), "postgresql")


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    type_annotation_map = {datetime: DateTime(timezone=True)}


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    # Versleuteld met de Fernet-sleutel.
    totp_secret: Mapped[str | None] = mapped_column(Text)
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_login_at: Mapped[datetime | None]
    last_login_ip: Mapped[str | None] = mapped_column(String(64))


class Session(Base):
    __tablename__ = "sessions"

    # sha256 van het cookie-token; het token zelf staat nergens opgeslagen.
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    mfa_ok: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    expires_at: Mapped[datetime]
    # Laatste moment waarop wachtwoord of TOTP werd ingegeven.
    auth_at: Mapped[datetime] = mapped_column(default=utcnow)
    ip: Mapped[str | None] = mapped_column(String(64))
    user_agent: Mapped[str | None] = mapped_column(String(255))
    # Landcode van Cloudflare (CF-IPCountry), alleen als het verzoek via NPM binnenkwam.
    country: Mapped[str | None] = mapped_column(String(2))
    # Hoogstens om de 5 minuten bijgewerkt, om niet bij elk verzoek te schrijven.
    last_seen_at: Mapped[datetime | None]

    user: Mapped[User] = relationship(lazy="joined")


class Page(Base):
    __tablename__ = "pages"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    icon: Mapped[str | None] = mapped_column(String(255))
    position: Mapped[int] = mapped_column(Integer, default=0)

    groups: Mapped[list["Group"]] = relationship(
        back_populates="page", cascade="all, delete-orphan", order_by="Group.position"
    )


class Group(Base):
    __tablename__ = "groups"

    id: Mapped[int] = mapped_column(primary_key=True)
    page_id: Mapped[int] = mapped_column(ForeignKey("pages.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    icon: Mapped[str | None] = mapped_column(String(255))
    position: Mapped[int] = mapped_column(Integer, default=0)
    collapsed: Mapped[bool] = mapped_column(Boolean, default=False)

    page: Mapped[Page] = relationship(back_populates="groups")
    services: Mapped[list["Service"]] = relationship(
        back_populates="group", cascade="all, delete-orphan", order_by="Service.position"
    )


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(primary_key=True)
    group_id: Mapped[int] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    description: Mapped[str | None] = mapped_column(String(255))
    url: Mapped[str | None] = mapped_column(String(500))
    icon: Mapped[str | None] = mapped_column(String(500))
    position: Mapped[int] = mapped_column(Integer, default=0)
    # Integratie-type (bv. "proxmox", "adguard"); "link" = gewone snelkoppeling.
    type: Mapped[str] = mapped_column(String(40), default="link")
    # Instellingen voor monitoring (fase 3): {"type": "http", "target": ..., "interval": 60}
    check: Mapped[dict] = mapped_column(Json, default=dict)
    # Niet-geheime instellingen van de integratie.
    config: Mapped[dict] = mapped_column(Json, default=dict)
    # Versleutelde JSON met API-sleutels, wachtwoorden, ... Komt nooit in de browser.
    secrets: Mapped[str | None] = mapped_column(Text)
    # Draait op / hangt af van (bv. de Proxmox-node). Valt die uit, dan één melding voor allemaal.
    parent_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), index=True)
    # Onderhoud: geen meldingen en telt niet mee voor de uptime. Geldt ook voor wat ervan afhangt.
    maintenance_until: Mapped[datetime | None]
    # Eigen notities in Markdown (wachtwoordloze uitleg, poorten, hoe herstellen, ...).
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    group: Mapped[Group] = relationship(back_populates="services")


class Revision(Base):
    __tablename__ = "revisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    summary: Mapped[str] = mapped_column(String(255))
    snapshot: Mapped[dict] = mapped_column(Json)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(String(64))
    detail: Mapped[dict] = mapped_column(Json, default=dict)
    ip: Mapped[str | None] = mapped_column(String(64))


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    # info | ok | warn | err
    level: Mapped[str] = mapped_column(String(8), default="info")
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(40), default="system")
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"))
    read_at: Mapped[datetime | None]


class CheckResult(Base):
    """Eén uitgevoerde check. Op PostgreSQL met TimescaleDB is dit een hypertable."""

    __tablename__ = "check_results"

    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), primary_key=True)
    ts: Mapped[datetime] = mapped_column(primary_key=True, default=utcnow, index=True)
    ok: Mapped[bool] = mapped_column(Boolean)
    latency_ms: Mapped[float | None]
    status_code: Mapped[int | None]
    error: Mapped[str | None] = mapped_column(String(300))
    # Tijdens onderhoud: bewaard, maar niet meegeteld in de uptime.
    maintenance: Mapped[bool | None] = mapped_column(Boolean, default=False, server_default=sa_false())


class ServiceState(Base):
    """Huidige toestand per service, bijgewerkt door de worker."""

    __tablename__ = "service_state"

    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), primary_key=True)
    # up | down | unknown
    status: Mapped[str] = mapped_column(String(8), default="unknown")
    since: Mapped[datetime] = mapped_column(default=utcnow)
    last_check: Mapped[datetime | None]
    latency_ms: Mapped[float | None]
    fail_count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(300))
    # Down zonder eigen melding, omdat iets waarvan hij afhangt al down was.
    quiet: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    cert_expires_at: Mapped[datetime | None]
    # Laatst gemelde drempel voor het certificaat (14 of 3 dagen), 0 = nog niets gemeld.
    cert_notified: Mapped[int] = mapped_column(SmallInteger, default=0, server_default="0")


class SshKey(Base):
    """Sleutelpaar voor de terminal. De private sleutel staat versleuteld in de database."""

    __tablename__ = "ssh_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    public_key: Mapped[str] = mapped_column(Text)
    private_key: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class SshHost(Base):
    __tablename__ = "ssh_hosts"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    host: Mapped[str] = mapped_column(String(255))
    port: Mapped[int] = mapped_column(Integer, default=22)
    username: Mapped[str] = mapped_column(String(64), default="root")
    key_id: Mapped[int | None] = mapped_column(ForeignKey("ssh_keys.id", ondelete="SET NULL"))
    # Versleuteld; alleen als er geen sleutel gebruikt wordt.
    password: Mapped[str | None] = mapped_column(Text)
    # Publieke hostsleutel (OpenSSH-formaat), vastgelegd bij de eerste verbinding na bevestiging.
    host_key: Mapped[str | None] = mapped_column(Text)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), index=True)
    position: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_used_at: Mapped[datetime | None]
    # Updates opvolgen: "" = niet, "host" = deze machine, "cts" = deze machine en (Proxmox-node) al zijn containers.
    updates: Mapped[str] = mapped_column(String(8), default="", server_default="")
    # Map in de lijst (bv. de Proxmox-node), leeg = bovenaan.
    folder: Mapped[str] = mapped_column(String(80), default="", server_default="")
    # Herkomst bij automatisch ophalen uit Proxmox, bv. "pve:3:lxc/105"; None = zelf toegevoegd.
    source: Mapped[str | None] = mapped_column(String(80), unique=True, index=True)


class LogEntry(Base):
    """Eén syslog-regel. Op PostgreSQL met TimescaleDB is dit een hypertable op ts."""

    __tablename__ = "log_entries"
    __table_args__ = (Index("ix_log_entries_host_ts", "host", "ts"),)

    id: Mapped[int] = mapped_column(BigInteger().with_variant(Integer, "sqlite"), primary_key=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    host: Mapped[str] = mapped_column(String(255))
    source_ip: Mapped[str | None] = mapped_column(String(64))
    facility: Mapped[int] = mapped_column(SmallInteger, default=1)
    # 0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5 notice, 6 info, 7 debug
    severity: Mapped[int] = mapped_column(SmallInteger, default=6)
    app: Mapped[str | None] = mapped_column(String(64))
    msg: Mapped[str] = mapped_column(Text)


class LogRule(Base):
    """Melding als een logregel overeenkomt (bv. 'Out of memory' of alles vanaf 'crit')."""

    __tablename__ = "log_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    pattern: Mapped[str | None] = mapped_column(String(500))
    host: Mapped[str | None] = mapped_column(String(255))
    # Alleen regels met severity <= deze waarde (0 = emerg ... 7 = debug).
    max_severity: Mapped[int] = mapped_column(SmallInteger, default=7)
    level: Mapped[str] = mapped_column(String(8), default="warn")
    cooldown_minutes: Mapped[int] = mapped_column(Integer, default=10)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class AppState(Base):
    """Kleine sleutel-waarde-opslag voor achtergrondtaken (bv. welke NPM-hosts al gezien zijn)."""

    __tablename__ = "app_state"

    key: Mapped[str] = mapped_column(String(100), primary_key=True)
    value: Mapped[dict] = mapped_column(Json, default=dict)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)


class Metric(Base):
    """Gebruik van nodes, VM's/CT's en opslag, elke 10 minuten uit Proxmox. Met TimescaleDB een hypertable."""

    __tablename__ = "metrics"

    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), primary_key=True)
    # node | guest | storage | power
    kind: Mapped[str] = mapped_column(String(8), primary_key=True)
    # node: "pve50" · guest: "pve50/101" · storage: "pve50/local-lvm" of gedeeld "ceph"
    name: Mapped[str] = mapped_column(String(120), primary_key=True)
    ts: Mapped[datetime] = mapped_column(primary_key=True, default=utcnow, index=True)
    label: Mapped[str | None] = mapped_column(String(120))
    cpu: Mapped[float | None] = mapped_column(Float)
    mem: Mapped[int | None] = mapped_column(BigInteger)
    mem_total: Mapped[int | None] = mapped_column(BigInteger)
    disk: Mapped[int | None] = mapped_column(BigInteger)
    disk_total: Mapped[int | None] = mapped_column(BigInteger)
    # Stroomverbruik in watt (kind "power", uit Home Assistant).
    watts: Mapped[float | None] = mapped_column(Float)


class Event(Base):
    """Eén gebeurtenis voor de tijdlijn: storing, herstart, back-up, updates, ... Blijft een jaar bewaard,
    ook als de melding zelf al gewist is."""

    __tablename__ = "events"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    # storing | herstart | backup | updates | capaciteit | log | netwerk | melding
    kind: Mapped[str] = mapped_column(String(16), index=True)
    level: Mapped[str] = mapped_column(String(8), default="info")
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str | None] = mapped_column(Text)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), index=True)
    # Extra gegevens, bv. {"down_s": 340} bij een herstelde storing.
    data: Mapped[dict] = mapped_column(Json, default=dict)
