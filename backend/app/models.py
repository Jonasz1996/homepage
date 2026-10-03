from datetime import datetime, timezone

from sqlalchemy import JSON, Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
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
