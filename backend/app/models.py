from datetime import datetime, timezone

from sqlalchemy import JSON, BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, SmallInteger, String, Text, text
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
    # Laatst gebruikte TOTP-stap: dezelfde code mag maar één keer dienen.
    totp_last_step: Mapped[int | None] = mapped_column(BigInteger)
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
    # API uit API-beheer: adres, sleutels en eigen calls komen dan daarvandaan (zie integrations.build).
    api_id: Mapped[int | None] = mapped_column(ForeignKey("api_connections.id", ondelete="SET NULL"), index=True)
    # Wanneer de check opnieuw begon (ander type of interval, pauze, hervat): een push-check rekent vanaf dan.
    check_changed_at: Mapped[datetime | None] = mapped_column(default=utcnow)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    group: Mapped[Group] = relationship(back_populates="services")
    # Altijd meteen mee geladen: build() heeft ze nodig, ook nadat de sessie dicht is.
    api: Mapped["ApiConnection | None"] = relationship(lazy="selectin")


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
    __table_args__ = (
        # Het aantal ongelezen meldingen (badge) wordt bij elke poll geteld: een kleine index op alleen die rijen.
        Index("ix_notifications_unread", "id", postgresql_where=text("read_at IS NULL"),
              sqlite_where=text("read_at IS NULL")),
        # Nog niet naar de gsm gestuurd (web push): de worker zoekt alleen die rijen.
        Index("ix_notifications_unpushed", "id", postgresql_where=text("pushed_at IS NULL"),
              sqlite_where=text("pushed_at IS NULL")),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    # info | ok | warn | err
    level: Mapped[str] = mapped_column(String(8), default="info")
    title: Mapped[str] = mapped_column(String(200))
    body: Mapped[str | None] = mapped_column(Text)
    source: Mapped[str] = mapped_column(String(40), default="system")
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"), index=True)
    read_at: Mapped[datetime | None]
    # Wanneer de worker hem naar de gsm('s) stuurde (web push); meteen gezet als hij daar niet heen moet.
    pushed_at: Mapped[datetime | None]
    # Over welke storing dit gaat (bv. "svc12" voor up/down van een tegel): nieuwer nieuws over dezelfde storing
    # vervangt op de gsm het oudere. Leeg: een losse melding.
    push_key: Mapped[str | None] = mapped_column(String(120))
    # Bij herstel (ok): het niveau van wat hij herstelt, zodat hij komt op elk toestel dat de storing kreeg.
    recovers: Mapped[str | None] = mapped_column(String(8))


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
    # Laatste herinnering "nog altijd down".
    reminded_at: Mapped[datetime | None]
    # Een http-check die op een andere host eindigde (bv. de loginpagina van Authentik): die host.
    redirected_to: Mapped[str | None] = mapped_column(String(255))
    # De check loopt niet meer (al lang geen resultaat): één keer gemeld.
    stale: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())


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
    # Incidentnotitie: wat de oorzaak was en hoe het opgelost werd (vooral bij een storing).
    note: Mapped[str | None] = mapped_column(Text)
    note_at: Mapped[datetime | None]


class CronJob(Base):
    """Eén geplande taak op een machine: een cronregel, systemd-timer, Proxmox-backupjob, PBS-sync, ...
    De scanner houdt deze lijst bij; verdwijnt een job, dan krijgt hij removed_at (de geschiedenis blijft)."""

    __tablename__ = "cron_jobs"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Vaste sleutel: machine + bron + schema + commando (of het job-id bij Proxmox/PBS).
    key: Mapped[str] = mapped_column(String(200), unique=True)
    # Waar hij draait: "ssh:3" (SSH-host 3) of "ssh:3:ct:105" (container 105, bereikt via node 3).
    target: Mapped[str] = mapped_column(String(80), index=True)
    target_name: Mapped[str] = mapped_column(String(120))
    host_id: Mapped[int | None] = mapped_column(ForeignKey("ssh_hosts.id", ondelete="SET NULL"), index=True)
    vmid: Mapped[int | None] = mapped_column(Integer)
    # cron | timer | periodic | pve-backup | pve-repl | pbs-sync | pbs-verify | pbs-prune | pbs-gc
    kind: Mapped[str] = mapped_column(String(16))
    source: Mapped[str] = mapped_column(String(255), default="")
    user: Mapped[str] = mapped_column(String(64), default="")
    schedule: Mapped[str] = mapped_column(String(200), default="")
    # cron | calendar | interval | reboot | none
    sched_type: Mapped[str] = mapped_column(String(12), default="cron")
    command: Mapped[str] = mapped_column(Text, default="")
    # De regel zoals hij in het bestand staat (om runs uit de cronlog te herkennen en om te bewaken).
    raw: Mapped[str] = mapped_column(Text, default="")
    name: Mapped[str] = mapped_column(String(200), default="")
    alias: Mapped[str | None] = mapped_column(String(120))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    system: Mapped[bool] = mapped_column(Boolean, default=False)
    # Id waarmee de wrapper (hp-cron) zijn runs meldt; gezet zodra de job bewaakt wordt.
    wid: Mapped[str | None] = mapped_column(String(16), index=True)
    monitored: Mapped[bool] = mapped_column(Boolean, default=False)
    muted: Mapped[bool] = mapped_column(Boolean, default=False)
    # Waar de job aan komt: [{"type": "host"|"pbs"|"storage"|"node"|..., "ref": ..., "label": ..., "via": ...}]
    targets: Mapped[list] = mapped_column(Json, default=list)
    extra: Mapped[dict] = mapped_column(Json, default=dict)
    tz: Mapped[str] = mapped_column(String(64), default="")
    next_run_at: Mapped[datetime | None]
    last_run_at: Mapped[datetime | None]
    # ok | fout | gemist | gestart (liep, resultaat onbekend) | bezig
    last_status: Mapped[str | None] = mapped_column(String(12))
    last_exit: Mapped[int | None] = mapped_column(Integer)
    last_duration: Mapped[float | None] = mapped_column(Float)
    runs_24h: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)
    removed_at: Mapped[datetime | None]


class CronRun(Base):
    __tablename__ = "cron_runs"
    # started_at apart: de scan haalt alle runs van de laatste dagen op en ruimt oude runs op.
    __table_args__ = (Index("ix_cron_runs_job_started", "job_id", "started_at", unique=True),
                      Index("ix_cron_runs_started_at", "started_at"))

    id: Mapped[int] = mapped_column(primary_key=True)
    job_id: Mapped[int] = mapped_column(ForeignKey("cron_jobs.id", ondelete="CASCADE"))
    started_at: Mapped[datetime]
    ended_at: Mapped[datetime | None]
    exit_code: Mapped[int | None] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(12))
    # schema | manueel
    trigger: Mapped[str] = mapped_column(String(12), default="schema")
    output: Mapped[str | None] = mapped_column(Text)


class Reading(Base):
    """Een meetwaarde van een sensor (temperatuur van cpu of schijf), elke 10 minuten. 30 dagen bewaard."""

    __tablename__ = "readings"

    # "ssh:3" (SSH-host 3)
    target: Mapped[str] = mapped_column(String(80), primary_key=True)
    # "cpu" of "disk:<serienummer>"
    sensor: Mapped[str] = mapped_column(String(80), primary_key=True)
    ts: Mapped[datetime] = mapped_column(primary_key=True, default=utcnow, index=True)
    value: Mapped[float] = mapped_column(Float)


class UpdateRun(Base):
    """Updates installeren op één machine of container: snapshot, apt, check van de services, eventueel terug."""

    __tablename__ = "update_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    # Zelfde sleutel als in het updates-overzicht: "ssh:3", "ssh:3:ct:105", "pve:1:pve50"
    target: Mapped[str] = mapped_column(String(80), index=True)
    target_name: Mapped[str] = mapped_column(String(120))
    # manueel | auto
    trigger: Mapped[str] = mapped_column(String(12), default="manueel")
    security_only: Mapped[bool] = mapped_column(Boolean, default=False)
    # wacht | snapshot | installeren | controleren | ok | fout | services_down | teruggedraaid | terugdraaien_mislukt
    status: Mapped[str] = mapped_column(String(24), default="wacht")
    # {"kind": "pct"|"api", "name": ..., "node": ..., "vmid": ..., "type": ..., "service_id": ..., "host_id": ...}
    snapshot: Mapped[dict | None] = mapped_column(Json)
    exit_code: Mapped[int | None] = mapped_column(Integer)
    reboot_needed: Mapped[bool] = mapped_column(Boolean, default=False)
    # [{"service_id": 1, "name": "Plex", "ok": true, "error": null}]
    checks: Mapped[list | None] = mapped_column(Json)
    output: Mapped[str | None] = mapped_column(Text)
    error: Mapped[str | None] = mapped_column(Text)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"))
    created_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    started_at: Mapped[datetime | None]
    finished_at: Mapped[datetime | None]
    rolled_back_at: Mapped[datetime | None]


class HealRule(Base):
    """Zelfherstel: als een service zoveel checks na elkaar down is, voer een actie uit (met een limiet)."""

    __tablename__ = "heal_rules"

    id: Mapped[int] = mapped_column(primary_key=True)
    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    after: Mapped[int] = mapped_column(Integer, default=3)
    max_per_hour: Mapped[int] = mapped_column(Integer, default=2)
    # {"kind": "integration", "service_id": 4, "action": "reboot", "params": {...}, "label": "..."}
    # {"kind": "ssh", "host_id": 3, "op": "systemctl"|"docker", "name": "plex"}
    action: Mapped[dict] = mapped_column(Json)
    # Tijdstippen (ISO) waarop de regel afging, het laatste uur.
    fired: Mapped[list] = mapped_column(Json, default=list)
    last_at: Mapped[datetime | None]
    last_result: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class ConfigVersion(Base):
    """Een versie van een configuratie (OPNsense config.xml, NPM-hosts, .conf van een VM/CT, een bestand via SSH).

    Alleen bewaard als ze verschilt van de vorige. De inhoud is versleuteld (er staan wachtwoorden en sleutels in).
    """

    __tablename__ = "config_versions"
    __table_args__ = (Index("ix_config_versions_item_ts", "item", "ts"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    # "opnsense:3", "npm:5", "pve:1:105", "file:3:/etc/nginx/nginx.conf"
    item: Mapped[str] = mapped_column(String(300))
    name: Mapped[str] = mapped_column(String(300))
    # opnsense | npm | pve | file
    kind: Mapped[str] = mapped_column(String(12))
    ts: Mapped[datetime] = mapped_column(default=utcnow)
    sha: Mapped[str] = mapped_column(String(64))
    size: Mapped[int] = mapped_column(Integer)
    added: Mapped[int] = mapped_column(Integer, default=0)
    removed: Mapped[int] = mapped_column(Integer, default=0)
    content: Mapped[str] = mapped_column(Text)


class Device(Base):
    """Een apparaat op het netwerk, uit de ARP- en DHCP-tabel van OPNsense."""

    __tablename__ = "devices"

    mac: Mapped[str] = mapped_column(String(17), primary_key=True)
    name: Mapped[str | None] = mapped_column(String(80))
    vendor: Mapped[str | None] = mapped_column(String(120))
    hostname: Mapped[str | None] = mapped_column(String(120))
    ip: Mapped[str | None] = mapped_column(String(45))
    intf: Mapped[str | None] = mapped_column(String(60))
    note: Mapped[str | None] = mapped_column(String(300))
    known: Mapped[bool] = mapped_column(Boolean, default=False)
    scan: Mapped[bool] = mapped_column(Boolean, default=False)
    ports: Mapped[list | None] = mapped_column(Json)
    ports_at: Mapped[datetime | None]
    first_seen: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)


class MaintenanceWindow(Base):
    """Gepland onderhoud voor een service of een hele groep: eenmalig, elke dag of op vaste weekdagen."""

    __tablename__ = "maintenance_windows"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), index=True)
    group_id: Mapped[int | None] = mapped_column(ForeignKey("groups.id", ondelete="CASCADE"), index=True)
    # once | daily | weekly
    repeat: Mapped[str] = mapped_column(String(8), default="once")
    # Eenmalig: begin als tijdstip. Herhalend: het uur en de minuut tellen (lokale tijd), plus de weekdagen.
    start: Mapped[datetime]
    minutes: Mapped[int] = mapped_column(Integer)
    # 0 = maandag ... 6 = zondag
    weekdays: Mapped[list] = mapped_column(Json, default=list)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class WebhookSource(Base):
    """Een eigen webhook-adres voor een externe tool (Proxmox, PBS, Uptime Kuma, ...): wat binnenkomt wordt
    een melding in het meldingencentrum."""

    __tablename__ = "webhook_sources"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    # proxmox | pbs | uptimekuma | homeassistant | generic
    kind: Mapped[str] = mapped_column(String(16), default="generic")
    # Zoekindex: sha256 van het token; het token zelf staat versleuteld zodat het adres opnieuw te tonen is.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token: Mapped[str] = mapped_column(Text)
    service_id: Mapped[int | None] = mapped_column(ForeignKey("services.id", ondelete="SET NULL"))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_at: Mapped[datetime | None]
    count: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(300))


class ApiConnection(Base):
    """Een API in API-beheer: adres, soort (proxmox, ..., of "rest" voor een eigen API), aanmelding en sleutels.
    Eén verbinding kan door meerdere tegels gebruikt worden (bv. één Proxmox-cluster voor elke node-tegel)."""

    __tablename__ = "api_connections"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80))
    category: Mapped[str] = mapped_column(String(40), default="overig")
    kind: Mapped[str] = mapped_column(String(40), default="rest")
    # Sjabloon waaruit ze gemaakt is (bv. "radarr"), alleen ter info.
    template: Mapped[str | None] = mapped_column(String(40))
    url: Mapped[str] = mapped_column(String(500))
    # Niet geheim: insecure, auth {type, name}, vaste headers, en instellingen van de ingebouwde integratie.
    config: Mapped[dict] = mapped_column(Json, default=dict)
    secrets: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(default=utcnow, onupdate=utcnow)

    calls: Mapped[list["ApiCall"]] = relationship(lazy="selectin", order_by="ApiCall.position, ApiCall.id",
                                                   cascade="all, delete-orphan", back_populates="connection")


class ApiCall(Base):
    """Een eigen call op een API: wat op de tegel komt (velden), een tabel in het mini dashboard, of een actie."""

    __tablename__ = "api_calls"

    id: Mapped[int] = mapped_column(primary_key=True)
    connection_id: Mapped[int] = mapped_column(ForeignKey("api_connections.id", ondelete="CASCADE"), index=True)
    name: Mapped[str] = mapped_column(String(80))
    method: Mapped[str] = mapped_column(String(8), default="GET")
    # Pad achter het adres van de API, met {variabelen} uit de instellingen van de tegel (bv. {node}).
    path: Mapped[str] = mapped_column(String(500), default="")
    query: Mapped[dict] = mapped_column(Json, default=dict)
    headers: Mapped[dict] = mapped_column(Json, default=dict)
    body: Mapped[str | None] = mapped_column(Text)
    # tile = velden op de tegel (en in het mini dashboard), detail = alleen mini dashboard, action = knop
    show: Mapped[str] = mapped_column(String(8), default="tile")
    # [{label, path, format, suffix, warn, err}]
    fields: Mapped[list] = mapped_column(Json, default=list)
    # {path, columns: [{label, path, format}]} of {}
    table: Mapped[dict] = mapped_column(Json, default=dict)
    confirm: Mapped[bool] = mapped_column(Boolean, default=True)
    position: Mapped[int] = mapped_column(Integer, default=0)

    connection: Mapped[ApiConnection] = relationship(back_populates="calls")


class PushMonitor(Base):
    """Push-monitor (zoals in Uptime Kuma): een script roept een geheim adres aan. Blijft dat uit, dan is de service
    down. De API schrijft alleen de laatste slag hier weg; de worker beslist (en is zo de enige die ServiceState
    bijwerkt)."""

    __tablename__ = "push_monitors"

    service_id: Mapped[int] = mapped_column(ForeignKey("services.id", ondelete="CASCADE"), primary_key=True)
    # Zoekindex: sha256 van het token; het token zelf staat versleuteld zodat het adres opnieuw te tonen is.
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    token: Mapped[str] = mapped_column(Text)
    # Ook aanvaarden via Cloudflare (van buitenaf), bv. voor een VPS.
    outside: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    last_at: Mapped[datetime | None]
    last_ok: Mapped[bool | None] = mapped_column(Boolean)
    last_msg: Mapped[str | None] = mapped_column(String(300))
    last_ping: Mapped[float | None] = mapped_column(Float)
    # Laatste slag met status=down: die mag niet verloren gaan als er vlak daarna een goede volgt.
    last_down_at: Mapped[datetime | None]
    last_down_msg: Mapped[str | None] = mapped_column(String(300))
    # Tot waar de worker de slagen verwerkt heeft, en wanneer hij voor het laatst "geen signaal" schreef.
    seen_at: Mapped[datetime | None]
    missed_at: Mapped[datetime | None]
    count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class PushSubscription(Base):
    """Een toestel (browser of app op het beginscherm) dat meldingen krijgt via web push."""

    __tablename__ = "push_subscriptions"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    # sha256 van het pushadres: zo is hetzelfde toestel terug te vinden zonder het adres leesbaar te bewaren.
    endpoint_hash: Mapped[str] = mapped_column(String(64), unique=True)
    # Versleuteld: {endpoint, p256dh, auth}.
    data: Mapped[str] = mapped_column(Text)
    label: Mapped[str] = mapped_column(String(80))
    # err | warn | info: vanaf welke ernst dit toestel meldingen krijgt.
    min_level: Mapped[str] = mapped_column(String(8), default="err", server_default="err")
    # sha256 van het geheim waarmee de service worker een vernieuwd pushadres doorgeeft (zonder sessie).
    renew_hash: Mapped[str] = mapped_column(String(64))
    # Het vorige vernieuwgeheim, alleen nog goed om exact hetzelfde verzoek te herhalen (antwoord onderweg verloren).
    prev_renew_hash: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_ok_at: Mapped[datetime | None]
    last_error: Mapped[str | None] = mapped_column(String(300))
    fail_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    # Al gemeld dat het misloopt (één keer, tot het weer lukt).
    warned: Mapped[bool] = mapped_column(Boolean, default=False, server_default=sa_false())
    # De pushdienst kent het adres niet meer (404/410). Blijft nog 30 dagen staan: Firefox meldt zich soms later
    # zelf opnieuw aan (pushsubscriptionchange), en dat lukt alleen als de rij met het vernieuwgeheim er nog is.
    gone_at: Mapped[datetime | None]


class PushQueue(Base):
    """Nog te versturen pushberichten, per toestel (met nieuwe pogingen als de pushdienst even niet antwoordt)."""

    __tablename__ = "push_queue"

    id: Mapped[int] = mapped_column(primary_key=True)
    subscription_id: Mapped[int] = mapped_column(ForeignKey("push_subscriptions.id", ondelete="CASCADE"), index=True)
    notification_id: Mapped[int | None] = mapped_column(ForeignKey("notifications.id", ondelete="CASCADE"))
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_at: Mapped[datetime] = mapped_column(default=utcnow, index=True)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
