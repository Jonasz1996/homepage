"""uurtotalen van de checks (check_hourly, 400 dagen); losse checks nog 90 dagen in plaats van een jaar

De grafiek en de uptime over 7 dagen tot een jaar en het weekrapport lezen de hele uren uit check_hourly (zie
app/monitoring/rollup.py). Wat er al aan checks is, wordt hier opgeteld, in dezelfde transactie als het kortere
bewaarbeleid: met TimescaleDB kan dat beleid meteen na de migratie de checks van meer dan 90 dagen geleden wissen,
en die moeten dan al in de uurtotalen zitten. Per week één query, zodat elke stap begrensd blijft (met TimescaleDB
pakt hij alleen de chunks van die week uit); de diensten liggen stil tijdens de migratie, en lezen houdt niemand
tegen. Daarna telt de worker elke 10 minuten verder.

Terug (downgrade): de checks die intussen weg zijn, komen niet terug; de 1j-grafiek toont dan alleen de laatste
90 dagen tot er weer een jaar is.

Revision ID: 0026
Revises: 0023
"""
import json
from datetime import datetime, timedelta, timezone

from alembic import op
import sqlalchemy as sa

revision = '0026'
down_revision = '0023'
branch_labels = None
depends_on = None

KEY = 'check_hourly'
STEP = timedelta(days=7)
# Zoals app/monitoring/rollup.py: per uur de checks buiten onderhoud, hoeveel daarvan gelukt, en de latency apart
# buiten en tijdens onderhoud.
BACKFILL = """
INSERT INTO check_hourly (service_id, hour, checks, ok, latency_n, latency_sum, latency_min, latency_max,
                          maint_latency_n, maint_latency_sum, maint_latency_min, maint_latency_max)
SELECT service_id, to_timestamp(floor(extract(epoch FROM ts) / 3600) * 3600),
       count(*) FILTER (WHERE maintenance IS NOT TRUE),
       count(*) FILTER (WHERE ok AND maintenance IS NOT TRUE),
       count(latency_ms) FILTER (WHERE maintenance IS NOT TRUE),
       sum(latency_ms) FILTER (WHERE maintenance IS NOT TRUE),
       min(latency_ms) FILTER (WHERE maintenance IS NOT TRUE),
       max(latency_ms) FILTER (WHERE maintenance IS NOT TRUE),
       count(latency_ms) FILTER (WHERE maintenance IS TRUE),
       sum(latency_ms) FILTER (WHERE maintenance IS TRUE),
       min(latency_ms) FILTER (WHERE maintenance IS TRUE),
       max(latency_ms) FILTER (WHERE maintenance IS TRUE)
  FROM check_results
 WHERE ts >= :a AND ts < :b
 GROUP BY 1, 2
"""


def _hypertable(bind) -> bool:
    """Is check_results een hypertable (TimescaleDB)? Dan wordt check_hourly er ook een, zoals de andere tabellen
    met metingen, en ruimt TimescaleDB beide op. Anders doet de worker dat."""
    if bind.dialect.name != "postgresql":
        return False
    if not bind.exec_driver_sql("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'").scalar():
        return False
    return bool(bind.exec_driver_sql("SELECT 1 FROM timescaledb_information.hypertables "
                                     "WHERE hypertable_name = 'check_results'").scalar())


def _keep_checks(interval: str) -> None:
    op.execute("SELECT remove_retention_policy('check_results', if_exists => TRUE)")
    op.execute(f"SELECT add_retention_policy('check_results', INTERVAL '{interval}')")


def upgrade() -> None:
    op.create_table('check_hourly',
    sa.Column('service_id', sa.Integer(), nullable=False),
    sa.Column('hour', sa.DateTime(timezone=True), nullable=False),
    sa.Column('checks', sa.Integer(), nullable=False),
    sa.Column('ok', sa.Integer(), nullable=False),
    sa.Column('latency_n', sa.Integer(), nullable=False),
    sa.Column('latency_sum', sa.Float(), nullable=True),
    sa.Column('latency_min', sa.Float(), nullable=True),
    sa.Column('latency_max', sa.Float(), nullable=True),
    sa.Column('maint_latency_n', sa.Integer(), nullable=False),
    sa.Column('maint_latency_sum', sa.Float(), nullable=True),
    sa.Column('maint_latency_min', sa.Float(), nullable=True),
    sa.Column('maint_latency_max', sa.Float(), nullable=True),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('service_id', 'hour')
    )
    op.create_index(op.f('ix_check_hourly_hour'), 'check_hourly', ['hour'], unique=False)

    bind = op.get_bind()
    hyper = _hypertable(bind)
    if hyper:
        # Klein (een rij per service per uur): chunks van 30 dagen, gecomprimeerd na 7 dagen zoals check_results.
        op.execute("SELECT create_hypertable('check_hourly', 'hour', chunk_time_interval => INTERVAL '30 days', "
                   "if_not_exists => TRUE)")
        op.execute("ALTER TABLE check_hourly SET (timescaledb.compress, "
                   "timescaledb.compress_segmentby = 'service_id', timescaledb.compress_orderby = 'hour DESC')")
        op.execute("SELECT add_compression_policy('check_hourly', INTERVAL '7 days', if_not_exists => TRUE)")
        op.execute("SELECT add_retention_policy('check_hourly', INTERVAL '400 days', if_not_exists => TRUE)")

    if bind.dialect.name == "postgresql":
        # Alle hele uren tot nu; het lopende uur telt de worker.
        until = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
        first = bind.execute(sa.text("SELECT min(ts) FROM check_results")).scalar()
        if first is not None:
            a = first.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
            while a < until:
                b = min(a + STEP, until)
                bind.execute(sa.text(BACKFILL), {"a": a, "b": b})
                a = b
        bind.execute(sa.text(
            "INSERT INTO app_state (key, value, updated_at) VALUES (:k, CAST(:v AS jsonb), now()) "
            "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = EXCLUDED.updated_at"),
            {"k": KEY, "v": json.dumps({"until": until.isoformat()})})

    if hyper:
        # Pas nu: wat ouder is dan 90 dagen, zit al in de uurtotalen.
        _keep_checks('90 days')


def downgrade() -> None:
    if _hypertable(op.get_bind()):
        _keep_checks('365 days')
    op.execute(f"DELETE FROM app_state WHERE key = '{KEY}'")
    op.drop_index(op.f('ix_check_hourly_hour'), table_name='check_hourly')
    op.drop_table('check_hourly')
