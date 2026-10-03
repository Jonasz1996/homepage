"""syslog: logregels en meldingsregels

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import sqlalchemy as sa


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('log_entries',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('host', sa.String(length=255), nullable=False),
    sa.Column('source_ip', sa.String(length=64), nullable=True),
    sa.Column('facility', sa.SmallInteger(), nullable=False),
    sa.Column('severity', sa.SmallInteger(), nullable=False),
    sa.Column('app', sa.String(length=64), nullable=True),
    sa.Column('msg', sa.Text(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_log_entries_host_ts', 'log_entries', ['host', 'ts'], unique=False)
    op.create_index(op.f('ix_log_entries_ts'), 'log_entries', ['ts'], unique=False)
    op.create_table('log_rules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('pattern', sa.String(length=500), nullable=True),
    sa.Column('host', sa.String(length=255), nullable=True),
    sa.Column('max_severity', sa.SmallInteger(), nullable=False),
    sa.Column('level', sa.String(length=8), nullable=False),
    sa.Column('cooldown_minutes', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    # Standaardregel: alles vanaf 'crit' (kernel panics, schijffouten, ...) wordt een melding.
    op.execute("INSERT INTO log_rules (name, pattern, host, max_severity, level, cooldown_minutes, enabled, created_at) "
               "VALUES ('Kritieke meldingen', NULL, NULL, 2, 'err', 10, true, CURRENT_TIMESTAMP)")

    # Met TimescaleDB: hypertable (de tijdkolom moet in de primaire sleutel), compressie na
    # 3 dagen en 30 dagen bewaren. Zonder TimescaleDB ruimt de syslog-ontvanger zelf op.
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    available = bind.exec_driver_sql(
        "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'"
    ).scalar()
    if available:
        op.execute("ALTER TABLE log_entries DROP CONSTRAINT log_entries_pkey")
        op.execute("ALTER TABLE log_entries ADD PRIMARY KEY (id, ts)")
        op.execute("SELECT create_hypertable('log_entries', 'ts', chunk_time_interval => INTERVAL '1 day', "
                   "migrate_data => TRUE, if_not_exists => TRUE)")
        op.execute("ALTER TABLE log_entries SET (timescaledb.compress, "
                   "timescaledb.compress_segmentby = 'host', timescaledb.compress_orderby = 'ts DESC, id DESC')")
        op.execute("SELECT add_compression_policy('log_entries', INTERVAL '3 days', if_not_exists => TRUE)")
        op.execute("SELECT add_retention_policy('log_entries', INTERVAL '30 days', if_not_exists => TRUE)")


def downgrade() -> None:
    op.drop_table('log_rules')
    op.drop_index(op.f('ix_log_entries_ts'), table_name='log_entries')
    op.drop_index('ix_log_entries_host_ts', table_name='log_entries')
    op.drop_table('log_entries')
