"""monitoring

Revision ID: 0002
Revises: 0001
Create Date: 2026-10-03 17:53:46.861552
"""
from alembic import op
import sqlalchemy as sa


revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('check_results',
    sa.Column('service_id', sa.Integer(), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('ok', sa.Boolean(), nullable=False),
    sa.Column('latency_ms', sa.Double(), nullable=True),
    sa.Column('status_code', sa.Integer(), nullable=True),
    sa.Column('error', sa.String(length=300), nullable=True),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('service_id', 'ts')
    )
    op.create_table('service_state',
    sa.Column('service_id', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=8), nullable=False),
    sa.Column('since', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_check', sa.DateTime(timezone=True), nullable=True),
    sa.Column('latency_ms', sa.Double(), nullable=True),
    sa.Column('fail_count', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.String(length=300), nullable=True),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('service_id')
    )
    op.create_index('ix_check_results_ts', 'check_results', ['ts'])

    # Met TimescaleDB: hypertable, compressie na 7 dagen en 1 jaar bewaren.
    # Zonder TimescaleDB ruimt de worker zelf oude rijen op.
    bind = op.get_bind()
    available = bind.exec_driver_sql(
        "SELECT 1 FROM pg_available_extensions WHERE name = 'timescaledb'"
    ).scalar()
    if available:
        op.execute("CREATE EXTENSION IF NOT EXISTS timescaledb")
        op.execute("SELECT create_hypertable('check_results', 'ts', migrate_data => TRUE, if_not_exists => TRUE)")
        op.execute(
            "ALTER TABLE check_results SET (timescaledb.compress, "
            "timescaledb.compress_segmentby = 'service_id', timescaledb.compress_orderby = 'ts DESC')"
        )
        op.execute("SELECT add_compression_policy('check_results', INTERVAL '7 days', if_not_exists => TRUE)")
        op.execute("SELECT add_retention_policy('check_results', INTERVAL '365 days', if_not_exists => TRUE)")


def downgrade() -> None:
    op.drop_table('service_state')
    op.drop_index('ix_check_results_ts', 'check_results')
    op.drop_table('check_results')
