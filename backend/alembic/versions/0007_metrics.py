"""extra's: capaciteit (metrics)

Revision ID: 0007
Revises: 0006
"""
from alembic import op
import sqlalchemy as sa

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('metrics',
    sa.Column('service_id', sa.Integer(), nullable=False),
    sa.Column('kind', sa.String(length=8), nullable=False),
    sa.Column('name', sa.String(length=120), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('label', sa.String(length=120), nullable=True),
    sa.Column('cpu', sa.Float(), nullable=True),
    sa.Column('mem', sa.BigInteger(), nullable=True),
    sa.Column('mem_total', sa.BigInteger(), nullable=True),
    sa.Column('disk', sa.BigInteger(), nullable=True),
    sa.Column('disk_total', sa.BigInteger(), nullable=True),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('service_id', 'kind', 'name', 'ts')
    )
    op.create_index(op.f('ix_metrics_ts'), 'metrics', ['ts'], unique=False)

    # Met TimescaleDB: hypertable, compressie na 7 dagen en 180 dagen bewaren (genoeg voor trends).
    # Zonder TimescaleDB ruimt de worker zelf op (90 dagen).
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    if bind.exec_driver_sql("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'").scalar():
        op.execute("SELECT create_hypertable('metrics', 'ts', chunk_time_interval => INTERVAL '7 days', "
                   "migrate_data => TRUE, if_not_exists => TRUE)")
        op.execute("ALTER TABLE metrics SET (timescaledb.compress, "
                   "timescaledb.compress_segmentby = 'service_id, kind, name', timescaledb.compress_orderby = 'ts DESC')")
        op.execute("SELECT add_compression_policy('metrics', INTERVAL '7 days', if_not_exists => TRUE)")
        op.execute("SELECT add_retention_policy('metrics', INTERVAL '180 days', if_not_exists => TRUE)")


def downgrade() -> None:
    op.drop_index(op.f('ix_metrics_ts'), table_name='metrics')
    op.drop_table('metrics')
