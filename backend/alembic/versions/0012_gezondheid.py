"""gezondheid: temperaturen van cpu en schijven

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import sqlalchemy as sa

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'readings',
        sa.Column('target', sa.String(length=80), nullable=False),
        sa.Column('sensor', sa.String(length=80), nullable=False),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('value', sa.Float(), nullable=False),
        sa.PrimaryKeyConstraint('target', 'sensor', 'ts'),
    )
    op.create_index(op.f('ix_readings_ts'), 'readings', ['ts'], unique=False)
    # Met TimescaleDB een hypertable die zichzelf na 30 dagen opruimt; anders doet de worker dat.
    bind = op.get_bind()
    if bind.dialect.name == "postgresql" and bind.exec_driver_sql(
            "SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'").scalar():
        op.execute("SELECT create_hypertable('readings', 'ts', chunk_time_interval => INTERVAL '7 days', "
                   "migrate_data => TRUE, if_not_exists => TRUE)")
        op.execute("SELECT add_retention_policy('readings', INTERVAL '30 days', if_not_exists => TRUE)")


def downgrade() -> None:
    op.drop_index(op.f('ix_readings_ts'), table_name='readings')
    op.drop_table('readings')
