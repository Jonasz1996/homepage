"""logregels na 1 dag comprimeren in plaats van na 3 (de schijf van de container is klein)

Revision ID: 0022
Revises: 0021
"""
from alembic import op

revision = '0022'
down_revision = '0021'
branch_labels = None
depends_on = None


def _compress_after(interval: str) -> None:
    # Alleen met TimescaleDB is log_entries een hypertable; zonder is er geen compressie en niets te doen.
    bind = op.get_bind()
    if bind.dialect.name != "postgresql":
        return
    if not bind.exec_driver_sql("SELECT 1 FROM pg_extension WHERE extname = 'timescaledb'").scalar():
        return
    if not bind.exec_driver_sql("SELECT 1 FROM timescaledb_information.hypertables "
                                "WHERE hypertable_name = 'log_entries'").scalar():
        return
    op.execute("SELECT remove_compression_policy('log_entries', if_exists => TRUE)")
    op.execute(f"SELECT add_compression_policy('log_entries', INTERVAL '{interval}')")


def upgrade() -> None:
    _compress_after('1 day')


def downgrade() -> None:
    _compress_after('3 days')
