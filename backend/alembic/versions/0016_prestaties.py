"""indexen voor meldingen en cronruns

Revision ID: 0016
Revises: 0015
"""
from alembic import op
import sqlalchemy as sa

revision = '0016'
down_revision = '0015'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Ongelezen meldingen tellen (badge) zonder de hele tabel te lezen.
    op.create_index('ix_notifications_unread', 'notifications', ['id'], unique=False,
                    postgresql_where=sa.text('read_at IS NULL'), sqlite_where=sa.text('read_at IS NULL'))
    op.create_index('ix_notifications_service_id', 'notifications', ['service_id'], unique=False)
    op.create_index('ix_cron_runs_started_at', 'cron_runs', ['started_at'], unique=False)


def downgrade() -> None:
    op.drop_index('ix_cron_runs_started_at', table_name='cron_runs')
    op.drop_index('ix_notifications_service_id', table_name='notifications')
    op.drop_index('ix_notifications_unread', table_name='notifications')
