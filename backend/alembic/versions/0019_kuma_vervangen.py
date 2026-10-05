"""het dashboard vervangt Uptime Kuma: herinneringen, doorverwijzingen, vastgelopen checks, herstart van een check,
web push-wachtrij

Revision ID: 0019
Revises: 0018
"""
from alembic import op
import sqlalchemy as sa

revision = '0019'
down_revision = '0018'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('service_state', sa.Column('reminded_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('service_state', sa.Column('redirected_to', sa.String(length=255), nullable=True))
    op.add_column('service_state', sa.Column('stale', sa.Boolean(), server_default=sa.false(), nullable=False))
    op.add_column('services', sa.Column('check_changed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('notifications', sa.Column('pushed_at', sa.DateTime(timezone=True), nullable=True))
    # Bestaande meldingen gaan nooit meer naar een gsm: anders volgt na de update een vloed.
    op.execute("UPDATE notifications SET pushed_at = CURRENT_TIMESTAMP")
    op.create_index('ix_notifications_unpushed', 'notifications', ['id'], unique=False,
                    postgresql_where=sa.text('pushed_at IS NULL'), sqlite_where=sa.text('pushed_at IS NULL'))


def downgrade() -> None:
    op.drop_index('ix_notifications_unpushed', table_name='notifications')
    op.drop_column('notifications', 'pushed_at')
    op.drop_column('services', 'check_changed_at')
    op.drop_column('service_state', 'stale')
    op.drop_column('service_state', 'redirected_to')
    op.drop_column('service_state', 'reminded_at')
