"""push-monitors: een geheim adres dat scripts aanroepen (zoals in Uptime Kuma)

Revision ID: 0021
Revises: 0020
"""
from alembic import op
import sqlalchemy as sa

revision = '0021'
down_revision = '0020'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'push_monitors',
        sa.Column('service_id', sa.Integer(), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('token', sa.Text(), nullable=False),
        sa.Column('outside', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column('last_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_ok', sa.Boolean(), nullable=True),
        sa.Column('last_msg', sa.String(length=300), nullable=True),
        sa.Column('last_ping', sa.Float(), nullable=True),
        sa.Column('last_down_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_down_msg', sa.String(length=300), nullable=True),
        sa.Column('seen_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('missed_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('service_id'),
        sa.UniqueConstraint('token_hash'),
    )


def downgrade() -> None:
    op.drop_table('push_monitors')
