"""web push: toestellen die meldingen krijgen, en de wachtrij naar de pushdiensten

Revision ID: 0020
Revises: 0019
"""
from alembic import op
import sqlalchemy as sa

revision = '0020'
down_revision = '0019'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'push_subscriptions',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('endpoint_hash', sa.String(length=64), nullable=False),
        sa.Column('data', sa.Text(), nullable=False),
        sa.Column('label', sa.String(length=80), nullable=False),
        sa.Column('min_level', sa.String(length=8), server_default='err', nullable=False),
        sa.Column('renew_hash', sa.String(length=64), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_ok_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_error', sa.String(length=300), nullable=True),
        sa.Column('fail_count', sa.Integer(), server_default='0', nullable=False),
        sa.Column('warned', sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('endpoint_hash'),
    )
    op.create_index(op.f('ix_push_subscriptions_user_id'), 'push_subscriptions', ['user_id'], unique=False)
    op.create_table(
        'push_queue',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('subscription_id', sa.Integer(), nullable=False),
        sa.Column('notification_id', sa.Integer(), nullable=True),
        sa.Column('attempts', sa.Integer(), server_default='0', nullable=False),
        sa.Column('next_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['notification_id'], ['notifications.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['subscription_id'], ['push_subscriptions.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_push_queue_next_at'), 'push_queue', ['next_at'], unique=False)
    op.create_index(op.f('ix_push_queue_subscription_id'), 'push_queue', ['subscription_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_push_queue_subscription_id'), table_name='push_queue')
    op.drop_index(op.f('ix_push_queue_next_at'), table_name='push_queue')
    op.drop_table('push_queue')
    op.drop_index(op.f('ix_push_subscriptions_user_id'), table_name='push_subscriptions')
    op.drop_table('push_subscriptions')
