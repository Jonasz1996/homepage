"""updates installeren met snapshot, en zelfherstel-regels

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None

Json = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')


def upgrade() -> None:
    op.create_table(
        'update_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('target', sa.String(length=80), nullable=False),
        sa.Column('target_name', sa.String(length=120), nullable=False),
        sa.Column('trigger', sa.String(length=12), nullable=False),
        sa.Column('security_only', sa.Boolean(), nullable=False),
        sa.Column('status', sa.String(length=24), nullable=False),
        sa.Column('snapshot', Json, nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('reboot_needed', sa.Boolean(), nullable=False),
        sa.Column('checks', Json, nullable=True),
        sa.Column('output', sa.Text(), nullable=True),
        sa.Column('error', sa.Text(), nullable=True),
        sa.Column('user_id', sa.Integer(), sa.ForeignKey('users.id', ondelete='SET NULL'), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('rolled_back_at', sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(op.f('ix_update_runs_target'), 'update_runs', ['target'], unique=False)
    op.create_index(op.f('ix_update_runs_created_at'), 'update_runs', ['created_at'], unique=False)
    op.create_table(
        'heal_rules',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('service_id', sa.Integer(), sa.ForeignKey('services.id', ondelete='CASCADE'), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('after', sa.Integer(), nullable=False),
        sa.Column('max_per_hour', sa.Integer(), nullable=False),
        sa.Column('action', Json, nullable=False),
        sa.Column('fired', Json, nullable=False),
        sa.Column('last_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_result', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index(op.f('ix_heal_rules_service_id'), 'heal_rules', ['service_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_heal_rules_service_id'), table_name='heal_rules')
    op.drop_table('heal_rules')
    op.drop_index(op.f('ix_update_runs_created_at'), table_name='update_runs')
    op.drop_index(op.f('ix_update_runs_target'), table_name='update_runs')
    op.drop_table('update_runs')
