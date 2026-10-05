"""incidentnotities, gepland onderhoud en webhooks

Revision ID: 0017
Revises: 0016
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0017'
down_revision = '0016'
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')


def upgrade() -> None:
    op.add_column('events', sa.Column('note', sa.Text(), nullable=True))
    op.add_column('events', sa.Column('note_at', sa.DateTime(timezone=True), nullable=True))
    op.create_table(
        'maintenance_windows',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('service_id', sa.Integer(), nullable=True),
        sa.Column('group_id', sa.Integer(), nullable=True),
        sa.Column('repeat', sa.String(length=8), nullable=False),
        sa.Column('start', sa.DateTime(timezone=True), nullable=False),
        sa.Column('minutes', sa.Integer(), nullable=False),
        sa.Column('weekdays', JSON, nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['group_id'], ['groups.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_maintenance_windows_group_id'), 'maintenance_windows', ['group_id'], unique=False)
    op.create_index(op.f('ix_maintenance_windows_service_id'), 'maintenance_windows', ['service_id'], unique=False)
    op.create_table(
        'webhook_sources',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('token_hash', sa.String(length=64), nullable=False),
        sa.Column('token', sa.Text(), nullable=False),
        sa.Column('service_id', sa.Integer(), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.Column('last_error', sa.String(length=300), nullable=True),
        sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('token_hash'),
    )


def downgrade() -> None:
    op.drop_table('webhook_sources')
    op.drop_index(op.f('ix_maintenance_windows_service_id'), table_name='maintenance_windows')
    op.drop_index(op.f('ix_maintenance_windows_group_id'), table_name='maintenance_windows')
    op.drop_table('maintenance_windows')
    op.drop_column('events', 'note_at')
    op.drop_column('events', 'note')
