"""later: tijdlijn (events) en updates per SSH-host

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
    sa.Column('kind', sa.String(length=16), nullable=False),
    sa.Column('level', sa.String(length=8), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=False),
    sa.Column('body', sa.Text(), nullable=True),
    sa.Column('service_id', sa.Integer(), nullable=True),
    sa.Column('data', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_events_kind'), 'events', ['kind'], unique=False)
    op.create_index(op.f('ix_events_service_id'), 'events', ['service_id'], unique=False)
    op.create_index(op.f('ix_events_ts'), 'events', ['ts'], unique=False)
    op.add_column('ssh_hosts', sa.Column('updates', sa.String(length=8), server_default='', nullable=False))


def downgrade() -> None:
    op.drop_column('ssh_hosts', 'updates')
    op.drop_index(op.f('ix_events_ts'), table_name='events')
    op.drop_index(op.f('ix_events_service_id'), table_name='events')
    op.drop_index(op.f('ix_events_kind'), table_name='events')
    op.drop_table('events')
