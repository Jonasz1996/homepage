"""configuratieversies en apparaten op het netwerk

Revision ID: 0014
Revises: 0013
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0014'
down_revision = '0013'
branch_labels = None
depends_on = None

Json = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')


def upgrade() -> None:
    op.create_table(
        'config_versions',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('item', sa.String(length=300), nullable=False),
        sa.Column('name', sa.String(length=300), nullable=False),
        sa.Column('kind', sa.String(length=12), nullable=False),
        sa.Column('ts', sa.DateTime(timezone=True), nullable=False),
        sa.Column('sha', sa.String(length=64), nullable=False),
        sa.Column('size', sa.Integer(), nullable=False),
        sa.Column('added', sa.Integer(), nullable=False),
        sa.Column('removed', sa.Integer(), nullable=False),
        sa.Column('content', sa.Text(), nullable=False),
    )
    op.create_index('ix_config_versions_item_ts', 'config_versions', ['item', 'ts'], unique=False)
    op.create_table(
        'devices',
        sa.Column('mac', sa.String(length=17), primary_key=True),
        sa.Column('name', sa.String(length=80), nullable=True),
        sa.Column('vendor', sa.String(length=120), nullable=True),
        sa.Column('hostname', sa.String(length=120), nullable=True),
        sa.Column('ip', sa.String(length=45), nullable=True),
        sa.Column('intf', sa.String(length=60), nullable=True),
        sa.Column('note', sa.String(length=300), nullable=True),
        sa.Column('known', sa.Boolean(), nullable=False),
        sa.Column('scan', sa.Boolean(), nullable=False),
        sa.Column('ports', Json, nullable=True),
        sa.Column('ports_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table('devices')
    op.drop_index('ix_config_versions_item_ts', table_name='config_versions')
    op.drop_table('config_versions')
