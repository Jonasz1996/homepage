"""API-beheer: verbindingen, eigen calls en de API van een tegel

Revision ID: 0018
Revises: 0017
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0018'
down_revision = '0017'
branch_labels = None
depends_on = None

JSON = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')


def upgrade() -> None:
    op.create_table(
        'api_connections',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('category', sa.String(length=40), nullable=False),
        sa.Column('kind', sa.String(length=40), nullable=False),
        sa.Column('template', sa.String(length=40), nullable=True),
        sa.Column('url', sa.String(length=500), nullable=False),
        sa.Column('config', JSON, nullable=False),
        sa.Column('secrets', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'api_calls',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('connection_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=80), nullable=False),
        sa.Column('method', sa.String(length=8), nullable=False),
        sa.Column('path', sa.String(length=500), nullable=False),
        sa.Column('query', JSON, nullable=False),
        sa.Column('headers', JSON, nullable=False),
        sa.Column('body', sa.Text(), nullable=True),
        sa.Column('show', sa.String(length=8), nullable=False),
        sa.Column('fields', JSON, nullable=False),
        sa.Column('table', JSON, nullable=False),
        sa.Column('confirm', sa.Boolean(), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['connection_id'], ['api_connections.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_api_calls_connection_id'), 'api_calls', ['connection_id'], unique=False)
    op.add_column('services', sa.Column('api_id', sa.Integer(), nullable=True))
    op.create_index(op.f('ix_services_api_id'), 'services', ['api_id'], unique=False)
    op.create_foreign_key('fk_services_api_id', 'services', 'api_connections', ['api_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    op.drop_constraint('fk_services_api_id', 'services', type_='foreignkey')
    op.drop_index(op.f('ix_services_api_id'), table_name='services')
    op.drop_column('services', 'api_id')
    op.drop_index(op.f('ix_api_calls_connection_id'), table_name='api_calls')
    op.drop_table('api_calls')
    op.drop_table('api_connections')
