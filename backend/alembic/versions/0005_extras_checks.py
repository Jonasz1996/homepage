"""extra's: onderhoud, afhankelijkheden, certificaten

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('app_state',
    sa.Column('key', sa.String(length=100), nullable=False),
    sa.Column('value', sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), 'postgresql'), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('key')
    )
    # Nullable: een NOT NULL-kolom toevoegen aan een gecomprimeerde hypertable kan TimescaleDB niet altijd.
    op.add_column('check_results', sa.Column('maintenance', sa.Boolean(), server_default=sa.text('false'), nullable=True))
    op.add_column('service_state', sa.Column('quiet', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    op.add_column('service_state', sa.Column('cert_expires_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('service_state', sa.Column('cert_notified', sa.SmallInteger(), server_default='0', nullable=False))
    op.add_column('services', sa.Column('parent_id', sa.Integer(), nullable=True))
    op.add_column('services', sa.Column('maintenance_until', sa.DateTime(timezone=True), nullable=True))
    op.create_index(op.f('ix_services_parent_id'), 'services', ['parent_id'], unique=False)
    op.create_foreign_key('fk_services_parent_id', 'services', 'services', ['parent_id'], ['id'], ondelete='SET NULL')


def downgrade() -> None:
    op.drop_constraint('fk_services_parent_id', 'services', type_='foreignkey')
    op.drop_index(op.f('ix_services_parent_id'), table_name='services')
    op.drop_column('services', 'maintenance_until')
    op.drop_column('services', 'parent_id')
    op.drop_column('service_state', 'cert_notified')
    op.drop_column('service_state', 'cert_expires_at')
    op.drop_column('service_state', 'quiet')
    op.drop_column('check_results', 'maintenance')
    op.drop_table('app_state')
