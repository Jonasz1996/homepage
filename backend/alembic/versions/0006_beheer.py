"""extra's: sessiebeheer en notities

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('sessions', sa.Column('country', sa.String(length=2), nullable=True))
    op.add_column('sessions', sa.Column('last_seen_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('services', sa.Column('notes', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('services', 'notes')
    op.drop_column('sessions', 'last_seen_at')
    op.drop_column('sessions', 'country')
