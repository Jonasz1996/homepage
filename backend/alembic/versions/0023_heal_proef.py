"""zelfherstel: een regel op alleen proef (zet op de tijdlijn wat hij zou doen, zonder het te doen)

Revision ID: 0023
Revises: 0022
"""
from alembic import op
import sqlalchemy as sa

revision = '0023'
down_revision = '0022'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('heal_rules', sa.Column('dry_run', sa.Boolean(), server_default=sa.false(), nullable=False))


def downgrade() -> None:
    op.drop_column('heal_rules', 'dry_run')
