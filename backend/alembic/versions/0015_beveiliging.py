"""beveiliging: laatst gebruikte TOTP-stap (geen hergebruik van een code)

Revision ID: 0015
Revises: 0014
"""
from alembic import op
import sqlalchemy as sa

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('totp_last_step', sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'totp_last_step')
