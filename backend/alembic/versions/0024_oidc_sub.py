"""inloggen via Authentik: het gekoppelde account (uitgever en vaste ID) per gebruiker, niet meer op naam

Revision ID: 0024
Revises: 0023
"""
from alembic import op
import sqlalchemy as sa

revision = '0024'
down_revision = '0023'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Niets om over te zetten: de sub stond nergens. Na de update is nog geen account gekoppeld.
    op.add_column('users', sa.Column('oidc_issuer', sa.String(length=300), nullable=True))
    op.add_column('users', sa.Column('oidc_sub', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('oidc_name', sa.String(length=64), nullable=True))
    op.create_unique_constraint('users_oidc_sub_key', 'users', ['oidc_sub'])


def downgrade() -> None:
    op.drop_constraint('users_oidc_sub_key', 'users', type_='unique')
    op.drop_column('users', 'oidc_name')
    op.drop_column('users', 'oidc_sub')
    op.drop_column('users', 'oidc_issuer')
