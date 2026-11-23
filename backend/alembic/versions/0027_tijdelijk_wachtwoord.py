"""tijdelijk wachtwoord na accountherstel (homepage-beheer herstel)

Revision ID: 0027
Revises: 0026
"""
from alembic import op
import sqlalchemy as sa

revision = '0027'
down_revision = '0026'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('users', sa.Column('password_temp_until', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('users', 'password_temp_until')
