"""een eigen achtergrondafbeelding voor het dashboard

Revision ID: 0026
Revises: 0025
"""
from alembic import op
import sqlalchemy as sa

revision = '0026'
down_revision = '0025'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('achtergrond',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('mime', sa.String(length=40), nullable=False),
    sa.Column('data', sa.LargeBinary(), nullable=False),
    sa.Column('sha', sa.String(length=64), nullable=False),
    sa.Column('bron', sa.String(length=500), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('achtergrond')
