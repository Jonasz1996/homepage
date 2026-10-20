"""later: stroomverbruik in metrics

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import sqlalchemy as sa

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Nullable kolom zonder standaardwaarde: kan ook op een gecomprimeerde hypertable.
    op.add_column('metrics', sa.Column('watts', sa.Float(), nullable=True))


def downgrade() -> None:
    op.drop_column('metrics', 'watts')
