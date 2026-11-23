"""accountherstel: herstelverzoeken met code en een tijdelijk wachtwoord (homepage-beheer herstel)

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
    op.create_table('herstel_verzoeken',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('code_hash', sa.String(length=64), nullable=False),
    sa.Column('login', sa.String(length=254), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('used_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('ip', sa.String(length=64), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code_hash')
    )
    op.create_index('ix_herstel_verzoeken_user_id', 'herstel_verzoeken', ['user_id'])


def downgrade() -> None:
    op.drop_index('ix_herstel_verzoeken_user_id', table_name='herstel_verzoeken')
    op.drop_table('herstel_verzoeken')
    op.drop_column('users', 'password_temp_until')
