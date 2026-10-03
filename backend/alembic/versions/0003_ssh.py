"""ssh-terminal: sleutels en hosts

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import sqlalchemy as sa


revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('ssh_keys',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('public_key', sa.Text(), nullable=False),
    sa.Column('private_key', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('ssh_hosts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=80), nullable=False),
    sa.Column('host', sa.String(length=255), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('key_id', sa.Integer(), nullable=True),
    sa.Column('password', sa.Text(), nullable=True),
    sa.Column('host_key', sa.Text(), nullable=True),
    sa.Column('service_id', sa.Integer(), nullable=True),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
    sa.ForeignKeyConstraint(['key_id'], ['ssh_keys.id'], ondelete='SET NULL'),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='SET NULL'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_ssh_hosts_service_id'), 'ssh_hosts', ['service_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_ssh_hosts_service_id'), table_name='ssh_hosts')
    op.drop_table('ssh_hosts')
    op.drop_table('ssh_keys')
