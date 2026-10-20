"""ssh: mappen en hosts uit Proxmox

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('ssh_hosts', sa.Column('folder', sa.String(length=80), nullable=False, server_default=''))
    # Herkomst bij automatisch ophalen, bv. "pve:3:lxc/105" (service 3, container 105); leeg = zelf toegevoegd.
    op.add_column('ssh_hosts', sa.Column('source', sa.String(length=80), nullable=True))
    op.create_index('ix_ssh_hosts_source', 'ssh_hosts', ['source'], unique=True)


def downgrade() -> None:
    op.drop_index('ix_ssh_hosts_source', table_name='ssh_hosts')
    op.drop_column('ssh_hosts', 'source')
    op.drop_column('ssh_hosts', 'folder')
