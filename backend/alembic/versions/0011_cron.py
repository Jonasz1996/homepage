"""cron: geplande taken van alle machines en hun runs

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None

Json = sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')


def upgrade() -> None:
    op.create_table(
        'cron_jobs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('key', sa.String(length=200), nullable=False),
        sa.Column('target', sa.String(length=80), nullable=False),
        sa.Column('target_name', sa.String(length=120), nullable=False),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('ssh_hosts.id', ondelete='SET NULL'), nullable=True),
        sa.Column('vmid', sa.Integer(), nullable=True),
        sa.Column('kind', sa.String(length=16), nullable=False),
        sa.Column('source', sa.String(length=255), nullable=False),
        sa.Column('user', sa.String(length=64), nullable=False),
        sa.Column('schedule', sa.String(length=200), nullable=False),
        sa.Column('sched_type', sa.String(length=12), nullable=False),
        sa.Column('command', sa.Text(), nullable=False),
        sa.Column('raw', sa.Text(), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=False),
        sa.Column('alias', sa.String(length=120), nullable=True),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('system', sa.Boolean(), nullable=False),
        sa.Column('wid', sa.String(length=16), nullable=True),
        sa.Column('monitored', sa.Boolean(), nullable=False),
        sa.Column('muted', sa.Boolean(), nullable=False),
        sa.Column('targets', Json, nullable=False),
        sa.Column('extra', Json, nullable=False),
        sa.Column('tz', sa.String(length=64), nullable=False),
        sa.Column('next_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_status', sa.String(length=12), nullable=True),
        sa.Column('last_exit', sa.Integer(), nullable=True),
        sa.Column('last_duration', sa.Float(), nullable=True),
        sa.Column('runs_24h', sa.Integer(), nullable=False),
        sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
        sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('key'),
    )
    op.create_index('ix_cron_jobs_target', 'cron_jobs', ['target'])
    op.create_index('ix_cron_jobs_host_id', 'cron_jobs', ['host_id'])
    op.create_index('ix_cron_jobs_wid', 'cron_jobs', ['wid'])
    op.create_table(
        'cron_runs',
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('job_id', sa.Integer(), sa.ForeignKey('cron_jobs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('ended_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('exit_code', sa.Integer(), nullable=True),
        sa.Column('status', sa.String(length=12), nullable=False),
        sa.Column('trigger', sa.String(length=12), nullable=False),
        sa.Column('output', sa.Text(), nullable=True),
    )
    op.create_index('ix_cron_runs_job_started', 'cron_runs', ['job_id', 'started_at'], unique=True)


def downgrade() -> None:
    op.drop_index('ix_cron_runs_job_started', table_name='cron_runs')
    op.drop_table('cron_runs')
    op.drop_index('ix_cron_jobs_wid', table_name='cron_jobs')
    op.drop_index('ix_cron_jobs_host_id', table_name='cron_jobs')
    op.drop_index('ix_cron_jobs_target', table_name='cron_jobs')
    op.drop_table('cron_jobs')
