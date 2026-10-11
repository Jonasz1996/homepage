"""inloggen via Authentik: het gekoppelde account (uitgever en vaste ID) per gebruiker, niet meer op naam

Revision ID: 0024
Revises: 0023
"""
from datetime import datetime, timezone

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '0024'
down_revision = '0023'
branch_labels = None
depends_on = None

# Onderhoud, een logregel verwijderen en het wachtwoord wijzigen stonden tot nu alleen in de auditlog, en zo op de
# tijdlijn. Voortaan geven ze zelf een melding of gebeurtenis: de tijdlijn toont die oude regels nog tot dit moment
# (routers/timeline.py, LEGACY_KEY).
LEGACY_KEY = 'tijdlijn_audit_tot'


def upgrade() -> None:
    # Niets om over te zetten: de sub stond nergens. Na de update is nog geen account gekoppeld.
    op.add_column('users', sa.Column('oidc_issuer', sa.String(length=300), nullable=True))
    op.add_column('users', sa.Column('oidc_sub', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('oidc_name', sa.String(length=64), nullable=True))
    op.create_unique_constraint('users_oidc_sub_key', 'users', ['oidc_sub'])
    app_state = sa.table('app_state', sa.column('key', sa.String()),
                         sa.column('value', sa.JSON().with_variant(postgresql.JSONB(), 'postgresql')),
                         sa.column('updated_at', sa.DateTime(timezone=True)))
    now = datetime.now(timezone.utc)
    op.bulk_insert(app_state, [{'key': LEGACY_KEY, 'value': {'tot': now.isoformat()}, 'updated_at': now}])


def downgrade() -> None:
    op.execute(sa.text('DELETE FROM app_state WHERE key = :key').bindparams(key=LEGACY_KEY))
    op.drop_constraint('users_oidc_sub_key', 'users', type_='unique')
    op.drop_column('users', 'oidc_name')
    op.drop_column('users', 'oidc_sub')
    op.drop_column('users', 'oidc_issuer')
