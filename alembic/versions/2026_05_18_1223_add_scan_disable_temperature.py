"""add scan disable_temperature

Revision ID: 477e6b947014
Revises: a3f1c7d9e2b4
Create Date: 2026-05-18 12:23:07.916765

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '477e6b947014'
down_revision: Union[str, None] = 'a3f1c7d9e2b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Adds the opt-in `scans.disable_temperature` flag (#92 / PRD #91).
    The autogenerate diff also surfaced unrelated index drops (GIN /
    partial / expression indexes created by raw SQL in earlier
    migrations that the ORM models don't declare) — those are NOT this
    migration's concern and are intentionally omitted.
    """
    op.add_column(
        'scans',
        sa.Column(
            'disable_temperature',
            sa.Boolean(),
            server_default='false',
            nullable=False,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'disable_temperature')
