"""add finding detected_by_llms

Revision ID: 1c658ded0a81
Revises: 396e6b152252
Create Date: 2026-05-18 13:42:43.159904

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '1c658ded0a81'
down_revision: Union[str, None] = '396e6b152252'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Adds the nullable `findings.detected_by_llms` provenance column
    (#94 / PRD #91). Unrelated index drops surfaced by autogenerate
    (GIN / partial / expression indexes created by raw SQL in earlier
    migrations) are intentionally omitted.
    """
    op.add_column(
        'findings',
        sa.Column(
            'detected_by_llms',
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'detected_by_llms')
