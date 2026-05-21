"""drop sarif_report + impact_report from scans

Revision ID: 0272e97e4cfb
Revises: 3fe63a5312ee
Create Date: 2026-04-25 20:03:48.624459

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "0272e97e4cfb"
down_revision: Union[str, None] = "3fe63a5312ee"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Drops the two JSONB columns the discontinued ImpactReportingAgent /
    SARIF generation node used to populate. Autogenerate also flagged
    `ix_scan_outbox_unpublished` and `ix_user_group_memberships_user_id`
    for removal — both are partial / explicit indexes Alembic doesn't
    detect, kept manually.
    """
    op.drop_column("scans", "impact_report")
    op.drop_column("scans", "sarif_report")


def downgrade() -> None:
    """Downgrade schema."""
    op.add_column(
        "scans",
        sa.Column(
            "sarif_report",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
    )
    op.add_column(
        "scans",
        sa.Column(
            "impact_report",
            postgresql.JSONB(astext_type=sa.Text()),
            autoincrement=False,
            nullable=True,
        ),
    )
