"""add cross-file validation columns

Revision ID: 388ccefe9a20
Revises: 5c2a9e0b3f18
Create Date: 2026-05-18 09:35:02.000061

Opt-in cross-file finding validation (#81 / PRD #75):
- scans.cross_file_validation — opt-in flag, default false.
- findings.cross_file_status / cross_file_rationale — the per-finding
  verdict and its justification; NULL when the scan did not opt in.

Only these three column additions are applied. The spurious
index-drop operations Alembic autogenerate proposed (partial / GIN
indexes it does not model) are intentionally omitted.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "388ccefe9a20"
down_revision: Union[str, None] = "5c2a9e0b3f18"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scans",
        sa.Column(
            "cross_file_validation",
            sa.Boolean(),
            server_default="false",
            nullable=False,
        ),
    )
    op.add_column(
        "findings",
        sa.Column("cross_file_status", sa.String(length=20), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("cross_file_rationale", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("findings", "cross_file_rationale")
    op.drop_column("findings", "cross_file_status")
    op.drop_column("scans", "cross_file_validation")
