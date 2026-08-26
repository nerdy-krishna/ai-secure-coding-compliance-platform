"""Allow pasted-code scans in the scan source-type constraint.

Revision ID: 2b3c4d5e6f70
Revises: 22a0b1c2d3e4
Create Date: 2026-08-26 22:10:00.000000
"""

from typing import Sequence, Union

from alembic import op


revision: str = "2b3c4d5e6f70"
down_revision: Union[str, None] = "22a0b1c2d3e4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_SOURCE_TYPE_CONSTRAINT = (
    "source_type IS NULL OR source_type IN ('upload', 'archive', 'git', 'paste')"
)
_PREVIOUS_SOURCE_TYPE_CONSTRAINT = (
    "source_type IS NULL OR source_type IN ('upload', 'archive', 'git')"
)


def upgrade() -> None:
    """Permit the pasted-code submission path to create scans."""
    op.drop_constraint("ck_scans_source_type", "scans", type_="check")
    op.create_check_constraint("ck_scans_source_type", "scans", _SOURCE_TYPE_CONSTRAINT)


def downgrade() -> None:
    """Restore the historical source-type constraint."""
    op.drop_constraint("ck_scans_source_type", "scans", type_="check")
    op.create_check_constraint(
        "ck_scans_source_type", "scans", _PREVIOUS_SOURCE_TYPE_CONSTRAINT
    )
