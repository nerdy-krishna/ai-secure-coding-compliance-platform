"""add stable scanner rule identity to findings

Revision ID: c9d0e1f2a3b4
Revises: b8c9d0e1f2a3
Create Date: 2026-08-23 22:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "c9d0e1f2a3b4"
down_revision: Union[str, None] = "b8c9d0e1f2a3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("scanner_rule_id", sa.String(512), nullable=True),
    )
    op.create_index(
        "ix_findings_scanner_rule_id",
        "findings",
        ["scanner_rule_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_findings_scanner_rule_id", table_name="findings")
    op.drop_column("findings", "scanner_rule_id")
