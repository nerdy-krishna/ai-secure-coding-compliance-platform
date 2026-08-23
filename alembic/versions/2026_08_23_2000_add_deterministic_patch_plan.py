"""add deterministic patch range and hunk lineage

Revision ID: b8c9d0e1f2a3
Revises: a7b8c9d0e1f2
Create Date: 2026-08-23 20:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "b8c9d0e1f2a3"
down_revision: Union[str, None] = "a7b8c9d0e1f2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    columns = (
        sa.Column("resolved_range", postgresql.JSONB(), nullable=True),
        sa.Column("context_fingerprint", sa.String(64), nullable=True),
        sa.Column("patch_hunk_id", sa.UUID(), nullable=True),
        sa.Column(
            "applicability_status",
            sa.String(32),
            server_default="unresolved",
            nullable=False,
        ),
        sa.Column("language", sa.String(64), nullable=True),
        sa.Column("symbol", sa.String(512), nullable=True),
        sa.Column(
            "required_imports",
            postgresql.JSONB(),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "required_dependencies",
            postgresql.JSONB(),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "configuration_changes",
            postgresql.JSONB(),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "migration_changes",
            postgresql.JSONB(),
            server_default="[]",
            nullable=False,
        ),
        sa.Column(
            "manual_steps", postgresql.JSONB(), server_default="[]", nullable=False
        ),
    )
    for column in columns:
        op.add_column("finding_fix_candidates", column)
    op.create_index(
        "ix_finding_fix_candidates_patch_hunk_id",
        "finding_fix_candidates",
        ["patch_hunk_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_finding_fix_candidates_patch_hunk_id",
        table_name="finding_fix_candidates",
    )
    for column in (
        "manual_steps",
        "migration_changes",
        "configuration_changes",
        "required_dependencies",
        "required_imports",
        "symbol",
        "language",
        "applicability_status",
        "patch_hunk_id",
        "context_fingerprint",
        "resolved_range",
    ):
        op.drop_column("finding_fix_candidates", column)
