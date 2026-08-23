"""add governed finding and fix-candidate lineage

Revision ID: a7b8c9d0e1f2
Revises: f6a1b2c3d4e5
Create Date: 2026-08-23 18:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "a7b8c9d0e1f2"
down_revision: Union[str, None] = "f6a1b2c3d4e5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("raw_finding_id", sa.UUID(), nullable=True))
    op.add_column(
        "findings", sa.Column("canonical_finding_id", sa.UUID(), nullable=True)
    )
    op.add_column(
        "findings",
        sa.Column(
            "contributing_raw_finding_ids",
            postgresql.ARRAY(sa.UUID()),
            nullable=True,
        ),
    )
    op.add_column(
        "findings", sa.Column("source_snapshot_hash", sa.String(64), nullable=True)
    )
    op.add_column(
        "findings", sa.Column("fix_selection_status", sa.String(32), nullable=True)
    )
    op.create_index("ix_findings_raw_finding_id", "findings", ["raw_finding_id"])
    op.create_index(
        "ix_findings_canonical_finding_id", "findings", ["canonical_finding_id"]
    )
    op.create_index(
        "ix_findings_source_snapshot_hash", "findings", ["source_snapshot_hash"]
    )

    op.create_table(
        "finding_fix_candidates",
        sa.Column("candidate_id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("raw_finding_id", sa.UUID(), nullable=False),
        sa.Column("canonical_finding_id", sa.UUID(), nullable=True),
        sa.Column("source_snapshot_hash", sa.String(64), nullable=False),
        sa.Column("anchor_fingerprint", sa.String(64), nullable=False),
        sa.Column("patch_fingerprint", sa.String(64), nullable=False),
        sa.Column("file_path", sa.Text(), nullable=False),
        sa.Column("line_number", sa.Integer(), nullable=False),
        sa.Column(
            "suggestion", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column("disposition", sa.String(20), nullable=False),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column(
            "contributing_agents",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column(
            "contributing_models",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("validation_status", sa.String(20), nullable=False),
        sa.Column("is_applied", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("batch", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "disposition IN ('pending', 'selected', 'alternative', 'duplicate', 'conflict', 'rejected')",
            name="ck_finding_fix_candidates_disposition",
        ),
        sa.CheckConstraint(
            "validation_status IN ('not_run', 'passed', 'failed')",
            name="ck_finding_fix_candidates_validation_status",
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("candidate_id"),
    )
    op.create_index(
        "ix_finding_fix_candidates_scan_id", "finding_fix_candidates", ["scan_id"]
    )
    op.create_index(
        "ix_finding_fix_candidates_raw_finding_id",
        "finding_fix_candidates",
        ["raw_finding_id"],
    )
    op.create_index(
        "ix_finding_fix_candidates_canonical_finding_id",
        "finding_fix_candidates",
        ["canonical_finding_id"],
    )


def downgrade() -> None:
    op.drop_table("finding_fix_candidates")
    op.drop_index("ix_findings_source_snapshot_hash", table_name="findings")
    op.drop_index("ix_findings_canonical_finding_id", table_name="findings")
    op.drop_index("ix_findings_raw_finding_id", table_name="findings")
    op.drop_column("findings", "fix_selection_status")
    op.drop_column("findings", "source_snapshot_hash")
    op.drop_column("findings", "canonical_finding_id")
    op.drop_column("findings", "contributing_raw_finding_ids")
    op.drop_column("findings", "raw_finding_id")
