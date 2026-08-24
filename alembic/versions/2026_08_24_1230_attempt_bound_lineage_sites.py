"""Bind exact finding-site idempotency to one scan attempt.

Revision ID: e6a4c83f2d19
Revises: d8f3a21c7b04
Create Date: 2026-08-24 12:30:00
"""

from typing import Sequence, Union

from alembic import op


revision: str = "e6a4c83f2d19"
down_revision: Union[str, None] = "d8f3a21c7b04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_constraint(
        "uq_finding_lineage_scan_fingerprint_state_site",
        "finding_lineage_records",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_finding_lineage_attempt_fingerprint_state_site",
        "finding_lineage_records",
        [
            "scan_id",
            "attempt_id",
            "fingerprint",
            "baseline_state",
            "site_identity",
        ],
    )


def downgrade() -> None:
    op.execute(
        "ALTER TABLE finding_lineage_records DISABLE TRIGGER "
        "sccap_finding_governance_immutable"
    )
    try:
        op.execute(
            """
            DELETE FROM finding_lineage_records
            WHERE id IN (
              SELECT id
              FROM (
                SELECT
                  id,
                  row_number() OVER (
                    PARTITION BY scan_id, fingerprint, baseline_state, site_identity
                    ORDER BY created_at NULLS LAST, id
                  ) AS occurrence
                FROM finding_lineage_records
              ) ranked
              WHERE occurrence > 1
            )
            """
        )
    finally:
        op.execute(
            "ALTER TABLE finding_lineage_records ENABLE TRIGGER "
            "sccap_finding_governance_immutable"
        )
    op.drop_constraint(
        "uq_finding_lineage_attempt_fingerprint_state_site",
        "finding_lineage_records",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_finding_lineage_scan_fingerprint_state_site",
        "finding_lineage_records",
        ["scan_id", "fingerprint", "baseline_state", "site_identity"],
    )
