"""Preserve every exact finding site in governance lineage.

Revision ID: d8f3a21c7b04
Revises: b7e19c4d2a60
Create Date: 2026-08-24 12:00:00
"""

import hashlib
import json
from typing import Any, Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "d8f3a21c7b04"
down_revision: Union[str, None] = "b7e19c4d2a60"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _site_identity(
    *,
    canonical_finding_id: Any,
    raw_finding_id: Any,
    exact_ranges: list[dict[str, Any]],
    fallback_identity: Any,
) -> str:
    """Mirror app.shared.lib.finding_governance.finding_site_identity."""
    canonical_identity = canonical_finding_id or raw_finding_id
    if canonical_identity is None:
        canonical_identity = (
            f"legacy:{fallback_identity}"
            if not exact_ranges and fallback_identity is not None
            else "legacy"
        )
    payload = json.dumps(
        ["finding-site-v1", str(canonical_identity), exact_ranges],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def upgrade() -> None:
    op.add_column(
        "finding_lineage_records",
        sa.Column("site_identity", sa.String(length=64), nullable=True),
    )
    connection = op.get_bind()
    op.execute(
        "ALTER TABLE finding_lineage_records DISABLE TRIGGER "
        "sccap_finding_governance_immutable"
    )
    try:
        last_id = None
        while True:
            # Keyset batches deliberately materialize and close each SELECT
            # before updating the table. PostgreSQL rejects later ALTER TABLE
            # operations while an asyncpg server-side cursor is still active.
            batch = connection.execute(
                sa.text(
                    """
                    SELECT id, finding_id, predecessor_finding_id, exact_ranges,
                           producer_provenance
                    FROM finding_lineage_records
                    WHERE CAST(id AS text) > COALESCE(:last_id, '')
                    ORDER BY CAST(id AS text)
                    LIMIT 500
                    """
                ),
                {"last_id": last_id},
            ).all()
            if not batch:
                break
            for row in batch:
                producer = row.producer_provenance or {}
                ranges = row.exact_ranges or []
                site_identity = _site_identity(
                    canonical_finding_id=producer.get("canonical_finding_id"),
                    raw_finding_id=producer.get("raw_finding_id"),
                    exact_ranges=ranges,
                    fallback_identity=(
                        row.id
                        if row.finding_id is None
                        and row.predecessor_finding_id is None
                        and not ranges
                        else None
                    ),
                )
                connection.execute(
                    sa.text(
                        """
                        UPDATE finding_lineage_records
                        SET site_identity = :site_identity
                        WHERE id = :record_id
                        """
                    ),
                    {"site_identity": site_identity, "record_id": row.id},
                )
            last_id = str(batch[-1].id)
    finally:
        op.execute(
            "ALTER TABLE finding_lineage_records ENABLE TRIGGER "
            "sccap_finding_governance_immutable"
        )
    op.alter_column("finding_lineage_records", "site_identity", nullable=False)
    op.drop_constraint(
        "uq_finding_lineage_scan_fingerprint_state",
        "finding_lineage_records",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_finding_lineage_scan_fingerprint_state_site",
        "finding_lineage_records",
        ["scan_id", "fingerprint", "baseline_state", "site_identity"],
    )


def downgrade() -> None:
    # Multiple exact sites can share one baseline fingerprint. Collapse only
    # on explicit downgrade so the legacy unique constraint can be restored.
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
                    PARTITION BY scan_id, fingerprint, baseline_state
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
        "uq_finding_lineage_scan_fingerprint_state_site",
        "finding_lineage_records",
        type_="unique",
    )
    op.create_unique_constraint(
        "uq_finding_lineage_scan_fingerprint_state",
        "finding_lineage_records",
        ["scan_id", "fingerprint", "baseline_state"],
    )
    op.drop_column("finding_lineage_records", "site_identity")
