"""Reconcile genuine schema gaps exposed by complete model metadata.

Revision ID: 5e6f7081a2b3
Revises: 4d5e6f708192
Create Date: 2026-08-28 01:00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa


revision: str = "5e6f7081a2b3"
down_revision: str = "4d5e6f708192"
branch_labels: None = None
depends_on: None = None


def _add_validated_check(table: str, name: str, expression: str) -> None:
    op.execute(
        sa.text(
            f"ALTER TABLE {table} ADD CONSTRAINT {name} "
            f"CHECK ({expression}) NOT VALID"
        )
    )
    op.execute(sa.text(f"ALTER TABLE {table} VALIDATE CONSTRAINT {name}"))


def upgrade() -> None:
    """Add missing protections and align stable constraint identities."""

    op.create_index(
        "ix_integration_outbox_expired_lease",
        "integration_outbox",
        ["lease_expires_at"],
        postgresql_where=sa.text("state = 'delivering'"),
    )

    _add_validated_check(
        "provider_reconciliation_adjustments",
        "ck_provider_reconciliation_adjustment_kind",
        "kind IN ('provider_adjustment_credit', 'timing_lag')",
    )
    _add_validated_check(
        "provider_reconciliation_evidence",
        "ck_provider_reconciliation_evidence_classification",
        "classification IN ('matched', 'missing_event', 'duplicate_event', "
        "'token_category_mismatch', 'price_catalog_mismatch', "
        "'provider_adjustment_credit', 'timing_lag', 'unresolved')",
    )
    _add_validated_check(
        "provider_reconciliation_runs",
        "ck_provider_reconciliation_run_coverage",
        "coverage_percent >= 0 AND coverage_percent <= 100",
    )
    _add_validated_check(
        "provider_reconciliation_runs",
        "ck_provider_reconciliation_run_trigger",
        "trigger_kind IN ('manual', 'scheduled')",
    )

    op.execute(
        "ALTER TABLE provider_reconciliation_alert_outbox "
        "RENAME CONSTRAINT provider_reconciliation_alert_outbox_run_id_key "
        "TO uq_provider_reconciliation_alert_run"
    )
    op.execute(
        "ALTER TABLE provider_reconciliation_runs "
        "RENAME CONSTRAINT provider_reconciliation_runs_idempotency_key_key "
        "TO uq_provider_reconciliation_run_key"
    )


def downgrade() -> None:
    """Restore the pre-reconciliation names and protections."""

    op.execute(
        "ALTER TABLE provider_reconciliation_runs "
        "RENAME CONSTRAINT uq_provider_reconciliation_run_key "
        "TO provider_reconciliation_runs_idempotency_key_key"
    )
    op.execute(
        "ALTER TABLE provider_reconciliation_alert_outbox "
        "RENAME CONSTRAINT uq_provider_reconciliation_alert_run "
        "TO provider_reconciliation_alert_outbox_run_id_key"
    )
    op.drop_constraint(
        "ck_provider_reconciliation_run_trigger",
        "provider_reconciliation_runs",
        type_="check",
    )
    op.drop_constraint(
        "ck_provider_reconciliation_run_coverage",
        "provider_reconciliation_runs",
        type_="check",
    )
    op.drop_constraint(
        "ck_provider_reconciliation_evidence_classification",
        "provider_reconciliation_evidence",
        type_="check",
    )
    op.drop_constraint(
        "ck_provider_reconciliation_adjustment_kind",
        "provider_reconciliation_adjustments",
        type_="check",
    )
    op.drop_index(
        "ix_integration_outbox_expired_lease",
        table_name="integration_outbox",
    )
