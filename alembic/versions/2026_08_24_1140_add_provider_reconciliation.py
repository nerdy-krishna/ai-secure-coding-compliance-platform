"""Add provider usage and cost reconciliation evidence.

Revision ID: a8f2c7d91e44
Revises: d4e71a9c6b20
Create Date: 2026-08-24 11:40:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "a8f2c7d91e44"
down_revision: Union[str, None] = "d4e71a9c6b20"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "provider_billing_connectors",
    "provider_reconciliation_runs",
    "provider_reconciliation_evidence",
    "provider_reconciliation_adjustments",
    "provider_reconciliation_alert_outbox",
)


def upgrade() -> None:
    op.create_table(
        "provider_billing_connectors",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("provider", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(100), nullable=False),
        sa.Column("credentials_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("provider_project_ids", postgresql.ARRAY(sa.String(255)), server_default="{}", nullable=False),
        sa.Column("verified_scopes", postgresql.ARRAY(sa.String(100)), server_default="{}", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.false(), nullable=False),
        sa.Column("absolute_tolerance_micro_usd", sa.BigInteger(), server_default="1000", nullable=False),
        sa.Column("percentage_tolerance", sa.Numeric(7, 4), server_default="1.0000", nullable=False),
        sa.Column("lookback_minutes", sa.Integer(), server_default="180", nullable=False),
        sa.Column("poll_interval_minutes", sa.Integer(), server_default="60", nullable=False),
        sa.Column("next_run_at", sa.DateTime(timezone=True)),
        sa.Column("last_run_at", sa.DateTime(timezone=True)),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("provider IN ('openai')", name="ck_provider_billing_connector_provider"),
        sa.CheckConstraint("absolute_tolerance_micro_usd >= 0", name="ck_provider_billing_connector_absolute_tolerance"),
        sa.CheckConstraint("percentage_tolerance >= 0 AND percentage_tolerance <= 100", name="ck_provider_billing_connector_percentage_tolerance"),
        sa.CheckConstraint("lookback_minutes BETWEEN 0 AND 10080", name="ck_provider_billing_connector_lookback"),
        sa.CheckConstraint("poll_interval_minutes BETWEEN 15 AND 10080", name="ck_provider_billing_connector_poll"),
        sa.UniqueConstraint("tenant_id", "provider", "display_name", name="uq_provider_billing_connector_name"),
    )
    op.create_index("ix_provider_billing_connectors_tenant_id", "provider_billing_connectors", ["tenant_id"])
    op.create_index("ix_provider_billing_connectors_next_run_at", "provider_billing_connectors", ["next_run_at"])

    op.create_table(
        "provider_reconciliation_runs",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("connector_id", sa.UUID(), sa.ForeignKey("provider_billing_connectors.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("idempotency_key", sa.String(512), nullable=False, unique=True),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("trigger_kind", sa.String(16), nullable=False),
        sa.Column("canonical_micro_usd", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("provider_micro_usd", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("variance_micro_usd", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("unresolved_micro_usd", sa.BigInteger(), server_default="0", nullable=False),
        sa.Column("coverage_percent", sa.Numeric(7, 4), server_default="0", nullable=False),
        sa.Column("compared_dimensions", sa.Integer(), server_default="0", nullable=False),
        sa.Column("unresolved_dimensions", sa.Integer(), server_default="0", nullable=False),
        sa.Column("provider_pages", sa.Integer(), server_default="0", nullable=False),
        sa.Column("error_code", sa.String(64)),
        sa.Column("created_by_user_id", sa.Integer()),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('completed', 'failed')", name="ck_provider_reconciliation_run_status"),
        sa.CheckConstraint("window_end > window_start", name="ck_provider_reconciliation_run_window"),
        sa.CheckConstraint("trigger_kind IN ('manual', 'scheduled')", name="ck_provider_reconciliation_run_trigger"),
        sa.CheckConstraint("coverage_percent >= 0 AND coverage_percent <= 100", name="ck_provider_reconciliation_run_coverage"),
    )
    op.create_index("ix_provider_reconciliation_runs_tenant_id", "provider_reconciliation_runs", ["tenant_id"])
    op.create_index("ix_provider_reconciliation_runs_connector_id", "provider_reconciliation_runs", ["connector_id"])
    op.create_index("ix_provider_reconciliation_runs_completed_at", "provider_reconciliation_runs", ["completed_at"])

    op.create_table(
        "provider_reconciliation_evidence",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("run_id", sa.UUID(), sa.ForeignKey("provider_reconciliation_runs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("dimension_key", sa.String(64), nullable=False),
        sa.Column("classification", sa.String(40), nullable=False),
        sa.Column("canonical_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column("provider_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column("variance_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column("within_tolerance", sa.Boolean(), nullable=False),
        sa.Column("canonical_tokens", postgresql.JSONB(), nullable=False),
        sa.Column("provider_tokens", postgresql.JSONB(), nullable=False),
        sa.Column("normalized_dimensions", postgresql.JSONB(), nullable=False),
        sa.Column("provider_item_ids", postgresql.ARRAY(sa.String(255)), server_default="{}", nullable=False),
        sa.Column("details", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "classification IN ('matched', 'missing_event', 'duplicate_event', "
            "'token_category_mismatch', 'price_catalog_mismatch', "
            "'provider_adjustment_credit', 'timing_lag', 'unresolved')",
            name="ck_provider_reconciliation_evidence_classification",
        ),
        sa.UniqueConstraint("run_id", "dimension_key", name="uq_provider_reconciliation_evidence_dimension"),
    )
    op.create_index("ix_provider_reconciliation_evidence_tenant_id", "provider_reconciliation_evidence", ["tenant_id"])
    op.create_index("ix_provider_reconciliation_evidence_run_id", "provider_reconciliation_evidence", ["run_id"])
    op.create_index("ix_provider_reconciliation_evidence_classification", "provider_reconciliation_evidence", ["classification"])

    op.create_table(
        "provider_reconciliation_adjustments",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("run_id", sa.UUID(), sa.ForeignKey("provider_reconciliation_runs.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("evidence_id", sa.UUID(), sa.ForeignKey("provider_reconciliation_evidence.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("kind", sa.String(40), nullable=False),
        sa.Column("amount_micro_usd", sa.BigInteger(), nullable=False),
        sa.Column("currency", sa.String(3), server_default="USD", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("kind IN ('provider_adjustment_credit', 'timing_lag')", name="ck_provider_reconciliation_adjustment_kind"),
    )
    op.create_index("ix_provider_reconciliation_adjustments_tenant_id", "provider_reconciliation_adjustments", ["tenant_id"])
    op.create_index("ix_provider_reconciliation_adjustments_run_id", "provider_reconciliation_adjustments", ["run_id"])

    op.create_table(
        "provider_reconciliation_alert_outbox",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("run_id", sa.UUID(), sa.ForeignKey("provider_reconciliation_runs.id", ondelete="RESTRICT"), nullable=False, unique=True),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
        sa.Column("state", sa.String(16), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True)),
        sa.Column("error", sa.Text()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("state IN ('pending', 'published', 'failed')", name="ck_provider_reconciliation_alert_state"),
    )
    op.create_index("ix_provider_reconciliation_alert_outbox_tenant_id", "provider_reconciliation_alert_outbox", ["tenant_id"])

    references = {
        "provider_billing_connectors": (("user", "id", "created_by_user_id"),),
        "provider_reconciliation_runs": (
            ("provider_billing_connectors", "id", "connector_id"),
            ("user", "id", "created_by_user_id"),
        ),
        "provider_reconciliation_evidence": (("provider_reconciliation_runs", "id", "run_id"),),
        "provider_reconciliation_adjustments": (
            ("provider_reconciliation_runs", "id", "run_id"),
            ("provider_reconciliation_evidence", "id", "evidence_id"),
        ),
        "provider_reconciliation_alert_outbox": (("provider_reconciliation_runs", "id", "run_id"),),
    }
    for table, table_refs in references.items():
        for index, (parent, parent_pk, local_fk) in enumerate(table_refs):
            op.execute(
                f"CREATE TRIGGER sccap_tenant_reference_{index} BEFORE INSERT OR UPDATE OF tenant_id, {local_fk} ON {table} "
                f"FOR EACH ROW EXECUTE FUNCTION sccap_enforce_tenant_reference('{parent}', '{parent_pk}', '{local_fk}')"
            )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY sccap_tenant_isolation ON {table} "
            "USING (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id()) "
            "WITH CHECK (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())"
        )

    op.execute(
        """
        CREATE FUNCTION sccap_reject_provider_reconciliation_mutation()
        RETURNS trigger AS $$ BEGIN
            RAISE EXCEPTION 'provider reconciliation evidence is immutable';
        END; $$ LANGUAGE plpgsql
        """
    )
    for table in (
        "provider_reconciliation_runs",
        "provider_reconciliation_evidence",
        "provider_reconciliation_adjustments",
    ):
        op.execute(
            f"CREATE TRIGGER sccap_provider_reconciliation_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION sccap_reject_provider_reconciliation_mutation()"
        )


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS sccap_reject_provider_reconciliation_mutation()")
