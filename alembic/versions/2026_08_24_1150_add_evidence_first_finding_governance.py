"""Add evidence-first finding lineage, waivers, and policy gates.

Revision ID: b7e19c4d2a60
Revises: a8f2c7d91e44
Create Date: 2026-08-24 11:50:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "b7e19c4d2a60"
down_revision: Union[str, None] = "a8f2c7d91e44"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "finding_lineage_records",
    "finding_policy_versions",
    "finding_policy_evaluations",
    "finding_waivers",
    "finding_waiver_events",
)


def upgrade() -> None:
    op.create_table(
        "finding_lineage_records",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            sa.UUID(),
            sa.ForeignKey("projects.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            sa.UUID(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "attempt_id",
            sa.UUID(),
            sa.ForeignKey("scan_attempts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "finding_id",
            sa.BigInteger(),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "predecessor_finding_id",
            sa.BigInteger(),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("baseline_state", sa.String(16), nullable=False),
        sa.Column(
            "exact_ranges", postgresql.JSONB(), server_default="[]", nullable=False
        ),
        sa.Column("dataflow", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column(
            "source_provenance", postgresql.JSONB(), server_default="{}", nullable=False
        ),
        sa.Column(
            "producer_provenance",
            postgresql.JSONB(),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "coverage_entry_ids",
            postgresql.ARRAY(sa.UUID()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "evidence_object_ids",
            postgresql.ARRAY(sa.UUID()),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "remediation_state", postgresql.JSONB(), server_default="{}", nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "baseline_state IN ('new', 'fixed', 'unchanged', 'reintroduced')",
            name="ck_finding_lineage_baseline_state",
        ),
        sa.UniqueConstraint(
            "scan_id",
            "fingerprint",
            "baseline_state",
            name="uq_finding_lineage_scan_fingerprint_state",
        ),
    )
    for column in (
        "tenant_id",
        "project_id",
        "scan_id",
        "attempt_id",
        "finding_id",
        "fingerprint",
        "baseline_state",
        "created_at",
    ):
        op.create_index(
            f"ix_finding_lineage_records_{column}", "finding_lineage_records", [column]
        )

    op.create_table(
        "finding_policy_versions",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("minimum_severity", sa.String(16), nullable=False),
        sa.Column("minimum_confidence", sa.String(16), nullable=False),
        sa.Column("require_complete_coverage", sa.Boolean(), nullable=False),
        sa.Column("allow_waivers", sa.Boolean(), nullable=False),
        sa.Column("minimum_waiver_remaining_hours", sa.Integer(), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "minimum_severity IN ('informational', 'low', 'medium', 'high', 'critical')",
            name="ck_finding_policy_minimum_severity",
        ),
        sa.CheckConstraint(
            "minimum_confidence IN ('low', 'medium', 'high')",
            name="ck_finding_policy_minimum_confidence",
        ),
        sa.CheckConstraint(
            "minimum_waiver_remaining_hours >= 0", name="ck_finding_policy_waiver_hours"
        ),
        sa.UniqueConstraint(
            "tenant_id", "version", name="uq_finding_policy_tenant_version"
        ),
    )
    op.create_index(
        "ix_finding_policy_versions_tenant_id", "finding_policy_versions", ["tenant_id"]
    )

    op.create_table(
        "finding_policy_evaluations",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            sa.UUID(),
            sa.ForeignKey("projects.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            sa.UUID(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "attempt_id",
            sa.UUID(),
            sa.ForeignKey("scan_attempts.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "policy_version_id",
            sa.UUID(),
            sa.ForeignKey("finding_policy_versions.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("outcome", sa.String(8), nullable=False),
        sa.Column("coverage_complete", sa.Boolean(), nullable=False),
        sa.Column(
            "blocking_fingerprints",
            postgresql.ARRAY(sa.String(64)),
            server_default="{}",
            nullable=False,
        ),
        sa.Column(
            "waived_fingerprints",
            postgresql.ARRAY(sa.String(64)),
            server_default="{}",
            nullable=False,
        ),
        sa.Column("details", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('pass', 'fail')", name="ck_finding_policy_evaluation_outcome"
        ),
    )
    for column in ("tenant_id", "project_id", "scan_id", "attempt_id", "created_at"):
        op.create_index(
            f"ix_finding_policy_evaluations_{column}",
            "finding_policy_evaluations",
            [column],
        )

    op.create_table(
        "finding_waivers",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "project_id",
            sa.UUID(),
            sa.ForeignKey("projects.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "scan_id",
            sa.UUID(),
            sa.ForeignKey("scans.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "finding_id",
            sa.BigInteger(),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("scope_value", sa.String(255), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "scope IN ('finding', 'fingerprint', 'project')",
            name="ck_finding_waiver_scope",
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name="ck_finding_waiver_future_expiry"
        ),
    )
    for column in (
        "tenant_id",
        "project_id",
        "scan_id",
        "finding_id",
        "fingerprint",
        "expires_at",
    ):
        op.create_index(f"ix_finding_waivers_{column}", "finding_waivers", [column])

    op.create_table(
        "finding_waiver_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column(
            "tenant_id",
            sa.UUID(),
            sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "waiver_id",
            sa.UUID(),
            sa.ForeignKey("finding_waivers.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("action", sa.String(16), nullable=False),
        sa.Column(
            "actor_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "action IN ('granted', 'revoked', 'expired')",
            name="ck_finding_waiver_event_action",
        ),
        sa.UniqueConstraint(
            "waiver_id", "action", name="uq_finding_waiver_event_action"
        ),
    )
    op.create_index(
        "ix_finding_waiver_events_tenant_id", "finding_waiver_events", ["tenant_id"]
    )
    op.create_index(
        "ix_finding_waiver_events_waiver_id", "finding_waiver_events", ["waiver_id"]
    )

    references = {
        "finding_lineage_records": (
            ("projects", "id", "project_id"),
            ("scans", "id", "scan_id"),
            ("scan_attempts", "id", "attempt_id"),
            ("findings", "id", "finding_id"),
            ("findings", "id", "predecessor_finding_id"),
        ),
        "finding_policy_versions": (("user", "id", "actor_user_id"),),
        "finding_policy_evaluations": (
            ("projects", "id", "project_id"),
            ("scans", "id", "scan_id"),
            ("scan_attempts", "id", "attempt_id"),
            ("finding_policy_versions", "id", "policy_version_id"),
        ),
        "finding_waivers": (
            ("projects", "id", "project_id"),
            ("scans", "id", "scan_id"),
            ("findings", "id", "finding_id"),
            ("user", "id", "actor_user_id"),
        ),
        "finding_waiver_events": (
            ("finding_waivers", "id", "waiver_id"),
            ("user", "id", "actor_user_id"),
        ),
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
        CREATE FUNCTION sccap_reject_finding_governance_mutation()
        RETURNS trigger AS $$ BEGIN
            -- Foreign-key SET NULL actions preserve the governance tombstone
            -- when an owning scan/finding is deleted. They execute nested.
            IF pg_trigger_depth() > 1 THEN
                RETURN NEW;
            END IF;
            RAISE EXCEPTION 'finding governance evidence is immutable';
        END; $$ LANGUAGE plpgsql
        """
    )
    for table in TENANT_TABLES:
        op.execute(
            f"CREATE TRIGGER sccap_finding_governance_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION sccap_reject_finding_governance_mutation()"
        )


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS sccap_reject_finding_governance_mutation()")
