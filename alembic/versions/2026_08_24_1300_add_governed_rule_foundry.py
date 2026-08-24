"""Add the tenant-governed AI rule foundry.

Revision ID: 18f0a1b2c3d4
Revises: f4c2b90d7a31
Create Date: 2026-08-24 13:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "18f0a1b2c3d4"
down_revision: Union[str, None] = "f4c2b90d7a31"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "rule_foundry_candidates",
    "rule_foundry_semgrep_candidates",
    "rule_foundry_gitleaks_candidates",
    "rule_foundry_osv_candidates",
    "rule_foundry_versions",
    "rule_foundry_deployments",
    "rule_foundry_shadow_observations",
    "rule_foundry_events",
)


def upgrade() -> None:
    op.create_table(
        "rule_foundry_candidates",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("source_finding_id", sa.BigInteger(), sa.ForeignKey("findings.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_scan_id", sa.UUID(), sa.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True),
        sa.Column("source_attempt_id", sa.UUID(), sa.ForeignKey("scan_attempts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("registry_kind", sa.String(16), nullable=False),
        sa.Column("predicate_kind", sa.String(32), nullable=False),
        sa.Column("static_representable", sa.Boolean(), nullable=False),
        sa.Column("non_representable_reason", sa.Text(), nullable=True),
        sa.Column("stable_identity", sa.String(64), nullable=False),
        sa.Column("status", sa.String(24), server_default="pending_review", nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("cwe", sa.String(50), nullable=True),
        sa.Column("normalized_evidence", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("fixtures", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("creator_user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reviewer_user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("promoter_user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("registry_kind IN ('semgrep', 'gitleaks', 'osv', 'ai_dataflow')", name="ck_rule_foundry_candidate_registry"),
        sa.CheckConstraint("predicate_kind IN ('ast', 'taint', 'dependency_advisory', 'secret_pattern', 'semantic_runtime')", name="ck_rule_foundry_candidate_predicate"),
        sa.CheckConstraint("status IN ('ai_dataflow', 'pending_review', 'rejected', 'approved', 'shadow', 'promoted', 'rolled_back', 'expired', 'review_required')", name="ck_rule_foundry_candidate_status"),
        sa.CheckConstraint("(static_representable AND registry_kind <> 'ai_dataflow' AND non_representable_reason IS NULL) OR (NOT static_representable AND registry_kind = 'ai_dataflow' AND length(non_representable_reason) > 0)", name="ck_rule_foundry_candidate_representability"),
        sa.UniqueConstraint("tenant_id", "registry_kind", "stable_identity", name="uq_rule_foundry_candidate_identity"),
    )
    for column in ("tenant_id", "source_finding_id", "source_scan_id", "source_attempt_id", "registry_kind", "status", "expires_at"):
        op.create_index(f"ix_rule_foundry_candidates_{column}", "rule_foundry_candidates", [column])

    for table, payload_name in (
        ("rule_foundry_semgrep_candidates", "rule"),
        ("rule_foundry_gitleaks_candidates", "rule"),
        ("rule_foundry_osv_candidates", "advisory"),
    ):
        op.create_table(
            table,
            sa.Column("candidate_id", sa.UUID(), sa.ForeignKey("rule_foundry_candidates.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
            sa.Column(payload_name, postgresql.JSONB(), nullable=False),
        )
        op.create_index(f"ix_{table}_tenant_id", table, ["tenant_id"])

    op.create_table(
        "rule_foundry_versions",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("candidate_id", sa.UUID(), sa.ForeignKey("rule_foundry_candidates.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("canonical_payload", postgresql.JSONB(), nullable=False),
        sa.Column("payload_sha256", sa.String(64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column("signature_algorithm", sa.String(64), nullable=False),
        sa.Column("signing_key_id", sa.String(512), nullable=False),
        sa.Column("quality_metrics", postgresql.JSONB(), nullable=False),
        sa.Column("reviewer_decision", postgresql.JSONB(), nullable=False),
        sa.Column("reviewer_user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("version > 0", name="ck_rule_foundry_version_positive"),
        sa.UniqueConstraint("candidate_id", "version", name="uq_rule_foundry_version"),
        sa.UniqueConstraint("tenant_id", "payload_sha256", name="uq_rule_foundry_payload_hash"),
    )
    for column in ("tenant_id", "candidate_id", "payload_sha256"):
        op.create_index(f"ix_rule_foundry_versions_{column}", "rule_foundry_versions", [column])

    op.create_table(
        "rule_foundry_deployments",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("candidate_id", sa.UUID(), sa.ForeignKey("rule_foundry_candidates.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("version_id", sa.UUID(), sa.ForeignKey("rule_foundry_versions.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("prior_version_id", sa.UUID(), sa.ForeignKey("rule_foundry_versions.id", ondelete="RESTRICT"), nullable=True),
        sa.Column("state", sa.String(24), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("shadow_started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("review_due_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("state IN ('shadow', 'promoted', 'rolled_back', 'superseded', 'review_required')", name="ck_rule_foundry_deployment_state"),
    )
    for column in ("tenant_id", "candidate_id", "version_id", "state"):
        op.create_index(f"ix_rule_foundry_deployments_{column}", "rule_foundry_deployments", [column])
    op.create_index(
        "uq_rule_foundry_active_deployment",
        "rule_foundry_deployments",
        ["tenant_id", "candidate_id"],
        unique=True,
        postgresql_where=sa.text("ended_at IS NULL"),
    )

    op.create_table(
        "rule_foundry_shadow_observations",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("deployment_id", sa.UUID(), sa.ForeignKey("rule_foundry_deployments.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("scan_id", sa.UUID(), sa.ForeignKey("scans.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("attempt_id", sa.UUID(), sa.ForeignKey("scan_attempts.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("eligible_files", sa.Integer(), nullable=False),
        sa.Column("unexpected_matches", sa.Integer(), nullable=False),
        sa.Column("evidence_digest", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("eligible_files >= 0 AND eligible_files <= 5000 AND unexpected_matches >= 0 AND unexpected_matches <= eligible_files", name="ck_rule_foundry_shadow_bounds"),
        sa.UniqueConstraint("deployment_id", "attempt_id", name="uq_rule_foundry_shadow_attempt"),
    )
    for column in ("tenant_id", "deployment_id", "scan_id", "attempt_id"):
        op.create_index(f"ix_rule_foundry_shadow_observations_{column}", "rule_foundry_shadow_observations", [column])

    op.create_table(
        "rule_foundry_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), primary_key=True),
        sa.Column("tenant_id", sa.UUID(), sa.ForeignKey("tenants.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("candidate_id", sa.UUID(), sa.ForeignKey("rule_foundry_candidates.id", ondelete="RESTRICT"), nullable=False),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), sa.ForeignKey("user.id", ondelete="SET NULL"), nullable=True),
        sa.Column("reason", sa.String(500), nullable=False),
        sa.Column("details", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    for column in ("tenant_id", "candidate_id", "created_at"):
        op.create_index(f"ix_rule_foundry_events_{column}", "rule_foundry_events", [column])

    _install_tenant_guards()
    _install_immutability_guards()


def _install_tenant_guards() -> None:
    references = {
        "rule_foundry_candidates": (
            ("findings", "id", "source_finding_id"),
            ("scans", "id", "source_scan_id"),
            ("scan_attempts", "id", "source_attempt_id"),
            ("user", "id", "creator_user_id"),
            ("user", "id", "reviewer_user_id"),
            ("user", "id", "promoter_user_id"),
        ),
        "rule_foundry_semgrep_candidates": (("rule_foundry_candidates", "id", "candidate_id"),),
        "rule_foundry_gitleaks_candidates": (("rule_foundry_candidates", "id", "candidate_id"),),
        "rule_foundry_osv_candidates": (("rule_foundry_candidates", "id", "candidate_id"),),
        "rule_foundry_versions": (
            ("rule_foundry_candidates", "id", "candidate_id"),
            ("user", "id", "reviewer_user_id"),
        ),
        "rule_foundry_deployments": (
            ("rule_foundry_candidates", "id", "candidate_id"),
            ("rule_foundry_versions", "id", "version_id"),
            ("rule_foundry_versions", "id", "prior_version_id"),
            ("user", "id", "actor_user_id"),
        ),
        "rule_foundry_shadow_observations": (
            ("rule_foundry_deployments", "id", "deployment_id"),
            ("scans", "id", "scan_id"),
            ("scan_attempts", "id", "attempt_id"),
        ),
        "rule_foundry_events": (
            ("rule_foundry_candidates", "id", "candidate_id"),
            ("user", "id", "actor_user_id"),
        ),
    }
    for table, table_refs in references.items():
        for index, (parent, parent_pk, local_fk) in enumerate(table_refs):
            op.execute(
                f"CREATE TRIGGER sccap_rule_foundry_tenant_reference_{index} "
                f"BEFORE INSERT OR UPDATE OF tenant_id, {local_fk} ON {table} "
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


def _install_immutability_guards() -> None:
    op.execute(
        """
        CREATE FUNCTION sccap_reject_rule_foundry_evidence_mutation()
        RETURNS trigger AS $$ BEGIN
            RAISE EXCEPTION 'rule foundry signed evidence is immutable';
        END; $$ LANGUAGE plpgsql
        """
    )
    for table in (
        "rule_foundry_semgrep_candidates",
        "rule_foundry_gitleaks_candidates",
        "rule_foundry_osv_candidates",
        "rule_foundry_versions",
        "rule_foundry_shadow_observations",
        "rule_foundry_events",
    ):
        op.execute(
            f"CREATE TRIGGER sccap_rule_foundry_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION sccap_reject_rule_foundry_evidence_mutation()"
        )


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS sccap_reject_rule_foundry_evidence_mutation()")
