"""PostgreSQL schema objects that supplement the ORM class declarations.

These objects are part of the durable database contract but are awkward or
misleading as ``mapped_column`` options: partial, descending, and GIN indexes;
legacy checks; and the offline bundle activation ledger, which has no runtime
ORM repository. Alembic loads this registry after every mapped model module so
autogenerate compares the complete intended schema instead of proposing
destructive drops.
"""

from __future__ import annotations

from collections.abc import Iterable

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID

from app.infrastructure.database.base import Base


_TOKEN_AMOUNT_NAMES = (
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "uncached_input_tokens",
    "billable_tokens",
    "usd",
    "provider_requests",
)


def _nonnegative(prefix: str) -> str:
    return " AND ".join(f"{prefix}_{name} >= 0" for name in _TOKEN_AMOUNT_NAMES)


def _table(name: str) -> sa.Table:
    return Base.metadata.tables[name]


def _add_check(table_name: str, name: str, expression: str) -> None:
    table = _table(table_name)
    if any(constraint.name == name for constraint in table.constraints):
        return
    table.append_constraint(sa.CheckConstraint(expression, name=name))


def _add_index(
    table_name: str,
    name: str,
    columns: Iterable[str],
    *,
    unique: bool = False,
    where: str | None = None,
    descending: bool = False,
    using: str | None = None,
) -> None:
    table = _table(table_name)
    if any(index.name == name for index in table.indexes):
        return
    expressions = [
        table.c[column].desc() if descending else table.c[column] for column in columns
    ]
    options: dict[str, object] = {"unique": unique}
    if where is not None:
        options["postgresql_where"] = sa.text(where)
    if using is not None:
        options["postgresql_using"] = using
    sa.Index(name, *expressions, **options)


def _register_offline_bundle_ledger() -> None:
    if "offline_bundle_deployments" not in Base.metadata.tables:
        sa.Table(
            "offline_bundle_deployments",
            Base.metadata,
            sa.Column("id", PG_UUID(as_uuid=True), primary_key=True),
            sa.Column("sequence", sa.Integer(), nullable=False),
            sa.Column("bundle_version", sa.String(96), nullable=False),
            sa.Column("bundle_sha256", sa.String(64), nullable=False),
            sa.Column("manifest_sha256", sa.String(64), nullable=False),
            sa.Column("signature_b64", sa.Text(), nullable=False),
            sa.Column("signature_algorithm", sa.String(64), nullable=False),
            sa.Column("signing_key_id", sa.String(512), nullable=False),
            sa.Column("status", sa.String(16), nullable=False),
            sa.Column(
                "previous_deployment_id",
                PG_UUID(as_uuid=True),
                sa.ForeignKey("offline_bundle_deployments.id", ondelete="RESTRICT"),
            ),
            sa.Column("manifest", JSONB(), nullable=False),
            sa.Column("actor", sa.String(128), nullable=False),
            sa.Column("reason", sa.Text(), nullable=False),
            sa.Column(
                "created_at",
                sa.DateTime(timezone=True),
                nullable=False,
                server_default=sa.func.now(),
            ),
            sa.CheckConstraint(
                "status IN ('staged', 'active', 'rolled_back', 'rejected')",
                name="ck_offline_bundle_deployment_status",
            ),
            sa.UniqueConstraint(
                "bundle_sha256",
                "sequence",
                name="uq_offline_bundle_deployment_sequence",
            ),
        )
    _add_index(
        "offline_bundle_deployments",
        "ix_offline_bundle_deployments_bundle_sha256",
        ("bundle_sha256",),
    )
    _add_index(
        "offline_bundle_deployments",
        "uq_offline_bundle_one_active",
        ("status",),
        unique=True,
        where="status = 'active'",
    )


def _register_indexes() -> None:
    specifications = (
        (
            "approval_gates",
            "uq_approval_gates_one_active_per_scan",
            ("scan_id",),
            True,
            "state IN ('pending', 'decided', 'resume_claimed')",
        ),
        ("auth_audit_events", "ix_auth_audit_events_tenant_id", ("tenant_id",)),
        (
            "evidence_objects",
            "ix_evidence_objects_retention",
            ("state", "legal_hold", "retain_until"),
        ),
        ("findings", "ix_findings_scan_bucket", ("scan_id", "finding_bucket")),
        (
            "governance_legal_holds",
            "uq_governance_legal_hold_active_scope",
            ("tenant_id", "scope_type", "scope_id"),
            True,
            "released_at IS NULL",
        ),
        (
            "governance_operations",
            "ix_governance_operations_due",
            ("created_at",),
            False,
            "status IN ('prepared', 'executing')",
        ),
        (
            "governance_store_actions",
            "ix_governance_store_actions_due",
            ("lease_expires_at", "created_at"),
            False,
            "status IN ('pending', 'leased', 'failed')",
        ),
        (
            "provider_reconciliation_runs",
            "ix_provider_reconciliation_runs_completed_at",
            ("completed_at",),
        ),
        (
            "rule_foundry_candidates",
            "ix_rule_foundry_candidates_expires_at",
            ("expires_at",),
        ),
        (
            "rule_foundry_candidates",
            "ix_rule_foundry_candidates_source_attempt_id",
            ("source_attempt_id",),
        ),
        (
            "rule_foundry_candidates",
            "ix_rule_foundry_candidates_source_finding_id",
            ("source_finding_id",),
        ),
        (
            "rule_foundry_candidates",
            "ix_rule_foundry_candidates_source_scan_id",
            ("source_scan_id",),
        ),
        (
            "rule_foundry_deployments",
            "ix_rule_foundry_deployments_candidate_id",
            ("candidate_id",),
        ),
        ("rule_foundry_deployments", "ix_rule_foundry_deployments_state", ("state",)),
        (
            "rule_foundry_deployments",
            "ix_rule_foundry_deployments_tenant_id",
            ("tenant_id",),
        ),
        (
            "rule_foundry_deployments",
            "ix_rule_foundry_deployments_version_id",
            ("version_id",),
        ),
        (
            "rule_foundry_deployments",
            "uq_rule_foundry_active_deployment",
            ("tenant_id", "candidate_id"),
            True,
            "ended_at IS NULL",
        ),
        (
            "rule_foundry_events",
            "ix_rule_foundry_events_candidate_id",
            ("candidate_id",),
        ),
        ("rule_foundry_events", "ix_rule_foundry_events_created_at", ("created_at",)),
        ("rule_foundry_events", "ix_rule_foundry_events_tenant_id", ("tenant_id",)),
        (
            "rule_foundry_gitleaks_candidates",
            "ix_rule_foundry_gitleaks_candidates_tenant_id",
            ("tenant_id",),
        ),
        (
            "rule_foundry_osv_candidates",
            "ix_rule_foundry_osv_candidates_tenant_id",
            ("tenant_id",),
        ),
        (
            "rule_foundry_semgrep_candidates",
            "ix_rule_foundry_semgrep_candidates_tenant_id",
            ("tenant_id",),
        ),
        (
            "rule_foundry_shadow_observations",
            "ix_rule_foundry_shadow_observations_attempt_id",
            ("attempt_id",),
        ),
        (
            "rule_foundry_shadow_observations",
            "ix_rule_foundry_shadow_observations_deployment_id",
            ("deployment_id",),
        ),
        (
            "rule_foundry_shadow_observations",
            "ix_rule_foundry_shadow_observations_scan_id",
            ("scan_id",),
        ),
        (
            "rule_foundry_shadow_observations",
            "ix_rule_foundry_shadow_observations_tenant_id",
            ("tenant_id",),
        ),
        (
            "rule_foundry_versions",
            "ix_rule_foundry_versions_candidate_id",
            ("candidate_id",),
        ),
        (
            "rule_foundry_versions",
            "ix_rule_foundry_versions_payload_sha256",
            ("payload_sha256",),
        ),
        ("rule_foundry_versions", "ix_rule_foundry_versions_tenant_id", ("tenant_id",)),
        (
            "scan_attempts",
            "uq_scan_attempts_one_active",
            ("scan_id",),
            True,
            "status = 'active'",
        ),
        (
            "scan_outbox",
            "ix_scan_outbox_unpublished",
            ("created_at",),
            False,
            "published_at IS NULL",
        ),
        (
            "scan_tasks",
            "ix_scan_tasks_scan_type_input_hash",
            ("scan_id", "task_type", "input_hash"),
        ),
        ("user", "ix_user_tenant_id", ("tenant_id",)),
        ("user_group_memberships", "ix_user_group_memberships_user_id", ("user_id",)),
    )
    for specification in specifications:
        table_name, name, columns, *optional = specification
        unique = bool(optional[0]) if optional else False
        where = str(optional[1]) if len(optional) > 1 else None
        _add_index(table_name, name, columns, unique=unique, where=where)

    _add_index(
        "auth_audit_events",
        "ix_auth_audit_events_ts_desc",
        ("ts",),
        descending=True,
    )
    _add_index(
        "authorization_audit_events",
        "ix_authorization_audit_events_occurred_at_desc",
        ("occurred_at",),
        descending=True,
    )
    _add_index(
        "semgrep_rules",
        "ix_semgrep_rules_languages_gin",
        ("languages",),
        using="gin",
    )
    _add_index(
        "semgrep_rules",
        "ix_semgrep_rules_technology_gin",
        ("technology",),
        using="gin",
    )


def _register_checks() -> None:
    checks = (
        (
            "integration_delivery_audit",
            "ck_integration_delivery_audit_attempt",
            "attempt > 0",
        ),
        (
            "integration_outbox",
            "ck_integration_outbox_attempts",
            "attempts >= 0 AND max_attempts BETWEEN 1 AND 20",
        ),
        (
            "scan_events",
            "ck_scan_events_activity_kind",
            "activity_kind IN ('workflow', 'scanner', 'llm_call', 'retry', "
            "'warning', 'degradation', 'decision', 'cancellation', 'terminal')",
        ),
        ("scan_events", "ck_scan_events_schema_version_positive", "schema_version > 0"),
        (
            "scans",
            "ck_scans_source_type",
            "source_type IS NULL OR source_type IN ('upload', 'archive', 'git', 'paste')",
        ),
        (
            "sso_providers",
            "ck_sso_providers_jit_policy",
            "jit_policy IN ('auto', 'approve', 'deny')",
        ),
        (
            "sso_providers",
            "ck_sso_providers_protocol",
            "protocol IN ('oidc', 'saml')",
        ),
        (
            "usage_budget_allocations",
            "ck_usage_budget_allocations_nonnegative",
            _nonnegative("held"),
        ),
        (
            "usage_budget_counters",
            "ck_usage_budget_counters_nonnegative",
            f"{_nonnegative('spent')} AND {_nonnegative('held')}",
        ),
        (
            "usage_budget_notification_outbox",
            "ck_usage_budget_notification_outbox_attempts",
            "attempts >= 0",
        ),
        (
            "usage_budget_overrides",
            "ck_usage_budget_overrides_nonnegative",
            _nonnegative("allowance"),
        ),
        (
            "usage_budget_policies",
            "ck_usage_budget_policies_caps_nonnegative",
            " AND ".join(
                f"cap_{name} IS NULL OR cap_{name} >= 0" for name in _TOKEN_AMOUNT_NAMES
            ),
        ),
        (
            "usage_budget_reservations",
            "ck_usage_budget_reservations_nonnegative",
            _nonnegative("estimated"),
        ),
        (
            "usage_budget_settlements",
            "ck_usage_budget_settlements_nonnegative",
            _nonnegative("actual"),
        ),
        (
            "usage_budget_threshold_events",
            "ck_usage_budget_threshold_events_percent",
            "threshold_percent > 0 AND threshold_percent < 100",
        ),
    )
    for table_name, name, expression in checks:
        _add_check(table_name, name, expression)


def register_schema_contracts() -> None:
    """Idempotently register every non-column PostgreSQL schema contract."""

    # Pentesting may already be present in ``sys.modules`` when Alembic loads
    # the shared ledger models. Re-run the idempotent cross-context FK hook
    # after every model module is populated so metadata is import-order safe.
    from app.pentesting.persistence.models import (
        register_shared_pentest_attempt_foreign_keys,
    )

    register_shared_pentest_attempt_foreign_keys()
    _register_offline_bundle_ledger()
    _register_indexes()
    _register_checks()
