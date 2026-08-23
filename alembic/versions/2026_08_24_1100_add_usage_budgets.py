"""Add hierarchical usage-budget policies and durable reservations.

Revision ID: 9e17fa3b5c24
Revises: 8d06e9f42a15
Create Date: 2026-08-24 11:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "9e17fa3b5c24"
down_revision: Union[str, None] = "8d06e9f42a15"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TOKEN_COLUMNS = (
    "input_tokens",
    "output_tokens",
    "total_tokens",
    "uncached_input_tokens",
    "billable_tokens",
)
TENANT_TABLES = (
    "usage_budget_policies",
    "usage_budget_counters",
    "usage_budget_reservations",
    "usage_budget_allocations",
    "usage_budget_settlements",
    "usage_budget_overrides",
    "usage_budget_threshold_events",
    "usage_budget_notification_outbox",
)


def _amount_columns(prefix: str, *, nullable: bool) -> list[sa.Column]:
    default = None if nullable else "0"
    columns = [
        sa.Column(
            f"{prefix}_{name}", sa.BigInteger(), nullable=nullable, server_default=default
        )
        for name in TOKEN_COLUMNS
    ]
    columns.extend(
        (
            sa.Column(
                f"{prefix}_usd",
                sa.Numeric(30, 12),
                nullable=nullable,
                server_default=default,
            ),
            sa.Column(
                f"{prefix}_provider_requests",
                sa.BigInteger(),
                nullable=nullable,
                server_default=default,
            ),
        )
    )
    return columns


def _nonnegative(prefix: str) -> str:
    names = (*TOKEN_COLUMNS, "usd", "provider_requests")
    return " AND ".join(f"{prefix}_{name} >= 0" for name in names)


def upgrade() -> None:
    op.create_table(
        "usage_budget_policies",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("logical_policy_id", sa.UUID(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("scope_kind", sa.String(16), nullable=False),
        sa.Column("target_group_id", sa.UUID(), nullable=True),
        sa.Column("target_user_id", sa.Integer(), nullable=True),
        sa.Column("window_kind", sa.String(16), nullable=False),
        sa.Column("llm_config_id", sa.UUID(), nullable=True),
        sa.Column("stage", sa.String(100), nullable=True),
        *_amount_columns("cap", nullable=True),
        sa.Column("soft_threshold_low", sa.Integer(), server_default="80", nullable=False),
        sa.Column("soft_threshold_high", sa.Integer(), server_default="95", nullable=False),
        sa.Column("unknown_price_action", sa.String(16), server_default="deny", nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effective_to", sa.DateTime(timezone=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("scope_kind IN ('tenant', 'group', 'user')", name="ck_usage_budget_policies_scope_kind"),
        sa.CheckConstraint("window_kind IN ('request', 'scan', 'day', 'month')", name="ck_usage_budget_policies_window_kind"),
        sa.CheckConstraint(
            "(scope_kind = 'tenant' AND target_group_id IS NULL AND target_user_id IS NULL) OR "
            "(scope_kind = 'group' AND target_group_id IS NOT NULL AND target_user_id IS NULL) OR "
            "(scope_kind = 'user' AND target_group_id IS NULL AND target_user_id IS NOT NULL)",
            name="ck_usage_budget_policies_scope_target",
        ),
        sa.CheckConstraint(
            "cap_input_tokens IS NOT NULL OR cap_output_tokens IS NOT NULL OR "
            "cap_total_tokens IS NOT NULL OR cap_uncached_input_tokens IS NOT NULL OR "
            "cap_billable_tokens IS NOT NULL OR cap_usd IS NOT NULL OR "
            "cap_provider_requests IS NOT NULL",
            name="ck_usage_budget_policies_has_cap",
        ),
        sa.CheckConstraint(
            "soft_threshold_low > 0 AND soft_threshold_low < soft_threshold_high "
            "AND soft_threshold_high < 100",
            name="ck_usage_budget_policies_thresholds",
        ),
        sa.CheckConstraint("unknown_price_action IN ('deny', 'token_only')", name="ck_usage_budget_policies_unknown_price_action"),
        sa.CheckConstraint("effective_to IS NULL OR effective_to > effective_from", name="ck_usage_budget_policies_interval"),
        sa.CheckConstraint(
            " AND ".join(
                f"cap_{name} IS NULL OR cap_{name} >= 0"
                for name in (*TOKEN_COLUMNS, "usd", "provider_requests")
            ),
            name="ck_usage_budget_policies_caps_nonnegative",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_group_id"], ["user_groups.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["llm_config_id"], ["llm_configurations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("logical_policy_id", "version", name="uq_usage_budget_policy_version"),
    )
    for column in ("logical_policy_id", "tenant_id", "target_group_id", "target_user_id"):
        op.create_index(f"ix_usage_budget_policies_{column}", "usage_budget_policies", [column])

    op.create_table(
        "usage_budget_counters",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("window_key", sa.String(512), nullable=False),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("window_end", sa.DateTime(timezone=True), nullable=False),
        *_amount_columns("spent", nullable=False),
        *_amount_columns("held", nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("window_end > window_start", name="ck_usage_budget_counters_interval"),
        sa.CheckConstraint(f"{_nonnegative('spent')} AND {_nonnegative('held')}", name="ck_usage_budget_counters_nonnegative"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id"], ["usage_budget_policies.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("policy_id", "window_key", name="uq_usage_budget_counter_window"),
    )
    op.create_index("ix_usage_budget_counters_tenant_id", "usage_budget_counters", ["tenant_id"])
    op.create_index("ix_usage_budget_counters_policy_id", "usage_budget_counters", ["policy_id"])

    op.create_table(
        "usage_budget_reservations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("idempotency_key", sa.String(512), nullable=False),
        sa.Column("operation_kind", sa.String(32), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("group_ids", postgresql.ARRAY(sa.UUID()), server_default="{}", nullable=False),
        sa.Column("request_key", sa.String(512), nullable=False),
        sa.Column("scan_attempt_id", sa.UUID(), nullable=True),
        sa.Column("llm_config_id", sa.UUID(), nullable=True),
        sa.Column("stage", sa.String(100), nullable=False),
        sa.Column("parent_reservation_id", sa.UUID(), nullable=True),
        sa.Column("state", sa.String(20), server_default="held", nullable=False),
        *_amount_columns("estimated", nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("release_reason", sa.String(100), nullable=True),
        sa.CheckConstraint(
            "state IN ('held', 'settled', 'released', 'expired', 'accounting_unknown')",
            name="ck_usage_budget_reservations_state",
        ),
        sa.CheckConstraint(_nonnegative("estimated"), name="ck_usage_budget_reservations_nonnegative"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["scan_attempt_id"], ["scan_attempts.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["llm_config_id"], ["llm_configurations.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["parent_reservation_id"], ["usage_budget_reservations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
    )
    for column in ("tenant_id", "scan_attempt_id", "parent_reservation_id", "expires_at"):
        op.create_index(f"ix_usage_budget_reservations_{column}", "usage_budget_reservations", [column])

    op.create_table(
        "usage_budget_allocations",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("reservation_id", sa.UUID(), nullable=False),
        sa.Column("counter_id", sa.UUID(), nullable=False),
        *_amount_columns("held", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(_nonnegative("held"), name="ck_usage_budget_allocations_nonnegative"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reservation_id"], ["usage_budget_reservations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["counter_id"], ["usage_budget_counters.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("reservation_id", "counter_id", name="uq_usage_budget_allocation"),
    )
    for column in ("tenant_id", "reservation_id", "counter_id"):
        op.create_index(f"ix_usage_budget_allocations_{column}", "usage_budget_allocations", [column])

    op.create_table(
        "usage_budget_settlements",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("reservation_id", sa.UUID(), nullable=False),
        sa.Column("usage_event_id", sa.UUID(), nullable=False),
        *_amount_columns("actual", nullable=False),
        sa.Column("overrun", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(_nonnegative("actual"), name="ck_usage_budget_settlements_nonnegative"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reservation_id"], ["usage_budget_reservations.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["usage_event_id"], ["llm_usage_events.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("reservation_id"),
        sa.UniqueConstraint("usage_event_id"),
    )
    op.create_index("ix_usage_budget_settlements_tenant_id", "usage_budget_settlements", ["tenant_id"])

    op.create_table(
        "usage_budget_overrides",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("window_key", sa.String(512), nullable=False),
        *_amount_columns("allowance", nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("effective_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("expires_at > effective_from", name="ck_usage_budget_overrides_interval"),
        sa.CheckConstraint(_nonnegative("allowance"), name="ck_usage_budget_overrides_nonnegative"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id"], ["usage_budget_policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["created_by_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    for column in ("tenant_id", "policy_id", "expires_at"):
        op.create_index(f"ix_usage_budget_overrides_{column}", "usage_budget_overrides", [column])

    op.create_table(
        "usage_budget_threshold_events",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("policy_id", sa.UUID(), nullable=False),
        sa.Column("counter_id", sa.UUID(), nullable=False),
        sa.Column("dimension", sa.String(40), nullable=False),
        sa.Column("threshold_percent", sa.Integer(), nullable=False),
        sa.Column("observed", sa.Numeric(30, 12), nullable=False),
        sa.Column("effective_cap", sa.Numeric(30, 12), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("threshold_percent > 0 AND threshold_percent < 100", name="ck_usage_budget_threshold_events_percent"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["policy_id"], ["usage_budget_policies.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["counter_id"], ["usage_budget_counters.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("counter_id", "dimension", "threshold_percent", name="uq_usage_budget_threshold_event"),
    )
    for column in ("tenant_id", "policy_id", "counter_id"):
        op.create_index(f"ix_usage_budget_threshold_events_{column}", "usage_budget_threshold_events", [column])

    op.create_table(
        "usage_budget_notification_outbox",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("threshold_event_id", sa.UUID(), nullable=False),
        sa.Column("recipient_user_id", sa.Integer(), nullable=False),
        sa.Column("state", sa.String(16), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("state IN ('pending', 'published', 'failed')", name="ck_usage_budget_notification_outbox_state"),
        sa.CheckConstraint("attempts >= 0", name="ck_usage_budget_notification_outbox_attempts"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["threshold_event_id"], ["usage_budget_threshold_events.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["recipient_user_id"], ["user.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("threshold_event_id", "recipient_user_id", name="uq_usage_budget_notification_recipient"),
    )
    for column in ("tenant_id", "threshold_event_id", "recipient_user_id"):
        op.create_index(f"ix_usage_budget_notification_outbox_{column}", "usage_budget_notification_outbox", [column])

    _install_tenant_guards()
    _install_immutability_guards()
    _seed_default_scan_policies()


def _install_tenant_guards() -> None:
    references = {
        "usage_budget_policies": (
            ("user_groups", "id", "target_group_id"),
            ("user", "id", "target_user_id"),
            ("user", "id", "created_by_user_id"),
        ),
        "usage_budget_counters": (("usage_budget_policies", "id", "policy_id"),),
        "usage_budget_reservations": (
            ("user", "id", "actor_user_id"),
            ("scan_attempts", "id", "scan_attempt_id"),
        ),
        "usage_budget_allocations": (
            ("usage_budget_reservations", "id", "reservation_id"),
            ("usage_budget_counters", "id", "counter_id"),
        ),
        "usage_budget_settlements": (
            ("usage_budget_reservations", "id", "reservation_id"),
            ("llm_usage_events", "id", "usage_event_id"),
        ),
        "usage_budget_overrides": (
            ("usage_budget_policies", "id", "policy_id"),
            ("user", "id", "created_by_user_id"),
        ),
        "usage_budget_threshold_events": (
            ("usage_budget_policies", "id", "policy_id"),
            ("usage_budget_counters", "id", "counter_id"),
        ),
        "usage_budget_notification_outbox": (
            ("usage_budget_threshold_events", "id", "threshold_event_id"),
            ("user", "id", "recipient_user_id"),
        ),
    }
    for table, table_refs in references.items():
        for index, (parent, parent_pk, local_fk) in enumerate(table_refs):
            op.execute(
                f"""
                CREATE TRIGGER sccap_tenant_reference_{index}
                BEFORE INSERT OR UPDATE OF tenant_id, {local_fk} ON {table}
                FOR EACH ROW EXECUTE FUNCTION sccap_enforce_tenant_reference(
                    '{parent}', '{parent_pk}', '{local_fk}'
                )
                """
            )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY sccap_tenant_isolation ON {table}
            USING (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())
            WITH CHECK (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())
            """
        )


def _install_immutability_guards() -> None:
    op.execute(
        """
        CREATE FUNCTION sccap_reject_usage_budget_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'usage budget history is immutable';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for table in (
        "usage_budget_policies",
        "usage_budget_settlements",
        "usage_budget_overrides",
        "usage_budget_threshold_events",
    ):
        op.execute(
            f"""
            CREATE TRIGGER sccap_usage_budget_immutable
            BEFORE UPDATE OR DELETE ON {table}
            FOR EACH ROW EXECUTE FUNCTION sccap_reject_usage_budget_mutation()
            """
        )


def _seed_default_scan_policies() -> None:
    op.execute(
        """
        INSERT INTO usage_budget_policies (
            id, logical_policy_id, version, tenant_id, scope_kind, window_kind,
            cap_usd, enabled, effective_from, reason, created_by_user_id
        )
        SELECT
            md5(t.id::text || chr(58) || 'default-scan-usd')::uuid,
            md5(t.id::text || chr(58) || 'default-scan-usd')::uuid,
            1, t.id, 'tenant', 'scan', 100, true, now(),
            'System migration of the legacy per-scan estimate ceiling',
            creator.id
        FROM tenants t
        CROSS JOIN LATERAL (
            SELECT u.id FROM "user" u WHERE u.tenant_id = t.id ORDER BY u.id LIMIT 1
        ) creator
        ON CONFLICT (logical_policy_id, version) DO NOTHING
        """
    )
    op.execute(
        """
        CREATE FUNCTION sccap_seed_tenant_scan_budget()
        RETURNS trigger AS $$
        DECLARE policy_uuid uuid;
        BEGIN
            policy_uuid := md5(
                NEW.tenant_id::text || chr(58) || 'default-scan-usd'
            )::uuid;
            INSERT INTO usage_budget_policies (
                id, logical_policy_id, version, tenant_id, scope_kind, window_kind,
                cap_usd, enabled, effective_from, reason, created_by_user_id
            ) VALUES (
                policy_uuid, policy_uuid, 1, NEW.tenant_id, 'tenant', 'scan',
                100, true, now(),
                'System default preserving the legacy per-scan estimate ceiling', NEW.id
            ) ON CONFLICT (logical_policy_id, version) DO NOTHING;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER sccap_seed_tenant_scan_budget
        AFTER INSERT ON "user"
        FOR EACH ROW EXECUTE FUNCTION sccap_seed_tenant_scan_budget()
        """
    )


def downgrade() -> None:
    op.execute('DROP TRIGGER IF EXISTS sccap_seed_tenant_scan_budget ON "user"')
    op.execute("DROP FUNCTION IF EXISTS sccap_seed_tenant_scan_budget()")
    for table in reversed(TENANT_TABLES):
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS sccap_reject_usage_budget_mutation()")
