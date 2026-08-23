"""Add tenant RBAC, durable SoD requests, and authorization audit.

Revision ID: 5a73b6f19c21
Revises: 4894a3e89588
Create Date: 2026-08-23 17:40:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "5a73b6f19c21"
down_revision: Union[str, None] = "4894a3e89588"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column(
            "separation_of_duties_mode",
            sa.String(length=16),
            nullable=False,
            server_default="off",
        ),
    )
    op.create_check_constraint(
        "ck_tenants_separation_of_duties_mode",
        "tenants",
        "separation_of_duties_mode IN ('off', 'critical')",
    )

    op.create_table(
        "role_assignments",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("role_key", sa.String(length=32), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "role_key IN ('platform_owner', 'tenant_admin', "
            "'security_approver', 'analyst', 'developer', 'auditor')",
            name="ck_role_assignments_builtin_role",
        ),
        sa.CheckConstraint(
            "(role_key = 'platform_owner' AND tenant_id IS NULL) OR "
            "(role_key <> 'platform_owner' AND tenant_id IS NOT NULL)",
            name="ck_role_assignments_scope",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"], ["user.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_role_assignments_user_id", "role_assignments", ["user_id"]
    )
    op.create_index(
        "ix_role_assignments_tenant_id", "role_assignments", ["tenant_id"]
    )
    op.create_index(
        "uq_role_assignments_global_user_role",
        "role_assignments",
        ["user_id", "role_key"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NULL"),
    )
    op.create_index(
        "uq_role_assignments_tenant_user_role",
        "role_assignments",
        ["tenant_id", "user_id", "role_key"],
        unique=True,
        postgresql_where=sa.text("tenant_id IS NOT NULL"),
    )

    # Preserve current behavior while moving authorization off the broad bit:
    # existing superusers become global platform owners and all other humans
    # become developers in their current (or seeded default) tenant.
    op.execute(
        """
        INSERT INTO role_assignments (user_id, tenant_id, role_key)
        SELECT id, NULL, 'platform_owner'
        FROM "user"
        WHERE is_superuser IS TRUE
        ON CONFLICT DO NOTHING
        """
    )
    op.execute(
        """
        INSERT INTO role_assignments (user_id, tenant_id, role_key)
        SELECT id,
               COALESCE(tenant_id, '00000000-0000-0000-0000-000000000001'::uuid),
               'developer'
        FROM "user"
        WHERE is_superuser IS FALSE
        ON CONFLICT DO NOTHING
        """
    )

    op.create_table(
        "authorization_action_requests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requester_user_id", sa.Integer(), nullable=False),
        sa.Column("requester_permission", sa.String(length=96), nullable=False),
        sa.Column("approver_permission", sa.String(length=96), nullable=False),
        sa.Column("target_type", sa.String(length=64), nullable=False),
        sa.Column("target_fingerprint", sa.String(length=64), nullable=False),
        sa.Column("payload_digest", sa.String(length=64), nullable=False),
        sa.Column("idempotency_key", sa.String(length=128), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approver_user_id", sa.Integer(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_reason", sa.String(length=500), nullable=True),
        sa.Column("executed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', "
            "'executed', 'cancelled')",
            name="ck_authorization_action_requests_status",
        ),
        sa.CheckConstraint(
            "approver_user_id IS NULL OR approver_user_id <> requester_user_id",
            name="ck_authorization_action_requests_distinct_actor",
        ),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "tenant_id",
            "idempotency_key",
            name="uq_authorization_action_requests_tenant_idempotency",
        ),
    )
    for column in ("tenant_id", "requester_user_id", "status", "expires_at"):
        op.create_index(
            f"ix_authorization_action_requests_{column}",
            "authorization_action_requests",
            [column],
        )

    op.create_table(
        "authorization_audit_events",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("principal_kind", sa.String(length=32), nullable=False),
        sa.Column("principal_id", sa.String(length=128), nullable=False),
        sa.Column("permission", sa.String(length=96), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("target_fingerprint", sa.String(length=64), nullable=True),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=False),
        sa.Column("correlation_id", sa.String(length=128), nullable=False),
        sa.Column("action_request_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approver_principal_id", sa.String(length=128), nullable=True),
        sa.CheckConstraint(
            "principal_kind IN ('human', 'service_principal', 'system')",
            name="ck_authorization_audit_events_principal_kind",
        ),
        sa.CheckConstraint(
            "outcome IN ('allowed', 'denied', 'requested', 'approved', "
            "'rejected', 'executed', 'failed')",
            name="ck_authorization_audit_events_outcome",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_authorization_audit_events_tenant_id",
        "authorization_audit_events",
        ["tenant_id"],
    )
    op.create_index(
        "ix_authorization_audit_events_action_request_id",
        "authorization_audit_events",
        ["action_request_id"],
    )
    op.execute(
        "CREATE INDEX ix_authorization_audit_events_occurred_at_desc "
        "ON authorization_audit_events (occurred_at DESC)"
    )
    op.execute(
        """
        CREATE FUNCTION authorization_audit_events_block_modify()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'authorization_audit_events is append-only; UPDATE/DELETE forbidden';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER authorization_audit_immutable
        BEFORE UPDATE OR DELETE ON authorization_audit_events
        FOR EACH ROW EXECUTE FUNCTION authorization_audit_events_block_modify();
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS authorization_audit_immutable "
        "ON authorization_audit_events"
    )
    op.execute("DROP FUNCTION IF EXISTS authorization_audit_events_block_modify()")
    op.drop_index(
        "ix_authorization_audit_events_occurred_at_desc",
        table_name="authorization_audit_events",
    )
    op.drop_index(
        "ix_authorization_audit_events_action_request_id",
        table_name="authorization_audit_events",
    )
    op.drop_index(
        "ix_authorization_audit_events_tenant_id",
        table_name="authorization_audit_events",
    )
    op.drop_table("authorization_audit_events")

    for column in ("expires_at", "status", "requester_user_id", "tenant_id"):
        op.drop_index(
            f"ix_authorization_action_requests_{column}",
            table_name="authorization_action_requests",
        )
    op.drop_table("authorization_action_requests")

    op.drop_index(
        "uq_role_assignments_tenant_user_role", table_name="role_assignments"
    )
    op.drop_index(
        "uq_role_assignments_global_user_role", table_name="role_assignments"
    )
    op.drop_index("ix_role_assignments_tenant_id", table_name="role_assignments")
    op.drop_index("ix_role_assignments_user_id", table_name="role_assignments")
    op.drop_table("role_assignments")

    op.drop_constraint(
        "ck_tenants_separation_of_duties_mode", "tenants", type_="check"
    )
    op.drop_column("tenants", "separation_of_duties_mode")
