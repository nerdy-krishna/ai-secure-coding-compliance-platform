"""Add cross-store governance and tenant retention policy ledgers.

Revision ID: 22a0b1c2d3e4
Revises: 20f0a1b2c3d4
Create Date: 2026-08-24 22:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "22a0b1c2d3e4"
down_revision: Union[str, None] = "20f0a1b2c3d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

TENANT_TABLES = (
    "governance_legal_holds",
    "governance_operations",
    "governance_store_actions",
    "tenant_retention_policies",
)


def _tenant_column() -> sa.Column:
    return sa.Column(
        "tenant_id",
        postgresql.UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
    )


def upgrade() -> None:
    op.create_table(
        "governance_legal_holds",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        _tenant_column(),
        sa.Column("scope_type", sa.String(24), nullable=False),
        sa.Column("scope_id", sa.String(128), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "placed_by_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "placed_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "released_by_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
        ),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.Column("release_reason", sa.Text()),
        sa.CheckConstraint(
            "scope_type IN ('tenant', 'project', 'scan', 'attempt', 'evidence')",
            name="ck_governance_legal_hold_scope",
        ),
    )
    op.create_index(
        "ix_governance_legal_holds_tenant_id",
        "governance_legal_holds",
        ["tenant_id"],
    )
    op.create_index(
        "uq_governance_legal_hold_active_scope",
        "governance_legal_holds",
        ["tenant_id", "scope_type", "scope_id"],
        unique=True,
        postgresql_where=sa.text("released_at IS NULL"),
    )

    op.create_table(
        "governance_operations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        _tenant_column(),
        sa.Column("kind", sa.String(12), nullable=False),
        sa.Column("status", sa.String(24), nullable=False, server_default="prepared"),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("scope", postgresql.JSONB(), nullable=False),
        sa.Column("policy_snapshot", postgresql.JSONB(), nullable=False),
        sa.Column("manifest", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("manifest_sha256", sa.String(64)),
        sa.Column("signature_b64", sa.Text()),
        sa.Column("signature_algorithm", sa.String(64)),
        sa.Column("signing_key_id", sa.String(512)),
        sa.Column("failure_code", sa.String(64)),
        sa.Column(
            "requested_by_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "kind IN ('export', 'delete')", name="ck_governance_operation_kind"
        ),
        sa.CheckConstraint(
            "status IN ('prepared', 'executing', 'completed', 'failed', "
            "'blocked_legal_hold')",
            name="ck_governance_operation_status",
        ),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_governance_operation_idempotency"
        ),
    )
    op.create_index(
        "ix_governance_operations_tenant_id",
        "governance_operations",
        ["tenant_id"],
    )
    op.create_index(
        "ix_governance_operations_due",
        "governance_operations",
        ["created_at"],
        postgresql_where=sa.text("status IN ('prepared', 'executing')"),
    )

    op.create_table(
        "governance_store_actions",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "operation_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("governance_operations.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        _tenant_column(),
        sa.Column("store", sa.String(20), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="pending"),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("result", postgresql.JSONB(), nullable=False, server_default="{}"),
        sa.Column("result_sha256", sa.String(64)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("applied_at", sa.DateTime(timezone=True)),
        sa.Column("verified_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "store IN ('postgres', 'object', 'qdrant', 'observability')",
            name="ck_governance_store_action_store",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'leased', 'applied', 'verified', 'failed')",
            name="ck_governance_store_action_status",
        ),
        sa.UniqueConstraint(
            "operation_id", "store", name="uq_governance_store_action_operation_store"
        ),
    )
    op.create_index(
        "ix_governance_store_actions_operation_id",
        "governance_store_actions",
        ["operation_id"],
    )
    op.create_index(
        "ix_governance_store_actions_tenant_id",
        "governance_store_actions",
        ["tenant_id"],
    )
    op.create_index(
        "ix_governance_store_actions_due",
        "governance_store_actions",
        ["lease_expires_at", "created_at"],
        postgresql_where=sa.text("status IN ('pending', 'leased', 'failed')"),
    )

    op.create_table(
        "tenant_retention_policies",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        _tenant_column(),
        sa.Column("data_class", sa.String(24), nullable=False),
        sa.Column("retention_days", sa.Integer(), nullable=False),
        sa.Column(
            "updated_by_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "data_class IN ('transactional', 'audit', 'evidence', 'llm', "
            "'vector', 'logs', 'backups')",
            name="ck_tenant_retention_policy_class",
        ),
        sa.CheckConstraint(
            "retention_days BETWEEN 1 AND 3650",
            name="ck_tenant_retention_policy_days",
        ),
        sa.UniqueConstraint(
            "tenant_id", "data_class", name="uq_tenant_retention_policy_class"
        ),
    )
    op.create_index(
        "ix_tenant_retention_policies_tenant_id",
        "tenant_retention_policies",
        ["tenant_id"],
    )

    # Rematerialize the legacy row-level expiries to Task22's approved
    # defaults. Chat/RAG history is only lengthened (never shortened). LLM
    # payloads move from the old 90-day default to 30 days, except where an
    # active governance hold applies or a tenant LLM override is present.
    op.execute(
        "UPDATE chat_messages cm SET expires_at = GREATEST("
        "COALESCE(cm.expires_at, cm.timestamp), "
        "cm.timestamp + INTERVAL '365 days')"
    )
    op.execute(
        "UPDATE rag_preprocessing_jobs rj SET expires_at = GREATEST("
        "COALESCE(rj.expires_at, rj.created_at), "
        "rj.created_at + INTERVAL '365 days')"
    )
    op.execute(
        "UPDATE llm_interactions li SET expires_at = li.timestamp + "
        "make_interval(days => COALESCE(("
        "SELECT p.retention_days FROM tenant_retention_policies p "
        "WHERE p.data_class = 'llm' AND p.tenant_id = COALESCE("
        "(SELECT s.tenant_id FROM scans s WHERE s.id = li.scan_id), "
        "(SELECT cs.tenant_id FROM chat_messages cm "
        "JOIN chat_sessions cs ON cs.id = cm.session_id "
        "WHERE cm.id = li.chat_message_id)) LIMIT 1), 30)) "
        "WHERE NOT EXISTS ("
        "SELECT 1 FROM governance_legal_holds h "
        "LEFT JOIN scans s ON s.id = li.scan_id "
        "LEFT JOIN chat_messages cm ON cm.id = li.chat_message_id "
        "LEFT JOIN chat_sessions cs ON cs.id = cm.session_id "
        "WHERE h.released_at IS NULL "
        "AND h.tenant_id = COALESCE(s.tenant_id, cs.tenant_id) AND ("
        "(h.scope_type = 'tenant' AND h.scope_id = h.tenant_id::text) OR "
        "(s.id IS NOT NULL AND h.scope_type = 'project' "
        "AND h.scope_id = s.project_id::text) OR "
        "(s.id IS NOT NULL AND h.scope_type = 'scan' "
        "AND h.scope_id = s.id::text) OR "
        "(s.id IS NOT NULL AND h.scope_type = 'attempt' AND EXISTS ("
        "SELECT 1 FROM scan_attempts a WHERE a.id::text = h.scope_id "
        "AND a.scan_id = s.id)) OR "
        "(s.id IS NOT NULL AND h.scope_type = 'evidence' AND EXISTS ("
        "SELECT 1 FROM evidence_objects e WHERE e.id::text = h.scope_id "
        "AND e.scan_id = s.id))))"
    )

    # Parent/child tenant equality is enforced before RLS so a system-scoped
    # worker cannot accidentally attach a store action to another tenant.
    op.execute(
        "CREATE TRIGGER sccap_tenant_reference_0 "
        "BEFORE INSERT OR UPDATE OF tenant_id, operation_id "
        "ON governance_store_actions FOR EACH ROW EXECUTE FUNCTION "
        "sccap_enforce_tenant_reference('governance_operations', 'id', 'operation_id')"
    )
    for table in TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY sccap_tenant_isolation ON {table} "
            "USING (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id()) "
            "WITH CHECK (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())"
        )


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.drop_table(table)
