"""Repair tenant retention policies missing from already-stamped databases.

Revision ID: 3c4d5e6f7081
Revises: 2b3c4d5e6f70
Create Date: 2026-08-27 01:00:00.000000
"""

from __future__ import annotations

from alembic import op


revision = "3c4d5e6f7081"
down_revision = "2b3c4d5e6f70"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The original 22a0 migration was applied locally before its retention
    # table was added. Keep this repair idempotent so fresh databases, where
    # 22a0 already creates the complete table, are unchanged.
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS tenant_retention_policies (
            id UUID PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
            data_class VARCHAR(24) NOT NULL,
            retention_days INTEGER NOT NULL,
            updated_by_user_id INTEGER NOT NULL
                REFERENCES "user"(id) ON DELETE RESTRICT,
            reason TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_tenant_retention_policy_class CHECK (
                data_class IN (
                    'transactional', 'audit', 'evidence', 'llm',
                    'vector', 'logs', 'backups'
                )
            ),
            CONSTRAINT ck_tenant_retention_policy_days CHECK (
                retention_days BETWEEN 1 AND 3650
            ),
            CONSTRAINT uq_tenant_retention_policy_class
                UNIQUE (tenant_id, data_class)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_tenant_retention_policies_tenant_id "
        "ON tenant_retention_policies (tenant_id)"
    )
    op.execute("ALTER TABLE tenant_retention_policies ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE tenant_retention_policies FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$ BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policy
                WHERE polname = 'sccap_tenant_isolation'
                  AND polrelid = 'tenant_retention_policies'::regclass
            ) THEN
                CREATE POLICY sccap_tenant_isolation
                ON tenant_retention_policies
                USING (
                    sccap_has_system_scope()
                    OR tenant_id = sccap_current_tenant_id()
                )
                WITH CHECK (
                    sccap_has_system_scope()
                    OR tenant_id = sccap_current_tenant_id()
                );
            END IF;
        END $$
        """
    )

    # Repeat the intended materialization from 22a0. These updates are
    # deterministic and safe when the complete original migration already ran.
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


def downgrade() -> None:
    # Forward-only repair: this table is part of the 22a0 schema and must not
    # be removed when stepping back across this marker revision.
    pass
