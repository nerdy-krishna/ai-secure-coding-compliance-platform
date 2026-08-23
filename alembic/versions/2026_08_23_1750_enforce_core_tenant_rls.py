"""Enforce non-null core tenant ownership and PostgreSQL RLS.

Revision ID: 6b84c7a20d32
Revises: 5a73b6f19c21
Create Date: 2026-08-23 17:50:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "6b84c7a20d32"
down_revision: Union[str, None] = "5a73b6f19c21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"

TENANT_FOREIGN_KEYS = {
    "user": "fk_user_tenant_id",
    "projects": "fk_projects_tenant_id",
    "scans": "fk_scans_tenant_id",
    "scan_attempts": "scan_attempts_tenant_id_fkey",
    "evidence_objects": "evidence_objects_tenant_id_fkey",
    "evidence_governance_events": "evidence_governance_events_tenant_id_fkey",
    "findings": "fk_findings_tenant_id",
    "llm_usage_events": "llm_usage_events_tenant_id_fkey",
    "chat_sessions": "fk_chat_sessions_tenant_id",
    "user_groups": "fk_user_groups_tenant_id",
}

DIRECT_TENANT_TABLES = (
    "projects",
    "scans",
    "scan_attempts",
    "evidence_objects",
    "evidence_governance_events",
    "findings",
    "llm_usage_events",
    "chat_sessions",
    "user_groups",
    "authorization_action_requests",
)

SCAN_CHILD_TABLES = (
    "scan_tasks",
    "scan_artifacts",
    "evidence_manifests",
    "scan_events",
    "approval_gates",
    "scan_outbox",
    "code_snapshots",
    "finding_fix_candidates",
)


def _backfill_and_constrain_tenants() -> None:
    op.execute(
        f'UPDATE "user" SET tenant_id = \'{DEFAULT_TENANT}\'::uuid '
        "WHERE tenant_id IS NULL"
    )
    op.execute(
        'UPDATE projects p SET tenant_id = u.tenant_id FROM "user" u '
        "WHERE u.id = p.user_id AND p.tenant_id IS DISTINCT FROM u.tenant_id"
    )
    op.execute(
        'UPDATE scans s SET tenant_id = u.tenant_id FROM "user" u '
        "WHERE u.id = s.user_id AND s.tenant_id IS DISTINCT FROM u.tenant_id"
    )
    op.execute(
        "UPDATE scan_attempts a SET tenant_id = s.tenant_id FROM scans s "
        "WHERE s.id = a.scan_id AND a.tenant_id IS DISTINCT FROM s.tenant_id"
    )
    op.execute(
        "UPDATE findings f SET tenant_id = s.tenant_id FROM scans s "
        "WHERE s.id = f.scan_id AND f.tenant_id IS DISTINCT FROM s.tenant_id"
    )
    op.execute(
        'UPDATE chat_sessions c SET tenant_id = u.tenant_id FROM "user" u '
        "WHERE u.id = c.user_id AND c.tenant_id IS DISTINCT FROM u.tenant_id"
    )
    op.execute(
        'UPDATE user_groups g SET tenant_id = u.tenant_id FROM "user" u '
        "WHERE u.id = g.created_by AND g.tenant_id IS DISTINCT FROM u.tenant_id"
    )
    op.execute(
        f"""
        UPDATE evidence_objects e
        SET tenant_id = COALESCE(
            (SELECT s.tenant_id FROM scans s WHERE s.id = e.scan_id),
            (SELECT a.tenant_id FROM scan_attempts a WHERE a.id = e.attempt_id),
            e.tenant_id,
            '{DEFAULT_TENANT}'::uuid
        )
        """
    )
    op.execute(
        f"""
        UPDATE evidence_governance_events g
        SET tenant_id = COALESCE(
            (SELECT e.tenant_id FROM evidence_objects e WHERE e.id = g.evidence_id),
            (SELECT s.tenant_id FROM scans s WHERE s.id = g.scan_id),
            (SELECT a.tenant_id FROM scan_attempts a WHERE a.id = g.attempt_id),
            g.tenant_id,
            '{DEFAULT_TENANT}'::uuid
        )
        """
    )
    op.execute(
        f"""
        UPDATE llm_usage_events e
        SET tenant_id = COALESCE(
            (SELECT s.tenant_id FROM scans s WHERE s.id = e.scan_id),
            (SELECT c.tenant_id FROM chat_sessions c WHERE c.id = e.chat_session_id),
            (SELECT u.tenant_id FROM "user" u WHERE u.id = e.user_id),
            e.tenant_id,
            '{DEFAULT_TENANT}'::uuid
        )
        """
    )

    for table_name, constraint_name in TENANT_FOREIGN_KEYS.items():
        op.drop_constraint(constraint_name, table_name, type_="foreignkey")
        op.alter_column(
            table_name,
            "tenant_id",
            existing_type=sa.UUID(),
            nullable=False,
            server_default=sa.text(f"'{DEFAULT_TENANT}'::uuid"),
        )
        op.create_foreign_key(
            constraint_name,
            table_name,
            "tenants",
            ["tenant_id"],
            ["id"],
            ondelete="RESTRICT",
        )


def _create_tenant_invariant_triggers() -> None:
    op.execute(
        f"""
        CREATE FUNCTION sccap_enforce_tenant_reference()
        RETURNS trigger AS $$
        DECLARE
            expected_tenant uuid;
            local_reference text;
        BEGIN
            local_reference := to_jsonb(NEW) ->> TG_ARGV[2];
            IF local_reference IS NULL THEN
                RETURN NEW;
            END IF;
            EXECUTE format(
                'SELECT tenant_id FROM %I WHERE %I::text = $1',
                TG_ARGV[0], TG_ARGV[1]
            ) INTO expected_tenant USING local_reference;
            IF expected_tenant IS NULL THEN
                RAISE EXCEPTION 'tenant reference is missing or outside active scope';
            END IF;
            IF NEW.tenant_id IS NULL OR NEW.tenant_id = '{DEFAULT_TENANT}'::uuid THEN
                NEW.tenant_id := expected_tenant;
            ELSIF NEW.tenant_id <> expected_tenant THEN
                RAISE EXCEPTION 'cross-tenant reference rejected';
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    references = {
        "projects": (("user", "id", "user_id"),),
        "scans": (
            ("projects", "id", "project_id"),
            ("user", "id", "user_id"),
        ),
        "scan_attempts": (("scans", "id", "scan_id"),),
        "findings": (("scans", "id", "scan_id"),),
        "chat_sessions": (
            ("user", "id", "user_id"),
            ("projects", "id", "project_id"),
        ),
        "evidence_objects": (
            ("scans", "id", "scan_id"),
            ("scan_attempts", "id", "attempt_id"),
        ),
        "evidence_governance_events": (
            ("scans", "id", "scan_id"),
            ("scan_attempts", "id", "attempt_id"),
            ("evidence_objects", "id", "evidence_id"),
        ),
        "llm_usage_events": (
            ("scans", "id", "scan_id"),
            ("chat_sessions", "id", "chat_session_id"),
            ("user", "id", "user_id"),
        ),
        "user_groups": (("user", "id", "created_by"),),
        "authorization_action_requests": (
            ("user", "id", "requester_user_id"),
        ),
    }
    for table_name, table_refs in references.items():
        for index, (parent_table, parent_pk, local_fk) in enumerate(table_refs):
            op.execute(
                f"""
                CREATE TRIGGER sccap_tenant_reference_{index}
                BEFORE INSERT OR UPDATE OF tenant_id, {local_fk} ON {table_name}
                FOR EACH ROW EXECUTE FUNCTION sccap_enforce_tenant_reference(
                    '{parent_table}', '{parent_pk}', '{local_fk}'
                )
                """
            )


def _create_runtime_role_and_rls() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'sccap_runtime') THEN
                CREATE ROLE sccap_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOBYPASSRLS;
            END IF;
        END $$
        """
    )
    op.execute("GRANT USAGE ON SCHEMA public TO sccap_runtime")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        "TO sccap_runtime"
    )
    op.execute("GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO sccap_runtime")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO sccap_runtime"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "GRANT USAGE, SELECT ON SEQUENCES TO sccap_runtime"
    )
    op.execute(
        """
        CREATE FUNCTION sccap_current_tenant_id()
        RETURNS uuid LANGUAGE sql STABLE AS $$
          SELECT NULLIF(current_setting('app.tenant_id', true), '')::uuid
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION sccap_has_system_scope()
        RETURNS boolean LANGUAGE sql STABLE AS $$
          SELECT current_setting('app.system_scope', true) = 'on'
             AND current_setting('app.principal_kind', true) = 'system'
        $$
        """
    )

    direct_expression = (
        "sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id()"
    )
    for table_name in DIRECT_TENANT_TABLES:
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY sccap_tenant_isolation ON {table_name} "
            f"USING ({direct_expression}) WITH CHECK ({direct_expression})"
        )

    # Global platform roles are readable only by their own human principal;
    # tenant roles remain bound to the active tenant. System maintenance can
    # inspect both without a general human cross-tenant bypass.
    role_expression = (
        "sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id() OR "
        "(tenant_id IS NULL AND user_id::text = "
        "current_setting('app.principal_id', true))"
    )
    op.execute("ALTER TABLE role_assignments ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE role_assignments FORCE ROW LEVEL SECURITY")
    op.execute(
        "CREATE POLICY sccap_tenant_isolation ON role_assignments "
        f"USING ({role_expression}) WITH CHECK ({role_expression})"
    )

    for table_name in SCAN_CHILD_TABLES:
        expression = (
            "sccap_has_system_scope() OR EXISTS ("
            f"SELECT 1 FROM scans s WHERE s.id = {table_name}.scan_id "
            "AND s.tenant_id = sccap_current_tenant_id())"
        )
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY sccap_tenant_isolation ON {table_name} "
            f"USING ({expression}) WITH CHECK ({expression})"
        )

    child_policies = {
        "evidence_deletion_outbox": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM evidence_objects e "
            "WHERE e.id = evidence_deletion_outbox.evidence_id "
            "AND e.tenant_id = sccap_current_tenant_id())"
        ),
        "finding_disposition_events": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM findings f "
            "WHERE f.id = finding_disposition_events.finding_id "
            "AND f.tenant_id = sccap_current_tenant_id())"
        ),
        "llm_usage_requests": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM llm_usage_events e "
            "WHERE e.id = llm_usage_requests.usage_event_id "
            "AND e.tenant_id = sccap_current_tenant_id())"
        ),
        "llm_usage_line_items": (
            "sccap_has_system_scope() OR EXISTS ("
            "SELECT 1 FROM llm_usage_requests r JOIN llm_usage_events e "
            "ON e.id = r.usage_event_id "
            "WHERE r.id = llm_usage_line_items.usage_request_id "
            "AND e.tenant_id = sccap_current_tenant_id())"
        ),
        "chat_messages": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM chat_sessions c "
            "WHERE c.id = chat_messages.session_id "
            "AND c.tenant_id = sccap_current_tenant_id())"
        ),
        "user_group_memberships": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM user_groups g "
            "WHERE g.id = user_group_memberships.group_id "
            "AND g.tenant_id = sccap_current_tenant_id())"
        ),
        "llm_interactions": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM scans s "
            "WHERE s.id = llm_interactions.scan_id "
            "AND s.tenant_id = sccap_current_tenant_id()) OR EXISTS ("
            "SELECT 1 FROM chat_messages m JOIN chat_sessions c "
            "ON c.id = m.session_id WHERE m.id = llm_interactions.chat_message_id "
            "AND c.tenant_id = sccap_current_tenant_id())"
        ),
        "llm_call_reservations": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM scans s "
            "WHERE s.id = llm_call_reservations.scan_id "
            "AND s.tenant_id = sccap_current_tenant_id()) OR EXISTS ("
            "SELECT 1 FROM llm_usage_events e "
            "WHERE e.id = llm_call_reservations.usage_event_id "
            "AND e.tenant_id = sccap_current_tenant_id())"
        ),
        "rag_preprocessing_jobs": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM \"user\" u "
            "WHERE u.id = rag_preprocessing_jobs.user_id "
            "AND u.tenant_id = sccap_current_tenant_id())"
        ),
        "push_subscriptions": (
            "sccap_has_system_scope() OR EXISTS (SELECT 1 FROM \"user\" u "
            "WHERE u.id = push_subscriptions.user_id "
            "AND u.tenant_id = sccap_current_tenant_id())"
        ),
    }
    for table_name, expression in child_policies.items():
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY sccap_tenant_isolation ON {table_name} "
            f"USING ({expression}) WITH CHECK ({expression})"
        )


def upgrade() -> None:
    _backfill_and_constrain_tenants()
    _create_tenant_invariant_triggers()
    _create_runtime_role_and_rls()


def downgrade() -> None:
    protected_tables = (
        *DIRECT_TENANT_TABLES,
        "role_assignments",
        *SCAN_CHILD_TABLES,
        "evidence_deletion_outbox",
        "finding_disposition_events",
        "llm_usage_requests",
        "llm_usage_line_items",
        "chat_messages",
        "user_group_memberships",
        "llm_interactions",
        "llm_call_reservations",
        "rag_preprocessing_jobs",
        "push_subscriptions",
    )
    for table_name in protected_tables:
        op.execute(f"DROP POLICY IF EXISTS sccap_tenant_isolation ON {table_name}")
        op.execute(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY")

    op.execute("DROP FUNCTION IF EXISTS sccap_has_system_scope()")
    op.execute("DROP FUNCTION IF EXISTS sccap_current_tenant_id()")
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM sccap_runtime"
    )
    op.execute(
        "ALTER DEFAULT PRIVILEGES IN SCHEMA public "
        "REVOKE USAGE, SELECT ON SEQUENCES FROM sccap_runtime"
    )
    op.execute("REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM sccap_runtime")
    op.execute("REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM sccap_runtime")
    op.execute("REVOKE USAGE ON SCHEMA public FROM sccap_runtime")
    op.execute("DROP ROLE IF EXISTS sccap_runtime")

    trigger_tables = (
        "projects",
        "scans",
        "scan_attempts",
        "findings",
        "chat_sessions",
        "evidence_objects",
        "evidence_governance_events",
        "llm_usage_events",
        "user_groups",
        "authorization_action_requests",
    )
    for table_name in trigger_tables:
        op.execute(
            f"DROP TRIGGER IF EXISTS sccap_tenant_reference_0 ON {table_name}"
        )
        op.execute(
            f"DROP TRIGGER IF EXISTS sccap_tenant_reference_1 ON {table_name}"
        )
        op.execute(
            f"DROP TRIGGER IF EXISTS sccap_tenant_reference_2 ON {table_name}"
        )
    op.execute("DROP FUNCTION IF EXISTS sccap_enforce_tenant_reference()")

    for table_name, constraint_name in TENANT_FOREIGN_KEYS.items():
        op.drop_constraint(constraint_name, table_name, type_="foreignkey")
        op.alter_column(
            table_name,
            "tenant_id",
            existing_type=sa.UUID(),
            nullable=True,
            server_default=None,
        )
        op.create_foreign_key(
            constraint_name,
            table_name,
            "tenants",
            ["tenant_id"],
            ["id"],
            ondelete="SET NULL",
        )
