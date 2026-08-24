"""Forward-only repair for late Task20 provenance additions.

Revision ID: 20f0a1b2c3d4
Revises: 20e0a1b2c3d4
"""

from __future__ import annotations

from alembic import op


revision = "20f0a1b2c3d4"
down_revision = "20e0a1b2c3d4"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # 20e0 was applied in some environments before source-event correlation
    # and atomic CI provenance were added. All operations are idempotent so the
    # repair is also a no-op after a fresh, complete 20e0 upgrade.
    op.execute(
        "ALTER TABLE integration_outbox "
        "ADD COLUMN IF NOT EXISTS source_event_key VARCHAR(128)"
    )
    op.execute(
        "ALTER TABLE integration_grants "
        "DROP CONSTRAINT IF EXISTS ck_integration_grant_feature"
    )
    op.execute(
        "ALTER TABLE integration_grants ADD CONSTRAINT ck_integration_grant_feature "
        "CHECK (feature IN ('repository_contents_read', 'security_events_write', "
        "'webhook_metadata_read', 'ticket_sync', 'siem_emit'))"
    )
    op.execute(
        """
        DO $$ BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_constraint
                WHERE conname = 'uq_integration_outbox_source_event'
                  AND conrelid = 'integration_outbox'::regclass
            ) THEN
                ALTER TABLE integration_outbox
                ADD CONSTRAINT uq_integration_outbox_source_event
                UNIQUE (principal_id, source_event_key);
            END IF;
        END $$
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS integration_source_submissions (
            id UUID PRIMARY KEY,
            tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT,
            scan_id UUID NOT NULL,
            provider VARCHAR(24) NOT NULL,
            commit_sha VARCHAR(64) NOT NULL,
            ref VARCHAR(255) NOT NULL,
            repository_slug VARCHAR(255) NOT NULL,
            trusted_context BOOLEAN NOT NULL,
            created_by_user_id INTEGER NOT NULL,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
            CONSTRAINT ck_integration_source_submission_provider
                CHECK (provider IN ('github', 'gitlab', 'azure_devops', 'bitbucket')),
            CONSTRAINT uq_integration_source_submission_scan UNIQUE (scan_id)
        )
        """
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_integration_source_submissions_tenant_id "
        "ON integration_source_submissions (tenant_id)"
    )
    op.execute(
        "CREATE INDEX IF NOT EXISTS ix_integration_source_submissions_scan_id "
        "ON integration_source_submissions (scan_id)"
    )
    op.execute("ALTER TABLE integration_source_submissions ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE integration_source_submissions FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        DO $$ BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_policy
                WHERE polname = 'sccap_tenant_isolation'
                  AND polrelid = 'integration_source_submissions'::regclass
            ) THEN
                CREATE POLICY sccap_tenant_isolation
                ON integration_source_submissions
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
    op.execute(
        """
        DO $$ BEGIN
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger
                WHERE tgname = 'sccap_tenant_reference_0'
                  AND tgrelid = 'integration_source_submissions'::regclass
                  AND NOT tgisinternal
            ) THEN
                CREATE TRIGGER sccap_tenant_reference_0
                BEFORE INSERT OR UPDATE OF tenant_id, scan_id
                ON integration_source_submissions
                FOR EACH ROW EXECUTE FUNCTION
                sccap_enforce_tenant_reference('scans', 'id', 'scan_id');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger
                WHERE tgname = 'sccap_tenant_reference_1'
                  AND tgrelid = 'integration_source_submissions'::regclass
                  AND NOT tgisinternal
            ) THEN
                CREATE TRIGGER sccap_tenant_reference_1
                BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id
                ON integration_source_submissions
                FOR EACH ROW EXECUTE FUNCTION
                sccap_enforce_tenant_reference('user', 'id', 'created_by_user_id');
            END IF;
            IF NOT EXISTS (
                SELECT 1 FROM pg_trigger
                WHERE tgname = 'sccap_integration_evidence_immutable'
                  AND tgrelid = 'integration_source_submissions'::regclass
                  AND NOT tgisinternal
            ) THEN
                CREATE TRIGGER sccap_integration_evidence_immutable
                BEFORE UPDATE OR DELETE ON integration_source_submissions
                FOR EACH ROW EXECUTE FUNCTION
                sccap_reject_integration_evidence_mutation();
            END IF;
        END $$
        """
    )


def downgrade() -> None:
    # Forward-only repair: the repaired objects are part of the 20e0 schema and
    # must not be removed when stepping back across this marker revision.
    pass
