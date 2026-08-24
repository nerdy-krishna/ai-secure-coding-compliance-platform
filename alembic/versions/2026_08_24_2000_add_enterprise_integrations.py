"""Add tenant-scoped enterprise integration delivery contracts.

Revision ID: 20e0a1b2c3d4
Revises: 18f0a1b2c3d4
Create Date: 2026-08-24 20:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "20e0a1b2c3d4"
down_revision: Union[str, None] = "18f0a1b2c3d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


TENANT_TABLES = (
    "integration_service_principals",
    "integration_grants",
    "integration_inbound_receipts",
    "integration_outbox",
    "integration_delivery_audit",
    "integration_finding_tickets",
    "integration_ticket_history",
    "integration_source_submissions",
)


def _tenant_column() -> sa.Column:
    return sa.Column(
        "tenant_id",
        sa.UUID(),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
    )


def _timestamps() -> tuple[sa.Column, sa.Column]:
    return (
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )


def upgrade() -> None:
    op.create_table(
        "integration_service_principals",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column("kind", sa.String(32), nullable=False),
        sa.Column("display_name", sa.String(120), nullable=False),
        sa.Column("config", postgresql.JSONB(), server_default="{}", nullable=False),
        sa.Column("secrets_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("secret_fingerprint", sa.String(64), nullable=False),
        sa.Column("enabled", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column(
            "created_by_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("revoked_by_user_id", sa.Integer()),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        *_timestamps(),
        sa.CheckConstraint(
            "kind IN ('github_app', 'jira_cloud', 'siem_webhook')",
            name="ck_integration_service_principal_kind",
        ),
        sa.UniqueConstraint(
            "tenant_id", "kind", "display_name", name="uq_integration_principal_name"
        ),
    )
    op.create_index(
        "ix_integration_service_principals_tenant_id",
        "integration_service_principals",
        ["tenant_id"],
    )

    op.create_table(
        "integration_grants",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column(
            "principal_id",
            sa.UUID(),
            sa.ForeignKey("integration_service_principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("feature", sa.String(40), nullable=False),
        sa.Column("scope", postgresql.JSONB(), nullable=False),
        sa.Column("scope_digest", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column("revoked_by_user_id", sa.Integer()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint(
            "feature IN ('repository_contents_read', 'checks_write', "
            "'security_events_write', 'webhook_metadata_read', 'ticket_sync', "
            "'siem_emit')",
            name="ck_integration_grant_feature",
        ),
    )
    op.create_index(
        "ix_integration_grants_tenant_id", "integration_grants", ["tenant_id"]
    )
    op.create_index(
        "ix_integration_grants_principal_id", "integration_grants", ["principal_id"]
    )
    op.create_index(
        "uq_integration_grant_active_scope",
        "integration_grants",
        ["principal_id", "feature", "scope_digest"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    op.create_table(
        "integration_inbound_receipts",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column(
            "principal_id",
            sa.UUID(),
            sa.ForeignKey("integration_service_principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("source_event_id", sa.String(128), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(96), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "received_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "principal_id", "source_event_id", name="uq_integration_receipt_source_event"
        ),
        sa.UniqueConstraint(
            "principal_id", "nonce", name="uq_integration_receipt_nonce"
        ),
    )
    op.create_index(
        "ix_integration_inbound_receipts_tenant_id",
        "integration_inbound_receipts",
        ["tenant_id"],
    )
    op.create_index(
        "ix_integration_inbound_receipts_principal_id",
        "integration_inbound_receipts",
        ["principal_id"],
    )

    op.create_table(
        "integration_outbox",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column(
            "principal_id",
            sa.UUID(),
            sa.ForeignKey("integration_service_principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("event_type", sa.String(96), nullable=False),
        sa.Column("envelope_version", sa.Integer(), server_default="1", nullable=False),
        sa.Column("idempotency_key", sa.String(64), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("payload_redacted", postgresql.JSONB(), nullable=False),
        sa.Column("payload_digest", sa.String(64), nullable=False),
        sa.Column("state", sa.String(16), server_default="pending", nullable=False),
        sa.Column("attempts", sa.Integer(), server_default="0", nullable=False),
        sa.Column("max_attempts", sa.Integer(), server_default="8", nullable=False),
        sa.Column(
            "next_attempt_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("last_error_code", sa.String(64)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'delivering', 'retry', 'delivered', 'dead_letter')",
            name="ck_integration_outbox_state",
        ),
        sa.CheckConstraint(
            "attempts >= 0 AND max_attempts BETWEEN 1 AND 20",
            name="ck_integration_outbox_attempts",
        ),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_integration_outbox_idempotency"
        ),
    )
    op.create_index(
        "ix_integration_outbox_tenant_id", "integration_outbox", ["tenant_id"]
    )
    op.create_index(
        "ix_integration_outbox_principal_id", "integration_outbox", ["principal_id"]
    )
    op.create_index(
        "ix_integration_outbox_due",
        "integration_outbox",
        ["next_attempt_at"],
        postgresql_where=sa.text("state IN ('pending', 'retry')"),
    )
    op.create_index(
        "ix_integration_outbox_expired_lease",
        "integration_outbox",
        ["lease_expires_at"],
        postgresql_where=sa.text("state = 'delivering'"),
    )

    op.create_table(
        "integration_delivery_audit",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column(
            "outbox_id",
            sa.UUID(),
            sa.ForeignKey("integration_outbox.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column(
            "principal_id",
            sa.UUID(),
            sa.ForeignKey("integration_service_principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("attempt", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("http_status", sa.Integer()),
        sa.Column("evidence_digest", sa.String(64), nullable=False),
        sa.Column("response_excerpt_redacted", sa.String(1024)),
        sa.Column("error_code", sa.String(64)),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint("attempt > 0", name="ck_integration_delivery_audit_attempt"),
    )
    op.create_index(
        "ix_integration_delivery_audit_tenant_id",
        "integration_delivery_audit",
        ["tenant_id"],
    )
    op.create_index(
        "ix_integration_delivery_audit_outbox_id",
        "integration_delivery_audit",
        ["outbox_id"],
    )

    op.create_table(
        "integration_finding_tickets",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column(
            "principal_id",
            sa.UUID(),
            sa.ForeignKey("integration_service_principals.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("canonical_root_id", sa.String(128), nullable=False),
        sa.Column("external_key", sa.String(128), nullable=False),
        sa.Column("external_url", sa.String(1024)),
        sa.Column("status", sa.String(64), nullable=False),
        sa.Column("waiver_expires_at", sa.DateTime(timezone=True)),
        *_timestamps(),
        sa.UniqueConstraint(
            "principal_id",
            "canonical_root_id",
            name="uq_integration_ticket_canonical_root",
        ),
    )
    op.create_index(
        "ix_integration_finding_tickets_tenant_id",
        "integration_finding_tickets",
        ["tenant_id"],
    )
    op.create_index(
        "ix_integration_finding_tickets_principal_id",
        "integration_finding_tickets",
        ["principal_id"],
    )

    op.create_table(
        "integration_ticket_history",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column(
            "ticket_id",
            sa.UUID(),
            sa.ForeignKey("integration_finding_tickets.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("from_status", sa.String(64)),
        sa.Column("to_status", sa.String(64), nullable=False),
        sa.Column("reason", sa.String(96), nullable=False),
        sa.Column("event_id", sa.UUID()),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
    )
    op.create_index(
        "ix_integration_ticket_history_tenant_id",
        "integration_ticket_history",
        ["tenant_id"],
    )
    op.create_index(
        "ix_integration_ticket_history_ticket_id",
        "integration_ticket_history",
        ["ticket_id"],
    )

    op.create_table(
        "integration_source_submissions",
        sa.Column("id", sa.UUID(), primary_key=True),
        _tenant_column(),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("provider", sa.String(24), nullable=False),
        sa.Column("commit_sha", sa.String(64), nullable=False),
        sa.Column("ref", sa.String(255), nullable=False),
        sa.Column("repository_slug", sa.String(255), nullable=False),
        sa.Column("trusted_context", sa.Boolean(), nullable=False),
        sa.Column("created_by_user_id", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "provider IN ('github', 'gitlab', 'azure_devops', 'bitbucket')",
            name="ck_integration_source_submission_provider",
        ),
        sa.UniqueConstraint("scan_id", name="uq_integration_source_submission_scan"),
    )
    op.create_index(
        "ix_integration_source_submissions_tenant_id",
        "integration_source_submissions",
        ["tenant_id"],
    )
    op.create_index(
        "ix_integration_source_submissions_scan_id",
        "integration_source_submissions",
        ["scan_id"],
    )

    references = {
        "integration_service_principals": (
            ("user", "id", "created_by_user_id"),
            ("user", "id", "revoked_by_user_id"),
        ),
        "integration_grants": (
            ("integration_service_principals", "id", "principal_id"),
            ("user", "id", "created_by_user_id"),
            ("user", "id", "revoked_by_user_id"),
        ),
        "integration_inbound_receipts": (
            ("integration_service_principals", "id", "principal_id"),
        ),
        "integration_outbox": (
            ("integration_service_principals", "id", "principal_id"),
        ),
        "integration_delivery_audit": (
            ("integration_outbox", "id", "outbox_id"),
            ("integration_service_principals", "id", "principal_id"),
        ),
        "integration_finding_tickets": (
            ("integration_service_principals", "id", "principal_id"),
        ),
        "integration_ticket_history": (
            ("integration_finding_tickets", "id", "ticket_id"),
        ),
        "integration_source_submissions": (
            ("scans", "id", "scan_id"),
            ("user", "id", "created_by_user_id"),
        ),
    }
    for table, table_refs in references.items():
        for index, (parent, parent_pk, local_fk) in enumerate(table_refs):
            op.execute(
                f"CREATE TRIGGER sccap_tenant_reference_{index} "
                f"BEFORE INSERT OR UPDATE OF tenant_id, {local_fk} ON {table} "
                "FOR EACH ROW EXECUTE FUNCTION "
                f"sccap_enforce_tenant_reference('{parent}', '{parent_pk}', '{local_fk}')"
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
        CREATE FUNCTION sccap_reject_integration_evidence_mutation()
        RETURNS trigger AS $$ BEGIN
            RAISE EXCEPTION 'integration delivery evidence is immutable';
        END; $$ LANGUAGE plpgsql
        """
    )
    for table in (
        "integration_inbound_receipts",
        "integration_delivery_audit",
        "integration_ticket_history",
        "integration_source_submissions",
    ):
        op.execute(
            f"CREATE TRIGGER sccap_integration_evidence_immutable "
            f"BEFORE UPDATE OR DELETE ON {table} FOR EACH ROW EXECUTE FUNCTION "
            "sccap_reject_integration_evidence_mutation()"
        )


def downgrade() -> None:
    for table in reversed(TENANT_TABLES):
        op.drop_table(table)
    op.execute("DROP FUNCTION IF EXISTS sccap_reject_integration_evidence_mutation()")
