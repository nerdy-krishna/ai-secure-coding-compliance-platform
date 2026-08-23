"""Add immutable scan attempts and encrypted evidence metadata.

Revision ID: f2a3b4c5d6e7
Revises: e1f2a3b4c5d6
Create Date: 2026-08-23
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "f2a3b4c5d6e7"
down_revision = "e1f2a3b4c5d6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_attempts",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("trigger", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("parent_attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("graph_thread_id", sa.String(length=255), nullable=False),
        sa.Column("configuration_digest", sa.String(length=64), nullable=True),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('active', 'completed', 'failed', 'cancelled', 'superseded')",
            name="ck_scan_attempts_status",
        ),
        sa.CheckConstraint(
            "trigger IN ('initial', 'restart', 'legacy_backfill')",
            name="ck_scan_attempts_trigger",
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["parent_attempt_id"], ["scan_attempts.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("scan_id", "sequence", name="uq_scan_attempts_sequence"),
    )
    op.create_index("ix_scan_attempts_scan_id", "scan_attempts", ["scan_id"])
    op.create_index("ix_scan_attempts_tenant_id", "scan_attempts", ["tenant_id"])
    op.create_index(
        "uq_scan_attempts_one_active",
        "scan_attempts",
        ["scan_id"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    # A scan UUID is a stable, collision-free legacy attempt UUID in a separate table.
    op.execute(
        """
        INSERT INTO scan_attempts (
            id, scan_id, tenant_id, sequence, trigger, status,
            actor_user_id, graph_thread_id, started_at, completed_at
        )
        SELECT
            s.id, s.id, s.tenant_id, 1, 'legacy_backfill',
            CASE
                WHEN s.status = 'CANCELLED' THEN 'cancelled'
                WHEN s.status = 'FAILED' THEN 'failed'
                WHEN s.completed_at IS NOT NULL THEN 'completed'
                ELSE 'active'
            END,
            s.user_id, s.id::text, s.created_at, s.completed_at
        FROM scans s
        """
    )

    op.add_column(
        "scans",
        sa.Column("current_attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_scans_current_attempt_id",
        "scans",
        "scan_attempts",
        ["current_attempt_id"],
        ["id"],
        ondelete="SET NULL",
        use_alter=True,
    )
    op.create_index("ix_scans_current_attempt_id", "scans", ["current_attempt_id"])
    op.execute("UPDATE scans SET current_attempt_id = id")

    for table, delete_rule in (
        ("scan_tasks", "CASCADE"),
        ("scan_events", "SET NULL"),
        ("approval_gates", "SET NULL"),
        ("scan_outbox", "SET NULL"),
    ):
        op.add_column(
            table,
            sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
        )
        op.create_foreign_key(
            f"fk_{table}_attempt_id",
            table,
            "scan_attempts",
            ["attempt_id"],
            ["id"],
            ondelete=delete_rule,
        )
        op.create_index(f"ix_{table}_attempt_id", table, ["attempt_id"])
        op.execute(
            f"UPDATE {table} t SET attempt_id = s.current_attempt_id "
            f"FROM scans s WHERE t.scan_id = s.id"
        )

    op.create_table(
        "evidence_objects",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("artifact_type", sa.String(length=64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("object_key", sa.String(length=1024), nullable=False),
        sa.Column("object_version", sa.String(length=255), nullable=False),
        sa.Column("media_type", sa.String(length=255), nullable=False),
        sa.Column("plaintext_size", sa.BigInteger(), nullable=False),
        sa.Column("ciphertext_size", sa.BigInteger(), nullable=False),
        sa.Column("plaintext_sha256", sa.String(length=64), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(length=64), nullable=False),
        sa.Column("producer", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("encryption_algorithm", sa.String(length=64), nullable=False),
        sa.Column("key_provider", sa.String(length=32), nullable=False),
        sa.Column("key_id", sa.String(length=512), nullable=False),
        sa.Column("wrapped_data_key", sa.LargeBinary(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("aad_sha256", sa.String(length=64), nullable=False),
        sa.Column("retention_policy", sa.String(length=64), nullable=False),
        sa.Column("retain_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("legal_hold", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("legacy_artifact_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "state IN ('available', 'deletion_pending', 'deleted')",
            name="ck_evidence_objects_state",
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["attempt_id"], ["scan_attempts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["legacy_artifact_id"], ["scan_artifacts.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "attempt_id",
            "artifact_type",
            "version",
            name="uq_evidence_objects_attempt_type_version",
        ),
        sa.UniqueConstraint(
            "legacy_artifact_id", name="uq_evidence_objects_legacy_artifact_id"
        ),
        sa.UniqueConstraint(
            "object_key", "object_version", name="uq_evidence_object_version"
        ),
    )
    op.create_index("ix_evidence_objects_scan_id", "evidence_objects", ["scan_id"])
    op.create_index(
        "ix_evidence_objects_attempt_id", "evidence_objects", ["attempt_id"]
    )
    op.create_index("ix_evidence_objects_tenant_id", "evidence_objects", ["tenant_id"])
    op.create_index(
        "ix_evidence_objects_retention",
        "evidence_objects",
        ["state", "legal_hold", "retain_until"],
    )

    op.create_table(
        "evidence_manifests",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("previous_manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("entries", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("finalized", sa.Boolean(), server_default="false", nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["attempt_id"], ["scan_attempts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "attempt_id", "generation", name="uq_evidence_manifest_generation"
        ),
        sa.UniqueConstraint(
            "attempt_id", "manifest_sha256", name="uq_evidence_manifest_digest"
        ),
    )
    op.create_index("ix_evidence_manifests_scan_id", "evidence_manifests", ["scan_id"])
    op.create_index(
        "ix_evidence_manifests_attempt_id", "evidence_manifests", ["attempt_id"]
    )

    op.create_table(
        "evidence_governance_events",
        sa.Column("id", sa.BigInteger(), sa.Identity(always=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=64), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("correlation_id", sa.String(length=255), nullable=True),
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["attempt_id"], ["scan_attempts.id"], ondelete="CASCADE"
        ),
        sa.ForeignKeyConstraint(
            ["evidence_id"], ["evidence_objects.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_evidence_governance_events_scan_id",
        "evidence_governance_events",
        ["scan_id"],
    )
    op.create_index(
        "ix_evidence_governance_events_attempt_id",
        "evidence_governance_events",
        ["attempt_id"],
    )
    op.create_index(
        "ix_evidence_governance_events_evidence_id",
        "evidence_governance_events",
        ["evidence_id"],
    )
    op.create_index(
        "ix_evidence_governance_events_tenant_id",
        "evidence_governance_events",
        ["tenant_id"],
    )

    op.create_table(
        "evidence_deletion_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("processed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(
            ["evidence_id"], ["evidence_objects.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("evidence_id"),
    )

    op.add_column(
        "scan_artifacts",
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "scan_artifacts",
        sa.Column("evidence_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.alter_column(
        "scan_artifacts", "payload", existing_type=postgresql.JSONB(), nullable=True
    )
    op.create_foreign_key(
        "fk_scan_artifacts_attempt_id",
        "scan_artifacts",
        "scan_attempts",
        ["attempt_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_scan_artifacts_evidence_id",
        "scan_artifacts",
        "evidence_objects",
        ["evidence_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index("ix_scan_artifacts_attempt_id", "scan_artifacts", ["attempt_id"])
    op.create_unique_constraint(
        "uq_scan_artifacts_evidence_id", "scan_artifacts", ["evidence_id"]
    )
    op.execute(
        "UPDATE scan_artifacts a SET attempt_id = s.current_attempt_id "
        "FROM scans s WHERE a.scan_id = s.id"
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_scan_artifacts_evidence_id", "scan_artifacts", type_="unique"
    )
    op.drop_index("ix_scan_artifacts_attempt_id", table_name="scan_artifacts")
    op.drop_constraint(
        "fk_scan_artifacts_evidence_id", "scan_artifacts", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_scan_artifacts_attempt_id", "scan_artifacts", type_="foreignkey"
    )
    op.alter_column(
        "scan_artifacts", "payload", existing_type=postgresql.JSONB(), nullable=False
    )
    op.drop_column("scan_artifacts", "evidence_id")
    op.drop_column("scan_artifacts", "attempt_id")
    op.drop_table("evidence_deletion_outbox")
    op.drop_index(
        "ix_evidence_governance_events_tenant_id",
        table_name="evidence_governance_events",
    )
    op.drop_index(
        "ix_evidence_governance_events_evidence_id",
        table_name="evidence_governance_events",
    )
    op.drop_index(
        "ix_evidence_governance_events_attempt_id",
        table_name="evidence_governance_events",
    )
    op.drop_index(
        "ix_evidence_governance_events_scan_id", table_name="evidence_governance_events"
    )
    op.drop_table("evidence_governance_events")
    op.drop_index("ix_evidence_manifests_attempt_id", table_name="evidence_manifests")
    op.drop_index("ix_evidence_manifests_scan_id", table_name="evidence_manifests")
    op.drop_table("evidence_manifests")
    op.drop_index("ix_evidence_objects_retention", table_name="evidence_objects")
    op.drop_index("ix_evidence_objects_tenant_id", table_name="evidence_objects")
    op.drop_index("ix_evidence_objects_attempt_id", table_name="evidence_objects")
    op.drop_index("ix_evidence_objects_scan_id", table_name="evidence_objects")
    op.drop_table("evidence_objects")
    for table in ("scan_outbox", "approval_gates", "scan_events", "scan_tasks"):
        op.drop_index(f"ix_{table}_attempt_id", table_name=table)
        op.drop_constraint(f"fk_{table}_attempt_id", table, type_="foreignkey")
        op.drop_column(table, "attempt_id")
    op.drop_index("ix_scans_current_attempt_id", table_name="scans")
    op.drop_constraint("fk_scans_current_attempt_id", "scans", type_="foreignkey")
    op.drop_column("scans", "current_attempt_id")
    op.drop_index("uq_scan_attempts_one_active", table_name="scan_attempts")
    op.drop_index("ix_scan_attempts_tenant_id", table_name="scan_attempts")
    op.drop_index("ix_scan_attempts_scan_id", table_name="scan_attempts")
    op.drop_table("scan_attempts")
