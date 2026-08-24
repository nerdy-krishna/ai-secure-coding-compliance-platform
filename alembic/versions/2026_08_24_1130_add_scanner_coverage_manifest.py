"""Add durable scanner/input coverage manifests and policy decisions.

Revision ID: d4e71a9c6b20
Revises: c2a84f6d1e39
Create Date: 2026-08-24 11:30:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "d4e71a9c6b20"
down_revision: Union[str, None] = "c2a84f6d1e39"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TABLES = (
    "scanner_coverage_entries",
    "scanner_coverage_policy_decisions",
)


def upgrade() -> None:
    op.create_table(
        "scanner_coverage_entries",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("attempt_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column("scanner_name", sa.String(length=64), nullable=False),
        sa.Column("input_path", sa.Text(), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("reason_code", sa.String(length=64), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("finding_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "native_evidence_available",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("provenance_status", sa.String(length=20), nullable=True),
        sa.Column(
            "details",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status IN ('planned', 'completed', 'clean', 'skipped', 'failed', "
            "'timeout', 'unsupported', 'truncated')",
            name="ck_scanner_coverage_status",
        ),
        sa.ForeignKeyConstraint(["attempt_id"], ["scan_attempts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "attempt_id",
            "scanner_name",
            "input_path",
            name="uq_scanner_coverage_attempt_scanner_input",
        ),
    )
    op.create_index(
        "ix_scanner_coverage_entries_scan_id",
        "scanner_coverage_entries",
        ["scan_id"],
    )
    op.create_index(
        "ix_scanner_coverage_entries_attempt_id",
        "scanner_coverage_entries",
        ["attempt_id"],
    )
    op.create_index(
        "ix_scanner_coverage_entries_tenant_id",
        "scanner_coverage_entries",
        ["tenant_id"],
    )
    op.create_table(
        "scanner_coverage_policy_decisions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("scan_id", sa.UUID(), nullable=False),
        sa.Column("attempt_id", sa.UUID(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=False),
        sa.Column(
            "failing_states", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column(
            "matching_entry_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("outcome", sa.String(length=16), nullable=False),
        sa.Column("audit_reason", sa.Text(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('pass', 'fail', 'waived')",
            name="ck_scanner_coverage_policy_outcome",
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["user.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["attempt_id"], ["scan_attempts.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_scanner_coverage_policy_decisions_scan_id",
        "scanner_coverage_policy_decisions",
        ["scan_id"],
    )
    op.create_index(
        "ix_scanner_coverage_policy_decisions_attempt_id",
        "scanner_coverage_policy_decisions",
        ["attempt_id"],
    )
    op.create_index(
        "ix_scanner_coverage_policy_decisions_tenant_id",
        "scanner_coverage_policy_decisions",
        ["tenant_id"],
    )
    op.add_column("findings", sa.Column("coverage_entry_id", sa.UUID(), nullable=True))
    op.add_column(
        "findings",
        sa.Column(
            "coverage_entry_ids",
            postgresql.ARRAY(sa.UUID()),
            nullable=True,
        ),
    )
    op.create_index(
        "ix_findings_coverage_entry_id", "findings", ["coverage_entry_id"]
    )
    op.create_foreign_key(
        "fk_findings_coverage_entry_id",
        "findings",
        "scanner_coverage_entries",
        ["coverage_entry_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.execute(
        """
        CREATE FUNCTION sccap_enforce_finding_coverage_tenant()
        RETURNS trigger AS $$
        DECLARE visible_count integer;
        BEGIN
            IF NEW.coverage_entry_id IS NOT NULL AND NOT EXISTS (
                SELECT 1 FROM scanner_coverage_entries c
                WHERE c.id = NEW.coverage_entry_id AND c.tenant_id = NEW.tenant_id
            ) THEN
                RAISE EXCEPTION 'cross-tenant scanner coverage reference rejected';
            END IF;
            IF NEW.coverage_entry_ids IS NOT NULL THEN
                SELECT count(*) INTO visible_count
                FROM scanner_coverage_entries c
                WHERE c.id = ANY(NEW.coverage_entry_ids)
                  AND c.tenant_id = NEW.tenant_id;
                IF visible_count <> cardinality(NEW.coverage_entry_ids) THEN
                    RAISE EXCEPTION 'cross-tenant scanner coverage references rejected';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER sccap_finding_coverage_tenant
        BEFORE INSERT OR UPDATE OF tenant_id, coverage_entry_id, coverage_entry_ids
        ON findings
        FOR EACH ROW EXECUTE FUNCTION sccap_enforce_finding_coverage_tenant()
        """
    )

    references = {
        "scanner_coverage_entries": (
            ("scans", "id", "scan_id"),
            ("scan_attempts", "id", "attempt_id"),
        ),
        "scanner_coverage_policy_decisions": (
            ("scans", "id", "scan_id"),
            ("scan_attempts", "id", "attempt_id"),
            ("user", "id", "actor_user_id"),
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
    for table in _TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY sccap_tenant_isolation ON {table}
            USING (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())
            WITH CHECK (sccap_has_system_scope() OR tenant_id = sccap_current_tenant_id())
            """
        )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS sccap_finding_coverage_tenant ON findings")
    op.execute("DROP FUNCTION IF EXISTS sccap_enforce_finding_coverage_tenant()")
    op.drop_constraint("fk_findings_coverage_entry_id", "findings", type_="foreignkey")
    op.drop_index("ix_findings_coverage_entry_id", table_name="findings")
    op.drop_column("findings", "coverage_entry_id")
    op.drop_column("findings", "coverage_entry_ids")
    op.drop_table("scanner_coverage_policy_decisions")
    op.drop_table("scanner_coverage_entries")
