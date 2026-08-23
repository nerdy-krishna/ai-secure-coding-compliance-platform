"""Preserve evidence manifests and audit tombstones after scan deletion.

Revision ID: a3b4c5d6e7f8
Revises: f2a3b4c5d6e7
Create Date: 2026-08-23
"""

from alembic import op
from sqlalchemy.dialects import postgresql


revision = "a3b4c5d6e7f8"
down_revision = "f2a3b4c5d6e7"
branch_labels = None
depends_on = None


_TABLES = (
    "evidence_objects",
    "evidence_manifests",
    "evidence_governance_events",
)


def upgrade() -> None:
    for table in _TABLES:
        op.drop_constraint(f"{table}_scan_id_fkey", table, type_="foreignkey")
        op.drop_constraint(f"{table}_attempt_id_fkey", table, type_="foreignkey")
        op.alter_column(
            table,
            "scan_id",
            existing_type=postgresql.UUID(as_uuid=True),
            nullable=True,
        )
        op.alter_column(
            table,
            "attempt_id",
            existing_type=postgresql.UUID(as_uuid=True),
            nullable=True,
        )
        op.create_foreign_key(
            f"{table}_scan_id_fkey",
            table,
            "scans",
            ["scan_id"],
            ["id"],
            ondelete="SET NULL",
        )
        op.create_foreign_key(
            f"{table}_attempt_id_fkey",
            table,
            "scan_attempts",
            ["attempt_id"],
            ["id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    for table in reversed(_TABLES):
        op.drop_constraint(f"{table}_attempt_id_fkey", table, type_="foreignkey")
        op.drop_constraint(f"{table}_scan_id_fkey", table, type_="foreignkey")
        op.execute(f"DELETE FROM {table} WHERE scan_id IS NULL OR attempt_id IS NULL")
        op.alter_column(
            table,
            "attempt_id",
            existing_type=postgresql.UUID(as_uuid=True),
            nullable=False,
        )
        op.alter_column(
            table,
            "scan_id",
            existing_type=postgresql.UUID(as_uuid=True),
            nullable=False,
        )
        op.create_foreign_key(
            f"{table}_attempt_id_fkey",
            table,
            "scan_attempts",
            ["attempt_id"],
            ["id"],
            ondelete="CASCADE",
        )
        op.create_foreign_key(
            f"{table}_scan_id_fkey",
            table,
            "scans",
            ["scan_id"],
            ["id"],
            ondelete="CASCADE",
        )
