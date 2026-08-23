"""Attribute scan LLM usage to a stable scan attempt.

Revision ID: b4c5d6e7f8a9
Revises: a3b4c5d6e7f8
Create Date: 2026-08-23
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "b4c5d6e7f8a9"
down_revision = "a3b4c5d6e7f8"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "llm_usage_events",
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_index(
        "ix_llm_usage_events_attempt_id",
        "llm_usage_events",
        ["attempt_id"],
        unique=False,
    )
    op.create_foreign_key(
        "llm_usage_events_attempt_id_fkey",
        "llm_usage_events",
        "scan_attempts",
        ["attempt_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.execute(
        """
        UPDATE llm_usage_events AS usage
        SET attempt_id = scans.current_attempt_id
        FROM scans
        WHERE usage.scan_id = scans.id
          AND usage.attempt_id IS NULL
        """
    )


def downgrade() -> None:
    op.drop_constraint(
        "llm_usage_events_attempt_id_fkey",
        "llm_usage_events",
        type_="foreignkey",
    )
    op.drop_index("ix_llm_usage_events_attempt_id", table_name="llm_usage_events")
    op.drop_column("llm_usage_events", "attempt_id")
