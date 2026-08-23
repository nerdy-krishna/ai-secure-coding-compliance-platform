"""Add one-shot pre-provider call reservations.

Revision ID: c5d6e7f8a9b0
Revises: b4c5d6e7f8a9
Create Date: 2026-08-23
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "c5d6e7f8a9b0"
down_revision = "b4c5d6e7f8a9"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "llm_call_reservations",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("idempotency_key", sa.String(length=512), nullable=False),
        sa.Column("owner_token", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("attempt_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("llm_config_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("stage", sa.String(length=100), nullable=False),
        sa.Column(
            "status", sa.String(length=20), server_default="reserved", nullable=False
        ),
        sa.Column("usage_event_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "status IN ('reserved', 'completed', 'failed')",
            name="ck_llm_call_reservations_status",
        ),
        sa.ForeignKeyConstraint(
            ["attempt_id"], ["scan_attempts.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(
            ["llm_config_id"], ["llm_configurations.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(
            ["usage_event_id"], ["llm_usage_events.id"], ondelete="SET NULL"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("idempotency_key"),
        sa.UniqueConstraint("owner_token"),
        sa.UniqueConstraint("usage_event_id"),
    )
    op.create_index(
        "ix_llm_call_reservations_scan_id",
        "llm_call_reservations",
        ["scan_id"],
        unique=False,
    )
    op.create_index(
        "ix_llm_call_reservations_attempt_id",
        "llm_call_reservations",
        ["attempt_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_llm_call_reservations_attempt_id", table_name="llm_call_reservations"
    )
    op.drop_index(
        "ix_llm_call_reservations_scan_id", table_name="llm_call_reservations"
    )
    op.drop_table("llm_call_reservations")
