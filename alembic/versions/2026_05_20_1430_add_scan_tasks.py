"""add durable scan task ledger

Revision ID: c4d8e9f1a2b3
Revises: b1e7f4a2c9d3
Create Date: 2026-05-20 14:30:00.000000

Adds scan-scoped durable task rows used by resumable scan work. Tasks are
unique by scan/type/key and carry input, prompt, and version hashes so
completed work can be reused only when the task input is unchanged.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c4d8e9f1a2b3"
down_revision: Union[str, None] = "b1e7f4a2c9d3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


_TASK_STATUS_CHECK = (
    "status IN ('pending', 'running', 'completed', 'failed', 'stale', 'retryable')"
)


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "scan_tasks",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("task_type", sa.String(length=64), nullable=False),
        sa.Column("task_key", sa.Text(), nullable=False),
        sa.Column("input_hash", sa.String(length=64), nullable=False),
        sa.Column("prompt_hash", sa.String(length=64), nullable=False),
        sa.Column("version_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "input_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=False
        ),
        sa.Column(
            "result_payload", postgresql.JSONB(astext_type=sa.Text()), nullable=True
        ),
        sa.Column("status", sa.String(length=20), nullable=False),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_attempts", sa.Integer(), nullable=False, server_default="3"),
        sa.Column("lease_owner", sa.String(length=255), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
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
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(_TASK_STATUS_CHECK, name="ck_scan_tasks_status"),
        sa.CheckConstraint("attempts >= 0", name="ck_scan_tasks_attempts_nonnegative"),
        sa.CheckConstraint(
            "max_attempts > 0", name="ck_scan_tasks_max_attempts_positive"
        ),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "scan_id", "task_type", "task_key", name="uq_scan_tasks_scan_type_key"
        ),
    )
    op.create_index("ix_scan_tasks_scan_id", "scan_tasks", ["scan_id"])
    op.create_index("ix_scan_tasks_status", "scan_tasks", ["status"])
    op.create_index(
        "ix_scan_tasks_lease_expires_at", "scan_tasks", ["lease_expires_at"]
    )
    op.create_index(
        "ix_scan_tasks_scan_type_input_hash",
        "scan_tasks",
        ["scan_id", "task_type", "input_hash"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_scan_tasks_scan_type_input_hash", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_lease_expires_at", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_status", table_name="scan_tasks")
    op.drop_index("ix_scan_tasks_scan_id", table_name="scan_tasks")
    op.drop_table("scan_tasks")
