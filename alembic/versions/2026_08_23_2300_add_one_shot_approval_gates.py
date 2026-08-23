"""add durable one-shot approval gates

Revision ID: d0e1f2a3b4c5
Revises: c9d0e1f2a3b4
Create Date: 2026-08-23 23:00:00.000000
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "d0e1f2a3b4c5"
down_revision: Union[str, None] = "c9d0e1f2a3b4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "approval_gates",
        sa.Column("gate_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("thread_id", sa.String(length=128), nullable=False),
        sa.Column("checkpoint_id", sa.String(length=128), nullable=True),
        sa.Column("node_name", sa.String(length=100), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("sequence", sa.Integer(), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("purpose", sa.Text(), nullable=False),
        sa.Column("evidence_hash", sa.String(length=64), nullable=False),
        sa.Column("evidence", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("state", sa.String(length=24), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("decision", sa.Boolean(), nullable=True),
        sa.Column(
            "override_critical_secret",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("actor_user_id", sa.Integer(), nullable=True),
        sa.Column("decision_idempotency_key", sa.String(length=128), nullable=True),
        sa.Column("resume_claimed_by", sa.String(length=255), nullable=True),
        sa.Column("resume_lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "kind IN ('prescan_approval', 'profiling_approval', 'cost_approval')",
            name="ck_approval_gates_kind",
        ),
        sa.CheckConstraint(
            "state IN ('pending', 'decided', 'resume_claimed', 'completed', "
            "'expired', 'cancelled')",
            name="ck_approval_gates_state",
        ),
        sa.CheckConstraint("version > 0", name="ck_approval_gates_version_positive"),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["user.id"],
            name="fk_approval_gates_actor",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["scan_id"], ["scans.id"], name="fk_approval_gates_scan", ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("gate_id"),
        sa.UniqueConstraint(
            "scan_id",
            "decision_idempotency_key",
            name="uq_approval_gates_scan_decision_key",
        ),
        sa.UniqueConstraint(
            "scan_id", "sequence", name="uq_approval_gates_scan_sequence"
        ),
    )
    op.create_index("ix_approval_gates_scan_id", "approval_gates", ["scan_id"])
    op.create_index(
        "ix_approval_gates_resume_lease_expires_at",
        "approval_gates",
        ["resume_lease_expires_at"],
    )
    op.create_index(
        "uq_approval_gates_one_active_per_scan",
        "approval_gates",
        ["scan_id"],
        unique=True,
        postgresql_where=sa.text("state IN ('pending', 'decided', 'resume_claimed')"),
    )
    op.add_column(
        "scan_outbox",
        sa.Column("idempotency_key", sa.String(length=255), nullable=True),
    )
    op.create_unique_constraint(
        "uq_scan_outbox_idempotency_key", "scan_outbox", ["idempotency_key"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_scan_outbox_idempotency_key", "scan_outbox", type_="unique")
    op.drop_column("scan_outbox", "idempotency_key")
    op.drop_index("uq_approval_gates_one_active_per_scan", table_name="approval_gates")
    op.drop_index(
        "ix_approval_gates_resume_lease_expires_at", table_name="approval_gates"
    )
    op.drop_index("ix_approval_gates_scan_id", table_name="approval_gates")
    op.drop_table("approval_gates")
