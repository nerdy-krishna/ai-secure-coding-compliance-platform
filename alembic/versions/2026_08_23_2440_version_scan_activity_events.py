"""Version scan activity events.

Revision ID: d6e7f8a9b0c1
Revises: c5d6e7f8a9b0
Create Date: 2026-08-23
"""

from alembic import op
import sqlalchemy as sa


revision = "d6e7f8a9b0c1"
down_revision = "c5d6e7f8a9b0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "scan_events",
        sa.Column("schema_version", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "scan_events",
        sa.Column(
            "activity_kind",
            sa.String(length=32),
            server_default="workflow",
            nullable=False,
        ),
    )
    op.create_check_constraint(
        "ck_scan_events_schema_version_positive",
        "scan_events",
        "schema_version > 0",
    )
    op.create_index(
        "uq_scan_events_cancellation_phase",
        "scan_events",
        ["scan_id", "attempt_id", "status"],
        unique=True,
        postgresql_where=sa.text("stage_name = 'CANCELLATION'"),
    )
    op.create_check_constraint(
        "ck_scan_events_activity_kind",
        "scan_events",
        "activity_kind IN ('workflow', 'scanner', 'llm_call', 'retry', 'warning', "
        "'degradation', 'decision', 'cancellation', 'terminal')",
    )


def downgrade() -> None:
    op.drop_index("uq_scan_events_cancellation_phase", table_name="scan_events")
    op.drop_constraint("ck_scan_events_activity_kind", "scan_events", type_="check")
    op.drop_constraint(
        "ck_scan_events_schema_version_positive", "scan_events", type_="check"
    )
    op.drop_column("scan_events", "activity_kind")
    op.drop_column("scan_events", "schema_version")
