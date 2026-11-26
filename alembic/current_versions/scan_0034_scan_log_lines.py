"""Per-scan application log capture for the live activity log.

Adds `scan_log_lines`: a bounded, redacted debug view of the application log
attributed to a scan, so the scan page can show worker/API log lines live
instead of making an operator query Loki. Kept apart from `scan_events`, which
stays the audit trail.

Revision ID: scan0034
Revises: pentest0033
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

revision = "scan0034"
down_revision = "pentest0033"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "scan_log_lines",
        sa.Column(
            "id",
            sa.BigInteger(),
            sa.Identity(always=True),
            primary_key=True,
        ),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("level", sa.String(10), nullable=False),
        sa.Column("logger_name", sa.String(120), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
    )
    op.create_index("ix_scan_log_lines_scan_id_id", "scan_log_lines", ["scan_id", "id"])


def downgrade() -> None:
    op.drop_index("ix_scan_log_lines_scan_id_id", table_name="scan_log_lines")
    op.drop_table("scan_log_lines")
