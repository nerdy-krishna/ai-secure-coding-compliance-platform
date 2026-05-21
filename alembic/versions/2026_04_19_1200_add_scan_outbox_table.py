"""Add scan_outbox table for atomic scan submission

Revision ID: c1f4a9e2b3d5
Revises: 52a101f3e9c5
Create Date: 2026-04-19 12:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = "c1f4a9e2b3d5"
down_revision: Union[str, None] = "52a101f3e9c5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_outbox",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("queue_name", sa.String(length=255), nullable=False),
        sa.Column("payload", postgresql.JSONB, nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
    )
    # Partial index: unpublished rows only — the sweep query is always
    # "WHERE published_at IS NULL", so we don't need to index published rows.
    op.create_index(
        "ix_scan_outbox_unpublished",
        "scan_outbox",
        ["created_at"],
        postgresql_where=sa.text("published_at IS NULL"),
    )


def downgrade() -> None:
    op.drop_index("ix_scan_outbox_unpublished", table_name="scan_outbox")
    op.drop_table("scan_outbox")
