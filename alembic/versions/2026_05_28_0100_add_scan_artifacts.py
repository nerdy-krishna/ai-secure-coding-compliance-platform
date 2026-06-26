"""Add scan_artifacts table for versioned scan lineage and other
pipeline outputs.

Revision ID: c3d4e5f6a7b8
Revises: 7e8f9a0b1c2d
Create Date: 2026-05-28 01:00:00.000000
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c3d4e5f6a7b8"
down_revision: Union[str, None] = "7e8f9a0b1c2d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scan_artifacts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "scan_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("scans.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column("artifact_type", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("payload", postgresql.JSONB(), nullable=False),
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
            onupdate=sa.func.now(),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "scan_id",
            "artifact_type",
            "version",
            name="uq_scan_artifacts_type_version",
        ),
    )


def downgrade() -> None:
    op.drop_table("scan_artifacts")
