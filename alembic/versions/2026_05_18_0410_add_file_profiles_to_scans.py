"""add file_profiles to scans

Revision ID: 3e8f1a6d2c47
Revises: 7d1c0a4e9b2f
Create Date: 2026-05-18 04:10:00.000000

Adds the nullable JSONB `file_profiles` column to `scans` — the shared
per-file understanding artifact produced by the FileProfiler (#71): a
{file_path: {summary, security_relevant_operations, applicable_domains}}
map. Nullable for scans created before the profiler existed.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "3e8f1a6d2c47"
down_revision: Union[str, None] = "7d1c0a4e9b2f"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("file_profiles", JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "file_profiles")
