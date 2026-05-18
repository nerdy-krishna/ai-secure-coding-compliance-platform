"""add stage_temperatures to scans

Revision ID: 5c2a9e0b3f18
Revises: 3e8f1a6d2c47
Create Date: 2026-05-18 15:00:00.000000

Adds the nullable JSONB `stage_temperatures` column to `scans` — the
per-stage LLM temperature map ({profiler, analysis, consolidation,
merge} → float) chosen at submit time (#78). Nullable: scans created
before this column, and submits that omit it, fall back to the 0.2
default per stage at resolution time.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "5c2a9e0b3f18"
down_revision: Union[str, None] = "3e8f1a6d2c47"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "scans",
        sa.Column("stage_temperatures", JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("scans", "stage_temperatures")
