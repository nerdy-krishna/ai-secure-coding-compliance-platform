"""add scan_events.details column

Adds a nullable JSONB payload to ScanEvent rows so per-event context
(e.g. `FILE_ANALYZED` with `{file_path, findings_count}` for §3.10b's
mid-scan finding deltas) can ride alongside the stage_name + status
through the SSE stream. NULL for all legacy events.

Revision ID: c00c968f0503
Revises: 041e434197c3
Create Date: 2026-04-26 20:01:13.984281

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "c00c968f0503"
down_revision: Union[str, None] = "041e434197c3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scan_events",
        sa.Column("details", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("scan_events", "details")
