"""add source_type to scans

Revision ID: b1e7f4a2c9d3
Revises: f3a9c1d7e8b5
Create Date: 2026-05-19 12:00:00.000000

Records how a scan's code was submitted — direct file upload, archive
upload, or a git repository — so the results page and the report can
state the source precisely. Nullable; pre-existing rows keep NULL.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "b1e7f4a2c9d3"
down_revision: Union[str, None] = "f3a9c1d7e8b5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "scans",
        sa.Column("source_type", sa.String(length=20), nullable=True),
    )
    op.create_check_constraint(
        "ck_scans_source_type",
        "scans",
        "source_type IS NULL OR source_type IN ('upload', 'archive', 'git')",
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint("ck_scans_source_type", "scans", type_="check")
    op.drop_column("scans", "source_type")
