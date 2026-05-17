"""add affected_locations to findings

Revision ID: 60bc2fe86848
Revises: 9a158d039ef7
Create Date: 2026-05-17 21:40:56.562252

Adds the nullable JSONB `affected_locations` column to `findings` — a
list of `{line_number, snippet}` enumerating every site a finding's
vulnerability manifests beyond its primary fix-anchor location. Set by
the consolidation pass for merged findings; NULL for single-site and
legacy findings.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

# revision identifiers, used by Alembic.
revision: str = "60bc2fe86848"
down_revision: Union[str, None] = "9a158d039ef7"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("affected_locations", JSONB(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "affected_locations")
