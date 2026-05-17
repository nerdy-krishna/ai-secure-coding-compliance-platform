"""add vulnerable_snippet to findings

Revision ID: 9a158d039ef7
Revises: 7b3cd482c485
Create Date: 2026-05-17 19:34:08.370002

Adds the nullable `vulnerable_snippet` column to `findings` — the exact
verbatim vulnerable code for a finding, used to anchor its line number
and the precise UI highlight span. Nullable: legacy findings and
deterministic-scanner findings carry no snippet.

Hand-trimmed: autogenerate also reported spurious `drop_index` calls for
partial / GIN / expression indexes it cannot round-trip introspect
(`ix_scan_outbox_unpublished`, the `semgrep_rules` GIN indexes,
`ix_auth_audit_events_*`, etc.). Those indexes are correct in the DB;
dropping them would be a regression, so only the `add_column` is kept.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9a158d039ef7"
down_revision: Union[str, None] = "7b3cd482c485"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "findings",
        sa.Column("vulnerable_snippet", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("findings", "vulnerable_snippet")
