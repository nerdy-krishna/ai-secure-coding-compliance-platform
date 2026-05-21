"""add version columns for optimistic locking

Revision ID: 8d3029fce81f
Revises: 2df4cb49c309
Create Date: 2026-05-01 14:09:48.553437

V02.3.4 — adds an `INTEGER NOT NULL DEFAULT 1` `version` column to
`system_configurations` and `user_groups`. The column is bumped on
every UPDATE; the corresponding repo (`set_value`/`update_group`)
uses a conditional UPDATE keyed on `expected_version` to detect lost
concurrent writes and raises `OptimisticLockError(current_version=...)`
on mismatch. Routers translate that to HTTP 409.

Server default = "1" so existing rows are pre-populated; no data
backfill needed.

Note: autogenerate flagged spurious drops on `ix_scan_outbox_unpublished`
and `ix_user_group_memberships_user_id` due to partial-index
introspection quirks; those operations are intentionally NOT in this
migration.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8d3029fce81f"
down_revision: Union[str, None] = "2df4cb49c309"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "system_configurations",
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
    )
    op.add_column(
        "user_groups",
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("user_groups", "version")
    op.drop_column("system_configurations", "version")
