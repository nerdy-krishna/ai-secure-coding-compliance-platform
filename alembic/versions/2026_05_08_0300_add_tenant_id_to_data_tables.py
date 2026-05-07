"""extend tenant scoping to projects / scans / findings / chat_sessions

Revision ID: c52d8a4a1f37
Revises: a107d2b3e859
Create Date: 2026-05-08 03:00:00.000000

Per-tenant foundation (Chunk 8) — purely additive schema. Following
the same pattern as the auth-aggregate scoping migration:

  * Add a nullable ``tenant_id UUID`` FK on each of the four core
    data tables (projects, scans, findings, chat_sessions).
  * Backfill via the existing ownership chain:
      - projects.tenant_id      ← user.tenant_id          (via projects.user_id)
      - scans.tenant_id         ← user.tenant_id          (via scans.user_id)
      - findings.tenant_id      ← scan.tenant_id          (via findings.scan_id)
      - chat_sessions.tenant_id ← user.tenant_id          (via chat_sessions.user_id)
    All existing rows end up pointing at the seeded default tenant
    because Chunk 7 backfilled every user.tenant_id to it.
  * Add an index on each tenant_id column for the future
    per-tenant query path.

Behaviour stays unchanged — there is NO scope check yet anywhere in
the request layer; that work lives in Chunk 9. This migration only
makes the data shape ready.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


revision: str = "c52d8a4a1f37"
down_revision: Union[str, None] = "a107d2b3e859"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# (table, fk_constraint, index_name).
_TARGETS = [
    ("projects", "fk_projects_tenant_id", "ix_projects_tenant_id"),
    ("scans", "fk_scans_tenant_id", "ix_scans_tenant_id"),
    ("findings", "fk_findings_tenant_id", "ix_findings_tenant_id"),
    ("chat_sessions", "fk_chat_sessions_tenant_id", "ix_chat_sessions_tenant_id"),
]


def upgrade() -> None:
    # ---- 1. Add nullable tenant_id columns ----------------------------------
    for table, fk_name, _ix in _TARGETS:
        op.add_column(
            table,
            sa.Column(
                "tenant_id",
                PG_UUID(as_uuid=True),
                sa.ForeignKey("tenants.id", ondelete="SET NULL", name=fk_name),
                nullable=True,
            ),
        )

    # ---- 2. Backfill ---------------------------------------------------------
    # The "user" table is double-quoted because USER is a SQL reserved word
    # in Postgres; consistent quoting is harmless on the others.
    op.execute(
        """
        UPDATE projects p
           SET tenant_id = u.tenant_id
          FROM "user" u
         WHERE u.id = p.user_id
           AND p.tenant_id IS NULL
        """
    )
    op.execute(
        """
        UPDATE scans s
           SET tenant_id = u.tenant_id
          FROM "user" u
         WHERE u.id = s.user_id
           AND s.tenant_id IS NULL
        """
    )
    # findings goes via scan, NOT via user, so a finding from another
    # user's scan (visible via groups) inherits the scan's tenant.
    op.execute(
        """
        UPDATE findings f
           SET tenant_id = s.tenant_id
          FROM scans s
         WHERE s.id = f.scan_id
           AND f.tenant_id IS NULL
        """
    )
    op.execute(
        """
        UPDATE chat_sessions c
           SET tenant_id = u.tenant_id
          FROM "user" u
         WHERE u.id = c.user_id
           AND c.tenant_id IS NULL
        """
    )

    # ---- 3. Indexes ---------------------------------------------------------
    for table, _fk, ix in _TARGETS:
        op.create_index(ix, table, ["tenant_id"], unique=False)


def downgrade() -> None:
    for table, fk_name, ix in reversed(_TARGETS):
        op.drop_index(ix, table_name=table)
        op.drop_constraint(fk_name, table, type_="foreignkey")
        op.drop_column(table, "tenant_id")
