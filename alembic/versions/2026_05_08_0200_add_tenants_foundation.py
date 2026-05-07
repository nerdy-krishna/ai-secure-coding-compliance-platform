"""add tenants table + nullable tenant_id on auth aggregates

Revision ID: a107d2b3e859
Revises: f4a91c20bdb6
Create Date: 2026-05-08 02:00:00.000000

Per-tenant foundation (Chunk 7) — pure schema scaffolding, no behavior
change. Existing single-tenant deployments continue to work because all
new ``tenant_id`` columns are NULLable and existing rows are backfilled
to the seeded ``default`` tenant.

Scope:
  * New ``tenants`` table.
  * New nullable ``tenant_id`` FK columns on the auth-adjacent
    aggregates: users, sso_providers, oauth_accounts, saml_subjects,
    user_groups, auth_audit_events. ALL backfill to the default tenant.
  * Project / scan / finding / chat-session aggregates are intentionally
    LEFT ALONE — they're scoped today by ``visible_user_ids`` (which
    derives from user_groups), and adding tenant scoping there is its
    own future phase. Foundation now; enforcement later.

Append-only audit table caveat: ``auth_audit_events`` carries the
``auth_audit_immutable`` trigger that rejects UPDATE/DELETE. ALTER TABLE
ADD COLUMN bypasses the trigger (it's a DDL operation, not a row-level
write), so the column add itself succeeds. The backfill UPDATE is
performed by temporarily dropping + recreating the trigger — operators
can verify the trigger is back at the end of the migration.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


revision: str = "a107d2b3e859"
down_revision: Union[str, None] = "f4a91c20bdb6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Tables that gain a nullable tenant_id column. Each tuple is
# (table_name, fk_constraint_name).
_TARGETS = [
    ("user", "fk_user_tenant_id"),
    ("sso_providers", "fk_sso_providers_tenant_id"),
    ("oauth_accounts", "fk_oauth_accounts_tenant_id"),
    ("saml_subjects", "fk_saml_subjects_tenant_id"),
    ("user_groups", "fk_user_groups_tenant_id"),
    ("auth_audit_events", "fk_auth_audit_events_tenant_id"),
]


def upgrade() -> None:
    # ---- 1. tenants table -----------------------------------------------
    op.create_table(
        "tenants",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("slug", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("slug", name="uq_tenants_slug"),
    )

    # Seed the default tenant. Backfilled into every existing aggregate.
    op.execute(
        """
        INSERT INTO tenants (id, slug, display_name)
        VALUES (
            '00000000-0000-0000-0000-000000000001',
            'default',
            'Default Tenant'
        )
        """
    )

    # ---- 2. Add nullable tenant_id on each target -----------------------
    for table_name, fk_name in _TARGETS:
        op.add_column(
            table_name,
            sa.Column(
                "tenant_id",
                PG_UUID(as_uuid=True),
                sa.ForeignKey("tenants.id", ondelete="SET NULL", name=fk_name),
                nullable=True,
            ),
        )

    # ---- 3. Backfill existing rows -------------------------------------
    # Every target except auth_audit_events takes a plain UPDATE. The
    # table name is double-quoted because `user` is a SQL reserved word
    # in Postgres; quoting it consistently is harmless for the others.
    plain_targets = [t for t, _ in _TARGETS if t != "auth_audit_events"]
    for table_name in plain_targets:
        op.execute(
            f"""
            UPDATE "{table_name}"
            SET tenant_id = '00000000-0000-0000-0000-000000000001'
            WHERE tenant_id IS NULL
            """
        )

    # auth_audit_events has the immutability trigger — drop, backfill,
    # restore. The trigger is RECREATED below; operators can verify
    # post-migration via `\d+ auth_audit_events` in psql.
    op.execute(
        "DROP TRIGGER IF EXISTS auth_audit_immutable ON auth_audit_events"
    )
    op.execute(
        """
        UPDATE auth_audit_events
        SET tenant_id = '00000000-0000-0000-0000-000000000001'
        WHERE tenant_id IS NULL
        """
    )
    op.execute(
        """
        CREATE TRIGGER auth_audit_immutable
        BEFORE UPDATE OR DELETE ON auth_audit_events
        FOR EACH ROW EXECUTE FUNCTION auth_audit_events_block_modify()
        """
    )

    # Indexes for future tenant-scoped queries. Add on the larger,
    # frequently-queried tables; small reference tables (sso_providers,
    # user_groups) don't need them yet.
    op.create_index(
        "ix_user_tenant_id",
        "user",
        ["tenant_id"],
        unique=False,
    )
    op.create_index(
        "ix_auth_audit_events_tenant_id",
        "auth_audit_events",
        ["tenant_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_auth_audit_events_tenant_id", table_name="auth_audit_events")
    op.drop_index("ix_user_tenant_id", table_name="user")

    # Restore the audit immutability dance (drop trigger before any DDL on
    # the audited table, then recreate after).
    op.execute(
        "DROP TRIGGER IF EXISTS auth_audit_immutable ON auth_audit_events"
    )

    for table_name, fk_name in reversed(_TARGETS):
        op.drop_constraint(fk_name, table_name, type_="foreignkey")
        op.drop_column(table_name, "tenant_id")

    op.execute(
        """
        CREATE TRIGGER auth_audit_immutable
        BEFORE UPDATE OR DELETE ON auth_audit_events
        FOR EACH ROW EXECUTE FUNCTION auth_audit_events_block_modify()
        """
    )

    op.drop_table("tenants")
