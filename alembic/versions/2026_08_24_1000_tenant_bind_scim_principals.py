"""Tenant-bind SCIM service principals and their database access.

Revision ID: 8d06e9f42a15
Revises: 7c95d8e31f04
Create Date: 2026-08-24 10:00:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "8d06e9f42a15"
down_revision: Union[str, None] = "7c95d8e31f04"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


DEFAULT_TENANT = "00000000-0000-0000-0000-000000000001"


def upgrade() -> None:
    op.add_column(
        "scim_tokens",
        sa.Column("tenant_id", sa.UUID(), nullable=True),
    )
    op.execute(
        f"""
        UPDATE scim_tokens t
        SET tenant_id = COALESCE(
            (SELECT u.tenant_id FROM "user" u WHERE u.id = t.created_by_user_id),
            '{DEFAULT_TENANT}'::uuid
        )
        """
    )
    op.alter_column(
        "scim_tokens",
        "tenant_id",
        existing_type=sa.UUID(),
        nullable=False,
        server_default=sa.text(f"'{DEFAULT_TENANT}'::uuid"),
    )
    op.create_foreign_key(
        "fk_scim_tokens_tenant_id",
        "scim_tokens",
        "tenants",
        ["tenant_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_index("ix_scim_tokens_tenant_id", "scim_tokens", ["tenant_id"])
    op.execute(
        """
        CREATE TRIGGER sccap_tenant_reference_0
        BEFORE INSERT OR UPDATE OF tenant_id, created_by_user_id ON scim_tokens
        FOR EACH ROW EXECUTE FUNCTION sccap_enforce_tenant_reference(
            'user', 'id', 'created_by_user_id'
        )
        """
    )
    op.execute("ALTER TABLE scim_tokens ENABLE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE scim_tokens FORCE ROW LEVEL SECURITY")
    op.execute(
        """
        CREATE POLICY sccap_tenant_isolation ON scim_tokens
        USING (
            sccap_has_system_scope()
            OR tenant_id = sccap_current_tenant_id()
        )
        WITH CHECK (
            sccap_has_system_scope()
            OR tenant_id = sccap_current_tenant_id()
        )
        """
    )

def downgrade() -> None:
    op.execute("DROP POLICY IF EXISTS sccap_tenant_isolation ON scim_tokens")
    op.execute("ALTER TABLE scim_tokens NO FORCE ROW LEVEL SECURITY")
    op.execute("ALTER TABLE scim_tokens DISABLE ROW LEVEL SECURITY")
    op.execute("DROP TRIGGER IF EXISTS sccap_tenant_reference_0 ON scim_tokens")
    op.drop_index("ix_scim_tokens_tenant_id", table_name="scim_tokens")
    op.drop_constraint(
        "fk_scim_tokens_tenant_id",
        "scim_tokens",
        type_="foreignkey",
    )
    op.drop_column("scim_tokens", "tenant_id")
