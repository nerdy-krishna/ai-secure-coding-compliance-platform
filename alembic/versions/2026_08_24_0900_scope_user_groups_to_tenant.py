"""Scope user-group identity and membership invariants to one tenant.

Revision ID: 7c95d8e31f04
Revises: 6b84c7a20d32
Create Date: 2026-08-24 09:00:00
"""

from typing import Sequence, Union

from alembic import op


revision: str = "7c95d8e31f04"
down_revision: Union[str, None] = "6b84c7a20d32"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1
                FROM user_group_memberships m
                JOIN user_groups g ON g.id = m.group_id
                JOIN "user" u ON u.id = m.user_id
                WHERE g.tenant_id IS DISTINCT FROM u.tenant_id
            ) THEN
                RAISE EXCEPTION
                    'cross-tenant user-group memberships must be remediated before upgrade'
                    USING ERRCODE = '23514';
            END IF;
        END
        $$
        """
    )
    op.drop_constraint("user_groups_name_key", "user_groups", type_="unique")
    op.create_unique_constraint(
        "uq_user_groups_tenant_name",
        "user_groups",
        ["tenant_id", "name"],
    )
    op.execute(
        """
        CREATE FUNCTION sccap_enforce_group_membership_tenant()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                FROM user_groups g
                JOIN "user" u ON u.id = NEW.user_id
                WHERE g.id = NEW.group_id
                  AND g.tenant_id = u.tenant_id
            ) THEN
                RAISE EXCEPTION 'group membership tenant mismatch'
                    USING ERRCODE = '23514';
            END IF;
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER sccap_group_membership_tenant
        BEFORE INSERT OR UPDATE OF group_id, user_id ON user_group_memberships
        FOR EACH ROW EXECUTE FUNCTION sccap_enforce_group_membership_tenant()
        """
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS sccap_group_membership_tenant "
        "ON user_group_memberships"
    )
    op.execute("DROP FUNCTION IF EXISTS sccap_enforce_group_membership_tenant()")
    op.drop_constraint(
        "uq_user_groups_tenant_name",
        "user_groups",
        type_="unique",
    )
    op.create_unique_constraint("user_groups_name_key", "user_groups", ["name"])
