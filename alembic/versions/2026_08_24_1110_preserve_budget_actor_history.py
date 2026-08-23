"""Preserve immutable budget actor history across user deletion.

Revision ID: b7c31d9e4a62
Revises: 9e17fa3b5c24
Create Date: 2026-08-24 11:10:00
"""

from typing import Sequence, Union

from alembic import op


revision: str = "b7c31d9e4a62"
down_revision: Union[str, None] = "9e17fa3b5c24"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # These rows are immutable audit history. Their tenant-reference triggers
    # validate the actor at insert time, while retaining the numeric identifier
    # allows users to be removed without deleting or rewriting that history.
    op.drop_constraint(
        "usage_budget_policies_created_by_user_id_fkey",
        "usage_budget_policies",
        type_="foreignkey",
    )
    op.drop_constraint(
        "usage_budget_overrides_created_by_user_id_fkey",
        "usage_budget_overrides",
        type_="foreignkey",
    )


def downgrade() -> None:
    op.create_foreign_key(
        "usage_budget_overrides_created_by_user_id_fkey",
        "usage_budget_overrides",
        "user",
        ["created_by_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
    op.create_foreign_key(
        "usage_budget_policies_created_by_user_id_fkey",
        "usage_budget_policies",
        "user",
        ["created_by_user_id"],
        ["id"],
        ondelete="RESTRICT",
    )
