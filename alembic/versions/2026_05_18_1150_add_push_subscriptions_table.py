"""add push_subscriptions table

Revision ID: a3f1c7d9e2b4
Revises: f7bc7902c62b
Create Date: 2026-05-18 11:50:00.000000

Web Push subscription store (#90 / PRD #83): one row per
(user, browser push endpoint). The push sender delivers
scan-completion notifications to every subscription the scan's owner
has registered.
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a3f1c7d9e2b4"
down_revision: Union[str, None] = "f7bc7902c62b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "push_subscriptions",
        sa.Column(
            "id",
            sa.BIGINT(),
            sa.Identity(always=True),
            primary_key=True,
        ),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("endpoint", sa.Text(), nullable=False),
        sa.Column("p256dh", sa.Text(), nullable=False),
        sa.Column("auth", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("endpoint", name="uq_push_subscriptions_endpoint"),
    )
    op.create_index(
        "ix_push_subscriptions_user_id",
        "push_subscriptions",
        ["user_id"],
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_push_subscriptions_user_id", table_name="push_subscriptions")
    op.drop_table("push_subscriptions")
