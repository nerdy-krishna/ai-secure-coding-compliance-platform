"""Add tenant-configurable concurrent browser-session policy.

Revision ID: 378392d78477
Revises: 267281c67366
Create Date: 2026-08-23 17:20:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


revision: str = "378392d78477"
down_revision: Union[str, None] = "267281c67366"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "tenants",
        sa.Column("session_concurrency_limit", sa.Integer(), nullable=True),
    )
    op.add_column(
        "tenants",
        sa.Column(
            "session_concurrency_mode",
            sa.String(length=16),
            nullable=False,
            server_default="deny_new",
        ),
    )
    op.create_check_constraint(
        "ck_tenants_session_concurrency_limit",
        "tenants",
        "session_concurrency_limit IS NULL OR "
        "(session_concurrency_limit >= 1 AND session_concurrency_limit <= 100)",
    )
    op.create_check_constraint(
        "ck_tenants_session_concurrency_mode",
        "tenants",
        "session_concurrency_mode IN ('deny_new', 'revoke_oldest')",
    )


def downgrade() -> None:
    op.drop_constraint(
        "ck_tenants_session_concurrency_mode", "tenants", type_="check"
    )
    op.drop_constraint(
        "ck_tenants_session_concurrency_limit", "tenants", type_="check"
    )
    op.drop_column("tenants", "session_concurrency_mode")
    op.drop_column("tenants", "session_concurrency_limit")
