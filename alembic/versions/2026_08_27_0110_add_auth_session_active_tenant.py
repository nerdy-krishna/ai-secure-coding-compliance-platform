"""Persist the selected tenant for the browser authentication session.

Revision ID: 4d5e6f708192
Revises: 3c4d5e6f7081
Create Date: 2026-08-27 01:10:00.000000
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision = "4d5e6f708192"
down_revision = "3c4d5e6f7081"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "auth_sessions",
        sa.Column(
            "active_tenant_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
    )
    op.create_foreign_key(
        "fk_auth_sessions_active_tenant_id",
        "auth_sessions",
        "tenants",
        ["active_tenant_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_auth_sessions_active_tenant_id",
        "auth_sessions",
        ["active_tenant_id"],
    )


def downgrade() -> None:
    op.drop_index("ix_auth_sessions_active_tenant_id", table_name="auth_sessions")
    op.drop_constraint(
        "fk_auth_sessions_active_tenant_id",
        "auth_sessions",
        type_="foreignkey",
    )
    op.drop_column("auth_sessions", "active_tenant_id")
