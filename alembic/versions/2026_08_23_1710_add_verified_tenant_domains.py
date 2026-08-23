"""Add DNS-verified tenant domains for SSO routing and JIT.

Revision ID: 267281c67366
Revises: 156170b56255
Create Date: 2026-08-23 17:10:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "267281c67366"
down_revision: Union[str, None] = "156170b56255"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tenant_verified_domains",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("domain", sa.String(length=253), nullable=False),
        sa.Column("verification_token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            nullable=False,
            server_default="pending",
        ),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'verified')",
            name="ck_tenant_verified_domains_status",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"], ["tenants.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("domain", name="uq_tenant_verified_domains_domain"),
    )
    op.create_index(
        "ix_tenant_verified_domains_tenant_id",
        "tenant_verified_domains",
        ["tenant_id"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_tenant_verified_domains_tenant_id",
        table_name="tenant_verified_domains",
    )
    op.drop_table("tenant_verified_domains")
