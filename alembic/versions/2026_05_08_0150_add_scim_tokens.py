"""add scim_tokens table

Revision ID: f4a91c20bdb6
Revises: e8f1c4a3b297
Create Date: 2026-05-08 01:50:00.000000

SCIM 2.0 (Users only) — Chunk 6:

  * scim_tokens stores admin-issued bearer tokens used by upstream
    identity providers (Okta, Azure AD, etc.) for outbound SCIM
    provisioning into SCCAP.
  * Token plaintext is shown ONCE at creation; the DB stores only
    sha256(token) so an operator with read access to system_config
    can't impersonate the IdP.
  * scopes is JSONB list — minimal vocab right now: ["users:read",
    "users:write"]. Future expansion (e.g. groups:write) just adds
    enum values.
  * Tokens are rotatable: admin re-issues, old tokens revoked via
    expires_at = now() or DELETE.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB


revision: str = "f4a91c20bdb6"
down_revision: Union[str, None] = "e8f1c4a3b297"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "scim_tokens",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=128), nullable=False),
        # sha256(plaintext) stored as 64-char hex. Plaintext is shown
        # once at creation and never persisted.
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column(
            "scopes",
            JSONB(),
            nullable=False,
            server_default=sa.text("'[]'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_by_user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint("token_hash", name="uq_scim_tokens_token_hash"),
    )


def downgrade() -> None:
    op.drop_table("scim_tokens")
