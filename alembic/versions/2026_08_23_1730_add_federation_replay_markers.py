"""Add durable SAML/OIDC replay markers.

Revision ID: 4894a3e89588
Revises: 378392d78477
Create Date: 2026-08-23 17:30:00
"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql


revision: str = "4894a3e89588"
down_revision: Union[str, None] = "378392d78477"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "federation_replay_markers",
        sa.Column("id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("provider_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("kind", sa.String(length=32), nullable=False),
        sa.Column("message_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"], ["sso_providers.id"], ondelete="CASCADE"
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "provider_id",
            "kind",
            "message_hash",
            name="uq_federation_replay_provider_kind_message",
        ),
    )
    op.create_index(
        "ix_federation_replay_markers_provider_id",
        "federation_replay_markers",
        ["provider_id"],
    )
    op.create_index(
        "ix_federation_replay_markers_expires_at",
        "federation_replay_markers",
        ["expires_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_federation_replay_markers_expires_at",
        table_name="federation_replay_markers",
    )
    op.drop_index(
        "ix_federation_replay_markers_provider_id",
        table_name="federation_replay_markers",
    )
    op.drop_table("federation_replay_markers")
