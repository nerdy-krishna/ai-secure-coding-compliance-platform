"""add oauth_accounts.idp_token_expires_at for session-bind feature

Revision ID: c2bd047a1f3e
Revises: a3f9b21e5c14
Create Date: 2026-05-08 01:21:00.000000

Session-bind to IdP (Chunk 4 of clear-followups-and-latent-fix run):

  * ``oauth_accounts.idp_token_expires_at`` (nullable TIMESTAMP) — set at
    the OIDC callback to the IdP-asserted expiry of the user's
    access_token.
  * When the OIDC provider has ``bind_to_idp_session=True``, the
    ``/auth/refresh`` route enforces this as an additional session
    ceiling. A SCCAP refresh past the IdP's token expiry triggers
    ``session.idp_token_expired`` audit event and a 401.

Backwards compatible: NULL means the user predates the feature OR the
provider doesn't have bind enabled — refresh skips the new check and
falls back to ``security.session_lifetime_hours`` (already enforced).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c2bd047a1f3e"
down_revision: Union[str, None] = "a3f9b21e5c14"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "oauth_accounts",
        sa.Column(
            "idp_token_expires_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )


def downgrade() -> None:
    op.drop_column("oauth_accounts", "idp_token_expires_at")
