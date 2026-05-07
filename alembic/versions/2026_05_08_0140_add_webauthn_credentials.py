"""add webauthn_credentials table

Revision ID: e8f1c4a3b297
Revises: c2bd047a1f3e
Create Date: 2026-05-08 01:40:00.000000

WebAuthn / passkey support (Chunk 5):

  * One row per registered authenticator (TouchID, Windows Hello,
    YubiKey, etc.). A user can register multiple passkeys — laptop +
    phone + hardware key are common.
  * ``credential_id`` is the binary credential ID returned by the
    authenticator at registration; we look up the credential by this id
    during authentication and verify the assertion against the stored
    public key.
  * ``sign_count`` is updated on every successful assertion (clone
    detection per W3C §6.1.3). py_webauthn flags a clone when the
    incoming counter is <= the stored counter.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB


revision: str = "e8f1c4a3b297"
down_revision: Union[str, None] = "c2bd047a1f3e"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "webauthn_credentials",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False,
        ),
        # Binary credential id from the authenticator (variable-length).
        # Indexed for the login lookup path.
        sa.Column("credential_id", sa.LargeBinary(), nullable=False),
        # Stored COSE public key (CBOR-encoded by py_webauthn).
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        # Authenticator-asserted signature counter; bumped on every
        # successful login. Clone detection per W3C §6.1.3.
        sa.Column("sign_count", sa.Integer(), nullable=False, server_default="0"),
        # JSON list of transport hints from registration
        # (["internal"], ["usb"], ["nfc","ble"], etc.). Optional —
        # browsers use this to filter the credential set during login.
        sa.Column("transports", JSONB(), nullable=True),
        # Operator-supplied label so users can manage their own keys.
        sa.Column("friendly_name", sa.String(length=128), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "last_used_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
        sa.UniqueConstraint(
            "credential_id", name="uq_webauthn_credentials_credential_id"
        ),
    )
    op.create_index(
        "ix_webauthn_credentials_user_id",
        "webauthn_credentials",
        ["user_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_webauthn_credentials_user_id", table_name="webauthn_credentials"
    )
    op.drop_table("webauthn_credentials")
