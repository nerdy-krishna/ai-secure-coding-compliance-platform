"""add sso providers, oauth accounts, saml subjects, and auth audit events

Revision ID: a3f9b21e5c14
Revises: 0ce89d3b19b1
Create Date: 2026-05-07 12:18:00.000000

Enterprise-SSO migration:

  * ``sso_providers``      — one row per configured IdP (OIDC or SAML); config
                             Fernet-encrypted in ``config_encrypted``.
  * ``oauth_accounts``     — links ``user.id`` to an IdP `sub` claim per
                             ``provider_id`` (multiple OIDC IdPs supported).
  * ``saml_subjects``      — links ``user.id`` to an IdP NameID per
                             ``provider_id``; carries ``session_index`` for SLO.
  * ``auth_audit_events``  — append-only audit log; an immutable trigger
                             rejects UPDATE/DELETE to satisfy SOC 2 / ISO 27001
                             evidence requirements (M7).

Hand-written because:
  1. ``op.execute`` is required for the immutability trigger (autogenerate
     does not produce DDL triggers).
  2. We want explicit indexing on the audit ``ts DESC`` column for the
     admin audit page (M15) — autogenerate produces ``ts ASC`` only.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID as PG_UUID, JSONB


# revision identifiers, used by Alembic.
revision: str = "a3f9b21e5c14"
down_revision: Union[str, None] = "0ce89d3b19b1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- sso_providers ----
    op.create_table(
        "sso_providers",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=64), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=False),
        sa.Column("protocol", sa.String(length=8), nullable=False),
        sa.Column(
            "enabled",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("config_encrypted", sa.LargeBinary(), nullable=False),
        sa.Column("allowed_email_domains", JSONB(), nullable=True),
        sa.Column("force_for_domains", JSONB(), nullable=True),
        sa.Column(
            "jit_policy",
            sa.String(length=16),
            server_default=sa.text("'auto'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint("name", name="uq_sso_providers_name"),
        sa.CheckConstraint(
            "protocol IN ('oidc', 'saml')", name="ck_sso_providers_protocol"
        ),
        sa.CheckConstraint(
            "jit_policy IN ('auto', 'approve', 'deny')",
            name="ck_sso_providers_jit_policy",
        ),
    )

    # ---- oauth_accounts ----
    op.create_table(
        "oauth_accounts",
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
        sa.Column(
            "provider_id",
            PG_UUID(as_uuid=True),
            sa.ForeignKey("sso_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("account_id", sa.String(length=320), nullable=False),
        sa.Column("account_email", sa.String(length=320), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "provider_id", "account_id", name="uq_oauth_accounts_provider_account"
        ),
    )
    op.create_index(
        "ix_oauth_accounts_user_id", "oauth_accounts", ["user_id"], unique=False
    )
    op.create_index(
        "ix_oauth_accounts_provider_id",
        "oauth_accounts",
        ["provider_id"],
        unique=False,
    )

    # ---- saml_subjects ----
    op.create_table(
        "saml_subjects",
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
        sa.Column(
            "provider_id",
            PG_UUID(as_uuid=True),
            sa.ForeignKey("sso_providers.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("name_id", sa.String(length=512), nullable=False),
        sa.Column("name_id_format", sa.String(length=128), nullable=False),
        sa.Column("session_index", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.UniqueConstraint(
            "provider_id", "name_id", name="uq_saml_subjects_provider_name_id"
        ),
    )
    op.create_index(
        "ix_saml_subjects_user_id", "saml_subjects", ["user_id"], unique=False
    )
    op.create_index(
        "ix_saml_subjects_provider_id",
        "saml_subjects",
        ["provider_id"],
        unique=False,
    )

    # ---- auth_audit_events ----
    op.create_table(
        "auth_audit_events",
        sa.Column(
            "id",
            PG_UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column(
            "ts",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("event", sa.String(length=64), nullable=False),
        sa.Column(
            "user_id",
            sa.Integer(),
            sa.ForeignKey("user.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "provider_id",
            PG_UUID(as_uuid=True),
            sa.ForeignKey("sso_providers.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("email_hash", sa.String(length=64), nullable=True),
        sa.Column("ip", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column("details", JSONB(), nullable=True),
    )
    op.create_index(
        "ix_auth_audit_events_event",
        "auth_audit_events",
        ["event"],
        unique=False,
    )
    op.create_index(
        "ix_auth_audit_events_user_id",
        "auth_audit_events",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        "ix_auth_audit_events_provider_id",
        "auth_audit_events",
        ["provider_id"],
        unique=False,
    )
    # M15: ts DESC index so the admin audit page (most-recent-first) stays
    # fast as the table grows.
    op.execute(
        "CREATE INDEX ix_auth_audit_events_ts_desc "
        "ON auth_audit_events (ts DESC)"
    )

    # ---- M7: append-only enforcement on auth_audit_events ----
    # A BEFORE UPDATE OR DELETE trigger raises and aborts the transaction.
    # Postgres superusers technically still bypass triggers, but the trigger
    # plus an audit-ed admin role gets us SOC 2 evidence-grade integrity.
    op.execute(
        """
        CREATE OR REPLACE FUNCTION auth_audit_events_block_modify()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'auth_audit_events is append-only; UPDATE/DELETE forbidden';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER auth_audit_immutable
        BEFORE UPDATE OR DELETE ON auth_audit_events
        FOR EACH ROW EXECUTE FUNCTION auth_audit_events_block_modify();
        """
    )


def downgrade() -> None:
    # Drop audit table trigger + function first.
    op.execute("DROP TRIGGER IF EXISTS auth_audit_immutable ON auth_audit_events")
    op.execute("DROP FUNCTION IF EXISTS auth_audit_events_block_modify()")

    op.drop_index(
        "ix_auth_audit_events_ts_desc", table_name="auth_audit_events"
    )
    op.drop_index(
        "ix_auth_audit_events_provider_id", table_name="auth_audit_events"
    )
    op.drop_index(
        "ix_auth_audit_events_user_id", table_name="auth_audit_events"
    )
    op.drop_index("ix_auth_audit_events_event", table_name="auth_audit_events")
    op.drop_table("auth_audit_events")

    op.drop_index("ix_saml_subjects_provider_id", table_name="saml_subjects")
    op.drop_index("ix_saml_subjects_user_id", table_name="saml_subjects")
    op.drop_table("saml_subjects")

    op.drop_index(
        "ix_oauth_accounts_provider_id", table_name="oauth_accounts"
    )
    op.drop_index("ix_oauth_accounts_user_id", table_name="oauth_accounts")
    op.drop_table("oauth_accounts")

    op.drop_table("sso_providers")
