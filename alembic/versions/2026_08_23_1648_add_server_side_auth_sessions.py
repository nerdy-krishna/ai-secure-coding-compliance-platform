"""Add server-side browser sessions.

Revision ID: d7b288ac6261
Revises: d6e7f8a9b0c1
Create Date: 2026-08-23 16:48:01.635407
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "d7b288ac6261"
down_revision: Union[str, None] = "d6e7f8a9b0c1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.UUID(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("tenant_id", sa.UUID(), nullable=True),
        sa.Column("provider_id", sa.UUID(), nullable=True),
        sa.Column("auth_method", sa.String(length=32), nullable=False),
        sa.Column("provider_session_hash", sa.String(length=64), nullable=True),
        sa.Column(
            "assurance_level",
            sa.String(length=16),
            server_default="aal1",
            nullable=False,
        ),
        sa.Column(
            "credential_generation", sa.Integer(), server_default="0", nullable=False
        ),
        sa.Column("credential_secret_hash", sa.String(length=64), nullable=False),
        sa.Column("authenticated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=64), nullable=True),
        sa.Column("ip_hash", sa.String(length=64), nullable=True),
        sa.Column("device_label", sa.String(length=128), nullable=True),
        sa.CheckConstraint(
            "credential_generation >= 0",
            name="ck_auth_sessions_generation_nonnegative",
        ),
        sa.CheckConstraint(
            "idle_expires_at <= absolute_expires_at",
            name="ck_auth_sessions_idle_before_absolute",
        ),
        sa.ForeignKeyConstraint(
            ["provider_id"],
            ["sso_providers.id"],
            name="fk_auth_sessions_provider_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["tenant_id"],
            ["tenants.id"],
            name="fk_auth_sessions_tenant_id",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name="fk_auth_sessions_user_id",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "credential_secret_hash", name="uq_auth_sessions_credential_secret_hash"
        ),
    )
    for column in (
        "absolute_expires_at",
        "idle_expires_at",
        "provider_id",
        "provider_session_hash",
        "revoked_at",
        "tenant_id",
        "user_id",
    ):
        op.create_index(f"ix_auth_sessions_{column}", "auth_sessions", [column])

    op.add_column(
        "auth_audit_events", sa.Column("actor_user_id", sa.Integer(), nullable=True)
    )
    op.add_column(
        "auth_audit_events", sa.Column("session_id", sa.UUID(), nullable=True)
    )
    op.add_column(
        "auth_audit_events",
        sa.Column(
            "outcome",
            sa.String(length=16),
            server_default="unknown",
            nullable=False,
        ),
    )
    op.create_index(
        "ix_auth_audit_events_actor_user_id",
        "auth_audit_events",
        ["actor_user_id"],
    )
    op.create_index(
        "ix_auth_audit_events_session_id", "auth_audit_events", ["session_id"]
    )
    op.create_foreign_key(
        "fk_auth_audit_events_actor_user_id",
        "auth_audit_events",
        "user",
        ["actor_user_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_foreign_key(
        "fk_auth_audit_events_session_id",
        "auth_audit_events",
        "auth_sessions",
        ["session_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        "fk_auth_audit_events_session_id", "auth_audit_events", type_="foreignkey"
    )
    op.drop_constraint(
        "fk_auth_audit_events_actor_user_id",
        "auth_audit_events",
        type_="foreignkey",
    )
    op.drop_index("ix_auth_audit_events_session_id", table_name="auth_audit_events")
    op.drop_index("ix_auth_audit_events_actor_user_id", table_name="auth_audit_events")
    op.drop_column("auth_audit_events", "outcome")
    op.drop_column("auth_audit_events", "session_id")
    op.drop_column("auth_audit_events", "actor_user_id")

    for column in (
        "user_id",
        "tenant_id",
        "revoked_at",
        "provider_session_hash",
        "provider_id",
        "idle_expires_at",
        "absolute_expires_at",
    ):
        op.drop_index(f"ix_auth_sessions_{column}", table_name="auth_sessions")
    op.drop_table("auth_sessions")
