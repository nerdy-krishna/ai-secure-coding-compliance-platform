"""Decouple immutable audit identifiers from mutable identity rows.

Revision ID: 156170b56255
Revises: d7b288ac6261
Create Date: 2026-08-23 16:59:26.666923

The audit trigger rejects every UPDATE. Foreign keys using ``ON DELETE SET
NULL`` therefore made user/provider/tenant/session deletion fail when an audit
row referenced the target. Audit identifiers are deliberately denormalized so
history retains the original UUID/integer without a trigger-bypassing mutation.
"""

from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "156170b56255"
down_revision: Union[str, None] = "d7b288ac6261"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    for constraint in (
        "auth_audit_events_user_id_fkey",
        "auth_audit_events_provider_id_fkey",
        "fk_auth_audit_events_tenant_id",
        "fk_auth_audit_events_actor_user_id",
        "fk_auth_audit_events_session_id",
    ):
        op.drop_constraint(constraint, "auth_audit_events", type_="foreignkey")


def downgrade() -> None:
    # NOT VALID permits rollback even if identity rows were legitimately
    # removed while identifiers were denormalized. New writes are still
    # checked after rollback, matching the former schema behavior.
    for constraint, column, target, target_column in (
        ("auth_audit_events_user_id_fkey", "user_id", '"user"', "id"),
        (
            "auth_audit_events_provider_id_fkey",
            "provider_id",
            "sso_providers",
            "id",
        ),
        ("fk_auth_audit_events_tenant_id", "tenant_id", "tenants", "id"),
        ("fk_auth_audit_events_actor_user_id", "actor_user_id", '"user"', "id"),
        ("fk_auth_audit_events_session_id", "session_id", "auth_sessions", "id"),
    ):
        op.execute(
            f"ALTER TABLE auth_audit_events ADD CONSTRAINT {constraint} "
            f"FOREIGN KEY ({column}) REFERENCES {target} ({target_column}) "
            "ON DELETE SET NULL NOT VALID"
        )
