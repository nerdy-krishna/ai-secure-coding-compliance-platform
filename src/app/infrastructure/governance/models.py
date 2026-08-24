"""Task22 persistence models kept separate from the historic monolithic model file."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.infrastructure.database.base import Base


class GovernanceLegalHold(Base):
    """Tenant-scoped legal hold that overrides every configured store policy."""

    __tablename__ = "governance_legal_holds"
    __table_args__ = (
        sa.CheckConstraint(
            "scope_type IN ('tenant', 'project', 'scan', 'attempt', 'evidence')",
            name="ck_governance_legal_hold_scope",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    scope_type: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    scope_id: Mapped[str] = mapped_column(sa.String(128), nullable=False)
    reason: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    placed_by_user_id: Mapped[int] = mapped_column(
        sa.ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    placed_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    released_by_user_id: Mapped[Optional[int]] = mapped_column(
        sa.ForeignKey("user.id", ondelete="RESTRICT")
    )
    released_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))
    release_reason: Mapped[Optional[str]] = mapped_column(sa.Text())


class GovernanceOperation(Base):
    """Durable two-phase export or deletion request and its signed conclusion."""

    __tablename__ = "governance_operations"
    __table_args__ = (
        sa.CheckConstraint(
            "kind IN ('export', 'delete')", name="ck_governance_operation_kind"
        ),
        sa.CheckConstraint(
            "status IN ('prepared', 'executing', 'completed', 'failed', "
            "'blocked_legal_hold')",
            name="ck_governance_operation_status",
        ),
        sa.UniqueConstraint(
            "tenant_id", "idempotency_key", name="uq_governance_operation_idempotency"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    kind: Mapped[str] = mapped_column(sa.String(12), nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(24), nullable=False, default="prepared", server_default="prepared"
    )
    idempotency_key: Mapped[str] = mapped_column(sa.String(64), nullable=False)
    scope: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    policy_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    manifest: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa.text("'{}'::jsonb")
    )
    manifest_sha256: Mapped[Optional[str]] = mapped_column(sa.String(64))
    signature_b64: Mapped[Optional[str]] = mapped_column(sa.Text())
    signature_algorithm: Mapped[Optional[str]] = mapped_column(sa.String(64))
    signing_key_id: Mapped[Optional[str]] = mapped_column(sa.String(512))
    failure_code: Mapped[Optional[str]] = mapped_column(sa.String(64))
    requested_by_user_id: Mapped[int] = mapped_column(
        sa.ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    reason: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    started_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))
    completed_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))


class GovernanceStoreAction(Base):
    """One idempotent store step belonging to a governance operation."""

    __tablename__ = "governance_store_actions"
    __table_args__ = (
        sa.CheckConstraint(
            "store IN ('postgres', 'object', 'qdrant', 'observability')",
            name="ck_governance_store_action_store",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'leased', 'applied', 'verified', 'failed')",
            name="ck_governance_store_action_status",
        ),
        sa.UniqueConstraint(
            "operation_id", "store", name="uq_governance_store_action_operation_store"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    operation_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        sa.ForeignKey("governance_operations.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    store: Mapped[str] = mapped_column(sa.String(20), nullable=False)
    status: Mapped[str] = mapped_column(
        sa.String(16), nullable=False, default="pending", server_default="pending"
    )
    attempts: Mapped[int] = mapped_column(
        sa.Integer(), nullable=False, default=0, server_default="0"
    )
    lease_expires_at: Mapped[Optional[datetime]] = mapped_column(
        sa.DateTime(timezone=True)
    )
    result: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=sa.text("'{}'::jsonb")
    )
    result_sha256: Mapped[Optional[str]] = mapped_column(sa.String(64))
    last_error_code: Mapped[Optional[str]] = mapped_column(sa.String(64))
    created_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()
    )
    applied_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))
    verified_at: Mapped[Optional[datetime]] = mapped_column(sa.DateTime(timezone=True))


class TenantRetentionPolicy(Base):
    """Auditable tenant override constrained by the approved policy floor."""

    __tablename__ = "tenant_retention_policies"
    __table_args__ = (
        sa.CheckConstraint(
            "data_class IN ('transactional', 'audit', 'evidence', 'llm', "
            "'vector', 'logs', 'backups')",
            name="ck_tenant_retention_policy_class",
        ),
        sa.CheckConstraint(
            "retention_days BETWEEN 1 AND 3650",
            name="ck_tenant_retention_policy_days",
        ),
        sa.UniqueConstraint(
            "tenant_id", "data_class", name="uq_tenant_retention_policy_class"
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        sa.ForeignKey("tenants.id", ondelete="RESTRICT"),
        nullable=False,
        index=True,
    )
    data_class: Mapped[str] = mapped_column(sa.String(24), nullable=False)
    retention_days: Mapped[int] = mapped_column(sa.Integer(), nullable=False)
    updated_by_user_id: Mapped[int] = mapped_column(
        sa.ForeignKey("user.id", ondelete="RESTRICT"), nullable=False
    )
    reason: Mapped[str] = mapped_column(sa.Text(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.func.now(),
        onupdate=sa.func.now(),
    )
