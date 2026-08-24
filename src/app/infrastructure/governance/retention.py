"""Approved evidence-lifecycle retention defaults and validation."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True)
class RetentionPolicy:
    transactional_days: int = 365
    audit_days: int = 365
    evidence_days: int = 365
    llm_days: int = 30
    vector_days: int = 365
    logs_days: int = 30
    backups_days: int = 35
    version: str = "task22-approved-v1"

    def __post_init__(self) -> None:
        values = asdict(self)
        for name, value in values.items():
            if name == "version":
                continue
            if not isinstance(value, int) or not 1 <= value <= 3650:
                raise ValueError(f"{name} must be between 1 and 3650 days")

    def snapshot(self) -> dict[str, int | str]:
        return asdict(self)


DEFAULT_RETENTION_POLICY = RetentionPolicy()

DATA_CLASSES = {
    "transactional": "transactional_days",
    "audit": "audit_days",
    "evidence": "evidence_days",
    "llm": "llm_days",
    "vector": "vector_days",
    "logs": "logs_days",
    "backups": "backups_days",
}
SHORTENABLE_CLASSES = {"llm", "logs"}
UNSUPPORTED_OVERRIDE_CLASSES = {"transactional", "audit"}


def validate_tenant_override(data_class: str, retention_days: int) -> None:
    field = DATA_CLASSES.get(data_class)
    if field is None:
        raise ValueError("Unsupported retention data class.")
    if not 1 <= retention_days <= 3650:
        raise ValueError("Retention must be between 1 and 3650 days.")
    if data_class in UNSUPPORTED_OVERRIDE_CLASSES:
        raise ValueError(
            f"{data_class} retention is fixed until its durable tenant sweeper "
            "is implemented."
        )
    approved_default = getattr(DEFAULT_RETENTION_POLICY, field)
    if retention_days < approved_default and data_class not in SHORTENABLE_CLASSES:
        raise ValueError(
            f"{data_class} retention cannot be shorter than {approved_default} days."
        )


async def effective_retention_days(
    db: AsyncSession,
    *,
    tenant_id: uuid.UUID | None,
    data_class: str,
    defaults: RetentionPolicy = DEFAULT_RETENTION_POLICY,
    default_days: int | None = None,
) -> int:
    """Resolve one persisted tenant override, falling back to the approved default."""
    field = DATA_CLASSES.get(data_class)
    if field is None:
        raise ValueError("Unsupported retention data class.")
    fallback = int(
        default_days if default_days is not None else getattr(defaults, field)
    )
    if tenant_id is None:
        return fallback

    # Local import avoids making the lightweight policy module part of the
    # SQLAlchemy model import cycle.
    from app.infrastructure.governance.models import TenantRetentionPolicy

    override = await db.scalar(
        select(TenantRetentionPolicy.retention_days).where(
            TenantRetentionPolicy.tenant_id == tenant_id,
            TenantRetentionPolicy.data_class == data_class,
        )
    )
    return int(override if override is not None else fallback)
