"""Resolve queue deliveries against their durable outbox identity."""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import Any, Mapping

from sqlalchemy import select

from app.infrastructure.database import AsyncSessionLocal, models as db_models
from app.infrastructure.database.tenant_context import principal_scope


logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TrustedScanDelivery:
    tenant_id: uuid.UUID
    outbox_id: uuid.UUID
    legacy_payload: bool = False


def _published_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    normalized.pop("correlation_id", None)
    return normalized


async def resolve_trusted_scan_delivery(
    *,
    scan_id: uuid.UUID,
    queue_name: str,
    body: Mapping[str, Any],
) -> TrustedScanDelivery | None:
    """Match an incoming message to an immutable durable outbox row.

    Queue fields are not trusted. A system-scoped lookup is used only to find
    the originating row; the caller then binds the returned tenant as a normal
    service principal for all workflow access.
    """

    raw_outbox_id = body.get("outbox_id")
    outbox_id: uuid.UUID | None = None
    if raw_outbox_id is not None:
        try:
            outbox_id = uuid.UUID(str(raw_outbox_id))
        except ValueError:
            return None

    with principal_scope(
        tenant_id=None,
        principal_kind="system",
        principal_id="worker-delivery-resolver",
        system_scope=True,
    ):
        async with AsyncSessionLocal() as db:
            stmt = (
                select(db_models.ScanOutbox, db_models.Scan.tenant_id)
                .join(db_models.Scan, db_models.Scan.id == db_models.ScanOutbox.scan_id)
                .where(
                    db_models.ScanOutbox.scan_id == scan_id,
                    db_models.ScanOutbox.queue_name == queue_name,
                )
            )
            if outbox_id is not None:
                stmt = stmt.where(db_models.ScanOutbox.id == outbox_id)
            candidates = (await db.execute(stmt)).all()

    incoming_payload = _published_payload(body)
    matches = [
        (row, tenant_id)
        for row, tenant_id in candidates
        if _published_payload(row.payload) == incoming_payload
    ]
    if not matches:
        logger.warning(
            "worker.delivery.untrusted",
            extra={"scan_id": str(scan_id), "queue_name": queue_name},
        )
        return None

    row, tenant_id = matches[-1]
    legacy_payload = raw_outbox_id is None
    if legacy_payload:
        logger.warning(
            "worker.delivery.legacy_outbox_identity",
            extra={"scan_id": str(scan_id), "outbox_id": str(row.id)},
        )
    return TrustedScanDelivery(
        tenant_id=tenant_id,
        outbox_id=row.id,
        legacy_payload=legacy_payload,
    )
