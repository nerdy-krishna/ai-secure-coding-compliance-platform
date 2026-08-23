"""Repository for stable scan execution attempt identities."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


def configuration_digest(scan: db_models.Scan) -> str:
    payload = {
        "scan_type": scan.scan_type,
        "frameworks": scan.frameworks or [],
        "reasoning_llm_config_id": str(scan.reasoning_llm_config_id or ""),
        "utility_llm_config_id": str(scan.utility_llm_config_id or ""),
        "secondary_reasoning_llm_config_id": str(
            scan.secondary_reasoning_llm_config_id or ""
        ),
        "stage_temperatures": scan.stage_temperatures or {},
        "disable_temperature": scan.disable_temperature,
        "cross_file_validation": scan.cross_file_validation,
        "deep_vendor_scan": scan.deep_vendor_scan,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


class ScanAttemptRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_current(self, scan_id: uuid.UUID) -> db_models.ScanAttempt | None:
        return await self.db.scalar(
            select(db_models.ScanAttempt)
            .join(
                db_models.Scan,
                db_models.Scan.current_attempt_id == db_models.ScanAttempt.id,
            )
            .where(db_models.Scan.id == scan_id)
        )

    async def create_initial(
        self,
        scan: db_models.Scan,
        *,
        actor_user_id: int | None,
        commit: bool = True,
    ) -> db_models.ScanAttempt:
        if scan.current_attempt_id:
            current = await self.db.get(db_models.ScanAttempt, scan.current_attempt_id)
            if current is not None:
                return current
        attempt = db_models.ScanAttempt(
            scan_id=scan.id,
            tenant_id=scan.tenant_id,
            sequence=1,
            trigger="initial",
            status="active",
            actor_user_id=actor_user_id,
            graph_thread_id=str(scan.id),
            configuration_digest=configuration_digest(scan),
        )
        self.db.add(attempt)
        await self.db.flush()
        scan.current_attempt_id = attempt.id
        if commit:
            await self.db.commit()
            await self.db.refresh(attempt)
        return attempt

    async def activate_resume(
        self, scan_id: uuid.UUID, *, commit: bool = True
    ) -> db_models.ScanAttempt:
        scan = await self.db.scalar(
            select(db_models.Scan).where(db_models.Scan.id == scan_id).with_for_update()
        )
        if scan is None:
            raise LookupError("Scan not found.")
        current = await self.get_current(scan_id)
        if current is None:
            current = await self.create_initial(
                scan, actor_user_id=scan.user_id, commit=False
            )
        current.status = "active"
        current.completed_at = None
        if commit:
            await self.db.commit()
            await self.db.refresh(current)
        return current

    async def create_restart(
        self,
        scan_id: uuid.UUID,
        *,
        actor_user_id: int | None,
        commit: bool = True,
    ) -> db_models.ScanAttempt:
        scan = await self.db.scalar(
            select(db_models.Scan).where(db_models.Scan.id == scan_id).with_for_update()
        )
        if scan is None:
            raise LookupError("Scan not found.")
        current = await self.get_current(scan_id)
        if current is not None:
            current.status = "superseded"
            current.completed_at = datetime.now(timezone.utc)
        sequence = (
            int(
                await self.db.scalar(
                    select(func.max(db_models.ScanAttempt.sequence)).where(
                        db_models.ScanAttempt.scan_id == scan_id
                    )
                )
                or 0
            )
            + 1
        )
        attempt = db_models.ScanAttempt(
            scan_id=scan.id,
            tenant_id=scan.tenant_id,
            sequence=sequence,
            trigger="restart",
            status="active",
            parent_attempt_id=current.id if current else None,
            actor_user_id=actor_user_id,
            graph_thread_id=str(scan.id),
            configuration_digest=configuration_digest(scan),
        )
        self.db.add(attempt)
        await self.db.flush()
        scan.current_attempt_id = attempt.id
        if commit:
            await self.db.commit()
            await self.db.refresh(attempt)
        return attempt

    async def mark_current_terminal(
        self,
        scan_id: uuid.UUID,
        *,
        status: str,
        commit: bool = True,
    ) -> db_models.ScanAttempt | None:
        if status not in {"completed", "failed", "cancelled"}:
            raise ValueError("Invalid terminal attempt status.")
        current = await self.get_current(scan_id)
        if current is None:
            return None
        current.status = status
        current.completed_at = datetime.now(timezone.utc)
        if commit:
            await self.db.commit()
            await self.db.refresh(current)
        return current
