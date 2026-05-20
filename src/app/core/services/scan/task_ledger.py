from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_task_repo import (
    ScanTaskEnsureResult,
    ScanTaskRepository,
)


@dataclass(frozen=True)
class ScanTaskLease:
    task: db_models.ScanTask


class ScanTaskLedgerService:
    """Application service for durable, scan-scoped task reuse.

    This is intentionally generic. Workflow nodes provide task type/key and
    deterministic hashes; the service handles reuse, leases, stale reruns, and
    retry bookkeeping without knowing whether the task is analysis,
    consolidation, or another future scan stage.
    """

    def __init__(self, db_session: AsyncSession):
        self.repo = ScanTaskRepository(db_session)

    async def ensure_task(
        self,
        *,
        scan_id: uuid.UUID,
        task_type: str,
        task_key: str,
        input_hash: str,
        prompt_hash: str,
        version_hash: str,
        input_payload: Dict[str, Any],
        max_attempts: int = 3,
    ) -> ScanTaskEnsureResult:
        return await self.repo.ensure_task(
            scan_id=scan_id,
            task_type=task_type,
            task_key=task_key,
            input_hash=input_hash,
            prompt_hash=prompt_hash,
            version_hash=version_hash,
            input_payload=input_payload,
            max_attempts=max_attempts,
        )

    async def get_reusable_result(
        self,
        *,
        scan_id: uuid.UUID,
        task_type: str,
        task_key: str,
        input_hash: str,
        prompt_hash: str,
        version_hash: str,
    ) -> Optional[Dict[str, Any]]:
        return await self.repo.get_completed_result(
            scan_id=scan_id,
            task_type=task_type,
            task_key=task_key,
            input_hash=input_hash,
            prompt_hash=prompt_hash,
            version_hash=version_hash,
        )

    async def acquire_task(
        self,
        *,
        scan_id: uuid.UUID,
        task_type: str,
        task_key: str,
        input_hash: str,
        prompt_hash: str,
        version_hash: str,
        input_payload: Dict[str, Any],
        lease_owner: str,
        lease_ttl_seconds: int = 600,
        max_attempts: int = 3,
    ) -> Optional[ScanTaskLease]:
        task = await self.repo.acquire_task(
            scan_id=scan_id,
            task_type=task_type,
            task_key=task_key,
            input_hash=input_hash,
            prompt_hash=prompt_hash,
            version_hash=version_hash,
            input_payload=input_payload,
            lease_owner=lease_owner,
            lease_ttl_seconds=lease_ttl_seconds,
            max_attempts=max_attempts,
        )
        return ScanTaskLease(task=task) if task is not None else None

    async def complete_task(
        self,
        task_id: uuid.UUID,
        *,
        result_payload: Dict[str, Any],
    ) -> Optional[db_models.ScanTask]:
        return await self.repo.mark_completed(task_id, result_payload=result_payload)

    async def fail_task(
        self,
        task_id: uuid.UUID,
        *,
        error: str,
        retryable: bool = True,
    ) -> Optional[db_models.ScanTask]:
        return await self.repo.mark_failed(task_id, error=error, retryable=retryable)

    async def mark_task_stale(self, task_id: uuid.UUID) -> Optional[db_models.ScanTask]:
        return await self.repo.mark_stale(task_id)

    async def summarize_scan_tasks(self, scan_id: uuid.UUID) -> Dict[str, int]:
        return await self.repo.count_by_status_for_scan(scan_id)

    async def delete_scan_tasks(self, scan_id: uuid.UUID) -> int:
        return await self.repo.delete_for_scan(scan_id)
