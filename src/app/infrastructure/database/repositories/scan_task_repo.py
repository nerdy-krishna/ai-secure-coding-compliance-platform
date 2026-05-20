from __future__ import annotations

import datetime as dt
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import sqlalchemy as sa
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.shared.lib.scan_task_status import (
    RETRYABLE_SCAN_TASK_STATUSES,
    STATUS_SCAN_TASK_COMPLETED,
    STATUS_SCAN_TASK_FAILED,
    STATUS_SCAN_TASK_PENDING,
    STATUS_SCAN_TASK_RETRYABLE,
    STATUS_SCAN_TASK_RUNNING,
    STATUS_SCAN_TASK_STALE,
)

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanTaskEnsureResult:
    task: db_models.ScanTask
    created: bool = False
    stale: bool = False
    reusable: bool = False


class ScanTaskRepository:
    """Database access for durable scan task ledger rows.

    The ledger deliberately scopes reuse to a single scan: the natural key is
    ``(scan_id, task_type, task_key)``. Matching hashes allow result reuse;
    hash drift resets the same row to pending so the work is rerun in-place.
    """

    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    @staticmethod
    def hashes_match(
        task: db_models.ScanTask,
        *,
        input_hash: str,
        prompt_hash: str,
        version_hash: str,
    ) -> bool:
        return (
            task.input_hash == input_hash
            and task.prompt_hash == prompt_hash
            and task.version_hash == version_hash
        )

    async def get_task(
        self,
        *,
        scan_id: uuid.UUID,
        task_type: str,
        task_key: str,
    ) -> Optional[db_models.ScanTask]:
        result = await self.db.execute(
            select(db_models.ScanTask).where(
                db_models.ScanTask.scan_id == scan_id,
                db_models.ScanTask.task_type == task_type,
                db_models.ScanTask.task_key == task_key,
            )
        )
        return result.scalars().first()

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
        """Create a task or reset a stale task to pending.

        If an existing row has matching hashes and is completed, callers can
        reuse its ``result_payload`` without redoing work. If hashes changed,
        prior result/lease/error state is discarded and the same row becomes a
        fresh pending task.
        """
        task = await self.get_task(
            scan_id=scan_id, task_type=task_type, task_key=task_key
        )
        if task is None:
            task = db_models.ScanTask(
                scan_id=scan_id,
                task_type=task_type,
                task_key=task_key,
                input_hash=input_hash,
                prompt_hash=prompt_hash,
                version_hash=version_hash,
                input_payload=input_payload,
                max_attempts=max_attempts,
                status=STATUS_SCAN_TASK_PENDING,
            )
            self.db.add(task)
            await self.db.commit()
            await self.db.refresh(task)
            return ScanTaskEnsureResult(task=task, created=True)

        if self.hashes_match(
            task,
            input_hash=input_hash,
            prompt_hash=prompt_hash,
            version_hash=version_hash,
        ):
            return ScanTaskEnsureResult(
                task=task,
                reusable=task.status == STATUS_SCAN_TASK_COMPLETED
                and task.result_payload is not None,
            )

        self._reset_for_rerun(
            task,
            input_hash=input_hash,
            prompt_hash=prompt_hash,
            version_hash=version_hash,
            input_payload=input_payload,
            max_attempts=max_attempts,
            status=STATUS_SCAN_TASK_PENDING,
        )
        await self.db.commit()
        await self.db.refresh(task)
        return ScanTaskEnsureResult(task=task, stale=True)

    async def get_completed_result(
        self,
        *,
        scan_id: uuid.UUID,
        task_type: str,
        task_key: str,
        input_hash: str,
        prompt_hash: str,
        version_hash: str,
    ) -> Optional[Dict[str, Any]]:
        task = await self.get_task(
            scan_id=scan_id, task_type=task_type, task_key=task_key
        )
        if (
            task is not None
            and task.status == STATUS_SCAN_TASK_COMPLETED
            and task.result_payload is not None
            and self.hashes_match(
                task,
                input_hash=input_hash,
                prompt_hash=prompt_hash,
                version_hash=version_hash,
            )
        ):
            return dict(task.result_payload)
        return None

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
    ) -> Optional[db_models.ScanTask]:
        """Atomically lease pending/stale/retryable or expired-running work.

        Returns ``None`` when matching work is already completed, currently
        leased by another worker, or has exhausted its retry cap.
        """
        now = dt.datetime.now(dt.timezone.utc)
        lease_until = now + dt.timedelta(seconds=lease_ttl_seconds)
        result = await self.db.execute(
            select(db_models.ScanTask)
            .where(
                db_models.ScanTask.scan_id == scan_id,
                db_models.ScanTask.task_type == task_type,
                db_models.ScanTask.task_key == task_key,
            )
            .with_for_update()
        )
        task = result.scalars().first()
        if task is None:
            task = db_models.ScanTask(
                scan_id=scan_id,
                task_type=task_type,
                task_key=task_key,
                input_hash=input_hash,
                prompt_hash=prompt_hash,
                version_hash=version_hash,
                input_payload=input_payload,
                max_attempts=max_attempts,
                status=STATUS_SCAN_TASK_PENDING,
            )
            self.db.add(task)
            await self.db.flush()
        elif not self.hashes_match(
            task,
            input_hash=input_hash,
            prompt_hash=prompt_hash,
            version_hash=version_hash,
        ):
            self._reset_for_rerun(
                task,
                input_hash=input_hash,
                prompt_hash=prompt_hash,
                version_hash=version_hash,
                input_payload=input_payload,
                max_attempts=max_attempts,
                status=STATUS_SCAN_TASK_STALE,
            )

        if task.status == STATUS_SCAN_TASK_COMPLETED:
            await self.db.commit()
            return None

        if task.status == STATUS_SCAN_TASK_RUNNING:
            if task.lease_expires_at and task.lease_expires_at > now:
                await self.db.commit()
                return None
            if task.attempts >= task.max_attempts:
                task.status = STATUS_SCAN_TASK_FAILED
                task.last_error = "lease expired and retry cap was reached"
                task.lease_owner = None
                task.lease_expires_at = None
                await self.db.commit()
                await self.db.refresh(task)
                return None
            task.status = STATUS_SCAN_TASK_RETRYABLE
            task.lease_owner = None
            task.lease_expires_at = None

        if (
            task.status == STATUS_SCAN_TASK_FAILED
            and task.attempts >= task.max_attempts
        ):
            await self.db.commit()
            return None

        if task.status not in RETRYABLE_SCAN_TASK_STATUSES | {STATUS_SCAN_TASK_FAILED}:
            await self.db.commit()
            return None

        if task.attempts >= task.max_attempts:
            task.status = STATUS_SCAN_TASK_FAILED
            task.last_error = "retry cap reached"
            task.lease_owner = None
            task.lease_expires_at = None
            await self.db.commit()
            await self.db.refresh(task)
            return None

        task.status = STATUS_SCAN_TASK_RUNNING
        task.attempts += 1
        task.max_attempts = max_attempts
        task.lease_owner = lease_owner
        task.lease_expires_at = lease_until
        task.last_error = None
        await self.db.commit()
        await self.db.refresh(task)
        return task

    async def mark_completed(
        self,
        task_id: uuid.UUID,
        *,
        result_payload: Dict[str, Any],
    ) -> Optional[db_models.ScanTask]:
        task = await self.db.get(db_models.ScanTask, task_id)
        if task is None:
            return None
        task.status = STATUS_SCAN_TASK_COMPLETED
        task.result_payload = result_payload
        task.lease_owner = None
        task.lease_expires_at = None
        task.last_error = None
        task.completed_at = dt.datetime.now(dt.timezone.utc)
        await self.db.commit()
        await self.db.refresh(task)
        return task

    async def mark_failed(
        self,
        task_id: uuid.UUID,
        *,
        error: str,
        retryable: bool = True,
    ) -> Optional[db_models.ScanTask]:
        task = await self.db.get(db_models.ScanTask, task_id)
        if task is None:
            return None
        capped_error = error[:4000]
        if retryable and task.attempts < task.max_attempts:
            task.status = STATUS_SCAN_TASK_RETRYABLE
        else:
            task.status = STATUS_SCAN_TASK_FAILED
        task.last_error = capped_error
        task.lease_owner = None
        task.lease_expires_at = None
        await self.db.commit()
        await self.db.refresh(task)
        return task

    async def mark_stale(self, task_id: uuid.UUID) -> Optional[db_models.ScanTask]:
        task = await self.db.get(db_models.ScanTask, task_id)
        if task is None:
            return None
        task.status = STATUS_SCAN_TASK_STALE
        task.result_payload = None
        task.lease_owner = None
        task.lease_expires_at = None
        task.completed_at = None
        await self.db.commit()
        await self.db.refresh(task)
        return task

    async def count_by_status_for_scan(self, scan_id: uuid.UUID) -> Dict[str, int]:
        result = await self.db.execute(
            select(db_models.ScanTask.status, sa.func.count(db_models.ScanTask.id))
            .where(db_models.ScanTask.scan_id == scan_id)
            .group_by(db_models.ScanTask.status)
        )
        return {status: int(count) for status, count in result.all()}

    async def delete_for_scan(self, scan_id: uuid.UUID) -> int:
        result = await self.db.execute(
            sa.delete(db_models.ScanTask).where(db_models.ScanTask.scan_id == scan_id)
        )
        await self.db.commit()
        return result.rowcount or 0

    def _reset_for_rerun(
        self,
        task: db_models.ScanTask,
        *,
        input_hash: str,
        prompt_hash: str,
        version_hash: str,
        input_payload: Dict[str, Any],
        max_attempts: int,
        status: str,
    ) -> None:
        task.input_hash = input_hash
        task.prompt_hash = prompt_hash
        task.version_hash = version_hash
        task.input_payload = input_payload
        task.result_payload = None
        task.status = status
        task.attempts = 0
        task.max_attempts = max_attempts
        task.lease_owner = None
        task.lease_expires_at = None
        task.last_error = None
        task.completed_at = None
