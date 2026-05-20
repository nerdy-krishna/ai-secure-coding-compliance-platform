from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.scan.task_ledger import ScanTaskLedgerService
from app.infrastructure.database import models as db_models
from app.shared.lib.scan_task_status import (
    STATUS_SCAN_TASK_FAILED,
    STATUS_SCAN_TASK_PENDING,
    STATUS_SCAN_TASK_RUNNING,
)

pytestmark = pytest.mark.asyncio


async def _scan(
    db_session: AsyncSession, seeded_user: db_models.User
) -> db_models.Scan:
    project = db_models.Project(name=f"p-{uuid.uuid4().hex}", user_id=seeded_user.id)
    scan = db_models.Scan(
        project=project,
        user_id=seeded_user.id,
        scan_type="AUDIT",
        status="QUEUED",
        frameworks=["ASVS"],
    )
    db_session.add(scan)
    await db_session.flush()
    return scan


async def test_completed_task_result_is_reused_without_new_lease(
    db_session: AsyncSession, seeded_user: db_models.User
):
    scan = await _scan(db_session, seeded_user)
    service = ScanTaskLedgerService(db_session)

    lease = await service.acquire_task(
        scan_id=scan.id,
        task_type="analysis",
        task_key="file.py:0:agent:primary",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={"file_path": "file.py"},
        lease_owner="worker-1",
    )
    assert lease is not None
    await service.complete_task(lease.task.id, result_payload={"findings": [1]})

    result = await service.get_reusable_result(
        scan_id=scan.id,
        task_type="analysis",
        task_key="file.py:0:agent:primary",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
    )
    assert result == {"findings": [1]}

    second_lease = await service.acquire_task(
        scan_id=scan.id,
        task_type="analysis",
        task_key="file.py:0:agent:primary",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={"file_path": "file.py"},
        lease_owner="worker-2",
    )
    assert second_lease is None


async def test_stale_hash_resets_completed_task_for_rerun(
    db_session: AsyncSession, seeded_user: db_models.User
):
    scan = await _scan(db_session, seeded_user)
    service = ScanTaskLedgerService(db_session)

    first = await service.acquire_task(
        scan_id=scan.id,
        task_type="analysis",
        task_key="same-key",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={"old": True},
        lease_owner="worker-1",
    )
    assert first is not None
    task_id = first.task.id
    await service.complete_task(task_id, result_payload={"old": True})

    ensure = await service.ensure_task(
        scan_id=scan.id,
        task_type="analysis",
        task_key="same-key",
        input_hash="d" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={"old": False},
    )
    assert ensure.stale is True
    assert ensure.task.id == task_id
    assert ensure.task.status == STATUS_SCAN_TASK_PENDING
    assert ensure.task.result_payload is None
    assert ensure.task.attempts == 0

    rerun = await service.acquire_task(
        scan_id=scan.id,
        task_type="analysis",
        task_key="same-key",
        input_hash="d" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={"old": False},
        lease_owner="worker-2",
    )
    assert rerun is not None
    assert rerun.task.id == task_id
    assert rerun.task.status == STATUS_SCAN_TASK_RUNNING
    assert rerun.task.attempts == 1


async def test_expired_running_task_is_retried_until_cap(
    db_session: AsyncSession, seeded_user: db_models.User
):
    scan = await _scan(db_session, seeded_user)
    service = ScanTaskLedgerService(db_session)

    lease = await service.acquire_task(
        scan_id=scan.id,
        task_type="consolidation",
        task_key="file.py",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={},
        lease_owner="worker-1",
        max_attempts=3,
    )
    assert lease is not None
    lease.task.lease_expires_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(
        seconds=1
    )
    await db_session.commit()

    retry = await service.acquire_task(
        scan_id=scan.id,
        task_type="consolidation",
        task_key="file.py",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={},
        lease_owner="worker-2",
        max_attempts=3,
    )
    assert retry is not None
    assert retry.task.attempts == 2
    assert retry.task.lease_owner == "worker-2"


async def test_retry_cap_marks_expired_task_failed(
    db_session: AsyncSession, seeded_user: db_models.User
):
    scan = await _scan(db_session, seeded_user)
    service = ScanTaskLedgerService(db_session)

    task = db_models.ScanTask(
        scan_id=scan.id,
        task_type="analysis",
        task_key="capped",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={},
        status=STATUS_SCAN_TASK_RUNNING,
        attempts=2,
        max_attempts=2,
        lease_owner="dead-worker",
        lease_expires_at=dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=1),
    )
    db_session.add(task)
    await db_session.commit()

    lease = await service.acquire_task(
        scan_id=scan.id,
        task_type="analysis",
        task_key="capped",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={},
        lease_owner="worker-2",
        max_attempts=2,
    )
    assert lease is None
    row = (
        await db_session.execute(
            select(db_models.ScanTask).where(db_models.ScanTask.id == task.id)
        )
    ).scalar_one()
    assert row.status == STATUS_SCAN_TASK_FAILED
    assert row.lease_owner is None


async def test_scan_delete_cascades_scan_tasks(
    db_session: AsyncSession, seeded_user: db_models.User
):
    scan = await _scan(db_session, seeded_user)
    service = ScanTaskLedgerService(db_session)
    lease = await service.acquire_task(
        scan_id=scan.id,
        task_type="analysis",
        task_key="owned-by-scan",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={},
        lease_owner="worker-1",
    )
    assert lease is not None
    task_id = lease.task.id

    await db_session.delete(scan)
    await db_session.commit()

    assert await db_session.get(db_models.ScanTask, task_id) is None
