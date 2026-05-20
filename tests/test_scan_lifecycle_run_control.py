from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.v1.models import ScanRunControlRequest
from app.core.services.scan.lifecycle import ScanLifecycleService
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_QUEUED,
)
from app.shared.lib.scan_task_status import STATUS_SCAN_TASK_COMPLETED

pytestmark = pytest.mark.asyncio


async def _scan(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    *,
    status: str = STATUS_FAILED,
) -> db_models.Scan:
    project = db_models.Project(name=f"p-{uuid.uuid4().hex}", user_id=seeded_user.id)
    scan = db_models.Scan(
        project=project,
        user_id=seeded_user.id,
        scan_type="AUDIT",
        status=status,
        frameworks=["ASVS"],
        summary={"old": True},
        risk_score=7,
    )
    db_session.add(scan)
    await db_session.flush()
    db_session.add(
        db_models.CodeSnapshot(
            scan_id=scan.id,
            snapshot_type="ORIGINAL_SUBMISSION",
            file_map={"app.py": "h1"},
        )
    )
    await db_session.commit()
    return scan


async def _install_publish_stub(monkeypatch: pytest.MonkeyPatch, published: list[dict]):
    async def _publish(queue_name: str, payload: dict) -> bool:
        published.append({"queue_name": queue_name, "payload": payload})
        return True

    monkeypatch.setattr("app.core.services.scan.lifecycle.publish_message", _publish)


async def test_failed_scan_resume_keeps_tasks_and_emits_boundary_events(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    published: list[dict] = []
    await _install_publish_stub(monkeypatch, published)
    scan = await _scan(db_session, seeded_user, status=STATUS_FAILED)
    task = db_models.ScanTask(
        scan_id=scan.id,
        task_type="analysis",
        task_key="app.py:0:agent:primary",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={"file_path": "app.py"},
        result_payload={"findings": []},
        status=STATUS_SCAN_TASK_COMPLETED,
    )
    db_session.add(task)
    await db_session.commit()

    result = await ScanLifecycleService(
        ScanRepository(db_session)
    ).resume_or_restart_scan(scan.id, seeded_user, ScanRunControlRequest(mode="resume"))

    await db_session.refresh(scan)
    assert result["mode"] == "resume"
    assert scan.status == STATUS_QUEUED
    assert await db_session.get(db_models.ScanTask, task.id) is not None
    events = (
        (
            await db_session.execute(
                select(db_models.ScanEvent.stage_name).where(
                    db_models.ScanEvent.scan_id == scan.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert "MANUAL_RESUME_REQUESTED" in events
    assert "RESUME_ARTIFACT_EVALUATION" in events
    assert published and published[-1]["payload"] == {
        "scan_id": str(scan.id),
        "action": "manual_resume",
        "mode": "resume",
    }


async def test_restart_deletes_artifacts_findings_and_derived_snapshots_but_keeps_events(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    published: list[dict] = []
    await _install_publish_stub(monkeypatch, published)
    scan = await _scan(db_session, seeded_user, status=STATUS_FAILED)
    task = db_models.ScanTask(
        scan_id=scan.id,
        task_type="analysis",
        task_key="old",
        input_hash="a" * 64,
        prompt_hash="b" * 64,
        version_hash="c" * 64,
        input_payload={},
        status=STATUS_SCAN_TASK_COMPLETED,
    )
    finding = db_models.Finding(
        scan_id=scan.id,
        file_path="app.py",
        title="old finding",
        severity="High",
    )
    old_event = db_models.ScanEvent(
        scan_id=scan.id, stage_name="OLD_AUDIT_EVENT", status="COMPLETED"
    )
    llm_interaction = db_models.LLMInteraction(
        scan_id=scan.id,
        agent_name="test-agent",
        raw_response="{}",
    )
    derived_snapshot = db_models.CodeSnapshot(
        scan_id=scan.id,
        snapshot_type="POST_REMEDIATION",
        file_map={"app.py": "h2"},
    )
    db_session.add_all([task, finding, old_event, llm_interaction, derived_snapshot])
    await db_session.commit()

    result = await ScanLifecycleService(
        ScanRepository(db_session)
    ).resume_or_restart_scan(
        scan.id, seeded_user, ScanRunControlRequest(mode="restart")
    )

    await db_session.refresh(scan)
    assert result["deleted_tasks"] == 1
    assert result["deleted_findings"] == 1
    assert result["deleted_derived_snapshots"] == 1
    assert scan.status == STATUS_QUEUED
    assert scan.summary is None
    assert scan.risk_score is None
    task_rows = (
        (
            await db_session.execute(
                select(db_models.ScanTask.id).where(db_models.ScanTask.id == task.id)
            )
        )
        .scalars()
        .all()
    )
    finding_rows = (
        (
            await db_session.execute(
                select(db_models.Finding.id).where(db_models.Finding.id == finding.id)
            )
        )
        .scalars()
        .all()
    )
    assert task_rows == []
    assert finding_rows == []
    snapshot_types = (
        (
            await db_session.execute(
                select(db_models.CodeSnapshot.snapshot_type).where(
                    db_models.CodeSnapshot.scan_id == scan.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert snapshot_types == ["ORIGINAL_SUBMISSION"]
    events = (
        (
            await db_session.execute(
                select(db_models.ScanEvent.stage_name).where(
                    db_models.ScanEvent.scan_id == scan.id
                )
            )
        )
        .scalars()
        .all()
    )
    assert "OLD_AUDIT_EVENT" in events
    assert "MANUAL_RESTART_REQUESTED" in events
    assert (
        await db_session.get(db_models.LLMInteraction, llm_interaction.id) is not None
    )


async def test_cancelled_scan_with_artifacts_is_resumable(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    published: list[dict] = []
    await _install_publish_stub(monkeypatch, published)
    scan = await _scan(db_session, seeded_user, status=STATUS_CANCELLED)
    db_session.add(
        db_models.ScanTask(
            scan_id=scan.id,
            task_type="analysis",
            task_key="resume-me",
            input_hash="a" * 64,
            prompt_hash="b" * 64,
            version_hash="c" * 64,
            input_payload={},
            status=STATUS_SCAN_TASK_COMPLETED,
        )
    )
    await db_session.commit()

    await ScanLifecycleService(ScanRepository(db_session)).resume_or_restart_scan(
        scan.id, seeded_user, ScanRunControlRequest(mode="resume")
    )

    await db_session.refresh(scan)
    assert scan.status == STATUS_QUEUED
    assert published[-1]["payload"]["mode"] == "resume"


async def test_cancelled_scan_without_artifacts_is_not_resumable(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    await _install_publish_stub(monkeypatch, [])
    scan = await _scan(db_session, seeded_user, status=STATUS_CANCELLED)

    with pytest.raises(HTTPException) as exc:
        await ScanLifecycleService(ScanRepository(db_session)).resume_or_restart_scan(
            scan.id, seeded_user, ScanRunControlRequest(mode="resume")
        )

    assert exc.value.status_code == 400
    assert "no resumable artifacts" in exc.value.detail


async def test_pending_approval_status_is_rejected(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    await _install_publish_stub(monkeypatch, [])
    scan = await _scan(db_session, seeded_user, status=STATUS_PENDING_APPROVAL)

    with pytest.raises(HTTPException) as exc:
        await ScanLifecycleService(ScanRepository(db_session)).resume_or_restart_scan(
            scan.id, seeded_user, ScanRunControlRequest(mode="restart")
        )

    assert exc.value.status_code == 400
    assert "existing approval flow" in exc.value.detail


async def test_run_control_authorization_matches_lifecycle_mutation_guard(
    db_session: AsyncSession,
    seeded_user: db_models.User,
    monkeypatch: pytest.MonkeyPatch,
):
    await _install_publish_stub(monkeypatch, [])
    scan = await _scan(db_session, seeded_user, status=STATUS_FAILED)
    other = db_models.User(
        email=f"other-{uuid.uuid4().hex}@sccap.test",
        hashed_password="x" * 64,
        is_active=True,
        is_superuser=False,
        is_verified=True,
    )
    db_session.add(other)
    await db_session.commit()

    with pytest.raises(HTTPException) as exc:
        await ScanLifecycleService(ScanRepository(db_session)).resume_or_restart_scan(
            scan.id, other, ScanRunControlRequest(mode="resume")
        )

    assert exc.value.status_code == 403
