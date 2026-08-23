"""Public resume/restart scenario executed while RabbitMQ is unavailable.

Pausing dispatch makes the API transaction observable without racing a real
worker. The scenario proves the public response, durable status/outbox intent,
resume preservation, restart cleanup, and duplicate-request rejection, then
removes all fixtures before the broker is restored.
"""

from __future__ import annotations

import asyncio
import os
from datetime import datetime, timezone
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, func, select

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    CodeSnapshot,
    Finding,
    Project,
    Scan,
    ScanOutbox,
    ScanTask,
    User,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import STATUS_CANCELLED, STATUS_FAILED, STATUS_QUEUED
from app.shared.lib.scan_task_status import STATUS_SCAN_TASK_COMPLETED


def _base_url() -> str:
    return os.getenv("SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


async def _create_fixtures() -> dict[str, object]:
    suffix = uuid4().hex
    password = f"A7!run-control-{suffix}z"
    async with AsyncSessionLocal() as db:
        user = User(
            email=f"integration-run-control-{suffix}@example.com",
            hashed_password=PasswordHelper().hash(password),
            is_active=True,
            is_superuser=False,
            is_verified=True,
        )
        db.add(user)
        await db.flush()

        project = Project(
            user_id=user.id,
            name=f"Integration Run Control {suffix}",
        )
        resume_scan = Scan(
            project=project,
            user_id=user.id,
            scan_type="AUDIT",
            status=STATUS_CANCELLED,
            frameworks=[],
            summary={"stale": True},
            risk_score=99,
            completed_at=datetime.now(timezone.utc),
        )
        restart_scan = Scan(
            project=project,
            user_id=user.id,
            scan_type="AUDIT",
            status=STATUS_FAILED,
            frameworks=[],
            summary={"stale": True},
            risk_score=99,
            completed_at=datetime.now(timezone.utc),
        )
        db.add_all([project, resume_scan, restart_scan])
        await db.flush()

        for scan in (resume_scan, restart_scan):
            db.add(
                ScanTask(
                    scan_id=scan.id,
                    task_type="analysis",
                    task_key="src/example.py",
                    input_hash="i" * 64,
                    prompt_hash="p" * 64,
                    version_hash="v" * 64,
                    input_payload={"path": "src/example.py"},
                    result_payload={"findings": []},
                    status=STATUS_SCAN_TASK_COMPLETED,
                )
            )

        db.add_all(
            [
                Finding(
                    scan_id=restart_scan.id,
                    file_path="src/example.py",
                    title="Derived result",
                    severity="High",
                    finding_bucket="consolidated",
                ),
                Finding(
                    scan_id=restart_scan.id,
                    file_path="src/example.py",
                    title="Preserved scanner evidence",
                    severity="High",
                    finding_bucket="sast",
                ),
                CodeSnapshot(
                    scan_id=restart_scan.id,
                    snapshot_type="ORIGINAL_SUBMISSION",
                    file_map={"src/example.py": "original-hash"},
                ),
                CodeSnapshot(
                    scan_id=restart_scan.id,
                    snapshot_type="REMEDIATED",
                    file_map={"src/example.py": "derived-hash"},
                ),
            ]
        )
        await db.commit()
        return {
            "email": user.email,
            "password": password,
            "user_id": user.id,
            "project_id": project.id,
            "resume_scan_id": resume_scan.id,
            "restart_scan_id": restart_scan.id,
        }


async def _login(fixture: dict[str, object], client: httpx.AsyncClient) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        data={"username": fixture["email"], "password": fixture["password"]},
    )
    if response.status_code != 200:
        raise AssertionError(f"login failed: {response.status_code} {response.text}")
    return response.json()["access_token"]


async def _exercise(fixture: dict[str, object]) -> None:
    resume_scan_id = fixture["resume_scan_id"]
    restart_scan_id = fixture["restart_scan_id"]
    async with httpx.AsyncClient(base_url=_base_url(), timeout=30.0) as client:
        token = await _login(fixture, client)
        headers = {"Authorization": f"Bearer {token}"}

        resume = await client.post(
            f"/api/v1/scans/{resume_scan_id}/run-control",
            json={"mode": "resume"},
            headers=headers,
        )
        if resume.status_code != 202:
            raise AssertionError(
                f"public resume failed: {resume.status_code} {resume.text}"
            )
        resume_body = resume.json()
        if resume_body["artifact_counts"] != {STATUS_SCAN_TASK_COMPLETED: 1}:
            raise AssertionError(f"resume did not expose reusable work: {resume_body}")
        if any(
            resume_body[key]
            for key in (
                "deleted_tasks",
                "deleted_findings",
                "deleted_derived_snapshots",
            )
        ):
            raise AssertionError(f"resume deleted durable work: {resume_body}")

        restart = await client.post(
            f"/api/v1/scans/{restart_scan_id}/run-control",
            json={"mode": "restart"},
            headers=headers,
        )
        if restart.status_code != 202:
            raise AssertionError(
                f"public restart failed: {restart.status_code} {restart.text}"
            )
        restart_body = restart.json()
        expected_deleted = {
            "deleted_tasks": 1,
            "deleted_findings": 1,
            "deleted_derived_snapshots": 1,
        }
        for key, expected in expected_deleted.items():
            if restart_body[key] != expected:
                raise AssertionError(f"restart cleanup mismatch: {restart_body}")

        for scan_id, mode in (
            (resume_scan_id, "resume"),
            (restart_scan_id, "restart"),
        ):
            duplicate = await client.post(
                f"/api/v1/scans/{scan_id}/run-control",
                json={"mode": mode},
                headers=headers,
            )
            if duplicate.status_code != 400:
                raise AssertionError(
                    "duplicate run-control request was not rejected: "
                    f"{duplicate.status_code} {duplicate.text}"
                )

    async with AsyncSessionLocal() as db:
        resume_state = (
            await db.execute(
                select(Scan.status, Scan.summary, Scan.risk_score).where(
                    Scan.id == resume_scan_id
                )
            )
        ).one()
        restart_state = (
            await db.execute(
                select(Scan.status, Scan.summary, Scan.risk_score).where(
                    Scan.id == restart_scan_id
                )
            )
        ).one()
        resume_tasks = int(
            await db.scalar(
                select(func.count())
                .select_from(ScanTask)
                .where(ScanTask.scan_id == resume_scan_id)
            )
            or 0
        )
        restart_tasks = int(
            await db.scalar(
                select(func.count())
                .select_from(ScanTask)
                .where(ScanTask.scan_id == restart_scan_id)
            )
            or 0
        )
        restart_buckets = list(
            (
                await db.scalars(
                    select(Finding.finding_bucket).where(
                        Finding.scan_id == restart_scan_id
                    )
                )
            ).all()
        )
        restart_snapshots = list(
            (
                await db.scalars(
                    select(CodeSnapshot.snapshot_type).where(
                        CodeSnapshot.scan_id == restart_scan_id
                    )
                )
            ).all()
        )
        outboxes = list(
            (
                await db.scalars(
                    select(ScanOutbox).where(
                        ScanOutbox.scan_id.in_([resume_scan_id, restart_scan_id])
                    )
                )
            ).all()
        )

    if resume_state.status != STATUS_QUEUED or resume_tasks != 1:
        raise AssertionError(
            f"resume state was not preserved: {resume_state}, tasks={resume_tasks}"
        )
    if resume_state.summary != {"stale": True} or resume_state.risk_score != 99:
        raise AssertionError(f"resume cleared final outputs: {resume_state}")
    if restart_state != (STATUS_QUEUED, None, None) or restart_tasks != 0:
        raise AssertionError(
            f"restart state was not reset: {restart_state}, tasks={restart_tasks}"
        )
    if restart_buckets != ["sast"]:
        raise AssertionError(
            f"restart did not preserve only scanner evidence: {restart_buckets}"
        )
    if restart_snapshots != ["ORIGINAL_SUBMISSION"]:
        raise AssertionError(
            f"restart did not preserve only source snapshot: {restart_snapshots}"
        )
    if len(outboxes) != 2 or any(row.published_at is not None for row in outboxes):
        raise AssertionError(
            "run-control intents must remain pending while RabbitMQ is stopped"
        )

    print(
        "public resume preserved reusable tasks; public restart cleared derived "
        "state; duplicate requests were rejected"
    )


async def _cleanup(fixture: dict[str, object]) -> None:
    async with AsyncSessionLocal() as db:
        await ScanRepository(db).delete_project(fixture["project_id"])
        await db.execute(delete(User).where(User.id == fixture["user_id"]))
        await db.commit()


async def _main() -> None:
    fixture = await _create_fixtures()
    try:
        await _exercise(fixture)
    finally:
        await _cleanup(fixture)
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(_main())
