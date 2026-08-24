"""Drive all three approval gates over public HTTP on one graph thread."""

from __future__ import annotations

import asyncio
import os
import time
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select, text

from app.config.config import settings
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    ApprovalGate,
    Framework,
    FrameworkAgentMapping,
    LLMConfiguration,
    Project,
    RoleAssignment,
    ScanEvent,
    ScanOutbox,
    User,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.messaging.publisher import publish_message
from app.shared.lib.encryption import FernetEncrypt
from app.shared.lib.permissions import DEVELOPER


BASE_URL = os.getenv("SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


async def _wait_status(
    client: httpx.AsyncClient, scan_id: str, token: str, expected: str
) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        response = await client.get(
            f"/api/v1/scans/{scan_id}/result",
            headers={"Authorization": f"Bearer {token}"},
        )
        if response.status_code == 200 and response.json()["status"] == expected:
            return
        await asyncio.sleep(1)
    raise AssertionError(f"scan {scan_id} did not reach {expected}")


async def _checkpoint_count(scan_id: str) -> int:
    async with AsyncSessionLocal() as db:
        rows = (
            await db.execute(
                text(
                    "SELECT thread_id, count(*) FROM checkpoints "
                    "WHERE thread_id = :thread_id GROUP BY thread_id"
                ),
                {"thread_id": scan_id},
            )
        ).all()
    if len(rows) != 1 or rows[0].thread_id != scan_id:
        raise AssertionError(f"checkpoint thread mismatch for scan {scan_id}: {rows}")
    return int(rows[0].count)


async def _provider_call_count(client: httpx.AsyncClient) -> int:
    response = await client.get("http://127.0.0.1:8765/stats")
    response.raise_for_status()
    return int(response.json()["request_count"])


async def _approval_outbox_payload(gate_id: str) -> dict:
    async with AsyncSessionLocal() as db:
        payload = await db.scalar(
            select(ScanOutbox.payload).where(
                ScanOutbox.idempotency_key == f"approval-gate:{gate_id}"
            )
        )
    if payload is None:
        raise AssertionError(f"gate {gate_id}: approval outbox payload is missing")
    return dict(payload)


async def main() -> None:
    run_id = uuid4().hex[:12]
    email = f"integration-gates-{run_id}@example.com"
    password = f"V7!gates-{run_id}-Z"
    project_name = f"Integration Gates {run_id}"
    llm_name = f"Integration Gate LLM {run_id}"
    scan_id: str | None = None

    async with AsyncSessionLocal() as db:
        framework_name = await db.scalar(
            select(Framework.name)
            .join(
                FrameworkAgentMapping,
                FrameworkAgentMapping.framework_id == Framework.id,
            )
            .limit(1)
        )
        if framework_name is None:
            raise AssertionError(
                "integration stack has no framework mapped to an agent"
            )
        user = User(
            email=email,
            hashed_password=PasswordHelper().hash(password),
            is_active=True,
            is_superuser=False,
            is_verified=True,
        )
        llm = LLMConfiguration(
            name=llm_name,
            provider="custom_openai",
            model_name="integration-model",
            base_url="http://app:8765/v1",
            encrypted_api_key=FernetEncrypt.encrypt("integration-only-key"),
            input_cost_per_million=0,
            output_cost_per_million=0,
        )
        db.add_all([user, llm])
        await db.flush()
        db.add(
            RoleAssignment(
                user_id=user.id,
                tenant_id=None,
                role_key=DEVELOPER,
            )
        )
        await db.commit()
        await db.refresh(llm)
        llm_id = llm.id

    try:
        async with httpx.AsyncClient(base_url=BASE_URL, timeout=30) as client:
            reset = await client.post("http://127.0.0.1:8765/reset")
            reset.raise_for_status()
            login = await client.post(
                "/api/v1/auth/login", data={"username": email, "password": password}
            )
            if login.status_code != 200:
                raise AssertionError(login.text)
            token = login.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            submit = await client.post(
                "/api/v1/scans",
                headers=headers,
                data={
                    "project_name": project_name,
                    "scan_type": "AUDIT",
                    "reasoning_llm_config_id": str(llm_id),
                    "utility_llm_config_id": str(llm_id),
                    "frameworks": framework_name,
                },
                files={
                    "files": (
                        "gate_probe.py",
                        b'import subprocess\nsubprocess.Popen("ls", shell=True)\n',
                        "text/x-python",
                    )
                },
            )
            if submit.status_code != 200:
                raise AssertionError(submit.text)
            scan_id = submit.json()["scan_id"]

            counts: list[int] = []
            gate_ids: list[str] = []
            provider_counts: list[int] = []
            previous_delivery: dict | None = None
            for status, kind, approved in (
                ("PENDING_PRESCAN_APPROVAL", "prescan_approval", True),
                ("PENDING_PROFILING_APPROVAL", "profiling_approval", True),
                ("PENDING_COST_APPROVAL", "cost_approval", False),
            ):
                await _wait_status(client, scan_id, token, status)
                if previous_delivery is not None:
                    checkpoint_before_redelivery = await _checkpoint_count(scan_id)
                    published = await publish_message(
                        queue_name=settings.RABBITMQ_APPROVAL_QUEUE,
                        message_body=previous_delivery,
                    )
                    if not published:
                        raise AssertionError(
                            "duplicate approval payload was not published"
                        )
                    await asyncio.sleep(1)
                    await _wait_status(client, scan_id, token, status)
                    if await _checkpoint_count(scan_id) != checkpoint_before_redelivery:
                        raise AssertionError(
                            "stale completed gate delivery advanced the next checkpoint"
                        )
                counts.append(await _checkpoint_count(scan_id))
                gate_response = await client.get(
                    f"/api/v1/scans/{scan_id}/result",
                    headers=headers,
                )
                gate = gate_response.json().get("active_approval_gate")
                if not gate or gate.get("kind") != kind:
                    raise AssertionError(f"{kind}: missing active gate: {gate}")
                gate_ids.append(gate["gate_id"])
                provider_counts.append(await _provider_call_count(client))
                decision_key = f"integration-{gate['gate_id']}"
                decision_body = {
                    "kind": kind,
                    "approved": approved,
                    "gate_id": gate["gate_id"],
                    "gate_version": gate["version"],
                    "evidence_hash": gate["evidence_hash"],
                }
                decision_headers = {
                    **headers,
                    "X-Idempotency-Key": decision_key,
                }
                approvals = await asyncio.gather(
                    *(
                        client.post(
                            f"/api/v1/scans/{scan_id}/approve",
                            headers=decision_headers,
                            json=decision_body,
                        )
                        for _ in range(2)
                    )
                )
                if any(response.status_code != 202 for response in approvals):
                    raise AssertionError(
                        f"{kind}: duplicate decisions were not idempotent: "
                        f"{[(r.status_code, r.text) for r in approvals]}"
                    )
                conflict = await client.post(
                    f"/api/v1/scans/{scan_id}/approve",
                    headers={
                        **headers,
                        "X-Idempotency-Key": f"conflict-{gate['gate_id']}",
                    },
                    json={**decision_body, "approved": not approved},
                )
                if conflict.status_code != 409:
                    raise AssertionError(
                        f"{kind}: conflicting decision returned {conflict.status_code}"
                    )
                previous_delivery = await _approval_outbox_payload(gate["gate_id"])

            if counts != sorted(counts) or len(set(counts)) != 3:
                raise AssertionError(f"checkpoint sequence did not advance: {counts}")
            await _wait_status(client, scan_id, token, "BLOCKED_USER_DECLINE")
            assert previous_delivery is not None
            if not await publish_message(
                queue_name=settings.RABBITMQ_APPROVAL_QUEUE,
                message_body=previous_delivery,
            ):
                raise AssertionError(
                    "terminal duplicate approval payload was not published"
                )
            await asyncio.sleep(1)
            await _wait_status(client, scan_id, token, "BLOCKED_USER_DECLINE")
            if provider_counts[:2] != [0, 0] or provider_counts[2] < 1:
                raise AssertionError(
                    "provider-call gate ordering violated: "
                    f"counts_at_gates={provider_counts}"
                )
            if await _provider_call_count(client) != provider_counts[2]:
                raise AssertionError(
                    "analysis provider called after declined cost gate"
                )

            async with AsyncSessionLocal() as db:
                gates = list(
                    (
                        await db.scalars(
                            select(ApprovalGate)
                            .where(ApprovalGate.scan_id == scan_id)
                            .order_by(ApprovalGate.sequence)
                        )
                    ).all()
                )
                outbox = list(
                    (
                        await db.scalars(
                            select(ScanOutbox).where(
                                ScanOutbox.scan_id == scan_id,
                                ScanOutbox.idempotency_key.isnot(None),
                            )
                        )
                    ).all()
                )
                events = list(
                    (
                        await db.scalars(
                            select(ScanEvent).where(ScanEvent.scan_id == scan_id)
                        )
                    ).all()
                )
            if [str(g.gate_id) for g in gates] != gate_ids:
                raise AssertionError(f"durable gate identities diverged: {gates}")
            if [g.sequence for g in gates] != [1, 2, 3]:
                raise AssertionError(f"gate sequence diverged: {gates}")
            if [g.decision for g in gates] != [True, True, False]:
                raise AssertionError(f"durable decisions diverged: {gates}")
            if any(g.state != "completed" for g in gates):
                raise AssertionError(f"gate did not complete once: {gates}")
            if {row.idempotency_key for row in outbox} != {
                f"approval-gate:{gate_id}" for gate_id in gate_ids
            }:
                raise AssertionError(f"outbox identities diverged: {outbox}")
            for gate_id in gate_ids:
                lineage = [
                    event
                    for event in events
                    if (event.details or {}).get("gate_id") == gate_id
                ]
                counts_by_status = {
                    status: sum(event.status == status for event in lineage)
                    for status in ("WAITING", "COMPLETED", "REJECTED")
                }
                decision_count = sum(
                    event.stage_name == "QUEUED_FOR_SCAN" for event in lineage
                )
                if (
                    counts_by_status
                    != {
                        "WAITING": 1,
                        "COMPLETED": 2,
                        "REJECTED": 1,
                    }
                    or decision_count != 1
                ):
                    # One COMPLETED is the durable decision/queue event and one
                    # is the gate's graph-completion event.
                    raise AssertionError(
                        f"gate {gate_id} lineage mismatch: "
                        f"statuses={counts_by_status} decision={decision_count}"
                    )
            print(
                f"all gates resumed graph thread {scan_id}; checkpoints={counts}; "
                f"provider_counts={provider_counts}"
            )
    finally:
        async with AsyncSessionLocal() as db:
            if scan_id is not None:
                # Terminal worker paths normally remove the thread. Explicit
                # cleanup also covers a scenario assertion/provider failure.
                for table in ("checkpoint_writes", "checkpoint_blobs", "checkpoints"):
                    await db.execute(
                        text(f"DELETE FROM {table} WHERE thread_id = :thread_id"),
                        {"thread_id": scan_id},
                    )
            project = await db.scalar(
                select(Project).where(Project.name == project_name)
            )
            if project is not None:
                await ScanRepository(db).delete_project(project.id)
            await db.execute(delete(User).where(User.email == email))
            await db.execute(
                delete(LLMConfiguration).where(LLMConfiguration.name == llm_name)
            )
            await db.commit()
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
