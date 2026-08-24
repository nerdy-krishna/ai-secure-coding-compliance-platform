"""Phased public-API scenario for a real RabbitMQ outage and recovery.

The host-side CI workflow controls the broker between phases. Keeping Docker
control outside the application container avoids mounting the Docker socket
into a test process.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import time
from dataclasses import dataclass

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select, text

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    Framework,
    LLMConfiguration,
    Project,
    RoleAssignment,
    Scan,
    ScanEvent,
    ScanOutbox,
    User,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.encryption import FernetEncrypt
from app.shared.lib.permissions import DEVELOPER


@dataclass(frozen=True)
class ScenarioIdentity:
    run_id: str

    @property
    def email(self) -> str:
        return f"integration-outbox-{self.run_id}@example.com"

    @property
    def password(self) -> str:
        return f"V7!outbox-{self.run_id}-Z"

    @property
    def project_name(self) -> str:
        return f"Integration Outbox {self.run_id}"

    @property
    def framework_name(self) -> str:
        return f"Integration Framework {self.run_id}"

    @property
    def llm_name(self) -> str:
        return f"Integration LLM {self.run_id}"


def _identity(raw_run_id: str) -> ScenarioIdentity:
    normalized = re.sub(r"[^a-z0-9-]", "-", raw_run_id.lower()).strip("-")
    if not normalized or len(normalized) > 40:
        raise ValueError("run id must normalize to 1-40 lowercase characters")
    return ScenarioIdentity(normalized)


def _base_url() -> str:
    return os.getenv("SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000").rstrip("/")


async def _prepare(identity: ScenarioIdentity) -> None:
    async with AsyncSessionLocal() as db:
        existing_user = await db.scalar(
            select(User).where(User.email == identity.email)
        )
        if existing_user is not None:
            raise AssertionError(
                f"scenario user already exists for run {identity.run_id}"
            )

        user = User(
            email=identity.email,
            hashed_password=PasswordHelper().hash(identity.password),
            is_active=True,
            is_superuser=False,
            is_verified=True,
        )
        db.add(user)
        db.add(
            Framework(
                name=identity.framework_name,
                description="Ephemeral integration framework for outbox recovery.",
            )
        )
        db.add(
            LLMConfiguration(
                name=identity.llm_name,
                provider="openai",
                model_name="gpt-4o-mini",
                encrypted_api_key=FernetEncrypt.encrypt(
                    "integration-key-must-never-be-called"
                ),
                input_cost_per_million=0,
                output_cost_per_million=0,
            )
        )
        await db.flush()
        db.add(
            RoleAssignment(
                user_id=user.id,
                tenant_id=user.tenant_id,
                role_key=DEVELOPER,
            )
        )
        await db.commit()

    print(f"prepared isolated outbox fixture {identity.run_id}")


async def _login(identity: ScenarioIdentity, client: httpx.AsyncClient) -> str:
    response = await client.post(
        "/api/v1/auth/login",
        data={"username": identity.email, "password": identity.password},
    )
    if response.status_code != 200:
        raise AssertionError(f"login failed: {response.status_code} {response.text}")
    return response.json()["access_token"]


async def _submit_while_broker_is_down(identity: ScenarioIdentity) -> None:
    async with AsyncSessionLocal() as db:
        llm_id = await db.scalar(
            select(LLMConfiguration.id).where(
                LLMConfiguration.name == identity.llm_name
            )
        )
        if llm_id is None:
            raise AssertionError("scenario LLM fixture is missing")

    async with httpx.AsyncClient(base_url=_base_url(), timeout=30.0) as client:
        token = await _login(identity, client)
        response = await client.post(
            "/api/v1/scans",
            headers={"Authorization": f"Bearer {token}"},
            data={
                "project_name": identity.project_name,
                "scan_type": "AUDIT",
                "reasoning_llm_config_id": str(llm_id),
                "utility_llm_config_id": str(llm_id),
                "frameworks": identity.framework_name,
            },
            files={
                "files": (
                    "outage_probe.py",
                    b'import subprocess\nsubprocess.Popen("ls", shell=True)\n',
                    "text/x-python",
                )
            },
        )
        if response.status_code != 200:
            raise AssertionError(
                f"public submission failed: {response.status_code} {response.text}"
            )
        submitted_scan_id = response.json()["scan_id"]

    async with AsyncSessionLocal() as db:
        row = (
            await db.execute(
                select(Scan.id, Scan.status, ScanOutbox.published_at)
                .join(Project, Scan.project_id == Project.id)
                .join(ScanOutbox, ScanOutbox.scan_id == Scan.id)
                .where(Project.name == identity.project_name)
            )
        ).one()
        if str(row.id) != submitted_scan_id:
            raise AssertionError("public response and durable scan id do not match")
        if row.status != "QUEUED":
            raise AssertionError(f"expected QUEUED during outage, got {row.status}")
        if row.published_at is not None:
            raise AssertionError(
                "outbox was marked published while RabbitMQ was stopped"
            )

    print(f"submission {submitted_scan_id} committed with pending outbox")


async def _assert_recovered(identity: ScenarioIdentity) -> None:
    deadline = time.monotonic() + 120
    scan_id = None
    status = None
    event_count = 0
    while time.monotonic() < deadline:
        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    select(Scan.id, Scan.status, ScanOutbox.published_at)
                    .join(Project, Scan.project_id == Project.id)
                    .join(ScanOutbox, ScanOutbox.scan_id == Scan.id)
                    .where(Project.name == identity.project_name)
                )
            ).one()
            scan_id = row.id
            status = row.status
            event_count = int(
                await db.scalar(
                    select(ScanEvent.id)
                    .where(ScanEvent.scan_id == scan_id)
                    .order_by(ScanEvent.id.desc())
                    .limit(1)
                )
                or 0
            )
            if row.published_at is not None and status != "QUEUED" and event_count > 0:
                break
        await asyncio.sleep(1)
    else:
        raise AssertionError(
            "outbox did not publish and reach the worker within 120s "
            f"(status={status}, latest_event_id={event_count})"
        )

    assert scan_id is not None
    async with httpx.AsyncClient(base_url=_base_url(), timeout=30.0) as client:
        token = await _login(identity, client)
        headers = {"Authorization": f"Bearer {token}"}
        public_result = await client.get(
            f"/api/v1/scans/{scan_id}/result", headers=headers
        )
        if public_result.status_code != 200:
            raise AssertionError(
                f"public result read failed: {public_result.status_code} {public_result.text}"
            )
        public_status = public_result.json()["status"]
        durable_status = status
        consistency_deadline = time.monotonic() + 30
        while (
            public_status != durable_status and time.monotonic() < consistency_deadline
        ):
            await asyncio.sleep(0.25)
            public_result = await client.get(
                f"/api/v1/scans/{scan_id}/result", headers=headers
            )
            if public_result.status_code != 200:
                raise AssertionError(
                    "public result re-read failed: "
                    f"{public_result.status_code} {public_result.text}"
                )
            public_status = public_result.json()["status"]
            async with AsyncSessionLocal() as db:
                durable_status = await db.scalar(
                    select(Scan.status).where(Scan.id == scan_id)
                )
        if public_status != durable_status:
            raise AssertionError(
                "public status did not converge with the durable worker state "
                f"(public={public_status}, durable={durable_status})"
            )
        status = durable_status

        cancel = await client.post(f"/api/v1/scans/{scan_id}/cancel", headers=headers)
        if cancel.status_code != 200:
            raise AssertionError(
                f"cleanup cancellation failed: {cancel.status_code} {cancel.text}"
            )

        # Keep the real worker alive briefly after the competing cancellation
        # write. A late node/status write must not escape the terminal policy.
        await asyncio.sleep(10)
        stable_result = await client.get(
            f"/api/v1/scans/{scan_id}/result", headers=headers
        )
        if stable_result.status_code != 200:
            raise AssertionError(
                "post-cancel result read failed: "
                f"{stable_result.status_code} {stable_result.text}"
            )
        if stable_result.json()["status"] != "CANCELLED":
            raise AssertionError(
                "late worker activity overwrote terminal CANCELLED status"
            )

        # Do not delete the fixture while a long scanner node still owns it.
        # The consumer removes the checkpointer thread only after the node
        # observes cancellation and exits. Waiting for that cleanup prevents
        # teardown from racing late finding/event persistence.
        checkpoint_deadline = time.monotonic() + 120
        while time.monotonic() < checkpoint_deadline:
            async with AsyncSessionLocal() as db:
                checkpoint_count = int(
                    await db.scalar(
                        text(
                            "SELECT count(*) FROM checkpoints "
                            "WHERE thread_id = :thread_id"
                        ),
                        {"thread_id": str(scan_id)},
                    )
                    or 0
                )
            if checkpoint_count == 0:
                break
            await asyncio.sleep(1)
        else:
            raise AssertionError("worker did not release cancelled checkpoint thread")

    print(
        f"outbox recovered; worker advanced {scan_id} to {status}; "
        "CANCELLED remained terminal"
    )


async def _cleanup(identity: ScenarioIdentity) -> None:
    async with AsyncSessionLocal() as db:
        project = await db.scalar(
            select(Project).where(Project.name == identity.project_name)
        )
        if project is not None:
            await ScanRepository(db).delete_project(project.id)

        await db.execute(delete(User).where(User.email == identity.email))
        await db.execute(
            delete(LLMConfiguration).where(LLMConfiguration.name == identity.llm_name)
        )
        await db.execute(
            delete(Framework).where(Framework.name == identity.framework_name)
        )
        await db.commit()

    print(f"removed isolated outbox fixture {identity.run_id}")


async def _run(phase: str, identity: ScenarioIdentity) -> None:
    try:
        if phase == "prepare":
            await _prepare(identity)
        elif phase == "submit":
            await _submit_while_broker_is_down(identity)
        elif phase == "assert-recovered":
            await _assert_recovered(identity)
        elif phase == "cleanup":
            await _cleanup(identity)
        else:
            raise ValueError(f"unknown phase: {phase}")
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "phase", choices=("prepare", "submit", "assert-recovered", "cleanup")
    )
    parser.add_argument("--run-id", required=True)
    args = parser.parse_args()
    asyncio.run(_run(args.phase, _identity(args.run_id)))


if __name__ == "__main__":
    main()
