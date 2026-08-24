"""Create, advance, and safely remove deterministic Playwright lifecycle data."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select, update

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    Finding,
    Framework,
    LLMConfiguration,
    Project,
    RoleAssignment,
    Scan,
    ScanArtifact,
    ScanAttempt,
    ScanEvent,
    User,
)
from app.infrastructure.database.repositories.approval_gate_repo import (
    ApprovalGateRepository,
)
from app.infrastructure.database.repositories.scan_artifact_repo import (
    ARTIFACT_TYPE_SCANNER_REPORTS,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.encryption import FernetEncrypt
from app.shared.lib.permissions import PLATFORM_OWNER
from app.shared.lib.scan_status import (
    STATUS_COMPLETED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED,
)

FIXTURE_LLM_PREFIX = "Browser lifecycle LLM user-"
FIXTURE_FRAMEWORK_PREFIX = "Browser lifecycle framework user-"


def _credentials() -> tuple[str, str]:
    email = os.environ["SCCAP_BROWSER_EMAIL"].strip().lower()
    password = os.environ["SCCAP_BROWSER_PASSWORD"]
    if not email.startswith("browser-") or not email.endswith("@example.com"):
        raise ValueError(
            "browser fixture email must match browser-*@example.com so cleanup cannot target a real account"
        )
    if len(password) < 16:
        raise ValueError("browser fixture password must be at least 16 characters")
    return email, password


async def _delete_fixture_user(db, user: User) -> None:
    llm_name = f"{FIXTURE_LLM_PREFIX}{user.id}"
    framework_name = f"{FIXTURE_FRAMEWORK_PREFIX}{user.id}"
    projects = list(
        (await db.scalars(select(Project).where(Project.user_id == user.id))).all()
    )
    for project in projects:
        await ScanRepository(db).delete_project(project.id)
    await db.execute(delete(LLMConfiguration).where(LLMConfiguration.name == llm_name))
    await db.execute(delete(Framework).where(Framework.name == framework_name))
    await db.delete(user)
    await db.commit()


async def _new_scan_with_attempt(
    db,
    *,
    project: Project,
    user: User,
    status: str,
    llm_config_id,
    summary=None,
    completed_at=None,
) -> tuple[Scan, ScanAttempt]:
    scan = Scan(
        project=project,
        user=user,
        scan_type="AUDIT",
        status=status,
        reasoning_llm_config_id=llm_config_id,
        utility_llm_config_id=llm_config_id,
        frameworks=[f"{FIXTURE_FRAMEWORK_PREFIX}{user.id}"],
        source_type="upload",
        summary=summary,
        completed_at=completed_at,
    )
    db.add(scan)
    await db.flush()
    attempt = ScanAttempt(
        scan_id=scan.id,
        sequence=1,
        trigger="initial",
        status="completed" if status == STATUS_COMPLETED else "active",
        actor_user_id=user.id,
        graph_thread_id=str(scan.id),
        completed_at=completed_at,
    )
    db.add(attempt)
    await db.flush()
    scan.current_attempt_id = attempt.id
    return scan, attempt


async def _setup() -> None:
    email, password = _credentials()
    async with AsyncSessionLocal() as db:
        stale = await db.scalar(select(User).where(User.email == email))
        if stale is not None:
            await _delete_fixture_user(db, stale)

        user = User(
            email=email,
            hashed_password=PasswordHelper().hash(password),
            is_active=True,
            is_superuser=True,
            is_verified=True,
        )
        db.add(user)
        await db.flush()
        db.add(
            RoleAssignment(
                user_id=user.id,
                tenant_id=None,
                role_key=PLATFORM_OWNER,
            )
        )

        llm = LLMConfiguration(
            name=f"{FIXTURE_LLM_PREFIX}{user.id}",
            provider="openai",
            model_name="browser-fixture-model",
            encrypted_api_key=FernetEncrypt.encrypt("ephemeral-browser-fixture-key"),
            input_cost_per_million=0,
            output_cost_per_million=0,
        )
        framework = Framework(
            name=f"{FIXTURE_FRAMEWORK_PREFIX}{user.id}",
            description="Disposable framework used only by the browser lifecycle suite.",
        )
        db.add_all([llm, framework])
        await db.flush()

        gate_project = Project(user=user, name=f"Browser gate {uuid4().hex[:10]}")
        replay_project = Project(user=user, name=f"Browser replay {uuid4().hex[:10]}")
        result_project = Project(user=user, name=f"Browser result {uuid4().hex[:10]}")
        db.add_all([gate_project, replay_project, result_project])
        await db.flush()

        profiling_cost = {
            "total_estimated_cost": 0.12,
            "upper_bound_estimated_cost": 0.25,
            "total_input_tokens": 1200,
            "upper_bound_input_tokens": 2400,
            "estimate_confidence": "high",
        }
        gate_scan, _ = await _new_scan_with_attempt(
            db,
            project=gate_project,
            user=user,
            status=STATUS_PENDING_PROFILING_APPROVAL,
            llm_config_id=llm.id,
        )
        gate_scan.cost_details = profiling_cost

        replay_scan, replay_attempt = await _new_scan_with_attempt(
            db,
            project=replay_project,
            user=user,
            status=STATUS_QUEUED,
            llm_config_id=llm.id,
        )
        first_event = ScanEvent(
            scan_id=replay_scan.id,
            attempt_id=replay_attempt.id,
            schema_version=1,
            activity_kind="workflow",
            stage_name="BROWSER_BOOTSTRAP",
            status="COMPLETED",
            details={"elapsed_ms": 12},
        )
        second_event = ScanEvent(
            scan_id=replay_scan.id,
            attempt_id=replay_attempt.id,
            schema_version=1,
            activity_kind="scanner",
            stage_name="BROWSER_SCANNER",
            status="COMPLETED",
            details={"scanner": "fixture", "elapsed_ms": 23},
        )
        db.add_all([first_event, second_event])

        completed_at = datetime.now(timezone.utc)
        result_scan, result_attempt = await _new_scan_with_attempt(
            db,
            project=result_project,
            user=user,
            status=STATUS_COMPLETED,
            llm_config_id=llm.id,
            completed_at=completed_at,
            summary={
                "summary": {
                    "total_findings_count": 1,
                    "files_analyzed_count": 1,
                    "severity_counts": {"HIGH": 1},
                },
                "overall_risk_score": {"score": 8.8, "severity": "High"},
            },
        )
        result_scan.repository_map = {
            "files": {"src/browser_fixture.py": {"errors": [], "language": "python"}}
        }
        finding = Finding(
            scan_id=result_scan.id,
            file_path="src/browser_fixture.py",
            line_number=7,
            vulnerable_snippet='cursor.execute("SELECT " + user_input)',
            title="Browser fixture SQL injection",
            description="User-controlled input reaches a SQL query.",
            severity="High",
            remediation="Use a parameterized query.",
            cwe="CWE-89",
            confidence="High",
            source="semgrep",
            cvss_score=8.8,
            references=["https://cwe.mitre.org/data/definitions/89.html"],
            finding_bucket="consolidated",
        )
        scanner_payload = {
            "schema_version": 1,
            "scan_id": str(result_scan.id),
            "reports": {
                "semgrep": {"version": "browser-fixture", "results": []},
                "bandit": {"results": []},
                "gitleaks": [],
                "osv": {"results": []},
            },
            "scanner_statuses": {
                "semgrep": "completed",
                "bandit": "completed",
                "gitleaks": "completed",
                "osv": "completed",
            },
            "toolchain_provenance": {
                "semgrep": {
                    "status": "verified",
                    "immutable": True,
                    "reasons": [],
                    "binary": {"version": "browser-fixture", "sha256": "a" * 64},
                    "rules": {
                        "status": "verified",
                        "selected_rule_count": 1,
                        "ruleset_sha256": "b" * 64,
                        "rules": [
                            {
                                "id": "browser.python.sql-injection",
                                "content_sha256": "c" * 64,
                            }
                        ],
                    },
                }
            },
        }
        artifact = ScanArtifact(
            scan_id=result_scan.id,
            attempt_id=result_attempt.id,
            artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
            version=1,
            payload=scanner_payload,
        )
        db.add_all([finding, artifact])
        await db.commit()

        gate = await ApprovalGateRepository(db).create_or_get_pending(
            scan_id=gate_scan.id,
            kind="profiling_approval",
            node_name="profiling_cost_gate",
            display_name="Approve file profiling cost",
            purpose="Approve utility-model profiling before full analysis.",
            evidence={"stage": "file_profiling", "cost_details": profiling_cost},
        )

        print(
            json.dumps(
                {
                    "llm_config_id": str(llm.id),
                    "framework_name": framework.name,
                    "gate_scan_id": str(gate_scan.id),
                    "gate_id": str(gate.gate_id),
                    "replay_scan_id": str(replay_scan.id),
                    "replay_attempt_id": str(replay_attempt.id),
                    "first_event_id": first_event.id,
                    "second_event_id": second_event.id,
                    "result_project_id": str(result_project.id),
                    "result_scan_id": str(result_scan.id),
                },
                sort_keys=True,
            )
        )


async def _advance(scan_id: UUID) -> None:
    async with AsyncSessionLocal() as db:
        scan = await db.get(Scan, scan_id)
        if scan is None:
            raise SystemExit(f"scan not found: {scan_id}")
        gates = ApprovalGateRepository(db)
        await gates.close_active(scan_id, state="completed", commit=False)
        cost_details = {
            "total_estimated_cost": 1.75,
            "upper_bound_estimated_cost": 3.5,
            "total_input_tokens": 18000,
            "predicted_output_tokens": 4000,
            "upper_bound_input_tokens": 36000,
            "estimate_confidence": "medium",
            "planned_request_count": 4,
        }
        await db.execute(
            update(Scan)
            .where(Scan.id == scan_id)
            .values(status=STATUS_PENDING_APPROVAL, cost_details=cost_details)
        )
        gate = await gates.create_or_get_pending(
            scan_id=scan_id,
            kind="cost_approval",
            node_name="cost_gate",
            display_name="Approve full security analysis cost",
            purpose="Approve the full multi-agent security-analysis estimate.",
            evidence={"stage": "analysis", "cost_details": cost_details},
            commit=False,
        )
        await db.commit()
        print(json.dumps({"gate_id": str(gate.gate_id), "sequence": gate.sequence}))


async def _cleanup() -> None:
    email, _ = _credentials()
    async with AsyncSessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == email))
        if user is not None:
            await _delete_fixture_user(db, user)
    print(json.dumps({"cleaned": True}))


async def _main(action: str, scan_id: UUID | None) -> None:
    try:
        if action == "setup":
            await _setup()
        elif action == "advance":
            if scan_id is None:
                raise SystemExit("advance requires a scan id")
            await _advance(scan_id)
        else:
            await _cleanup()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("setup", "advance", "cleanup"))
    parser.add_argument("scan_id", nargs="?", type=UUID)
    args = parser.parse_args()
    asyncio.run(_main(args.action, args.scan_id))
