"""Disposable real-API fixture for approval-gate browser acceptance checks."""

from __future__ import annotations

import argparse
import asyncio
import json
from uuid import UUID, uuid4

from fastapi_users.password import PasswordHelper
from sqlalchemy import select, update

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import Project, Scan, User
from app.infrastructure.database.repositories.approval_gate_repo import (
    ApprovalGateRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import (
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
)


async def create_fixture() -> None:
    suffix = uuid4().hex[:10]
    email = f"browser-gate-{suffix}@example.com"
    password = f"V7!browser-{suffix}-Z"
    async with AsyncSessionLocal() as db:
        user = User(
            email=email,
            hashed_password=PasswordHelper().hash(password),
            is_active=True,
            is_superuser=False,
            is_verified=True,
        )
        project = Project(user=user, name=f"Browser gate fixture {suffix}")
        cost_details = {
            "total_estimated_cost": 0.12,
            "upper_bound_estimated_cost": 0.25,
            "total_input_tokens": 1200,
            "upper_bound_input_tokens": 2400,
            "estimate_confidence": "high",
        }
        scan = Scan(
            project=project,
            user=user,
            scan_type="AUDIT",
            status=STATUS_PENDING_PROFILING_APPROVAL,
            frameworks=[],
            cost_details=cost_details,
        )
        db.add_all([user, project, scan])
        await db.commit()
        gate = await ApprovalGateRepository(db).create_or_get_pending(
            scan_id=scan.id,
            kind="profiling_approval",
            node_name="profiling_cost_gate",
            display_name="Approve file profiling cost",
            purpose="Approve utility-model profiling before full analysis.",
            evidence={"stage": "file_profiling", "cost_details": cost_details},
        )
        print(
            json.dumps(
                {
                    "email": email,
                    "password": password,
                    "scan_id": str(scan.id),
                    "gate_id": str(gate.gate_id),
                }
            )
        )


async def advance_fixture(scan_id: UUID) -> None:
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
            "upper_bound_input_tokens": 36000,
            "estimate_confidence": "medium",
            "requires_dual_approval": True,
            "dual_approval_enforced": False,
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


async def cleanup_fixture(email: str) -> None:
    async with AsyncSessionLocal() as db:
        user = await db.scalar(select(User).where(User.email == email))
        if user is not None:
            projects = list(
                (
                    await db.scalars(select(Project).where(Project.user_id == user.id))
                ).all()
            )
            for project in projects:
                await ScanRepository(db).delete_project(project.id)
            await db.delete(user)
            await db.commit()


async def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("create")
    advance = subparsers.add_parser("advance")
    advance.add_argument("scan_id", type=UUID)
    cleanup = subparsers.add_parser("cleanup")
    cleanup.add_argument("email")
    args = parser.parse_args()
    try:
        if args.command == "create":
            await create_fixture()
        elif args.command == "advance":
            await advance_fixture(args.scan_id)
        else:
            await cleanup_fixture(args.email)
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(main())
