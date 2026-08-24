"""Prepare or crash-resume Task22 export/deletion operations."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import uuid

from sqlalchemy import select

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.tenant_context import principal_scope
from app.infrastructure.governance.models import GovernanceOperation
from app.infrastructure.governance.runner import governance_service
from app.infrastructure.governance.service import GovernanceService


async def _run(args: argparse.Namespace) -> int:
    with principal_scope(
        tenant_id=args.tenant_id,
        principal_kind="system",
        principal_id="governance-operation-runner",
        system_scope=True,
    ):
        async with AsyncSessionLocal() as db:
            if args.command in {"place-hold", "release-hold", "set-retention"}:
                service = GovernanceService(db, signer=None, adapters=None)
                return await _run_control(args, service)
            async with governance_service(db) as service:
                return await _run_operation(args, db, service)


async def _run_control(args: argparse.Namespace, service: GovernanceService) -> int:
    if args.command == "place-hold":
        hold = await service.place_legal_hold(
            tenant_id=args.tenant_id,
            scope_type=args.scope_type,
            scope_id=str(args.scope_id),
            actor_user_id=args.actor_user_id,
            reason=args.reason,
        )
        print(json.dumps({"hold_id": str(hold.id), "status": "active"}))
        return 0
    if args.command == "release-hold":
        hold = await service.release_legal_hold(
            hold_id=args.hold_id,
            tenant_id=args.tenant_id,
            actor_user_id=args.actor_user_id,
            reason=args.reason,
        )
        print(json.dumps({"hold_id": str(hold.id), "status": "released"}))
        return 0
    if args.command == "set-retention":
        policy = await service.set_tenant_retention_policy(
            tenant_id=args.tenant_id,
            data_class=args.data_class,
            retention_days=args.days,
            actor_user_id=args.actor_user_id,
            reason=args.reason,
        )
        print(
            json.dumps(
                {
                    "policy_id": str(policy.id),
                    "data_class": policy.data_class,
                    "days": policy.retention_days,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0


async def _run_operation(args, db, service) -> int:
    if args.command == "prepare":
        idempotency_key = (
            args.idempotency_key
            or hashlib.sha256(
                (
                    f"{args.tenant_id}:{args.kind}:{args.scope_type}:"
                    f"{args.scope_id}:{args.actor_user_id}:{args.reason}"
                ).encode()
            ).hexdigest()
        )
        operation = await service.prepare_operation(
            tenant_id=args.tenant_id,
            kind=args.kind,
            scope_type=args.scope_type,
            scope_id=str(args.scope_id),
            idempotency_key=idempotency_key,
            actor_user_id=args.actor_user_id,
            reason=args.reason,
        )
        if args.execute:
            operation = await service.execute(
                operation.id, expected_tenant_id=args.tenant_id
            )
        _print(operation)
        return 0 if operation.status not in {"failed", "blocked_legal_hold"} else 2
    if args.command == "execute":
        operation = await service.execute(
            args.operation_id, expected_tenant_id=args.tenant_id
        )
        _print(operation)
        return 0 if operation.status == "completed" else 2

    operations = list(
        (
            await db.scalars(
                select(GovernanceOperation)
                .where(
                    GovernanceOperation.tenant_id == args.tenant_id,
                    GovernanceOperation.status.in_(["prepared", "executing", "failed"]),
                )
                .order_by(GovernanceOperation.created_at)
                .limit(args.limit)
            )
        ).all()
    )
    failures = 0
    for operation in operations:
        operation = await service.execute(
            operation.id, expected_tenant_id=args.tenant_id
        )
        _print(operation)
        failures += operation.status != "completed"
    return 2 if failures else 0


def _print(operation: GovernanceOperation) -> None:
    print(
        json.dumps(
            {
                "operation_id": str(operation.id),
                "tenant_id": str(operation.tenant_id),
                "kind": operation.kind,
                "status": operation.status,
                "manifest_sha256": operation.manifest_sha256,
                "failure_code": operation.failure_code,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", type=uuid.UUID, required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--kind", choices=("export", "delete"), required=True)
    prepare.add_argument(
        "--scope-type",
        choices=("tenant", "project", "scan", "attempt", "evidence"),
        required=True,
    )
    prepare.add_argument("--scope-id", type=uuid.UUID, required=True)
    prepare.add_argument("--actor-user-id", type=int, required=True)
    prepare.add_argument("--reason", required=True)
    prepare.add_argument("--idempotency-key")
    prepare.add_argument("--execute", action="store_true")

    execute = subparsers.add_parser("execute")
    execute.add_argument("--operation-id", type=uuid.UUID, required=True)

    pending = subparsers.add_parser("run-pending")
    pending.add_argument("--limit", type=int, default=50)
    place_hold = subparsers.add_parser("place-hold")
    place_hold.add_argument(
        "--scope-type",
        choices=("tenant", "project", "scan", "attempt", "evidence"),
        required=True,
    )
    place_hold.add_argument("--scope-id", type=uuid.UUID, required=True)
    place_hold.add_argument("--actor-user-id", type=int, required=True)
    place_hold.add_argument("--reason", required=True)
    release_hold = subparsers.add_parser("release-hold")
    release_hold.add_argument("--hold-id", type=uuid.UUID, required=True)
    release_hold.add_argument("--actor-user-id", type=int, required=True)
    release_hold.add_argument("--reason", required=True)
    retention = subparsers.add_parser("set-retention")
    retention.add_argument(
        "--data-class",
        choices=(
            "transactional",
            "audit",
            "evidence",
            "llm",
            "vector",
            "logs",
            "backups",
        ),
        required=True,
    )
    retention.add_argument("--days", type=int, required=True)
    retention.add_argument("--actor-user-id", type=int, required=True)
    retention.add_argument("--reason", required=True)
    args = parser.parse_args()
    if args.command == "prepare" and args.idempotency_key:
        if len(args.idempotency_key) != 64:
            parser.error("--idempotency-key must be a SHA-256 hex digest")
        try:
            int(args.idempotency_key, 16)
        except ValueError:
            parser.error("--idempotency-key must be hexadecimal")
    if args.command == "run-pending" and not 1 <= args.limit <= 1000:
        parser.error("--limit must be between 1 and 1000")
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
