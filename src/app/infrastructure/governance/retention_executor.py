"""Operator-executable vector, observability, log, and backup retention."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import httpx
from qdrant_client import models as qmodels
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.governance.adapters import GovernanceArtifactSink, MAX_RECORDS
from app.infrastructure.governance.contracts import (
    RetentionActionResult,
    canonical_json,
)
from app.infrastructure.governance.models import (
    GovernanceLegalHold,
    TenantRetentionPolicy,
)
from app.infrastructure.governance.retention import DEFAULT_RETENTION_POLICY
from app.infrastructure.signing import DigestSigner


class RetentionExecutor:
    """Run bounded destructive retention while serialized with legal holds."""

    def __init__(
        self,
        db: AsyncSession,
        *,
        qdrant_client: Any,
        observability_url: str,
        observability_token: str,
        backup_root: Path,
        sink: GovernanceArtifactSink,
        signer: DigestSigner,
        http_client: httpx.AsyncClient,
    ) -> None:
        self.db = db
        self.qdrant = qdrant_client
        self.observability_url = observability_url.rstrip("/")
        self.observability_token = observability_token
        self.backup_root = backup_root.resolve()
        if self.backup_root in {Path("/"), Path.home().resolve()}:
            raise ValueError("Backup retention root must be a dedicated subdirectory.")
        self.sink = sink
        self.signer = signer
        self.http = http_client

    async def execute(
        self, tenant_id: uuid.UUID, *, operation_id: uuid.UUID
    ) -> dict[str, Any]:
        await self.db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"governance-delete-barrier:{tenant_id}"},
        )
        holds = list(
            (
                await self.db.scalars(
                    select(GovernanceLegalHold).where(
                        GovernanceLegalHold.tenant_id == tenant_id,
                        GovernanceLegalHold.released_at.is_(None),
                    )
                )
            ).all()
        )
        days = await self._effective_days(tenant_id)
        now = datetime.now(timezone.utc)
        vector = await self._retain_vectors(
            operation_id, tenant_id, now - timedelta(days=days["vector"]), holds
        )
        observability = await self._retain_observability(
            operation_id,
            tenant_id,
            logs_cutoff=now - timedelta(days=days["logs"]),
            holds=holds,
        )
        backups = await asyncio.to_thread(
            self._retain_backups,
            operation_id,
            tenant_id,
            now - timedelta(days=days["backups"]),
            holds,
        )
        report = {
            "schema_version": 1,
            "artifact_kind": "retention_enforcement_evidence",
            "operation_id": str(operation_id),
            "tenant_id": str(tenant_id),
            "effective_days": days,
            "legal_hold_count": len(holds),
            "stores": [vector, observability, backups],
            "completed_at": now.isoformat(),
        }
        digest = hashlib.sha256(canonical_json(report)).digest()
        signature = await self.signer.sign_sha256(digest)
        signed = {
            "report": report,
            "report_sha256": digest.hex(),
            "signature": {
                "signature_b64": signature.signature_b64,
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
            },
        }
        self.sink.write(operation_id, "retention", canonical_json(signed))
        await self.db.commit()
        return signed

    async def _effective_days(self, tenant_id: uuid.UUID) -> dict[str, int]:
        effective = {
            "vector": DEFAULT_RETENTION_POLICY.vector_days,
            "logs": DEFAULT_RETENTION_POLICY.logs_days,
            "backups": DEFAULT_RETENTION_POLICY.backups_days,
        }
        policies = list(
            (
                await self.db.scalars(
                    select(TenantRetentionPolicy).where(
                        TenantRetentionPolicy.tenant_id == tenant_id,
                        TenantRetentionPolicy.data_class.in_(effective),
                    )
                )
            ).all()
        )
        for policy in policies:
            effective[policy.data_class] = policy.retention_days
        return effective

    @staticmethod
    def _point_is_held(point: Any, tenant_id: uuid.UUID, holds: list[Any]) -> bool:
        payload = point.payload or {}
        scopes = {("tenant", str(tenant_id))}
        for name in ("project", "scan", "attempt", "evidence"):
            if payload.get(f"{name}_id") is not None:
                scopes.add((name, str(payload[f"{name}_id"])))
        return any((hold.scope_type, hold.scope_id) in scopes for hold in holds)

    async def _retain_vectors(self, operation_id, tenant_id, cutoff, holds):
        plan_bytes = self.sink.read(operation_id, "retention-qdrant-plan")
        if plan_bytes is None:
            matched: list[tuple[str, Any]] = []
            collections = await asyncio.to_thread(self.qdrant.get_collections)
            for collection in collections.collections:
                offset = None
                while True:
                    points, offset = await asyncio.to_thread(
                        self.qdrant.scroll,
                        collection_name=collection.name,
                        scroll_filter=qmodels.Filter(
                            must=[
                                qmodels.FieldCondition(
                                    key="tenant_id",
                                    match=qmodels.MatchValue(value=str(tenant_id)),
                                ),
                                qmodels.FieldCondition(
                                    key="created_at",
                                    range=qmodels.DatetimeRange(lt=cutoff),
                                ),
                            ]
                        ),
                        limit=1000,
                        offset=offset,
                        with_payload=True,
                        with_vectors=False,
                    )
                    matched.extend((collection.name, point) for point in points)
                    if len(matched) > MAX_RECORDS:
                        raise RuntimeError("retention_scope_requires_chunking")
                    if offset is None:
                        break
            eligible = [
                item
                for item in matched
                if not self._point_is_held(item[1], tenant_id, holds)
            ]
            plan_bytes = canonical_json(
                {
                    "schema_version": 1,
                    "tenant_id": str(tenant_id),
                    "cutoff": cutoff.isoformat(),
                    "matched_count": len(matched),
                    "eligible": [
                        {
                            "collection": collection,
                            "id": point.id,
                            "scopes": {
                                name: str((point.payload or {}).get(f"{name}_id"))
                                for name in ("project", "scan", "attempt", "evidence")
                                if (point.payload or {}).get(f"{name}_id") is not None
                            },
                        }
                        for collection, point in eligible
                    ],
                }
            )
            self.sink.write(operation_id, "retention-qdrant-plan", plan_bytes)
        plan = json.loads(plan_bytes)
        if plan["tenant_id"] != str(tenant_id):
            raise ValueError("retention_qdrant_plan_tenant_mismatch")
        active_holds = {(hold.scope_type, hold.scope_id) for hold in holds}
        eligible_now = [
            item
            for item in plan["eligible"]
            if ("tenant", str(tenant_id)) not in active_holds
            and not any(
                (name, value) in active_holds for name, value in item["scopes"].items()
            )
        ]
        grouped: dict[str, list[Any]] = {}
        for item in eligible_now:
            grouped.setdefault(item["collection"], []).append(item["id"])
        for collection, ids in grouped.items():
            await asyncio.to_thread(
                self.qdrant.delete,
                collection_name=collection,
                points_selector=qmodels.PointIdsList(points=ids),
                wait=True,
            )
        return RetentionActionResult(
            store="qdrant",
            kind="delete",
            operation_id=operation_id,
            matched_count=plan["matched_count"],
            applied_count=len(eligible_now),
            content_sha256=hashlib.sha256(plan_bytes).hexdigest(),
            artifact_ref=f"qdrant-retention:{operation_id}",
        ).model_dump(mode="json")

    async def _retain_observability(
        self, operation_id, tenant_id, *, logs_cutoff, holds
    ):
        response = await self.http.post(
            f"{self.observability_url}/v1/governance/retention/{operation_id}",
            headers={
                "Authorization": f"Bearer {self.observability_token}",
                "Idempotency-Key": str(operation_id),
            },
            json={
                "tenant_id": str(tenant_id),
                "logs_cutoff": logs_cutoff.isoformat(),
                "legal_holds": [
                    {"scope_type": hold.scope_type, "scope_id": hold.scope_id}
                    for hold in holds
                ],
            },
        )
        response.raise_for_status()
        result = RetentionActionResult.model_validate_json(response.content)
        if result.store != "observability" or result.operation_id != operation_id:
            raise ValueError("observability_retention_identity_mismatch")
        return result.model_dump(mode="json")

    def _retain_backups(self, operation_id, tenant_id, cutoff, holds):
        tenant_root = (self.backup_root / str(tenant_id)).resolve()
        if tenant_root.parent != self.backup_root:
            raise ValueError("backup tenant root escapes configured root")
        plan_bytes = self.sink.read(operation_id, "retention-backup-plan")
        if plan_bytes is None:
            if not tenant_root.exists():
                candidates: list[Path] = []
            else:
                candidates = [
                    path
                    for path in tenant_root.rglob("*")
                    if path.is_file()
                    and datetime.fromtimestamp(path.stat().st_mtime, timezone.utc)
                    < cutoff
                ]
            if len(candidates) > MAX_RECORDS:
                raise RuntimeError("backup_retention_scope_requires_chunking")
            plan_bytes = canonical_json(
                {
                    "schema_version": 1,
                    "tenant_id": str(tenant_id),
                    "cutoff": cutoff.isoformat(),
                    "matched_count": len(candidates),
                    "eligible": (
                        [str(path.relative_to(tenant_root)) for path in candidates]
                        if not holds
                        else []
                    ),
                }
            )
            self.sink.write(operation_id, "retention-backup-plan", plan_bytes)
        plan = json.loads(plan_bytes)
        if plan["tenant_id"] != str(tenant_id):
            raise ValueError("retention_backup_plan_tenant_mismatch")
        eligible_now = [] if holds else plan["eligible"]
        for relative in eligible_now:
            path = (tenant_root / relative).resolve()
            if not path.is_relative_to(tenant_root):
                raise ValueError("backup retention plan escapes tenant root")
            if path.is_file():
                path.unlink()
        return RetentionActionResult(
            store="backups",
            operation_id=operation_id,
            matched_count=plan["matched_count"],
            applied_count=len(eligible_now),
            content_sha256=hashlib.sha256(plan_bytes).hexdigest(),
            artifact_ref=f"backup-retention:{operation_id}",
        ).model_dump(mode="json")
