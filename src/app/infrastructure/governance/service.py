"""Durable two-phase export/deletion orchestration across every evidence store."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping, Protocol

from sqlalchemy import or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.governance.models import (
    GovernanceLegalHold,
    GovernanceOperation,
    GovernanceStoreAction,
    TenantRetentionPolicy,
)
from app.infrastructure.governance.contracts import StoreActionResult, canonical_json
from app.infrastructure.governance.retention import (
    DATA_CLASSES,
    DEFAULT_RETENTION_POLICY,
    RetentionPolicy,
    validate_tenant_override,
)
from app.infrastructure.signing import DigestSigner

STORES = ("postgres", "object", "qdrant", "observability")
DELETE_STORE_ORDER = ("qdrant", "observability", "object", "postgres")
LEASE_SECONDS = 300
MAX_ATTEMPTS = 8
MAX_STORE_RESULT_BYTES = 256 * 1024


class GovernanceStoreAdapter(Protocol):
    """Idempotent external-store contract used by the durable coordinator."""

    store: str

    async def apply(
        self,
        *,
        operation_id: uuid.UUID,
        kind: str,
        tenant_id: uuid.UUID,
        scope: Mapping[str, str],
    ) -> Mapping[str, Any]:
        """Export/delete the scope and return bounded, non-secret evidence."""

    async def verify(
        self,
        *,
        operation_id: uuid.UUID,
        kind: str,
        tenant_id: uuid.UUID,
        scope: Mapping[str, str],
        result: Mapping[str, Any],
    ) -> bool:
        """Independently confirm the applied result."""


def normalize_scope(
    scope_type: str, scope_id: str, tenant_id: uuid.UUID
) -> dict[str, str]:
    if scope_type not in {"tenant", "project", "scan", "attempt", "evidence"}:
        raise ValueError("Unsupported governance scope.")
    canonical_scope_id = str(uuid.UUID(scope_id))
    if scope_type == "tenant":
        if uuid.UUID(canonical_scope_id) != tenant_id:
            raise ValueError("Tenant scope must equal the selected tenant.")
    return {"scope_type": scope_type, "scope_id": canonical_scope_id}


class GovernanceService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        signer: DigestSigner | None,
        adapters: Mapping[str, GovernanceStoreAdapter] | None,
        retention: RetentionPolicy = DEFAULT_RETENTION_POLICY,
    ) -> None:
        if adapters is not None:
            if set(adapters) != set(STORES):
                raise ValueError("All four governance store adapters are required.")
            if any(name != adapter.store for name, adapter in adapters.items()):
                raise ValueError("Governance adapter names do not match their store.")
        self.db = db
        self.signer = signer
        self.adapters = dict(adapters or {})
        self.retention = retention

    async def place_legal_hold(
        self,
        *,
        tenant_id: uuid.UUID,
        scope_type: str,
        scope_id: str,
        actor_user_id: int,
        reason: str,
    ) -> GovernanceLegalHold:
        scope = normalize_scope(scope_type, scope_id, tenant_id)
        await self._scope_ancestors(tenant_id, scope)
        if not reason.strip():
            raise ValueError("Legal hold reason is required.")
        # The same transaction-scoped barrier is held by destructive store
        # actions. A hold therefore either wins before external deletion, or
        # waits until that bounded action is durably recorded.
        await self._acquire_tenant_barrier(tenant_id)
        existing = await self.db.scalar(
            select(GovernanceLegalHold).where(
                GovernanceLegalHold.tenant_id == tenant_id,
                GovernanceLegalHold.scope_type == scope["scope_type"],
                GovernanceLegalHold.scope_id == scope["scope_id"],
                GovernanceLegalHold.released_at.is_(None),
            )
        )
        if existing is not None:
            await self._synchronize_evidence_hold_flags(tenant_id)
            await self.db.commit()
            return existing
        hold = GovernanceLegalHold(
            tenant_id=tenant_id,
            scope_type=scope["scope_type"],
            scope_id=scope["scope_id"],
            reason=reason.strip(),
            placed_by_user_id=actor_user_id,
        )
        self.db.add(hold)
        await self.db.flush()
        await self._synchronize_evidence_hold_flags(tenant_id)
        await self.db.commit()
        await self.db.refresh(hold)
        return hold

    async def release_legal_hold(
        self,
        *,
        hold_id: uuid.UUID,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        reason: str,
    ) -> GovernanceLegalHold:
        if not reason.strip():
            raise ValueError("Legal hold release reason is required.")
        hold = await self.db.scalar(
            select(GovernanceLegalHold)
            .where(
                GovernanceLegalHold.id == hold_id,
                GovernanceLegalHold.tenant_id == tenant_id,
            )
            .with_for_update()
        )
        if hold is None:
            raise LookupError("Legal hold not found.")
        if hold.released_at is None:
            hold.released_at = datetime.now(timezone.utc)
            hold.released_by_user_id = actor_user_id
            hold.release_reason = reason.strip()
            await self.db.flush()
            await self._synchronize_evidence_hold_flags(tenant_id)
            await self.db.commit()
            await self.db.refresh(hold)
        return hold

    async def set_tenant_retention_policy(
        self,
        *,
        tenant_id: uuid.UUID,
        data_class: str,
        retention_days: int,
        actor_user_id: int,
        reason: str,
    ) -> TenantRetentionPolicy:
        validate_tenant_override(data_class, retention_days)
        if not reason.strip():
            raise ValueError("Retention override reason is required.")
        await self._acquire_tenant_barrier(tenant_id)
        policy = await self.db.scalar(
            select(TenantRetentionPolicy)
            .where(
                TenantRetentionPolicy.tenant_id == tenant_id,
                TenantRetentionPolicy.data_class == data_class,
            )
            .with_for_update()
        )
        if policy is None:
            policy = TenantRetentionPolicy(
                tenant_id=tenant_id,
                data_class=data_class,
                retention_days=retention_days,
                updated_by_user_id=actor_user_id,
                reason=reason.strip(),
            )
            self.db.add(policy)
        else:
            policy.retention_days = retention_days
            policy.updated_by_user_id = actor_user_id
            policy.reason = reason.strip()
        await self.db.flush()
        await self._materialize_retention_override(
            tenant_id=tenant_id,
            data_class=data_class,
            retention_days=retention_days,
        )
        await self.db.commit()
        await self.db.refresh(policy)
        return policy

    async def _materialize_retention_override(
        self, *, tenant_id: uuid.UUID, data_class: str, retention_days: int
    ) -> None:
        """Project policy changes onto rows whose sweepers consume explicit expiry."""
        if data_class == "evidence":
            await self.db.execute(
                text(
                    "UPDATE evidence_objects SET retain_until = created_at + "
                    "make_interval(days => :days), retention_policy = :policy "
                    "WHERE tenant_id = :tenant_id AND state <> 'deleted'"
                ),
                {
                    "days": retention_days,
                    "policy": f"tenant-effective-{retention_days}d-v1",
                    "tenant_id": tenant_id,
                },
            )
        elif data_class == "llm":
            await self.db.execute(
                text(
                    "UPDATE llm_interactions li SET expires_at = li.timestamp + "
                    "make_interval(days => :days) WHERE EXISTS ("
                    "SELECT 1 FROM scans s WHERE s.id = li.scan_id "
                    "AND s.tenant_id = :tenant_id) OR EXISTS ("
                    "SELECT 1 FROM chat_messages cm JOIN chat_sessions cs "
                    "ON cs.id = cm.session_id WHERE cm.id = li.chat_message_id "
                    "AND cs.tenant_id = :tenant_id)"
                ),
                {"days": retention_days, "tenant_id": tenant_id},
            )

    async def prepare_operation(
        self,
        *,
        tenant_id: uuid.UUID,
        kind: str,
        scope_type: str,
        scope_id: str,
        idempotency_key: str,
        actor_user_id: int,
        reason: str,
    ) -> GovernanceOperation:
        if kind not in {"export", "delete"}:
            raise ValueError("Governance operation must be export or delete.")
        if len(idempotency_key) != 64:
            raise ValueError("Idempotency key must be a SHA-256 hex digest.")
        int(idempotency_key, 16)
        if idempotency_key != idempotency_key.lower():
            raise ValueError("Idempotency key must use lowercase hexadecimal.")
        if not reason.strip():
            raise ValueError("Governance reason is required.")
        scope = normalize_scope(scope_type, scope_id, tenant_id)
        # Positive ownership is required for exports as well as deletion. RLS
        # remains the final boundary, not a substitute for scope validation.
        await self._scope_ancestors(tenant_id, scope)
        policy_snapshot = await self._effective_retention_snapshot(tenant_id)
        await self.db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"governance-idempotency:{tenant_id}:{idempotency_key}"},
        )
        existing = await self.db.scalar(
            select(GovernanceOperation).where(
                GovernanceOperation.tenant_id == tenant_id,
                GovernanceOperation.idempotency_key == idempotency_key,
            )
        )
        if existing is not None:
            expected = {
                "kind": kind,
                "scope": scope,
                "actor": actor_user_id,
                "policy": policy_snapshot,
                "reason": reason.strip(),
            }
            observed = {
                "kind": existing.kind,
                "scope": existing.scope,
                "actor": existing.requested_by_user_id,
                "policy": existing.policy_snapshot,
                "reason": existing.reason,
            }
            if observed != expected:
                await self.db.rollback()
                raise ValueError(
                    "Idempotency key was already used for another request."
                )
            await self.db.commit()
            return existing
        held = kind == "delete" and await self._scope_is_held(tenant_id, scope)
        operation = GovernanceOperation(
            tenant_id=tenant_id,
            kind=kind,
            status="blocked_legal_hold" if held else "prepared",
            idempotency_key=idempotency_key,
            scope=scope,
            policy_snapshot=policy_snapshot,
            requested_by_user_id=actor_user_id,
            reason=reason.strip(),
            failure_code="active_legal_hold" if held else None,
        )
        self.db.add(operation)
        await self.db.flush()
        for store in STORES:
            self.db.add(
                GovernanceStoreAction(
                    operation_id=operation.id,
                    tenant_id=tenant_id,
                    store=store,
                    status="pending",
                )
            )
        await self.db.commit()
        await self.db.refresh(operation)
        return operation

    async def _effective_retention_snapshot(
        self, tenant_id: uuid.UUID
    ) -> dict[str, int | str]:
        snapshot = self.retention.snapshot()
        policies = list(
            (
                await self.db.scalars(
                    select(TenantRetentionPolicy).where(
                        TenantRetentionPolicy.tenant_id == tenant_id
                    )
                )
            ).all()
        )
        applied: dict[str, int] = {}
        for policy in policies:
            field = DATA_CLASSES.get(policy.data_class)
            if field is None:
                raise ValueError(
                    "Persisted retention policy has an unknown data class."
                )
            validate_tenant_override(policy.data_class, policy.retention_days)
            snapshot[field] = policy.retention_days
            applied[policy.data_class] = policy.retention_days
        snapshot["tenant_overrides"] = applied
        return snapshot

    async def execute(
        self,
        operation_id: uuid.UUID,
        *,
        expected_tenant_id: uuid.UUID | None = None,
    ) -> GovernanceOperation:
        if self.signer is None or set(self.adapters) != set(STORES):
            raise RuntimeError(
                "Governance execution requires signer and all store adapters."
            )
        operation = await self.db.scalar(
            select(GovernanceOperation)
            .where(GovernanceOperation.id == operation_id)
            .with_for_update()
        )
        if operation is None:
            raise LookupError("Governance operation not found.")
        if expected_tenant_id is not None and operation.tenant_id != expected_tenant_id:
            raise LookupError("Governance operation not found for selected tenant.")
        if operation.status == "completed":
            await self.db.commit()
            return operation
        if operation.kind == "delete":
            if await self._scope_is_held(operation.tenant_id, operation.scope):
                operation.status = "blocked_legal_hold"
                operation.failure_code = "active_legal_hold"
                await self.db.commit()
                return operation
            if operation.status == "blocked_legal_hold":
                operation.status = "prepared"
                operation.failure_code = None
        operation.status = "executing"
        operation.started_at = operation.started_at or datetime.now(timezone.utc)
        await self.db.commit()

        actions = list(
            (
                await self.db.scalars(
                    select(GovernanceStoreAction).where(
                        GovernanceStoreAction.operation_id == operation.id
                    )
                )
            ).all()
        )
        store_order = DELETE_STORE_ORDER if operation.kind == "delete" else STORES
        actions.sort(key=lambda action: store_order.index(action.store))
        for action in actions:
            if action.status == "verified":
                continue
            if operation.kind == "delete" and await self._scope_is_held(
                operation.tenant_id, operation.scope
            ):
                operation.status = "blocked_legal_hold"
                operation.failure_code = "active_legal_hold"
                await self.db.commit()
                return operation
            await self._execute_action(operation, action)

        operation = await self.db.scalar(
            select(GovernanceOperation)
            .where(GovernanceOperation.id == operation.id)
            .with_for_update()
        )
        if operation is None:
            raise LookupError("Governance operation disappeared during execution.")
        if operation.status == "completed":
            await self.db.commit()
            return operation
        actions = list(
            (
                await self.db.scalars(
                    select(GovernanceStoreAction)
                    .where(GovernanceStoreAction.operation_id == operation.id)
                    .order_by(GovernanceStoreAction.store)
                )
            ).all()
        )
        if any(action.status != "verified" for action in actions):
            await self.db.commit()
            return operation
        manifest = {
            "schema_version": 1,
            "artifact_kind": (
                "evidence_export_manifest"
                if operation.kind == "export"
                else "evidence_deletion_tombstone"
            ),
            "operation_id": str(operation.id),
            "tenant_id": str(operation.tenant_id),
            "scope": operation.scope,
            "policy": operation.policy_snapshot,
            "stores": [
                {
                    "store": action.store,
                    "result": action.result,
                    "result_sha256": action.result_sha256,
                    "verified_at": action.verified_at.isoformat(),
                }
                for action in actions
            ],
        }
        digest = hashlib.sha256(canonical_json(manifest)).digest()
        signature = await self.signer.sign_sha256(digest)
        operation.manifest = manifest
        operation.manifest_sha256 = digest.hex()
        operation.signature_b64 = signature.signature_b64
        operation.signature_algorithm = signature.algorithm
        operation.signing_key_id = signature.key_id
        operation.status = "completed"
        operation.failure_code = None
        operation.completed_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(operation)
        return operation

    async def verify_manifest(self, operation: GovernanceOperation) -> bool:
        if self.signer is None:
            raise RuntimeError("Governance manifest verification requires a signer.")
        if (
            operation.status != "completed"
            or not operation.manifest_sha256
            or not operation.signature_b64
            or not operation.signature_algorithm
            or not operation.signing_key_id
        ):
            return False
        digest = hashlib.sha256(canonical_json(operation.manifest)).digest()
        if digest.hex() != operation.manifest_sha256:
            return False
        from app.infrastructure.signing import DigestSignature

        return await self.signer.verify_sha256(
            digest,
            DigestSignature(
                signature_b64=operation.signature_b64,
                algorithm=operation.signature_algorithm,
                key_id=operation.signing_key_id,
            ),
        )

    async def _execute_action(
        self, operation: GovernanceOperation, action: GovernanceStoreAction
    ) -> None:
        now = datetime.now(timezone.utc)
        if (
            action.status == "leased"
            and action.lease_expires_at is not None
            and action.lease_expires_at > now
        ):
            return
        if action.attempts >= MAX_ATTEMPTS:
            operation.status = "failed"
            operation.failure_code = f"{action.store}_attempts_exhausted"
            await self.db.commit()
            return
        claimed_id = await self.db.scalar(
            update(GovernanceStoreAction)
            .where(
                GovernanceStoreAction.id == action.id,
                GovernanceStoreAction.attempts < MAX_ATTEMPTS,
                or_(
                    GovernanceStoreAction.status != "leased",
                    GovernanceStoreAction.lease_expires_at.is_(None),
                    GovernanceStoreAction.lease_expires_at <= now,
                ),
            )
            .values(
                status="leased",
                attempts=GovernanceStoreAction.attempts + 1,
                lease_expires_at=now + timedelta(seconds=LEASE_SECONDS),
            )
            .returning(GovernanceStoreAction.id)
        )
        if claimed_id is None:
            await self.db.rollback()
            return
        await self.db.commit()
        await self.db.refresh(action)
        adapter = self.adapters[action.store]
        try:
            await self._acquire_tenant_barrier(operation.tenant_id)
            if operation.kind == "delete" and await self._scope_is_held(
                operation.tenant_id, operation.scope
            ):
                operation.status = "blocked_legal_hold"
                operation.failure_code = "active_legal_hold"
                action.status = "pending"
                action.lease_expires_at = None
                await self.db.commit()
                return
            untrusted_result = await adapter.apply(
                operation_id=operation.id,
                kind=operation.kind,
                tenant_id=operation.tenant_id,
                scope=operation.scope,
            )
            parsed = StoreActionResult.model_validate(untrusted_result)
            if (
                parsed.store != action.store
                or parsed.kind != operation.kind
                or parsed.operation_id != operation.id
            ):
                raise ValueError("store_result_identity_mismatch")
            result = parsed.model_dump(mode="json")
            result_bytes = canonical_json(result)
            if len(result_bytes) > MAX_STORE_RESULT_BYTES:
                raise ValueError("store_result_exceeds_governance_cap")
            action.result = result
            action.result_sha256 = hashlib.sha256(result_bytes).hexdigest()
            action.status = "applied"
            action.applied_at = datetime.now(timezone.utc)
            action.last_error_code = None
            verified = await adapter.verify(
                operation_id=operation.id,
                kind=operation.kind,
                tenant_id=operation.tenant_id,
                scope=operation.scope,
                result=result,
            )
            if not verified:
                raise RuntimeError("store_verification_failed")
            action.status = "verified"
            action.verified_at = datetime.now(timezone.utc)
            action.lease_expires_at = None
            await self.db.commit()
        except Exception as exc:  # noqa: BLE001
            await self.db.rollback()
            operation = await self.db.get(GovernanceOperation, operation.id)
            action = await self.db.get(GovernanceStoreAction, action.id)
            if operation is None or action is None:
                raise
            action.status = "failed"
            action.last_error_code = exc.__class__.__name__[:64]
            action.lease_expires_at = None
            if action.attempts >= MAX_ATTEMPTS:
                operation.status = "failed"
                operation.failure_code = f"{action.store}_attempts_exhausted"
            await self.db.commit()

    async def _acquire_tenant_barrier(self, tenant_id: uuid.UUID) -> None:
        await self.db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:key, 0))"),
            {"key": f"governance-delete-barrier:{tenant_id}"},
        )

    async def _scope_is_held(
        self, tenant_id: uuid.UUID, scope: Mapping[str, str]
    ) -> bool:
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
        if not holds:
            return False
        ancestors = await self._scope_ancestors(tenant_id, scope)
        target = (scope["scope_type"], scope["scope_id"])
        for hold in holds:
            held_scope = (hold.scope_type, hold.scope_id)
            if held_scope in ancestors:
                return True
            # A broad deletion/export scope also overlaps a narrower hold. For
            # example, deleting a project must stop when one child attempt is
            # held, even though the hold is not an ancestor of the project.
            hold_ancestors = await self._scope_ancestors(
                tenant_id,
                {"scope_type": hold.scope_type, "scope_id": hold.scope_id},
            )
            if target in hold_ancestors:
                return True
        return False

    async def _scope_ancestors(
        self, tenant_id: uuid.UUID, scope: Mapping[str, str]
    ) -> set[tuple[str, str]]:
        scope_type, scope_id = scope["scope_type"], scope["scope_id"]
        ancestors = {("tenant", str(tenant_id)), (scope_type, scope_id)}
        scan_id: uuid.UUID | None = None
        if scope_type == "project":
            project = await self.db.scalar(
                select(db_models.Project).where(
                    db_models.Project.id == uuid.UUID(scope_id),
                    db_models.Project.tenant_id == tenant_id,
                )
            )
            if project is None:
                raise LookupError("Governance scope not found.")
            return ancestors
        if scope_type == "scan":
            scan_id = uuid.UUID(scope_id)
        elif scope_type == "attempt":
            attempt = await self.db.scalar(
                select(db_models.ScanAttempt).where(
                    db_models.ScanAttempt.id == uuid.UUID(scope_id),
                    db_models.ScanAttempt.tenant_id == tenant_id,
                )
            )
            if attempt is None:
                raise LookupError("Governance scope not found.")
            scan_id = attempt.scan_id
            ancestors.add(("scan", str(attempt.scan_id)))
        elif scope_type == "evidence":
            evidence = await self.db.scalar(
                select(db_models.EvidenceObject).where(
                    db_models.EvidenceObject.id == uuid.UUID(scope_id),
                    db_models.EvidenceObject.tenant_id == tenant_id,
                )
            )
            if evidence is None:
                raise LookupError("Governance scope not found.")
            if evidence.attempt_id:
                ancestors.add(("attempt", str(evidence.attempt_id)))
            if evidence.scan_id:
                scan_id = evidence.scan_id
                ancestors.add(("scan", str(evidence.scan_id)))
        if scan_id is not None:
            scan = await self.db.scalar(
                select(db_models.Scan).where(
                    db_models.Scan.id == scan_id,
                    db_models.Scan.tenant_id == tenant_id,
                )
            )
            if scan is None:
                raise LookupError("Governance scope not found.")
            ancestors.add(("project", str(scan.project_id)))
        return ancestors

    async def _synchronize_evidence_hold_flags(self, tenant_id: uuid.UUID) -> None:
        """Project the authoritative multi-store holds onto the legacy evidence flag."""
        await self.db.execute(
            update(db_models.EvidenceObject)
            .where(db_models.EvidenceObject.tenant_id == tenant_id)
            .values(legal_hold=False)
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
        for hold in holds:
            statement = update(db_models.EvidenceObject).where(
                db_models.EvidenceObject.tenant_id == tenant_id
            )
            if hold.scope_type == "evidence":
                statement = statement.where(
                    db_models.EvidenceObject.id == uuid.UUID(hold.scope_id)
                )
            elif hold.scope_type == "attempt":
                statement = statement.where(
                    db_models.EvidenceObject.attempt_id == uuid.UUID(hold.scope_id)
                )
            elif hold.scope_type == "scan":
                statement = statement.where(
                    db_models.EvidenceObject.scan_id == uuid.UUID(hold.scope_id)
                )
            elif hold.scope_type == "project":
                scan_ids = select(db_models.Scan.id).where(
                    db_models.Scan.tenant_id == tenant_id,
                    db_models.Scan.project_id == uuid.UUID(hold.scope_id),
                )
                statement = statement.where(
                    db_models.EvidenceObject.scan_id.in_(scan_ids)
                )
            await self.db.execute(statement.values(legal_hold=True))
