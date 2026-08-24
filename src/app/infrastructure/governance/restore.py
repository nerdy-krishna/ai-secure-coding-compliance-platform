"""Isolated-restore verification for tenancy, resumability, and evidence integrity.

The verifier is intentionally allowed to exercise writes because it only runs
against an isolated restore.  Every destructive-looking probe is enclosed in a
savepoint and its rollback is itself verified before the check can pass.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import math
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol, Sequence

import httpx
import psycopg
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
from psycopg.rows import dict_row
from pydantic import BaseModel, ConfigDict, Field

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.evidence_repo import EvidenceRepository
from app.infrastructure.evidence.object_store import EvidenceObjectStore
from app.infrastructure.governance.models import GovernanceOperation
from app.infrastructure.governance.contracts import StoreActionResult, canonical_json
from app.infrastructure.governance.models import GovernanceStoreAction
from app.infrastructure.integrations.secrets import verify_principal_secrets
from app.infrastructure.secrets.scoped import decrypt_scoped_secret
from app.infrastructure.signing import DigestSignature, DigestSigner
from app.infrastructure.workflows.checkpoint_serde import checkpoint_serializer


SHA256_PATTERN = r"^[0-9a-f]{64}$"


class _RestoreSignature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signature_b64: str = Field(min_length=1, max_length=16_384)
    algorithm: str = Field(min_length=1, max_length=64)
    key_id: str = Field(min_length=1, max_length=512)


class _QdrantCollectionArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    points_count: int = Field(strict=True, gt=0)
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    snapshot_name: str = Field(min_length=1, max_length=512)
    snapshot_size: int = Field(strict=True, gt=0)
    snapshot_sha256: str = Field(pattern=SHA256_PATTERN)


class _QdrantRestoreArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    artifact_kind: Literal["qdrant_restore"]
    collections: list[_QdrantCollectionArtifact] = Field(min_length=1, max_length=100)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    signature: _RestoreSignature


class _ObservabilityRestoreArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    artifact_kind: Literal["observability_restore"]
    artifact_ref: str = Field(min_length=1, max_length=512)
    snapshot_id: str = Field(min_length=1, max_length=255)
    record_count: int = Field(strict=True, gt=0)
    content_sha256: str = Field(pattern=SHA256_PATTERN)
    verified_content_sha256: str = Field(pattern=SHA256_PATTERN)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    signature: _RestoreSignature


@dataclass(frozen=True)
class RestoreCheck:
    name: str
    passed: bool
    evidence: dict[str, Any]


@dataclass(frozen=True)
class OutboxReplayRequest:
    """Committed handoff selected for a real isolated replay."""

    outbox_id: uuid.UUID
    scan_id: uuid.UUID
    attempt_id: uuid.UUID | None
    queue_name: str
    payload_sha256: str


@dataclass(frozen=True)
class OutboxReplayReceipt:
    """Durable consumer-effect receipt returned by the replay harness."""

    outbox_id: uuid.UUID
    effect_sha256: str
    durable_receipt_id: str
    converged: bool


class OutboxReplayProbe(Protocol):
    """Publish canaries and wait until their durable effects converge."""

    async def __call__(
        self, requests: Sequence[OutboxReplayRequest]
    ) -> Sequence[OutboxReplayReceipt]: ...


@dataclass(frozen=True)
class CheckpointResumeRequest:
    """Exact durable checkpoint selected for a production resume probe."""

    scan_id: uuid.UUID
    tenant_id: uuid.UUID
    attempt_id: uuid.UUID
    outbox_id: uuid.UUID
    gate_id: uuid.UUID
    gate_version: int
    gate_sequence: int
    node_name: str
    thread_id: str
    checkpoint_ns: str
    checkpoint_id: str
    state_sha256: str


@dataclass(frozen=True)
class CheckpointResumeReceipt:
    """Proof returned after the real graph resumes the selected checkpoint."""

    scan_id: uuid.UUID
    tenant_id: uuid.UUID
    attempt_id: uuid.UUID
    outbox_id: uuid.UUID
    gate_id: uuid.UUID
    gate_version: int
    gate_sequence: int
    node_name: str
    thread_id: str
    source_checkpoint_id: str
    resumed_checkpoint_id: str
    deserialized_state_sha256: str
    serializer_id: str
    worker_identity: str


class CheckpointResumeProbe(Protocol):
    """Run the production graph/checkpointer against isolated canaries."""

    async def __call__(
        self, requests: Sequence[CheckpointResumeRequest]
    ) -> Sequence[CheckpointResumeReceipt]: ...


@dataclass(frozen=True)
class GovernanceRecoveryRequest:
    operation_id: uuid.UUID
    tenant_id: uuid.UUID
    status: str


@dataclass(frozen=True)
class GovernanceRecoveryReceipt:
    operation_id: uuid.UUID
    tenant_id: uuid.UUID
    status: str
    manifest_sha256: str


class GovernanceRecoveryProbe(Protocol):
    async def __call__(
        self, requests: Sequence[GovernanceRecoveryRequest]
    ) -> Sequence[GovernanceRecoveryReceipt]: ...


CHECKPOINT_SERIALIZER_ID = "sccap-jsonplus-allowlist-v1"
MAX_RESTORE_CANARIES = 10
MAX_OUTBOX_REPLAY_ROWS = 10_000
MAX_QDRANT_POINTS = 100_000


def _json_safe(value: Any) -> Any:
    """Convert Qdrant response values to a stable JSON-compatible value."""
    if value is None or isinstance(value, (str, int, bool)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("non_finite_qdrant_vector_value")
        return value
    if isinstance(value, bytes):
        return {"base64": base64.b64encode(value).decode("ascii")}
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump(mode="json"))
    raise TypeError(f"unsupported_restore_artifact_value:{type(value).__name__}")


def _signed_body(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude={"manifest_sha256", "signature"})


async def _verify_signed_artifact(model: BaseModel, signer: DigestSigner) -> bool:
    body_digest = hashlib.sha256(canonical_json(_signed_body(model))).digest()
    signature = model.signature
    return body_digest.hex() == model.manifest_sha256 and await signer.verify_sha256(
        body_digest,
        DigestSignature(
            signature_b64=signature.signature_b64,
            algorithm=signature.algorithm,
            key_id=signature.key_id,
        ),
    )


class RestoreVerifier:
    """Fail-closed verifier intended only for an isolated restored environment."""

    def __init__(
        self,
        db: AsyncSession,
        *,
        signer: DigestSigner,
        object_store: EvidenceObjectStore,
        qdrant_client: Any | None = None,
        qdrant_restore_artifact: dict[str, Any] | None = None,
        checkpoint_conn_string: str | None = None,
        observability_url: str | None = None,
        observability_token: str | None = None,
        http_client: httpx.AsyncClient | None = None,
        governance_artifact_root: Path | None = None,
        expected_observability_sha256: str | None = None,
        outbox_replay_probe: OutboxReplayProbe | None = None,
        checkpoint_resume_probe: CheckpointResumeProbe | None = None,
        governance_recovery_probe: GovernanceRecoveryProbe | None = None,
    ) -> None:
        self.db = db
        self.signer = signer
        self.object_store = object_store
        self.qdrant_client = qdrant_client
        self.qdrant_restore_artifact = qdrant_restore_artifact
        self.checkpoint_conn_string = checkpoint_conn_string or ""
        self.observability_url = (observability_url or "").rstrip("/")
        self.observability_token = observability_token or ""
        self.http_client = http_client
        configured_root = os.environ.get("GOVERNANCE_ARTIFACT_ROOT", "").strip()
        self.governance_artifact_root = (
            governance_artifact_root.resolve()
            if governance_artifact_root is not None
            else Path(configured_root).resolve() if configured_root else None
        )
        self.expected_observability_sha256 = (
            expected_observability_sha256
            or os.environ.get("RESTORE_EXPECTED_OBSERVABILITY_SHA256", "")
        ).strip()
        self.outbox_replay_probe = outbox_replay_probe
        self.checkpoint_resume_probe = checkpoint_resume_probe
        self.governance_recovery_probe = governance_recovery_probe

    async def run(self, *, max_evidence_objects: int = 0) -> dict[str, Any]:
        final_acceptance = max_evidence_objects == 0
        checks = [
            await self._check_runtime_role(),
            await self._check_rls(),
            await self._probe_tenant_isolation(),
            await self._check_configuration_restore(),
            await self._check_checkpoints(require_canary=final_acceptance),
            await self._check_outbox(require_canary=final_acceptance),
            await self._check_evidence_manifests(require_canary=final_acceptance),
            await self._check_evidence_objects(
                max_evidence_objects, require_canary=final_acceptance
            ),
            await self._check_governance_convergence(require_canary=final_acceptance),
            await self._check_governance_signatures(require_canary=final_acceptance),
            await self._check_qdrant_restore(),
            await self._check_observability_restore(),
            await self._check_offline_deployment(),
        ]
        report = {
            "schema_version": 1,
            "artifact_kind": "isolated_restore_verification",
            "passed": all(check.passed for check in checks),
            "checks": [
                {
                    "name": check.name,
                    "passed": check.passed,
                    "evidence": check.evidence,
                }
                for check in checks
            ],
        }
        digest = hashlib.sha256(canonical_json(report)).digest()
        signature = await self.signer.sign_sha256(digest)
        return {
            "report": report,
            "report_sha256": digest.hex(),
            "signature": {
                "signature_b64": signature.signature_b64,
                "algorithm": signature.algorithm,
                "key_id": signature.key_id,
            },
        }

    async def _check_runtime_role(self) -> RestoreCheck:
        row = (
            await self.db.execute(
                text(
                    "SELECT current_user, r.rolsuper, r.rolbypassrls "
                    "FROM pg_roles r WHERE r.rolname = current_user"
                )
            )
        ).one()
        return RestoreCheck(
            "runtime_role_cannot_bypass_rls",
            not bool(row.rolsuper) and not bool(row.rolbypassrls),
            {
                "role": row.current_user,
                "superuser": bool(row.rolsuper),
                "bypass_rls": bool(row.rolbypassrls),
            },
        )

    async def _check_rls(self) -> RestoreCheck:
        rows = (
            await self.db.execute(
                text(
                    "SELECT c.relname, c.relrowsecurity, c.relforcerowsecurity, "
                    "EXISTS (SELECT 1 FROM pg_policies p WHERE p.schemaname = "
                    "current_schema() AND p.tablename = c.relname AND "
                    "p.policyname = 'sccap_tenant_isolation') AS has_policy "
                    "FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace "
                    "JOIN information_schema.columns col ON col.table_schema = n.nspname "
                    "AND col.table_name = c.relname AND col.column_name = 'tenant_id' "
                    "WHERE n.nspname = current_schema() AND c.relkind = 'r'"
                )
            )
        ).all()
        observed = {
            row.relname: {
                "enabled": bool(row.relrowsecurity),
                "forced": bool(row.relforcerowsecurity),
                "policy": bool(row.has_policy),
            }
            for row in rows
        }
        passed = bool(observed) and all(
            all(values.values()) for values in observed.values()
        )
        return RestoreCheck("tenant_rls_policy", passed, {"tables": observed})

    async def _probe_tenant_isolation(self) -> RestoreCheck:
        """Exercise non-vacuous reads and writes as a tenant human principal."""
        tenant_rows = (
            await self.db.execute(
                text(
                    "SELECT tenant_id, count(*) AS scan_count FROM scans "
                    "GROUP BY tenant_id HAVING count(*) > 0 ORDER BY tenant_id LIMIT 2"
                )
            )
        ).all()
        if len(tenant_rows) < 2:
            return RestoreCheck(
                "tenant_rls_runtime_probe",
                False,
                {"reason": "positive_two_tenant_scan_probe_unavailable"},
            )
        selected, expected_same = tenant_rows[0]
        other, expected_other = tenant_rows[1]
        selected_scan_id = await self.db.scalar(
            text(
                "SELECT id FROM scans WHERE tenant_id = :tenant_id "
                "ORDER BY id LIMIT 1"
            ),
            {"tenant_id": selected},
        )
        other_scan_id = await self.db.scalar(
            text(
                "SELECT id FROM scans WHERE tenant_id = :tenant_id "
                "ORDER BY id LIMIT 1"
            ),
            {"tenant_id": other},
        )
        original_risk_score = await self.db.scalar(
            text("SELECT risk_score FROM scans WHERE id = :scan_id"),
            {"scan_id": selected_scan_id},
        )
        await self.db.execute(
            text(
                "SELECT set_config('app.tenant_id', :tenant_id, true), "
                "set_config('app.principal_kind', 'human', true), "
                "set_config('app.principal_id', 'restore-rls-probe', true), "
                "set_config('app.system_scope', 'off', true)"
            ),
            {"tenant_id": str(selected)},
        )
        same_write_allowed = False
        cross_write_denied = False
        probe_rolled_back = False
        try:
            visible_same = int(
                (await self.db.scalar(text("SELECT count(*) FROM scans"))) or 0
            )
            visible_other = int(
                (
                    await self.db.scalar(
                        text("SELECT count(*) FROM scans WHERE tenant_id = :tenant_id"),
                        {"tenant_id": other},
                    )
                )
                or 0
            )
            probe = await self.db.begin_nested()
            try:
                same_write_allowed = (
                    await self.db.scalar(
                        text(
                            "UPDATE scans SET risk_score = CASE "
                            "WHEN risk_score = 0 THEN 1 ELSE 0 END "
                            "WHERE id = :scan_id RETURNING id"
                        ),
                        {"scan_id": selected_scan_id},
                    )
                    == selected_scan_id
                )
                cross_write_denied = (
                    await self.db.scalar(
                        text(
                            "UPDATE scans SET risk_score = CASE "
                            "WHEN risk_score = 0 THEN 1 ELSE 0 END "
                            "WHERE id = :scan_id RETURNING id"
                        ),
                        {"scan_id": other_scan_id},
                    )
                    is None
                )
            finally:
                await probe.rollback()
            same_row_still_visible = (
                await self.db.scalar(
                    text("SELECT risk_score FROM scans WHERE id = :scan_id"),
                    {"scan_id": selected_scan_id},
                )
                == original_risk_score
            )
            probe_rolled_back = same_row_still_visible
        finally:
            await self.db.execute(
                text(
                    "SELECT set_config('app.tenant_id', '', true), "
                    "set_config('app.principal_kind', 'system', true), "
                    "set_config('app.principal_id', 'isolated-restore-verifier', true), "
                    "set_config('app.system_scope', 'on', true)"
                )
            )
        same_allowed = visible_same == expected_same
        cross_denied = int(expected_other) > 0 and visible_other == 0
        return RestoreCheck(
            "tenant_rls_runtime_probe",
            (
                same_allowed
                and cross_denied
                and same_write_allowed
                and cross_write_denied
                and probe_rolled_back
            ),
            {
                "same_tenant_expected": expected_same,
                "same_tenant_visible": visible_same,
                "cross_tenant_visible": visible_other,
                "cross_tenant_system_rows": int(expected_other),
                "positive_probe": int(expected_same) > 0 and int(expected_other) > 0,
                "same_tenant_write_allowed": same_write_allowed,
                "cross_tenant_write_denied": cross_write_denied,
                "write_probe_rolled_back": probe_rolled_back,
            },
        )

    async def _check_configuration_restore(self) -> RestoreCheck:
        system_count = int(
            (await self.db.scalar(text("SELECT count(*) FROM system_configurations")))
            or 0
        )
        plaintext_system_secrets = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM system_configurations "
                        "WHERE is_secret AND NOT encrypted"
                    )
                )
            )
            or 0
        )
        connector_count = int(
            (
                await self.db.scalar(
                    text("SELECT count(*) FROM integration_service_principals")
                )
            )
            or 0
        )
        invalid_connectors = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM integration_service_principals "
                        "WHERE octet_length(secrets_encrypted) = 0 OR "
                        "secret_fingerprint !~ '^[0-9a-f]{64}$'"
                    )
                )
            )
            or 0
        )
        invalid_grants = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM integration_grants g "
                        "LEFT JOIN integration_service_principals p ON p.id = g.principal_id "
                        "WHERE p.id IS NULL OR p.tenant_id IS DISTINCT FROM g.tenant_id"
                    )
                )
            )
            or 0
        )
        principals = list(
            (
                await self.db.scalars(
                    select(db_models.IntegrationServicePrincipal).order_by(
                        db_models.IntegrationServicePrincipal.id
                    )
                )
            ).all()
        )
        undecryptable: list[str] = []
        principal_failures = 0
        for principal in principals:
            try:
                await verify_principal_secrets(principal)
            except Exception:  # noqa: BLE001
                undecryptable.append(str(principal.id))
                principal_failures += 1
        application_secret_checks: list[tuple[str, str, dict[str, str]]] = []
        llm_configs = list(
            (await self.db.scalars(select(db_models.LLMConfiguration))).all()
        )
        application_secret_checks.extend(
            (
                f"llm:{row.id}",
                row.encrypted_api_key,
                {"kind": "llm_configuration", "id": str(row.id)},
            )
            for row in llm_configs
        )
        sso_providers = list(
            (await self.db.scalars(select(db_models.SsoProvider))).all()
        )
        application_secret_checks.extend(
            (
                f"sso:{row.id}",
                row.config_encrypted.decode(),
                {
                    "kind": "sso_provider",
                    "tenant_id": str(row.tenant_id),
                    "id": str(row.id),
                },
            )
            for row in sso_providers
        )
        billing = list(
            (await self.db.scalars(select(db_models.ProviderBillingConnector))).all()
        )
        application_secret_checks.extend(
            (
                f"billing:{row.id}",
                row.credentials_encrypted.decode(),
                {
                    "kind": "provider_billing_connector",
                    "tenant_id": str(row.tenant_id),
                    "id": str(row.id),
                },
            )
            for row in billing
        )
        system_secrets = list(
            (
                await self.db.scalars(
                    select(db_models.SystemConfiguration).where(
                        db_models.SystemConfiguration.encrypted.is_(True)
                    )
                )
            ).all()
        )
        for row in system_secrets:
            stored = row.value if isinstance(row.value, dict) else {}
            envelope = stored.get("_kms_envelope") or stored.get("_encrypted")
            if not isinstance(envelope, str):
                undecryptable.append(f"system:{row.key}")
            else:
                application_secret_checks.append(
                    (
                        f"system:{row.key}",
                        envelope,
                        {"kind": "system_configuration", "key": row.key},
                    )
                )
        for identifier, envelope, scope in application_secret_checks:
            try:
                await decrypt_scoped_secret(envelope, scope=scope)
            except Exception:  # noqa: BLE001
                undecryptable.append(identifier)
        passed = (
            not plaintext_system_secrets
            and not invalid_connectors
            and not invalid_grants
            and not undecryptable
        )
        return RestoreCheck(
            "connector_and_policy_configuration",
            passed,
            {
                "system_configuration_rows": system_count,
                "plaintext_secret_rows": plaintext_system_secrets,
                "connector_rows": connector_count,
                "invalid_connector_envelopes": invalid_connectors,
                "invalid_grants": invalid_grants,
                "decryptable_connector_rows": len(principals) - principal_failures,
                "undecryptable_connector_ids": undecryptable[:100],
                "application_secret_envelopes_checked": len(application_secret_checks),
            },
        )

    async def _check_outbox(self, *, require_canary: bool) -> RestoreCheck:
        invalid = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM scan_outbox o "
                        "LEFT JOIN scans s ON s.id = o.scan_id "
                        "LEFT JOIN scan_attempts a ON a.id = o.attempt_id "
                        "WHERE (o.scan_id IS NOT NULL AND s.id IS NULL) OR "
                        "(o.attempt_id IS NOT NULL AND a.id IS NULL) OR "
                        "(a.id IS NOT NULL AND a.scan_id IS DISTINCT FROM o.scan_id)"
                    )
                )
            )
            or 0
        )
        pending = int(
            await self.db.scalar(
                text("SELECT count(*) FROM scan_outbox WHERE published_at IS NULL")
            )
            or 0
        )
        if invalid:
            return RestoreCheck(
                "outbox_replay_convergence",
                False,
                {"invalid_references": invalid, "pending_recoverable": pending},
            )
        if pending == 0:
            return RestoreCheck(
                "outbox_replay_convergence",
                not require_canary,
                {
                    "invalid_references": 0,
                    "pending_recoverable": 0,
                    "probed": 0,
                    "reason": "unpublished_restore_canary_missing",
                },
            )
        if self.outbox_replay_probe is None:
            return RestoreCheck(
                "outbox_replay_convergence",
                False,
                {
                    "invalid_references": 0,
                    "pending_recoverable": pending,
                    "reason": "outbox_replay_probe_not_configured",
                },
            )
        if pending > MAX_OUTBOX_REPLAY_ROWS:
            return RestoreCheck(
                "outbox_replay_convergence",
                False,
                {
                    "invalid_references": 0,
                    "pending_recoverable": pending,
                    "reason": "outbox_restore_scope_exceeds_bound",
                },
            )
        probed = 0
        published = 0
        durable_ids: set[str] = set()
        try:
            while True:
                rows = list(
                    (
                        await self.db.scalars(
                            select(db_models.ScanOutbox)
                            .where(db_models.ScanOutbox.published_at.is_(None))
                            .order_by(
                                db_models.ScanOutbox.created_at,
                                db_models.ScanOutbox.id,
                            )
                            .limit(MAX_RESTORE_CANARIES)
                        )
                    ).all()
                )
                if not rows:
                    break
                requests = [
                    OutboxReplayRequest(
                        outbox_id=row.id,
                        scan_id=row.scan_id,
                        attempt_id=row.attempt_id,
                        queue_name=row.queue_name,
                        payload_sha256=hashlib.sha256(
                            canonical_json(row.payload)
                        ).hexdigest(),
                    )
                    for row in rows
                ]
                receipts = list(await self.outbox_replay_probe(tuple(requests)))
                expected_ids = {request.outbox_id for request in requests}
                receipt_ids = {receipt.outbox_id for receipt in receipts}
                batch_durable_ids = {receipt.durable_receipt_id for receipt in receipts}
                valid_receipts = (
                    len(receipts) == len(expected_ids)
                    and receipt_ids == expected_ids
                    and len(batch_durable_ids) == len(receipts)
                    and not (batch_durable_ids & durable_ids)
                    and all(
                        receipt.converged
                        and len(receipt.effect_sha256) == 64
                        and set(receipt.effect_sha256) <= set("0123456789abcdef")
                        and 0 < len(receipt.durable_receipt_id) <= 512
                        for receipt in receipts
                    )
                )
                if not valid_receipts:
                    raise ValueError("outbox_replay_receipt_mismatch")
                published_ids = set(
                    (
                        await self.db.scalars(
                            select(db_models.ScanOutbox.id).where(
                                db_models.ScanOutbox.id.in_(expected_ids),
                                db_models.ScanOutbox.published_at.is_not(None),
                            )
                        )
                    ).all()
                )
                if published_ids != expected_ids:
                    raise ValueError("outbox_replay_not_durable")
                durable_ids.update(batch_durable_ids)
                probed += len(requests)
                published += len(published_ids)
            remaining = int(
                await self.db.scalar(
                    text("SELECT count(*) FROM scan_outbox WHERE published_at IS NULL")
                )
                or 0
            )
        except Exception as exc:  # noqa: BLE001
            return RestoreCheck(
                "outbox_replay_convergence",
                False,
                {
                    "invalid_references": 0,
                    "pending_recoverable": pending,
                    "error_class": exc.__class__.__name__,
                },
            )
        return RestoreCheck(
            "outbox_replay_convergence",
            remaining == 0 and probed == pending,
            {
                "invalid_references": 0,
                "pending_recoverable": pending,
                "probed": probed,
                "durable_receipts": len(durable_ids),
                "published_after_replay": published,
                "pending_after_replay": remaining,
                "all_effects_converged": remaining == 0 and probed == pending,
            },
        )

    async def _check_checkpoints(self, *, require_canary: bool) -> RestoreCheck:
        exists = bool(
            await self.db.scalar(
                text("SELECT to_regclass('public.checkpoints') IS NOT NULL")
            )
        )
        if not exists:
            return RestoreCheck(
                "checkpoint_resumability",
                False,
                {"reason": "checkpoints_table_missing"},
            )
        missing = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM scans s WHERE s.status IN "
                        "('PENDING_PRESCAN_APPROVAL', 'PENDING_PROFILING_APPROVAL', "
                        "'PENDING_COST_APPROVAL', 'RUNNING_AGENTS') AND NOT EXISTS ("
                        "SELECT 1 FROM checkpoints c WHERE c.thread_id = s.id::text)"
                    )
                )
            )
            or 0
        )
        counts = {
            table: int(
                (await self.db.scalar(text(f"SELECT count(*) FROM {table}"))) or 0
            )
            for table in ("checkpoints", "checkpoint_blobs", "checkpoint_writes")
        }
        invalid_payloads = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM checkpoints WHERE NOT ("
                        "checkpoint ? 'id' AND checkpoint ? 'v' AND "
                        "checkpoint ? 'channel_versions' AND "
                        "checkpoint ? 'versions_seen')"
                    )
                )
            )
            or 0
        )
        selected = (
            (
                await self.db.execute(
                    text(
                        "SELECT s.id AS scan_id, s.tenant_id, s.current_attempt_id, "
                        "c.thread_id, c.checkpoint_ns, c.checkpoint_id, "
                        "c.checkpoint->>'id' AS embedded_checkpoint_id, "
                        "g.gate_id, g.attempt_id AS gate_attempt_id, g.version AS gate_version, "
                        "g.sequence AS gate_sequence, g.node_name, "
                        "g.checkpoint_id AS gate_checkpoint_id, o.id AS outbox_id, "
                        "o.payload->>'gate_id' AS outbox_gate_id, "
                        "o.payload->>'node_name' AS outbox_node_name, "
                        "o.payload->>'attempt_id' AS outbox_attempt_id "
                        "FROM checkpoints c JOIN scans s ON s.id::text = c.thread_id "
                        "JOIN approval_gates g ON g.scan_id = s.id "
                        "AND g.thread_id = c.thread_id "
                        "AND g.checkpoint_id = c.checkpoint_id "
                        "JOIN scan_outbox o ON o.scan_id = s.id "
                        "AND o.attempt_id = g.attempt_id "
                        "AND o.payload->>'gate_id' = g.gate_id::text "
                        "WHERE g.state IN ('decided', 'resume_claimed') "
                        "AND g.attempt_id = s.current_attempt_id "
                        "ORDER BY c.thread_id, c.checkpoint_id DESC LIMIT 1"
                    )
                )
            )
            .mappings()
            .first()
        )
        decoded = False
        exact_identity = False
        latest_identity = False
        gate_identity = False
        pending_writes_decoded = 0
        selected_identity: dict[str, Any] | None = None
        decode_error: str | None = None
        resume_verified = False
        resumed_checkpoint_durable = False
        resumed_checkpoint_id: str | None = None
        if selected is not None and self.checkpoint_conn_string:
            selected_identity = {
                "thread_id": selected["thread_id"],
                "checkpoint_ns": selected["checkpoint_ns"],
                "checkpoint_id": selected["checkpoint_id"],
                "gate_id": str(selected["gate_id"]) if selected["gate_id"] else None,
                "tenant_id": str(selected["tenant_id"]),
                "attempt_id": str(selected["gate_attempt_id"]),
                "outbox_id": str(selected["outbox_id"]),
                "node_name": selected["node_name"],
            }
            try:
                exact, latest = await self._decode_checkpoint_pair(
                    thread_id=selected["thread_id"],
                    checkpoint_ns=selected["checkpoint_ns"],
                    checkpoint_id=selected["checkpoint_id"],
                )
                if exact is not None:
                    decoded = isinstance(exact.checkpoint, dict)
                    exact_config = exact.config.get("configurable", {})
                    exact_identity = (
                        exact_config.get("thread_id") == selected["thread_id"]
                        and exact_config.get("checkpoint_ns", "")
                        == selected["checkpoint_ns"]
                        and exact_config.get("checkpoint_id")
                        == selected["checkpoint_id"]
                        and exact.checkpoint.get("id") == selected["checkpoint_id"]
                        and selected["embedded_checkpoint_id"]
                        == selected["checkpoint_id"]
                    )
                    pending_writes_decoded = len(exact.pending_writes or [])
                    state_sha256 = hashlib.sha256(
                        canonical_json(_json_safe(exact.checkpoint))
                    ).hexdigest()
                if latest is not None:
                    latest_config = latest.config.get("configurable", {})
                    latest_identity = (
                        latest_config.get("thread_id") == selected["thread_id"]
                        and latest_config.get("checkpoint_id")
                        == selected["checkpoint_id"]
                    )
                gate_identity = (
                    selected["gate_id"] is not None
                    and selected["gate_checkpoint_id"] == selected["checkpoint_id"]
                    and selected["gate_attempt_id"] == selected["current_attempt_id"]
                    and selected["outbox_gate_id"] == str(selected["gate_id"])
                    and selected["outbox_node_name"] == selected["node_name"]
                    and selected["outbox_attempt_id"]
                    == str(selected["gate_attempt_id"])
                )
                if (
                    decoded
                    and exact_identity
                    and latest_identity
                    and gate_identity
                    and self.checkpoint_resume_probe is not None
                ):
                    receipts = list(
                        await self.checkpoint_resume_probe(
                            (
                                CheckpointResumeRequest(
                                    scan_id=selected["scan_id"],
                                    tenant_id=selected["tenant_id"],
                                    attempt_id=selected["gate_attempt_id"],
                                    outbox_id=selected["outbox_id"],
                                    gate_id=selected["gate_id"],
                                    gate_version=selected["gate_version"],
                                    gate_sequence=selected["gate_sequence"],
                                    node_name=selected["node_name"],
                                    thread_id=selected["thread_id"],
                                    checkpoint_ns=selected["checkpoint_ns"],
                                    checkpoint_id=selected["checkpoint_id"],
                                    state_sha256=state_sha256,
                                ),
                            )
                        )
                    )
                    if len(receipts) == 1:
                        receipt = receipts[0]
                        resumed_checkpoint_id = receipt.resumed_checkpoint_id
                        resume_verified = (
                            receipt.scan_id == selected["scan_id"]
                            and receipt.tenant_id == selected["tenant_id"]
                            and receipt.attempt_id == selected["gate_attempt_id"]
                            and receipt.outbox_id == selected["outbox_id"]
                            and receipt.gate_id == selected["gate_id"]
                            and receipt.gate_version == selected["gate_version"]
                            and receipt.gate_sequence == selected["gate_sequence"]
                            and receipt.node_name == selected["node_name"]
                            and receipt.thread_id == selected["thread_id"]
                            and receipt.source_checkpoint_id
                            == selected["checkpoint_id"]
                            and bool(receipt.resumed_checkpoint_id)
                            and receipt.resumed_checkpoint_id
                            != receipt.source_checkpoint_id
                            and receipt.deserialized_state_sha256 == state_sha256
                            and receipt.serializer_id == CHECKPOINT_SERIALIZER_ID
                            and bool(receipt.worker_identity)
                        )
                        if resume_verified:
                            resumed, _ = await self._decode_checkpoint_pair(
                                thread_id=receipt.thread_id,
                                checkpoint_ns=selected["checkpoint_ns"],
                                checkpoint_id=receipt.resumed_checkpoint_id,
                            )
                            resumed_config = (
                                resumed.config.get("configurable", {})
                                if resumed is not None
                                else {}
                            )
                            resumed_checkpoint_durable = bool(
                                resumed is not None
                                and resumed_config.get("thread_id")
                                == selected["thread_id"]
                                and resumed_config.get("checkpoint_id")
                                == receipt.resumed_checkpoint_id
                                and resumed.checkpoint.get("id")
                                == receipt.resumed_checkpoint_id
                            )
                            durable_identity = (
                                (
                                    await self.db.execute(
                                        text(
                                            "SELECT s.id AS scan_id, s.tenant_id, "
                                            "s.current_attempt_id, g.scan_id AS gate_scan_id, "
                                            "g.attempt_id, g.state AS gate_state, g.version, "
                                            "g.sequence, g.node_name, o.id AS outbox_id, "
                                            "o.scan_id AS outbox_scan_id, "
                                            "o.attempt_id AS outbox_attempt_id_fk, "
                                            "o.payload->>'gate_id' AS outbox_gate_id, "
                                            "o.payload->>'node_name' AS outbox_node_name, "
                                            "o.payload->>'attempt_id' AS outbox_attempt_id "
                                            "FROM approval_gates g JOIN scans s ON s.id = g.scan_id "
                                            "JOIN scan_outbox o ON o.id = :outbox_id "
                                            "WHERE g.gate_id = :gate_id"
                                        ),
                                        {
                                            "gate_id": receipt.gate_id,
                                            "outbox_id": receipt.outbox_id,
                                        },
                                    )
                                )
                                .mappings()
                                .one_or_none()
                            )
                            resumed_checkpoint_durable = bool(
                                resumed_checkpoint_durable
                                and durable_identity
                                and durable_identity["scan_id"] == receipt.scan_id
                                and durable_identity["gate_scan_id"] == receipt.scan_id
                                and durable_identity["outbox_scan_id"]
                                == receipt.scan_id
                                and durable_identity["tenant_id"] == receipt.tenant_id
                                and durable_identity["current_attempt_id"]
                                == receipt.attempt_id
                                and durable_identity["attempt_id"] == receipt.attempt_id
                                and durable_identity["outbox_attempt_id_fk"]
                                == receipt.attempt_id
                                and durable_identity["gate_state"]
                                in {"resumed", "completed"}
                                and durable_identity["version"] == receipt.gate_version
                                and durable_identity["sequence"]
                                == receipt.gate_sequence
                                and durable_identity["node_name"] == receipt.node_name
                                and durable_identity["outbox_id"] == receipt.outbox_id
                                and durable_identity["outbox_gate_id"]
                                == str(receipt.gate_id)
                                and durable_identity["outbox_node_name"]
                                == receipt.node_name
                                and durable_identity["outbox_attempt_id"]
                                == str(receipt.attempt_id)
                            )
            except Exception as exc:  # noqa: BLE001
                decode_error = exc.__class__.__name__
        canary_available = selected is not None
        return RestoreCheck(
            "checkpoint_resumability",
            (
                (counts["checkpoints"] > 0 or not require_canary)
                and missing == 0
                and invalid_payloads == 0
                and (not require_canary or canary_available)
                and (not canary_available or decoded)
                and (not canary_available or exact_identity)
                and (not canary_available or latest_identity)
                and (not canary_available or gate_identity)
                and (not canary_available or resume_verified)
                and (not canary_available or resumed_checkpoint_durable)
            ),
            {
                "paused_scans_without_checkpoint": missing,
                "invalid_checkpoint_payloads": invalid_payloads,
                "row_counts": counts,
                "selected_identity": selected_identity,
                "checkpoint_decoded": decoded,
                "exact_checkpoint_identity": exact_identity,
                "latest_resume_identity": latest_identity,
                "approval_gate_identity": gate_identity,
                "production_graph_resume_verified": resume_verified,
                "resumed_checkpoint_durable": resumed_checkpoint_durable,
                "resumed_checkpoint_id": resumed_checkpoint_id,
                "pending_writes_decoded": pending_writes_decoded,
                "decode_error_class": decode_error,
                "prerequisite": "at_least_one_paused_scan_with_approval_gate_checkpoint",
            },
        )

    async def _decode_checkpoint_pair(
        self, *, thread_id: str, checkpoint_ns: str, checkpoint_id: str
    ) -> tuple[Any | None, Any | None]:
        """Decode the exact and resume-selected latest tuples via LangGraph."""
        conn = await psycopg.AsyncConnection.connect(
            self.checkpoint_conn_string,
            autocommit=True,
            prepare_threshold=0,
            row_factory=dict_row,
        )
        try:
            role = await (
                await conn.execute(
                    "SELECT current_user AS role, r.rolsuper, r.rolbypassrls "
                    "FROM pg_roles r WHERE r.rolname = current_user"
                )
            ).fetchone()
            if role is None or bool(role["rolsuper"]) or bool(role["rolbypassrls"]):
                raise PermissionError("checkpoint_connection_can_bypass_rls")
            saver = AsyncPostgresSaver(conn=conn, serde=checkpoint_serializer())
            exact = await saver.aget_tuple(
                {
                    "configurable": {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                        "checkpoint_id": checkpoint_id,
                    }
                }
            )
            latest = await saver.aget_tuple(
                {
                    "configurable": {
                        "thread_id": thread_id,
                        "checkpoint_ns": checkpoint_ns,
                    }
                }
            )
            return exact, latest
        finally:
            await conn.close()

    async def _check_evidence_manifests(self, *, require_canary: bool) -> RestoreCheck:
        manifests = list(
            (
                await self.db.scalars(
                    select(db_models.EvidenceManifest).order_by(
                        db_models.EvidenceManifest.attempt_id,
                        db_models.EvidenceManifest.generation,
                    )
                )
            ).all()
        )
        evidence_objects = list(
            (
                await self.db.scalars(
                    select(db_models.EvidenceObject).order_by(
                        db_models.EvidenceObject.attempt_id,
                        db_models.EvidenceObject.id,
                    )
                )
            ).all()
        )
        evidence_by_id = {str(evidence.id): evidence for evidence in evidence_objects}
        invalid: list[str] = []
        invalid_entries: list[str] = []
        prior_by_attempt: dict[uuid.UUID | None, str | None] = {}
        entries_by_attempt: dict[uuid.UUID | None, list[dict[str, Any]]] = {}
        latest_ids_by_attempt: dict[uuid.UUID, set[str]] = {}
        for manifest in manifests:
            prior = prior_by_attempt.get(manifest.attempt_id)
            body: dict[str, Any] = {
                "attempt_id": str(manifest.attempt_id),
                "generation": manifest.generation,
                "previous_manifest_sha256": prior,
                "entries": manifest.entries,
            }
            if manifest.finalized:
                body["finalized"] = True
            digest = hashlib.sha256(canonical_json(body)).hexdigest()
            if (
                manifest.attempt_id is None
                or manifest.scan_id is None
                or manifest.previous_manifest_sha256 != prior
                or manifest.manifest_sha256 != digest
                or manifest.entries[
                    : len(entries_by_attempt.get(manifest.attempt_id, []))
                ]
                != entries_by_attempt.get(manifest.attempt_id, [])
            ):
                invalid.append(str(manifest.id))
            seen: set[str] = set()
            for entry in manifest.entries:
                evidence_id = (
                    entry.get("evidence_id") if isinstance(entry, dict) else None
                )
                evidence = evidence_by_id.get(str(evidence_id))
                if (
                    not isinstance(entry, dict)
                    or evidence is None
                    or str(evidence_id) in seen
                    or evidence.attempt_id != manifest.attempt_id
                    or evidence.scan_id != manifest.scan_id
                    or not evidence.object_key
                    or entry.get("artifact_type") != evidence.artifact_type
                    or entry.get("version") != evidence.version
                    or entry.get("plaintext_sha256") != evidence.plaintext_sha256
                    or entry.get("object_version") != evidence.object_version
                ):
                    invalid_entries.append(f"{manifest.id}:{str(evidence_id)[:64]}")
                seen.add(str(evidence_id))
            prior_by_attempt[manifest.attempt_id] = manifest.manifest_sha256
            entries_by_attempt[manifest.attempt_id] = list(manifest.entries)
            if manifest.attempt_id is not None:
                latest_ids_by_attempt[manifest.attempt_id] = seen
        unmanifested = [
            str(evidence.id)
            for evidence in evidence_objects
            if evidence.attempt_id is None
            or str(evidence.id)
            not in latest_ids_by_attempt.get(evidence.attempt_id, set())
        ]
        return RestoreCheck(
            "evidence_manifest_digest_chains",
            (
                (bool(manifests) or not require_canary)
                and (bool(evidence_objects) or not require_canary)
                and not invalid
                and not invalid_entries
                and not unmanifested
            ),
            {
                "checked": len(manifests),
                "evidence_objects_checked": len(evidence_objects),
                "invalid_ids": invalid[:100],
                "invalid_entries": invalid_entries[:100],
                "unmanifested_evidence_ids": unmanifested[:100],
                "prerequisite": "at_least_one_evidence_manifest",
            },
        )

    async def _check_evidence_objects(
        self, max_objects: int, *, require_canary: bool
    ) -> RestoreCheck:
        statement = (
            select(db_models.EvidenceObject)
            .where(db_models.EvidenceObject.state == "available")
            .order_by(db_models.EvidenceObject.created_at, db_models.EvidenceObject.id)
        )
        if max_objects > 0:
            statement = statement.limit(max_objects)
        objects = list((await self.db.scalars(statement)).all())
        invalid: list[str] = []
        for evidence in objects:
            try:
                await self.object_store.get(
                    object_key=evidence.object_key,
                    object_version=evidence.object_version,
                    aad_fields=EvidenceRepository._aad_fields(
                        evidence_id=evidence.id,
                        scan_id=evidence.scan_id,
                        attempt_id=evidence.attempt_id,
                        tenant_id=evidence.tenant_id,
                        media_type=evidence.media_type,
                        plaintext_sha256=evidence.plaintext_sha256,
                    ),
                    plaintext_sha256=evidence.plaintext_sha256,
                    ciphertext_sha256=evidence.ciphertext_sha256,
                    wrapped_data_key=evidence.wrapped_data_key,
                    key_id=evidence.key_id,
                    nonce=evidence.nonce,
                    aad_sha256=evidence.aad_sha256,
                )
            except Exception:  # noqa: BLE001
                invalid.append(str(evidence.id))
        return RestoreCheck(
            "evidence_object_digests",
            (bool(objects) or not require_canary) and not invalid,
            {
                "checked": len(objects),
                "invalid_ids": invalid[:100],
                "bounded": max_objects > 0,
                "prerequisite": "at_least_one_available_evidence_object",
            },
        )

    async def _check_governance_signatures(
        self, *, require_canary: bool
    ) -> RestoreCheck:
        operations = list(
            (
                await self.db.scalars(
                    select(GovernanceOperation).where(
                        GovernanceOperation.status == "completed"
                    )
                )
            ).all()
        )
        invalid: list[str] = []
        for operation in operations:
            if not await self._operation_signature_valid(operation):
                invalid.append(str(operation.id))
        return RestoreCheck(
            "governance_manifest_signatures",
            (bool(operations) or not require_canary) and not invalid,
            {
                "checked": len(operations),
                "invalid_ids": invalid[:100],
                "prerequisite": "at_least_one_completed_governance_operation",
            },
        )

    async def _operation_signature_valid(self, operation: GovernanceOperation) -> bool:
        digest = hashlib.sha256(canonical_json(operation.manifest)).digest()
        return bool(
            operation.manifest_sha256
            and operation.signature_b64
            and operation.signature_algorithm
            and operation.signing_key_id
            and digest.hex() == operation.manifest_sha256
            and await self.signer.verify_sha256(
                digest,
                DigestSignature(
                    signature_b64=operation.signature_b64,
                    algorithm=operation.signature_algorithm,
                    key_id=operation.signing_key_id,
                ),
            )
        )

    async def _check_governance_convergence(
        self, *, require_canary: bool
    ) -> RestoreCheck:
        recoverable_statement = select(GovernanceOperation).where(
            or_(
                GovernanceOperation.status.in_(["prepared", "executing", "failed"]),
                GovernanceOperation.id.in_(
                    select(GovernanceStoreAction.operation_id).where(
                        GovernanceStoreAction.status == "leased",
                        GovernanceStoreAction.lease_expires_at
                        < datetime.now(timezone.utc),
                    )
                ),
            )
        )
        recoverable = list((await self.db.scalars(recoverable_statement)).all())
        recovered = 0
        if recoverable:
            if self.governance_recovery_probe is None:
                return RestoreCheck(
                    "governance_replay_and_convergence",
                    False,
                    {
                        "recoverable_operations": len(recoverable),
                        "reason": "governance_recovery_probe_not_configured",
                    },
                )
            try:
                receipts = list(
                    await self.governance_recovery_probe(
                        tuple(
                            GovernanceRecoveryRequest(
                                operation_id=operation.id,
                                tenant_id=operation.tenant_id,
                                status=operation.status,
                            )
                            for operation in recoverable
                        )
                    )
                )
                receipt_by_id = {receipt.operation_id: receipt for receipt in receipts}
                if len(receipt_by_id) != len(receipts) or set(receipt_by_id) != {
                    operation.id for operation in recoverable
                }:
                    raise ValueError("governance_recovery_receipt_identity_mismatch")
                restored = list(
                    (
                        await self.db.scalars(
                            select(GovernanceOperation).where(
                                GovernanceOperation.id.in_(receipt_by_id)
                            )
                        )
                    ).all()
                )
                if len(restored) != len(recoverable) or any(
                    operation.status != "completed"
                    or receipt_by_id[operation.id].tenant_id != operation.tenant_id
                    or receipt_by_id[operation.id].status != "completed"
                    or receipt_by_id[operation.id].manifest_sha256
                    != operation.manifest_sha256
                    for operation in restored
                ):
                    raise ValueError("governance_recovery_not_durable")
                for operation in restored:
                    if not await self._operation_signature_valid(operation):
                        raise ValueError("governance_recovery_signature_invalid")
                remaining = list((await self.db.scalars(recoverable_statement)).all())
                if remaining:
                    raise ValueError("governance_recovery_incomplete")
                recovered = len(restored)
            except Exception as exc:  # noqa: BLE001
                return RestoreCheck(
                    "governance_replay_and_convergence",
                    False,
                    {
                        "recoverable_operations": len(recoverable),
                        "error_class": exc.__class__.__name__,
                    },
                )
        operations = list(
            (
                await self.db.scalars(
                    select(GovernanceOperation).where(
                        GovernanceOperation.status == "completed"
                    )
                )
            ).all()
        )
        invalid: list[str] = []
        artifacts_checked = 0
        for operation in operations:
            actions = list(
                (
                    await self.db.scalars(
                        select(GovernanceStoreAction).where(
                            GovernanceStoreAction.operation_id == operation.id
                        )
                    )
                ).all()
            )
            if (
                len(actions) != 4
                or {action.store for action in actions}
                != {"postgres", "object", "qdrant", "observability"}
                or any(action.status != "verified" for action in actions)
            ):
                invalid.append(str(operation.id))
                continue
            manifest_stores = operation.manifest.get("stores", [])
            manifest_by_store = {
                item.get("store"): item
                for item in manifest_stores
                if isinstance(item, dict) and isinstance(item.get("store"), str)
            }
            if (
                operation.manifest.get("schema_version") != 1
                or operation.manifest.get("artifact_kind")
                != (
                    "evidence_export_manifest"
                    if operation.kind == "export"
                    else "evidence_deletion_tombstone"
                )
                or operation.manifest.get("operation_id") != str(operation.id)
                or operation.manifest.get("tenant_id") != str(operation.tenant_id)
                or operation.manifest.get("scope") != operation.scope
                or operation.manifest.get("policy") != operation.policy_snapshot
                or set(manifest_by_store)
                != {"postgres", "object", "qdrant", "observability"}
                or len(manifest_stores) != 4
            ):
                invalid.append(str(operation.id))
                continue
            for action in actions:
                try:
                    parsed = StoreActionResult.model_validate(action.result)
                    digest = hashlib.sha256(canonical_json(action.result)).hexdigest()
                    manifest_action = manifest_by_store[action.store]
                    if (
                        parsed.store != action.store
                        or parsed.kind != operation.kind
                        or parsed.operation_id != operation.id
                        or action.tenant_id != operation.tenant_id
                        or digest != action.result_sha256
                        or manifest_action.get("result") != action.result
                        or manifest_action.get("result_sha256") != action.result_sha256
                    ):
                        raise ValueError("action convergence mismatch")
                    if action.store != "observability":
                        self._verify_governance_artifact(operation, parsed)
                        artifacts_checked += 1
                except Exception:  # noqa: BLE001
                    invalid.append(str(operation.id))
                    break
        duplicate_actions = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM (SELECT operation_id, store FROM "
                        "governance_store_actions GROUP BY operation_id, store "
                        "HAVING count(*) > 1) duplicate"
                    )
                )
            )
            or 0
        )
        expired_leases = int(
            (
                await self.db.scalar(
                    text(
                        "SELECT count(*) FROM governance_store_actions WHERE "
                        "status = 'leased' AND lease_expires_at < now()"
                    )
                )
            )
            or 0
        )
        return RestoreCheck(
            "governance_replay_and_convergence",
            (
                (bool(operations) or not require_canary)
                and not invalid
                and duplicate_actions == 0
                and expired_leases == 0
            ),
            {
                "completed_checked": len(operations),
                "invalid_operation_ids": invalid[:100],
                "duplicate_store_effect_rows": duplicate_actions,
                "expired_leases_resumeable": expired_leases,
                "recovered_operations": recovered,
                "local_artifacts_rehashed": artifacts_checked,
                "prerequisite": "at_least_one_completed_four_store_operation",
            },
        )

    def _verify_governance_artifact(
        self, operation: GovernanceOperation, result: StoreActionResult
    ) -> None:
        """Dereference a local artifact without allowing path substitution."""
        if self.governance_artifact_root is None:
            raise ValueError("governance_artifact_root_not_configured")
        operation_id = operation.id
        expected_ref = f"governance/{operation_id}/{result.store}.json"
        if result.artifact_ref != expected_ref:
            raise ValueError("governance_artifact_reference_mismatch")
        expected_path = (
            self.governance_artifact_root / str(operation_id) / f"{result.store}.json"
        )
        if expected_path.is_symlink() or not expected_path.is_file():
            raise ValueError("governance_artifact_missing_or_unsafe")
        resolved = expected_path.resolve(strict=True)
        try:
            resolved.relative_to(self.governance_artifact_root)
        except ValueError as exc:
            raise ValueError("governance_artifact_escapes_root") from exc
        stat = resolved.stat()
        if stat.st_size <= 0 or stat.st_size > 256 * 1024 * 1024:
            raise ValueError("governance_artifact_size_invalid")
        payload = resolved.read_bytes()
        if hashlib.sha256(payload).hexdigest() != result.content_sha256:
            raise ValueError("governance_artifact_digest_mismatch")
        if result.store == "object" and result.kind == "export":
            self._verify_object_export_files(operation, result, payload)

    def _verify_object_export_files(
        self,
        operation: GovernanceOperation,
        result: StoreActionResult,
        manifest_bytes: bytes,
    ) -> None:
        if self.governance_artifact_root is None:
            raise ValueError("governance_artifact_root_not_configured")
        manifest = json.loads(manifest_bytes)
        records = manifest.get("records") if isinstance(manifest, dict) else None
        if (
            manifest.get("schema_version") != 1
            or manifest.get("artifact_kind") != "object_export"
            or manifest.get("operation_id") != str(operation.id)
            or manifest.get("tenant_id") != str(operation.tenant_id)
            or manifest.get("scope") != operation.scope
            or not isinstance(records, list)
            or len(records) != result.matched_count
            or len(records) != result.applied_count
        ):
            raise ValueError("object_export_manifest_identity_mismatch")
        objects_root = self.governance_artifact_root / str(operation.id) / "objects"
        expected_paths: set[str] = set()
        seen_ids: set[uuid.UUID] = set()
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("object_export_record_invalid")
            evidence_id = uuid.UUID(str(record.get("id")))
            state = record.get("state")
            relative_path = record.get("relative_path")
            expected_relative = f"objects/{evidence_id}"
            digest = record.get("ciphertext_sha256")
            size = record.get("size_bytes")
            if (
                evidence_id in seen_ids
                or state not in {"live", "deleted"}
                or not isinstance(digest, str)
                or len(digest) != 64
                or set(digest) > set("0123456789abcdef")
                or (
                    state == "live"
                    and (
                        relative_path != expected_relative
                        or not isinstance(size, int)
                        or isinstance(size, bool)
                        or size <= 0
                    )
                )
                or (
                    state == "deleted"
                    and (relative_path is not None or size is not None)
                )
            ):
                raise ValueError("object_export_record_invalid")
            seen_ids.add(evidence_id)
            if state == "deleted":
                continue
            expected_paths.add(relative_path)
            path = self.governance_artifact_root / str(operation.id) / relative_path
            if path.is_symlink() or not path.is_file():
                raise ValueError("object_export_ciphertext_missing_or_unsafe")
            resolved = path.resolve(strict=True)
            try:
                resolved.relative_to(objects_root.resolve(strict=True))
            except ValueError as exc:
                raise ValueError("object_export_ciphertext_escapes_root") from exc
            if resolved.stat().st_size != size:
                raise ValueError("object_export_ciphertext_digest_mismatch")
            observed_digest = hashlib.sha256()
            with resolved.open("rb") as handle:
                while chunk := handle.read(1024 * 1024):
                    observed_digest.update(chunk)
            if observed_digest.hexdigest() != digest:
                raise ValueError("object_export_ciphertext_digest_mismatch")
        if objects_root.exists():
            if objects_root.is_symlink() or not objects_root.is_dir():
                raise ValueError("object_export_directory_missing_or_unsafe")
            observed_paths = {
                f"objects/{path.name}"
                for path in objects_root.iterdir()
                if path.is_file() and not path.is_symlink()
            }
            unsafe_or_nested = any(
                path.is_symlink() or not path.is_file()
                for path in objects_root.iterdir()
            )
        else:
            observed_paths = set()
            unsafe_or_nested = False
        if unsafe_or_nested or observed_paths != expected_paths:
            raise ValueError("object_export_ciphertext_file_set_mismatch")

    async def _check_qdrant_restore(self) -> RestoreCheck:
        if self.qdrant_client is None:
            return RestoreCheck(
                "qdrant_restore", False, {"reason": "client_not_configured"}
            )
        if self.qdrant_restore_artifact is None:
            return RestoreCheck(
                "qdrant_restore", False, {"reason": "restore_artifact_not_configured"}
            )
        try:
            artifact = _QdrantRestoreArtifact.model_validate(
                self.qdrant_restore_artifact
            )
            signature_valid = await _verify_signed_artifact(artifact, self.signer)
            declared_names = [item.name for item in artifact.collections]
            unique_names = len(set(declared_names)) == len(declared_names)
            available = await asyncio.to_thread(self.qdrant_client.get_collections)
            available_names = {collection.name for collection in available.collections}
            exact_inventory = available_names == set(declared_names)
            restored_tenants = {
                str(tenant_id)
                for tenant_id in (
                    await self.db.scalars(select(db_models.Tenant.id))
                ).all()
            }
            mismatches: list[str] = []
            observed: dict[str, dict[str, Any]] = {}
            tenant_canaries = 0
            for expected in artifact.collections:
                if expected.name not in available_names:
                    mismatches.append(f"{expected.name}:collection_missing")
                    continue
                points = await self._qdrant_points(expected.name)
                content = canonical_json(
                    {
                        "schema_version": 1,
                        "collection": expected.name,
                        "points": points,
                    }
                )
                content_sha256 = hashlib.sha256(content).hexdigest()
                point_ids = [point["id"] for point in points]
                if len(set(point_ids)) != len(point_ids):
                    mismatches.append(f"{expected.name}:duplicate_point_identity")
                collection_tenants: set[str] = set()
                for point in points:
                    payload = point["payload"]
                    if not isinstance(payload, dict) or "tenant_id" not in payload:
                        continue
                    tenant_id = str(payload["tenant_id"])
                    if tenant_id not in restored_tenants:
                        mismatches.append(f"{expected.name}:unknown_tenant_identity")
                    else:
                        collection_tenants.add(tenant_id)
                        tenant_canaries += 1
                snapshots_result = await asyncio.to_thread(
                    self.qdrant_client.list_snapshots,
                    collection_name=expected.name,
                )
                snapshots = getattr(snapshots_result, "snapshots", snapshots_result)
                snapshot = next(
                    (item for item in snapshots if item.name == expected.snapshot_name),
                    None,
                )
                snapshot_bound = bool(
                    snapshot is not None
                    and int(snapshot.size) == expected.snapshot_size
                    and str(snapshot.checksum or "").lower() == expected.snapshot_sha256
                )
                if len(points) != expected.points_count:
                    mismatches.append(f"{expected.name}:point_count")
                if content_sha256 != expected.content_sha256:
                    mismatches.append(f"{expected.name}:content_digest")
                if not snapshot_bound:
                    mismatches.append(f"{expected.name}:snapshot_digest")
                observed[expected.name] = {
                    "points_count": len(points),
                    "content_sha256": content_sha256,
                    "snapshot_bound": snapshot_bound,
                    "tenant_count": len(collection_tenants),
                }
            return RestoreCheck(
                "qdrant_restore",
                (
                    signature_valid
                    and unique_names
                    and exact_inventory
                    and tenant_canaries > 0
                    and not mismatches
                ),
                {
                    "manifest_signature_valid": signature_valid,
                    "unique_collection_names": unique_names,
                    "exact_collection_inventory": exact_inventory,
                    "tenant_canary_points": tenant_canaries,
                    "collections": observed,
                    "mismatches": mismatches[:100],
                    "prerequisite": "signed_nonempty_qdrant_restore_artifact",
                },
            )
        except Exception as exc:  # noqa: BLE001
            return RestoreCheck(
                "qdrant_restore", False, {"error_class": exc.__class__.__name__}
            )

    async def _qdrant_points(self, collection_name: str) -> list[dict[str, Any]]:
        def collect() -> list[dict[str, Any]]:
            offset = None
            points: list[dict[str, Any]] = []
            while True:
                page, offset = self.qdrant_client.scroll(
                    collection_name=collection_name,
                    limit=1000,
                    offset=offset,
                    with_payload=True,
                    with_vectors=True,
                )
                points.extend(
                    {
                        "id": str(point.id),
                        "payload": _json_safe(point.payload),
                        "vector": _json_safe(point.vector),
                    }
                    for point in page
                )
                if len(points) > MAX_QDRANT_POINTS:
                    raise RuntimeError("qdrant_restore_probe_too_large")
                if offset is None:
                    break
            return sorted(points, key=lambda item: item["id"])

        return await asyncio.to_thread(collect)

    async def _check_observability_restore(self) -> RestoreCheck:
        if (
            not self.observability_url
            or not self.observability_token
            or self.http_client is None
        ):
            return RestoreCheck(
                "observability_restore", False, {"reason": "gateway_not_configured"}
            )
        if len(self.expected_observability_sha256) != 64 or set(
            self.expected_observability_sha256
        ) > set("0123456789abcdef"):
            return RestoreCheck(
                "observability_restore",
                False,
                {"reason": "expected_observability_digest_not_configured"},
            )
        try:
            response = await self.http_client.get(
                f"{self.observability_url}/v1/governance/restore-status",
                headers={"Authorization": f"Bearer {self.observability_token}"},
            )
            response.raise_for_status()
            artifact = _ObservabilityRestoreArtifact.model_validate_json(
                response.content
            )
            signature_valid = await _verify_signed_artifact(artifact, self.signer)
            digest_bound = (
                artifact.content_sha256 == artifact.verified_content_sha256
                and artifact.content_sha256 == self.expected_observability_sha256
            )
            return RestoreCheck(
                "observability_restore",
                signature_valid and digest_bound,
                {
                    "artifact_ref": artifact.artifact_ref,
                    "snapshot_id": artifact.snapshot_id,
                    "record_count": artifact.record_count,
                    "content_sha256": artifact.content_sha256,
                    "manifest_signature_valid": signature_valid,
                    "content_digest_bound": digest_bound,
                    "prerequisite": "signed_nonempty_observability_restore_artifact",
                },
            )
        except Exception as exc:  # noqa: BLE001
            return RestoreCheck(
                "observability_restore", False, {"error_class": exc.__class__.__name__}
            )

    async def _check_offline_deployment(self) -> RestoreCheck:
        from app.infrastructure.governance.offline_runtime import (
            configure_offline_runtime_from_environment,
        )

        environment = dict(os.environ)
        if not environment.get("SCCAP_OFFLINE_INSTALL_ROOT", "").strip():
            return RestoreCheck(
                "offline_deployment_signatures",
                True,
                {"configured": False, "reason": "no_offline_deployment_restored"},
            )
        try:
            paths = await configure_offline_runtime_from_environment(environment)
            return RestoreCheck(
                "offline_deployment_signatures",
                paths is not None,
                {
                    "configured": True,
                    "release_sha256": paths.release_sha256 if paths else None,
                },
            )
        except Exception as exc:  # noqa: BLE001
            return RestoreCheck(
                "offline_deployment_signatures",
                False,
                {"configured": True, "error_class": exc.__class__.__name__},
            )
