"""Run Task22 integrity checks against an isolated restored environment."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import urllib.parse
import uuid
from pathlib import Path
from typing import Any, Literal, Sequence

import httpx
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.tenant_context import principal_scope
from app.infrastructure.evidence.object_store import EvidenceObjectStore
from app.infrastructure.governance.contracts import canonical_json
from app.infrastructure.governance.adapters import (
    GovernanceArtifactSink,
    ObjectGovernanceAdapter,
    ObservabilityGovernanceAdapter,
    PostgresGovernanceAdapter,
    QdrantGovernanceAdapter,
)
from app.infrastructure.governance.restore import (
    CHECKPOINT_SERIALIZER_ID,
    CheckpointResumeReceipt,
    CheckpointResumeRequest,
    GovernanceRecoveryReceipt,
    GovernanceRecoveryRequest,
    OutboxReplayReceipt,
    OutboxReplayRequest,
    RestoreVerifier,
)
from app.infrastructure.governance.service import GovernanceService
from app.infrastructure.messaging.publisher import publish_message
from app.infrastructure.rag.qdrant_store import QdrantStore
from app.infrastructure.signing import AwsKmsDigestSigner, DigestSignature, DigestSigner


SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_PROBE_RECEIPTS = 10
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024


class _Signature(BaseModel):
    model_config = ConfigDict(extra="forbid")

    signature_b64: str = Field(min_length=1, max_length=16_384)
    algorithm: str = Field(min_length=1, max_length=64)
    key_id: str = Field(min_length=1, max_length=512)


class _OutboxEffect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    outbox_id: uuid.UUID
    payload_sha256: str = Field(pattern=SHA256_PATTERN)
    effect_sha256: str = Field(pattern=SHA256_PATTERN)
    durable_receipt_id: str = Field(min_length=1, max_length=512)
    effect_store: str = Field(min_length=1, max_length=128)
    effect_version: str = Field(min_length=1, max_length=128)


class _OutboxReplayArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    artifact_kind: Literal["outbox_replay_convergence"]
    probe_nonce: uuid.UUID
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    receipts: list[_OutboxEffect] = Field(min_length=1, max_length=MAX_PROBE_RECEIPTS)
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    signature: _Signature


class _CheckpointEffect(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: uuid.UUID
    tenant_id: uuid.UUID
    attempt_id: uuid.UUID
    outbox_id: uuid.UUID
    gate_id: uuid.UUID
    gate_version: int = Field(strict=True, gt=0)
    gate_sequence: int = Field(strict=True, gt=0)
    node_name: str = Field(min_length=1, max_length=100)
    thread_id: str = Field(min_length=1, max_length=128)
    source_checkpoint_id: str = Field(min_length=1, max_length=128)
    resumed_checkpoint_id: str = Field(min_length=1, max_length=128)
    deserialized_state_sha256: str = Field(pattern=SHA256_PATTERN)
    serializer_id: Literal[CHECKPOINT_SERIALIZER_ID]
    worker_identity: str = Field(min_length=1, max_length=255)


class _CheckpointResumeArtifact(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1] = 1
    artifact_kind: Literal["checkpoint_resume_convergence"]
    probe_nonce: uuid.UUID
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    receipts: list[_CheckpointEffect] = Field(
        min_length=1, max_length=MAX_PROBE_RECEIPTS
    )
    manifest_sha256: str = Field(pattern=SHA256_PATTERN)
    signature: _Signature


def _artifact_body(model: BaseModel) -> dict[str, Any]:
    return model.model_dump(mode="json", exclude={"manifest_sha256", "signature"})


async def _verify_probe_artifact(model: BaseModel, signer: DigestSigner) -> bool:
    digest = hashlib.sha256(canonical_json(_artifact_body(model))).digest()
    signature = model.signature
    return digest.hex() == model.manifest_sha256 and await signer.verify_sha256(
        digest,
        DigestSignature(
            signature_b64=signature.signature_b64,
            algorithm=signature.algorithm,
            key_id=signature.key_id,
        ),
    )


def _bounded_json_file(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise RuntimeError(f"restore artifact is missing or unsafe: {path}")
    resolved = path.resolve(strict=True)
    size = resolved.stat().st_size
    if size <= 0 or size > MAX_ARTIFACT_BYTES:
        raise RuntimeError("restore artifact size is outside the approved bound")
    payload = json.loads(resolved.read_bytes())
    if not isinstance(payload, dict):
        raise RuntimeError("restore artifact must be a JSON object")
    return payload


def _request_digest(
    payload: Sequence[dict[str, Any]], *, probe_nonce: uuid.UUID
) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "schema_version": 1,
                "probe_nonce": str(probe_nonce),
                "requests": list(payload),
            }
        )
    ).hexdigest()


def _authorization(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _bounded_response(response: httpx.Response) -> bytes:
    response.raise_for_status()
    content = response.content
    if not content or len(content) > MAX_ARTIFACT_BYTES:
        raise RuntimeError("recovery probe response size is outside the approved bound")
    return content


class _ProductionOutboxReplayProbe:
    """Publish through RabbitMQ and accept only signed durable consumer effects."""

    def __init__(
        self,
        *,
        db: AsyncSession,
        signer: DigestSigner,
        client: httpx.AsyncClient,
        receipt_url: str,
        bearer_token: str,
    ) -> None:
        self.db = db
        self.signer = signer
        self.client = client
        self.receipt_url = receipt_url
        self.bearer_token = bearer_token

    async def __call__(
        self, requests: Sequence[OutboxReplayRequest]
    ) -> Sequence[OutboxReplayReceipt]:
        expected_ids = {request.outbox_id for request in requests}
        rows = list(
            (
                await self.db.scalars(
                    select(db_models.ScanOutbox).where(
                        db_models.ScanOutbox.id.in_(expected_ids),
                        db_models.ScanOutbox.published_at.is_(None),
                    )
                )
            ).all()
        )
        if len(rows) != len(expected_ids) or {row.id for row in rows} != expected_ids:
            raise RuntimeError("outbox replay selection changed before publication")
        request_by_id = {request.outbox_id: request for request in requests}
        wire_requests: list[dict[str, Any]] = []
        for row in rows:
            request = request_by_id[row.id]
            payload_sha256 = hashlib.sha256(canonical_json(row.payload)).hexdigest()
            if (
                payload_sha256 != request.payload_sha256
                or row.scan_id != request.scan_id
                or row.attempt_id != request.attempt_id
                or row.queue_name != request.queue_name
            ):
                raise RuntimeError("outbox replay identity changed before publication")
            payload = dict(row.payload)
            correlation_id = payload.pop("correlation_id", None)
            if not await publish_message(
                queue_name=row.queue_name,
                message_body=payload,
                correlation_id=correlation_id,
            ):
                raise RuntimeError("outbox replay publication failed")
            wire_requests.append(
                {
                    "outbox_id": str(row.id),
                    "scan_id": str(row.scan_id),
                    "attempt_id": str(row.attempt_id) if row.attempt_id else None,
                    "queue_name": row.queue_name,
                    "payload_sha256": payload_sha256,
                }
            )
        wire_requests.sort(key=lambda item: item["outbox_id"])
        probe_nonce = uuid.uuid4()
        request_sha256 = _request_digest(wire_requests, probe_nonce=probe_nonce)
        response = await self.client.post(
            self.receipt_url,
            headers=_authorization(self.bearer_token),
            json={
                "schema_version": 1,
                "artifact_kind": "outbox_replay_request",
                "probe_nonce": str(probe_nonce),
                "request_sha256": request_sha256,
                "requests": wire_requests,
            },
        )
        artifact = _OutboxReplayArtifact.model_validate_json(
            _bounded_response(response)
        )
        if (
            artifact.probe_nonce != probe_nonce
            or artifact.request_sha256 != request_sha256
            or not await _verify_probe_artifact(artifact, self.signer)
        ):
            raise RuntimeError("outbox recovery receipt signature or request mismatch")
        effects = {receipt.outbox_id: receipt for receipt in artifact.receipts}
        if len(effects) != len(artifact.receipts) or set(effects) != expected_ids:
            raise RuntimeError("outbox recovery receipts do not exactly match requests")
        durable_ids = {receipt.durable_receipt_id for receipt in artifact.receipts}
        if len(durable_ids) != len(artifact.receipts):
            raise RuntimeError("outbox recovery durable receipt identity is duplicated")
        for request in requests:
            if effects[request.outbox_id].payload_sha256 != request.payload_sha256:
                raise RuntimeError("outbox recovery receipt payload digest mismatch")
        repository = ScanOutboxRepository(self.db)
        for request in requests:
            await repository.mark_published(request.outbox_id)
        return [
            OutboxReplayReceipt(
                outbox_id=effect.outbox_id,
                effect_sha256=effect.effect_sha256,
                durable_receipt_id=effect.durable_receipt_id,
                converged=True,
            )
            for effect in artifact.receipts
        ]


class _SignedCheckpointResumeProbe:
    """Invoke the isolated worker harness and verify its exact signed advancement."""

    def __init__(
        self,
        *,
        signer: DigestSigner,
        client: httpx.AsyncClient,
        resume_url: str,
        bearer_token: str,
    ) -> None:
        self.signer = signer
        self.client = client
        self.resume_url = resume_url
        self.bearer_token = bearer_token

    async def __call__(
        self, requests: Sequence[CheckpointResumeRequest]
    ) -> Sequence[CheckpointResumeReceipt]:
        wire_requests = sorted(
            (
                {
                    "scan_id": str(request.scan_id),
                    "tenant_id": str(request.tenant_id),
                    "attempt_id": str(request.attempt_id),
                    "outbox_id": str(request.outbox_id),
                    "gate_id": str(request.gate_id),
                    "gate_version": request.gate_version,
                    "gate_sequence": request.gate_sequence,
                    "node_name": request.node_name,
                    "thread_id": request.thread_id,
                    "checkpoint_ns": request.checkpoint_ns,
                    "checkpoint_id": request.checkpoint_id,
                    "state_sha256": request.state_sha256,
                    "serializer_id": CHECKPOINT_SERIALIZER_ID,
                }
                for request in requests
            ),
            key=lambda item: (item["thread_id"], item["checkpoint_id"]),
        )
        probe_nonce = uuid.uuid4()
        request_sha256 = _request_digest(wire_requests, probe_nonce=probe_nonce)
        response = await self.client.post(
            self.resume_url,
            headers=_authorization(self.bearer_token),
            json={
                "schema_version": 1,
                "artifact_kind": "checkpoint_resume_request",
                "probe_nonce": str(probe_nonce),
                "request_sha256": request_sha256,
                "requests": wire_requests,
            },
        )
        artifact = _CheckpointResumeArtifact.model_validate_json(
            _bounded_response(response)
        )
        if (
            artifact.probe_nonce != probe_nonce
            or artifact.request_sha256 != request_sha256
            or not await _verify_probe_artifact(artifact, self.signer)
        ):
            raise RuntimeError("checkpoint resume signature or request mismatch")
        expected = {(request.scan_id, request.checkpoint_id) for request in requests}
        observed = {
            (receipt.scan_id, receipt.source_checkpoint_id)
            for receipt in artifact.receipts
        }
        if len(observed) != len(artifact.receipts) or observed != expected:
            raise RuntimeError(
                "checkpoint resume receipts do not exactly match requests"
            )
        request_by_identity = {
            (request.scan_id, request.checkpoint_id): request for request in requests
        }
        receipts: list[CheckpointResumeReceipt] = []
        for effect in artifact.receipts:
            request = request_by_identity[(effect.scan_id, effect.source_checkpoint_id)]
            if (
                effect.thread_id != request.thread_id
                or effect.tenant_id != request.tenant_id
                or effect.attempt_id != request.attempt_id
                or effect.outbox_id != request.outbox_id
                or effect.gate_id != request.gate_id
                or effect.gate_version != request.gate_version
                or effect.gate_sequence != request.gate_sequence
                or effect.node_name != request.node_name
                or effect.deserialized_state_sha256 != request.state_sha256
                or effect.resumed_checkpoint_id == effect.source_checkpoint_id
            ):
                raise RuntimeError("checkpoint resume identity did not advance exactly")
            receipts.append(
                CheckpointResumeReceipt(
                    scan_id=effect.scan_id,
                    tenant_id=effect.tenant_id,
                    attempt_id=effect.attempt_id,
                    outbox_id=effect.outbox_id,
                    gate_id=effect.gate_id,
                    gate_version=effect.gate_version,
                    gate_sequence=effect.gate_sequence,
                    node_name=effect.node_name,
                    thread_id=effect.thread_id,
                    source_checkpoint_id=effect.source_checkpoint_id,
                    resumed_checkpoint_id=effect.resumed_checkpoint_id,
                    deserialized_state_sha256=effect.deserialized_state_sha256,
                    serializer_id=effect.serializer_id,
                    worker_identity=effect.worker_identity,
                )
            )
        return receipts


class _ProductionGovernanceRecoveryProbe:
    """Resume durable four-store operations through the production coordinator."""

    def __init__(self, service: GovernanceService) -> None:
        self.service = service

    async def __call__(
        self, requests: Sequence[GovernanceRecoveryRequest]
    ) -> Sequence[GovernanceRecoveryReceipt]:
        receipts: list[GovernanceRecoveryReceipt] = []
        for request in requests:
            operation = await self.service.execute(
                request.operation_id,
                expected_tenant_id=request.tenant_id,
            )
            if operation.status != "completed" or not operation.manifest_sha256:
                raise RuntimeError("governance operation did not converge")
            receipts.append(
                GovernanceRecoveryReceipt(
                    operation_id=operation.id,
                    tenant_id=operation.tenant_id,
                    status=operation.status,
                    manifest_sha256=operation.manifest_sha256,
                )
            )
        return receipts


def _default_checkpoint_dsn() -> str:
    configured = os.environ.get("RESTORE_CHECKPOINT_DSN", "").strip()
    if configured:
        return configured
    return str(settings.ASYNC_DATABASE_URL).replace(
        "postgresql+asyncpg://", "postgresql://", 1
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    qdrant_artifact = os.environ.get("RESTORE_QDRANT_ARTIFACT", "").strip()
    governance_root = os.environ.get("GOVERNANCE_ARTIFACT_ROOT", "").strip()
    parser.set_defaults(
        probe_bearer_token=os.environ.get("RESTORE_PROBE_BEARER_TOKEN", "").strip(),
        observability_token=os.environ.get(
            "GOVERNANCE_OBSERVABILITY_BEARER_TOKEN", ""
        ).strip(),
    )
    parser.add_argument(
        "--max-evidence-objects",
        type=int,
        default=0,
        help="0 verifies every available evidence object; a positive value bounds drills.",
    )
    parser.add_argument("--checkpoint-dsn", default=_default_checkpoint_dsn())
    parser.add_argument(
        "--qdrant-restore-artifact",
        type=Path,
        default=Path(qdrant_artifact) if qdrant_artifact else None,
    )
    parser.add_argument(
        "--governance-artifact-root",
        type=Path,
        default=Path(governance_root) if governance_root else None,
    )
    parser.add_argument(
        "--observability-expected-sha256",
        default=os.environ.get("RESTORE_EXPECTED_OBSERVABILITY_SHA256", ""),
    )
    parser.add_argument(
        "--outbox-receipt-url",
        default=os.environ.get("RESTORE_OUTBOX_RECEIPT_URL", ""),
    )
    parser.add_argument(
        "--checkpoint-resume-url",
        default=os.environ.get("RESTORE_CHECKPOINT_RESUME_URL", ""),
    )
    parser.add_argument(
        "--allow-loopback-http",
        action="store_true",
        default=os.environ.get("RESTORE_ALLOW_LOOPBACK_HTTP", "").lower()
        in {"1", "true", "yes"},
        help="Allow authenticated HTTP only to an exact loopback host.",
    )
    parser.add_argument(
        "--observability-url",
        default=os.environ.get("GOVERNANCE_OBSERVABILITY_URL", ""),
    )
    return parser


def _validate_args(parser: argparse.ArgumentParser, args: argparse.Namespace) -> None:
    if args.max_evidence_objects < 0:
        parser.error("--max-evidence-objects must be non-negative")
    required = {
        "--checkpoint-dsn": args.checkpoint_dsn,
        "--qdrant-restore-artifact": str(args.qdrant_restore_artifact),
        "--governance-artifact-root": str(args.governance_artifact_root),
        "--observability-expected-sha256": args.observability_expected_sha256,
        "--outbox-receipt-url": args.outbox_receipt_url,
        "--checkpoint-resume-url": args.checkpoint_resume_url,
        "RESTORE_PROBE_BEARER_TOKEN": args.probe_bearer_token,
        "--observability-url": args.observability_url,
        "GOVERNANCE_OBSERVABILITY_BEARER_TOKEN": args.observability_token,
    }
    missing = [name for name, value in required.items() if not str(value).strip()]
    if missing:
        parser.error(f"required restore inputs missing: {', '.join(missing)}")
    if (
        args.qdrant_restore_artifact.is_symlink()
        or not args.qdrant_restore_artifact.is_file()
    ):
        parser.error("--qdrant-restore-artifact must be a regular non-symlink file")
    if (
        args.governance_artifact_root.is_symlink()
        or not args.governance_artifact_root.is_dir()
    ):
        parser.error("--governance-artifact-root must be a non-symlink directory")
    for name, value in (
        ("--outbox-receipt-url", args.outbox_receipt_url),
        ("--checkpoint-resume-url", args.checkpoint_resume_url),
    ):
        parsed = urllib.parse.urlsplit(value)
        loopback_http = (
            parsed.scheme == "http"
            and parsed.hostname in {"127.0.0.1", "::1"}
            and parsed.username is None
            and parsed.password is None
        )
        if parsed.scheme != "https" and not (
            args.allow_loopback_http and loopback_http
        ):
            parser.error(
                f"{name} must use HTTPS; authenticated loopback HTTP requires "
                "--allow-loopback-http"
            )
    if not args.observability_url.startswith("https://"):
        parser.error("--observability-url must use https://")
    digest = args.observability_expected_sha256
    if len(digest) != 64 or set(digest) > set("0123456789abcdef"):
        parser.error("--observability-expected-sha256 must be lowercase SHA-256")
    if not args.checkpoint_dsn.startswith(("postgresql://", "postgres://")):
        parser.error("--checkpoint-dsn must use the psycopg PostgreSQL scheme")


async def _run(args: argparse.Namespace) -> int:
    key_id = os.environ.get("GOVERNANCE_SIGNING_KMS_KEY_ID", "").strip()
    if not key_id:
        raise RuntimeError("GOVERNANCE_SIGNING_KMS_KEY_ID is required.")
    signer = AwsKmsDigestSigner(
        key_id=key_id,
        region=os.environ.get("GOVERNANCE_SIGNING_KMS_REGION", "us-east-1"),
    )
    qdrant_artifact = _bounded_json_file(args.qdrant_restore_artifact)
    with principal_scope(
        tenant_id=None,
        principal_kind="system",
        principal_id="isolated-restore-verifier",
        system_scope=True,
    ):
        qdrant = QdrantStore()
        async with AsyncSessionLocal() as db, httpx.AsyncClient(
            timeout=httpx.Timeout(60.0)
        ) as client:
            object_store = EvidenceObjectStore()
            sink = GovernanceArtifactSink(args.governance_artifact_root)
            governance_service = GovernanceService(
                db,
                signer=signer,
                adapters={
                    "postgres": PostgresGovernanceAdapter(db, sink),
                    "object": ObjectGovernanceAdapter(db, object_store, sink),
                    "qdrant": QdrantGovernanceAdapter(qdrant._client, sink),
                    "observability": ObservabilityGovernanceAdapter(
                        base_url=args.observability_url,
                        bearer_token=args.observability_token,
                        client=client,
                    ),
                },
            )
            outbox_probe = _ProductionOutboxReplayProbe(
                db=db,
                signer=signer,
                client=client,
                receipt_url=args.outbox_receipt_url,
                bearer_token=args.probe_bearer_token,
            )
            checkpoint_probe = _SignedCheckpointResumeProbe(
                signer=signer,
                client=client,
                resume_url=args.checkpoint_resume_url,
                bearer_token=args.probe_bearer_token,
            )
            result = await RestoreVerifier(
                db,
                signer=signer,
                object_store=object_store,
                qdrant_client=qdrant._client,
                qdrant_restore_artifact=qdrant_artifact,
                checkpoint_conn_string=args.checkpoint_dsn,
                observability_url=args.observability_url,
                observability_token=args.observability_token,
                http_client=client,
                governance_artifact_root=args.governance_artifact_root,
                expected_observability_sha256=args.observability_expected_sha256,
                outbox_replay_probe=outbox_probe,
                checkpoint_resume_probe=checkpoint_probe,
                governance_recovery_probe=_ProductionGovernanceRecoveryProbe(
                    governance_service
                ),
            ).run(max_evidence_objects=args.max_evidence_objects)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["report"]["passed"] else 2


def main() -> int:
    parser = _parser()
    args = parser.parse_args()
    _validate_args(parser, args)
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
