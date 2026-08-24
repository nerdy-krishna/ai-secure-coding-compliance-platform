"""Loopback-only operator gateway for isolated restore recovery probes."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import os
import uuid
from typing import Any, Literal

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.tenant_context import principal_scope
from app.infrastructure.governance.contracts import canonical_json
from app.infrastructure.governance.restore import (
    CHECKPOINT_SERIALIZER_ID,
    _json_safe,
)
from app.infrastructure.signing import AwsKmsDigestSigner
from app.infrastructure.workflows.state import WorkerState
from app.workers.consumer import (
    _current_checkpoint_id,
    _run_workflow_for_scan,
    get_workflow,
)


SHA256_PATTERN = r"^[0-9a-f]{64}$"
MAX_REQUESTS = 10
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def _system_principal_scope(request: Any, call_next: Any) -> Any:
    """Give the authenticated operator gateway explicit forced-RLS system scope."""

    with principal_scope(
        tenant_id=None,
        principal_kind="system",
        principal_id="isolated-restore-recovery-gateway",
        system_scope=True,
    ):
        return await call_next(request)


class _OutboxRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    outbox_id: uuid.UUID
    scan_id: uuid.UUID
    attempt_id: uuid.UUID | None
    queue_name: str = Field(min_length=1, max_length=255)
    payload_sha256: str = Field(pattern=SHA256_PATTERN)


class OutboxProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    artifact_kind: Literal["outbox_replay_request"]
    probe_nonce: uuid.UUID
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    requests: list[_OutboxRequest] = Field(min_length=1, max_length=MAX_REQUESTS)


class _CheckpointRequest(BaseModel):
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
    checkpoint_ns: str = Field(max_length=128)
    checkpoint_id: str = Field(min_length=1, max_length=128)
    state_sha256: str = Field(pattern=SHA256_PATTERN)
    serializer_id: Literal[CHECKPOINT_SERIALIZER_ID]


class CheckpointProbeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal[1] = 1
    artifact_kind: Literal["checkpoint_resume_request"]
    probe_nonce: uuid.UUID
    request_sha256: str = Field(pattern=SHA256_PATTERN)
    requests: list[_CheckpointRequest] = Field(min_length=1, max_length=1)


def _expected_request_sha256(nonce: uuid.UUID, requests: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        canonical_json(
            {
                "schema_version": 1,
                "probe_nonce": str(nonce),
                "requests": requests,
            }
        )
    ).hexdigest()


def _authorize(authorization: str) -> None:
    expected = os.environ.get("RESTORE_PROBE_BEARER_TOKEN", "").strip()
    supplied = authorization.removeprefix("Bearer ").strip()
    if not expected or not hmac.compare_digest(expected, supplied):
        raise HTTPException(status_code=401, detail="unauthorized")


def _signer() -> AwsKmsDigestSigner:
    key_id = os.environ.get("GOVERNANCE_SIGNING_KMS_KEY_ID", "").strip()
    if not key_id:
        raise RuntimeError("GOVERNANCE_SIGNING_KMS_KEY_ID is required")
    return AwsKmsDigestSigner(
        key_id=key_id,
        region=os.environ.get("GOVERNANCE_SIGNING_KMS_REGION", "us-east-1"),
    )


async def _signed(body: dict[str, Any]) -> dict[str, Any]:
    digest = hashlib.sha256(canonical_json(body)).digest()
    signature = await _signer().sign_sha256(digest)
    return {
        **body,
        "manifest_sha256": digest.hex(),
        "signature": {
            "signature_b64": signature.signature_b64,
            "algorithm": signature.algorithm,
            "key_id": signature.key_id,
        },
    }


def _initial_state(scan_id: uuid.UUID, attempt_id: uuid.UUID) -> WorkerState:
    return {
        "scan_id": scan_id,
        "attempt_id": attempt_id,
        "scan_type": "AUDIT",
        "current_scan_status": None,
        "distributed_worker_pools": False,
        "reasoning_llm_config_id": None,
        "utility_llm_config_id": None,
        "secondary_reasoning_llm_config_id": None,
        "stage_temperatures": None,
        "disable_temperature": None,
        "cross_file_validation": None,
        "files": None,
        "initial_file_map": None,
        "final_file_map": None,
        "patched_files": None,
        "repository_map": None,
        "dependency_graph": None,
        "file_profiles": None,
        "profiling_approval": None,
        "all_relevant_agents": {},
        "live_codebase": None,
        "findings": [],
        "fix_candidates": None,
        "finding_lineage": None,
        "patch_plan": None,
        "patch_validation_summary": None,
        "agent_results": None,
        "bom_cyclonedx": None,
        "prescan_approval": None,
        "active_approval_gate": None,
        "resume_attempts": None,
        "error_message": None,
        "_batch": 1,
    }


def _checkpoint_tuple_identity(checkpoint_tuple: Any) -> tuple[str, str, str] | None:
    if checkpoint_tuple is None:
        return None
    config = getattr(checkpoint_tuple, "config", None) or {}
    configurable = config.get("configurable", {})
    checkpoint = getattr(checkpoint_tuple, "checkpoint", None) or {}
    thread_id = str(configurable.get("thread_id") or "")
    checkpoint_ns = str(configurable.get("checkpoint_ns") or "")
    checkpoint_id = str(configurable.get("checkpoint_id") or "")
    if (
        not thread_id
        or not checkpoint_id
        or str(checkpoint.get("id") or "") != checkpoint_id
    ):
        return None
    return thread_id, checkpoint_ns, checkpoint_id


def _source_tuple_matches(checkpoint_tuple: Any, item: _CheckpointRequest) -> bool:
    identity = _checkpoint_tuple_identity(checkpoint_tuple)
    checkpoint = getattr(checkpoint_tuple, "checkpoint", None) or {}
    return bool(
        identity == (item.thread_id, item.checkpoint_ns, item.checkpoint_id)
        and hashlib.sha256(canonical_json(_json_safe(checkpoint))).hexdigest()
        == item.state_sha256
    )


def _resume_rows_match(
    scan: Any, gate: Any, outbox: Any, item: _CheckpointRequest
) -> bool:
    return bool(
        scan is not None
        and gate is not None
        and outbox is not None
        and item.thread_id == str(item.scan_id)
        and scan.tenant_id == item.tenant_id
        and scan.current_attempt_id == item.attempt_id
        and gate.scan_id == item.scan_id
        and gate.attempt_id == item.attempt_id
        and gate.version == item.gate_version
        and gate.sequence == item.gate_sequence
        and gate.node_name == item.node_name
        and gate.checkpoint_id == item.checkpoint_id
        and gate.state in {"decided", "resume_claimed"}
        and outbox.scan_id == item.scan_id
        and outbox.attempt_id == item.attempt_id
        and str(outbox.payload.get("gate_id")) == str(item.gate_id)
    )


async def _outbox_effect(row: db_models.ScanOutbox) -> dict[str, Any] | None:
    payload = dict(row.payload)
    workflow = await get_workflow()
    config = {"configurable": {"thread_id": str(row.scan_id)}}
    checkpoint_id = await _current_checkpoint_id(workflow, config)
    async with AsyncSessionLocal() as db:
        scan = await db.get(db_models.Scan, row.scan_id)
        if scan is None or scan.current_attempt_id != row.attempt_id:
            return None
        gate_id = payload.get("gate_id")
        if gate_id:
            gate = await db.get(db_models.ApprovalGate, uuid.UUID(str(gate_id)))
            if (
                gate is None
                or gate.scan_id != row.scan_id
                or gate.attempt_id != row.attempt_id
                or gate.state not in {"resumed", "completed"}
                or not checkpoint_id
                or checkpoint_id == gate.checkpoint_id
            ):
                return None
            effect = {
                "scan_id": str(scan.id),
                "attempt_id": str(scan.current_attempt_id),
                "gate_id": str(gate.gate_id),
                "gate_state": gate.state,
                "checkpoint_id": checkpoint_id,
            }
        elif payload.get("kind") == "report_handoff":
            snapshot = await workflow.aget_state(config)
            values = getattr(snapshot, "values", None) or {}
            if (
                str(values.get("report_handoff_outbox_id") or "") != str(row.id)
                or not checkpoint_id
            ):
                return None
            effect = {
                "scan_id": str(scan.id),
                "attempt_id": str(scan.current_attempt_id),
                "outbox_id": str(row.id),
                "checkpoint_id": checkpoint_id,
            }
        else:
            if not checkpoint_id or scan.status in {"QUEUED", "QUEUED_FOR_SCAN"}:
                return None
            effect = {
                "scan_id": str(scan.id),
                "attempt_id": str(scan.current_attempt_id),
                "scan_status": scan.status,
                "checkpoint_id": checkpoint_id,
            }
    return {
        "outbox_id": str(row.id),
        "payload_sha256": hashlib.sha256(canonical_json(row.payload)).hexdigest(),
        "effect_sha256": hashlib.sha256(canonical_json(effect)).hexdigest(),
        "durable_receipt_id": f"{row.id}:{checkpoint_id}",
        "effect_store": "postgres+langgraph",
        "effect_version": str(checkpoint_id),
    }


@app.post("/v1/restore/outbox-receipts")
async def outbox_receipts(
    request: OutboxProbeRequest,
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    _authorize(authorization)
    wire = [item.model_dump(mode="json") for item in request.requests]
    if request.request_sha256 != _expected_request_sha256(request.probe_nonce, wire):
        raise HTTPException(status_code=400, detail="request digest mismatch")
    timeout = int(os.environ.get("RESTORE_PROBE_EFFECT_TIMEOUT_SECONDS", "300"))
    deadline = asyncio.get_running_loop().time() + max(1, min(timeout, 3600))
    receipts: list[dict[str, Any]] = []
    while asyncio.get_running_loop().time() < deadline:
        receipts = []
        async with AsyncSessionLocal() as db:
            rows = list(
                (
                    await db.scalars(
                        select(db_models.ScanOutbox).where(
                            db_models.ScanOutbox.id.in_(
                                item.outbox_id for item in request.requests
                            )
                        )
                    )
                ).all()
            )
        by_id = {row.id: row for row in rows}
        if set(by_id) != {item.outbox_id for item in request.requests}:
            raise HTTPException(status_code=409, detail="outbox identity missing")
        for item in request.requests:
            row = by_id[item.outbox_id]
            if (
                row.scan_id != item.scan_id
                or row.attempt_id != item.attempt_id
                or row.queue_name != item.queue_name
                or hashlib.sha256(canonical_json(row.payload)).hexdigest()
                != item.payload_sha256
            ):
                raise HTTPException(status_code=409, detail="outbox identity mismatch")
            effect = await _outbox_effect(row)
            if effect is None:
                receipts = []
                break
            receipts.append(effect)
        if len(receipts) == len(request.requests):
            break
        await asyncio.sleep(0.25)
    if len(receipts) != len(request.requests):
        raise HTTPException(status_code=409, detail="durable effects did not converge")
    body = {
        "schema_version": 1,
        "artifact_kind": "outbox_replay_convergence",
        "probe_nonce": str(request.probe_nonce),
        "request_sha256": request.request_sha256,
        "receipts": receipts,
    }
    return await _signed(body)


@app.post("/v1/restore/checkpoint-resume")
async def checkpoint_resume(
    request: CheckpointProbeRequest,
    authorization: str = Header(default=""),
) -> dict[str, Any]:
    _authorize(authorization)
    wire = [item.model_dump(mode="json") for item in request.requests]
    if request.request_sha256 != _expected_request_sha256(request.probe_nonce, wire):
        raise HTTPException(status_code=400, detail="request digest mismatch")
    item = request.requests[0]
    async with AsyncSessionLocal() as db:
        scan = await db.get(db_models.Scan, item.scan_id)
        gate = await db.get(db_models.ApprovalGate, item.gate_id)
        outbox = await db.get(db_models.ScanOutbox, item.outbox_id)
        if not _resume_rows_match(scan, gate, outbox, item):
            raise HTTPException(status_code=409, detail="resume identity mismatch")
        if gate.decision is None:
            raise HTTPException(status_code=409, detail="gate has no durable decision")
        resume_payload = {
            "scan_id": str(item.scan_id),
            "attempt_id": str(item.attempt_id),
            "gate_id": str(item.gate_id),
            "gate_version": gate.version,
            "gate_sequence": gate.sequence,
            "node_name": gate.node_name,
            "evidence_hash": gate.evidence_hash,
            "kind": gate.kind,
            "approved": gate.decision,
            "override_critical_secret": gate.override_critical_secret,
            "approver_user_id": gate.actor_user_id,
        }
    workflow = await get_workflow()
    source_config = {
        "configurable": {
            "thread_id": item.thread_id,
            "checkpoint_ns": item.checkpoint_ns,
            "checkpoint_id": item.checkpoint_id,
        }
    }
    source = await workflow.checkpointer.aget_tuple(source_config)
    if not _source_tuple_matches(source, item):
        raise HTTPException(
            status_code=409, detail="source checkpoint identity mismatch"
        )
    source_sha256 = item.state_sha256
    # The production worker resumes the latest checkpoint for the scan-derived
    # thread. Re-read it immediately before invocation so a stale request or a
    # concurrent advancement cannot be silently redirected to newer state.
    latest_config = {
        "configurable": {
            "thread_id": item.thread_id,
            "checkpoint_ns": item.checkpoint_ns,
        }
    }
    latest = await workflow.checkpointer.aget_tuple(latest_config)
    if not _source_tuple_matches(latest, item):
        raise HTTPException(status_code=409, detail="source checkpoint is not latest")
    timeout = int(os.environ.get("RESTORE_PROBE_RESUME_TIMEOUT_SECONDS", "1800"))
    success = await asyncio.wait_for(
        _run_workflow_for_scan(
            _initial_state(item.scan_id, item.attempt_id),
            resume_payload=resume_payload,
        ),
        timeout=max(1, min(timeout, 3600)),
    )
    if not success:
        raise HTTPException(status_code=409, detail="production worker resume failed")
    resumed = await workflow.checkpointer.aget_tuple(
        {
            "configurable": {
                "thread_id": item.thread_id,
                "checkpoint_ns": item.checkpoint_ns,
            }
        }
    )
    resumed_identity = _checkpoint_tuple_identity(resumed)
    if (
        resumed_identity is None
        or resumed_identity[:2] != (item.thread_id, item.checkpoint_ns)
        or resumed_identity[2] == item.checkpoint_id
    ):
        raise HTTPException(status_code=409, detail="checkpoint did not advance")
    resumed_checkpoint_id = resumed_identity[2]
    body = {
        "schema_version": 1,
        "artifact_kind": "checkpoint_resume_convergence",
        "probe_nonce": str(request.probe_nonce),
        "request_sha256": request.request_sha256,
        "receipts": [
            {
                "scan_id": str(item.scan_id),
                "tenant_id": str(item.tenant_id),
                "attempt_id": str(item.attempt_id),
                "outbox_id": str(item.outbox_id),
                "gate_id": str(item.gate_id),
                "gate_version": item.gate_version,
                "gate_sequence": item.gate_sequence,
                "node_name": item.node_name,
                "thread_id": item.thread_id,
                "source_checkpoint_id": item.checkpoint_id,
                "resumed_checkpoint_id": resumed_checkpoint_id,
                "deserialized_state_sha256": source_sha256,
                "serializer_id": CHECKPOINT_SERIALIZER_ID,
                "worker_identity": "restore-recovery-gateway",
            }
        ],
    }
    return await _signed(body)
