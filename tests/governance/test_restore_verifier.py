from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

from app.infrastructure.governance.contracts import StoreActionResult, canonical_json
from app.infrastructure.governance.restore import (
    CHECKPOINT_SERIALIZER_ID,
    CheckpointResumeReceipt,
    GovernanceRecoveryReceipt,
    OutboxReplayReceipt,
    RestoreVerifier,
)
from app.infrastructure.signing import DigestSignature


class _ScalarRows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _MappingRows:
    def __init__(self, row):
        self._row = row

    def mappings(self):
        return self

    def first(self):
        return self._row

    def one_or_none(self):
        return self._row


class _Signer:
    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool:
        return signature.signature_b64 == digest.hex()


def _signed_artifact(body: dict) -> dict:
    digest = hashlib.sha256(canonical_json(body)).digest()
    return {
        **body,
        "manifest_sha256": digest.hex(),
        "signature": {
            "signature_b64": digest.hex(),
            "algorithm": "test-sha256",
            "key_id": "test-key",
        },
    }


class RestoreVerifierContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_outbox_requires_durable_replay_receipts(self) -> None:
        outbox_id = uuid.uuid4()
        row = SimpleNamespace(
            id=outbox_id,
            scan_id=uuid.uuid4(),
            attempt_id=uuid.uuid4(),
            queue_name="scan",
            payload={"kind": "scan", "outbox_id": str(outbox_id)},
        )
        db = SimpleNamespace(
            scalar=AsyncMock(side_effect=[0, 1, 0]),
            scalars=AsyncMock(
                side_effect=[
                    _ScalarRows([row]),
                    _ScalarRows([outbox_id]),
                    _ScalarRows([]),
                ]
            ),
        )

        async def replay(requests):
            return [
                OutboxReplayReceipt(
                    outbox_id=requests[0].outbox_id,
                    effect_sha256="a" * 64,
                    durable_receipt_id="consumer-effect-1",
                    converged=True,
                )
            ]

        verifier = RestoreVerifier(
            db,
            signer=_Signer(),
            object_store=SimpleNamespace(),
            outbox_replay_probe=replay,
        )
        check = await verifier._check_outbox(require_canary=True)
        self.assertTrue(check.passed)
        self.assertEqual(check.evidence["published_after_replay"], 1)

        missing_probe_db = SimpleNamespace(
            scalar=AsyncMock(side_effect=[0, 1]),
            scalars=AsyncMock(return_value=_ScalarRows([row])),
        )
        missing_probe = RestoreVerifier(
            missing_probe_db,
            signer=_Signer(),
            object_store=SimpleNamespace(),
        )
        failed = await missing_probe._check_outbox(require_canary=True)
        self.assertFalse(failed.passed)
        self.assertEqual(
            failed.evidence["reason"], "outbox_replay_probe_not_configured"
        )

    async def test_outbox_rejects_sampled_success_with_pending_rows_remaining(
        self,
    ) -> None:
        outbox_id = uuid.uuid4()
        row = SimpleNamespace(
            id=outbox_id,
            scan_id=uuid.uuid4(),
            attempt_id=uuid.uuid4(),
            queue_name="scan",
            payload={"kind": "scan", "outbox_id": str(outbox_id)},
        )

        async def replay(requests):
            return [
                OutboxReplayReceipt(
                    outbox_id=requests[0].outbox_id,
                    effect_sha256="a" * 64,
                    durable_receipt_id="effect-1",
                    converged=True,
                )
            ]

        db = SimpleNamespace(
            scalar=AsyncMock(side_effect=[0, 1, 1]),
            scalars=AsyncMock(
                side_effect=[
                    _ScalarRows([row]),
                    _ScalarRows([outbox_id]),
                    _ScalarRows([]),
                ]
            ),
        )
        verifier = RestoreVerifier(
            db,
            signer=_Signer(),
            object_store=SimpleNamespace(),
            outbox_replay_probe=replay,
        )
        check = await verifier._check_outbox(require_canary=True)
        self.assertFalse(check.passed)
        self.assertEqual(check.evidence["pending_after_replay"], 1)

    async def test_checkpoint_requires_production_resume_identity(self) -> None:
        scan_id = uuid.uuid4()
        checkpoint_id = "checkpoint-1"
        selected = {
            "scan_id": scan_id,
            "tenant_id": uuid.uuid4(),
            "current_attempt_id": uuid.uuid4(),
            "thread_id": str(scan_id),
            "checkpoint_ns": "",
            "checkpoint_id": checkpoint_id,
            "embedded_checkpoint_id": checkpoint_id,
            "gate_id": uuid.uuid4(),
            "gate_attempt_id": None,
            "gate_version": 1,
            "gate_sequence": 1,
            "node_name": "cost_gate",
            "gate_checkpoint_id": checkpoint_id,
            "outbox_id": uuid.uuid4(),
            "outbox_gate_id": None,
            "outbox_node_name": "cost_gate",
            "outbox_attempt_id": None,
        }
        selected["gate_attempt_id"] = selected["current_attempt_id"]
        selected["outbox_gate_id"] = str(selected["gate_id"])
        selected["outbox_attempt_id"] = str(selected["gate_attempt_id"])
        durable_identity = {
            "scan_id": scan_id,
            "tenant_id": selected["tenant_id"],
            "current_attempt_id": selected["current_attempt_id"],
            "gate_scan_id": scan_id,
            "attempt_id": selected["gate_attempt_id"],
            "gate_state": "completed",
            "version": 1,
            "sequence": 1,
            "node_name": "cost_gate",
            "outbox_id": selected["outbox_id"],
            "outbox_scan_id": scan_id,
            "outbox_attempt_id_fk": selected["gate_attempt_id"],
            "outbox_gate_id": str(selected["gate_id"]),
            "outbox_node_name": "cost_gate",
            "outbox_attempt_id": str(selected["gate_attempt_id"]),
        }
        checkpoint = {
            "id": checkpoint_id,
            "v": 4,
            "channel_versions": {},
            "versions_seen": {},
        }
        exact = SimpleNamespace(
            checkpoint=checkpoint,
            config={
                "configurable": {
                    "thread_id": str(scan_id),
                    "checkpoint_ns": "",
                    "checkpoint_id": checkpoint_id,
                }
            },
            pending_writes=[],
        )
        latest = exact
        resumed = SimpleNamespace(
            checkpoint={**checkpoint, "id": "checkpoint-2"},
            config={
                "configurable": {
                    "thread_id": str(scan_id),
                    "checkpoint_ns": "",
                    "checkpoint_id": "checkpoint-2",
                }
            },
            pending_writes=[],
        )

        async def resume(requests):
            request = requests[0]
            return [
                CheckpointResumeReceipt(
                    scan_id=request.scan_id,
                    tenant_id=request.tenant_id,
                    attempt_id=request.attempt_id,
                    outbox_id=request.outbox_id,
                    gate_id=request.gate_id,
                    gate_version=request.gate_version,
                    gate_sequence=request.gate_sequence,
                    node_name=request.node_name,
                    thread_id=request.thread_id,
                    source_checkpoint_id=request.checkpoint_id,
                    resumed_checkpoint_id="checkpoint-2",
                    deserialized_state_sha256=request.state_sha256,
                    serializer_id=CHECKPOINT_SERIALIZER_ID,
                    worker_identity="isolated-worker-1",
                )
            ]

        db = SimpleNamespace(
            scalar=AsyncMock(side_effect=[True, 0, 1, 1, 1, 0]),
            execute=AsyncMock(
                side_effect=[_MappingRows(selected), _MappingRows(durable_identity)]
            ),
        )
        verifier = RestoreVerifier(
            db,
            signer=_Signer(),
            object_store=SimpleNamespace(),
            checkpoint_conn_string="postgresql://restore",
            checkpoint_resume_probe=resume,
        )
        verifier._decode_checkpoint_pair = AsyncMock(
            side_effect=[(exact, latest), (resumed, resumed)]
        )
        check = await verifier._check_checkpoints(require_canary=True)
        self.assertTrue(check.passed)
        self.assertTrue(check.evidence["production_graph_resume_verified"])

        async def wrong_serializer(requests):
            receipt = (await resume(requests))[0]
            return [
                CheckpointResumeReceipt(
                    **{
                        **receipt.__dict__,
                        "serializer_id": "unsafe-pickle",
                    }
                )
            ]

        bad_db = SimpleNamespace(
            scalar=AsyncMock(side_effect=[True, 0, 1, 1, 1, 0]),
            execute=AsyncMock(return_value=_MappingRows(selected)),
        )
        bad = RestoreVerifier(
            bad_db,
            signer=_Signer(),
            object_store=SimpleNamespace(),
            checkpoint_conn_string="postgresql://restore",
            checkpoint_resume_probe=wrong_serializer,
        )
        bad._decode_checkpoint_pair = AsyncMock(return_value=(exact, latest))
        self.assertFalse((await bad._check_checkpoints(require_canary=True)).passed)

    def test_governance_artifact_is_dereferenced_and_hashed(self) -> None:
        operation_id = uuid.uuid4()
        payload = b'{"schema_version":1}'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            directory = root / str(operation_id)
            directory.mkdir()
            path = directory / "postgres.json"
            path.write_bytes(payload)
            result = StoreActionResult(
                store="postgres",
                kind="export",
                operation_id=operation_id,
                matched_count=1,
                applied_count=1,
                content_sha256=hashlib.sha256(payload).hexdigest(),
                artifact_ref=f"governance/{operation_id}/postgres.json",
            )
            verifier = RestoreVerifier(
                SimpleNamespace(),
                signer=_Signer(),
                object_store=SimpleNamespace(),
                governance_artifact_root=root,
            )
            operation = SimpleNamespace(
                id=operation_id,
                tenant_id=uuid.uuid4(),
                scope={"scope_type": "tenant", "scope_id": str(uuid.uuid4())},
            )
            verifier._verify_governance_artifact(operation, result)
            path.write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "digest_mismatch"):
                verifier._verify_governance_artifact(operation, result)

    def test_object_export_verifies_exact_ciphertext_file_set(self) -> None:
        operation_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        evidence_id = uuid.uuid4()
        scope = {"scope_type": "tenant", "scope_id": str(tenant_id)}
        ciphertext = b"ciphertext"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operation_root = root / str(operation_id)
            objects_root = operation_root / "objects"
            objects_root.mkdir(parents=True)
            (objects_root / str(evidence_id)).write_bytes(ciphertext)
            manifest = {
                "schema_version": 1,
                "artifact_kind": "object_export",
                "operation_id": str(operation_id),
                "tenant_id": str(tenant_id),
                "scope": scope,
                "records": [
                    {
                        "id": str(evidence_id),
                        "state": "live",
                        "relative_path": f"objects/{evidence_id}",
                        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                        "size_bytes": len(ciphertext),
                    }
                ],
            }
            payload = canonical_json(manifest)
            (operation_root / "object.json").write_bytes(payload)
            result = StoreActionResult(
                store="object",
                kind="export",
                operation_id=operation_id,
                matched_count=1,
                applied_count=1,
                content_sha256=hashlib.sha256(payload).hexdigest(),
                artifact_ref=f"governance/{operation_id}/object.json",
            )
            operation = SimpleNamespace(
                id=operation_id, tenant_id=tenant_id, scope=scope
            )
            verifier = RestoreVerifier(
                SimpleNamespace(),
                signer=_Signer(),
                object_store=SimpleNamespace(),
                governance_artifact_root=root,
            )
            verifier._verify_governance_artifact(operation, result)
            (objects_root / "extra").write_bytes(b"not-bound")
            with self.assertRaisesRegex(ValueError, "file_set_mismatch"):
                verifier._verify_governance_artifact(operation, result)

    def test_object_export_accepts_bound_deleted_metadata_without_file(self) -> None:
        operation_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        evidence_id = uuid.uuid4()
        scope = {"scope_type": "tenant", "scope_id": str(tenant_id)}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            operation_root = root / str(operation_id)
            operation_root.mkdir()
            manifest = {
                "schema_version": 1,
                "artifact_kind": "object_export",
                "operation_id": str(operation_id),
                "tenant_id": str(tenant_id),
                "scope": scope,
                "records": [
                    {
                        "id": str(evidence_id),
                        "state": "deleted",
                        "relative_path": None,
                        "ciphertext_sha256": "a" * 64,
                        "size_bytes": None,
                    }
                ],
            }
            payload = canonical_json(manifest)
            (operation_root / "object.json").write_bytes(payload)
            result = StoreActionResult(
                store="object",
                kind="export",
                operation_id=operation_id,
                matched_count=1,
                applied_count=1,
                content_sha256=hashlib.sha256(payload).hexdigest(),
                artifact_ref=f"governance/{operation_id}/object.json",
            )
            verifier = RestoreVerifier(
                SimpleNamespace(),
                signer=_Signer(),
                object_store=SimpleNamespace(),
                governance_artifact_root=root,
            )
            verifier._verify_governance_artifact(
                SimpleNamespace(id=operation_id, tenant_id=tenant_id, scope=scope),
                result,
            )

    async def test_manifest_entries_must_link_every_evidence_object(self) -> None:
        attempt_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        evidence_id = uuid.uuid4()
        evidence = SimpleNamespace(
            id=evidence_id,
            attempt_id=attempt_id,
            scan_id=scan_id,
            object_key="tenant/evidence/object",
            object_version="v1",
            artifact_type="report",
            version=1,
            plaintext_sha256="a" * 64,
        )
        entry = {
            "evidence_id": str(evidence_id),
            "artifact_type": "report",
            "version": 1,
            "plaintext_sha256": "a" * 64,
            "object_version": "v1",
            "created_at": None,
        }
        body = {
            "attempt_id": str(attempt_id),
            "generation": 1,
            "previous_manifest_sha256": None,
            "entries": [entry],
        }
        manifest = SimpleNamespace(
            id=uuid.uuid4(),
            attempt_id=attempt_id,
            scan_id=scan_id,
            generation=1,
            previous_manifest_sha256=None,
            manifest_sha256=hashlib.sha256(canonical_json(body)).hexdigest(),
            entries=[entry],
            finalized=False,
        )
        verifier = RestoreVerifier(
            SimpleNamespace(
                scalars=AsyncMock(
                    side_effect=[_ScalarRows([manifest]), _ScalarRows([evidence])]
                )
            ),
            signer=_Signer(),
            object_store=SimpleNamespace(),
        )
        self.assertTrue(
            (await verifier._check_evidence_manifests(require_canary=True)).passed
        )
        missing = RestoreVerifier(
            SimpleNamespace(
                scalars=AsyncMock(
                    side_effect=[_ScalarRows([manifest]), _ScalarRows([])]
                )
            ),
            signer=_Signer(),
            object_store=SimpleNamespace(),
        )
        self.assertFalse(
            (await missing._check_evidence_manifests(require_canary=True)).passed
        )
        mismatched_entry = {**entry, "plaintext_sha256": "b" * 64}
        mismatched_body = {**body, "entries": [mismatched_entry]}
        mismatched_manifest = SimpleNamespace(
            **{
                **manifest.__dict__,
                "entries": [mismatched_entry],
                "manifest_sha256": hashlib.sha256(
                    canonical_json(mismatched_body)
                ).hexdigest(),
            }
        )
        mismatched = RestoreVerifier(
            SimpleNamespace(
                scalars=AsyncMock(
                    side_effect=[
                        _ScalarRows([mismatched_manifest]),
                        _ScalarRows([evidence]),
                    ]
                )
            ),
            signer=_Signer(),
            object_store=SimpleNamespace(),
        )
        self.assertFalse(
            (await mismatched._check_evidence_manifests(require_canary=True)).passed
        )

    async def test_incomplete_governance_operation_requires_real_recovery(self) -> None:
        operation = SimpleNamespace(
            id=uuid.uuid4(), tenant_id=uuid.uuid4(), status="executing"
        )
        verifier = RestoreVerifier(
            SimpleNamespace(scalars=AsyncMock(return_value=_ScalarRows([operation]))),
            signer=_Signer(),
            object_store=SimpleNamespace(),
        )
        check = await verifier._check_governance_convergence(require_canary=True)
        self.assertFalse(check.passed)
        self.assertEqual(
            check.evidence["reason"], "governance_recovery_probe_not_configured"
        )

    async def test_recovered_operation_requires_its_own_valid_signature(self) -> None:
        operation_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        manifest = {"schema_version": 1, "operation_id": str(operation_id)}
        manifest_sha256 = hashlib.sha256(canonical_json(manifest)).hexdigest()
        recovering = SimpleNamespace(
            id=operation_id, tenant_id=tenant_id, status="failed"
        )
        recovered = SimpleNamespace(
            id=operation_id,
            tenant_id=tenant_id,
            status="completed",
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            signature_b64="0" * 64,
            signature_algorithm="test-sha256",
            signing_key_id="test-key",
        )

        async def recover(_requests):
            return [
                GovernanceRecoveryReceipt(
                    operation_id=operation_id,
                    tenant_id=tenant_id,
                    status="completed",
                    manifest_sha256=manifest_sha256,
                )
            ]

        verifier = RestoreVerifier(
            SimpleNamespace(
                scalars=AsyncMock(
                    side_effect=[_ScalarRows([recovering]), _ScalarRows([recovered])]
                )
            ),
            signer=_Signer(),
            object_store=SimpleNamespace(),
            governance_recovery_probe=recover,
        )
        check = await verifier._check_governance_convergence(require_canary=True)
        self.assertFalse(check.passed)
        self.assertEqual(check.evidence["error_class"], "ValueError")

    async def test_qdrant_inventory_is_signed_content_and_tenant_bound(self) -> None:
        tenant_id = uuid.uuid4()
        point = SimpleNamespace(
            id="point-1",
            payload={"tenant_id": str(tenant_id), "document": "canary"},
            vector=[0.1, 0.2],
        )
        points = [
            {
                "id": "point-1",
                "payload": point.payload,
                "vector": point.vector,
            }
        ]
        content_sha256 = hashlib.sha256(
            canonical_json(
                {"schema_version": 1, "collection": "tenant-canary", "points": points}
            )
        ).hexdigest()
        body = {
            "schema_version": 1,
            "artifact_kind": "qdrant_restore",
            "collections": [
                {
                    "name": "tenant-canary",
                    "points_count": 1,
                    "content_sha256": content_sha256,
                    "snapshot_name": "restore.snapshot",
                    "snapshot_size": 123,
                    "snapshot_sha256": "c" * 64,
                }
            ],
        }
        qdrant = SimpleNamespace(
            get_collections=lambda: SimpleNamespace(
                collections=[SimpleNamespace(name="tenant-canary")]
            ),
            scroll=lambda **_kwargs: ([point], None),
            list_snapshots=lambda **_kwargs: [
                SimpleNamespace(name="restore.snapshot", size=123, checksum="c" * 64)
            ],
        )
        db = SimpleNamespace(scalars=AsyncMock(return_value=_ScalarRows([tenant_id])))
        verifier = RestoreVerifier(
            db,
            signer=_Signer(),
            object_store=SimpleNamespace(),
            qdrant_client=qdrant,
            qdrant_restore_artifact=_signed_artifact(body),
        )
        check = await verifier._check_qdrant_restore()
        self.assertTrue(check.passed)
        self.assertEqual(check.evidence["tenant_canary_points"], 1)

        point.payload["tenant_id"] = str(uuid.uuid4())
        self.assertFalse((await verifier._check_qdrant_restore()).passed)

    async def test_observability_requires_pinned_signed_digest(self) -> None:
        content_sha256 = "d" * 64
        artifact = _signed_artifact(
            {
                "schema_version": 1,
                "artifact_kind": "observability_restore",
                "artifact_ref": "backups/observability/restore.json",
                "snapshot_id": "snapshot-1",
                "record_count": 42,
                "content_sha256": content_sha256,
                "verified_content_sha256": content_sha256,
            }
        )
        response = SimpleNamespace(
            content=json.dumps(artifact).encode(),
            raise_for_status=lambda: None,
        )
        client = SimpleNamespace(get=AsyncMock(return_value=response))
        verifier = RestoreVerifier(
            SimpleNamespace(),
            signer=_Signer(),
            object_store=SimpleNamespace(),
            observability_url="https://observability.example",
            observability_token="secret",
            http_client=client,
            expected_observability_sha256=content_sha256,
        )
        self.assertTrue((await verifier._check_observability_restore()).passed)

        verifier.expected_observability_sha256 = "e" * 64
        self.assertFalse((await verifier._check_observability_restore()).passed)


if __name__ == "__main__":
    unittest.main()
