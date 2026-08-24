from __future__ import annotations

import hashlib
import os
import unittest
import uuid
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException

from app.infrastructure.database.tenant_context import (
    principal_id_var,
    system_scope_var,
)
from app.infrastructure.governance.contracts import canonical_json
from app.infrastructure.signing import DigestSignature
from app.scripts import generate_qdrant_restore_artifact as generator
from app.scripts import restore_recovery_gateway as gateway


class _Signer:
    async def sign_sha256(self, digest: bytes) -> DigestSignature:
        return DigestSignature(
            signature_b64=digest.hex(),
            algorithm="test-sha256",
            key_id="test-key",
        )


class _QdrantClient:
    def get_collections(self):
        return SimpleNamespace(collections=[SimpleNamespace(name="canary")])

    def scroll(self, **_kwargs):
        return (
            [
                SimpleNamespace(
                    id="point-1",
                    payload={"tenant_id": str(uuid.uuid4()), "text": "canary"},
                    vector=[0.1, 0.2],
                )
            ],
            None,
        )

    def list_snapshots(self, **_kwargs):
        return [SimpleNamespace(name="snapshot-1", size=123, checksum="a" * 64)]


class RestoreOperationalToolTests(unittest.IsolatedAsyncioTestCase):
    def _checkpoint_request(self) -> gateway._CheckpointRequest:
        scan_id = uuid.uuid4()
        checkpoint = {"id": "checkpoint-1", "values": {"canary": True}}
        return gateway._CheckpointRequest(
            scan_id=scan_id,
            tenant_id=uuid.uuid4(),
            attempt_id=uuid.uuid4(),
            outbox_id=uuid.uuid4(),
            gate_id=uuid.uuid4(),
            gate_version=1,
            gate_sequence=1,
            node_name="cost_gate",
            thread_id=str(scan_id),
            checkpoint_ns="",
            checkpoint_id="checkpoint-1",
            state_sha256=hashlib.sha256(canonical_json(checkpoint)).hexdigest(),
            serializer_id=gateway.CHECKPOINT_SERIALIZER_ID,
        )

    async def test_gateway_runs_request_under_explicit_system_principal(self) -> None:
        observed = {}

        async def call_next(_request):
            observed["system_scope"] = system_scope_var.get()
            observed["principal_id"] = principal_id_var.get()
            return "ok"

        result = await gateway._system_principal_scope(object(), call_next)
        self.assertEqual(result, "ok")
        self.assertTrue(observed["system_scope"])
        self.assertEqual(observed["principal_id"], "isolated-restore-recovery-gateway")
        self.assertFalse(system_scope_var.get())

    def test_gateway_requires_exact_bearer_token(self) -> None:
        with patch.dict(os.environ, {"RESTORE_PROBE_BEARER_TOKEN": "drill-secret"}):
            gateway._authorize("Bearer drill-secret")
            with self.assertRaises(HTTPException):
                gateway._authorize("Bearer wrong")

    def test_gateway_rejects_stale_or_raced_checkpoint_identity(self) -> None:
        item = self._checkpoint_request()
        expected = SimpleNamespace(
            config={
                "configurable": {
                    "thread_id": item.thread_id,
                    "checkpoint_ns": item.checkpoint_ns,
                    "checkpoint_id": item.checkpoint_id,
                }
            },
            checkpoint={"id": "checkpoint-1", "values": {"canary": True}},
        )
        self.assertTrue(gateway._source_tuple_matches(expected, item))
        raced = SimpleNamespace(
            config={
                "configurable": {
                    "thread_id": item.thread_id,
                    "checkpoint_ns": item.checkpoint_ns,
                    "checkpoint_id": "checkpoint-2",
                }
            },
            checkpoint={"id": "checkpoint-2", "values": {"canary": True}},
        )
        self.assertFalse(gateway._source_tuple_matches(raced, item))
        wrong_thread = SimpleNamespace(
            config={
                "configurable": {
                    "thread_id": str(uuid.uuid4()),
                    "checkpoint_ns": item.checkpoint_ns,
                    "checkpoint_id": item.checkpoint_id,
                }
            },
            checkpoint=expected.checkpoint,
        )
        self.assertFalse(gateway._source_tuple_matches(wrong_thread, item))

    def test_gateway_requires_resumable_gate_state_and_scan_thread(self) -> None:
        item = self._checkpoint_request()
        scan = SimpleNamespace(
            tenant_id=item.tenant_id, current_attempt_id=item.attempt_id
        )
        gate = SimpleNamespace(
            scan_id=item.scan_id,
            attempt_id=item.attempt_id,
            version=item.gate_version,
            sequence=item.gate_sequence,
            node_name=item.node_name,
            checkpoint_id=item.checkpoint_id,
            state="decided",
        )
        outbox = SimpleNamespace(
            scan_id=item.scan_id,
            attempt_id=item.attempt_id,
            payload={"gate_id": str(item.gate_id)},
        )
        self.assertTrue(gateway._resume_rows_match(scan, gate, outbox, item))
        gate.state = "completed"
        self.assertFalse(gateway._resume_rows_match(scan, gate, outbox, item))
        gate.state = "decided"
        wrong_thread_item = item.model_copy(update={"thread_id": str(uuid.uuid4())})
        self.assertFalse(
            gateway._resume_rows_match(scan, gate, outbox, wrong_thread_item)
        )

    async def test_qdrant_generator_binds_points_snapshot_and_signature(self) -> None:
        artifact = await generator.build_artifact(
            _QdrantClient(), _Signer(), {"canary": "snapshot-1"}
        )
        self.assertEqual(artifact["collections"][0]["points_count"], 1)
        self.assertEqual(artifact["collections"][0]["snapshot_sha256"], "a" * 64)
        body = {
            key: value
            for key, value in artifact.items()
            if key not in {"manifest_sha256", "signature"}
        }
        digest = hashlib.sha256(canonical_json(body)).hexdigest()
        self.assertEqual(artifact["manifest_sha256"], digest)
        self.assertEqual(artifact["signature"]["signature_b64"], digest)

    async def test_qdrant_generator_requires_explicit_snapshot_per_collection(
        self,
    ) -> None:
        with self.assertRaisesRegex(ValueError, "every collection"):
            await generator.build_artifact(_QdrantClient(), _Signer(), {})


if __name__ == "__main__":
    unittest.main()
