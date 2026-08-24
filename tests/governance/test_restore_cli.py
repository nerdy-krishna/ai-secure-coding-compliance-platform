from __future__ import annotations

import argparse
import hashlib
import json
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

from app.infrastructure.governance.contracts import canonical_json
from app.infrastructure.governance.restore import (
    CHECKPOINT_SERIALIZER_ID,
    CheckpointResumeRequest,
    GovernanceRecoveryRequest,
    OutboxReplayRequest,
)
from app.infrastructure.signing import DigestSignature
from app.scripts import verify_governance_restore as cli


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def all(self):
        return list(self._rows)


class _Signer:
    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool:
        return signature.signature_b64 == digest.hex()


def _signed(body: dict, *, valid: bool = True) -> dict:
    digest = hashlib.sha256(canonical_json(body)).digest()
    return {
        **body,
        "manifest_sha256": digest.hex(),
        "signature": {
            "signature_b64": digest.hex() if valid else "0" * 64,
            "algorithm": "test-sha256",
            "key_id": "test-key",
        },
    }


class _OutboxClient:
    def __init__(self, *, valid_signature: bool = True, stale_nonce: bool = False):
        self.valid_signature = valid_signature
        self.stale_nonce = stale_nonce

    async def post(self, _url, *, headers, json):
        self.request = json
        self.headers = headers
        request = json["requests"][0]
        body = {
            "schema_version": 1,
            "artifact_kind": "outbox_replay_convergence",
            "probe_nonce": (
                str(uuid.uuid4()) if self.stale_nonce else json["probe_nonce"]
            ),
            "request_sha256": json["request_sha256"],
            "receipts": [
                {
                    "outbox_id": request["outbox_id"],
                    "payload_sha256": request["payload_sha256"],
                    "effect_sha256": "a" * 64,
                    "durable_receipt_id": "database-effect-1",
                    "effect_store": "postgres",
                    "effect_version": "1",
                }
            ],
        }
        artifact = _signed(body, valid=self.valid_signature)
        return SimpleNamespace(
            content=json_module(artifact),
            raise_for_status=lambda: None,
        )


class _CheckpointClient:
    def __init__(self, *, advance: bool = True):
        self.advance = advance

    async def post(self, _url, *, headers, json):
        request = json["requests"][0]
        body = {
            "schema_version": 1,
            "artifact_kind": "checkpoint_resume_convergence",
            "probe_nonce": json["probe_nonce"],
            "request_sha256": json["request_sha256"],
            "receipts": [
                {
                    "scan_id": request["scan_id"],
                    "tenant_id": request["tenant_id"],
                    "attempt_id": request["attempt_id"],
                    "outbox_id": request["outbox_id"],
                    "gate_id": request["gate_id"],
                    "gate_version": request["gate_version"],
                    "gate_sequence": request["gate_sequence"],
                    "node_name": request["node_name"],
                    "thread_id": request["thread_id"],
                    "source_checkpoint_id": request["checkpoint_id"],
                    "resumed_checkpoint_id": (
                        "checkpoint-2" if self.advance else request["checkpoint_id"]
                    ),
                    "deserialized_state_sha256": request["state_sha256"],
                    "serializer_id": CHECKPOINT_SERIALIZER_ID,
                    "worker_identity": "isolated-worker-1",
                }
            ],
        }
        return SimpleNamespace(
            content=json_module(_signed(body)),
            raise_for_status=lambda: None,
        )


def json_module(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


class RestoreCliContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_outbox_probe_publishes_and_requires_signed_durable_effect(
        self,
    ) -> None:
        outbox_id = uuid.uuid4()
        scan_id = uuid.uuid4()
        attempt_id = uuid.uuid4()
        payload = {"kind": "scan", "outbox_id": str(outbox_id)}
        row = SimpleNamespace(
            id=outbox_id,
            scan_id=scan_id,
            attempt_id=attempt_id,
            queue_name="scan",
            payload=payload,
        )
        db = SimpleNamespace(
            scalars=AsyncMock(return_value=_Rows([row])),
            execute=AsyncMock(),
            commit=AsyncMock(),
        )
        request = OutboxReplayRequest(
            outbox_id=outbox_id,
            scan_id=scan_id,
            attempt_id=attempt_id,
            queue_name="scan",
            payload_sha256=hashlib.sha256(canonical_json(payload)).hexdigest(),
        )
        probe = cli._ProductionOutboxReplayProbe(
            db=db,
            signer=_Signer(),
            client=_OutboxClient(),
            receipt_url="https://probe.example/outbox",
            bearer_token="secret",
        )
        with patch.object(
            cli, "publish_message", AsyncMock(return_value=True)
        ) as publish:
            receipts = await probe((request,))
        self.assertEqual(receipts[0].outbox_id, outbox_id)
        publish.assert_awaited_once()
        db.commit.assert_awaited_once()

        rejected_db = SimpleNamespace(
            scalars=AsyncMock(return_value=_Rows([row])),
            execute=AsyncMock(),
            commit=AsyncMock(),
        )
        rejected = cli._ProductionOutboxReplayProbe(
            db=rejected_db,
            signer=_Signer(),
            client=_OutboxClient(valid_signature=False),
            receipt_url="https://probe.example/outbox",
            bearer_token="secret",
        )
        with patch.object(cli, "publish_message", AsyncMock(return_value=True)):
            with self.assertRaisesRegex(RuntimeError, "signature"):
                await rejected((request,))
        rejected_db.commit.assert_not_awaited()

        stale = cli._ProductionOutboxReplayProbe(
            db=SimpleNamespace(
                scalars=AsyncMock(return_value=_Rows([row])),
                execute=AsyncMock(),
                commit=AsyncMock(),
            ),
            signer=_Signer(),
            client=_OutboxClient(stale_nonce=True),
            receipt_url="https://probe.example/outbox",
            bearer_token="secret",
        )
        with patch.object(cli, "publish_message", AsyncMock(return_value=True)):
            with self.assertRaisesRegex(RuntimeError, "request mismatch"):
                await stale((request,))

    async def test_checkpoint_probe_requires_signed_exact_advancement(self) -> None:
        scan_id = uuid.uuid4()
        request = CheckpointResumeRequest(
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
            state_sha256="c" * 64,
        )
        probe = cli._SignedCheckpointResumeProbe(
            signer=_Signer(),
            client=_CheckpointClient(),
            resume_url="https://probe.example/checkpoint",
            bearer_token="secret",
        )
        receipt = (await probe((request,)))[0]
        self.assertEqual(receipt.source_checkpoint_id, "checkpoint-1")
        self.assertEqual(receipt.resumed_checkpoint_id, "checkpoint-2")

        no_advance = cli._SignedCheckpointResumeProbe(
            signer=_Signer(),
            client=_CheckpointClient(advance=False),
            resume_url="https://probe.example/checkpoint",
            bearer_token="secret",
        )
        with self.assertRaisesRegex(RuntimeError, "did not advance"):
            await no_advance((request,))

    async def test_governance_probe_uses_production_coordinator_result(self) -> None:
        operation_id = uuid.uuid4()
        tenant_id = uuid.uuid4()
        service = SimpleNamespace(
            execute=AsyncMock(
                return_value=SimpleNamespace(
                    id=operation_id,
                    tenant_id=tenant_id,
                    status="completed",
                    manifest_sha256="d" * 64,
                )
            )
        )
        probe = cli._ProductionGovernanceRecoveryProbe(service)
        receipts = await probe(
            (
                GovernanceRecoveryRequest(
                    operation_id=operation_id,
                    tenant_id=tenant_id,
                    status="failed",
                ),
            )
        )
        self.assertEqual(receipts[0].manifest_sha256, "d" * 64)
        service.execute.assert_awaited_once_with(
            operation_id, expected_tenant_id=tenant_id
        )

    def test_cli_fails_closed_without_explicit_recovery_contracts(self) -> None:
        parser = argparse.ArgumentParser()
        parser.error = unittest.mock.Mock(side_effect=SystemExit(2))
        args = argparse.Namespace(
            max_evidence_objects=0,
            checkpoint_dsn="postgresql://runtime@db/sccap",
            qdrant_restore_artifact=None,
            governance_artifact_root=None,
            observability_expected_sha256="d" * 64,
            outbox_receipt_url="https://probe.example/outbox",
            checkpoint_resume_url="https://probe.example/checkpoint",
            allow_loopback_http=False,
            probe_bearer_token="",
            observability_url="https://observability.example",
            observability_token="secret",
        )
        with self.assertRaises(SystemExit):
            cli._validate_args(parser, args)
        self.assertIn("RESTORE_PROBE_BEARER_TOKEN", parser.error.call_args.args[0])

    def test_cli_accepts_complete_isolated_restore_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qdrant_artifact = root / "qdrant.json"
            qdrant_artifact.write_text("{}")
            governance_root = root / "governance"
            governance_root.mkdir()
            args = argparse.Namespace(
                max_evidence_objects=0,
                checkpoint_dsn="postgresql://runtime@db/sccap",
                qdrant_restore_artifact=qdrant_artifact,
                governance_artifact_root=governance_root,
                observability_expected_sha256="d" * 64,
                outbox_receipt_url="https://probe.example/outbox",
                checkpoint_resume_url="https://probe.example/checkpoint",
                allow_loopback_http=False,
                probe_bearer_token="secret",
                observability_url="https://observability.example",
                observability_token="secret",
            )
            cli._validate_args(argparse.ArgumentParser(), args)

    def test_loopback_http_requires_explicit_operator_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            qdrant_artifact = root / "qdrant.json"
            qdrant_artifact.write_text("{}")
            governance_root = root / "governance"
            governance_root.mkdir()
            args = argparse.Namespace(
                max_evidence_objects=0,
                checkpoint_dsn="postgresql://runtime@db/sccap",
                qdrant_restore_artifact=qdrant_artifact,
                governance_artifact_root=governance_root,
                observability_expected_sha256="d" * 64,
                outbox_receipt_url="http://127.0.0.1:8765/outbox",
                checkpoint_resume_url="http://[::1]:8765/checkpoint",
                allow_loopback_http=False,
                probe_bearer_token="secret",
                observability_url="https://observability.example",
                observability_token="secret",
            )
            parser = argparse.ArgumentParser()
            parser.error = unittest.mock.Mock(side_effect=SystemExit(2))
            with self.assertRaises(SystemExit):
                cli._validate_args(parser, args)
            self.assertIn("--allow-loopback-http", parser.error.call_args.args[0])

            args.allow_loopback_http = True
            cli._validate_args(argparse.ArgumentParser(), args)


if __name__ == "__main__":
    unittest.main()
