from __future__ import annotations

import unittest
import uuid
import tempfile
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from app.infrastructure.governance.models import (
    GovernanceOperation,
    GovernanceStoreAction,
)
from app.infrastructure.governance.service import GovernanceService
from app.infrastructure.governance.adapters import (
    GovernanceArtifactSink,
    ObjectGovernanceAdapter,
    QdrantGovernanceAdapter,
)
from app.infrastructure.signing.digest_signer import LocalTestDigestSigner


class _Rows:
    def all(self):
        return []


class _Db:
    def __init__(self, operation, action):
        self.operation = operation
        self.action = action
        self.commits = 0
        self.rollbacks = 0

    async def execute(self, *_args, **_kwargs):
        return None

    async def scalar(self, *_args, **_kwargs):
        self.action.status = "leased"
        self.action.attempts += 1
        return self.action.id

    async def scalars(self, *_args, **_kwargs):
        return _Rows()

    async def commit(self):
        self.commits += 1

    async def rollback(self):
        self.rollbacks += 1

    async def get(self, model, _identifier):
        return self.operation if model is GovernanceOperation else self.action

    async def refresh(self, _row):
        return None


class _Adapter:
    store = "postgres"

    def __init__(self):
        self.calls = 0

    async def apply(self, *, operation_id, kind, **_kwargs):
        self.calls += 1
        if self.calls == 1:
            raise ConnectionError("simulated crash after durable lease")
        return {
            "schema_version": 1,
            "store": self.store,
            "kind": kind,
            "operation_id": str(operation_id),
            "matched_count": 1,
            "applied_count": 1,
            "content_sha256": "a" * 64,
            "artifact_ref": f"governance:{operation_id}",
        }

    async def verify(self, **_kwargs):
        return True


class OperationRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_execute_rejects_operation_from_another_tenant(self) -> None:
        tenant_id = uuid.uuid4()
        operation = GovernanceOperation(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            kind="export",
            status="prepared",
            scope={"scope_type": "tenant", "scope_id": str(uuid.uuid4())},
        )

        class CrossTenantDb:
            async def scalar(self, *_args, **_kwargs):
                return operation

        service = object.__new__(GovernanceService)
        service.db = CrossTenantDb()
        service.signer = LocalTestDigestSigner()
        service.adapters = {
            name: SimpleNamespace(store=name)
            for name in ("postgres", "object", "qdrant", "observability")
        }
        with self.assertRaisesRegex(LookupError, "selected tenant"):
            await service.execute(
                operation.id,
                expected_tenant_id=tenant_id,
            )

    async def test_failed_action_is_safely_released_and_resumed(self) -> None:
        tenant_id = uuid.uuid4()
        operation = GovernanceOperation(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            kind="export",
            status="executing",
            scope={"scope_type": "tenant", "scope_id": str(tenant_id)},
        )
        action = GovernanceStoreAction(
            id=uuid.uuid4(),
            operation_id=operation.id,
            tenant_id=tenant_id,
            store="postgres",
            status="pending",
            attempts=0,
        )
        db = _Db(operation, action)
        adapter = _Adapter()
        service = object.__new__(GovernanceService)
        service.db = db
        service.signer = LocalTestDigestSigner()
        service.adapters = {"postgres": adapter}

        await service._execute_action(operation, action)
        self.assertEqual(action.status, "failed")
        self.assertIsNone(action.lease_expires_at)
        self.assertEqual(action.attempts, 1)
        self.assertEqual(db.rollbacks, 1)

        await service._execute_action(operation, action)
        self.assertEqual(action.status, "verified")
        self.assertEqual(action.attempts, 2)
        self.assertEqual(adapter.calls, 2)
        self.assertEqual(action.result["store"], "postgres")

    async def test_qdrant_delete_plan_is_minimal_and_crash_idempotent(self) -> None:
        class Qdrant:
            def __init__(self):
                self.points = [
                    SimpleNamespace(
                        id=str(uuid.uuid4()),
                        payload={
                            "tenant_id": str(tenant_id),
                            "source": "secret source text",
                        },
                        vector=[0.123456789, 0.987654321],
                    )
                ]

            def get_collections(self):
                return SimpleNamespace(collections=[SimpleNamespace(name="documents")])

            def scroll(self, **_kwargs):
                return list(self.points), None

            def delete(self, *, points_selector, **_kwargs):
                ids = {str(value) for value in points_selector.points}
                self.points = [
                    point for point in self.points if str(point.id) not in ids
                ]

            def retrieve(self, *, ids, **_kwargs):
                requested = {str(value) for value in ids}
                return [point for point in self.points if str(point.id) in requested]

        tenant_id = uuid.uuid4()
        operation_id = uuid.uuid4()
        scope = {"scope_type": "tenant", "scope_id": str(tenant_id)}
        client = Qdrant()
        with tempfile.TemporaryDirectory() as temporary:
            sink = GovernanceArtifactSink(Path(temporary))
            adapter = QdrantGovernanceAdapter(client, sink)
            first = await adapter.apply(
                operation_id=operation_id,
                kind="delete",
                tenant_id=tenant_id,
                scope=scope,
            )
            persisted = sink.read(operation_id, "qdrant")
            self.assertIsNotNone(persisted)
            self.assertNotIn(b"secret source text", persisted)
            self.assertNotIn(b"0.123456789", persisted)
            self.assertIn(b"point_sha256", persisted)
            self.assertFalse(client.points)

            second = await adapter.apply(
                operation_id=operation_id,
                kind="delete",
                tenant_id=tenant_id,
                scope=scope,
            )
            self.assertEqual(second, first)
            self.assertEqual(sink.read(operation_id, "qdrant"), persisted)
            self.assertTrue(
                await adapter.verify(
                    operation_id=operation_id,
                    kind="delete",
                    tenant_id=tenant_id,
                    scope=scope,
                    result=second,
                )
            )
            planned_id = json.loads(persisted)["points"][0]["id"]
            client.points = [
                SimpleNamespace(
                    id=planned_id,
                    payload={
                        "tenant_id": str(uuid.uuid4()),
                        "source": "reassigned source",
                    },
                    vector=[9.0],
                )
            ]
            with self.assertRaisesRegex(ValueError, "live_point_mismatch"):
                await adapter.apply(
                    operation_id=operation_id,
                    kind="delete",
                    tenant_id=tenant_id,
                    scope=scope,
                )
            self.assertEqual(len(client.points), 1)
            client.points[0].payload = {
                "tenant_id": str(tenant_id),
                "source": "changed source",
            }
            with self.assertRaisesRegex(ValueError, "live_point_mismatch"):
                await adapter.apply(
                    operation_id=operation_id,
                    kind="delete",
                    tenant_id=tenant_id,
                    scope=scope,
                )
            self.assertEqual(len(client.points), 1)

    async def test_object_export_binds_ciphertext_files_to_store_result(self) -> None:
        tenant_id = uuid.uuid4()
        operation_id = uuid.uuid4()
        evidence_id = uuid.uuid4()
        ciphertext = b"ciphertext-bytes"
        ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()
        row = SimpleNamespace(
            id=evidence_id,
            legal_hold=False,
            state="available",
            object_key="evidence/key",
            object_version="v1",
            ciphertext_sha256=ciphertext_sha256,
        )

        class Db:
            async def flush(self):
                return None

        class ObjectStore:
            async def get_ciphertext(self, **_kwargs):
                return ciphertext

        scope = {"scope_type": "tenant", "scope_id": str(tenant_id)}
        with tempfile.TemporaryDirectory() as temporary:
            sink = GovernanceArtifactSink(Path(temporary))
            adapter = ObjectGovernanceAdapter(Db(), ObjectStore(), sink)
            with mock.patch(
                "app.infrastructure.governance.adapters._evidence_rows",
                mock.AsyncMock(return_value=[row]),
            ):
                result = await adapter.apply(
                    operation_id=operation_id,
                    kind="export",
                    tenant_id=tenant_id,
                    scope=scope,
                )
                self.assertTrue(
                    await adapter.verify(
                        operation_id=operation_id,
                        kind="export",
                        tenant_id=tenant_id,
                        scope=scope,
                        result=result,
                    )
                )
                manifest = json.loads(sink.read(operation_id, "object"))
                self.assertEqual(
                    manifest["records"],
                    [
                        {
                            "ciphertext_sha256": ciphertext_sha256,
                            "id": str(evidence_id),
                            "relative_path": f"objects/{evidence_id}",
                            "size_bytes": len(ciphertext),
                            "state": "live",
                        }
                    ],
                )
                exported = sink.root / str(operation_id) / "objects" / str(evidence_id)
                exported.write_bytes(b"tampered")
                self.assertFalse(
                    await adapter.verify(
                        operation_id=operation_id,
                        kind="export",
                        tenant_id=tenant_id,
                        scope=scope,
                        result=result,
                    )
                )
                exported.write_bytes(ciphertext)
                extra = exported.with_name("unexpected")
                extra.write_bytes(b"extra")
                self.assertFalse(
                    await adapter.verify(
                        operation_id=operation_id,
                        kind="export",
                        tenant_id=tenant_id,
                        scope=scope,
                        result=result,
                    )
                )
                extra.unlink()
                exported.unlink()
                self.assertFalse(
                    await adapter.verify(
                        operation_id=operation_id,
                        kind="export",
                        tenant_id=tenant_id,
                        scope=scope,
                        result=result,
                    )
                )

    async def test_object_export_allows_hold_and_deleted_metadata_tombstone(
        self,
    ) -> None:
        tenant_id = uuid.uuid4()
        operation_id = uuid.uuid4()
        ciphertext = b"held-ciphertext"
        held = SimpleNamespace(
            id=uuid.uuid4(),
            legal_hold=True,
            state="available",
            object_key="held/key",
            object_version="v1",
            ciphertext_sha256=hashlib.sha256(ciphertext).hexdigest(),
        )
        deleted = SimpleNamespace(
            id=uuid.uuid4(),
            legal_hold=True,
            state="deleted",
            object_key="deleted/key",
            object_version="v1",
            ciphertext_sha256="d" * 64,
        )

        class Db:
            async def flush(self):
                return None

        class ObjectStore:
            def __init__(self):
                self.calls = []

            async def get_ciphertext(self, *, object_key, **_kwargs):
                self.calls.append(object_key)
                if object_key == "deleted/key":
                    raise AssertionError("deleted ciphertext must not be fetched")
                return ciphertext

        scope = {"scope_type": "tenant", "scope_id": str(tenant_id)}
        store = ObjectStore()
        with tempfile.TemporaryDirectory() as temporary:
            sink = GovernanceArtifactSink(Path(temporary))
            adapter = ObjectGovernanceAdapter(Db(), store, sink)
            with mock.patch(
                "app.infrastructure.governance.adapters._evidence_rows",
                mock.AsyncMock(return_value=[held, deleted]),
            ):
                result = await adapter.apply(
                    operation_id=operation_id,
                    kind="export",
                    tenant_id=tenant_id,
                    scope=scope,
                )
                self.assertTrue(
                    await adapter.verify(
                        operation_id=operation_id,
                        kind="export",
                        tenant_id=tenant_id,
                        scope=scope,
                        result=result,
                    )
                )
                manifest = json.loads(sink.read(operation_id, "object"))
        self.assertEqual(store.calls, ["held/key"])
        deleted_record = next(
            record for record in manifest["records"] if record["id"] == str(deleted.id)
        )
        self.assertEqual(
            deleted_record,
            {
                "ciphertext_sha256": "d" * 64,
                "id": str(deleted.id),
                "relative_path": None,
                "size_bytes": None,
                "state": "deleted",
            },
        )
