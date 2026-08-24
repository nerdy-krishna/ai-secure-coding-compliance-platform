from __future__ import annotations

import json
import os
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace

from app.infrastructure.governance.adapters import GovernanceArtifactSink
from app.infrastructure.governance.retention_executor import RetentionExecutor
from app.infrastructure.signing.digest_signer import LocalTestDigestSigner


class _Scalars:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class _Db:
    def __init__(self, holds=(), policies=()):
        self.responses = [list(holds), list(policies)]
        self.commits = 0

    async def execute(self, *_args, **_kwargs):
        return None

    async def scalars(self, *_args, **_kwargs):
        return _Scalars(self.responses.pop(0))

    async def commit(self):
        self.commits += 1


class _Qdrant:
    def __init__(self, points):
        self.points = list(points)
        self.deleted = []

    def get_collections(self):
        return SimpleNamespace(collections=[SimpleNamespace(name="tenant-vectors")])

    def scroll(self, **_kwargs):
        return list(self.points), None

    def delete(self, *, points_selector, **_kwargs):
        ids = set(points_selector.points)
        self.deleted.extend(ids)
        self.points = [point for point in self.points if point.id not in ids]


class _Response:
    def __init__(self, payload):
        self.content = json.dumps(payload).encode()

    def raise_for_status(self):
        return None


class _Http:
    async def post(self, url, **_kwargs):
        operation_id = uuid.UUID(url.rsplit("/", 1)[-1])
        return _Response(
            {
                "schema_version": 1,
                "store": "observability",
                "kind": "delete",
                "operation_id": str(operation_id),
                "matched_count": 2,
                "applied_count": 2,
                "content_sha256": "a" * 64,
                "artifact_ref": f"observability:{operation_id}",
            }
        )


class RetentionExecutorTests(unittest.IsolatedAsyncioTestCase):
    async def test_effective_days_scoped_holds_and_signed_evidence(self) -> None:
        tenant_id = uuid.uuid4()
        point = SimpleNamespace(
            id="point-1", payload={"tenant_id": str(tenant_id), "scan_id": "scan-1"}
        )
        hold = SimpleNamespace(scope_type="scan", scope_id="scan-1")
        policy = SimpleNamespace(data_class="logs", retention_days=7)
        db = _Db(holds=[hold], policies=[policy])
        qdrant = _Qdrant([point])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backup = root / "backups" / str(tenant_id) / "old.dump"
            backup.parent.mkdir(parents=True)
            backup.write_bytes(b"backup")
            os.utime(backup, (1, 1))
            result = await RetentionExecutor(
                db,
                qdrant_client=qdrant,
                observability_url="https://observability.example",
                observability_token="token",
                backup_root=root / "backups",
                sink=GovernanceArtifactSink(root / "evidence"),
                signer=LocalTestDigestSigner(),
                http_client=_Http(),
            ).execute(tenant_id, operation_id=uuid.uuid4())
            self.assertEqual(result["report"]["effective_days"]["logs"], 7)
            self.assertEqual(result["report"]["legal_hold_count"], 1)
            self.assertFalse(qdrant.deleted)
            self.assertTrue(backup.exists())
            self.assertEqual(db.commits, 1)
            self.assertEqual(len(result["report_sha256"]), 64)
            self.assertTrue(result["signature"]["signature_b64"])

    async def test_unheld_vector_and_backup_are_deleted(self) -> None:
        tenant_id = uuid.uuid4()
        point = SimpleNamespace(id="point-1", payload={"tenant_id": str(tenant_id)})
        db = _Db()
        qdrant = _Qdrant([point])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            backup = root / "backups" / str(tenant_id) / "old.dump"
            backup.parent.mkdir(parents=True)
            backup.write_bytes(b"backup")
            os.utime(backup, (1, 1))
            result = await RetentionExecutor(
                db,
                qdrant_client=qdrant,
                observability_url="https://observability.example",
                observability_token="token",
                backup_root=root / "backups",
                sink=GovernanceArtifactSink(root / "evidence"),
                signer=LocalTestDigestSigner(),
                http_client=_Http(),
            ).execute(tenant_id, operation_id=uuid.uuid4())
            self.assertEqual(qdrant.deleted, ["point-1"])
            self.assertFalse(backup.exists())
            backup_result = result["report"]["stores"][2]
            self.assertEqual(backup_result["applied_count"], 1)

    async def test_observability_failure_does_not_publish_signed_success(self) -> None:
        class FailingHttp:
            async def post(self, *_args, **_kwargs):
                raise RuntimeError("gateway unavailable")

        tenant_id = uuid.uuid4()
        db = _Db()
        qdrant = _Qdrant(
            [SimpleNamespace(id="point-1", payload={"tenant_id": str(tenant_id)})]
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            executor = RetentionExecutor(
                db,
                qdrant_client=qdrant,
                observability_url="https://observability.example",
                observability_token="token",
                backup_root=root / "backups",
                sink=GovernanceArtifactSink(root / "evidence"),
                signer=LocalTestDigestSigner(),
                http_client=FailingHttp(),
            )
            operation_id = uuid.uuid4()
            with self.assertRaisesRegex(RuntimeError, "gateway unavailable"):
                await executor.execute(tenant_id, operation_id=operation_id)
            self.assertEqual(db.commits, 0)
            self.assertFalse(list((root / "evidence").rglob("retention.json")))
            retry_db = _Db()
            retry = RetentionExecutor(
                retry_db,
                qdrant_client=qdrant,
                observability_url="https://observability.example",
                observability_token="token",
                backup_root=root / "backups",
                sink=GovernanceArtifactSink(root / "evidence"),
                signer=LocalTestDigestSigner(),
                http_client=_Http(),
            )
            result = await retry.execute(tenant_id, operation_id=operation_id)
            self.assertEqual(result["report"]["stores"][0]["matched_count"], 1)
            self.assertEqual(retry_db.commits, 1)
