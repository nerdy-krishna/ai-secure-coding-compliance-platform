"""Concrete bounded adapters for Task22 four-store governance operations."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

import httpx
from qdrant_client import models as qmodels
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.evidence_repo import EvidenceRepository
from app.infrastructure.evidence.object_store import EvidenceObjectStore
from app.infrastructure.governance.contracts import (
    MAX_RECORDS,
    StoreActionResult,
    canonical_json,
)


def _serializable_point_id(value: Any) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return str(value)


def _point_id_key(value: Any) -> str:
    return json.dumps(_serializable_point_id(value), separators=(",", ":"))


def _point_sha256(point: Any) -> str:
    return hashlib.sha256(
        canonical_json({"payload": point.payload or {}, "vector": point.vector})
    ).hexdigest()


def _point_matches_scope(
    point: Any, tenant_id: uuid.UUID, scope: Mapping[str, str]
) -> bool:
    payload = point.payload or {}
    if payload.get("tenant_id") != str(tenant_id):
        return False
    return (
        scope["scope_type"] == "tenant"
        or payload.get(f"{scope['scope_type']}_id") == scope["scope_id"]
    )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_write(destination: Path, payload: bytes, *, mode: int = 0o600) -> None:
    temporary = destination.with_name(f".{destination.name}.tmp")
    with temporary.open("wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    temporary.chmod(mode)
    os.replace(temporary, destination)
    _fsync_directory(destination.parent)


class GovernanceArtifactSink:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.root.chmod(0o700)

    def write(self, operation_id: uuid.UUID, store: str, payload: bytes) -> str:
        directory = self.root / str(operation_id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        directory.chmod(0o700)
        _fsync_directory(directory.parent)
        destination = directory / f"{store}.json"
        _durable_write(destination, payload)
        return f"governance/{operation_id}/{store}.json"

    def path(self, operation_id: uuid.UUID, store: str) -> Path:
        return self.root / str(operation_id) / f"{store}.json"

    def read(self, operation_id: uuid.UUID, store: str) -> bytes | None:
        path = self.path(operation_id, store)
        return path.read_bytes() if path.is_file() else None


def _scope_evidence_statement(
    tenant_id: uuid.UUID, scope: Mapping[str, str]
) -> Select[tuple[db_models.EvidenceObject]]:
    statement = select(db_models.EvidenceObject).where(
        db_models.EvidenceObject.tenant_id == tenant_id
    )
    scope_type = scope["scope_type"]
    scope_id = uuid.UUID(scope["scope_id"])
    if scope_type == "evidence":
        statement = statement.where(db_models.EvidenceObject.id == scope_id)
    elif scope_type == "attempt":
        statement = statement.where(db_models.EvidenceObject.attempt_id == scope_id)
    elif scope_type == "scan":
        statement = statement.where(db_models.EvidenceObject.scan_id == scope_id)
    elif scope_type == "project":
        statement = statement.where(
            db_models.EvidenceObject.scan_id.in_(
                select(db_models.Scan.id).where(
                    db_models.Scan.tenant_id == tenant_id,
                    db_models.Scan.project_id == scope_id,
                )
            )
        )
    return statement.order_by(db_models.EvidenceObject.id).limit(MAX_RECORDS + 1)


async def _evidence_rows(
    db: AsyncSession, tenant_id: uuid.UUID, scope: Mapping[str, str]
) -> list[db_models.EvidenceObject]:
    rows = list((await db.scalars(_scope_evidence_statement(tenant_id, scope))).all())
    if len(rows) > MAX_RECORDS:
        raise RuntimeError("governance_scope_requires_chunking")
    return rows


class PostgresGovernanceAdapter:
    store = "postgres"

    def __init__(self, db: AsyncSession, sink: GovernanceArtifactSink) -> None:
        self.db = db
        self.sink = sink

    async def apply(self, *, operation_id, kind, tenant_id, scope):
        rows = await _evidence_rows(self.db, tenant_id, scope)
        payload = canonical_json(
            {
                "schema_version": 1,
                "operation_id": str(operation_id),
                "tenant_id": str(tenant_id),
                "scope": dict(scope),
                "records": [
                    {
                        "id": str(row.id),
                        "scan_id": str(row.scan_id) if row.scan_id else None,
                        "attempt_id": str(row.attempt_id) if row.attempt_id else None,
                        "artifact_type": row.artifact_type,
                        "version": row.version,
                        "state": row.state,
                        "plaintext_sha256": row.plaintext_sha256,
                        "ciphertext_sha256": row.ciphertext_sha256,
                        "object_key": row.object_key,
                        "object_version": row.object_version,
                        "key_provider": row.key_provider,
                        "key_id": row.key_id,
                        "wrapped_data_key_b64": base64.b64encode(
                            row.wrapped_data_key
                        ).decode(),
                        "nonce_b64": base64.b64encode(row.nonce).decode(),
                        "aad_sha256": row.aad_sha256,
                        "retain_until": row.retain_until.isoformat(),
                        "legal_hold": row.legal_hold,
                    }
                    for row in rows
                ],
            }
        )
        reference = self.sink.write(operation_id, self.store, payload)
        applied = (
            len(rows)
            if kind == "export"
            else sum(row.state == "deleted" for row in rows)
        )
        return StoreActionResult(
            store=self.store,
            kind=kind,
            operation_id=operation_id,
            matched_count=len(rows),
            applied_count=applied,
            content_sha256=hashlib.sha256(payload).hexdigest(),
            artifact_ref=reference,
        ).model_dump(mode="json")

    async def verify(self, *, operation_id, kind, tenant_id, scope, result):
        parsed = StoreActionResult.model_validate(result)
        rows = await _evidence_rows(self.db, tenant_id, scope)
        if kind == "delete" and any(row.state != "deleted" for row in rows):
            return False
        return parsed.operation_id == operation_id and parsed.matched_count == len(rows)


class ObjectGovernanceAdapter:
    store = "object"

    def __init__(
        self,
        db: AsyncSession,
        object_store: EvidenceObjectStore,
        sink: GovernanceArtifactSink,
    ) -> None:
        self.db = db
        self.object_store = object_store
        self.sink = sink

    async def apply(self, *, operation_id, kind, tenant_id, scope):
        rows = await _evidence_rows(self.db, tenant_id, scope)
        records: list[dict[str, Any]] = []
        applied = 0
        repo = EvidenceRepository(self.db, object_store=self.object_store)
        for row in rows:
            if kind == "export":
                if row.state == "deleted":
                    records.append(
                        {
                            "id": str(row.id),
                            "state": "deleted",
                            "relative_path": None,
                            "ciphertext_sha256": row.ciphertext_sha256,
                            "size_bytes": None,
                        }
                    )
                    applied += 1
                    continue
                ciphertext = await self.object_store.get_ciphertext(
                    object_key=row.object_key,
                    object_version=row.object_version,
                    ciphertext_sha256=row.ciphertext_sha256,
                )
                if hashlib.sha256(ciphertext).hexdigest() != row.ciphertext_sha256:
                    raise ValueError("object_export_ciphertext_digest_mismatch")
                payload_path = (
                    self.sink.root / str(operation_id) / "objects" / str(row.id)
                )
                payload_path.parent.mkdir(parents=True, exist_ok=True)
                payload_path.parent.chmod(0o700)
                _fsync_directory(payload_path.parent.parent)
                _durable_write(payload_path, ciphertext)
                applied += 1
                records.append(
                    {
                        "id": str(row.id),
                        "state": "live",
                        "relative_path": f"objects/{row.id}",
                        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                        "size_bytes": len(ciphertext),
                    }
                )
            elif row.state != "deleted":
                if row.legal_hold:
                    raise PermissionError("governance_legal_hold_active")
                await self.object_store.delete(
                    object_key=row.object_key, object_version=row.object_version
                )
                row.state = "deleted"
                row.deleted_at = datetime.now(timezone.utc)
                row.wrapped_data_key = b""
                row.nonce = b""
                repo._audit(
                    row,
                    "EVIDENCE_DELETED",
                    actor_user_id=None,
                    reason=f"governance_operation:{operation_id}",
                    details={"object_version": row.object_version},
                )
                applied += 1
                records.append({"id": str(row.id), "deleted": True})
        payload = canonical_json(
            {
                "schema_version": 1,
                "artifact_kind": f"object_{kind}",
                "operation_id": str(operation_id),
                "tenant_id": str(tenant_id),
                "scope": dict(scope),
                "records": records,
            }
        )
        reference = self.sink.write(operation_id, self.store, payload)
        await self.db.flush()
        return StoreActionResult(
            store=self.store,
            kind=kind,
            operation_id=operation_id,
            matched_count=len(rows),
            applied_count=applied,
            content_sha256=hashlib.sha256(payload).hexdigest(),
            artifact_ref=reference,
        ).model_dump(mode="json")

    async def verify(self, *, operation_id, kind, tenant_id, scope, result):
        parsed = StoreActionResult.model_validate(result)
        artifact = self.sink.read(operation_id, self.store)
        if (
            artifact is None
            or hashlib.sha256(artifact).hexdigest() != parsed.content_sha256
        ):
            return False
        try:
            manifest = json.loads(artifact)
        except (TypeError, ValueError):
            return False
        if (
            manifest.get("artifact_kind") != f"object_{kind}"
            or manifest.get("operation_id") != str(operation_id)
            or manifest.get("tenant_id") != str(tenant_id)
            or manifest.get("scope") != dict(scope)
            or not isinstance(manifest.get("records"), list)
        ):
            return False
        rows = await _evidence_rows(self.db, tenant_id, scope)
        if kind == "delete":
            for row in rows:
                if row.state != "deleted" or await self.object_store.version_exists(
                    object_key=row.object_key, object_version=row.object_version
                ):
                    return False
        else:
            operation_root = self.sink.path(operation_id, self.store).parent
            objects_root = operation_root / "objects"
            records = manifest["records"]
            rows_by_id = {str(row.id): row for row in rows}
            expected_paths: set[str] = set()
            expected_ids: set[str] = set()
            for record in records:
                if not isinstance(record, dict):
                    return False
                evidence_id = record.get("id")
                relative_path = record.get("relative_path")
                if (
                    not isinstance(evidence_id, str)
                    or evidence_id in expected_ids
                    or evidence_id not in rows_by_id
                ):
                    return False
                expected_ids.add(evidence_id)
                row = rows_by_id[evidence_id]
                if record.get("state") == "deleted":
                    if (
                        row.state != "deleted"
                        or relative_path is not None
                        or record.get("size_bytes") is not None
                        or record.get("ciphertext_sha256") != row.ciphertext_sha256
                    ):
                        return False
                    continue
                if (
                    record.get("state") != "live"
                    or row.state == "deleted"
                    or relative_path != f"objects/{evidence_id}"
                ):
                    return False
                expected_paths.add(relative_path)
                path = operation_root / relative_path
                if (
                    not path.is_file()
                    or path.is_symlink()
                    or path.parent != objects_root
                ):
                    return False
                ciphertext = path.read_bytes()
                if (
                    record.get("size_bytes") != len(ciphertext)
                    or record.get("ciphertext_sha256")
                    != hashlib.sha256(ciphertext).hexdigest()
                ):
                    return False
            if objects_root.exists() and (
                not objects_root.is_dir() or objects_root.is_symlink()
            ):
                return False
            actual_entries = (
                list(objects_root.iterdir()) if objects_root.exists() else []
            )
            if any(not path.is_file() or path.is_symlink() for path in actual_entries):
                return False
            actual_paths = {
                str(path.relative_to(operation_root)) for path in actual_entries
            }
            if actual_paths != expected_paths or expected_ids != {
                str(row.id) for row in rows
            }:
                return False
        return parsed.operation_id == operation_id and parsed.matched_count == len(rows)


class QdrantGovernanceAdapter:
    store = "qdrant"

    def __init__(self, client: Any, sink: GovernanceArtifactSink) -> None:
        self.client = client
        self.sink = sink

    def _points(self, tenant_id: uuid.UUID, scope: Mapping[str, str]):
        must = [
            qmodels.FieldCondition(
                key="tenant_id", match=qmodels.MatchValue(value=str(tenant_id))
            )
        ]
        if scope["scope_type"] != "tenant":
            must.append(
                qmodels.FieldCondition(
                    key=f"{scope['scope_type']}_id",
                    match=qmodels.MatchValue(value=scope["scope_id"]),
                )
            )
        found: list[tuple[str, Any]] = []
        for collection in self.client.get_collections().collections:
            offset = None
            while True:
                points, offset = self.client.scroll(
                    collection_name=collection.name,
                    scroll_filter=qmodels.Filter(must=must),
                    limit=1000,
                    offset=offset,
                    with_payload=True,
                    with_vectors=True,
                )
                found.extend((collection.name, point) for point in points)
                if len(found) > MAX_RECORDS:
                    raise RuntimeError("governance_scope_requires_chunking")
                if offset is None:
                    break
        return found

    async def apply(self, *, operation_id, kind, tenant_id, scope):
        persisted = (
            self.sink.read(operation_id, self.store) if kind == "delete" else None
        )
        if persisted is not None:
            plan = json.loads(persisted)
            if (
                plan.get("artifact_kind") != "qdrant_deletion_plan"
                or plan.get("operation_id") != str(operation_id)
                or plan.get("tenant_id") != str(tenant_id)
                or plan.get("scope") != dict(scope)
            ):
                raise ValueError("qdrant_deletion_plan_identity_mismatch")
            records = plan["points"]
            grouped: dict[str, list[Any]] = {}
            for record in records:
                grouped.setdefault(record["collection"], []).append(record["id"])
            live_by_collection: dict[str, list[Any]] = {}
            for collection, ids in grouped.items():
                live = await asyncio.to_thread(
                    self.client.retrieve,
                    collection_name=collection,
                    ids=ids,
                    with_payload=True,
                    with_vectors=True,
                )
                live_by_collection[collection] = list(live)
                expected = {
                    _point_id_key(record["id"]): record
                    for record in records
                    if record["collection"] == collection
                }
                for point in live:
                    record = expected.get(_point_id_key(point.id))
                    if (
                        record is None
                        or not _point_matches_scope(point, tenant_id, scope)
                        or record.get("point_sha256") != _point_sha256(point)
                    ):
                        raise ValueError("qdrant_deletion_plan_live_point_mismatch")
            # Validate every still-live planned ID across all collections before
            # deleting any of them. Missing IDs are the idempotent-success case.
            for collection, live in live_by_collection.items():
                if not live:
                    continue
                await asyncio.to_thread(
                    self.client.delete,
                    collection_name=collection,
                    points_selector=qmodels.PointIdsList(
                        points=[point.id for point in live]
                    ),
                    wait=True,
                )
            return StoreActionResult(
                store=self.store,
                kind=kind,
                operation_id=operation_id,
                matched_count=len(records),
                applied_count=len(records),
                content_sha256=hashlib.sha256(persisted).hexdigest(),
                artifact_ref=f"governance/{operation_id}/{self.store}.json",
            ).model_dump(mode="json")

        points = await asyncio.to_thread(self._points, tenant_id, scope)
        if kind == "delete":
            # A deletion tombstone retains only identity plus a digest of the
            # deleted point. Source payloads and embeddings must not become a
            # second long-lived copy in governance evidence.
            payload = canonical_json(
                {
                    "schema_version": 1,
                    "artifact_kind": "qdrant_deletion_plan",
                    "operation_id": str(operation_id),
                    "tenant_id": str(tenant_id),
                    "scope": dict(scope),
                    "points": [
                        {
                            "collection": collection,
                            "id": _serializable_point_id(point.id),
                            "point_sha256": _point_sha256(point),
                        }
                        for collection, point in points
                    ],
                }
            )
            self.sink.write(operation_id, self.store, payload)
            # Re-enter through the persisted-plan path so even the first
            # deletion re-fetches and validates each live point after the
            # durable plan exists.
            return await self.apply(
                operation_id=operation_id,
                kind=kind,
                tenant_id=tenant_id,
                scope=scope,
            )
        else:
            payload = canonical_json(
                {
                    "schema_version": 1,
                    "artifact_kind": "qdrant_export",
                    "points": [
                        {
                            "collection": collection,
                            "id": str(point.id),
                            "payload": point.payload,
                            "vector": point.vector,
                        }
                        for collection, point in points
                    ],
                }
            )
            reference = self.sink.write(operation_id, self.store, payload)
        return StoreActionResult(
            store=self.store,
            kind=kind,
            operation_id=operation_id,
            matched_count=len(points),
            applied_count=len(points),
            content_sha256=hashlib.sha256(payload).hexdigest(),
            artifact_ref=reference,
        ).model_dump(mode="json")

    async def verify(self, *, operation_id, kind, tenant_id, scope, result):
        parsed = StoreActionResult.model_validate(result)
        remaining = await asyncio.to_thread(self._points, tenant_id, scope)
        return parsed.operation_id == operation_id and (
            kind == "export" or not remaining
        )


class ObservabilityGovernanceAdapter:
    store = "observability"

    def __init__(
        self, *, base_url: str, bearer_token: str, client: httpx.AsyncClient
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.client = client

    async def apply(self, *, operation_id, kind, tenant_id, scope):
        response = await self.client.post(
            f"{self.base_url}/v1/governance/operations/{operation_id}",
            headers={
                "Authorization": f"Bearer {self.bearer_token}",
                "Idempotency-Key": str(operation_id),
            },
            json={"kind": kind, "tenant_id": str(tenant_id), "scope": dict(scope)},
        )
        response.raise_for_status()
        return StoreActionResult.model_validate(response.json()).model_dump(mode="json")

    async def verify(self, *, operation_id, kind, tenant_id, scope, result):
        expected = StoreActionResult.model_validate(result)
        response = await self.client.get(
            f"{self.base_url}/v1/governance/operations/{operation_id}",
            headers={"Authorization": f"Bearer {self.bearer_token}"},
        )
        response.raise_for_status()
        observed = StoreActionResult.model_validate(response.json())
        return observed == expected
