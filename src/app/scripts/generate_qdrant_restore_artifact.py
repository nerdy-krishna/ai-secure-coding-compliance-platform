"""Generate the signed Qdrant inventory expected by isolated restore verification."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from app.infrastructure.governance.contracts import canonical_json
from app.infrastructure.governance.restore import MAX_QDRANT_POINTS, _json_safe
from app.infrastructure.rag.qdrant_store import QdrantStore
from app.infrastructure.signing import AwsKmsDigestSigner, DigestSigner


def _points(client: Any, collection_name: str) -> list[dict[str, Any]]:
    offset = None
    points: list[dict[str, Any]] = []
    while True:
        page, offset = client.scroll(
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
            raise RuntimeError("qdrant restore inventory exceeds approved bound")
        if offset is None:
            break
    return sorted(points, key=lambda item: item["id"])


async def build_artifact(
    client: Any,
    signer: DigestSigner,
    snapshot_names: dict[str, str],
) -> dict[str, Any]:
    available = {
        item.name
        for item in (await asyncio.to_thread(client.get_collections)).collections
    }
    if not available or set(snapshot_names) != available:
        raise ValueError("one explicit snapshot name is required for every collection")
    collections: list[dict[str, Any]] = []
    for name in sorted(available):
        points = await asyncio.to_thread(_points, client, name)
        if not points:
            raise ValueError(f"collection {name!r} has no restore canary points")
        content = canonical_json(
            {"schema_version": 1, "collection": name, "points": points}
        )
        snapshots_result = await asyncio.to_thread(
            client.list_snapshots, collection_name=name
        )
        snapshots = getattr(snapshots_result, "snapshots", snapshots_result)
        snapshot = next(
            (item for item in snapshots if item.name == snapshot_names[name]), None
        )
        checksum = str(getattr(snapshot, "checksum", "") or "").lower()
        if (
            snapshot is None
            or int(snapshot.size or 0) <= 0
            or len(checksum) != 64
            or set(checksum) > set("0123456789abcdef")
        ):
            raise ValueError(
                f"snapshot {snapshot_names[name]!r} lacks SHA-256 evidence"
            )
        collections.append(
            {
                "name": name,
                "points_count": len(points),
                "content_sha256": hashlib.sha256(content).hexdigest(),
                "snapshot_name": snapshot.name,
                "snapshot_size": int(snapshot.size),
                "snapshot_sha256": checksum,
            }
        )
    body = {
        "schema_version": 1,
        "artifact_kind": "qdrant_restore",
        "collections": collections,
    }
    digest = hashlib.sha256(canonical_json(body)).digest()
    signature = await signer.sign_sha256(digest)
    return {
        **body,
        "manifest_sha256": digest.hex(),
        "signature": {
            "signature_b64": signature.signature_b64,
            "algorithm": signature.algorithm,
            "key_id": signature.key_id,
        },
    }


def _snapshot(value: str) -> tuple[str, str]:
    collection, separator, name = value.partition("=")
    if not separator or not collection or not name:
        raise argparse.ArgumentTypeError("use COLLECTION=SNAPSHOT")
    return collection, name


async def _run(args: argparse.Namespace) -> int:
    key_id = os.environ.get("GOVERNANCE_SIGNING_KMS_KEY_ID", "").strip()
    if not key_id:
        raise RuntimeError("GOVERNANCE_SIGNING_KMS_KEY_ID is required")
    signer = AwsKmsDigestSigner(
        key_id=key_id,
        region=os.environ.get("GOVERNANCE_SIGNING_KMS_REGION", "us-east-1"),
    )
    artifact = await build_artifact(QdrantStore()._client, signer, dict(args.snapshot))
    payload = canonical_json(artifact)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(args.output, flags, 0o600)
    try:
        remaining = memoryview(payload)
        while remaining:
            written = os.write(descriptor, remaining)
            if written <= 0:
                raise OSError("short write while creating Qdrant restore artifact")
            remaining = remaining[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent_descriptor = os.open(args.output.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)
    print(
        json.dumps(
            {"output": str(args.output), "sha256": hashlib.sha256(payload).hexdigest()}
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", action="append", type=_snapshot, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("--output must not already exist")
    if args.output.parent.is_symlink() or not args.output.parent.is_dir():
        parser.error("--output parent must be a non-symlink directory")
    return asyncio.run(_run(args))


if __name__ == "__main__":
    raise SystemExit(main())
