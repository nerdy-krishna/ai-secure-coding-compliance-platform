"""Enforce vector/log/observability/backup retention with signed evidence."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import uuid
from pathlib import Path

import httpx

from app.config.config import settings
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.tenant_context import principal_scope
from app.infrastructure.governance.adapters import GovernanceArtifactSink
from app.infrastructure.governance.retention_executor import RetentionExecutor
from app.infrastructure.rag.qdrant_store import QdrantStore
from app.infrastructure.signing import AwsKmsDigestSigner


async def _run(tenant_id: uuid.UUID, operation_id: uuid.UUID) -> int:
    key_id = os.environ.get("GOVERNANCE_SIGNING_KMS_KEY_ID", "").strip()
    observability_url = os.environ.get("GOVERNANCE_OBSERVABILITY_URL", "").strip()
    token = os.environ.get("GOVERNANCE_OBSERVABILITY_BEARER_TOKEN", "").strip()
    if not key_id or not observability_url.startswith("https://") or not token:
        raise RuntimeError("KMS signing and HTTPS observability settings are required.")
    signer = AwsKmsDigestSigner(
        key_id=key_id,
        region=os.environ.get(
            "GOVERNANCE_SIGNING_KMS_REGION", settings.EVIDENCE_S3_REGION
        ),
    )
    qdrant = QdrantStore()
    with principal_scope(
        tenant_id=tenant_id,
        principal_kind="system",
        principal_id="governance-retention-runner",
        system_scope=True,
    ):
        async with AsyncSessionLocal() as db, httpx.AsyncClient(
            timeout=httpx.Timeout(60.0)
        ) as client:
            result = await RetentionExecutor(
                db,
                qdrant_client=qdrant._client,
                observability_url=observability_url,
                observability_token=token,
                backup_root=Path(
                    os.environ.get("GOVERNANCE_BACKUP_ROOT", "/var/backups/sccap")
                ),
                sink=GovernanceArtifactSink(
                    Path(
                        os.environ.get(
                            "GOVERNANCE_ARTIFACT_ROOT", "/var/lib/sccap/governance"
                        )
                    )
                ),
                signer=signer,
                http_client=client,
            ).execute(tenant_id, operation_id=operation_id)
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant-id", type=uuid.UUID, required=True)
    parser.add_argument("--operation-id", type=uuid.UUID, required=True)
    args = parser.parse_args()
    return asyncio.run(_run(args.tenant_id, args.operation_id))


if __name__ == "__main__":
    raise SystemExit(main())
