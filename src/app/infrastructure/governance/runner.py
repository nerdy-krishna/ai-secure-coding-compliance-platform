"""Reachable system-scoped construction for durable governance operations."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncIterator

import httpx
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.infrastructure.evidence.object_store import EvidenceObjectStore
from app.infrastructure.governance.adapters import (
    GovernanceArtifactSink,
    ObjectGovernanceAdapter,
    ObservabilityGovernanceAdapter,
    PostgresGovernanceAdapter,
    QdrantGovernanceAdapter,
)
from app.infrastructure.governance.service import GovernanceService
from app.infrastructure.rag.qdrant_store import QdrantStore
from app.infrastructure.signing import AwsKmsDigestSigner


@asynccontextmanager
async def governance_service(db: AsyncSession) -> AsyncIterator[GovernanceService]:
    """Build production adapters; no store can silently degrade to a no-op."""
    signing_key = os.environ.get("GOVERNANCE_SIGNING_KMS_KEY_ID", "").strip()
    observability_url = os.environ.get("GOVERNANCE_OBSERVABILITY_URL", "").strip()
    observability_token = os.environ.get(
        "GOVERNANCE_OBSERVABILITY_BEARER_TOKEN", ""
    ).strip()
    artifact_root = Path(
        os.environ.get("GOVERNANCE_ARTIFACT_ROOT", "/var/lib/sccap/governance")
    )
    if not signing_key:
        raise RuntimeError("GOVERNANCE_SIGNING_KMS_KEY_ID is required.")
    if not observability_url.startswith("https://"):
        raise RuntimeError("GOVERNANCE_OBSERVABILITY_URL must use HTTPS.")
    if not observability_token:
        raise RuntimeError("GOVERNANCE_OBSERVABILITY_BEARER_TOKEN is required.")

    signer = AwsKmsDigestSigner(
        key_id=signing_key,
        region=os.environ.get(
            "GOVERNANCE_SIGNING_KMS_REGION", settings.EVIDENCE_S3_REGION
        ),
    )
    qdrant = QdrantStore()
    sink = GovernanceArtifactSink(artifact_root)
    async with httpx.AsyncClient(timeout=httpx.Timeout(60.0)) as client:
        yield GovernanceService(
            db,
            signer=signer,
            adapters={
                "postgres": PostgresGovernanceAdapter(db, sink),
                "object": ObjectGovernanceAdapter(db, EvidenceObjectStore(), sink),
                "qdrant": QdrantGovernanceAdapter(qdrant._client, sink),
                "observability": ObservabilityGovernanceAdapter(
                    base_url=observability_url,
                    bearer_token=observability_token,
                    client=client,
                ),
            },
        )
