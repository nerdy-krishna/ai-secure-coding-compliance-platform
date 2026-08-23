"""ScanArtifactRepository — CRUD for versioned scan artifacts."""

from __future__ import annotations

import hashlib
import uuid
from typing import Any, Dict, Optional

from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.config.config import settings
from app.infrastructure.database.repositories.evidence_repo import (
    EvidenceRepository,
    canonical_json,
)

ARTIFACT_TYPE_LINEAGE = "finding_lineage"
ARTIFACT_TYPE_SCANNER_REPORTS = "scanner_reports"
ARTIFACT_TYPE_PATCH_PLAN = "patch_plan"


class ScanArtifactRepository:
    """Persist versioned scan artifacts."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def upsert(
        self,
        *,
        scan_id: uuid.UUID,
        artifact_type: str,
        version: int,
        payload: Dict[str, Any],
    ) -> db_models.ScanArtifact:
        """Persist without mutating an existing immutable generation.

        Identical retries return the original row. A changed payload receives
        the next generation even when a legacy caller still passes ``version=1``.
        """
        existing = await self.db.scalar(
            select(db_models.ScanArtifact).where(
                db_models.ScanArtifact.scan_id == scan_id,
                db_models.ScanArtifact.artifact_type == artifact_type,
                db_models.ScanArtifact.version == version,
            )
        )
        if existing is not None:
            payload_matches = existing.payload == payload
            if not payload_matches and existing.evidence_id is not None:
                evidence = await self.db.get(
                    db_models.EvidenceObject, existing.evidence_id
                )
                payload_matches = evidence is not None and (
                    evidence.plaintext_sha256
                    == hashlib.sha256(canonical_json(payload)).hexdigest()
                )
            if payload_matches:
                return existing
        if existing is not None:
            return await self.create_next_version(
                scan_id=scan_id, artifact_type=artifact_type, payload=payload
            )
        return await self._create_generation(
            scan_id=scan_id,
            artifact_type=artifact_type,
            version=version,
            payload=payload,
        )

    async def _create_generation(
        self,
        *,
        scan_id: uuid.UUID,
        artifact_type: str,
        version: int,
        payload: Dict[str, Any],
        scan: db_models.Scan | None = None,
    ) -> db_models.ScanArtifact:
        if scan is None:
            scan = await self.db.scalar(
                select(db_models.Scan)
                .where(db_models.Scan.id == scan_id)
                .with_for_update()
            )
        if scan is None:
            raise LookupError("Scan not found for artifact persistence.")
        artifact = db_models.ScanArtifact(
            id=uuid.uuid4(),
            scan_id=scan_id,
            attempt_id=scan.current_attempt_id,
            artifact_type=artifact_type,
            version=version,
            payload=payload if settings.EVIDENCE_DUAL_WRITE_LEGACY else None,
        )
        self.db.add(artifact)
        await self.db.flush()
        if settings.EVIDENCE_STORE_ENABLED:
            evidence = await EvidenceRepository(self.db).persist_json(
                scan=scan,
                artifact_type=artifact_type,
                version=version,
                payload=payload,
                producer={"component": "scan_artifact_repository"},
                actor_user_id=scan.user_id,
                legacy_artifact_id=artifact.id,
                commit=False,
            )
            artifact.attempt_id = evidence.attempt_id
            artifact.evidence_id = evidence.id
        await self.db.commit()
        await self.db.refresh(artifact)
        return artifact

    async def create_next_version(
        self,
        *,
        scan_id: uuid.UUID,
        artifact_type: str,
        payload: Dict[str, Any],
    ) -> db_models.ScanArtifact:
        """Append an immutable generation and retain every prior payload.

        Scan lifecycle serialization ensures one worker owns a scan at a time;
        the unique constraint remains the final guard against a split-brain
        writer. Issue 12 will associate these generations with first-class
        scan attempts.
        """
        scan = await self.db.scalar(
            select(db_models.Scan).where(db_models.Scan.id == scan_id).with_for_update()
        )
        if scan is None:
            raise LookupError("Scan not found for artifact persistence.")
        latest = await self.db.scalar(
            select(func.max(db_models.ScanArtifact.version)).where(
                db_models.ScanArtifact.scan_id == scan_id,
                db_models.ScanArtifact.artifact_type == artifact_type,
            )
        )
        return await self._create_generation(
            scan_id=scan_id,
            artifact_type=artifact_type,
            version=int(latest or 0) + 1,
            payload=payload,
            scan=scan,
        )

    async def get_by_type(
        self,
        scan_id: uuid.UUID,
        artifact_type: str,
        version: Optional[int] = None,
        attempt_id: Optional[uuid.UUID] = None,
    ) -> Optional[db_models.ScanArtifact]:
        """Fetch a specific generation, or the latest when omitted."""
        stmt = (
            select(db_models.ScanArtifact)
            .where(
                db_models.ScanArtifact.scan_id == scan_id,
                db_models.ScanArtifact.artifact_type == artifact_type,
            )
            .order_by(
                db_models.ScanArtifact.version.desc(),
                db_models.ScanArtifact.created_at.desc(),
            )
            .limit(1)
        )
        if version is not None:
            stmt = stmt.where(db_models.ScanArtifact.version == version)
        if attempt_id is not None:
            stmt = stmt.where(db_models.ScanArtifact.attempt_id == attempt_id)
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def resolve_payload(
        self,
        artifact: db_models.ScanArtifact,
        *,
        actor_user_id: int | None = None,
        audit: bool = True,
    ) -> Dict[str, Any]:
        """Prefer verified object evidence; fall back only for legacy rows."""
        if artifact.evidence_id is not None:
            evidence = await self.db.get(db_models.EvidenceObject, artifact.evidence_id)
            if evidence is None:
                raise RuntimeError("Artifact evidence metadata is missing.")
            return await EvidenceRepository(self.db).read_json(
                evidence, actor_user_id=actor_user_id, audit=audit
            )
        if artifact.payload is None:
            raise FileNotFoundError("Artifact payload is unavailable.")
        return artifact.payload

    async def delete_for_scan(self, scan_id: uuid.UUID) -> int:
        """Delete all artifacts for a scan. Returns count deleted."""
        result = await self.db.execute(
            delete(db_models.ScanArtifact).where(
                db_models.ScanArtifact.scan_id == scan_id
            )
        )
        await self.db.commit()
        return result.rowcount or 0
