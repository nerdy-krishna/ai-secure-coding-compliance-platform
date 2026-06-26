"""ScanArtifactRepository — CRUD for versioned scan artifacts."""

from __future__ import annotations

import uuid
from typing import Any, Dict, Optional

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

ARTIFACT_TYPE_LINEAGE = "finding_lineage"


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
        """Insert or overwrite one version of a scan artifact."""
        stmt = (
            pg_insert(db_models.ScanArtifact)
            .values(
                id=uuid.uuid4(),
                scan_id=scan_id,
                artifact_type=artifact_type,
                version=version,
                payload=payload,
            )
            .on_conflict_do_update(
                constraint="uq_scan_artifacts_type_version",
                set_={"payload": payload},
            )
            .returning(db_models.ScanArtifact)
        )
        result = await self.db.execute(stmt)
        await self.db.commit()
        return result.scalar_one()

    async def get_by_type(
        self, scan_id: uuid.UUID, artifact_type: str, version: int = 1
    ) -> Optional[db_models.ScanArtifact]:
        """Fetch the latest payload for a given artifact type and version."""
        stmt = (
            select(db_models.ScanArtifact)
            .where(
                db_models.ScanArtifact.scan_id == scan_id,
                db_models.ScanArtifact.artifact_type == artifact_type,
                db_models.ScanArtifact.version == version,
            )
            .order_by(db_models.ScanArtifact.created_at.desc())
            .limit(1)
        )
        result = await self.db.execute(stmt)
        return result.scalar_one_or_none()

    async def delete_for_scan(self, scan_id: uuid.UUID) -> int:
        """Delete all artifacts for a scan. Returns count deleted."""
        result = await self.db.execute(
            delete(db_models.ScanArtifact).where(
                db_models.ScanArtifact.scan_id == scan_id
            )
        )
        await self.db.commit()
        return result.rowcount or 0
