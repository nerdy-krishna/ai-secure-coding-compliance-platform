"""Resumable legacy ScanArtifact JSONB -> encrypted evidence backfill.

Run inside Docker:
    python -m app.scripts.backfill_evidence_store --batch-size 100
"""

from __future__ import annotations

import argparse
import asyncio
import logging

from sqlalchemy import select

from app.config.config import settings
from app.infrastructure.database import AsyncSessionLocal, models as db_models
from app.infrastructure.database.repositories.evidence_repo import EvidenceRepository

logger = logging.getLogger(__name__)


async def backfill_batch(batch_size: int = 100) -> int:
    if not settings.EVIDENCE_STORE_ENABLED:
        raise RuntimeError("EVIDENCE_STORE_ENABLED must be true for backfill.")
    async with AsyncSessionLocal() as db:
        artifacts = list(
            (
                await db.scalars(
                    select(db_models.ScanArtifact)
                    .where(
                        db_models.ScanArtifact.evidence_id.is_(None),
                        db_models.ScanArtifact.payload.isnot(None),
                    )
                    .order_by(
                        db_models.ScanArtifact.created_at, db_models.ScanArtifact.id
                    )
                    .limit(batch_size)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        repo = EvidenceRepository(db)
        for artifact in artifacts:
            scan = await db.get(db_models.Scan, artifact.scan_id)
            if scan is None or artifact.payload is None:
                continue
            evidence = await repo.persist_json(
                scan=scan,
                artifact_type=artifact.artifact_type,
                version=artifact.version,
                payload=artifact.payload,
                producer={
                    "component": "legacy_evidence_backfill",
                    "legacy_artifact_id": str(artifact.id),
                },
                actor_user_id=scan.user_id,
                legacy_artifact_id=artifact.id,
                commit=False,
            )
            artifact.attempt_id = evidence.attempt_id
            artifact.evidence_id = evidence.id
        await db.commit()
        return len(artifacts)


async def run(batch_size: int) -> int:
    total = 0
    while True:
        count = await backfill_batch(batch_size)
        total += count
        logger.info("evidence_backfill.batch", extra={"count": count, "total": total})
        if count < batch_size:
            return total


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch-size", type=int, default=100)
    args = parser.parse_args()
    if args.batch_size < 1 or args.batch_size > 1000:
        parser.error("--batch-size must be between 1 and 1000")
    total = asyncio.run(run(args.batch_size))
    print(f"Backfilled {total} legacy scan artifacts.")


if __name__ == "__main__":
    main()
