"""Tenant-scoped persistence boundary for governed rule candidates."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.shared.lib.rule_foundry import (
    PROMOTED_FAILURE_WINDOW,
    sustained_promoted_failure_requires_review,
)


class RuleFoundryConflictError(RuntimeError):
    pass


class RuleFoundryRepository:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def source_finding(
        self, *, tenant_id: uuid.UUID, finding_id: int
    ) -> db_models.Finding | None:
        return await self.db.scalar(
            select(db_models.Finding).where(
                db_models.Finding.id == finding_id,
                db_models.Finding.tenant_id == tenant_id,
            )
        )

    async def source_lineage(
        self, *, tenant_id: uuid.UUID, finding_id: int
    ) -> db_models.FindingLineageRecord | None:
        return await self.db.scalar(
            select(db_models.FindingLineageRecord)
            .where(
                db_models.FindingLineageRecord.tenant_id == tenant_id,
                db_models.FindingLineageRecord.finding_id == finding_id,
            )
            .order_by(db_models.FindingLineageRecord.created_at.desc())
            .limit(1)
        )

    async def create_candidate(
        self,
        *,
        candidate: db_models.RuleFoundryCandidate,
        payload: Mapping[str, Any] | None,
    ) -> db_models.RuleFoundryCandidate:
        self.db.add(candidate)
        await self.db.flush()
        if candidate.registry_kind == "semgrep":
            self.db.add(
                db_models.RuleFoundrySemgrepCandidate(
                    candidate_id=candidate.id,
                    tenant_id=candidate.tenant_id,
                    rule=dict(payload or {}),
                )
            )
        elif candidate.registry_kind == "gitleaks":
            self.db.add(
                db_models.RuleFoundryGitleaksCandidate(
                    candidate_id=candidate.id,
                    tenant_id=candidate.tenant_id,
                    rule=dict(payload or {}),
                )
            )
        elif candidate.registry_kind == "osv":
            self.db.add(
                db_models.RuleFoundryOsvCandidate(
                    candidate_id=candidate.id,
                    tenant_id=candidate.tenant_id,
                    advisory=dict(payload or {}),
                )
            )
        try:
            await self.db.flush()
        except IntegrityError as exc:
            raise RuleFoundryConflictError(
                "A candidate with this stable identity already exists."
            ) from exc
        return candidate

    async def get_candidate(
        self, *, tenant_id: uuid.UUID, candidate_id: uuid.UUID, lock: bool = False
    ) -> db_models.RuleFoundryCandidate | None:
        statement = select(db_models.RuleFoundryCandidate).where(
            db_models.RuleFoundryCandidate.id == candidate_id,
            db_models.RuleFoundryCandidate.tenant_id == tenant_id,
        )
        if lock:
            statement = statement.with_for_update()
        return await self.db.scalar(statement)

    async def list_candidates(
        self,
        *,
        tenant_id: uuid.UUID,
        page: int,
        page_size: int,
        status: str | None = None,
    ) -> tuple[list[db_models.RuleFoundryCandidate], int]:
        filters = [db_models.RuleFoundryCandidate.tenant_id == tenant_id]
        if status:
            filters.append(db_models.RuleFoundryCandidate.status == status)
        total = int(
            await self.db.scalar(
                select(func.count(db_models.RuleFoundryCandidate.id)).where(*filters)
            )
            or 0
        )
        rows = await self.db.scalars(
            select(db_models.RuleFoundryCandidate)
            .where(*filters)
            .order_by(db_models.RuleFoundryCandidate.created_at.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
        return list(rows.all()), total

    async def candidate_payload(
        self, candidate: db_models.RuleFoundryCandidate
    ) -> dict[str, Any] | None:
        model_and_field = {
            "semgrep": (db_models.RuleFoundrySemgrepCandidate, "rule"),
            "gitleaks": (db_models.RuleFoundryGitleaksCandidate, "rule"),
            "osv": (db_models.RuleFoundryOsvCandidate, "advisory"),
        }.get(candidate.registry_kind)
        if model_and_field is None:
            return None
        model, field = model_and_field
        row = await self.db.get(model, candidate.id)
        return dict(getattr(row, field)) if row is not None else None

    async def latest_version(
        self, *, tenant_id: uuid.UUID, candidate_id: uuid.UUID
    ) -> db_models.RuleFoundryVersion | None:
        return await self.db.scalar(
            select(db_models.RuleFoundryVersion)
            .where(
                db_models.RuleFoundryVersion.tenant_id == tenant_id,
                db_models.RuleFoundryVersion.candidate_id == candidate_id,
            )
            .order_by(db_models.RuleFoundryVersion.version.desc())
            .limit(1)
        )

    async def add_version(
        self,
        *,
        tenant_id: uuid.UUID,
        candidate_id: uuid.UUID,
        canonical_payload: Mapping[str, Any],
        payload_sha256: str,
        signature: str,
        signature_algorithm: str,
        signing_key_id: str,
        quality_metrics: Mapping[str, Any],
        reviewer_decision: Mapping[str, Any],
        reviewer_user_id: int,
    ) -> db_models.RuleFoundryVersion:
        latest = await self.latest_version(
            tenant_id=tenant_id, candidate_id=candidate_id
        )
        row = db_models.RuleFoundryVersion(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            candidate_id=candidate_id,
            version=(latest.version + 1) if latest else 1,
            canonical_payload=dict(canonical_payload),
            payload_sha256=payload_sha256,
            signature=signature,
            signature_algorithm=signature_algorithm,
            signing_key_id=signing_key_id,
            quality_metrics=dict(quality_metrics),
            reviewer_decision=dict(reviewer_decision),
            reviewer_user_id=reviewer_user_id,
        )
        self.db.add(row)
        await self.db.flush()
        return row

    async def active_deployment(
        self, *, tenant_id: uuid.UUID, candidate_id: uuid.UUID, lock: bool = False
    ) -> db_models.RuleFoundryDeployment | None:
        statement = select(db_models.RuleFoundryDeployment).where(
            db_models.RuleFoundryDeployment.tenant_id == tenant_id,
            db_models.RuleFoundryDeployment.candidate_id == candidate_id,
            db_models.RuleFoundryDeployment.ended_at.is_(None),
        )
        if lock:
            statement = statement.with_for_update()
        return await self.db.scalar(statement)

    async def last_promoted_version(
        self, *, tenant_id: uuid.UUID, candidate_id: uuid.UUID
    ) -> uuid.UUID | None:
        return await self.db.scalar(
            select(db_models.RuleFoundryDeployment.version_id)
            .where(
                db_models.RuleFoundryDeployment.tenant_id == tenant_id,
                db_models.RuleFoundryDeployment.candidate_id == candidate_id,
                db_models.RuleFoundryDeployment.state.in_(("promoted", "superseded")),
            )
            .order_by(db_models.RuleFoundryDeployment.promoted_at.desc())
            .limit(1)
        )

    async def shadow_totals(
        self, *, tenant_id: uuid.UUID, deployment_id: uuid.UUID
    ) -> tuple[int, int]:
        row = (
            await self.db.execute(
                select(
                    func.coalesce(
                        func.sum(db_models.RuleFoundryShadowObservation.eligible_files), 0
                    ),
                    func.coalesce(
                        func.sum(
                            db_models.RuleFoundryShadowObservation.unexpected_matches
                        ),
                        0,
                    ),
                ).where(
                    db_models.RuleFoundryShadowObservation.tenant_id == tenant_id,
                    db_models.RuleFoundryShadowObservation.deployment_id == deployment_id,
                )
            )
        ).one()
        return int(row[0]), int(row[1])

    async def add_event(
        self,
        *,
        candidate: db_models.RuleFoundryCandidate,
        action: str,
        actor_user_id: int | None,
        reason: str,
        details: Mapping[str, Any] | None = None,
    ) -> None:
        self.db.add(
            db_models.RuleFoundryEvent(
                tenant_id=candidate.tenant_id,
                candidate_id=candidate.id,
                action=action,
                actor_user_id=actor_user_id,
                reason=reason[:500],
                details=dict(details or {}),
            )
        )

    async def baseline_median_ms(self) -> str:
        value = await self.db.scalar(
            select(db_models.SystemConfiguration.value).where(
                db_models.SystemConfiguration.key == "rule_foundry.baseline_metrics"
            )
        )
        if isinstance(value, dict) and value.get("median_ms") is not None:
            return str(value["median_ms"])
        return "100"

    async def expire_due(self, *, tenant_id: uuid.UUID, now: datetime) -> int:
        rows = await self.db.scalars(
            select(db_models.RuleFoundryCandidate)
            .where(
                db_models.RuleFoundryCandidate.tenant_id == tenant_id,
                db_models.RuleFoundryCandidate.expires_at <= now,
                db_models.RuleFoundryCandidate.status.in_(
                    ("pending_review", "approved", "rejected")
                ),
            )
            .with_for_update(skip_locked=True)
        )
        candidates = list(rows.all())
        for candidate in candidates:
            candidate.status = "expired"
            await self.add_event(
                candidate=candidate,
                action="expired",
                actor_user_id=None,
                reason="30-day unpromoted candidate expiry",
            )
        return len(candidates)

    async def record_promoted_degradation(
        self,
        *,
        tenant_id: uuid.UUID,
        candidate_id: uuid.UUID,
        scan_id: uuid.UUID,
        reason_code: str,
    ) -> bool:
        """Idempotently record a failure and require review only when sustained."""

        candidate = await self.get_candidate(
            tenant_id=tenant_id, candidate_id=candidate_id, lock=True
        )
        if candidate is None:
            return False
        deployment = await self.active_deployment(
            tenant_id=tenant_id, candidate_id=candidate_id, lock=True
        )
        if deployment is None or deployment.promoted_at is None:
            return False
        if deployment.state == "review_required":
            return True
        if deployment.state != "promoted":
            return False
        scan_text = str(scan_id)
        existing = await self.db.scalar(
            select(db_models.RuleFoundryEvent.id).where(
                db_models.RuleFoundryEvent.tenant_id == tenant_id,
                db_models.RuleFoundryEvent.candidate_id == candidate_id,
                db_models.RuleFoundryEvent.action == "runtime_degraded",
                db_models.RuleFoundryEvent.details["scan_id"].as_string() == scan_text,
            )
        )
        if existing is not None:
            return False
        now = datetime.now(timezone.utc)
        await self.add_event(
            candidate=candidate,
            action="runtime_degraded",
            actor_user_id=None,
            reason="promoted tenant rule pack execution degraded",
            details={"scan_id": scan_text, "reason_code": reason_code[:64]},
        )
        await self.db.flush()
        count = int(
            await self.db.scalar(
                select(
                    func.count(
                        func.distinct(
                            db_models.RuleFoundryEvent.details["scan_id"].as_string()
                        )
                    )
                ).where(
                    db_models.RuleFoundryEvent.tenant_id == tenant_id,
                    db_models.RuleFoundryEvent.candidate_id == candidate_id,
                    db_models.RuleFoundryEvent.action == "runtime_degraded",
                    db_models.RuleFoundryEvent.created_at
                    >= now - PROMOTED_FAILURE_WINDOW,
                )
            )
            or 0
        )
        if sustained_promoted_failure_requires_review(count):
            deployment.state = "review_required"
            candidate.status = "review_required"
            await self.add_event(
                candidate=candidate,
                action="review_required",
                actor_user_id=None,
                reason="sustained promoted-pack execution degradation",
                details={
                    "trigger": "sustained_quality_threshold_breach",
                    "distinct_failed_scans": count,
                    "window_hours": int(PROMOTED_FAILURE_WINDOW.total_seconds() // 3600),
                },
            )
            return True
        return False
