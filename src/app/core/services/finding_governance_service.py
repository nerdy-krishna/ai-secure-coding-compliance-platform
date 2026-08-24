"""Application service for evidence-first finding governance."""

from __future__ import annotations

import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy import select

from app.api.v1.schemas.finding_governance import (
    FindingLineageListResponse,
    FindingLineageRecordResponse,
    FindingPolicyEvaluationResponse,
    FindingPolicyRequest,
    FindingPolicyResponse,
    FindingPortfolioTrendsResponse,
    FindingTrendBucketResponse,
    FindingWaiverEventResponse,
    FindingWaiverRequest,
    FindingWaiverResponse,
)
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.finding_governance_repo import (
    FindingGovernanceRepository,
)
from app.shared.lib.finding_governance import GatePolicy


class FindingGovernanceService:
    def __init__(self, repo: FindingGovernanceRepository):
        self.repo = repo

    async def _scan(
        self,
        scan_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
    ) -> db_models.Scan:
        scan = await self.repo.visible_scan(
            scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
        )
        if scan is None:
            raise HTTPException(status_code=404, detail="Scan not found.")
        return scan

    async def lineage(
        self,
        scan_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
        finding_id: int | None = None,
    ) -> FindingLineageListResponse:
        scan = await self._scan(
            scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
        )
        records = await self.repo.lineage_for_scan(scan_id)
        if finding_id is not None:
            records = [row for row in records if row.finding_id == finding_id]
            if not records:
                raise HTTPException(
                    status_code=404, detail="Finding evidence not found."
                )
        counts = Counter(row.baseline_state for row in records)
        evaluation = await self.repo.db.scalar(
            select(db_models.FindingPolicyEvaluation)
            .where(
                db_models.FindingPolicyEvaluation.scan_id == scan_id,
                db_models.FindingPolicyEvaluation.attempt_id
                == scan.current_attempt_id,
            )
            .order_by(db_models.FindingPolicyEvaluation.created_at.desc())
            .limit(1)
        )
        revoked = select(db_models.FindingWaiverEvent.waiver_id).where(
            db_models.FindingWaiverEvent.action == "revoked"
        )
        waivers = list(
            (
                await self.repo.db.scalars(
                    select(db_models.FindingWaiver).where(
                        db_models.FindingWaiver.scan_id == scan_id,
                        db_models.FindingWaiver.expires_at
                        > datetime.now(timezone.utc),
                        db_models.FindingWaiver.id.not_in(revoked),
                    )
                )
            ).all()
        )
        return FindingLineageListResponse(
            scan_id=scan_id,
            counts={
                state: counts.get(state, 0)
                for state in ("new", "fixed", "unchanged", "reintroduced")
            },
            items=[FindingLineageRecordResponse.model_validate(row) for row in records],
            policy_evaluation=(
                FindingPolicyEvaluationResponse.model_validate(evaluation)
                if evaluation
                else None
            ),
            active_waivers=[
                {
                    "id": str(row.id),
                    "finding_id": row.finding_id,
                    "fingerprint": row.fingerprint,
                    "scope": row.scope,
                    "reason": row.reason,
                    "expires_at": row.expires_at.isoformat(),
                }
                for row in waivers
            ],
        )

    async def latest_policy(self, tenant_id: uuid.UUID) -> FindingPolicyResponse:
        policy = await self.repo.latest_policy(tenant_id, create_default=True)
        assert policy is not None
        await self.repo.db.commit()
        return FindingPolicyResponse.model_validate(policy)

    async def create_policy(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        request: FindingPolicyRequest,
    ) -> FindingPolicyResponse:
        policy = await self.repo.create_policy_version(
            tenant_id=tenant_id,
            actor_user_id=actor_user_id,
            reason=request.reason.strip(),
            policy=GatePolicy(
                minimum_severity=request.minimum_severity,
                minimum_confidence=request.minimum_confidence,
                require_complete_coverage=request.require_complete_coverage,
                allow_waivers=request.allow_waivers,
                minimum_waiver_remaining_hours=request.minimum_waiver_remaining_hours,
            ),
        )
        return FindingPolicyResponse.model_validate(policy)

    async def evaluate(
        self,
        scan_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
    ) -> FindingPolicyEvaluationResponse:
        await self._scan(
            scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
        )
        evaluation = await self.repo.evaluate_scan_policy(scan_id)
        return FindingPolicyEvaluationResponse.model_validate(evaluation)

    async def grant_waiver(
        self,
        scan_id: uuid.UUID,
        finding_id: int,
        request: FindingWaiverRequest,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
        actor_user_id: int,
    ) -> FindingWaiverResponse:
        scan = await self._scan(
            scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
        )
        now = datetime.now(timezone.utc)
        if request.expires_at <= now:
            raise HTTPException(
                status_code=400, detail="Waiver expiry must be in the future."
            )
        if request.expires_at > now + timedelta(days=365):
            raise HTTPException(
                status_code=400, detail="Waiver expiry cannot exceed one year."
            )
        finding = await self.repo.db.scalar(
            select(db_models.Finding).where(
                db_models.Finding.id == finding_id,
                db_models.Finding.scan_id == scan.id,
                db_models.Finding.tenant_id == tenant_id,
            )
        )
        if finding is None:
            raise HTTPException(status_code=404, detail="Finding not found.")
        waiver = await self.repo.grant_waiver(
            scan=scan,
            finding=finding,
            scope=request.scope,
            reason=request.reason.strip(),
            expires_at=request.expires_at,
            actor_user_id=actor_user_id,
        )
        _, events = await self.repo.waiver_history(waiver.id, tenant_id=tenant_id)
        return self._waiver_response(waiver, events)

    async def revoke_waiver(
        self,
        waiver_id: uuid.UUID,
        *,
        reason: str,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
        actor_user_id: int,
    ) -> FindingWaiverResponse:
        waiver, events = await self.repo.waiver_history(waiver_id, tenant_id=tenant_id)
        if waiver is None or waiver.scan_id is None:
            raise HTTPException(status_code=404, detail="Waiver not found.")
        await self._scan(
            waiver.scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
        )
        if any(event.action == "revoked" for event in events):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Waiver is already revoked.",
            )
        await self.repo.revoke_waiver(
            waiver, actor_user_id=actor_user_id, reason=reason.strip()
        )
        _, events = await self.repo.waiver_history(waiver_id, tenant_id=tenant_id)
        return self._waiver_response(waiver, events)

    async def waiver_history(
        self,
        waiver_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
    ) -> FindingWaiverResponse:
        waiver, events = await self.repo.waiver_history(waiver_id, tenant_id=tenant_id)
        if waiver is None or waiver.scan_id is None:
            raise HTTPException(status_code=404, detail="Waiver not found.")
        await self._scan(
            waiver.scan_id, tenant_id=tenant_id, visible_user_ids=visible_user_ids
        )
        return self._waiver_response(waiver, events)

    @staticmethod
    def _waiver_response(waiver, events) -> FindingWaiverResponse:
        return FindingWaiverResponse(
            **{
                key: getattr(waiver, key)
                for key in (
                    "id",
                    "scan_id",
                    "finding_id",
                    "fingerprint",
                    "scope",
                    "scope_value",
                    "reason",
                    "expires_at",
                    "actor_user_id",
                    "created_at",
                )
            },
            events=[
                FindingWaiverEventResponse.model_validate(event) for event in events
            ],
        )

    async def trends(
        self,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
        days: int,
    ) -> FindingPortfolioTrendsResponse:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        items = await self.repo.portfolio_trends(
            tenant_id=tenant_id,
            visible_user_ids=visible_user_ids,
            since=since,
        )
        return FindingPortfolioTrendsResponse(
            since=since,
            items=[FindingTrendBucketResponse.model_validate(item) for item in items],
        )
