"""System-scoped periodic enforcement for Rule Foundry lifecycle deadlines."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import Iterable

from sqlalchemy import select

from app.infrastructure.database import AsyncSessionLocal, models as db_models
from app.infrastructure.database.repositories.rule_foundry_repo import (
    RuleFoundryRepository,
)
from app.infrastructure.database.tenant_context import system_principal_task


logger = logging.getLogger(__name__)
SWEEP_INTERVAL_SECONDS = 900
BATCH_SIZE = 100


async def apply_due_lifecycle_transitions(
    *,
    repo: RuleFoundryRepository,
    candidates: Iterable[db_models.RuleFoundryCandidate],
    shadows: Iterable[
        tuple[db_models.RuleFoundryCandidate, db_models.RuleFoundryDeployment]
    ],
    now: datetime,
) -> tuple[int, int]:
    """Apply exact-boundary, state-guarded transitions; safe to call repeatedly."""

    expired = 0
    review_required = 0
    for candidate in candidates:
        if candidate.expires_at <= now and candidate.status in {
            "pending_review",
            "approved",
            "rejected",
        }:
            candidate.status = "expired"
            await repo.add_event(
                candidate=candidate,
                action="expired",
                actor_user_id=None,
                reason="30-day unpromoted candidate expiry",
            )
            expired += 1
    for candidate, deployment in shadows:
        if (
            deployment.state == "shadow"
            and deployment.review_due_at is not None
            and deployment.review_due_at <= now
        ):
            deployment.state = "review_required"
            candidate.status = "review_required"
            await repo.add_event(
                candidate=candidate,
                action="review_required",
                actor_user_id=None,
                reason="90-day shadow review deadline reached",
                details={"trigger": "shadow_review_due"},
            )
            review_required += 1
    return expired, review_required


@system_principal_task("rule-foundry-sweeper")
async def enforce_rule_foundry_lifecycle() -> tuple[int, int]:
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as db:
        candidates = list(
            (
                await db.scalars(
                    select(db_models.RuleFoundryCandidate)
                    .where(
                        db_models.RuleFoundryCandidate.expires_at <= now,
                        db_models.RuleFoundryCandidate.status.in_(
                            ("pending_review", "approved", "rejected")
                        ),
                    )
                    .order_by(db_models.RuleFoundryCandidate.expires_at)
                    .limit(BATCH_SIZE)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        shadows = list(
            (
                await db.execute(
                    select(
                        db_models.RuleFoundryCandidate,
                        db_models.RuleFoundryDeployment,
                    )
                    .join(
                        db_models.RuleFoundryDeployment,
                        db_models.RuleFoundryDeployment.candidate_id
                        == db_models.RuleFoundryCandidate.id,
                    )
                    .where(
                        db_models.RuleFoundryDeployment.state == "shadow",
                        db_models.RuleFoundryDeployment.review_due_at <= now,
                        db_models.RuleFoundryDeployment.ended_at.is_(None),
                    )
                    .order_by(db_models.RuleFoundryDeployment.review_due_at)
                    .limit(BATCH_SIZE)
                    .with_for_update(skip_locked=True)
                )
            ).all()
        )
        counts = await apply_due_lifecycle_transitions(
            repo=RuleFoundryRepository(db),
            candidates=candidates,
            shadows=shadows,
            now=now,
        )
        await db.commit()
        return counts


async def run_rule_foundry_sweeper(stop_event: asyncio.Event) -> None:
    logger.info("rule_foundry_sweeper.started")
    while not stop_event.is_set():
        try:
            expired, review_required = await enforce_rule_foundry_lifecycle()
            if expired or review_required:
                logger.info(
                    "rule_foundry_sweeper.transitioned",
                    extra={
                        "expired_candidates": expired,
                        "review_required_shadows": review_required,
                    },
                )
        except Exception:
            logger.error("rule_foundry_sweeper.tick_failed", exc_info=True)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=SWEEP_INTERVAL_SECONDS)
        except asyncio.TimeoutError:
            continue
    logger.info("rule_foundry_sweeper.stopped")


__all__ = [
    "apply_due_lifecycle_transitions",
    "enforce_rule_foundry_lifecycle",
    "run_rule_foundry_sweeper",
]
