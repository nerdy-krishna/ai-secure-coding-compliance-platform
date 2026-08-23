"""Budget-exhaustion boundary for scan workflows.

An upstream request that has already been billed is allowed to settle normally.
When admission denies the *next* request, the LLM boundary raises
``BudgetExceededError``.  This module converts that domain denial into a
durable, partial-result terminal scan without misclassifying it as a provider
failure.
"""

from __future__ import annotations

import logging
from decimal import Decimal
from typing import Any, Mapping

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.usage_budget_service import (
    BudgetExceededError,
    UsageBudgetService,
)
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_attempt_repo import (
    ScanAttemptRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.usage_budget_repo import (
    BudgetAmounts,
    UsageBudgetRepository,
)
from app.shared.lib.scan_status import (
    ACTIVE_SCAN_STATUSES,
    STATUS_BUDGET_EXHAUSTED,
)

logger = logging.getLogger(__name__)


class ScanBudgetExhausted(Exception):
    """Control-flow signal for an already-persisted terminal budget denial."""


def raise_first_budget_denial(results: list[Any]) -> None:
    """Do not let ``asyncio.gather(return_exceptions=True)`` hide admission denial."""
    for result in results:
        if isinstance(result, BudgetExceededError):
            raise result


async def release_scan_budget(
    db: AsyncSession,
    scan_id: Any,
    *,
    reason: str,
) -> int:
    """Idempotently release unused scan-envelope capacity in ``db``'s transaction."""
    return await UsageBudgetService(UsageBudgetRepository(db)).release_scan_attempt(
        scan_id, reason=reason
    )


def scan_gate_estimate(details: Mapping[str, Any]) -> BudgetAmounts:
    """Map persisted conservative gate evidence to canonical budget dimensions."""
    input_tokens = max(0, int(details.get("upper_bound_input_tokens") or 0))
    output_tokens = max(0, int(details.get("upper_bound_output_tokens") or 0))
    total_tokens = input_tokens + output_tokens
    return BudgetAmounts(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        # Preflight assumes no cache hit. Settlement returns cache capacity.
        uncached_input_tokens=input_tokens,
        billable_tokens=total_tokens,
        usd=Decimal(str(details.get("upper_bound_estimated_cost") or "0")),
        provider_requests=max(
            0,
            int(
                details.get("upper_bound_request_count")
                or details.get("planned_request_count")
                or 0
            ),
        ),
    )


async def reserve_scan_gate_budget(
    db: AsyncSession,
    scan_id: Any,
    *,
    gate_kind: str,
    details: Mapping[str, Any],
    actor_user_id: int | None,
) -> Any:
    """Reserve an approved profiling/analysis tranche without committing it."""
    return await UsageBudgetService(UsageBudgetRepository(db)).reserve_scan_gate(
        scan_id,
        gate_kind,
        scan_gate_estimate(details),
        actor_user_id=actor_user_id,
    )


def _reason_snapshot(exc: BudgetExceededError) -> dict[str, Any]:
    """Return the privacy-safe stable denial payload exposed by the service."""
    return dict(exc.as_detail())


async def mark_scan_budget_exhausted(
    scan_id: Any,
    exc: BudgetExceededError,
) -> bool:
    """Release unused holds and persist terminal partial-result evidence.

    All writes share one session and commit, so an externally visible terminal
    status cannot be separated from envelope release and its audit event.
    Re-entry is harmless: the status compare-and-set rejects duplicate events,
    while reservation release is idempotent.
    """
    reason = _reason_snapshot(exc)
    stable_code = str(reason.get("code") or exc.code)
    async with AsyncSessionLocal() as db:
        repo = ScanRepository(db)
        await release_scan_budget(db, scan_id, reason=stable_code)
        changed = await repo.update_status(
            scan_id,
            STATUS_BUDGET_EXHAUSTED,
            allowed_current_statuses=ACTIVE_SCAN_STATUSES,
            commit=False,
        )
        if changed:
            await repo.set_error_message(scan_id, stable_code)
            await repo.create_scan_event(
                scan_id=scan_id,
                stage_name="BUDGET_ENFORCEMENT",
                status="BLOCKED",
                details=reason,
                activity_kind="budget",
                commit=False,
            )
            attempt = await ScanAttemptRepository(db).mark_current_terminal(
                scan_id, status="failed", commit=False
            )
            if attempt is not None:
                from app.infrastructure.database.repositories.evidence_repo import (
                    EvidenceRepository,
                )

                await EvidenceRepository(db).finalize_attempt(
                    attempt.id, actor_user_id=None, commit=False
                )
        await db.commit()
    logger.info(
        "scan budget terminal persisted",
        extra={"scan_id": str(scan_id), "reason_code": stable_code},
    )
    return changed
