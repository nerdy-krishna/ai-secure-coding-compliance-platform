"""Application boundary for durable usage-budget admission and settlement."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, is_dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Mapping

from app.infrastructure.database.repositories.llm_usage_repo import LLMUsageContext
from app.infrastructure.database.repositories.usage_budget_repo import (
    BudgetAmounts,
    BudgetDenial,
    BudgetReservationRequest,
    UsageBudgetRepository,
)
from app.shared.lib.llm_usage import PriceSnapshot


BUDGET_HARD_LIMIT_EXCEEDED = "budget_hard_limit_exceeded"
BUDGET_PRICE_UNKNOWN = "budget_price_unknown"


@dataclass(frozen=True)
class BudgetFailureSnapshot:
    policy_id: uuid.UUID
    scope: str
    dimension: str
    window: str
    remaining: int | Decimal
    requested: int | Decimal
    reset_at: datetime | None = None


class BudgetExceededError(RuntimeError):
    """Stable, privacy-safe denial raised before a billable provider request."""

    def __init__(
        self,
        *,
        code: str = BUDGET_HARD_LIMIT_EXCEEDED,
        snapshot: BudgetFailureSnapshot,
    ) -> None:
        self.code = code
        self.snapshot = snapshot
        super().__init__(code)

    @property
    def retry_after(self) -> int | None:
        if self.snapshot.reset_at is None:
            return None
        seconds = int(
            (self.snapshot.reset_at - datetime.now(timezone.utc)).total_seconds()
        )
        return max(seconds, 0)

    def as_detail(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "policy_id": str(self.snapshot.policy_id),
            "scope": self.snapshot.scope,
            "dimension": self.snapshot.dimension,
            "window": self.snapshot.window,
            "remaining": str(self.snapshot.remaining),
            "requested": str(self.snapshot.requested),
            "reset_at": (
                self.snapshot.reset_at.isoformat()
                if self.snapshot.reset_at is not None
                else None
            ),
        }


def _from_denial(denial: BudgetDenial) -> BudgetFailureSnapshot:
    return BudgetFailureSnapshot(
        policy_id=denial.policy_id,
        scope=denial.scope_kind,
        dimension=denial.dimension,
        window=denial.window_kind,
        remaining=denial.remaining,
        requested=denial.requested,
        reset_at=denial.reset_at,
    )


def _coerce_amounts(value: BudgetAmounts | Mapping[str, Any] | Any) -> BudgetAmounts:
    if isinstance(value, BudgetAmounts):
        return value
    if isinstance(value, Mapping):
        source = value
    elif is_dataclass(value):
        source = asdict(value)
    else:
        source = vars(value)

    def integer(*names: str) -> int:
        for name in names:
            candidate = source.get(name)
            if candidate is not None:
                return max(int(candidate), 0)
        return 0

    input_tokens = integer("input_tokens", "upper_bound_input_tokens")
    output_tokens = integer("output_tokens", "upper_bound_output_tokens")
    total_tokens = integer("total_tokens", "upper_bound_total_tokens")
    if not total_tokens:
        total_tokens = input_tokens + output_tokens
    uncached = integer("uncached_input_tokens", "upper_bound_uncached_input_tokens")
    if not uncached:
        uncached = input_tokens
    billable = integer("billable_tokens", "upper_bound_billable_tokens")
    if not billable:
        billable = uncached + output_tokens
    raw_usd = source.get(
        "usd",
        source.get(
            "upper_bound_usd",
            source.get("upper_bound_estimated_cost", source.get("upper_bound_cost", 0)),
        ),
    )
    return BudgetAmounts(
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=total_tokens,
        uncached_input_tokens=uncached,
        billable_tokens=billable,
        usd=Decimal(str(raw_usd or 0)),
        provider_requests=integer(
            "provider_requests", "upstream_requests", "upper_bound_request_count"
        ),
    )


def _reservation_id(reservation: Any) -> uuid.UUID:
    if isinstance(reservation, uuid.UUID):
        return reservation
    value = getattr(reservation, "id", reservation)
    return uuid.UUID(str(value))


class UsageBudgetService:
    """Coordinate policy evaluation through one transaction-capable repository.

    Repository methods own the short database transactions that protect holds
    across long provider calls.  Callers must never release a hold after an
    upstream response: uncertain accounting conservatively converts it to spend.
    """

    def __init__(self, repo: UsageBudgetRepository):
        self.repo = repo

    async def reserve_logical_call(
        self,
        context: LLMUsageContext,
        llm_config_id: uuid.UUID | None,
        estimate: BudgetAmounts | Mapping[str, Any] | Any,
        price_snapshot: PriceSnapshot | None,
        *,
        expires_at: datetime | None = None,
        parent_reservation_id: uuid.UUID | None = None,
        prepriced_estimate: bool = False,
        window_kinds: tuple[str, ...] | None = None,
        auto_parent: bool = True,
        commit: bool = True,
    ) -> uuid.UUID | None:
        attribution = await self.repo.resolve_attribution(context)
        effective_windows = window_kinds or (
            ("request", "attempt", "day", "month")
            if context.operation_kind == "pentest"
            else ("request", "scan", "day", "month")
        )
        amounts = _coerce_amounts(estimate)
        now = datetime.now(timezone.utc)
        policies = await self.repo.list_active_policies(
            tenant_id=attribution.tenant_id,
            user_id=attribution.actor_user_id,
            group_ids=attribution.group_ids,
            llm_config_id=llm_config_id,
            stage=context.stage,
            window_kinds=effective_windows,
            at=now,
        )
        if not policies:
            return None
        if price_snapshot is None and not prepriced_estimate:
            blocking = next(
                (
                    policy
                    for policy in policies
                    if policy.cap_usd is not None
                    and policy.unknown_price_action != "token_only"
                ),
                None,
            )
            if blocking is not None:
                await self.repo.record_denial(
                    tenant_id=attribution.tenant_id,
                    actor_user_id=attribution.actor_user_id,
                    operation_kind=context.operation_kind,
                    request_key=context.idempotency_key,
                    policy_id=blocking.id,
                    reason_code=BUDGET_PRICE_UNKNOWN,
                    commit=commit,
                )
                raise BudgetExceededError(
                    code=BUDGET_PRICE_UNKNOWN,
                    snapshot=BudgetFailureSnapshot(
                        policy_id=blocking.id,
                        scope=blocking.scope_kind,
                        dimension="usd",
                        window=blocking.window_kind,
                        remaining=Decimal("0"),
                        requested=Decimal("0"),
                    ),
                )
        if (
            auto_parent
            and parent_reservation_id is None
            and context.operation_kind == "scan"
            and attribution.scan_attempt_id is not None
        ):
            parent = await self.repo.find_active_scan_parent(
                attribution.scan_attempt_id,
                stage=(
                    "file_profiling"
                    if context.stage == "file_profiling"
                    else "analysis"
                ),
            )
            parent_reservation_id = parent.id if parent is not None else None
        decision = await self.repo.reserve(
            BudgetReservationRequest(
                tenant_id=attribution.tenant_id,
                idempotency_key=f"call:{context.idempotency_key}",
                operation_kind=context.operation_kind,
                request_key=context.idempotency_key,
                stage=context.stage,
                estimate=amounts,
                expires_at=expires_at or now + timedelta(hours=1),
                actor_user_id=attribution.actor_user_id,
                group_ids=attribution.group_ids,
                scan_attempt_id=attribution.scan_attempt_id,
                pentest_attempt_id=attribution.pentest_attempt_id,
                llm_config_id=llm_config_id,
                parent_reservation_id=parent_reservation_id,
                window_kinds=effective_windows,
                at=now,
            ),
            commit=commit,
        )
        if not decision.allowed:
            assert decision.denial is not None
            raise BudgetExceededError(snapshot=_from_denial(decision.denial))
        return decision.reservation.id if decision.reservation is not None else None

    async def settle_logical_call(
        self,
        reservation: uuid.UUID | Any | None,
        usage_event_id: uuid.UUID | None,
        *,
        provider_called: bool = True,
        commit: bool = True,
    ) -> Any | None:
        if reservation is None:
            return None
        reservation_id = _reservation_id(reservation)
        if usage_event_id is not None:
            return await self.repo.settle(reservation_id, usage_event_id, commit=commit)
        if provider_called:
            await self.repo.mark_accounting_unknown(
                reservation_id,
                "provider_called_usage_accounting_unknown",
                commit=commit,
            )
            return None
        await self.repo.release(reservation_id, "provider_not_called", commit=commit)
        return None

    async def release_logical_call(
        self,
        reservation: uuid.UUID | Any | None,
        reason: str,
        *,
        commit: bool = True,
    ) -> bool:
        if reservation is None:
            return True
        return await self.repo.release(
            _reservation_id(reservation), reason, commit=commit
        )

    async def reserve_scan_gate(
        self,
        scan_id: uuid.UUID,
        gate_kind: str,
        estimate: BudgetAmounts | Mapping[str, Any] | Any,
        *,
        actor_user_id: int | None = None,
    ) -> uuid.UUID | None:
        stage = {
            "profiling_approval": "file_profiling",
            "cost_approval": "analysis",
        }.get(gate_kind, gate_kind)
        identity_context = LLMUsageContext(
            operation_kind="scan",
            operation_id=str(scan_id),
            scan_id=scan_id,
            stage=stage,
            agent_name="scan_budget_gate",
            idempotency_key=f"scan-gate:{scan_id}:{gate_kind}:resolve",
            actor_user_id=actor_user_id,
        )
        attribution = await self.repo.resolve_attribution(identity_context)
        if attribution.scan_attempt_id is None:
            raise ValueError("scan budget gate requires an active scan attempt")
        if attribution.actor_user_id is None:
            raise ValueError("scan budget gate requires an attributable actor")
        await self.repo.ensure_default_scan_policy(
            tenant_id=attribution.tenant_id,
            created_by_user_id=attribution.actor_user_id,
            commit=False,
        )
        context = LLMUsageContext(
            operation_kind="scan",
            operation_id=str(scan_id),
            scan_id=scan_id,
            stage=stage,
            agent_name="scan_budget_gate",
            idempotency_key=(
                f"scan-gate:{scan_id}:{attribution.scan_attempt_id}:{gate_kind}"
            ),
            actor_user_id=actor_user_id,
        )
        # Scan estimates already carry their priced conservative upper bound.
        return await self.reserve_logical_call(
            context,
            None,
            estimate,
            price_snapshot=None,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            prepriced_estimate=True,
            window_kinds=("scan", "day", "month"),
            auto_parent=False,
            commit=False,
        )

    async def release_scan_attempt(
        self, scan_id: uuid.UUID, reason: str, *, commit: bool = False
    ) -> int:
        return await self.repo.release_scan_attempt(
            scan_id=scan_id, reason=reason, commit=commit
        )


__all__ = [
    "BUDGET_HARD_LIMIT_EXCEEDED",
    "BUDGET_PRICE_UNKNOWN",
    "BudgetExceededError",
    "BudgetFailureSnapshot",
    "UsageBudgetService",
]
