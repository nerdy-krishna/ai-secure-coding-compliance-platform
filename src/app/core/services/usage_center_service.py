"""Application boundary for scoped usage analytics and budget presentation."""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_UP
from typing import Any, Literal

from app.api.v1.schemas.usage_budgets import BudgetCaps, UsageBudgetPolicyCreate
from app.api.v1.schemas.usage_center import (
    UsageBreakdownItem,
    UsageBudgetStateRead,
    UsageTotals,
    UsageTrendPoint,
)
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.usage_budget_repo import (
    UsageBudgetRepository,
)
from app.infrastructure.database.repositories.usage_center_repo import (
    UsageCenterRepository,
    UsageQuery,
)
from app.shared.lib.permissions import (
    AUDIT_READ,
    GROUP_MANAGE,
    SCAN_READ_TENANT,
    TENANT_POLICY_MANAGE,
)


_ZERO = Decimal("0")
_PERCENT = Decimal("100")
_MONEY_QUANTUM = Decimal("0.000000000001")


@dataclass(frozen=True)
class UsageVisibility:
    scope: Literal["self", "group", "tenant"]
    visible_user_ids: tuple[int, ...] | None
    visible_group_ids: tuple[uuid.UUID, ...] | None
    tenant_wide: bool


class UsageScopeError(ValueError):
    """A requested identifier is outside the caller's usage visibility."""


def encode_cursor(created_at: datetime, event_id: uuid.UUID) -> str:
    raw = json.dumps(
        [created_at.astimezone(timezone.utc).isoformat(), str(event_id)],
        separators=(",", ":"),
    ).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(value: str) -> tuple[datetime, uuid.UUID]:
    try:
        padded = value + "=" * (-len(value) % 4)
        timestamp, event_id = json.loads(
            base64.urlsafe_b64decode(padded.encode()).decode()
        )
        parsed = datetime.fromisoformat(timestamp)
        if parsed.tzinfo is None:
            raise ValueError
        return parsed.astimezone(timezone.utc), uuid.UUID(event_id)
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise UsageScopeError("invalid usage cursor") from exc


class UsageCenterService:
    def __init__(self, repo: UsageCenterRepository):
        self.repo = repo

    async def resolve_visibility(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: int,
        permissions: frozenset[str],
        dependency_visible_user_ids: list[int] | None,
    ) -> UsageVisibility:
        tenant_wide = bool(
            permissions
            & {
                SCAN_READ_TENANT,
                AUDIT_READ,
                TENANT_POLICY_MANAGE,
                GROUP_MANAGE,
            }
        )
        if tenant_wide:
            return UsageVisibility("tenant", None, None, True)
        owned_group_ids = tuple(
            await self.repo.user_group_ids(
                tenant_id=tenant_id, user_id=user_id, owner_only=True
            )
        )
        if not owned_group_ids:
            return UsageVisibility("self", (user_id,), (), False)
        owned_users = set(
            await self.repo.group_user_ids(
                tenant_id=tenant_id, group_ids=owned_group_ids
            )
        )
        # The standard visibility dependency remains an upper bound. This
        # additional owner-role restriction prevents ordinary group members
        # from seeing peers' spend.
        if dependency_visible_user_ids is not None:
            owned_users.intersection_update(dependency_visible_user_ids)
        owned_users.add(user_id)
        return UsageVisibility(
            "group", tuple(sorted(owned_users)), owned_group_ids, False
        )

    def authorize_query(
        self, query: UsageQuery, visibility: UsageVisibility
    ) -> UsageQuery:
        if (
            query.user_id is not None
            and visibility.visible_user_ids is not None
            and query.user_id not in visibility.visible_user_ids
        ):
            raise UsageScopeError("usage scope not found")
        if (
            query.group_id is not None
            and visibility.visible_group_ids is not None
            and query.group_id not in visibility.visible_group_ids
        ):
            raise UsageScopeError("usage scope not found")
        return replace(query, visible_user_ids=visibility.visible_user_ids)

    @staticmethod
    def _totals(event: Any, reservation: Any | None = None) -> UsageTotals:
        event_values = event._mapping if hasattr(event, "_mapping") else event
        reservation_values = (
            reservation._mapping
            if reservation is not None and hasattr(reservation, "_mapping")
            else (reservation or {})
        )
        actual = Decimal(str(event_values.get("actual_cost") or 0))
        estimated = Decimal(
            str(event_values.get("event_estimated_cost") or 0)
        ) + Decimal(str(reservation_values.get("reservation_estimated_cost") or 0))
        input_tokens = int(event_values.get("input_tokens") or 0)
        cache_read = int(event_values.get("cache_read_tokens") or 0)
        hit_rate = (
            (Decimal(cache_read) * _PERCENT / Decimal(input_tokens)).quantize(
                Decimal("0.01"), rounding=ROUND_HALF_UP
            )
            if input_tokens > 0
            else _ZERO
        )
        return UsageTotals(
            actual_cost=actual.quantize(_MONEY_QUANTUM),
            estimated_cost=estimated.quantize(_MONEY_QUANTUM),
            reconciled_cost=Decimal(
                str(event_values.get("reconciled_cost") or 0)
            ).quantize(_MONEY_QUANTUM),
            reserved_cost=Decimal(
                str(reservation_values.get("reserved_cost") or 0)
            ).quantize(_MONEY_QUANTUM),
            variance=(actual - estimated).quantize(_MONEY_QUANTUM),
            input_tokens=input_tokens,
            output_tokens=int(event_values.get("output_tokens") or 0),
            total_tokens=int(event_values.get("total_tokens") or 0),
            cache_read_tokens=cache_read,
            cache_write_tokens=int(event_values.get("cache_write_tokens") or 0),
            reasoning_tokens=int(event_values.get("reasoning_tokens") or 0),
            requests=int(event_values.get("requests") or 0),
            events=int(event_values.get("events") or 0),
            unknown_events=int(event_values.get("unknown_events") or 0),
            estimated_events=int(event_values.get("estimated_events") or 0),
            reconciled_events=int(event_values.get("reconciled_events") or 0),
            reserved_requests=int(reservation_values.get("reserved_requests") or 0),
            cache_hit_rate=hit_rate,
        )

    async def summary(self, query: UsageQuery) -> UsageTotals:
        event, reservation = await self.repo.summary(query)
        return self._totals(event, reservation)

    async def trends(
        self,
        query: UsageQuery,
        interval: Literal["hour", "day", "week", "month"],
    ) -> list[UsageTrendPoint]:
        events, reservations = await self.repo.trends(query, interval=interval)
        reservation_by_bucket = {row.bucket: row for row in reservations}
        event_by_bucket = {row.bucket: row for row in events}
        buckets = sorted(set(event_by_bucket) | set(reservation_by_bucket))
        empty: dict[str, int] = {}
        return [
            UsageTrendPoint(
                bucket=bucket,
                **self._totals(
                    event_by_bucket.get(bucket, empty),
                    reservation_by_bucket.get(bucket),
                ).model_dump(),
            )
            for bucket in buckets
        ]

    async def breakdown(
        self,
        query: UsageQuery,
        *,
        dimension: str,
        page: int,
        page_size: int,
    ) -> tuple[list[UsageBreakdownItem], int]:
        rows, count = await self.repo.breakdown(
            query, dimension=dimension, page=page, page_size=page_size
        )
        return [
            UsageBreakdownItem(key=str(row.key), **self._totals(row).model_dump())
            for row in rows
        ], count

    async def budget_state(
        self,
        *,
        tenant_id: uuid.UUID,
        user_id: int,
        visibility: UsageVisibility,
    ) -> tuple[
        list[UsageBudgetStateRead],
        list[db_models.UsageBudgetThresholdEvent],
        list[db_models.AuthorizationAuditEvent],
    ]:
        now = datetime.now(timezone.utc)
        group_ids = await self.repo.user_group_ids(tenant_id=tenant_id, user_id=user_id)
        rows = await self.repo.current_budget_rows(
            tenant_id=tenant_id,
            user_id=user_id,
            group_ids=group_ids,
            tenant_wide=visibility.tenant_wide,
            at=now,
        )
        states: list[UsageBudgetStateRead] = []
        for policy, counter in rows:
            spent_usd = Decimal(str(counter.spent_usd if counter else 0))
            held_usd = Decimal(str(counter.held_usd if counter else 0))
            spent_tokens = int(counter.spent_total_tokens if counter else 0)
            held_tokens = int(counter.held_total_tokens if counter else 0)
            ratios: list[Decimal] = []
            if policy.cap_usd is not None and policy.cap_usd > 0:
                ratios.append((spent_usd + held_usd) * _PERCENT / policy.cap_usd)
            if policy.cap_total_tokens is not None and policy.cap_total_tokens > 0:
                ratios.append(
                    Decimal(spent_tokens + held_tokens)
                    * _PERCENT
                    / Decimal(policy.cap_total_tokens)
                )
            utilization = max(ratios, default=_ZERO).quantize(Decimal("0.01"))
            if utilization >= 100:
                threshold_state = "exhausted"
            elif utilization >= policy.soft_threshold_high:
                threshold_state = "critical"
            elif utilization >= policy.soft_threshold_low:
                threshold_state = "warning"
            else:
                threshold_state = "normal"
            states.append(
                UsageBudgetStateRead(
                    policy_id=policy.id,
                    scope=policy.scope_kind,
                    target_group_id=policy.target_group_id,
                    target_user_id=policy.target_user_id,
                    window=policy.window_kind,
                    window_key=counter.window_key if counter else None,
                    window_start=counter.window_start if counter else None,
                    window_end=counter.window_end if counter else None,
                    stage=policy.stage,
                    caps=BudgetCaps(
                        input_tokens=policy.cap_input_tokens,
                        output_tokens=policy.cap_output_tokens,
                        total_tokens=policy.cap_total_tokens,
                        uncached_input_tokens=policy.cap_uncached_input_tokens,
                        billable_tokens=policy.cap_billable_tokens,
                        usd=policy.cap_usd,
                        upstream_requests=policy.cap_provider_requests,
                    ),
                    spent_usd=spent_usd,
                    held_usd=held_usd,
                    remaining_usd=(
                        max(policy.cap_usd - spent_usd - held_usd, _ZERO)
                        if policy.cap_usd is not None
                        else None
                    ),
                    spent_total_tokens=spent_tokens,
                    held_total_tokens=held_tokens,
                    remaining_total_tokens=(
                        max(policy.cap_total_tokens - spent_tokens - held_tokens, 0)
                        if policy.cap_total_tokens is not None
                        else None
                    ),
                    utilization_percent=utilization,
                    threshold_state=threshold_state,
                )
            )
        policy_ids = [state.policy_id for state in states]
        thresholds = await self.repo.recent_thresholds(
            tenant_id=tenant_id, policy_ids=policy_ids
        )
        denials = await self.repo.recent_budget_denials(
            tenant_id=tenant_id,
            visible_user_ids=visibility.visible_user_ids,
        )
        return states, thresholds, denials

    async def preview_policy(
        self,
        *,
        tenant_id: uuid.UUID,
        candidate: UsageBudgetPolicyCreate,
    ) -> dict[str, Any]:
        at = candidate.effective_from or datetime.now(timezone.utc)
        if not await self.repo.policy_target_exists(
            tenant_id=tenant_id,
            user_id=candidate.user_id,
            group_id=candidate.group_id,
        ):
            raise UsageScopeError("budget policy target not found")
        group_ids: list[uuid.UUID] = []
        user_id = candidate.user_id
        if user_id is not None:
            group_ids = await self.repo.user_group_ids(
                tenant_id=tenant_id, user_id=user_id
            )
        elif candidate.group_id is not None:
            group_ids = [candidate.group_id]
        existing = await UsageBudgetRepository(self.repo.db).list_active_policies(
            tenant_id=tenant_id,
            user_id=user_id,
            group_ids=group_ids,
            llm_config_id=candidate.llm_config_id,
            stage=candidate.stage or "*",
            window_kinds=(candidate.window,),
            effective_at=at,
        )
        dimensions = (
            "input_tokens",
            "output_tokens",
            "total_tokens",
            "uncached_input_tokens",
            "billable_tokens",
            "usd",
            "upstream_requests",
        )
        effective: dict[str, Any] = {}
        strictest: dict[str, uuid.UUID | None] = {}
        for dimension in dimensions:
            candidate_value = getattr(candidate.caps, dimension)
            values: list[tuple[Any, uuid.UUID | None]] = []
            if candidate_value is not None:
                values.append((candidate_value, None))
            model_name = (
                "provider_requests" if dimension == "upstream_requests" else dimension
            )
            values.extend(
                (getattr(policy, f"cap_{model_name}"), policy.id)
                for policy in existing
                if getattr(policy, f"cap_{model_name}") is not None
            )
            if values:
                value, policy_id = min(values, key=lambda pair: pair[0])
                effective[dimension] = value
                strictest[dimension] = policy_id
            else:
                effective[dimension] = None
                strictest[dimension] = None
        warnings: list[str] = []
        if any(policy.scope_kind != candidate.scope for policy in existing):
            warnings.append(
                "Multiple scopes apply; enforcement uses the strictest finite cap."
            )
        if candidate.effective_from and candidate.effective_from > datetime.now(
            timezone.utc
        ):
            warnings.append("This policy is scheduled and does not apply yet.")
        return {
            "candidate_scope": candidate.scope,
            "matching_policy_ids": [policy.id for policy in existing],
            "precedence": ["user", "group", "tenant", "strictest finite cap wins"],
            "effective_caps": BudgetCaps(**effective),
            "strictest_policy_ids": strictest,
            "warnings": warnings,
        }
