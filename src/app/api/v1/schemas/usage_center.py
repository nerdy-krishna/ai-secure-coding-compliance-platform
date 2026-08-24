"""Privacy-safe contracts for the canonical usage and budget center."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from app.api.v1.schemas.usage_budgets import BudgetCaps, UsageBudgetPolicyCreate


UsageDimension = Literal[
    "operation",
    "project",
    "scan",
    "stage",
    "agent",
    "provider",
    "model",
    "account",
    "group",
]
UsageInterval = Literal["hour", "day", "week", "month"]


class UsageTotals(BaseModel):
    actual_cost: Decimal = Decimal("0")
    estimated_cost: Decimal = Decimal("0")
    reconciled_cost: Decimal = Decimal("0")
    reserved_cost: Decimal = Decimal("0")
    variance: Decimal = Decimal("0")
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0
    requests: int = 0
    events: int = 0
    unknown_events: int = 0
    estimated_events: int = 0
    reconciled_events: int = 0
    reserved_requests: int = 0
    cache_hit_rate: Decimal = Decimal("0")
    currency: str = "USD"


class UsageSummaryResponse(BaseModel):
    from_at: datetime
    to_at: datetime
    scope: Literal["self", "group", "tenant"]
    totals: UsageTotals


class UsageTrendPoint(UsageTotals):
    bucket: datetime


class UsageTrendsResponse(BaseModel):
    from_at: datetime
    to_at: datetime
    interval: UsageInterval
    points: list[UsageTrendPoint]


class UsageBreakdownItem(UsageTotals):
    key: str


class UsageBreakdownResponse(BaseModel):
    dimension: UsageDimension
    items: list[UsageBreakdownItem]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class UsageEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    operation_kind: Literal["scan", "chat", "rag"]
    operation_id: str
    scan_id: uuid.UUID | None
    stage: str
    agent_name: str
    user_id: int | None
    group_ids: list[uuid.UUID]
    provider: str
    requested_model: str
    resolved_models: list[str]
    request_count: int
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    reasoning_tokens: int
    usage_source: Literal["provider", "estimated", "reconciled"]
    quality_state: Literal["exact", "normalized", "estimated", "unknown"]
    cost_status: Literal["exact", "estimated", "unknown", "reconciled"]
    currency: str | None
    total_cost: Decimal | None
    created_at: datetime


class UsageEventsResponse(BaseModel):
    items: list[UsageEventRead]
    next_cursor: str | None = None


class UsageBudgetStateRead(BaseModel):
    policy_id: uuid.UUID
    scope: Literal["tenant", "group", "user"]
    target_group_id: uuid.UUID | None
    target_user_id: int | None
    window: Literal["request", "scan", "day", "month"]
    window_key: str | None
    window_start: datetime | None
    window_end: datetime | None
    stage: str | None
    caps: BudgetCaps
    spent_usd: Decimal
    held_usd: Decimal
    remaining_usd: Decimal | None
    spent_total_tokens: int
    held_total_tokens: int
    remaining_total_tokens: int | None
    utilization_percent: Decimal
    threshold_state: Literal["normal", "warning", "critical", "exhausted"]


class UsageBudgetStatusResponse(BaseModel):
    states: list[UsageBudgetStateRead]
    recent_thresholds: list[dict[str, str | int]]
    recent_denials: list[dict[str, str]]


class UsagePolicyPreviewRequest(BaseModel):
    policy: UsageBudgetPolicyCreate


class UsagePolicyPreviewResponse(BaseModel):
    candidate_scope: Literal["tenant", "group", "user"]
    matching_policy_ids: list[uuid.UUID]
    precedence: list[str]
    effective_caps: BudgetCaps
    strictest_policy_ids: dict[str, uuid.UUID | None]
    warnings: list[str]
