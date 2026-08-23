"""Public tenant usage-budget API schemas.

The persistence layer keeps immutable policy versions.  These schemas expose
that vocabulary without leaking locking/counter implementation details.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


BudgetScope = Literal["tenant", "group", "user"]
BudgetWindow = Literal["request", "scan", "day", "month"]
UnknownPriceAction = Literal["deny", "token_only"]
ReservationState = Literal[
    "held", "settled", "released", "expired", "accounting_unknown"
]


class BudgetCaps(BaseModel):
    """Hard limits for every canonical usage dimension."""

    model_config = ConfigDict(extra="forbid")

    input_tokens: int | None = Field(default=None, ge=0)
    output_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    uncached_input_tokens: int | None = Field(default=None, ge=0)
    billable_tokens: int | None = Field(default=None, ge=0)
    usd: Decimal | None = Field(default=None, ge=0, max_digits=20, decimal_places=8)
    upstream_requests: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def require_cap(self) -> "BudgetCaps":
        if all(value is None for value in self.model_dump().values()):
            raise ValueError("at least one hard cap is required")
        return self


class UsageBudgetPolicyCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scope: BudgetScope
    group_id: uuid.UUID | None = None
    user_id: int | None = Field(default=None, ge=1)
    window: BudgetWindow
    llm_config_id: uuid.UUID | None = None
    stage: str | None = Field(default=None, min_length=1, max_length=100)
    caps: BudgetCaps
    soft_thresholds: tuple[int, ...] = (80, 95)
    unknown_price_action: UnknownPriceAction = "deny"
    effective_from: datetime | None = None
    effective_to: datetime | None = None
    reason: str = Field(min_length=10, max_length=500)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 10:
            raise ValueError("reason must contain at least 10 non-whitespace characters")
        return normalized

    @field_validator("effective_from", "effective_to")
    @classmethod
    def require_aware_datetime(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("budget timestamps must include a timezone")
        return value.astimezone(timezone.utc)

    @field_validator("soft_thresholds")
    @classmethod
    def validate_thresholds(cls, value: tuple[int, ...]) -> tuple[int, ...]:
        if len(value) != 2 or any(item <= 0 or item >= 100 for item in value):
            raise ValueError(
                "exactly two soft thresholds between 1 and 99 are required"
            )
        if tuple(sorted(set(value))) != value:
            raise ValueError("soft thresholds must be unique and strictly increasing")
        return value

    @model_validator(mode="after")
    def validate_scope_and_policy(self) -> "UsageBudgetPolicyCreate":
        if self.scope == "tenant" and (self.group_id is not None or self.user_id is not None):
            raise ValueError("tenant scope cannot include a group_id or user_id")
        if self.scope == "group" and (self.group_id is None or self.user_id is not None):
            raise ValueError("group scope requires only group_id")
        if self.scope == "user" and (self.user_id is None or self.group_id is not None):
            raise ValueError("user scope requires only user_id")
        if self.effective_from and self.effective_to and self.effective_to <= self.effective_from:
            raise ValueError("effective_to must be after effective_from")
        if self.unknown_price_action == "token_only" and all(
            value is None
            for value in (
                self.caps.input_tokens,
                self.caps.output_tokens,
                self.caps.total_tokens,
                self.caps.uncached_input_tokens,
                self.caps.billable_tokens,
            )
        ):
            raise ValueError("token_only requires a finite token cap")
        return self


class UsageBudgetPolicyReplace(UsageBudgetPolicyCreate):
    enabled: bool = True


class UsageBudgetPolicyDisable(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=10, max_length=500)

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 10:
            raise ValueError("reason must contain at least 10 non-whitespace characters")
        return normalized


class UsageBudgetPolicyRead(UsageBudgetPolicyReplace):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    logical_policy_id: uuid.UUID
    tenant_id: uuid.UUID
    version: int
    previous_version_id: uuid.UUID | None = None
    created_by_user_id: int
    created_at: datetime


class BudgetAmountsRead(BaseModel):
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    uncached_input_tokens: int = 0
    billable_tokens: int = 0
    usd: Decimal | None = None
    upstream_requests: int = 0


class UsageBudgetCounterRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    policy_id: uuid.UUID
    window_key: str
    window_start: datetime | None = None
    window_end: datetime | None = None
    spent: BudgetAmountsRead
    held: BudgetAmountsRead
    updated_at: datetime


class UsageBudgetReservationRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    actor_user_id: int | None
    state: ReservationState
    idempotency_key: str
    request_key: str | None = None
    scan_attempt_id: uuid.UUID | None = None
    llm_config_id: uuid.UUID | None = None
    stage: str | None = None
    estimate: BudgetAmountsRead
    expires_at: datetime
    created_at: datetime


class UsageBudgetThresholdEventRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    policy_id: uuid.UUID
    counter_id: uuid.UUID
    dimension: str
    threshold_percent: int
    observed: Decimal
    effective_cap: Decimal
    created_at: datetime


class UsageBudgetOverrideCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    policy_id: uuid.UUID
    window_key: str = Field(min_length=1, max_length=255)
    allowance: BudgetCaps
    expires_at: datetime
    reason: str = Field(min_length=10, max_length=500)
    action_request_id: uuid.UUID | None = None

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str) -> str:
        normalized = value.strip()
        if len(normalized) < 10:
            raise ValueError("reason must contain at least 10 non-whitespace characters")
        return normalized

    @field_validator("expires_at")
    @classmethod
    def normalize_expiry(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("expires_at must include a timezone")
        return value.astimezone(timezone.utc)


class UsageBudgetOverrideRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    policy_id: uuid.UUID
    window_key: str
    allowance: BudgetAmountsRead
    reason: str
    created_by_user_id: int
    expires_at: datetime
    created_at: datetime
