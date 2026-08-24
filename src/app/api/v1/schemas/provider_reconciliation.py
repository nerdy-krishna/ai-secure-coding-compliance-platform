"""API contract for provider billing reconciliation and usage-center status."""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class ProviderCredentialInput(BaseModel):
    api_key: SecretStr = Field(min_length=12, max_length=4096)


class ConnectorCreate(BaseModel):
    provider: Literal["openai"]
    display_name: str = Field(min_length=1, max_length=100)
    credentials: ProviderCredentialInput
    project_ids: list[str] = Field(default_factory=list, max_length=100)
    enabled: bool = False
    absolute_tolerance_micro_usd: int = Field(default=1000, ge=0)
    percentage_tolerance: Decimal = Field(default=Decimal("1"), ge=0, le=100)
    lookback_minutes: int = Field(default=180, ge=0, le=10080)
    poll_interval_minutes: int = Field(default=60, ge=15, le=10080)

    @field_validator("project_ids")
    @classmethod
    def validate_projects(cls, value: list[str]) -> list[str]:
        normalized = [item.strip() for item in value]
        if any(not item or len(item) > 255 for item in normalized):
            raise ValueError("project IDs must be 1-255 characters")
        if len(set(normalized)) != len(normalized):
            raise ValueError("project IDs must be unique")
        return normalized


class ConnectorUpdate(BaseModel):
    credentials: ProviderCredentialInput | None = None
    project_ids: list[str] = Field(default_factory=list, max_length=100)
    enabled: bool
    absolute_tolerance_micro_usd: int = Field(default=1000, ge=0)
    percentage_tolerance: Decimal = Field(default=Decimal("1"), ge=0, le=100)
    lookback_minutes: int = Field(default=180, ge=0, le=10080)
    poll_interval_minutes: int = Field(default=60, ge=15, le=10080)

    _validate_projects = field_validator("project_ids")(ConnectorCreate.validate_projects.__func__)


class ConnectorRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    tenant_id: uuid.UUID
    provider: str
    display_name: str
    project_ids: list[str]
    verified_scopes: list[str]
    enabled: bool
    credentials_configured: bool = True
    absolute_tolerance_micro_usd: int
    percentage_tolerance: Decimal
    lookback_minutes: int
    poll_interval_minutes: int
    next_run_at: datetime | None
    last_run_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ReconciliationRunRequest(BaseModel):
    window_start: datetime
    window_end: datetime

    @field_validator("window_start", "window_end")
    @classmethod
    def timezone_required(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("reconciliation timestamps must be timezone-aware")
        return value


class ReconciliationRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    connector_id: uuid.UUID
    window_start: datetime
    window_end: datetime
    status: Literal["completed", "failed"]
    trigger_kind: str
    canonical_micro_usd: int
    provider_micro_usd: int
    variance_micro_usd: int
    unresolved_micro_usd: int
    coverage_percent: Decimal
    compared_dimensions: int
    unresolved_dimensions: int
    provider_pages: int
    error_code: str | None
    started_at: datetime
    completed_at: datetime


class ReconciliationEvidenceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: uuid.UUID
    run_id: uuid.UUID
    dimension_key: str
    classification: str
    canonical_micro_usd: int
    provider_micro_usd: int
    variance_micro_usd: int
    within_tolerance: bool
    canonical_tokens: dict[str, int]
    provider_tokens: dict[str, int]
    normalized_dimensions: dict[str, Any]
    provider_item_ids: list[str]
    details: dict[str, Any]
    created_at: datetime


class ReconciliationSummaryRead(BaseModel):
    last_reconciliation_at: datetime | None = None
    status: str = "not_configured"
    coverage_percent: Decimal = Decimal("0")
    variance_micro_usd: int = 0
    unresolved_micro_usd: int = 0
    unresolved_dimensions: int = 0
    run_id: uuid.UUID | None = None
