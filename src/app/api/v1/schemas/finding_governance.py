from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


Severity = Literal["informational", "low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]


class FindingLineageRecordResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    attempt_id: uuid.UUID | None
    finding_id: int | None
    predecessor_finding_id: int | None
    fingerprint: str
    baseline_state: Literal["new", "fixed", "unchanged", "reintroduced"]
    exact_ranges: list[dict[str, Any]]
    dataflow: dict[str, Any]
    source_provenance: dict[str, Any]
    producer_provenance: dict[str, Any]
    coverage_entry_ids: list[uuid.UUID]
    evidence_object_ids: list[uuid.UUID]
    remediation_state: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingLineageListResponse(BaseModel):
    scan_id: uuid.UUID
    counts: dict[str, int]
    items: list[FindingLineageRecordResponse]
    policy_evaluation: "FindingPolicyEvaluationResponse | None" = None
    active_waivers: list[dict[str, Any]] = Field(default_factory=list)


class FindingPolicyRequest(BaseModel):
    minimum_severity: Severity = "high"
    minimum_confidence: Confidence = "medium"
    require_complete_coverage: bool = True
    allow_waivers: bool = True
    minimum_waiver_remaining_hours: int = Field(default=0, ge=0, le=8760)
    reason: str = Field(min_length=3, max_length=2000)


class FindingPolicyResponse(BaseModel):
    id: uuid.UUID
    version: int
    minimum_severity: Severity
    minimum_confidence: Confidence
    require_complete_coverage: bool
    allow_waivers: bool
    minimum_waiver_remaining_hours: int
    actor_user_id: int | None
    reason: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingPolicyEvaluationResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    attempt_id: uuid.UUID | None
    policy_version_id: uuid.UUID
    outcome: Literal["pass", "fail"]
    coverage_complete: bool
    blocking_fingerprints: list[str]
    waived_fingerprints: list[str]
    details: dict[str, Any]
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingWaiverRequest(BaseModel):
    scope: Literal["finding", "fingerprint", "project"] = "finding"
    reason: str = Field(min_length=3, max_length=2000)
    expires_at: datetime

    @model_validator(mode="after")
    def ensure_timezone(self) -> "FindingWaiverRequest":
        if self.expires_at.tzinfo is None:
            raise ValueError("expires_at must include a timezone")
        return self


class FindingWaiverEventResponse(BaseModel):
    id: int
    action: Literal["granted", "revoked", "expired"]
    actor_user_id: int | None
    reason: str
    created_at: datetime

    model_config = {"from_attributes": True}


class FindingWaiverResponse(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID | None
    finding_id: int | None
    fingerprint: str
    scope: Literal["finding", "fingerprint", "project"]
    scope_value: str
    reason: str
    expires_at: datetime
    actor_user_id: int | None
    created_at: datetime
    events: list[FindingWaiverEventResponse] = Field(default_factory=list)

    model_config = {"from_attributes": True}


class RevokeFindingWaiverRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=2000)


class FindingTrendBucketResponse(BaseModel):
    date: date
    new: int
    fixed: int
    unchanged: int
    reintroduced: int


class FindingPortfolioTrendsResponse(BaseModel):
    since: datetime
    items: list[FindingTrendBucketResponse]
