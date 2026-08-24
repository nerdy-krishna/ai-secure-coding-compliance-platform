"""Strict API contracts for tenant-governed rule candidates."""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


PredicateKind = Literal[
    "ast", "taint", "dependency_advisory", "secret_pattern", "semantic_runtime"
]
RegistryKind = Literal["semgrep", "gitleaks", "osv", "ai_dataflow"]


class RuleFixture(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.-]+$")
    language: str = Field(min_length=1, max_length=32)
    content: str = Field(min_length=1, max_length=50_000)


class RuleFixturePack(BaseModel):
    model_config = ConfigDict(extra="forbid")

    vulnerable: list[RuleFixture] = Field(min_length=1, max_length=50)
    fixed: list[RuleFixture] = Field(min_length=1, max_length=50)
    negative: list[RuleFixture] = Field(min_length=1, max_length=50)
    performance: list[RuleFixture] = Field(min_length=1, max_length=50)
    churn: list[RuleFixture] = Field(min_length=1, max_length=50)

    @model_validator(mode="after")
    def bounded_total(self) -> "RuleFixturePack":
        total = sum(len(getattr(self, key)) for key in self.model_fields)
        if total > 100:
            raise ValueError("fixture pack may contain at most 100 files")
        return self


class CandidateCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: int = Field(gt=0)
    predicate_kind: PredicateKind
    bounded: bool
    uses_project_specific_names: bool = False
    requires_hidden_runtime_state: bool = False
    proposed_rule: dict[str, Any] | None = None
    fixtures: RuleFixturePack | None = None

    @model_validator(mode="after")
    def bound_payload(self) -> "CandidateCreate":
        if self.proposed_rule is not None:
            encoded = json.dumps(self.proposed_rule, separators=(",", ":"), default=str)
            if len(encoded.encode("utf-8")) > 200_000:
                raise ValueError("proposed rule exceeds 200 KB")
        return self


class ReviewDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    approved: bool
    reason: str = Field(min_length=3, max_length=500)


class TransitionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=3, max_length=500)


class ReviewRequiredRequest(TransitionRequest):
    trigger: Literal["tool_incompatibility", "sustained_quality_breach"]


class SignedVersionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    version: int
    payload_sha256: str
    signature_algorithm: str
    signing_key_id: str
    quality_metrics: dict[str, Any]
    created_at: datetime


class DeploymentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    version_id: uuid.UUID
    prior_version_id: uuid.UUID | None
    state: str
    shadow_started_at: datetime | None
    review_due_at: datetime | None
    promoted_at: datetime | None
    ended_at: datetime | None
    eligible_files: int = 0
    unexpected_matches: int = 0


class CandidateRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    source_finding_id: int | None
    registry_kind: RegistryKind
    predicate_kind: PredicateKind
    static_representable: bool
    non_representable_reason: str | None
    stable_identity: str
    status: str
    severity: str
    cwe: str | None
    normalized_evidence: dict[str, Any]
    creator_user_id: int | None
    reviewer_user_id: int | None
    promoter_user_id: int | None
    expires_at: datetime
    reviewed_at: datetime | None
    promoted_at: datetime | None
    created_at: datetime
    latest_version: SignedVersionRead | None = None
    active_deployment: DeploymentRead | None = None


class CandidatePage(BaseModel):
    items: list[CandidateRead]
    total: int
    page: int
    page_size: int
