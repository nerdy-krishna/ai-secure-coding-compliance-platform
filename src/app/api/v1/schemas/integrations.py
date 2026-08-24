from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


IntegrationKind = Literal["github_app", "jira_cloud", "siem_webhook"]
IntegrationFeature = Literal[
    "repository_contents_read",
    "security_events_write",
    "webhook_metadata_read",
    "ticket_sync",
    "siem_emit",
]


class PrincipalCreate(BaseModel):
    kind: IntegrationKind
    display_name: str = Field(min_length=3, max_length=120)
    config: dict[str, Any]
    secret_values: dict[str, SecretStr]

    @field_validator("secret_values")
    @classmethod
    def bounded_secret_values(cls, value: dict[str, SecretStr]) -> dict[str, SecretStr]:
        if not value or len(value) > 8:
            raise ValueError("between one and eight connector secrets are required")
        return value


class PrincipalRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    kind: IntegrationKind
    display_name: str
    config: dict[str, Any]
    enabled: bool
    secret_fingerprint: str
    revoked_at: datetime | None
    created_at: datetime
    updated_at: datetime


class GrantCreate(BaseModel):
    feature: IntegrationFeature
    scope: dict[str, Any]


class GrantRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    principal_id: uuid.UUID
    feature: IntegrationFeature
    scope: dict[str, Any]
    scope_digest: str
    created_at: datetime
    revoked_at: datetime | None


class PolicyEventRequest(BaseModel):
    scan_id: uuid.UUID


class TicketSyncRequest(BaseModel):
    canonical_root_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=255)
    severity: str = Field(min_length=1, max_length=16)
    status: str = Field(min_length=1, max_length=64)
    waiver_expires_at: datetime | None = None
    reason: str = Field(min_length=3, max_length=96)
    authorized_view: str = Field(pattern=r"^/[-A-Za-z0-9_./]+$", max_length=1024)


class OutboxRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    principal_id: uuid.UUID
    event_type: str
    idempotency_key: str
    state: str
    attempts: int
    max_attempts: int
    next_attempt_at: datetime
    delivered_at: datetime | None
    last_error_code: str | None
    created_at: datetime


class DeliveryAuditRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    outbox_id: uuid.UUID
    principal_id: uuid.UUID
    attempt: int
    outcome: str
    http_status: int | None
    evidence_digest: str
    response_excerpt_redacted: str | None
    error_code: str | None
    created_at: datetime


class FindingTicketRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    principal_id: uuid.UUID
    canonical_root_id: str
    external_key: str
    external_url: str | None
    status: str
    waiver_expires_at: datetime | None
    created_at: datetime
    updated_at: datetime


class GithubSourceRequest(BaseModel):
    commit_sha: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")


class GithubSarifRequest(BaseModel):
    scan_id: uuid.UUID
    commit_sha: str = Field(pattern=r"^(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})$")
    ref: str = Field(pattern=r"^refs/(heads|tags|pull)/[-A-Za-z0-9_./]+$", max_length=255)


class GithubWebhookReceiptRead(BaseModel):
    receipt_id: uuid.UUID
    duplicate: bool
    event_type: str


class CiSubmissionRead(BaseModel):
    scan_id: uuid.UUID
    project_id: uuid.UUID
    provider: Literal["github", "gitlab", "azure_devops", "bitbucket"]
    commit_sha: str
    ref: str


class CiPolicyRead(BaseModel):
    scan_id: uuid.UUID
    status: str
    terminal: bool
    policy_evaluation_id: uuid.UUID | None = None
    policy_version_id: uuid.UUID | None = None
    outcome: Literal["pass", "fail"] | None = None
    coverage_complete: bool | None = None
    report_url: str | None = None
