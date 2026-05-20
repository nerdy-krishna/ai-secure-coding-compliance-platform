# src/app/api/v1/models.py

from datetime import datetime
import ipaddress
import socket
import uuid
from pydantic import (
    UUID4,
    BaseModel,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from typing import List, Literal, Optional, Dict, Any

# Allowlist of permitted repo hosts for SSRF prevention (V01.3.6)
_ALLOWED_REPO_HOSTS = frozenset({"github.com", "gitlab.com", "bitbucket.org"})


def _validate_repo_url(url: str) -> str:
    """Validate a repo URL against an allowlist of protocols, hosts, and ports.

    Enforces:
    - scheme must be 'https'
    - no userinfo in netloc
    - hostname must be in the allowed host allowlist
    - port must be None or 443
    - hostname must not resolve to a private/reserved IP

    Raises ValueError on any violation.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)

    if parsed.scheme != "https":
        raise ValueError("repo_url must use the https scheme.")

    if "@" in (parsed.netloc or ""):
        raise ValueError("repo_url must not contain userinfo (credentials in URL).")

    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError("repo_url must have a valid hostname.")

    if hostname not in _ALLOWED_REPO_HOSTS:
        raise ValueError(
            f"repo_url hostname '{hostname}' is not in the allowed host list "
            f"({', '.join(sorted(_ALLOWED_REPO_HOSTS))})."
        )

    port = parsed.port
    if port is not None and port != 443:
        raise ValueError("repo_url must use port 443 or no explicit port.")

    # Guard against DNS rebinding to private/reserved ranges
    try:
        resolved_ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(resolved_ip)
        if not addr.is_global:
            raise ValueError(
                f"repo_url hostname resolves to a non-global IP address ({resolved_ip})."
            )
    except socket.gaierror:
        raise ValueError(f"repo_url hostname '{hostname}' could not be resolved.")

    return url


class ScanRunControlRequest(BaseModel):
    """Body for `POST /api/v1/scans/{id}/run-control`.

    ``resume`` keeps durable scan task rows so completed work can be reused.
    ``restart`` discards durable task rows and derived final outputs, then
    reruns the original submitted snapshot/config under the same scan id.
    """

    mode: Literal["resume", "restart"]


class ApprovalRequest(BaseModel):
    """Body for `POST /api/v1/scans/{id}/approve`.

    Three pause points exist in the worker graph: the prescan-approval
    interrupt (`STATUS_PENDING_PRESCAN_APPROVAL`, ADR-009), the
    profiling-cost interrupt (`STATUS_PENDING_PROFILING_APPROVAL`, #71),
    and the cost-approval interrupt (`STATUS_PENDING_COST_APPROVAL`).
    The `kind` field discriminates which one is being resumed; the
    consumer also validates `kind` against the scan's current pause
    point before handing the payload to LangGraph (G4 / M1).

    Backward-compatibility: `kind` defaults to `"cost_approval"` for
    one release. Callers that haven't been upgraded keep working;
    `scan_service.approve_scan` emits a one-time WARN-log when the
    default is taken.
    """

    kind: Literal["prescan_approval", "profiling_approval", "cost_approval"] = (
        "cost_approval"
    )
    approved: bool = True
    override_critical_secret: bool = False


# === LLM Configuration Schemas (UPDATED) ===


class LLMConfigurationBase(BaseModel):
    name: str = Field(
        ...,
        description="A unique, user-friendly name for the LLM configuration.",
        min_length=1,
        max_length=200,
    )
    provider: Literal["openai", "anthropic", "google", "deepseek", "xai"] = Field(
        ...,
        description="The LLM provider. One of: 'openai', 'anthropic', 'google', 'deepseek', 'xai'.",
    )
    model_name: str = Field(
        ...,
        description="The specific model name (e.g., 'gpt-4o', 'gemini-1.5-pro').",
        min_length=1,
        max_length=200,
    )
    tokenizer: Optional[str] = Field(
        None,
        description="The tokenizer to use for token counting (e.g., 'cl100k_base'). Defaults to model-specific or a general tokenizer if not provided.",
        max_length=120,
    )
    input_cost_per_million: float = Field(
        default=0.0,
        description="Cost per 1 million input tokens in USD.",
        ge=0,
        le=10000,
    )
    output_cost_per_million: float = Field(
        default=0.0,
        description="Cost per 1 million output tokens in USD.",
        ge=0,
        le=10000,
    )
    requests_per_minute: Optional[int] = Field(
        default=None,
        ge=1,
        le=100000,
        description="Optional per-configuration RPM limit. Null falls back to provider defaults.",
    )
    tokens_per_minute: Optional[int] = Field(
        default=None,
        ge=1,
        le=100000000,
        description="Optional per-configuration TPM limit. Null falls back to provider defaults.",
    )
    max_prompt_tokens: Optional[int] = Field(
        default=None,
        ge=1,
        le=10000000,
        description="Optional max prompt/input token budget for a single request.",
    )
    # --- End of added fields ---


class SystemConfigurationBase(BaseModel):
    key: str = Field(
        ...,
        min_length=1,
        max_length=200,
        pattern=r"^[a-zA-Z0-9_.\-]+$",
        description="The unique key for the configuration setting.",
    )
    value: Dict[str, Any] = Field(
        ..., description="The value of the configuration setting (JSON)."
    )
    description: Optional[str] = Field(
        None, description="A description of what this setting controls."
    )
    is_secret: bool = Field(
        False,
        description="Whether this setting contains sensitive information (masked in UI).",
    )
    encrypted: bool = Field(
        False, description="Whether this setting is encrypted in the database."
    )


class SystemConfigurationCreate(SystemConfigurationBase):
    pass


class SystemConfigurationUpdate(BaseModel):
    value: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    is_secret: Optional[bool] = None
    encrypted: Optional[bool] = None
    # V02.3.4 — optimistic-locking version the client expects to overwrite.
    # Optional; when omitted the legacy unsafe-overwrite path is used.
    expected_version: Optional[int] = Field(
        default=None,
        ge=1,
        description=(
            "Caller-supplied row version (read from a prior GET). When set, the "
            "update is conditional: a 409 Conflict is returned if the row was "
            "modified by another writer in the meantime."
        ),
    )


class SystemConfigurationRead(SystemConfigurationBase):
    # V02.3.4 — exposes the row's current version so the client can pass it
    # back in a subsequent SystemConfigurationUpdate as `expected_version`.
    version: int = 1
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

    @model_validator(mode="after")
    def _mask_secret_value(self) -> "SystemConfigurationRead":
        """Mask secret values at the schema layer (V15.3.1)."""
        if self.is_secret:
            object.__setattr__(self, "value", {"_redacted": True})
        return self


class LLMConfigurationCreate(LLMConfigurationBase):
    api_key: SecretStr = Field(
        ...,
        description="The API key for the provider.",
        min_length=10,
        max_length=512,
        json_schema_extra={"x-sensitivity": "secret"},
    )


class LLMConfigurationUpdate(BaseModel):
    name: Optional[str] = Field(
        None, description="A unique, user-friendly name for the LLM configuration."
    )
    provider: Optional[Literal["openai", "anthropic", "google", "deepseek", "xai"]] = (
        Field(
            None,
            description="The LLM provider. One of: 'openai', 'anthropic', 'google', 'deepseek', 'xai'.",
        )
    )
    model_name: Optional[str] = Field(
        None, description="The specific model name (e.g., 'gpt-4o', 'gemini-1.5-pro')."
    )
    tokenizer: Optional[str] = Field(
        None,
        description="The tokenizer to use for token counting (e.g., 'cl100k_base').",
    )
    api_key: Optional[SecretStr] = Field(
        None,
        description="The API key for the provider. If provided, it will be updated and re-encrypted.",
        min_length=10,
        max_length=512,
        json_schema_extra={"x-sensitivity": "secret"},
    )
    input_cost_per_million: Optional[float] = Field(
        None, description="Cost per 1 million input tokens in USD."
    )
    output_cost_per_million: Optional[float] = Field(
        None, description="Cost per 1 million output tokens in USD."
    )
    requests_per_minute: Optional[int] = Field(None, ge=1, le=100000)
    tokens_per_minute: Optional[int] = Field(None, ge=1, le=100000000)
    max_prompt_tokens: Optional[int] = Field(None, ge=1, le=10000000)

    class Config:
        from_attributes = True


class LLMConfigurationRead(LLMConfigurationBase):
    # Read schema relaxes `provider` to `str` so that legacy rows whose
    # provider value predates the current allowlist (e.g. 'gemini' from
    # pre-2026-04-27 setup-form rows; see Alembic c0f39ef37367) still
    # serialise. Validation at write time is enforced via the `Literal`
    # on `LLMConfigurationBase.provider` for Create + Update.
    provider: str  # type: ignore[assignment]
    id: uuid.UUID
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# --- Agent Schemas (NEW) ---
class AgentBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=2000)
    domain_query: Dict[str, Any]


class AgentCreate(AgentBase):
    pass


class AgentUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    domain_query: Optional[str] = None


class AgentRead(AgentBase):
    id: uuid.UUID

    class Config:
        from_attributes = True


# --- Framework Schemas (NEW) ---
class FrameworkBase(BaseModel):
    name: str = Field(
        ...,
        description="The unique name of the security framework (e.g., 'OWASP ASVS').",
        min_length=1,
        max_length=200,
    )
    description: str = Field(
        ...,
        description="A brief description of the framework.",
        max_length=2000,
    )
    source_url: Optional[str] = Field(
        None,
        description="URL pointing to where this framework's source documents live.",
        max_length=2048,
    )


class FrameworkCreate(FrameworkBase):
    pass


class FrameworkUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    source_url: Optional[str] = Field(None, max_length=2048)


class FrameworkRead(FrameworkBase):
    id: uuid.UUID
    agents: List[AgentRead] = []

    class Config:
        from_attributes = True


# --- Framework-Agent Mapping Schema (NEW) ---
class FrameworkAgentMappingUpdate(BaseModel):
    agent_ids: List[uuid.UUID]


# --- RAG Management Schemas (NEW) ---
class RAGDocumentDeleteRequest(BaseModel):
    document_ids: List[str] = Field(..., min_length=1, max_length=500)


# --- Prompt Template Schemas (NEW) ---
class PromptTemplateBase(BaseModel):
    name: str = Field(
        ...,
        description="The unique name for the prompt template.",
        max_length=200,
    )
    template_type: str = Field(
        ...,
        description="The type of template (e.g., 'QUICK_AUDIT', 'DETAILED_REMEDIATION').",
        max_length=64,
    )
    agent_name: Optional[str] = Field(
        None,
        description="The name of the agent this prompt is for.",
        max_length=200,
    )
    variant: str = Field(
        "generic",
        description=(
            "Which LLM optimization mode this template targets. "
            "'generic' works across all providers; 'anthropic' is tuned for "
            "Claude with cache-friendly prefixes. The runtime picks by the "
            "active llm.optimization_mode with fallback to 'generic'."
        ),
        max_length=64,
    )
    version: int = Field(
        1, description="The version of the prompt template.", ge=1, le=10000
    )
    template_text: str = Field(
        ...,
        description="The content of the prompt template.",
        max_length=200_000,
    )


class PromptTemplateCreate(PromptTemplateBase):
    pass


class PromptTemplateUpdate(BaseModel):
    name: Optional[str] = None
    template_type: Optional[str] = None
    agent_name: Optional[str] = None
    variant: Optional[str] = None
    version: Optional[int] = None
    template_text: Optional[str] = None


class PromptTemplateRead(PromptTemplateBase):
    id: uuid.UUID

    class Config:
        from_attributes = True


# --- Request Models (EXISTING, MERGED & UPDATED) ---


class SubmissionRequest(BaseModel):
    files: Optional[List[Dict[str, str]]] = Field(
        None,
        description="List of files, each a dict with 'path' and 'content'.",
        max_length=1000,
    )
    repo_url: Optional[str] = Field(
        None,
        description="URL of the Git repository to analyze.",
        max_length=2048,
        pattern=r"^https://",
    )
    frameworks: List[str] = Field(
        ...,
        description="List of security frameworks to analyze against.",
        min_length=1,
        max_length=20,
    )
    main_llm_config_id: uuid.UUID = Field(
        ..., description="ID of the LLM config for the main agent."
    )
    specialized_llm_config_id: uuid.UUID = Field(
        ..., description="ID of the LLM config for specialized agents."
    )

    @field_validator("repo_url", mode="after")
    @classmethod
    def _validate_repo_url(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        return _validate_repo_url(v)

    @field_validator("frameworks", mode="after")
    @classmethod
    def _validate_framework_lengths(cls, v: List[str]) -> List[str]:
        for item in v:
            if len(item) > 64:
                raise ValueError(
                    f"Each framework name must be at most 64 characters; got {len(item)}."
                )
        return v

    @model_validator(mode="after")
    def _enforce_files_xor_repo(self) -> "SubmissionRequest":
        """Enforce XOR invariant: exactly one of files or repo_url must be provided (V02.2.3)."""
        if bool(self.files) == bool(self.repo_url):
            raise ValueError("Provide exactly one of `files` or `repo_url`.")
        return self


# --- Individual File Model (NEW - for graph input) ---
class CodeFile(BaseModel):
    filename: str = Field(
        ..., description="The name/path of the file.", min_length=1, max_length=1024
    )
    content: str = Field(
        ..., description="The content of the file.", max_length=2_000_000
    )


class SecurityQueryCreate(BaseModel):
    query_name: str = Field(..., min_length=1, max_length=200)
    language: str = Field(..., min_length=1, max_length=64)
    query_content: str = Field(..., max_length=200_000)
    description: Optional[str] = Field(None, max_length=4000)
    cwe_id: Optional[str] = Field(None, max_length=32, pattern=r"^CWE-[0-9]+$")
    asvs_category: Optional[str] = None


class SecurityQueryUpdate(BaseModel):
    query_name: Optional[str] = None
    query_content: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None


# --- Response Models (EXISTING, MODERNIZED) ---


class SubmissionResponse(BaseModel):
    submission_id: uuid.UUID
    message: str


class FixSuggestionResponse(BaseModel):
    id: int
    description: str
    original_snippet: str  # ADDED
    suggested_fix: str

    class Config:
        from_attributes = True


class VulnerabilityFindingResponse(BaseModel):
    id: int
    file_path: str
    title: str
    # Populated only by SAST scanners that emit a CWE; null for LLM findings.
    cwe: Optional[str] = None
    description: str
    severity: str
    line_number: int = Field(..., ge=0)
    # Exact verbatim vulnerable code — the UI matches it against the file
    # to highlight the precise span. NULL for legacy / scanner findings.
    vulnerable_snippet: Optional[str] = None
    # Every site a merged finding manifests — list of {line_number, snippet}.
    # NULL for single-site and legacy findings.
    affected_locations: Optional[List[Dict[str, Any]]] = None
    remediation: str
    confidence: str
    # Originating scanner/agent for the finding. Mirrors the DB
    # `findings.source` column (bandit / semgrep / gitleaks / osv /
    # NULL for legacy LLM-emitted rows). Surfaced so the results
    # page can drive a per-source filter chip row off the same
    # value the `source_counts` aggregate is computed from.
    source: Optional[str] = None
    corroborating_agents: Optional[List[str]] = None
    # The reasoning LLM(s) that detected the finding (#94 / PRD #91).
    # Two entries ⇒ both models in a dual-LLM scan independently flagged
    # it. NULL for scanner-emitted / pre-#94 findings.
    detected_by_llms: Optional[List[str]] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    references: List[str]
    fixes: Optional[Dict[str, Any]] = None
    is_applied_in_remediation: bool = False
    fix_verified: Optional[bool] = None
    # Opt-in cross-file validation verdict (#81 / PRD #75). NULL when the
    # scan did not opt in or the finding was skipped by the eligibility
    # pre-filter; otherwise 'confirmed' / 'mitigated' / 'unconfirmed'.
    cross_file_status: Optional[str] = None
    cross_file_rationale: Optional[str] = None
    # Operator triage disposition (PRD #96 / #97). One of open /
    # confirmed / false_positive / remediated / risk_accepted. `_by` /
    # `_at` / `_note` record who last set it, when, and the
    # justification. See `app.shared.lib.finding_disposition`.
    disposition: str = "open"
    disposition_by: Optional[int] = None
    disposition_at: Optional[datetime] = None
    disposition_note: Optional[str] = None

    @field_validator("fixes", mode="before")
    @classmethod
    def empty_dict_for_none_fixes(cls, v: Any) -> Any:
        if v is None:
            return None
        return v

    class Config:
        from_attributes = True


class FindingDispositionUpdateRequest(BaseModel):
    """Body of the per-finding disposition PATCH (PRD #96 / #97)."""

    disposition: str = Field(..., description="Target disposition state.")
    note: Optional[str] = Field(
        None,
        max_length=4000,
        description=(
            "Justification note. Required when the target disposition is "
            "false_positive or risk_accepted."
        ),
    )


class FindingDispositionResponse(BaseModel):
    """The triage state of a finding after a disposition change, plus
    the scan's freshly recomputed 0-10 risk score (PRD #96 / #99)."""

    finding_id: int
    disposition: str
    disposition_by: Optional[int] = None
    disposition_at: Optional[datetime] = None
    disposition_note: Optional[str] = None
    scan_risk_score: Optional[int] = None

    class Config:
        from_attributes = True


class BulkFindingDispositionUpdateRequest(BaseModel):
    """Body of the bulk disposition PATCH (PRD #96 / #100) — one
    disposition + note applied to many findings of a single scan."""

    finding_ids: List[int] = Field(
        ..., min_length=1, max_length=2000, description="Findings to update."
    )
    disposition: str = Field(..., description="Target disposition state.")
    note: Optional[str] = Field(
        None,
        max_length=4000,
        description=(
            "Justification note. Required when the target disposition is "
            "false_positive or risk_accepted."
        ),
    )


class BulkFindingDispositionResponse(BaseModel):
    """Outcome of a bulk disposition change."""

    updated_count: int
    disposition: str
    scan_risk_score: Optional[int] = None


class BulkFindingDispositionClearRequest(BaseModel):
    """Body of the bulk disposition-delete (PRD #96) — superuser-only.
    Resets the listed findings to untriaged and wipes their history."""

    finding_ids: List[int] = Field(
        ..., min_length=1, max_length=2000, description="Findings to clear."
    )


class FindingDispositionEventResponse(BaseModel):
    """One entry in a finding's disposition-change history (PRD #96)."""

    id: int
    finding_id: int
    old_disposition: str
    new_disposition: str
    actor_user_id: Optional[int] = None
    note: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True


class SubmissionResultResponse(BaseModel):
    id: uuid.UUID
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    findings: List[VulnerabilityFindingResponse] = []

    class Config:
        from_attributes = True


class SubmissionStatus(BaseModel):
    submission_id: uuid.UUID
    status: str
    submitted_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    estimated_cost: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class SecurityQueryResponse(BaseModel):
    id: int
    query_name: str
    language: str
    description: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class LLMInteractionResponse(BaseModel):
    id: int
    scan_id: Optional[uuid.UUID] = None
    file_path: Optional[str] = None
    agent_name: str
    # The LLM this call ran on — id + resolved display name — so the
    # LLM-logs page can filter by model. Null for older rows.
    llm_config_id: Optional[uuid.UUID] = None
    llm_name: Optional[str] = None
    timestamp: datetime
    cost: Optional[float] = None
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    total_tokens: Optional[int] = None
    prompt_template_name: Optional[str] = None
    prompt_context: Optional[Dict[str, Any]] = Field(
        default=None,
        json_schema_extra={"x-sensitivity": "pii_or_secret"},
    )
    parsed_output: Optional[Dict[str, Any]] = Field(
        default=None,
        json_schema_extra={"x-sensitivity": "pii_or_secret"},
    )
    error: Optional[str] = None

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_submissions: int
    pending_submissions: int
    completed_submissions: int
    total_findings: int
    high_severity_findings: int


class EstimatedCost(BaseModel):
    input_cost: float
    predicted_output_cost: float
    total_estimated_cost: float
    predicted_output_tokens: float


class ActualCost(BaseModel):
    total_cost: float
    total_input_tokens: int
    total_output_tokens: int
    total_tokens: int


class SubmissionHistoryItem(BaseModel):
    id: UUID4
    project_name: str
    status: str
    submitted_at: datetime
    completed_at: Optional[datetime] = None
    estimated_cost: Optional[EstimatedCost] = None
    actual_cost: Optional[ActualCost] = None

    class Config:
        from_attributes = True


class PaginatedSubmissionHistoryResponse(BaseModel):
    items: List[SubmissionHistoryItem]
    total: int


class ResultIndexItem(BaseModel):
    submission_id: uuid.UUID
    project_name: str
    completed_at: Optional[datetime]
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    risk_score: int

    class Config:
        from_attributes = True


class PaginatedResultsResponse(BaseModel):
    items: List[ResultIndexItem]
    total: int


class GitRepoPreviewRequest(BaseModel):
    repo_url: str = Field(
        ...,
        min_length=8,
        max_length=2048,
        pattern=r"^https://",
    )

    @field_validator("repo_url", mode="after")
    @classmethod
    def _validate_repo_url(cls, v: str) -> str:
        return _validate_repo_url(v)


class RemediationRequest(BaseModel):
    categories_to_fix: List[str] = Field(
        ...,
        description="A list of vulnerability categories (agent names) to remediate.",
        min_length=1,
        max_length=50,
    )

    @field_validator("categories_to_fix", mode="after")
    @classmethod
    def _validate_category_lengths(cls, v: List[str]) -> List[str]:
        for item in v:
            if len(item) > 64:
                raise ValueError(
                    f"Each category name must be at most 64 characters; got {len(item)}."
                )
        return v


# --- Detailed Analysis Result Models (NEW - for /result/{submission_id}) ---


class SeverityCountsResponse(BaseModel):
    CRITICAL: int = 0
    HIGH: int = 0
    MEDIUM: int = 0
    LOW: int = 0
    INFORMATIONAL: int = 0

    class Config:
        from_attributes = True


class SummaryResponse(BaseModel):
    total_findings_count: int = 0
    files_analyzed_count: int = 0
    severity_counts: SeverityCountsResponse = Field(
        default_factory=SeverityCountsResponse
    )

    class Config:
        from_attributes = True


class OverallRiskScoreResponse(BaseModel):
    score: float = 0.0
    severity: str = "N/A"

    class Config:
        from_attributes = True


class SubmittedFileReportItem(BaseModel):
    file_path: str
    findings: List[VulnerabilityFindingResponse] = []
    language: Optional[str] = None
    analysis_summary: Optional[str] = None
    skipped_reason: Optional[str] = None
    identified_components: Optional[List[str]] = None
    asvs_analysis: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True


class SummaryReportResponse(BaseModel):
    submission_id: uuid.UUID
    project_id: uuid.UUID
    project_name: Optional[str] = "N/A"
    scan_type: str = "audit"
    primary_language: Optional[str] = "N/A"
    selected_frameworks: List[str] = []
    analysis_timestamp: Optional[datetime] = None
    summary: SummaryResponse = Field(default_factory=SummaryResponse)
    files_analyzed: List[SubmittedFileReportItem] = []
    overall_risk_score: OverallRiskScoreResponse = Field(
        default_factory=OverallRiskScoreResponse
    )

    class Config:
        from_attributes = True


class LLMUsageItem(BaseModel):
    """One LLM slot a scan used — surfaced on the Results page so the
    operator can see which model ran in each role."""

    category: str  # "Reasoning LLM" / "Utility LLM" / "2nd Analysis LLM"
    name: str
    provider: str
    model_name: str


class ConsolidationStats(BaseModel):
    """The consolidation pass tally — surfaced on the Results page so the
    operator sees how the reasoning model reduced the raw findings."""

    raw_count: int = 0
    consolidated_count: int = 0
    merged_roots: int = 0  # root findings merged from >1 raw finding
    merged_inputs: int = 0  # raw findings absorbed into those roots
    dropped: int = 0  # raw findings dropped as false-positive / noise


class AnalysisResultDetailResponse(BaseModel):
    status: str
    # Always-present pointers to the scan's owning project. Top-level
    # so callers (e.g. ScanRunningPage) can route back to the project
    # even when `summary_report` is null because the scan never reached
    # report-generation (still queued, cancelled, failed early).
    project_id: uuid.UUID
    project_name: str = "N/A"
    summary_report: Optional[SummaryReportResponse] = None
    text_report: Optional[str] = None
    original_code_map: Optional[Dict[str, str]] = None
    fixed_code_map: Optional[Dict[str, str]] = None
    # Per-source finding counts for the scan results page badge row
    # (sast-prescan-followups Group D2). Bucket "agent" covers legacy
    # LLM-emitted findings whose `source` is NULL. Empty dict when no
    # findings exist.
    source_counts: Dict[str, int] = Field(default_factory=dict)
    # The estimate produced by the cost node before the user is asked
    # to approve. Surfaced on the ScanRunningPage so the user sees the
    # number alongside the "Approve & run" button. Stored as JSONB on
    # the Scan row so it's an opaque dict here. Non-null only when the
    # cost-estimate node has run; null for very-early-status scans.
    cost_details: Optional[Dict[str, Any]] = None
    # Whether the scan opted in to cross-file finding validation (#82).
    # Surfaced so ScanRunningPage can show the cross-file-validation
    # stage in the progress rail only for opted-in scans.
    cross_file_validation: bool = False
    deep_vendor_scan: bool = False
    # The LLM configs the scan ran with — reasoning, utility, and the
    # optional second analysis LLM — each with its model. Surfaced on
    # the Results page. Empty for scans created before the column set.
    llms_used: List["LLMUsageItem"] = Field(default_factory=list)
    # The consolidation-pass tally (raw → consolidated, merged, dropped),
    # read from the CONSOLIDATING timeline event. None for scans that
    # never reached consolidation.
    consolidation_stats: Optional["ConsolidationStats"] = None
    # Submission settings — surfaced in the results-page "Scan
    # information" panel. `scan_type` / `repository_url` are top-level
    # here so the panel never depends on `summary_report` being set.
    scan_type: str = "audit"
    disable_temperature: bool = False
    stage_temperatures: Optional[Dict[str, Any]] = None
    repository_url: Optional[str] = None
    # How the code was submitted: 'upload' / 'archive' / 'git'. None for
    # scans created before the column existed.
    source_type: Optional[str] = None
    # Whether durable per-scan task artifacts exist for this scan. Used by
    # the scan-status page to decide if a CANCELLED scan can offer manual
    # resume/restart controls.
    has_resumable_artifacts: bool = False
    # Stage-event audit trail (QUEUED / QUEUED_FOR_SCAN / FILE_ANALYZED
    # etc.). The SSE stream emits these live, but a terminal scan's
    # stream emits them then immediately closes — so a user landing
    # on a FAILED / COMPLETED scan can't reliably see historical
    # events. Including them here lets ScanRunningPage seed the live-
    # event-log deterministically on mount; SSE adds any new ones.
    events: List["ScanEventItem"] = Field(default_factory=list)

    class Config:
        from_attributes = True


class ScanResponse(BaseModel):
    scan_id: uuid.UUID
    project_id: uuid.UUID
    message: str


class PrescanFindingItem(BaseModel):
    """One row in the prescan-approval review card (ADR-009 / G6).

    Mirrors the deterministic-scanner subset of `Finding` rows the
    worker has already persisted by the time the graph hits the
    prescan-approval interrupt. Only the columns the operator needs
    to decide whether to proceed to the LLM phase.
    """

    id: int
    file_path: str
    line_number: Optional[int] = None
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    source: Optional[str] = None
    cwe: Optional[str] = None
    cve_id: Optional[str] = None

    class Config:
        from_attributes = True


class PrescanReviewResponse(BaseModel):
    """Payload for `GET /scans/{scan_id}/prescan-findings` (ADR-009 / G6).

    `has_critical_secret` is true iff at least one Gitleaks finding
    with severity Critical exists. The frontend uses this to decide
    whether to show the override modal when the operator clicks
    Continue.
    """

    scan_id: uuid.UUID
    status: str
    findings: List[PrescanFindingItem] = []
    has_critical_secret: bool = False


class ScanEventItem(BaseModel):
    # DB primary key of the scan_events row. Exposed as `event_id` so
    # the frontend can dedupe the live-event-log against the SSE
    # `scan_event` stream (which carries the same value) by a stable
    # integer rather than a fragile (stage_name, timestamp) fingerprint.
    event_id: int = Field(validation_alias="id")
    stage_name: str
    status: str
    timestamp: datetime
    # §3.10b: optional per-event payload. For `FILE_ANALYZED` events
    # this carries `{file_path, findings_count, fixes_count}`. NULL
    # for legacy stage events.
    details: Optional[Dict[str, Any]] = None

    class Config:
        from_attributes = True
        populate_by_name = True


class ScanHistoryItem(BaseModel):
    id: uuid.UUID
    project_id: uuid.UUID
    project_name: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    cost_details: Optional[Dict[str, Any]] = None
    events: List[ScanEventItem] = []
    # Finding-metrics overview (#86) so list views render the shared
    # ScanCard without an extra request per scan. Populated from
    # `Scan.risk_score` + `Scan.summary`; None for scans that never
    # produced a final report.
    risk_score: Optional[int] = None
    total_findings: Optional[int] = None
    severity_counts: Optional[Dict[str, int]] = None
    has_resumable_artifacts: bool = False
    active_processing_seconds: Optional[float] = None

    class Config:
        from_attributes = True


class PaginatedScanHistoryResponse(BaseModel):
    items: List[ScanHistoryItem]
    total: int


class ProjectOpenFindings(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0


class ProjectStats(BaseModel):
    """Per-project rollup derived from the latest terminal scan.

    Populated by `scan_service.get_paginated_projects`. `risk_score`
    uses the same weighted-findings heuristic as the dashboard so
    numbers stay consistent across pages. `None`-safe: absent when the
    project has never had a terminal scan.
    """

    risk_score: int = 100
    open_findings: ProjectOpenFindings = ProjectOpenFindings()
    fixes_ready: int = 0


class ProjectHistoryItem(BaseModel):
    id: uuid.UUID
    name: str
    repository_url: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    scans: List[ScanHistoryItem] = []
    stats: Optional[ProjectStats] = None

    class Config:
        from_attributes = True


class PaginatedProjectHistoryResponse(BaseModel):
    items: List[ProjectHistoryItem]
    total: int


# ---------------------------------------------------------------------------
# Semgrep Rule Ingestion schemas
# ---------------------------------------------------------------------------


class RuleSourceBase(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1, max_length=4000)
    repo_url: str = Field(..., min_length=1, max_length=2048)
    branch: str = Field("main", min_length=1, max_length=128)
    subpath: Optional[str] = Field(None, max_length=1024)
    license_spdx: str = Field(..., min_length=1, max_length=64)
    author: str = Field(..., min_length=1, max_length=255)


class RuleSourceCreate(RuleSourceBase):
    slug: str = Field(..., min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")


class RuleSourceUpdate(BaseModel):
    display_name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, min_length=1, max_length=4000)
    repo_url: Optional[str] = Field(None, min_length=1, max_length=2048)
    branch: Optional[str] = Field(None, min_length=1, max_length=128)
    subpath: Optional[str] = Field(None, max_length=1024)
    license_spdx: Optional[str] = Field(None, min_length=1, max_length=64)
    author: Optional[str] = Field(None, min_length=1, max_length=255)
    sync_cron: Optional[str] = Field(None, max_length=64)
    enabled: Optional[bool] = None
    auto_sync: Optional[bool] = None


class RuleSourceRead(RuleSourceBase):
    id: uuid.UUID
    slug: str
    sync_cron: Optional[str]
    enabled: bool
    auto_sync: bool
    last_synced_at: Optional[datetime]
    last_commit_sha: Optional[str]
    last_sync_status: str
    last_sync_error: Optional[str]
    rule_count: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class SyncRunRead(BaseModel):
    id: uuid.UUID
    source_id: uuid.UUID
    started_at: datetime
    finished_at: Optional[datetime]
    status: str
    commit_sha_before: Optional[str]
    commit_sha_after: Optional[str]
    rules_added: int
    rules_updated: int
    rules_removed: int
    rules_invalid: int
    error: Optional[str]
    triggered_by: str

    class Config:
        from_attributes = True


class RuleRead(BaseModel):
    id: uuid.UUID
    source_id: uuid.UUID
    namespaced_id: str
    original_id: str
    languages: List[str]
    severity: str
    category: Optional[str]
    technology: List[str]
    cwe: List[str]
    owasp: List[str]
    confidence: Optional[str]
    message: str
    license_spdx: str
    enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class PaginatedSyncRunsResponse(BaseModel):
    items: List[SyncRunRead]
    total: int
    page: int
    page_size: int


class PaginatedRulesResponse(BaseModel):
    items: List[RuleRead]
    total: int
    page: int
    page_size: int


class IngestionSettingsRead(BaseModel):
    allowed_licenses: List[str]
    workdir: str
    global_enabled: bool
    max_rules_per_scan: int
    sweep_interval_seconds: int


class IngestionSettingsUpdate(BaseModel):
    allowed_licenses: Optional[List[str]] = None
    workdir: Optional[str] = Field(None, max_length=1024)
    global_enabled: Optional[bool] = None
    max_rules_per_scan: Optional[int] = Field(None, ge=1, le=50000)
    sweep_interval_seconds: Optional[int] = Field(None, ge=60, le=86400)


class ScanCoverageEntry(BaseModel):
    covered: bool
    enabled_rule_count: int
    recommended_sources: List[RuleSourceRead]


class ScanCoverageResponse(BaseModel):
    coverage: dict[str, ScanCoverageEntry]
