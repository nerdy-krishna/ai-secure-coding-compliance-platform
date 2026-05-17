# src/app/core/schemas.py
#
# WARNING: VulnerabilityFinding and LLMInteraction model attacker-influenced data —
# `description`, `title`, `remediation`, `references`, `original_snippet`, `code`,
# `file_path`, `raw_response`, `parsed_output` originate from LLM output and uploaded
# code; downstream renderers must treat them as untrusted (HTML-escape, never log raw,
# never use in shell/SQL).
#
from datetime import datetime, timezone
from typing import Any, Dict, List, TypedDict, Optional, Literal
import uuid

from pydantic import BaseModel, Field, field_validator, model_validator

WorkflowMode = Literal["audit", "suggest", "remediate"]


class MergedFixResponse(BaseModel):
    original_snippet_for_replacement: str = Field(
        description="The exact, complete, and unmodified original code block that should be replaced."
    )
    merged_code: str = Field(
        description="A single, cohesive code block that merges conflicting suggestions."
    )
    explanation: str = Field(
        description="A brief explanation of how the fixes were merged."
    )


class CodeChunk(TypedDict):
    symbol_name: str
    code: str
    start_line: int
    end_line: int


class FixSuggestion(BaseModel):
    """A standard representation of a single code fix, including the original code."""

    description: str = Field(
        description="A brief description of the suggested code change."
    )
    original_snippet: str = Field(
        max_length=200_000,
        description="The exact, original code snippet that is vulnerable and should be replaced.",
    )
    code: str = Field(
        max_length=200_000,
        description="The secure code snippet to replace the vulnerable part.",
    )


class VulnerabilityFinding(BaseModel):
    id: Optional[int] = None
    cwe: Optional[str] = Field(
        default=None,
        pattern=r"^CWE-\d{1,5}$",
        max_length=10,
        description=(
            "CWE ID, e.g. 'CWE-22'. Populated only by deterministic SAST "
            "scanners that emit one; None for LLM-agent findings."
        ),
    )
    title: str = Field(
        max_length=200,
        description="A concise, one-line title for the vulnerability.",
    )
    description: str = Field(
        max_length=8000,
        description="A detailed description of the vulnerability found.",
    )
    severity: Literal["Critical", "High", "Medium", "Low", "Informational"] = Field(
        description="The assessed severity."
    )
    line_number: int = Field(
        ge=0,
        description=(
            "1-based line number where the vulnerability occurs. "
            "0 is reserved for file-level findings that have no specific "
            "line — e.g. OSV CVEs against a dependency manifest, gitleaks "
            "matches without a StartLine, or scanner timeout placeholders."
        ),
    )
    remediation: str = Field(
        max_length=8000,
        description="A detailed explanation of how to fix the vulnerability.",
    )
    confidence: Literal["High", "Medium", "Low"] = Field(
        description="The confidence level of the finding."
    )
    references: List[str] = Field(
        default_factory=list,
        max_length=20,
        description="A list of URLs or reference links.",
    )
    cvss_score: Optional[float] = Field(
        None, ge=0.0, le=10.0, description="The calculated CVSS 3.1 score."
    )
    cvss_vector: Optional[str] = Field(None, description="The CVSS 3.1 vector string.")
    file_path: str = Field(max_length=4096)
    vulnerable_snippet: Optional[str] = Field(
        default=None,
        max_length=20_000,
        description=(
            "The exact, verbatim vulnerable code for this finding — a "
            "substring of the file under review. Anchors the finding's "
            "line number and the UI highlight span. None for legacy "
            "findings and scanner findings without a snippet."
        ),
    )
    fixes: Optional[FixSuggestion] = Field(
        default=None,
        description="The suggested code fix, including original and new snippets.",
    )
    source: Optional[str] = Field(
        default=None,
        description="Provenance: 'bandit' / 'semgrep' / 'gitleaks' / 'osv' for deterministic-scanner findings, None for LLM-agent findings.",
    )
    cve_id: Optional[str] = Field(
        default=None,
        pattern=r"^CVE-\d{4}-\d{4,}$",
        description="CVE identifier (e.g. 'CVE-2024-12345') for findings derived from a known vulnerability database entry. Set by `osv_runner`; None for SAST/secret findings.",
    )
    agent_name: Optional[str] = Field(
        default=None, description="The name of the agent that generated the finding."
    )
    corroborating_agents: Optional[List[str]] = Field(
        default=None, description="List of agents that identified this finding."
    )
    is_applied_in_remediation: bool = Field(
        default=False,
        description="Flag indicating if this finding's fix was applied in a remediation scan.",
    )
    fix_verified: Optional[bool] = Field(
        default=None,
        description=(
            "Patch-verifier result (§3.9). NULL for findings where verification "
            "was not attempted (audit / suggest scans, scanner-only findings, "
            "fixes that weren't applied). True when re-running Semgrep over the "
            "patched code no longer reports a finding for this rule at this "
            "file/line. False when the same Semgrep rule still fires."
        ),
    )

    @field_validator("references")
    @classmethod
    def validate_references(cls, v: List[str]) -> List[str]:
        for ref in v:
            if len(ref) > 2048:
                raise ValueError(
                    f"Reference URL exceeds 2048 characters: {ref[:80]}..."
                )
            if not ref.startswith(("http://", "https://")):
                raise ValueError(
                    f"Reference must start with http:// or https://: {ref[:80]}"
                )
        return v

    @field_validator("file_path")
    @classmethod
    def validate_file_path(cls, v: str) -> str:
        if ".." in v:
            raise ValueError("file_path must not contain '..'")
        return v

    @model_validator(mode="after")
    def validate_cross_fields(self) -> "VulnerabilityFinding":
        # cvss_score and cvss_vector must both be present or both absent
        if (self.cvss_score is None) != (self.cvss_vector is None):
            raise ValueError(
                "cvss_score and cvss_vector must both be set or both be None"
            )
        # Severity must be consistent with cvss_score band
        if self.cvss_score is not None:
            score = self.cvss_score
            expected: Optional[str] = None
            if score >= 9.0:
                expected = "Critical"
            elif score >= 7.0:
                expected = "High"
            elif score >= 4.0:
                expected = "Medium"
            elif score > 0.0:
                expected = "Low"
            else:
                expected = "Informational"
            if expected and self.severity != expected:
                raise ValueError(
                    f"severity '{self.severity}' is inconsistent with cvss_score {score:.1f} (expected '{expected}')"
                )
        return self


class FixResult(BaseModel):
    """Links a specific finding to its suggested fix for collation."""

    finding: VulnerabilityFinding
    suggestion: FixSuggestion


# --- ADDED: New model for a combined finding-and-fix result from a single LLM call ---
class RemediationResult(BaseModel):
    """Represents a single, self-contained vulnerability finding and its corresponding fix."""

    finding: VulnerabilityFinding
    suggestion: FixSuggestion


class AnalysisResult(BaseModel):
    """The structured output of an agent run."""

    # In audit mode, this contains findings.
    # In remediate mode, this contains full remediation results.
    findings: List[VulnerabilityFinding] = Field(default_factory=list)
    remediations: List[RemediationResult] = Field(default_factory=list)


class SpecializedAgentState(TypedDict, total=False):
    """Represents the state of any specialized agent's workflow."""

    scan_id: uuid.UUID
    llm_config_id: Optional[uuid.UUID]
    filename: str
    code_snippet: str
    workflow_mode: str
    file_content_for_verification: Optional[str]
    findings: List[VulnerabilityFinding]
    fixes: List[FixResult]
    error: Optional[str]
    # Verified-findings prompt prefix (sast-prescan-followups B4):
    # SAST scanner findings for the current file, injected into the
    # agent prompt as an `<UNTRUSTED_SCANNER_FINDINGS>` block so the
    # agent skips re-flagging obvious issues. Filtered upstream in
    # `analyze_files_parallel_node` to findings whose `file_path`
    # matches `filename`.
    prescan_findings_for_file: Optional[List[VulnerabilityFinding]]


class LLMInteraction(BaseModel):
    scan_id: Optional[uuid.UUID] = None
    file_path: Optional[str] = None
    agent_name: str = Field(
        description="The name of the agent that initiated the interaction."
    )
    prompt_template_name: Optional[str] = Field(
        None, description="The name of the prompt template used."
    )
    prompt_context: Optional[Dict[str, Any]] = Field(
        None, description="The context data used to format the prompt."
    )
    raw_response: str = Field(
        max_length=1_000_000, description="The raw text response from the LLM."
    )
    parsed_output: Optional[Dict] = Field(
        None, description="The structured output after parsing the response."
    )
    error: Optional[str] = Field(
        None, description="Any validation or parsing errors that occurred."
    )
    cost: Optional[float] = Field(
        None, description="The estimated cost of the LLM interaction."
    )
    input_tokens: Optional[int] = Field(
        None, description="Number of input tokens for the interaction."
    )
    output_tokens: Optional[int] = Field(
        None, description="Number of output tokens for the interaction."
    )
    total_tokens: Optional[int] = Field(
        None, description="Total tokens for the interaction."
    )
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EnrichedDocument(BaseModel):
    """Represents a single document/control after LLM enrichment."""

    id: str
    original_document: str
    enriched_content: str
    metadata: Dict[str, Any]


class PreprocessingResponse(BaseModel):
    """The API response after a framework CSV has been processed."""

    framework_name: str
    llm_config_name: str
    processed_documents: List[EnrichedDocument]
    scan_ready: bool = True


class RAGJobStartResponse(BaseModel):
    """Response when starting a new RAG preprocessing job."""

    job_id: uuid.UUID
    framework_name: str
    status: str
    estimated_cost: Optional[Dict[str, Any]] = None
    message: str


class RAGJobStatusResponse(BaseModel):
    """Response for a job status check."""

    job_id: uuid.UUID
    framework_name: str
    status: str
    estimated_cost: Optional[Dict[str, Any]] = None
    actual_cost: Optional[float] = None
    processed_documents: Optional[List[EnrichedDocument]] = None
    error_message: Optional[str] = None
