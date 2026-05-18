// secure-code-ui/src/shared/types/api.ts
//
// **Partial facade** over the auto-generated OpenAPI types.
//
// Types whose shape matches the backend schema 1:1 are aliased from
// `api-generated.ts` (so schema drift fails the TS build). Frontend-only
// types and ones whose names diverge from the backend (e.g., our flat
// `ScanResultResponse` vs. generated `AnalysisResultDetailResponse`) stay
// hand-maintained for now; a full rename sweep is planned for Phase G
// when every page's imports get rewritten anyway.
//
// To regenerate `api-generated.ts` against the current backend:
//     npm run generate:api
// The generated file should not be edited by hand.

import type { components } from "./api-generated";

type Schemas = components["schemas"];

// UUID is a branded string type used for IDs throughout the API.
type UUID = `${string}-${string}-${string}-${string}-${string}`;

// --- Auth (frontend-only — OAuth2 form payloads, not pydantic-typed) ----
export interface UserLoginData {
  username: string;
  password: string;
  grant_type?: string;
  scope?: string;
  client_id?: string;
  client_secret?: string;
}

// NOTE: privilege flags (is_active, is_superuser, is_verified) are intentionally
// absent — registration payloads must never set them. Use AdminUserCreate
// (aliased from the generated schemas) for admin-only user creation.
export interface UserRegisterData {
  email: string;
  password: string;
}

export type UserRead = Schemas["UserRead"];

export interface TokenResponse {
  access_token: string;
  token_type: string;
}

// --- LLM Configuration --------------------------------------------------
// Frontend `LLMConfiguration` diverged from backend `LLMConfigurationRead`
// historically (different field set). Keep the flat version hand-written,
// but alias the Create/Update variants that match 1:1.
export interface LLMConfiguration {
  id: string;
  name: string;
  provider: "openai" | "anthropic" | "google" | "deepseek" | "xai";
  model_name: string;
  tokenizer?: string;
  input_cost_per_million: number;
  output_cost_per_million: number;
  created_at: string;
  updated_at: string;
}

export type LLMConfigurationCreate = Schemas["LLMConfigurationCreate"];
export type LLMConfigurationRead = Schemas["LLMConfigurationRead"];
export type LLMConfigurationUpdate = Schemas["LLMConfigurationUpdate"];

// --- Chat ---------------------------------------------------------------
export type ChatSessionCreateRequest = Schemas["ChatSessionCreateRequest"];
export type AskQuestionRequest = Schemas["AskQuestionRequest"];

// ChatSession and ChatMessage are frontend-shaped (match backend
// ChatSessionResponse/ChatMessageResponse but under different names).
// Kept hand-written so consumers' imports don't change.
export interface ChatSession {
  id: string;
  title: string;
  project_id?: string;
  llm_config_id?: string;
  frameworks?: string[];
  created_at: string;
}

export interface ChatMessage {
  id: number;
  role: "user" | "assistant";
  content: string;
  timestamp: string;
  cost?: number;
}

// --- Agents -------------------------------------------------------------
// Backend has no AgentBase; frontend uses it to share the Create/Update shape.
export interface AgentBase {
  name: string;
  description: string;
  domain_query: string;
}

export type AgentCreate = Schemas["AgentCreate"];
export type AgentUpdate = Schemas["AgentUpdate"];
export type AgentRead = Schemas["AgentRead"];

// --- Frameworks ---------------------------------------------------------
export interface FrameworkBase {
  name: string;
  description: string;
}

export type FrameworkCreate = Schemas["FrameworkCreate"];
export type FrameworkUpdate = Schemas["FrameworkUpdate"];
export type FrameworkRead = Schemas["FrameworkRead"];
export type FrameworkAgentMappingUpdate = Schemas["FrameworkAgentMappingUpdate"];

// --- RAG ----------------------------------------------------------------
export interface RAGDocument {
  id: string;
  document: string;
  metadata: Record<string, JsonValue>;
}

export type EnrichedDocument = Schemas["EnrichedDocument"];
export type PreprocessingResponse = Schemas["PreprocessingResponse"];
export type RAGJobStartResponse = Schemas["RAGJobStartResponse"];
export type RAGJobStatusResponse = Schemas["RAGJobStatusResponse"];

// --- Prompt Templates ---------------------------------------------------
export type PromptVariant = "generic" | "anthropic";

// Backend has no PromptTemplateBase; keep shared shape hand-written.
export interface PromptTemplateBase {
  name: string;
  template_type: string;
  agent_name?: string | null;
  /** Which LLM optimization mode this template targets; defaults to "generic". */
  variant: PromptVariant;
  version: number;
  template_text: string;
}

export type PromptTemplateCreate = Schemas["PromptTemplateCreate"];
export type PromptTemplateUpdate = Schemas["PromptTemplateUpdate"];
export type PromptTemplateRead = Schemas["PromptTemplateRead"];

// --- Submission / Scans -------------------------------------------------
export type ScanType = "AUDIT" | "SUGGEST" | "REMEDIATE";

export interface SubmissionFormValues {
  project_name: string;
  scan_type: ScanType;
  repo_url?: string;
  reasoning_llm_config_id: string;
  frameworks: string[];
}

export type ScanResponse = Schemas["ScanResponse"];
export type GitRepoPreviewRequest = Schemas["GitRepoPreviewRequest"];

// --- Scan results (frontend decomposes the backend's single
// AnalysisResultDetailResponse into several flat types for UI convenience;
// kept hand-written to avoid a page-wide rename). -----------------------
export interface SuggestedFix {
  description?: string;
  original_snippet?: string;
  code?: string;
}

export interface Finding {
  id: number;
  file_path: string;
  title: string;
  // Populated only by SAST scanners that emit a CWE; absent for LLM findings.
  cwe?: string | null;
  description: string;
  severity: string;
  line_number: number;
  // Exact verbatim vulnerable code; the UI matches it against the file
  // to highlight the precise span. null for legacy / scanner findings.
  vulnerable_snippet?: string | null;
  // Every site a merged finding manifests, beyond the primary location.
  affected_locations?: { line_number: number; snippet?: string | null }[] | null;
  remediation: string;
  confidence: string;
  // Originating scanner/agent for the finding. Mirrors the
  // `findings.source` column on the backend (bandit / semgrep /
  // gitleaks / osv / null for legacy LLM-emitted rows). Used to
  // drive the by-source filter chip row on ResultsPage.
  source?: string | null;
  corroborating_agents?: string[];
  // Reasoning LLM(s) that detected the finding (#94). Two entries ⇒
  // both models in a dual-LLM scan independently flagged it. Absent /
  // null for scanner-emitted and pre-#94 findings.
  detected_by_llms?: string[] | null;
  cvss_score?: number;
  cvss_vector?: string;
  references: string[];
  fixes?: SuggestedFix;
  is_applied_in_remediation?: boolean;
  // Opt-in cross-file validation verdict (#81 / PRD #75). null when the
  // scan did not opt in or the finding was skipped by the eligibility
  // pre-filter; otherwise "confirmed" / "mitigated" / "unconfirmed".
  cross_file_status?: "confirmed" | "mitigated" | "unconfirmed" | null;
  cross_file_rationale?: string | null;
}

export interface SubmittedFile {
  file_path: string;
  findings: Finding[];
  language?: string;
  analysis_summary?: string;
  skipped_reason?: string;
}

export interface Summary {
  total_findings_count?: number;
  files_analyzed_count?: number;
  severity_counts?: {
    CRITICAL?: number;
    HIGH?: number;
    MEDIUM?: number;
    LOW?: number;
    INFORMATIONAL?: number;
  };
}

export interface OverallRiskScore {
  score: number | string;
  severity: string;
}

export interface SummaryReport {
  scan_id: string;
  project_id: string;
  project_name: string;
  scan_type: string;
  primary_language?: string;
  selected_frameworks: string[];
  analysis_timestamp: string;
  summary: Summary;
  files_analyzed: SubmittedFile[];
  overall_risk_score?: OverallRiskScore;
}

// One LLM slot a scan ran with — shown in the Results page "Models
// used" panel.
export interface LLMUsageItem {
  category: string;
  name: string;
  provider: string;
  model_name: string;
}

// The consolidation-pass tally, shown in the Results "Models used" card.
export interface ConsolidationStats {
  raw_count: number;
  consolidated_count: number;
  merged_roots: number;
  merged_inputs: number;
  dropped: number;
}

export interface ScanResultResponse {
  scan_id: string;
  status: string;
  // Always-present project pointers (top-level on the backend response).
  // Populated even when `summary_report` is null because the scan never
  // produced one (queued / cancelled / failed early).
  project_id: string;
  project_name: string;
  summary_report?: SummaryReport;
  original_code_map?: { [filePath: string]: string };
  fixed_code_map?: { [filePath: string]: string };
  // Per-source finding counts for the per-source counter row on the
  // results page (sast-prescan-followups Group D2). Empty object when
  // the scan has no findings.
  source_counts?: { [source: string]: number };
  // Estimate produced by the cost node before approval. Surfaced on
  // ScanRunningPage so the user sees the number alongside the
  // "Approve & run" button. Null until cost-estimate runs.
  cost_details?: CostDetails | null;
  // Whether the scan opted in to cross-file finding validation (#82).
  // Drives the cross-file-validation stage in ScanRunningPage's rail.
  cross_file_validation?: boolean;
  // The LLM configs the scan ran with — reasoning / utility / 2nd
  // analysis LLM — each with its provider + model. Shown on Results.
  llms_used?: LLMUsageItem[];
  // Consolidation-pass tally (raw → consolidated, merged, dropped).
  consolidation_stats?: ConsolidationStats | null;
  // Stage-event audit trail. SSE emits these live for in-progress
  // scans; the same list is included here so a terminal scan's page
  // can seed the live-event-log deterministically on mount, instead
  // of waiting for an SSE that may have already closed.
  events?: ScanEventItem[];
}

// --- Prescan-approval gate (ADR-009 / G6). One row per deterministic-
// scanner finding produced before the LLM phase; rendered on the
// scan-status page when status === "PENDING_PRESCAN_APPROVAL".
export interface PrescanFindingItem {
  id: number;
  file_path: string;
  line_number?: number | null;
  title: string;
  description?: string | null;
  severity?: string | null;
  source?: string | null;
  cwe?: string | null;
  cve_id?: string | null;
}

export interface PrescanReviewResponse {
  scan_id: string;
  status: string;
  findings: PrescanFindingItem[];
  has_critical_secret: boolean;
}

export interface CostDetails {
  input_cost: number;
  predicted_output_cost: number;
  total_estimated_cost: number;
  predicted_output_tokens: number;
  total_input_tokens: number;
}

export type ScanEventItem = Schemas["ScanEventItem"];

export interface ScanHistoryItem {
  id: UUID;
  project_id: UUID;
  project_name: string;
  scan_type: string;
  status: string;
  created_at: string;
  completed_at: string | null;
  cost_details: CostDetails | null;
  events: ScanEventItem[];
  llm_interactions?: LLMInteractionResponse[];
  // Finding-metrics overview (#86) — populated for scans that produced
  // a final report; null otherwise. Drives the shared ScanCard.
  risk_score?: number | null;
  total_findings?: number | null;
  severity_counts?: Record<string, number> | null;
}

export interface PaginatedScanHistoryResponse {
  items: ScanHistoryItem[];
  total: number;
}

export interface ProjectOpenFindings {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}

export interface ProjectStats {
  risk_score: number;
  open_findings: ProjectOpenFindings;
  fixes_ready: number;
}

export interface ProjectHistoryItem {
  id: UUID;
  name: string;
  repository_url: string | null;
  created_at: string;
  updated_at: string;
  scans: ScanHistoryItem[];
  stats: ProjectStats | null;
}

export interface PaginatedProjectHistoryResponse {
  items: ProjectHistoryItem[];
  total: number;
}

// Defines a type for any valid JSON value, improving type safety over 'any'.
export type JsonValue =
  | string
  | number
  | boolean
  | null
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface LLMInteractionResponse {
  id: number;
  scan_id?: string;
  file_path?: string;
  agent_name: string;
  llm_config_id?: string | null;
  llm_name?: string | null;
  timestamp: string;
  cost?: number;
  input_tokens?: number;
  output_tokens?: number;
  total_tokens?: number;
  prompt_template_name?: string | null;
  prompt_context?: Record<string, JsonValue> | null;
  parsed_output?: Record<string, JsonValue> | null;
  error?: string | null;
}

// --- Setup --------------------------------------------------------------
export type SetupStatusResponse = Schemas["SetupStatusResponse"];

// --- Semgrep Rule Ingestion ---

export interface RuleSourceRead {
  id: string;
  slug: string;
  display_name: string;
  description: string;
  repo_url: string;
  branch: string;
  subpath: string | null;
  license_spdx: string;
  author: string;
  sync_cron: string | null;
  enabled: boolean;
  auto_sync: boolean;
  last_synced_at: string | null;
  last_commit_sha: string | null;
  last_sync_status: "never" | "running" | "success" | "failed";
  last_sync_error: string | null;
  rule_count: number;
  created_at: string;
  updated_at: string;
}

export interface RuleSourceCreate {
  slug: string;
  display_name: string;
  description: string;
  repo_url: string;
  branch: string;
  subpath?: string | null;
  license_spdx: string;
  author: string;
}

export interface RuleSourceUpdate {
  display_name?: string;
  description?: string;
  repo_url?: string;
  branch?: string;
  subpath?: string | null;
  license_spdx?: string;
  author?: string;
  sync_cron?: string | null;
  enabled?: boolean;
  auto_sync?: boolean;
}

export interface SyncRunRead {
  id: string;
  source_id: string;
  started_at: string;
  finished_at: string | null;
  status: "running" | "success" | "failed";
  commit_sha_before: string | null;
  commit_sha_after: string | null;
  rules_added: number;
  rules_updated: number;
  rules_removed: number;
  rules_invalid: number;
  error: string | null;
  triggered_by: string;
}

export interface RuleRead {
  id: string;
  source_id: string;
  namespaced_id: string;
  original_id: string;
  languages: string[];
  severity: string;
  category: string | null;
  technology: string[];
  cwe: string[];
  owasp: string[];
  confidence: string | null;
  message: string;
  license_spdx: string;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface PaginatedSyncRunsResponse {
  items: SyncRunRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface PaginatedRulesResponse {
  items: RuleRead[];
  total: number;
  page: number;
  page_size: number;
}

export interface IngestionSettingsRead {
  allowed_licenses: string[];
  workdir: string;
  global_enabled: boolean;
  max_rules_per_scan: number;
  sweep_interval_seconds: number;
}

export interface IngestionSettingsUpdate {
  allowed_licenses?: string[];
  workdir?: string;
  global_enabled?: boolean;
  max_rules_per_scan?: number;
  sweep_interval_seconds?: number;
}

export interface ScanCoverageEntry {
  covered: boolean;
  enabled_rule_count: number;
  recommended_sources: RuleSourceRead[];
}

export interface ScanCoverageResponse {
  coverage: Record<string, ScanCoverageEntry>;
}
