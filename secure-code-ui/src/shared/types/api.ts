// secure-code-ui/src/shared/types/api.ts
//
// **Partial facade** over the auto-generated OpenAPI types.
//
// Types whose shape matches the backend schema 1:1 are aliased from
// `api-generated.ts` (so schema drift fails the TS build). Frontend-only
// view models remain hand-maintained. The scan submission/result/report
// boundary is operation-derived in `shared/lib/scanContract.ts`, which also
// narrows the backend's intentionally free-form JSON before rendering.
//
// To regenerate `api-generated.ts` against the current backend:
//     npm run generate:api
// The generated file should not be edited by hand.

import type { components } from "./api-generated";
import type {
  CostDetails,
  CreateScanResponse,
  FindingDisposition,
} from "../lib/scanContract";

export type {
  ConsolidationStats,
  CostDetails,
  Finding,
  FindingDisposition,
  LLMUsageItem,
  OverallRiskScore,
  ScanResultResponse,
  SubmittedFile,
  SuggestedFix,
  Summary,
  SummaryReport,
} from "../lib/scanContract";

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
  provider: "openai" | "anthropic" | "google" | "deepseek" | "xai" | "custom_openai";
  model_name: string;
  base_url?: string | null;
  tokenizer?: string;
  input_cost_per_million: number;
  output_cost_per_million: number;
  requests_per_minute?: number | null;
  tokens_per_minute?: number | null;
  max_prompt_tokens?: number | null;
  created_at: string;
  updated_at: string;
}

export interface LLMConfigurationCreate {
  name: string;
  provider: "openai" | "anthropic" | "google" | "deepseek" | "xai" | "custom_openai";
  model_name: string;
  base_url?: string | null;
  tokenizer?: string | null;
  input_cost_per_million?: number;
  output_cost_per_million?: number;
  requests_per_minute?: number | null;
  tokens_per_minute?: number | null;
  max_prompt_tokens?: number | null;
  api_key: string;
}
export type LLMConfigurationRead = LLMConfiguration;
export type LLMConfigurationUpdate = Partial<Omit<LLMConfigurationCreate, "api_key">> & {
  api_key?: string;
};

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

export type ScanResponse = CreateScanResponse;
export type GitRepoPreviewRequest = Schemas["GitRepoPreviewRequest"];

// --- Scan results -------------------------------------------------------
// The full result graph is exported from scanContract.ts. It is derived from
// concrete OpenAPI operations and only refines backend fields intentionally
// declared as free-form JSON before they cross the rendering boundary.

export interface FindingDispositionResponse {
  finding_id: number;
  disposition: FindingDisposition;
  disposition_by?: number | null;
  disposition_at?: string | null;
  disposition_note?: string | null;
  // The scan's 0-10 risk score, recomputed after this change (#99).
  scan_risk_score?: number | null;
}

export interface BulkFindingDispositionResponse {
  updated_count: number;
  disposition: FindingDisposition;
  scan_risk_score?: number | null;
}

export interface FindingDispositionEvent {
  id: number;
  finding_id: number;
  old_disposition: FindingDisposition;
  new_disposition: FindingDisposition;
  actor_user_id?: number | null;
  note?: string | null;
  created_at: string;
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
  scanner_rule_id?: string | null;
  cwe?: string | null;
  cve_id?: string | null;
}

export interface PrescanReviewResponse {
  scan_id: string;
  status: string;
  findings: PrescanFindingItem[];
  has_critical_secret: boolean;
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
  has_resumable_artifacts?: boolean;
  active_processing_seconds?: number | null;
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

// --- Governed AI Rule Foundry ---

export type RuleFoundryRegistry = "semgrep" | "gitleaks" | "osv" | "ai_dataflow";
export type RuleFoundryPredicate =
  | "ast"
  | "taint"
  | "dependency_advisory"
  | "secret_pattern"
  | "semantic_runtime";

export interface RuleFoundryFixture {
  name: string;
  language: string;
  content: string;
}

export interface RuleFoundryFixturePack {
  vulnerable: RuleFoundryFixture[];
  fixed: RuleFoundryFixture[];
  negative: RuleFoundryFixture[];
  performance: RuleFoundryFixture[];
  churn: RuleFoundryFixture[];
}

export interface RuleFoundryCandidateCreate {
  finding_id: number;
  predicate_kind: RuleFoundryPredicate;
  bounded: boolean;
  uses_project_specific_names: boolean;
  requires_hidden_runtime_state: boolean;
  proposed_rule?: Record<string, JsonValue>;
  fixtures?: RuleFoundryFixturePack;
}

export interface RuleFoundrySignedVersion {
  id: string;
  version: number;
  payload_sha256: string;
  signature_algorithm: string;
  signing_key_id: string;
  quality_metrics: Record<string, JsonValue>;
  created_at: string;
}

export interface RuleFoundryDeployment {
  id: string;
  version_id: string;
  prior_version_id: string | null;
  state: "shadow" | "promoted" | "rolled_back" | "superseded" | "review_required";
  shadow_started_at: string | null;
  review_due_at: string | null;
  promoted_at: string | null;
  ended_at: string | null;
  eligible_files: number;
  unexpected_matches: number;
}

export interface RuleFoundryCandidate {
  id: string;
  tenant_id: string;
  source_finding_id: number | null;
  registry_kind: RuleFoundryRegistry;
  predicate_kind: RuleFoundryPredicate;
  static_representable: boolean;
  non_representable_reason: string | null;
  stable_identity: string;
  status: string;
  severity: string;
  cwe: string | null;
  normalized_evidence: Record<string, JsonValue>;
  creator_user_id: number | null;
  reviewer_user_id: number | null;
  promoter_user_id: number | null;
  expires_at: string;
  reviewed_at: string | null;
  promoted_at: string | null;
  created_at: string;
  latest_version: RuleFoundrySignedVersion | null;
  active_deployment: RuleFoundryDeployment | null;
}

export interface RuleFoundryCandidatePage {
  items: RuleFoundryCandidate[];
  total: number;
  page: number;
  page_size: number;
}
