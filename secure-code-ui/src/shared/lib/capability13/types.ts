export const C13_CONTRACT_MAJOR = 1 as const;
export const C13_EVENT_MAJOR = 7 as const;

export type ProjectionHealth = "complete" | "partial" | "stale" | "conflict";
export type Freshness = "current" | "stale" | "unavailable";
export type ConnectionState =
  | "connecting"
  | "live"
  | "catching_up"
  | "disconnected"
  | "offline"
  | "stale"
  | "partial"
  | "conflict"
  | "unsupported";

export interface OwnerTuple {
  tenant_id: string;
  project_id: string;
  engagement_id: string;
  attempt_id: string;
  resource_owner_user_id?: number;
}

export interface SourceCutoff {
  aggregate_sequence: number;
  event_digest: string;
  captured_at: string;
}

export interface SourcePin {
  owner: "F0" | "F2" | "C4" | "C6" | "C8" | "C9" | "C10" | "C11" | "C13";
  projection_id: string;
  revision_or_generation: number;
  cutoff: number;
  digest: string;
  freshness: Freshness;
  completeness: ProjectionHealth;
  limitations: string[];
}

export interface SafeRef {
  id: string;
  revision: number;
  digest: string;
  label: string;
}

export interface CountSummary {
  label: string;
  count: number;
  state?: string;
}

export interface CausalNode {
  id: string;
  sequence: number;
  occurred_at: string;
  state: string;
  what_changed: string;
  why_it_matters: string;
  next_test?: string | null;
  expected_evidence?: string | null;
  plan_change_condition?: string | null;
  source_refs: SafeRef[];
}

export interface CausalEdge {
  id: string;
  source_node_id: string;
  target_node_id: string;
  relationship: "caused" | "correlated";
}

export interface CapabilityActionSet {
  can_create_report: boolean;
  can_publish_report: boolean;
  can_export_evidence: boolean;
  can_request_governance: boolean;
  can_approve_governance: boolean;
  can_create_retest: boolean;
  disabled_reasons: Partial<Record<keyof Omit<CapabilityActionSet, "disabled_reasons">, string>>;
}

export interface C13CockpitSnapshot {
  contract_major: number;
  snapshot_id: string;
  owner: OwnerTuple;
  attempt_generation: number;
  attempt_state: string;
  attempt_is_terminal: boolean;
  source_cutoff: SourceCutoff;
  source_pins: SourcePin[];
  objective: SafeRef | null;
  current_decision: SafeRef | null;
  active_executions: SafeRef[];
  waiting_executions: SafeRef[];
  unresolved_questions: SafeRef[];
  observation_summary: CountSummary[];
  finding_summary: CountSummary[];
  coverage_summary: CountSummary[];
  cleanup_summary: CountSummary[];
  callback_summary: CountSummary[];
  usage_summary: CountSummary[];
  timeline: CausalNode[];
  edges: CausalEdge[];
  projection_state: ProjectionHealth;
  limitation_codes: string[];
  snapshot_digest: string;
  actions: CapabilityActionSet;
}

export interface CursorPage<T> {
  items: T[];
  next_cursor: string | null;
  source_cutoff: SourceCutoff;
  projection_state: ProjectionHealth;
  limitation_codes: string[];
}

export type ObservationState = "observed" | "candidate" | "refuted" | "superseded";
export interface ObservationProjection {
  id: string;
  revision: number;
  digest: string;
  title: string;
  summary: string;
  state: ObservationState;
  correlation_key: string | null;
  observed_at: string;
  evidence_refs: SafeRef[];
}

export interface FindingProjection {
  id: string;
  revision: number;
  digest: string;
  title: string;
  summary: string;
  truth_state: "candidate" | "confirmed" | "refuted" | "invalidated";
  severity: string;
  severity_source_revision: number;
  severity_is_historical: boolean;
  verification_state: string;
  evidence_refs: SafeRef[];
  framework_refs: SafeRef[];
  cleanup_ref: SafeRef | null;
  governance: GovernanceOverlay[];
}

export interface CanonicalProjection {
  id: string;
  revision: number;
  digest: string;
  title: string;
  kind: "test" | "operation" | "framework" | "coverage";
  state: string;
  outcome: string;
  applicability: string;
  mapping_type: string | null;
  source_generation: number;
  related_refs: SafeRef[];
  limitation_codes: string[];
}

export interface CleanupProjection {
  id: string;
  revision: number;
  digest: string;
  obligation: string;
  action_state: string;
  restoration_disposition: string;
  completion_hold: boolean;
  limitation_codes: string[];
}

export interface CallbackProjection {
  id: string;
  revision: number;
  digest: string;
  expectation_state: string;
  wait_state: string;
  receipt_state: string;
  causality_state: string;
  cleanup_bridge_state: string;
  finding_consequence_ref: SafeRef | null;
  limitation_codes: string[];
}

export interface GovernanceOverlay {
  id: string;
  generation: number;
  digest: string;
  subject_type: string;
  subject_id: string;
  subject_revision: number;
  subject_digest: string;
  treatment: string;
  state: "requested" | "pending_approval" | "approved" | "rejected" | "cancelled" | "scheduled" | "active" | "expired" | "revoked" | "superseded";
  reason_code: string;
  effective_from: string | null;
  expires_at: string | null;
  supersedes_id: string | null;
  decided_at: string | null;
}

export type ReportState = "queued" | "building" | "validated" | "failed" | "cancelled";
export interface ReportProjection {
  id: string;
  version: number;
  state: ReportState;
  profile: string;
  completeness: ProjectionHealth;
  source_manifest_digest: string;
  content_manifest_digest: string | null;
  created_at: string;
  publication_state: "unpublished" | "published" | "withdrawn" | "superseded";
  predecessor_id: string | null;
  limitation_codes: string[];
  artifacts: ArtifactProjection[];
}

export interface ArtifactProjection {
  id: string;
  format: string;
  mime_type: string;
  byte_length: number;
  sha256: string;
}

export interface ExportProjection {
  id: string;
  state: "queued" | "building" | "ready" | "failed" | "cancelled" | "expired";
  profile: "integrity_metadata" | "portable_redacted" | "protected_forensic";
  manifest_digest: string | null;
  artifact_id: string | null;
  artifact_digest: string | null;
  byte_length: number | null;
  expires_at: string | null;
  limitation_codes: string[];
}

export interface RetestProjection {
  id: string;
  source_attempt_id: string;
  successor_engagement_id: string | null;
  successor_attempt_id: string | null;
  scope_variant: "finding_revision" | "finding_group" | "root_cause" | "coverage_branch" | "full_assessment";
  state: string;
  source_digest: string;
  plan_digest: string;
  authority_state: string;
  created_at: string;
  limitation_codes: string[];
}

export interface DeltaProjection {
  id: string;
  source_attempt_id: string;
  successor_attempt_id: string;
  section: "findings" | "coverage" | "cleanup" | "callbacks" | "observations" | "limitations";
  disposition: "added" | "removed_from_current_projection" | "unchanged" | "changed" | "not_comparable";
  owner_outcome: string | null;
  before_ref: SafeRef | null;
  after_ref: SafeRef | null;
  evidence_refs: SafeRef[];
  limitation_codes: string[];
  digest: string;
}

export interface AuditProjection {
  id: string;
  occurred_at: string;
  actor_ref: string;
  action: string;
  subject_type: string;
  subject_id: string;
  outcome: string;
  reason_code: string | null;
  correlation_id: string;
}

export interface EngagementSummary {
  id: string;
  project_id: string;
  title: string;
  assessment_mode: string;
  state: string;
  owner_ref: string;
  current_attempt_id: string | null;
  updated_at: string;
  projection_state: ProjectionHealth;
}

export interface AttemptSummary {
  id: string;
  generation: number;
  state: string;
  is_current: boolean;
  created_at: string;
  completed_at: string | null;
}

export interface CreateEngagementInput {
  schema_version: "sccap.pentest.v1";
  project_id: string;
  name: string;
  mode: "black_box";
  target_url: string;
  authorization_confirmed: true;
  authorization_statement_version: string;
  client_idempotency_key: string;
  rules: {
    maximum_duration_seconds: number;
    maximum_response_bytes: number;
    evidence_retention_days: number;
  };
}

export interface EngagementCreatedReceipt {
  schema_version: "sccap.pentest.v1";
  engagement_id: string;
  attempt_id: string;
  state: string;
  mode: "black_box";
  normalized_origin: string;
  created_at: string;
}

export interface C13Event {
  contract_major: number;
  event_id: string;
  event_type: string;
  owner: OwnerTuple;
  aggregate_sequence: number;
  predecessor_digest: string;
  event_digest: string;
  resource_type: string;
  resource_id: string;
  state: string;
  generation_or_revision: number;
  occurred_at: string;
  invalidates: C13Resource[];
}

export type C13Resource =
  | "snapshot" | "activity" | "observations" | "findings" | "tests"
  | "operations" | "frameworks" | "coverage" | "cleanup" | "callbacks"
  | "reports" | "exports" | "governance" | "retests" | "deltas" | "audit";

export interface C13Filters {
  cursor?: string;
  state?: string;
  kind?: string;
  query?: string;
}

/** Exact closed projection returned by the generic C13 owner-reference lists. */
export interface SafeProjectionRow {
  id: string;
  owner: SourcePin["owner"];
  kind: string;
  revision: number;
  digest: string;
  state: string | null;
  authoritative: boolean;
  limitation_codes: string[];
}

export interface CommandEnvelope {
  idempotency_key: string;
  expected_generation: number;
  expected_digest: string;
}

export interface ReportRequestInput extends CommandEnvelope {
  profile: "executive" | "technical" | "developer_remediation" | "framework_coverage" | "retest_delta";
  formats: Array<"html" | "pdf" | "json" | "csv" | "sarif">;
  locale: string;
  timezone: string;
}

export interface ExportRequestInput extends CommandEnvelope {
  report_id: string;
  source_manifest_digest: string;
  profile: ExportProjection["profile"];
  purpose_code: string;
  category_allowlist: string[];
  classification_ceiling?: "public" | "internal" | "restricted";
  recipient_key_version_id?: string;
  authorization_action_ref?: string;
}

export interface GovernanceRequestInput extends CommandEnvelope {
  subject_owner: "C6" | "C9" | "C10" | "C11" | "C13";
  subject_type: string;
  subject_id: string;
  subject_revision: number;
  subject_digest: string;
  treatment: string;
  reason_code: string;
  justification: string;
  requested_expires_at: string | null;
  authorization_action_ref: string;
  authorization_action_digest: string;
}

export interface GovernanceDecisionInput extends CommandEnvelope {
  decision: "approve" | "reject" | "cancel";
  reason_code: string;
  justification: string;
  authorization_action_ref: string;
  authorization_action_digest: string;
  policy_version: string;
  maximum_duration_seconds?: number;
}

export interface ReportPublicationInput extends CommandEnvelope {
  decision: "published" | "withdrawn" | "superseded";
  reason_code: string;
  justification: string;
  partial_policy_version?: string;
  partial_acknowledgement?: boolean;
  authorization_action_ref?: string;
}

export interface RetestRequestInput {
  idempotency_key: string;
  source_project_id: string;
  source_resource_owner_user_id: number;
  source_cutoff_sequence: number;
  source_cutoff_digest: string;
  scope_variant: RetestProjection["scope_variant"];
  source_refs: Array<{
    owner: "C6" | "C9";
    subject_type: string;
    subject_id: string;
    subject_revision: number;
    subject_digest: string;
  }>;
  reason_code: string;
  assessment_mode: "black_box" | "white_box";
  methodology_profile_ref: string;
  methodology_profile_digest: string;
  source_attempt_revision: number;
  source_attempt_digest: string;
  successor_name: string;
  target_url: string;
  authorization_confirmed: true;
  authorization_statement_version: string;
  rules: {
    maximum_duration_seconds: number;
    maximum_response_bytes: number;
    evidence_retention_days: number;
  };
  maximum_requests: 1;
  interaction_class: "read_only_bootstrap";
  identity_disposition: "anonymous_not_required";
}

export interface FreshRetestReceipt {
  request_id: string;
  plan_id: string;
  link_id: string;
  successor_engagement_id: string;
  successor_attempt_id: string;
  creation_event_id: string;
  execution_outbox_id: string;
  canonical_digest: string;
  duplicate: boolean;
}
