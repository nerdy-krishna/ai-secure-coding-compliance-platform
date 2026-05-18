---
title: Agent System
sidebar_position: 2
---

# Agent System

SCCAP builds on **LangGraph 1.x** — every long-running workflow is a
compiled `StateGraph` whose state is persisted per scan in the
Postgres checkpointer. This gives us durable pauses (each approval
gate is a native `interrupt()` + `Command(resume=...)`), clean
step-level retries, and structured parallelism.

## Top-level graph

`src/app/infrastructure/workflows/worker_graph.py` defines the scan
`StateGraph`. The wired flow is:

```
retrieve_and_prepare_data
  → deterministic_prescan
  → pending_prescan_approval    (interrupt — only when prescan findings exist)
  → estimate_profiling_cost     (interrupt → resume via Command)
  → profile_files               (per-file FileProfiler, utility slot)
  → estimate_cost               (interrupt → resume via Command)
  → analyze_files_parallel
  → consolidate_findings        (FindingConsolidator, reasoning slot)
  → validate_cross_file         (opt-in — no-op unless cross_file_validation)
  → consolidate_and_patch       (no-op for AUDIT / SUGGEST)
  → verify_patches              (REMEDIATE-only Semgrep re-pass)
  → save_results
  → save_final_report → END
```

`handle_error` is reachable from every node via `should_continue`
conditional edges and sets status `FAILED`. A declined prescan gate
routes to the terminal `user_decline` / `blocked_pre_llm` nodes; a
declined profiling gate routes to `user_decline`.

### Gated audit pass

`retrieve_and_prepare_data` builds the `RepositoryMappingEngine` +
`ContextBundlingEngine` dependency graph; `deterministic_prescan` runs
the SAST scanners. The graph then crosses up to three native-
`interrupt()` gates — prescan-approval (when the prescan found
something), profiling-cost, and analysis-cost — pausing with full
state in the checkpointer at each. The UI streams `/scans/{id}/stream`
for status changes and posts to `/scans/{id}/approve` to resume.

### Per-file profiling

Between the profiling-cost gate and the analysis-cost gate,
`profile_files` runs the **FileProfiler** over every file on the
*utility* LLM slot. Each profile records a summary, the file's
security-relevant operations, and its **applicable domains** — the
agents relevant to the file's content — and is persisted to
`Scan.file_profiles`. The profiler prompt is **grounded in the
repository map**: the file's tree-sitter imports + symbol index are
fed alongside the source, so the profile's domain picks are anchored
to structure that does not vary between runs (#77).

### Single-pass parallel analysis

When the user approves the analysis-cost gate, the worker resumes the
**same** thread and execution falls through to
`analyze_files_parallel`. Key properties:

- **No topological ordering, no cross-file patch propagation.** Every
  agent sees the original code from the `ORIGINAL_SUBMISSION`
  snapshot.
- **Baseline-aware routing** — `resolve_agents_for_file` computes
  `baseline(language) ∪ (profiler_domains ∩ gating_eligible)`. The
  **baseline** is a deterministic, human-curated floor: every agent
  declares `baseline_languages` in its `domain_query`, and an agent is
  **force-included** for a file in one of its baseline languages
  regardless of what the profiler picked — so an LLM profiler that
  drops a relevant agent can never silently lose coverage. The
  profiler's content-based picks union *on top of* that floor. A file
  with no baseline and no profile falls back to the full gating
  roster. The curated language → concern-area mapping is documented in
  [Baseline Language Routing](./baseline-languages.md) (#76 / #80).
- **Per-file dependency context** is injected from the repository
  map: `build_dep_summary(file_path)` reads symbol signatures from
  successors in the dependency graph and prefixes each chunk with a
  `# --- [DEPENDENCY CONTEXT] ---` block.
- **Concurrency** is a single `asyncio.Semaphore(CONCURRENT_LLM_LIMIT)`
  (default 5) over the union of file × chunk × agent calls.
- **No mid-graph DB writes.** Findings + `proposed_fixes` flow through
  state to `consolidate_findings` and beyond.

### Consolidation + remediation

`consolidate_findings` is backed by the **FindingConsolidator**: per
file, the reasoning LLM merges raw findings describing the same root
cause into one root finding (with every `affected_location`, unioned
`corroborating_agents`, and a re-assessed CVSS) and drops false
positives, duplicates, and noise — a qualitative quality gate with no
severity floor. It replaces the old exact-key `correlate_findings`.

`consolidate_and_patch` is REMEDIATE-only: groups `proposed_fixes`
by file, resolves line-range conflicts via `_run_merge_agent`,
tree-sitter syntax-verifies the patched content, and builds
`final_file_map` for the `POST_REMEDIATION` snapshot. AUDIT is a
no-op; SUGGEST keeps the embedded `fixes` field on each finding but
doesn't build a snapshot.

`save_results` deletes the raw prescan rows and writes the
consolidated finding set fresh; `save_final_report` writes the
CVSS-weighted 0–10 `risk_score` and the `summary` JSON, and sets the
final status (`COMPLETED` or `REMEDIATION_COMPLETED`).

### Cross-file validation (opt-in)

`validate_cross_file` runs after `consolidate_findings`. It is wired
into the graph permanently but is a **true no-op** — no state change,
no timeline event — unless the scan opted in via the
`cross_file_validation` flag, so an opted-out scan's pipeline is
byte-identical to before the node existed.

When opted in, the node closes the single-file blind spot of the
parallel analysis pass — a finding can look real in isolation but be
neutralised by an upstream caller, or confirmed by how a related file
feeds it untrusted data. For each consolidated finding:

- The **`CrossFileSlicer`** runs a deterministic eligibility
  pre-filter — using a tree-sitter `calls` query plus the repository
  map's symbol index, it extracts the *caller slices* (functions in
  other files that call the finding's enclosing function) and the
  *input-context slices* (cross-file functions that function itself
  calls). Findings with no cross-file connection, or from the secret /
  dependency-CVE scanners, are skipped.
- Each eligible finding gets one **`CrossFileValidator`** reasoning-LLM
  call (bounded concurrency) that returns a non-destructive verdict:
  `cross_file_status` ∈ `confirmed` / `mitigated` / `unconfirmed` plus
  a `cross_file_rationale`. Severity is never changed and no finding
  is added or dropped; empty slices or an LLM error fail safe to
  `unconfirmed`, never `mitigated`.

The Results page collapses `mitigated` findings out of the default
view (still expandable), badges `confirmed` ones, and shows the
rationale on the finding detail (#81 / #82).

## Specialized agents

Specialized agents live under `src/app/infrastructure/agents/`:

- **`generic_specialized_agent`** — parameterized per finding type;
  the workhorse called by `analyze_files_parallel`. Takes a chunk +
  a finding-type prompt template, calls the reasoning LLM, returns a
  validated Pydantic model.
- **`file_profiler`** — the FileProfiler (#71); profiles each file on
  the utility slot into a summary + security-relevant operations +
  applicable domains.
- **`finding_consolidator`** — the FindingConsolidator (#72); merges
  and quality-gates raw findings per file on the reasoning slot.
- **`cross_file_validator`** — the CrossFileValidator (#81); re-judges
  an eligible finding against its cross-file caller / input-context
  slices on the reasoning slot, returning a non-destructive verdict.
- **`chat_agent`** — one-shot LLM call used by the Advisor. Runs RAG
  retrieval scoped to the session's `frameworks`, injects the docs
  into the prompt, and returns a response + usage metadata.
- **`symbol_map_agent`** — builds the repo-map symbol index used by
  `ContextBundlingEngine`.

Impact-summary and SARIF generation were removed in the 2026-04-26
cleanup. The downloadable HTML / CSV / PDF findings report
(`GET /scans/{id}/report`) is rendered directly from the consolidated
findings — see [Reporting](../user-guide/reporting.md) — so no
separate reporting node is needed.

## Structured output with Pydantic AI

As of Phase I.3 every structured-output call routes through
`llm_client.generate_structured_output`, which wraps Pydantic AI:

- The call site declares a `ResponseModel` (a Pydantic class).
- Pydantic AI dispatches the LLM call, validates the response, and —
  if validation fails — retries with a typed error message inside the
  same call. The call site receives either a `parsed_output: Model` or
  an `error` field.
- On LangChain 1.x the underlying request uses
  `ChatModel.with_structured_output(ToolStrategy(Model))`. The
  provider-specific JSON-mode conditionals + regex fallbacks from the
  0.3.x era are gone.

## Token + cost accounting

`TokenUsageCallbackHandler` (in `src/app/infrastructure/llm_client.py`)
reads the standardized `response.usage_metadata` field added in
LangChain 1.x — one path for all providers, no per-provider
branches. Counts are persisted on every `llm_interaction` row.

Pre-call estimation and post-call exact cost both run through
LiteLLM; see
[Architecture → LLM Integration](./llm-integration.md) for the full
data flow.

## Observability of agents

Every LLM call writes one `llm_interaction` row with:

- `agent_name`
- `prompt_template_name` + `prompt_context` (JSONB — the exact
  variables fed to `.format(...)`)
- `raw_response` (full text) + `parsed_output` (structured, if valid)
- `input_tokens` / `output_tokens` / `total_tokens`
- `cost`
- `timestamp` (with the request's correlation id attached to every
  log line)

Admins can replay any step from Admin → LLM Interactions for a given
scan, which is invaluable for debugging agent drift.
