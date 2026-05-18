# 05 — Remediation Flow

What happens when a scan is submitted with `scan_type=REMEDIATE`: the
analysis agents propose fixes, the worker merges and syntax-verifies
them in-graph, re-runs Semgrep over the patched code, and persists a
`POST_REMEDIATION` snapshot.

There is **no separate "apply fixes" trigger.** Remediation is not a
post-hoc action on a finished scan — it is a scan *type*, chosen at
submit time. A `REMEDIATE` scan travels the exact same path as `AUDIT`
/ `SUGGEST` (outbox → `code_submission_queue` → worker graph; prescan,
profiling-cost and cost-approval gates from diagram **04**); the only
difference is in three graph nodes near the end.

A `SUGGEST` scan also produces per-finding fixes and runs the same
merge/conflict resolution, but **stops short of writing a patched
snapshot** — it is advisory. `AUDIT` produces no fixes at all.

---

## 1. Flow diagram

```mermaid
flowchart TB
    Start[/"REMEDIATE scan, post cost-approval<br/>(workflow_mode = remediate)"/]:::edge

    subgraph Analyze["analyze_files_parallel"]
      A1["Each routed agent emits a finding<br/>+ a proposed FixSuggestion<br/>(original_snippet → code)"]:::app
      A2["Fixes collect into<br/>WorkerState.proposed_fixes"]:::app
    end

    subgraph Consolidate["consolidate_findings → validate_cross_file"]
      C1["FindingConsolidator merges<br/>same-defect findings"]:::app
    end

    subgraph Patch["consolidate_and_patch_node"]
      P1["Group proposed_fixes by file"]:::app
      P2{">1 fix<br/>overlapping in<br/>one file?"}:::gate
      P3["_resolve_file_fix_conflicts:<br/>apply non-overlapping fixes directly"]:::app
      P4["_run_merge_agent (reasoning LLM,<br/>single shot → MergedFixResponse)"]:::app
      P5{"tree-sitter<br/>parse OK?"}:::gate
      P6["Accept merged code"]:::app
      P7["Fall back — keep the file unpatched<br/>(never emit broken code)"]:::app
      P8["Build final_file_map<br/>(REMEDIATE only)"]:::app
    end

    subgraph Verify["verify_patches_node"]
      V1["Re-stage patched files,<br/>re-run Semgrep (timeout-bounded)"]:::app
      V2{"original Semgrep<br/>rule still fires<br/>at the file?"}:::gate
      V3["finding.fix_verified = False"]:::app
      V4["finding.fix_verified = True"]:::app
    end

    subgraph Save["save_results → save_final_report"]
      S1["Persist findings + fixes"]:::app
      S2["Write code_snapshots<br/>(type = POST_REMEDIATION)"]:::app
      S3["status = REMEDIATION_COMPLETED<br/>+ risk_score + summary"]:::app
    end

    UI["UI ResultsPage<br/>before/after diff tab"]:::edge
    PG[("Postgres<br/>findings · scans · code_snapshots")]:::data
    LLM{{Reasoning LLM<br/>via Pydantic AI}}:::ext
    SG{{Semgrep subprocess}}:::ext

    Start --> Analyze --> Consolidate --> Patch
    A1 --> A2
    P1 --> P2
    P2 -- no --> P3 --> P8
    P2 -- yes --> P4 -. merge call .-> LLM
    P4 --> P5
    P5 -- yes --> P6 --> P8
    P5 -- no --> P7 --> P8
    Patch --> Verify
    V1 -. subprocess .-> SG
    V1 --> V2
    V2 -- yes --> V3
    V2 -- no --> V4
    Verify --> Save
    S1 --> S2 --> S3 --> PG
    PG --> UI

    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
    classDef ext  fill:#ffe4e6,stroke:#9f1239,color:#4c0519;
    classDef gate fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-dasharray: 4 3;
```

---

## 2. Sequence

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant SPA as Submit page
    participant API as FastAPI /api/v1
    participant W as Worker (LangGraph)
    participant LLM as Reasoning LLM
    participant SG as Semgrep subprocess
    participant DB as Postgres

    Dev->>SPA: submit code, scan_type = REMEDIATE
    SPA->>API: POST /scans
    API->>DB: Scan row + ORIGINAL_SUBMISSION snapshot + scan_outbox
    Note over W: prescan / profiling / cost gates (diagram 04)
    W->>LLM: analyze — agents emit findings + proposed fixes
    W->>W: consolidate_findings, validate_cross_file
    W->>W: consolidate_and_patch — group fixes per file
    opt fixes overlap in a file
      W->>LLM: _run_merge_agent — unify into one block
    end
    W->>W: tree-sitter parse-check each patched file
    W->>SG: verify_patches — re-run Semgrep on patched code
    SG-->>W: post-remediation findings
    W->>DB: set fix_verified on Semgrep findings
    W->>DB: code_snapshots (POST_REMEDIATION) + status REMEDIATION_COMPLETED
    SPA->>API: GET /scans/{id}/result
    API-->>SPA: findings + before/after diff
```

---

## Legend

### Where fixes come from

In `remediate` workflow mode every analysis agent that reports a
finding also returns a `FixSuggestion` (`original_snippet` → `code`).
These ride through `WorkerState.proposed_fixes`; remediation does not
make a fresh LLM round per finding — the only extra LLM call is the
**merge agent**, and only when fixes collide.

### consolidate_and_patch_node

`proposed_fixes` are grouped per file. `_resolve_file_fix_conflicts`
applies non-overlapping fixes directly; when two or more fixes touch
the same region, `_run_merge_agent` makes a **single** reasoning-LLM
call that returns a `MergedFixResponse`
(`original_snippet_for_replacement` + `merged_code` + `explanation`)
unifying them. (The older 3-attempt retry loop was removed — it was
weak-model scaffolding.) Every candidate file is parse-checked by
`_verify_syntax_with_treesitter`; if it fails to parse, the merge is
discarded and the file is left unpatched — the graph never emits
syntactically broken code. The patched `final_file_map` is built only
for `REMEDIATE` scans; `SUGGEST` runs the same merge but writes no
snapshot.

### verify_patches_node — Semgrep regression check

After patching, Semgrep is re-run over the patched tree (the only
deterministic scanner replayable this way). For each **Semgrep-emitted,
applied** finding, `fix_verified` is set: `True` when the original rule
no longer fires for that CWE in that file, `False` when it still does.
Findings from other sources (Bandit / Gitleaks / OSV / LLM agents)
keep `fix_verified = NULL` — this node can't replay their detection. A
Semgrep failure here is swallowed; verification is best-effort and
never blocks the scan.

### Tables touched

| Table            | Write                                                            |
|------------------|------------------------------------------------------------------|
| `findings`       | `fixes`, `fix_verified`, `is_applied_in_remediation`             |
| `scans`          | `status = REMEDIATION_COMPLETED`, `risk_score`, `summary`        |
| `code_snapshots` | `INSERT` row `type = POST_REMEDIATION` from `final_file_map`     |
| `scan_events`    | stage events across the patch + verify nodes                    |
| `llm_interactions` | one row per merge-agent call (token + cost accounting)         |

### Reviewing the result

A completed `REMEDIATE` scan's ResultsPage gains a before/after diff
tab (`ORIGINAL_SUBMISSION` vs `POST_REMEDIATION`). There is no
"apply fix" button — the patched snapshot *is* the output of the scan.

---

## Source files

- `src/app/infrastructure/workflows/nodes/consolidate.py` — `consolidate_and_patch_node`, `_resolve_file_fix_conflicts`, `_run_merge_agent`, `_verify_syntax_with_treesitter`
- `src/app/infrastructure/workflows/nodes/verify.py` — `verify_patches_node`
- `src/app/infrastructure/workflows/nodes/results.py` — `save_results_node`, `save_final_report_node`
- `src/app/core/schemas.py` — `FixSuggestion`, `FixResult`, `MergedFixResponse`
- `src/app/infrastructure/scanners/semgrep_runner.py`
- `secure-code-ui/src/pages/analysis/ResultsPage.tsx` — before/after diff viewer
