# 05 — Remediation Flow

What happens when a scan is submitted with `scan_type=REMEDIATE`, or when the user invokes **"Apply selective fixes"** on an existing AUDIT scan. Covers fix proposal, Aider-style consolidation, syntax verification, semgrep re-check, and persistence.

Inherits the prescan / cost-approval gates from diagram **04**.

---

## 1. Flow diagram

```mermaid
flowchart TB
    Start[/"Trigger:<br/>POST /scans (REMEDIATE)<br/>or POST /scans/{id}/apply-selective-fixes"/]:::edge

    subgraph Resolve["Resolve target scan + findings"]
      R1["Look up scans row + parent AUDIT (if any)"]:::app
      R2["Filter findings by user-selected finding_ids<br/>or all where severity ≥ threshold"]:::app
      R3["Load proposed_fixes JSONB (per Finding)"]:::app
    end

    subgraph Workflow["LangGraph worker (resumed via remediation_trigger_queue)"]
      direction TB

      N6["Node 9 - consolidate_and_patch_node"]:::app
      N6a["Group fixes per file<br/>(collision detection)"]:::app
      N6b["Render as Aider SEARCH/REPLACE blocks<br/>(multi-line context → multi-line replacement)"]:::app
      N6c{Multiple<br/>overlapping<br/>fixes?}:::gate
      N6d["_run_merge_agent (Sonnet 4.6)<br/>unify conflicting blocks"]:::app
      N6e["Apply block to file copy"]:::app
      N6f{Syntax<br/>OK?}:::gate
      N6g["Tree-sitter verify<br/>(py_compile, node --check,<br/>tree-sitter parse for others)"]:::app
      N6h{Retries<br/>< 3?}:::gate
      N6i["Re-prompt editor agent<br/>with mismatch context"]:::app
      N6j["Mark fix as INVALID"]:::app

      N7["Node 10 - verify_patches_node"]:::app
      N7a["Stage patched_files to temp dir"]:::app
      N7b["Re-run Semgrep on patched files"]:::app
      N7c{Original<br/>finding still<br/>fires?}:::gate
      N7d["finding.fix_verified = True"]:::app
      N7e["finding.fix_verified = False<br/>(partial / regression)"]:::app
      N7f{New Semgrep<br/>finding<br/>introduced?}:::gate
      N7g["Mark patch as INVALID<br/>(regression guard)"]:::app

      N8["Node 11 - save_results_node"]:::app
      N8a["Persist findings.fixes JSONB<br/>{patch_content, applied_at, verified_at}"]:::app
      N8b["Persist scan.final_file_map (snapshot)"]:::app
      N8c["scans.status = REMEDIATION_COMPLETED"]:::app
    end

    subgraph DownloadUI["Download / review (UI)"]
      U1["GET /scans/{id}/preview-archive<br/>→ zip(patched files)"]:::edge
      U2["GET /scans/{id}/preview-git<br/>→ unified git diff"]:::edge
      U3["UI ResultsPage diff viewer<br/>· per-finding diff rows<br/>· verified badge"]:::edge
    end

    PG[("Postgres<br/>findings · scans<br/>code_snapshots (POST_REMEDIATION)")]:::data
    MQ[/"RabbitMQ<br/>remediation_trigger_queue"/]:::data
    LLM{{Anthropic / OpenAI / Google<br/>via Pydantic AI}}:::ext
    SG{{Semgrep 1.95 subprocess}}:::ext

    Start --> Resolve
    Resolve -. "scan_outbox + outbox_sweeper" .-> MQ
    MQ --> N6
    N6 --> N6a --> N6b --> N6c
    N6c -- yes --> N6d --> N6e
    N6c -- no --> N6e
    N6d -. "merge_agent call" .-> LLM
    N6e --> N6f
    N6f -- yes --> N6g --> N7
    N6f -- no --> N6h
    N6h -- yes --> N6i -. "editor agent reprompt" .-> LLM --> N6e
    N6h -- no --> N6j --> N7
    N7 --> N7a --> N7b
    N7b -. "subprocess" .-> SG
    N7b --> N7c
    N7c -- no --> N7d
    N7c -- yes --> N7e
    N7e --> N7f
    N7d --> N7f
    N7f -- yes --> N7g --> N8
    N7f -- no --> N8
    N8 --> N8a --> N8b --> N8c --> PG
    PG --> U1 & U2 & U3

    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
    classDef ext  fill:#ffe4e6,stroke:#9f1239,color:#4c0519;
    classDef gate fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-dasharray: 4 3;
```

---

## 2. Sequence: "Apply selective fixes" from the UI

```mermaid
sequenceDiagram
    autonumber
    actor Dev as Developer
    participant SPA as ResultsPage
    participant API as FastAPI /api/v1
    participant DB as Postgres
    participant MQ as RabbitMQ<br/>remediation_trigger_queue
    participant W as Worker (LangGraph resume)
    participant LLM as LLM provider
    participant SG as Semgrep subprocess
    participant SSE as SSE stream

    Dev->>SPA: select N findings · click "Apply fixes"
    SPA->>API: POST /scans/{id}/apply-selective-fixes<br/>{finding_ids:[...], idempotency_key}
    API->>DB: validate scan ownership · tenant scope
    API->>DB: insert scan_outbox (kind="remediation_trigger",<br/>payload={scan_id, finding_ids})
    API-->>SPA: 202 Accepted

    Note over MQ: outbox_sweeper publishes
    MQ-->>W: deliver

    W->>DB: load scan + selected findings + proposed_fixes
    W->>W: consolidate_and_patch_node<br/>(see flow diagram above)
    W-->>SSE: scan_event REMEDIATING / file_path
    loop per file with fix
      W->>LLM: editor agent · SEARCH/REPLACE block
      LLM-->>W: patched content
      W->>W: tree-sitter syntax check (3 retries)
    end
    W->>SG: re-scan patched files (180 s timeout)
    SG-->>W: rescan findings
    W->>DB: update findings.fix_verified
    W->>DB: insert code_snapshots (POST_REMEDIATION)
    W->>DB: scans.status = REMEDIATION_COMPLETED
    W-->>SSE: scan_event DONE
    SSE-->>SPA: done → refresh
    SPA->>API: GET /scans/{id}/preview-archive  (or /preview-git)
    API-->>SPA: zip / diff
```

---

## Legend

### Where fixes come from

Every analysis agent that finds a vulnerability is also asked to return a `FixResult` (`src/app/infrastructure/agents/types.py`). These are accumulated in `WorkerState.proposed_fixes` during **Node 7 — analyze_files_parallel_node** (see diagram 14) and persisted onto each `Finding.fixes` JSONB. Remediation does **not** call new LLM rounds per finding — it only invokes the **editor** and (on conflict) the **merge** sub-agents.

### Patch format — Aider SEARCH/REPLACE

```text
<<<<<<< SEARCH
def login(user, pwd):
    query = f"SELECT * FROM users WHERE user='{user}'"
=======
def login(user, pwd):
    query = "SELECT * FROM users WHERE user = %s"
>>>>>>> REPLACE
```

The consolidator emits one or more SEARCH/REPLACE blocks per file, with at least one line of context above/below to make the match unique. If the SEARCH text doesn't appear verbatim in the file, the editor re-prompts up to **3 times**, each time widening the context window.

### Sub-agents involved

| Sub-agent     | Model (default) | Role                                                        |
|---------------|-----------------|-------------------------------------------------------------|
| Editor agent  | Sonnet 4.6      | Produces / rewrites SEARCH/REPLACE blocks                   |
| Merge agent   | Sonnet 4.6      | Unifies overlapping or contradictory blocks from peers      |
| Verifier      | (deterministic) | Runs `py_compile` / `node --check` / tree-sitter parse      |

### Syntax verification by language

| Extension              | Validator                                  |
|------------------------|--------------------------------------------|
| `.py`, `.pyi`          | `py_compile.compile(path, doraise=True)`   |
| `.js`, `.mjs`, `.cjs`  | `node --check path.js`                     |
| `.ts`, `.tsx`          | `tsc --noEmit --target ES2020`             |
| `.go`                  | `gofmt -e`                                 |
| Other (`.java`, `.rb`, `.php`, `.c`, `.cpp`, …) | tree-sitter parse with strict grammar |

A patch that fails verification three times in a row is recorded with `finding.fix_verified = false` and `finding.fixes[*].state = "INVALID"`; the original file is left unmodified.

### Regression guard (verify_patches_node)

After all patches apply cleanly, the worker re-runs **Semgrep** (only Semgrep — Bandit/Gitleaks/OSV results are already deterministic) over the patched tree. Two booleans are computed per finding:

| Column                    | Meaning                                                                       |
|---------------------------|-------------------------------------------------------------------------------|
| `findings.fix_verified`   | `true` ⇔ the original rule no longer fires at the original location           |
| `findings.fixes[*].regression_introduced` | `true` ⇔ Semgrep raised a **new** rule on the patched file       |

If a regression is introduced, the patch is rolled back and marked INVALID — the regression guard never lets a "fix" sneak in a new finding.

### Tables touched

| Table             | Write                                                                                 |
|-------------------|---------------------------------------------------------------------------------------|
| `findings`        | `UPDATE … SET fixes = ?, fix_verified = ?, is_applied_in_remediation = true`          |
| `scans`           | `UPDATE … SET status='REMEDIATION_COMPLETED', completed_at = now(), summary = ?`      |
| `code_snapshots`  | `INSERT INTO code_snapshots(type='POST_REMEDIATION', files = <patched JSONB>)`        |
| `scan_events`     | `INSERT INTO scan_events(stage_name='REMEDIATING' / 'COMPLETED', details = ?)`        |
| `llm_interactions`| One row per editor/merge call (token + cost accounting)                                |
| `auth_audit_events` | (optional) `REMEDIATION_APPLIED` event with selected finding count                  |

### Idempotency

The frontend always sends an `X-Idempotency-Key` header (`crypto.randomUUID()` by default — `secure-code-ui/src/shared/api/scanService.ts`). The backend uses it to deduplicate `apply-selective-fixes` requests so refreshing the page or double-clicking the button cannot enqueue two parallel remediation runs.

### Download endpoints

| Endpoint                                      | Returns                                                                     |
|-----------------------------------------------|------------------------------------------------------------------------------|
| `GET /scans/{id}/preview-archive`             | `application/zip` of `code_snapshots[type=POST_REMEDIATION].files`           |
| `GET /scans/{id}/preview-git`                 | Unified `git diff` between `ORIGINAL_SUBMISSION` and `POST_REMEDIATION`      |
| `GET /scans/{id}/preview-archive?source=ORIGINAL_SUBMISSION` | Zip of the originally submitted tree                          |

### Not yet implemented

- Direct **PR creation** on GitHub / GitLab / Bitbucket. The infrastructure (allowlist, project repo URL, OAuth tokens) is scoped but the "open PR" endpoint and per-provider client are out of scope for the current release. The flow above produces patched files + diff that a developer applies manually or via their own CI pipe.
- **Per-language linter** beyond syntax check (e.g., `ruff`, `eslint`) — currently a stretch goal.

---

## Source files

- `src/app/infrastructure/workflows/nodes/consolidate.py`
- `src/app/infrastructure/workflows/nodes/verify.py`
- `src/app/infrastructure/workflows/nodes/results.py`
- `src/app/infrastructure/agents/{editor_agent,merge_agent,types}.py`
- `src/app/api/v1/routers/projects.py` (`apply-selective-fixes`, `preview-archive`, `preview-git`)
- `src/app/infrastructure/scanners/semgrep_runner.py`
- `secure-code-ui/src/pages/analysis/ResultsPage.tsx` (diff viewer, apply UI)
