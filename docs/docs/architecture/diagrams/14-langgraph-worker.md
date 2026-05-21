# 14 — LangGraph Worker State Machine

Deep dive into `sccap_worker` — the heart of every scan. Built on **LangGraph 1.1.9** with an `AsyncPostgresSaver` checkpointer so a scan can be paused at an approval gate, the worker can restart, and the flow resumes exactly where it left off.

---

## 1. Node graph

```mermaid
flowchart TB
    Start([RabbitMQ message<br/>code_submission_queue new scan<br/>· analysis_approved_queue resume]):::edge
    Consumer["consumer.py · aio_pika robust connection<br/>idempotency precheck on scans.status<br/>SCAN_WORKFLOW_TIMEOUT_SECONDS bound<br/>LangGraph thread_id = scan_id"]:::app

    subgraph Graph["LangGraph StateGraph (AsyncPostgresSaver checkpointer)"]
      direction TB
      N1["retrieve_and_prepare_data<br/>load ORIGINAL_SUBMISSION · repo map + dep graph"]:::app
      N2["deterministic_prescan<br/>Bandit · Semgrep · Gitleaks · OSV<br/>CycloneDX BOM · seed WorkerState.findings"]:::app
      DP{prescan<br/>findings?}:::gate
      N3["pending_prescan_approval — interrupt<br/>status=PENDING_PRESCAN_APPROVAL"]:::app
      DPA{prescan<br/>decision}:::gate
      N4["estimate_profiling_cost — work node<br/>utility-slot token estimate<br/>status=PENDING_PROFILING_APPROVAL"]:::app
      N5["profiling_cost_gate — interrupt"]:::app
      DPF{profiling<br/>decision}:::gate
      N6["profile_files<br/>FileProfiler on the utility LLM"]:::app
      N7["estimate_cost — work node<br/>analysis dry-run · prices both reasoning LLMs<br/>status=PENDING_COST_APPROVAL"]:::app
      N8["cost_gate — interrupt"]:::app
      N9["analyze_files_parallel<br/>routed agents × file × reasoning lane(s)<br/>Pydantic AI structured output"]:::app
      N9a["save_raw_llm_findings<br/>snapshot pre-consolidation LLM findings<br/>to raw_llm bucket"]:::app
      N10["consolidate_findings<br/>FindingConsolidator — merge / drop"]:::app
      N11["validate_cross_file<br/>opt-in #81 — no-op unless enabled"]:::app
      N12["consolidate_and_patch<br/>REMEDIATE: merge agent + tree-sitter verify<br/>(no snapshot for AUDIT / SUGGEST)"]:::app
      N13["verify_patches<br/>REMEDIATE: re-run Semgrep on patched code"]:::app
      N14["save_results"]:::app
      N15["save_final_report<br/>risk_score + summary JSON<br/>status=COMPLETED / REMEDIATION_COMPLETED"]:::app
      T1["user_decline<br/>status=BLOCKED_USER_DECLINE"]:::app
      T2["blocked_pre_llm<br/>status=BLOCKED_PRE_LLM"]:::app
      ERR["handle_error<br/>status=FAILED · scan.error_message"]:::app
    end

    CkPt[(checkpoints<br/>thread_id=scan_id · snapshot per node)]:::data
    MQ2[/analysis_approved_queue/]:::data
    LLM{{Reasoning + utility LLMs<br/>Pydantic AI}}:::ext
    SC{{Subprocess scanners<br/>Bandit · Semgrep · Gitleaks · OSV}}:::ext
    Done([END]):::edge

    Start --> Consumer --> N1 --> N2
    N2 -. subprocess .-> SC
    N2 --> DP
    DP -- "findings present" --> N3
    DP -- "none" --> N4
    N3 -. "interrupt → checkpoint" .-> CkPt
    N3 -. "resume via POST /approve" .-> MQ2
    MQ2 --> Consumer
    Consumer -- "Command(resume)" --> DPA
    DPA -- "declined · or >3 resume attempts" --> T1
    DPA -- "approved · critical secret, no override" --> T2
    DPA -- "approved" --> N4
    N4 --> N5
    N5 -. "interrupt → checkpoint" .-> CkPt
    N5 -. "resume via POST /approve" .-> MQ2
    Consumer -- "Command(resume)" --> DPF
    DPF -- "declined" --> T1
    DPF -- "approved" --> N6
    N6 --> N7 --> N8
    N8 -. "interrupt → checkpoint" .-> CkPt
    N8 -. "resume via POST /approve" .-> MQ2
    Consumer -- "Command(resume)" --> N9
    N9 -. "fan-out (per reasoning lane)" .-> LLM
    N9 --> N9a --> N10 --> N11 --> N12
    N12 -. merge-agent .-> LLM
    N12 --> N13
    N13 -. subprocess .-> SC
    N13 --> N14 --> N15 --> Done
    T1 --> Done
    T2 --> Done
    N1 & N2 & N4 & N6 & N7 & N9 & N9a & N10 & N11 & N12 & N13 & N14 -. error_message .-> ERR
    ERR --> Done

    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
    classDef ext  fill:#ffe4e6,stroke:#9f1239,color:#4c0519;
    classDef gate fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-dasharray: 4 3;
```

---

## 2. Worker lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant MQ as RabbitMQ
    participant W as Worker (consumer.py)
    participant DB as Postgres (scans + checkpoints)
    participant G as LangGraph StateGraph
    participant N as Current node

    MQ-->>W: deliver message (prefetch=1)
    W->>DB: SELECT scans WHERE id=?<br/>idempotency precheck<br/>(status IN entry-set)
    alt duplicate / terminal
        W-->>MQ: ack (no-op)
    else fresh
        W->>G: get_workflow().with_config(<br/>configurable={"thread_id":scan_id})
        loop until terminal
            G->>N: execute node
            N->>DB: writes (scan_events, llm_interactions, findings, …)
            N-->>G: WorkerState update
            G->>DB: AsyncPostgresSaver.aput()<br/>(serialize WorkerState into checkpoints)
            alt node is interrupt
                G-->>W: yield interrupt signal
                W-->>MQ: ack (yield without finishing)
                Note over W,DB: worker is free to crash or scale down — state lives in checkpoints
            end
        end
        W->>DB: update scans.status = terminal
        W->>DB: AsyncPostgresSaver.adelete_thread(scan_id)
        W-->>MQ: ack
    end
```

---

## 3. `WorkerState` (typed)

```mermaid
classDiagram
    class WorkerState {
      +UUID scan_id
      +str  scan_type                       "AUDIT | SUGGEST | REMEDIATE"
      +str  current_scan_status
      +UUID reasoning_llm_config_id          "primary reasoning slot"
      +UUID secondary_reasoning_llm_config_id "optional 2nd analysis LLM (#93)"
      +UUID utility_llm_config_id            "profiler + fix verification"
      +dict stage_temperatures               "profiler/analysis/consolidation/merge → float (#78)"
      +bool disable_temperature              "opt-in: provider default temp (#92)"
      +bool cross_file_validation            "opt-in cross-file validation (#81)"
      +dict[str,str] files                   "file_path → content"
      +dict[str,str] initial_file_map        "file_path → hash"
      +dict[str,str] final_file_map          "file_path → hash (post-remediation)"
      +dict[str,str] patched_files           "file_path → patched content (REMEDIATE)"
      +dict repository_map
      +dict dependency_graph
      +dict file_profiles                    "file_path → FileProfile (#71)"
      +dict all_relevant_agents
      +list[VulnerabilityFinding] findings
      +list[FixResult] proposed_fixes
      +dict bom_cyclonedx
      +dict prescan_approval                 "approved + override_critical_secret"
      +dict profiling_approval               "approved"
      +int  resume_attempts                  "prescan-gate loop-back cap (≤3)"
      +str  error_message
    }
    class VulnerabilityFinding {
      +str file_path
      +int line_number
      +str title
      +str severity              "Critical|High|Medium|Low|Informational"
      +str confidence            "High|Medium|Low"
      +str source                "bandit|semgrep|gitleaks|osv · None for agent"
      +str cwe
      +float cvss_score
      +str description
      +str remediation
      +FixSuggestion fixes
      +list[AffectedLocation] affected_locations
      +list[str] corroborating_agents
      +list[str] detected_by_llms          "reasoning LLM(s) that flagged it (#94)"
      +bool fix_verified                   "Semgrep re-run verdict (REMEDIATE)"
      +str cross_file_status               "confirmed|mitigated|unconfirmed (#81)"
    }
    class FixResult {
      +VulnerabilityFinding finding
      +FixSuggestion suggestion
    }
    class FixSuggestion {
      +str description
      +str original_snippet
      +str code
    }
    WorkerState "1" o-- "*" VulnerabilityFinding
    WorkerState "1" o-- "*" FixResult
    FixResult "1" o-- "1" FixSuggestion
    VulnerabilityFinding "1" o-- "0..1" FixSuggestion
```

---

## Legend

### Node responsibilities (one-line each)

| #   | Node                          | Reads                                              | Writes                                                                                              |
|-----|-------------------------------|----------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| 1   | `retrieve_and_prepare_data`   | `scans`, `code_snapshots`, `source_code_files`     | `WorkerState.files/initial_file_map/repository_map/dependency_graph`, `scan_events(RETRIEVE)`        |
| 2   | `deterministic_prescan`       | `WorkerState.files`                                | `WorkerState.findings (prescan)`, `WorkerState.bom_cyclonedx`, `scan_events(PRESCAN_ANALYSIS)`       |
| 3   | `pending_prescan_approval`    | prescan findings, resume payload                   | `scans.status = PENDING_PRESCAN_APPROVAL`, LangGraph interrupt + checkpoint                          |
| 4   | `estimate_profiling_cost`     | `WorkerState.files`                                | `scans.cost_details (profiling)`, `scans.status = PENDING_PROFILING_APPROVAL`                        |
| 5   | `profiling_cost_gate`         | resume payload                                     | LangGraph interrupt + checkpoint; routes on the profiling decision                                   |
| 6   | `profile_files`               | files + repository map                             | `WorkerState.file_profiles` (FileProfiler on the utility LLM slot)                                   |
| 7   | `estimate_cost`               | `file_profiles`, routed agents, reasoning configs  | `scans.cost_details (analysis)`, `scans.status = PENDING_COST_APPROVAL`                              |
| 8   | `cost_gate`                   | resume payload                                     | LangGraph interrupt + checkpoint; routes to `analyze_files_parallel`                                 |
| 9   | `analyze_files_parallel`      | files + routed agents + dep summary (RAG)          | `WorkerState.findings`, `proposed_fixes`, `llm_interactions`, per-file `scan_events(FILE_ANALYZED)` |
| 10  | `consolidate_findings`        | per-agent findings                                 | `FindingConsolidator` reasoning-LLM pass — merge same-defect findings, drop demonstrable FPs        |
| 11  | `validate_cross_file`         | consolidated findings                              | opt-in #81 — stamps `cross_file_status`/`cross_file_rationale`; no-op unless `Scan.cross_file_validation` |
| 12  | `consolidate_and_patch`       | `WorkerState.findings + proposed_fixes`            | REMEDIATE only — `WorkerState.patched_files`, `final_file_map`; merge agent + tree-sitter verify     |
| 13  | `verify_patches`              | `patched_files` vs original                        | REMEDIATE only — `finding.fix_verified`, Semgrep regression detection                                |
| 14  | `save_results`                | `WorkerState.findings`                             | `findings` (bulk insert), fixes JSONB                                                                |
| 15  | `save_final_report`           | findings + fixes                                   | `scans.summary`, `scans.risk_score`, `scans.status = COMPLETED \| REMEDIATION_COMPLETED`, `adelete_thread()` |
| —   | `user_decline`                | resume payload (declined)                          | `scans.status = BLOCKED_USER_DECLINE`                                                                |
| —   | `blocked_pre_llm`             | resume payload (non-overridable critical secret)   | `scans.status = BLOCKED_PRE_LLM`, audit event                                                        |
| —   | `handle_error`                | `WorkerState.error_message`                        | `scans.status = FAILED`, `scans.error_message`, `scan_events(FAILED)`                                |

### Two cost gates

The graph pauses for cost approval **twice**, because profiling (#71) itself spends utility-LLM tokens:

1. **`PENDING_PROFILING_APPROVAL`** — `estimate_profiling_cost` prices the FileProfiler pass on the utility-LLM slot; `profiling_cost_gate` is the bare `interrupt()`.
2. **`PENDING_COST_APPROVAL`** — `estimate_cost` prices the per-agent analysis fan-out (across both reasoning-LLM slots when a secondary is configured); `cost_gate` is the bare `interrupt()`.

The estimate node and its gate node are deliberately split (#84): the estimate node does the work and persists `cost_details`, the gate node only carries the `interrupt()` so a resume re-enters a side-effect-free node.

### Concurrency

- **CONCURRENT_LLM_LIMIT**: 5 — `analyze_files_parallel` bounds file × chunk × agent calls with a single `asyncio.Semaphore`. With a secondary reasoning LLM configured, each lane gets its own pool. Backpressure is also enforced by the per-provider rate limiter token bucket (`*_TOKENS_PER_MINUTE`).
- **Merge agent (REMEDIATE)**: when proposed fixes overlap within a file, `consolidate_and_patch` makes a single reasoning-LLM call (`_run_merge_agent`) to unify them; the merged file is tree-sitter parse-checked, and on a parse failure the file is left unpatched rather than emitting broken code (see diagram 05).
- **`SCAN_WORKFLOW_TIMEOUT_SECONDS`**: 7200 (2 h default). The consumer wraps the entire workflow run in `asyncio.wait_for()` — exceeding the bound forces a `handle_error` transition.

### Resume semantics

When an interrupt fires, the node persists the partial `WorkerState` into the `checkpoints` table and the worker ACKs the message. To resume, the API (in response to `POST /scans/{id}/approve`) inserts a message into `analysis_approved_queue` whose payload includes the approval decision. The consumer reads it and re-invokes the **same** graph thread with a `Command`:

```python
config = {"configurable": {"thread_id": str(scan_id)}}
await graph.ainvoke(Command(resume=payload), config)   # continues from the checkpoint
```

`payload` is the approval decision (`{"kind": "prescan_approval" | "profiling_approval" | "cost_approval", "approved": ...}`). The interrupt site receives it as the `interrupt()` return value, and the gate's routing function moves the state graph past the interrupt.

### Idempotency precheck

```python
ENTRY_STATUSES = {
    "QUEUED",
    "QUEUED_FOR_SCAN",
    "PENDING_APPROVAL",
    "PENDING_PRESCAN_APPROVAL",
    "PENDING_PROFILING_APPROVAL",
    "PENDING_COST_APPROVAL",
}
if scan.status not in ENTRY_STATUSES:
    log.info("worker.duplicate_delivery", scan_id=scan.id, status=scan.status)
    return  # ack and drop
```

This guards against RabbitMQ re-delivery (network hiccup, container restart) without doing double work.

### Checkpoint cleanup

When the workflow reaches a terminal status (`COMPLETED`, `REMEDIATION_COMPLETED`, `CANCELLED`, `BLOCKED_*`, `EXPIRED`, `FAILED`):

```python
await checkpointer.adelete_thread(thread_id=str(scan_id))
```

…which deletes all `checkpoints` rows for that scan. Mitigates **M5** (`checkpoints` table growth) — the table only retains live scans + the most recent interrupted scans.

### Per-call observability

Every LLM call goes through `LLMClient`, which:

1. Acquires a token from the per-provider rate limiter.
2. Calls the Pydantic AI agent for the configured provider.
3. Captures usage: `input_tokens`, `output_tokens`, `cache_read_input_tokens`, `cache_creation_input_tokens` (Anthropic), `total_tokens`, `latency_ms`, `cost` (LiteLLM cost map).
4. Inserts an `llm_interactions` row with `expires_at = now() + RETENTION_DAYS_LLM_INTERACTIONS`.
5. Emits a Langfuse span when `LANGFUSE_ENABLED=true`.

### Failure handling

- Subprocess scanners are wrapped with timeouts (Bandit 120 s; Semgrep / Gitleaks / OSV 180 s). A failed scanner does not fail the whole scan — its findings are simply missing and an audit log row records the failure.
- LLM 5xx / rate-limit responses are retried with exponential backoff (Pydantic AI's `validation_with_retry`) up to 2 attempts.
- A panic anywhere in the graph triggers `handle_error_node`, which sets `scans.status=FAILED`, persists `scans.error_message`, and emits a `scan_event(FAILED)` so the SSE stream surfaces the failure before terminating.

### Outputs available to the UI

| Path                                                  | Result                                                                            |
|-------------------------------------------------------|-----------------------------------------------------------------------------------|
| `GET /scans/{id}`                                     | Full result (findings + fixes + summary + cost_details + risk_score)              |
| `GET /scans/{id}/prescan-findings`                    | Just the deterministic prescan output (for the approval gate UI)                  |
| `GET /scans/{id}/events`                              | Cursor-paginated timeline                                                          |
| `GET /scans/{id}/llm-interactions`                    | Per-LLM-call log (cost + token breakdown; redacted prompts)                       |
| `GET /scans/{id}/stream` (SSE)                        | Live progress — see diagram 09                                                    |
| `GET /scans/{id}/preview-archive` / `/preview-git`    | Patched output download (REMEDIATE only)                                          |

---

## Source files

- `src/app/workers/consumer.py`
- `src/app/infrastructure/workflows/state.py` — `WorkerState`, `VulnerabilityFinding`, `FixResult` types
- `src/app/infrastructure/workflows/graph.py` — `get_workflow()` factory
- `src/app/infrastructure/workflows/nodes/{retrieve,prescan,profile,cost,analyze,consolidate_findings,validate_cross_file,consolidate,verify,results,error}.py`
- `src/app/infrastructure/workflows/callbacks/scan_progress_notifier.py`
- `src/app/infrastructure/messaging/{publisher,outbox_sweeper}.py`
- `src/app/infrastructure/llm_client.py`, `llm_client_rate_limiter.py`
- `src/app/infrastructure/agents/{generic_specialized_agent,chat_agent,finding_consolidator,file_profiler,cross_file_validator}.py`
- `src/app/infrastructure/scanners/{bandit_runner,semgrep_runner,gitleaks_runner,osv_runner,staging,registry}.py`
- `src/app/shared/lib/agent_routing.py`
- `src/app/infrastructure/database/models.py` (`Scan`, `ScanEvent`, `Finding`, `LLMInteraction`)
