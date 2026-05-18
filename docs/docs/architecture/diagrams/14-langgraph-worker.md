# 14 — LangGraph Worker State Machine

Deep dive into `sccap_worker` — the heart of every scan. Built on **LangGraph 1.1.9** with an `AsyncPostgresSaver` checkpointer so a scan can be paused at an approval gate, the worker can restart, and the flow resumes exactly where it left off.

---

## 1. Node graph

```mermaid
flowchart TB
    Start([RabbitMQ message<br/>code_submission_queue new scan<br/>or analysis_approved_queue resume]):::edge

    Consumer["consumer.py<br/>aio_pika robust connection<br/>· idempotency precheck on scans.status<br/>· SCAN_WORKFLOW_TIMEOUT_SECONDS bound<br/>· LangGraph thread_id = scan_id"]:::app

    subgraph Graph["LangGraph StateGraph (AsyncPostgresSaver)"]
      direction TB
      N1["1 · retrieve_and_prepare_data_node<br/>load code_snapshots<br/>build repo_map + dep_graph"]:::app
      N2["2 · deterministic_prescan_node<br/>Bandit · Semgrep · Gitleaks · OSV<br/>build CycloneDX 1.5 BOM"]:::app
      DG{Critical<br/>Gitleaks<br/>secret?}:::gate
      N3["3 · pending_prescan_approval_node<br/>(interrupt)<br/>status=PENDING_PRESCAN_APPROVAL"]:::app
      DGU{User<br/>decision}:::gate
      N4["4 · user_decline_node<br/>status=BLOCKED_USER_DECLINE"]:::app
      N5["5 · blocked_pre_llm_node<br/>status=BLOCKED_PRE_LLM"]:::app
      N6["6 · estimate_cost_node<br/>per file × framework × agent token estimate<br/>scan.cost_details JSONB"]:::app
      N6G["interrupt<br/>status=PENDING_COST_APPROVAL"]:::app
      DGC{Cost<br/>approval}:::gate
      N7["7 · analyze_files_parallel_node<br/>fan-out CONCURRENT_LLM_LIMIT=16<br/>per-file/framework/agent LLM calls<br/>(Pydantic AI structured output)<br/>RAG-enriched context"]:::app
      N8["8 · correlate_findings_node<br/>dedupe (file,line,rule)<br/>CWE/CVSS rollup"]:::app
      N9["9 · consolidate_and_patch_node<br/>(only when scan_type=REMEDIATE)<br/>Aider SEARCH/REPLACE blocks<br/>3-retry editor + merge agents"]:::app
      N10["10 · verify_patches_node<br/>re-run Semgrep on patched files<br/>set fix_verified + regression guard"]:::app
      N11["11 · save_results_node<br/>bulk INSERT findings · fixes JSONB"]:::app
      N12["12 · save_final_report_node<br/>scan.summary · risk_score<br/>status=COMPLETED or REMEDIATION_COMPLETED"]:::app
      N13["13 · handle_error_node<br/>status=FAILED<br/>scan.error_message"]:::app
    end

    CkPt[(checkpoints<br/>thread_id=scan_id<br/>snapshot per node)]:::data
    DB[(scans · scan_events · findings ·<br/>llm_interactions · code_snapshots)]:::data
    MQ2[/RabbitMQ<br/>analysis_approved_queue/]:::data
    LLM{{"Anthropic / OpenAI / Google<br/>Pydantic AI · cache_control"}}:::ext
    RAG[(Qdrant<br/>SECURITY_GUIDELINES · CWE)]:::data
    SC{{Subprocess scanners<br/>Bandit · Semgrep · Gitleaks · OSV}}:::ext

    Start --> Consumer --> N1
    N1 --> N2
    N2 -. subprocess .-> SC
    N2 --> DG
    DG -- yes --> N3
    DG -- no --> N6
    N3 -- interrupt persisted --> CkPt
    N3 -. resume payload via MQ .-> MQ2
    MQ2 --> Consumer
    Consumer -- "Command(resume=...)" --> DGU
    DGU -- "approved + override" --> N6
    DGU -- "approved (non-overridable)" --> N5
    DGU -- "declined" --> N4
    N4 --> N12
    N5 --> N12
    N6 --> N6G
    N6G --> CkPt
    N6G -. resume payload via MQ .-> MQ2
    MQ2 --> Consumer
    Consumer --> DGC
    DGC -- approved --> N7
    DGC -- declined --> N4
    N7 -. fan-out RAG search .-> RAG
    N7 -. fan-out LLM calls .-> LLM
    N7 --> N8
    N8 -->|scan_type=AUDIT or SUGGEST| N11
    N8 -->|scan_type=REMEDIATE| N9
    N9 -. merge-agent LLM .-> LLM
    N9 --> N10
    N10 -. subprocess .-> SC
    N10 --> N11
    N11 --> N12
    N12 --> DB
    N12 -- terminal: adelete_thread(scan_id) --> CkPt

    N1 -. on error .-> N13
    N2 -. on error .-> N13
    N6 -. on error .-> N13
    N7 -. on error .-> N13
    N8 -. on error .-> N13
    N9 -. on error .-> N13
    N10 -. on error .-> N13
    N11 -. on error .-> N13
    N13 --> DB

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
      +str  scan_type            "AUDIT | SUGGEST | REMEDIATE"
      +list[str] frameworks
      +UUID reasoning_llm_config_id
      +dict[str,bytes] files              "file_path → content"
      +dict[str,str]   initial_file_map   "file_path → hash"
      +dict[str,str]   final_file_map     "file_path → hash (post-remediation)"
      +dict[str,str]   patched_files      "file_path → patched content"
      +list[VulnerabilityFinding] findings
      +list[FixResult] proposed_fixes
      +dict bom_cyclonedx
      +dict repository_map
      +dict dependency_graph
      +dict prescan_approval     "approved + override_critical_secret"
      +dict cost_approval        "approved"
      +dict cost_details
      +str  error_message
    }
    class VulnerabilityFinding {
      +str file_path
      +int line_number
      +str title
      +str severity              "Critical|High|Medium|Low|Info"
      +str source                "bandit|semgrep|gitleaks|osv|agent"
      +str framework
      +str cwe
      +str description
      +str remediation
      +list[str] references
    }
    class FixResult {
      +UUID finding_id
      +str  file_path
      +str  type                 "search_replace | rewrite"
      +str  suggestion
      +str  reasoning
      +float confidence
    }
    WorkerState "1" o-- "*" VulnerabilityFinding
    WorkerState "1" o-- "*" FixResult
```

---

## Legend

### Node responsibilities (one-line each)

| #   | Node                                       | Reads                                                | Writes                                                                                              |
|-----|--------------------------------------------|------------------------------------------------------|-----------------------------------------------------------------------------------------------------|
| 1   | `retrieve_and_prepare_data_node`           | `scans`, `code_snapshots`, `source_code_files`       | `WorkerState.files/initial_file_map/repo_map/dep_graph`, `scan_events(RETRIEVE)`                    |
| 2   | `deterministic_prescan_node`               | `WorkerState.files`                                  | `WorkerState.findings (prescan)`, `WorkerState.bom_cyclonedx`, `scan_events(PRESCAN_ANALYSIS)`       |
| 3   | `pending_prescan_approval_node`            | prescan findings                                     | `scans.status = PENDING_PRESCAN_APPROVAL`, LangGraph interrupt + checkpoint                          |
| 4   | `user_decline_node`                        | resume payload                                       | `scans.status = BLOCKED_USER_DECLINE`                                                                |
| 5   | `blocked_pre_llm_node`                     | resume payload (non-overridable critical secret)     | `scans.status = BLOCKED_PRE_LLM`, audit event                                                       |
| 6   | `estimate_cost_node`                       | `WorkerState.files`, frameworks, agent registry      | `scans.cost_details`, interrupt                                                                      |
| 7   | `analyze_files_parallel_node`              | files + framework controls (RAG)                     | `WorkerState.findings`, `proposed_fixes`, `llm_interactions`, per-file `scan_events(FILE_ANALYZED)` |
| 8   | `correlate_findings_node`                  | per-agent findings                                   | dedup + CWE/CVSS roll-up on `WorkerState.findings`                                                  |
| 9   | `consolidate_and_patch_node`               | `WorkerState.findings + proposed_fixes`              | `WorkerState.patched_files`, `final_file_map`                                                       |
| 10  | `verify_patches_node`                      | `patched_files` vs original                          | `finding.fix_verified`, regression detection                                                         |
| 11  | `save_results_node`                        | `WorkerState.findings`                               | `findings` (bulk insert), `scans.summary`                                                            |
| 12  | `save_final_report_node`                   | `scans.summary`                                      | `scans.status = COMPLETED \| REMEDIATION_COMPLETED`, `adelete_thread()`                              |
| 13  | `handle_error_node`                        | exception                                            | `scans.status = FAILED`, `scans.error_message`, audit event                                          |

### Concurrency

- **CONCURRENT_LLM_LIMIT**: 16 (env var) — `analyze_files_parallel_node` fans out up to this many concurrent agent calls. Backpressure is enforced by the per-provider rate limiter token bucket (`*_TOKENS_PER_MINUTE`).
- **Merge agent (REMEDIATE)**: when proposed fixes overlap within a file, `consolidate_and_patch_node` makes a single reasoning-LLM call (`_run_merge_agent`) to unify them; the merged file is tree-sitter parse-checked, and on a parse failure the file is left unpatched rather than emitting broken code (see diagram 05).
- **`SCAN_WORKFLOW_TIMEOUT_SECONDS`**: 7200 (2 h default). The consumer wraps the entire workflow run in `asyncio.wait_for()` — exceeding the bound forces a `handle_error_node` transition.

### Resume semantics

When an interrupt fires, the node persists the partial `WorkerState` into the `checkpoints` table and the worker ACKs the message. To resume, the API (in response to `POST /scans/{id}/approve`) inserts a message into `analysis_approved_queue` whose payload includes the approval decision. The consumer reads it, calls:

```python
await graph.aupdate_state(
    {"configurable": {"thread_id": scan_id}},
    {"prescan_approval": {...}}  # or "cost_approval"
)
await graph.ainvoke(None, config)   # continues from the checkpoint
```

…which moves the state graph past the interrupt.

### Idempotency precheck

```python
ENTRY_STATUSES = {
    "QUEUED",
    "QUEUED_FOR_SCAN",
    "PENDING_APPROVAL",
    "PENDING_PRESCAN_APPROVAL",
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
- `src/app/infrastructure/workflows/nodes/{retrieve,prescan,prescan_approval,user_decline,blocked_pre_llm,cost,analyze,correlate,consolidate,verify,results,error}.py`
- `src/app/infrastructure/workflows/callbacks/scan_progress_notifier.py`
- `src/app/infrastructure/messaging/{publisher,outbox_sweeper}.py`
- `src/app/infrastructure/llm_client.py`, `llm_client_rate_limiter.py`
- `src/app/infrastructure/agents/{generic_specialized_agent,chat_agent,finding_consolidator,file_profiler,cross_file_validator}.py`
- `src/app/infrastructure/scanners/{bandit_runner,semgrep_runner,gitleaks_runner,osv_runner,staging,registry}.py`
- `src/app/shared/lib/agent_routing.py`
- `src/app/infrastructure/database/models.py` (`Scan`, `ScanEvent`, `Finding`, `LLMInteraction`)
