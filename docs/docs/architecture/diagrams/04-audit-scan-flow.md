# 04 — Audit Scan Flow

End-to-end behavior of an **AUDIT** scan: from the upload form in the SPA to a final `COMPLETED` scan with persisted findings. Two diagrams here:

1. A **sequence diagram** showing every API/queue/DB interaction in time order.
2. A **state machine** of the `scans.status` column with all approval gates and terminal states.

(Remediation-only logic lives in diagram **05**; the LangGraph worker itself is detailed in diagram **14**.)

---

## 1. Sequence diagram

```mermaid
sequenceDiagram
    autonumber
    actor Dev as End User / Developer
    participant SPA as React SPA<br/>(SubmitPage)
    participant NGX as Nginx
    participant API as FastAPI /api/v1
    participant SUB as ScanSubmissionService
    participant DB as PostgreSQL
    participant OUT as scan_outbox<br/>+ outbox_sweeper
    participant MQ as RabbitMQ<br/>code_submission_queue
    participant W as LangGraph Worker
    participant SC as Deterministic scanners<br/>Bandit · Semgrep · Gitleaks · OSV
    participant RAG as Qdrant RAG
    participant LLM as LLM provider<br/>(Pydantic AI)
    participant SSE as SSE stream<br/>(GET /scans/{id}/stream)

    Dev->>SPA: choose files / git URL / archive<br/>scan_type=AUDIT, frameworks=[…]
    SPA->>NGX: POST /api/v1/scans (multipart)
    NGX->>API: forward + X-Forwarded-For + corr-id
    API->>SUB: ScanSubmissionService.submit(...)
    SUB->>SUB: validate (size, magic-byte, path-traversal,<br/>frameworks allowlist, SSRF allowlist)
    SUB->>DB: BEGIN TX
    SUB->>DB: upsert projects (user_id, name)
    SUB->>DB: insert source_code_files (deduped by hash)
    SUB->>DB: insert scans (status=QUEUED, scan_type=AUDIT)
    SUB->>DB: insert code_snapshots (ORIGINAL_SUBMISSION)
    SUB->>DB: insert scan_events (QUEUED, COMPLETED)
    SUB->>DB: insert scan_outbox (payload={scan_id})
    SUB->>DB: COMMIT
    SUB-->>API: { scan_id }
    API-->>SPA: 201 Created · { scan_id }

    SPA->>API: POST /scans/{id}/stream-token
    API-->>SPA: { access_token (60 s, aud=sse:scan-stream) }
    SPA->>SSE: EventSource(/scans/{id}/stream?access_token=…)
    Note over SSE: open SSE channel - server polls scan_events every 1 s

    par Outbox publish loop
      OUT-->>MQ: AMQP publish (persistent)<br/>routing_key=code_submission_queue
      OUT->>DB: UPDATE scan_outbox SET published_at=now()
    end

    MQ-->>W: deliver message (prefetch=1)
    W->>DB: SELECT scan WHERE id=?<br/>idempotency precheck (status in entry set)
    W->>DB: LangGraph: AsyncPostgresSaver init thread

    rect rgba(199, 210, 254, 0.25)
      Note over W,SC: Node 1 - retrieve_and_prepare_data_node
      W->>DB: load code_snapshots, build repo_map + dep_graph
      W->>DB: insert scan_events (RETRIEVE, STARTED→COMPLETED)
    end

    rect rgba(199, 210, 254, 0.25)
      Note over W,SC: Node 2 - deterministic_prescan_node
      W->>SC: stage files (temp dir)
      W->>SC: bandit_runner (.py / 120 s)
      W->>SC: semgrep_runner (180 s · p/security-audit)
      W->>SC: gitleaks_runner (180 s · secret patterns)
      W->>SC: osv_runner (180 s · CycloneDX 1.5)
      SC-->>W: per-tool JSON findings + BOM
      W->>DB: scan.bom_cyclonedx (≤ 5 MB)
      W->>DB: insert scan_events (PRESCAN_ANALYSIS, COMPLETED)
    end

    alt Critical secret found (Gitleaks Critical)
      W->>DB: scans.status = PENDING_PRESCAN_APPROVAL
      W->>DB: AsyncPostgresSaver interrupt snapshot
      W-->>SSE: scan_state event (PENDING_PRESCAN_APPROVAL)
      Dev->>SPA: review prescan card
      SPA->>API: POST /scans/{id}/approve<br/>{kind: prescan_approval, approved, override_critical_secret}
      API->>DB: insert auth_audit_events / PRESCAN_OVERRIDE_CRITICAL_SECRET event
      API->>MQ: publish analysis_approved_queue<br/>(via scan_outbox)
      MQ-->>W: deliver resume command
      W->>W: Command(resume={prescan_approval:{approved:true, ...}})
    end

    rect rgba(199, 210, 254, 0.25)
      Note over W,LLM: Node 6 - estimate_cost_node
      W->>LLM: count_tokens(prompt) per file × framework × agent
      W->>DB: scan.cost_details (estimated_input_tokens, predicted_output_tokens, total_estimated_cost)
      W->>DB: scans.status = PENDING_COST_APPROVAL
      W-->>SSE: scan_state event (carries cost_details)
    end

    Dev->>SPA: approve cost
    SPA->>API: POST /scans/{id}/approve {kind: cost_approval, approved: true}
    API->>MQ: publish analysis_approved_queue (via outbox)
    MQ-->>W: resume

    rect rgba(199, 210, 254, 0.25)
      Note over W,LLM: Node 7 - analyze_files_parallel_node (16-way fan-out)
      W->>RAG: search_by_framework(framework, file_excerpt) · top-k
      RAG-->>W: enriched control snippets
      W->>LLM: per-finding agent call<br/>Pydantic AI structured output<br/>cache_control on system prompt
      LLM-->>W: parsed VulnerabilityFinding + FixResult
      W->>DB: insert llm_interactions (tokens, cost, latency)
      W->>DB: insert scan_events (FILE_ANALYZED with file_path, findings_count, fixes_count)
      W-->>SSE: scan_event per file
    end

    rect rgba(199, 210, 254, 0.25)
      Note over W: consolidate_findings_node + validate_cross_file_node
      W->>LLM: FindingConsolidator — merge same-defect findings, drop FPs
    end

    rect rgba(199, 210, 254, 0.25)
      Note over W,DB: save_results_node + save_final_report_node
      W->>DB: bulk insert findings (cwe, severity, source, fixes JSONB, disposition='open')
      W->>DB: scan.summary (totals, risk_score)
      W->>DB: scans.status = COMPLETED, completed_at=now()
      W->>DB: insert scan_events (COMPLETED)
      W->>DB: AsyncPostgresSaver.adelete_thread(scan_id)
    end

    W-->>SSE: scan_event (status=COMPLETED) → done
    SSE-->>SPA: done event
    SPA->>API: GET /scans/{id}  → render ResultsPage
```

---

## 2. State machine — `scans.status`

```mermaid
stateDiagram-v2
    [*] --> QUEUED : POST /scans

    QUEUED --> ANALYZING_CONTEXT : worker picks up
    ANALYZING_CONTEXT --> PRESCAN_RUNNING : retrieve done

    PRESCAN_RUNNING --> PENDING_PRESCAN_APPROVAL : critical secret found<br/>(Gitleaks Critical)
    PRESCAN_RUNNING --> ESTIMATING_COST : no critical secret

    PENDING_PRESCAN_APPROVAL --> ESTIMATING_COST : POST /approve - prescan_approval - approved=true
    PENDING_PRESCAN_APPROVAL --> BLOCKED_USER_DECLINE : approved=false
    PENDING_PRESCAN_APPROVAL --> BLOCKED_PRE_LLM : auto-block (non-overridable critical)
    PENDING_PRESCAN_APPROVAL --> EXPIRED : prescan_approval_sweeper (30 min TTL)

    ESTIMATING_COST --> PENDING_COST_APPROVAL : cost computed

    PENDING_COST_APPROVAL --> RUNNING_AGENTS : POST /approve - cost_approval - approved=true
    PENDING_COST_APPROVAL --> CANCELLED : POST /scans/{id}/cancel

    RUNNING_AGENTS --> CORRELATING : agents done
    CORRELATING --> GENERATING_REPORTS : dedupe complete
    GENERATING_REPORTS --> COMPLETED : results persisted<br/>scan_type = AUDIT

    GENERATING_REPORTS --> REMEDIATION_COMPLETED : scan_type = REMEDIATE<br/>(see diagram 05)

    RUNNING_AGENTS --> FAILED : worker error / timeout
    CORRELATING --> FAILED
    GENERATING_REPORTS --> FAILED
    PRESCAN_RUNNING --> FAILED
    ANALYZING_CONTEXT --> FAILED

    COMPLETED --> [*]
    REMEDIATION_COMPLETED --> [*]
    CANCELLED --> [*]
    BLOCKED_USER_DECLINE --> [*]
    BLOCKED_PRE_LLM --> [*]
    EXPIRED --> [*]
    FAILED --> [*]
```

---

## Legend

### Validation gates inside `ScanSubmissionService` (`src/app/core/services/scan/submission.py`)

| Constant                    | Value                  | Defense                                                     |
|-----------------------------|------------------------|-------------------------------------------------------------|
| `MAX_FILES_PER_SCAN`        | 5 000                  | Resource exhaustion                                         |
| `MAX_TOTAL_BYTES`           | 200 MB                 | Storage/perf bound                                          |
| `MAX_FILE_BYTES`            | 10 MB                  | Per-file outlier guard                                      |
| `_VALID_FRAMEWORKS`         | `{asvs, proactive_controls, cheatsheets, llm_top10, agentic_top10}` | Allowlist                          |
| Magic-byte blocklist        | PE · ELF · Mach-O · shebang | Reject pre-compiled / native binaries                  |
| Path-traversal              | `..`, NUL, `\` rejected | Filesystem safety                                          |
| Git URL allowlist           | `github.com`, `gitlab.com`, `bitbucket.org` (HTTPS only) | SSRF                                       |
| `mask_secrets()` on `repo_url` | strips userinfo     | Prevent leaking credentials to logs / DB                    |

### Tables touched (in order)

| Table              | Write kind                                                                |
|--------------------|---------------------------------------------------------------------------|
| `projects`         | upsert (unique `user_id, name`)                                           |
| `source_code_files`| insert (deduped by content hash)                                          |
| `scans`            | insert (`status=QUEUED`, `scan_type`, `frameworks` JSONB)                 |
| `code_snapshots`   | insert (`type=ORIGINAL_SUBMISSION`, `files` JSONB hash-keyed)             |
| `scan_events`      | append per stage (`stage_name`, `status`, `details` JSONB)                |
| `scan_outbox`      | insert (payload + target queue, `published_at=NULL`)                       |
| `checkpoints`      | per-node LangGraph snapshot (`thread_id=scan_id`)                         |
| `llm_interactions` | one row per LLM call (prompt context redacted, cost, tokens, `expires_at`)|
| `findings`         | bulk insert at end (CWE, CVSS, severity, source, `fixes` JSONB)           |
| `auth_audit_events`| append on prescan override (`PRESCAN_OVERRIDE_CRITICAL_SECRET`)            |

### Queues used

| Queue                          | Direction          | Routing key   | Purpose                                                              |
|--------------------------------|--------------------|---------------|----------------------------------------------------------------------|
| `code_submission_queue`        | API → Worker       | same          | Start of every scan                                                  |
| `analysis_approved_queue`      | API → Worker       | same          | Resume after a `*_APPROVAL` interrupt                                |

Both carry `DeliveryMode.PERSISTENT`; the `sccap-bounded-queues` RabbitMQ policy caps each at 100k messages with `overflow=drop-head` so a runaway producer cannot exhaust disk.

### Interrupt payloads (`Command(resume=...)`)

| Gate                 | Resume payload shape                                                                                                  |
|----------------------|-----------------------------------------------------------------------------------------------------------------------|
| Prescan approval     | `{"prescan_approval": {"approved": bool, "override_critical_secret": bool}}`                                          |
| Cost approval        | `{"cost_approval": {"approved": bool}}`                                                                               |

### SSE event types emitted by `scan_progress_notifier`

| Event         | Payload                                                                                                          |
|---------------|------------------------------------------------------------------------------------------------------------------|
| `scan_state`  | `{ scan_id, status, cost_details? }` — every status transition                                                   |
| `scan_event`  | `{ scan_id, event_id, stage_name, status, timestamp, details? }` — per-stage / per-file                          |
| `done`        | sent once on terminal status                                                                                     |

### Terminal statuses

| Status                  | Cause                                                                                                      |
|-------------------------|------------------------------------------------------------------------------------------------------------|
| `COMPLETED`             | AUDIT scan finished successfully                                                                            |
| `REMEDIATION_COMPLETED` | REMEDIATE scan finished (see diagram 05)                                                                    |
| `CANCELLED`             | User canceled at cost gate                                                                                  |
| `BLOCKED_USER_DECLINE`  | User declined at prescan gate                                                                               |
| `BLOCKED_PRE_LLM`       | Non-overridable critical secret; LLM tokens never spent                                                     |
| `EXPIRED`               | Prescan-approval sweeper timed the scan out after 30 min                                                    |
| `FAILED`                | Worker exception; full trace persisted via Fluentd → Loki + `scans.error_message`                            |

### Cleanup

When any terminal status is reached, the worker calls `AsyncPostgresSaver.adelete_thread(thread_id=scan_id)` so the `checkpoints` table does not grow unboundedly (mitigation **M5**).

---

## Source files

- `src/app/api/v1/routers/projects.py` (`POST /scans`, `/stream-token`, `/approve`, `/cancel`, `/stream`)
- `src/app/core/services/scan/submission.py`
- `src/app/infrastructure/messaging/{publisher,outbox_sweeper}.py`
- `src/app/workers/consumer.py`
- `src/app/infrastructure/workflows/nodes/*.py`
- `src/app/infrastructure/scanners/{registry,bandit_runner,semgrep_runner,gitleaks_runner,osv_runner,staging}.py`
- `src/app/infrastructure/database/models.py` (`Scan`, `ScanEvent`, `ScanOutbox`, `CodeSnapshot`, `SourceCodeFile`, `Finding`)
- `secure-code-ui/src/pages/submission/SubmitPage.tsx`, `ScanRunningPage.tsx`
