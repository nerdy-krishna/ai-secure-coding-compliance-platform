# 07 — Framework Management & RAG Ingestion

Two related concerns:

1. **Framework CRUD** — admins register ASVS / OWASP Proactive Controls / Cheatsheets / NIST / PCI / custom standards, link agents to frameworks, and inspect coverage.
2. **RAG ingestion pipeline** — turn the framework's source corpus (CSV, JSON, PDF/MD, GitHub URL) into LLM-enriched, embedded vectors in Qdrant so the analysis and chat agents can ground their answers.

---

## 1. Framework CRUD (admin console)

```mermaid
flowchart LR
    Admin([Admin / Superuser]):::actor
    UI["FrameworkManagementPage<br/>(pages/admin/FrameworkManagementPage.tsx)"]:::edge
    API1["/api/v1/admin/frameworks"]:::app
    API2["/api/v1/admin/frameworks/{id}/agents"]:::app
    SVC["AdminService<br/>(core/services/admin_service.py)"]:::app
    LOCK["_framework_delete_locks<br/>(in-process advisory lock)"]:::app
    RAGSVC["RAGService<br/>delete_by_framework()"]:::app
    DB[("Postgres<br/>frameworks · framework_agent_mappings<br/>agents · prompt_templates")]:::data
    QD[("Qdrant<br/>SECURITY_GUIDELINES_COLLECTION<br/>(payload.framework filter)")]:::data
    Audit[("auth_audit_events<br/>+ structured logs")]:::data

    Admin -- "HTTPS · JWT (is_superuser)" --> UI
    UI -- "GET" --> API1
    UI -- "POST/PATCH/DELETE" --> API1
    UI -- "POST/DELETE" --> API2
    API1 --> SVC
    API2 --> SVC
    SVC -- "in-process serialize delete" --> LOCK
    SVC -- "CRUD" --> DB
    SVC -- "on DELETE: cascade FK<br/>framework_agent_mappings" --> DB
    SVC -- "on DELETE: cleanup vectors" --> RAGSVC
    RAGSVC -- "delete_by_payload<br/>{framework: name}" --> QD
    SVC -. "logger.info(admin.framework.*)" .-> Audit

    classDef actor fill:#fafafa,stroke:#475569,color:#0f172a;
    classDef edge  fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app   fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data  fill:#dcfce7,stroke:#15803d,color:#052e16;
```

### Operations & invariants

| Operation                                                | Effect                                                                                              | Notes |
|----------------------------------------------------------|-----------------------------------------------------------------------------------------------------|-------|
| `POST /admin/frameworks`                                 | Insert `frameworks(name UNIQUE, description, source_url)`                                            | `name` must not collide with seed defaults `asvs`, `proactive_controls`, `cheatsheets` |
| `GET /admin/frameworks`                                  | List all                                                                                            | Admin-only |
| `GET /admin/frameworks/{id}`                             | Read one                                                                                            | — |
| `PATCH /admin/frameworks/{id}`                           | Mutate description / source_url                                                                      | Managed frameworks (`is_managed=true`) refuse rename |
| `DELETE /admin/frameworks/{id}`                          | Acquire in-process lock → DELETE row (CASCADE) → call `RAGService.delete_by_framework(name)`         | If DB delete succeeds but Qdrant cleanup fails → return `502` and log an audit event so the operator can re-trigger |
| `POST /admin/frameworks/{id}/agents` `{agent_ids:[…]}`   | Replace rows in `framework_agent_mappings`                                                          | Drives agent dispatch in analyze node |

### Built-in (managed) frameworks seeded at startup

| Name                   | Source                                                                                                   |
|------------------------|----------------------------------------------------------------------------------------------------------|
| `asvs`                 | OWASP ASVS 5.0 CSV (controls + descriptions)                                                            |
| `proactive_controls`   | OWASP Proactive Controls markdown (cloned from GitHub)                                                  |
| `cheatsheets`          | OWASP Cheat Sheet Series                                                                                 |
| `llm_top10`            | OWASP Top 10 for LLM Applications                                                                       |
| `agentic_top10`        | OWASP Top 10 for Agentic AI (early draft)                                                               |

---

## 2. RAG ingestion pipeline

```mermaid
flowchart TB
    subgraph SourceTypes["Source kinds (admin chooses)"]
      C1[/"CSV upload<br/>(rows: control_id, title, description, …)<br/>≤ 25 MB · ≤ 100 000 rows · ≤ 10 KB / cell"/]:::edge
      C2[/"JSON upload<br/>≤ 5 MB"/]:::edge
      C3[/"PDF / Markdown upload<br/>≤ 25 MB"/]:::edge
      C4[/"GitHub URL fetch<br/>HTTPS only · github.com /<br/>raw.githubusercontent.com"/]:::edge
    end

    UI["CompliancePage / FrameworkIngestionModal"]:::edge
    API["/api/v1/rag/documents/ingest<br/>/api/v1/rag/ingest-security-standard"]:::app
    Parse["Parser<br/>(pandas for CSV, native JSON,<br/>PDF text extract, MD chunker)"]:::app
    Sanitize["Sanitizer<br/>· allowed cols: control_family, control_title,<br/>  section, category, language<br/>· strip newlines/backticks<br/>· max 256 chars per value"]:::app
    Prep["RAGPreprocessorService<br/>(rag_preprocessor_service.py)<br/>· Semaphore(10)<br/>· MAX_DOC_TEXT_CHARS=8000<br/>· MAX_JOB_COST_USD=$25"]:::app
    Cost["Cost estimator<br/>count_tokens × pricing →<br/>estimated_cost"]:::app
    JobP["rag_preprocessing_jobs<br/>status=PENDING_APPROVAL"]:::data
    Approve{Admin approves<br/>cost gate}:::gate
    Enrich["Per-document LLM enrichment<br/>system prompt asks for JSON:<br/>{security_rule, vulnerability_pattern,<br/>secure_pattern, code_patterns[]}<br/>· UNTRUSTED_CONTROL wrapper<br/>· structured output (Pydantic AI)"]:::app
    Embed["Embedder<br/>fastembed all-MiniLM-L6-v2<br/>(384-dim)"]:::app
    QD[("Qdrant<br/>upsert with payload<br/>{framework, doc_id, control_id,<br/>section, language, chunk_index}")]:::data
    JobC["rag_preprocessing_jobs<br/>status=COMPLETED<br/>actual_cost, processed_documents[]"]:::data
    LF["Langfuse trace (optional)"]:::obs

    C1 & C2 & C3 & C4 --> UI --> API
    API --> Parse --> Sanitize --> Prep
    Prep --> Cost --> JobP
    JobP --> Approve
    Approve -- approve --> Enrich
    Approve -- decline --> X1["status=DECLINED"]:::data
    Enrich -. "LLM call (provider per job.llm_config_id)" .-> LF
    Enrich --> Embed --> QD
    Embed --> JobC

    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
    classDef obs  fill:#fef3c7,stroke:#b45309,color:#451a03;
    classDef gate fill:#ede9fe,stroke:#6d28d9,color:#2e1065,stroke-dasharray: 4 3;
```

### Job lifecycle — `rag_preprocessing_jobs` state machine

```mermaid
stateDiagram-v2
    [*] --> PENDING_APPROVAL : POST /rag/preprocess
    PENDING_APPROVAL --> RUNNING : POST /rag/jobs/{id}/approve
    PENDING_APPROVAL --> DECLINED : POST /rag/jobs/{id}/approve - approved=false
    PENDING_APPROVAL --> EXPIRED : sweep · 24 h TTL
    RUNNING --> COMPLETED : all docs enriched + upserted
    RUNNING --> FAILED : LLM error / cost overrun / parse failure
    COMPLETED --> [*]
    DECLINED --> [*]
    EXPIRED --> [*]
    FAILED --> [*]
```

---

## Legend

### Endpoints

| Endpoint                                                      | Purpose                                                                                          |
|---------------------------------------------------------------|--------------------------------------------------------------------------------------------------|
| `POST /api/v1/rag/documents/ingest`                           | Upload CSV/JSON/PDF/MD for a framework — kicks off a `RAGPreprocessingJob`                       |
| `POST /api/v1/rag/ingest-security-standard`                   | Same but with a GitHub raw URL (no upload)                                                       |
| `POST /api/v1/rag/preprocess/{mode}` (mode = `csv` \| `git_url`) | Legacy / shorthand variant                                                                     |
| `POST /api/v1/rag/jobs/{job_id}/approve`                      | Approve the cost estimate · starts the enrichment phase                                          |
| `GET /api/v1/rag/jobs/{job_id}`                               | Job status, estimated/actual cost, processed_documents (when complete)                           |
| `GET /api/v1/rag/documents/{framework_name}`                  | List enriched documents indexed for a framework                                                  |
| `POST /api/v1/rag/preprocess/reprocess`                       | Re-run enrichment with a different LLM config / target languages, reusing prior `raw_content`    |
| `DELETE /api/v1/admin/frameworks/{id}`                        | Cascade: drop FK + Qdrant cleanup via `RAGService.delete_by_framework()`                          |

### Sanitization (defense against prompt injection from framework docs)

- The raw document body is wrapped in `<UNTRUSTED_CONTROL>…</UNTRUSTED_CONTROL>` before being inserted in the enrichment prompt. The system prompt instructs the LLM to ignore any instructions inside this wrapper.
- Allowed metadata columns are whitelisted: `{control_family, control_title, section, category, language}`. Anything else is dropped before the LLM ever sees it.
- Newlines, backticks and ` ` U+2028/2029 paragraph separators are stripped from metadata values, then values are truncated to **256 characters**.
- Target languages allowlisted: `{python, javascript, typescript, java, go, ruby, php, generic}`. The enriched payload's `code_patterns[].language` must match this list.

### Cost controls

| Knob                          | Value                                                            |
|-------------------------------|------------------------------------------------------------------|
| `MAX_DOC_TEXT_CHARS`          | 8 000 per chunk                                                  |
| `CONCURRENCY_SEMAPHORE`       | `asyncio.Semaphore(10)` on enrichment LLM calls                  |
| `MAX_JOB_COST_USD`            | $25 hard cap per job                                             |
| Cost math                     | `count_tokens()` (LiteLLM bundled tokenizer) × per-model pricing |

### Consent — raw content retention (V14.2.8)

When the operator unchecks "Retain raw content for re-processing", `RAGJobRepository.create_job()` refuses to persist the upload's `raw_content`. The retention sweeper additionally purges `raw_content` 30 days after a job reaches `COMPLETED`, regardless of consent (per `RETENTION_DAYS_RAG_JOBS`).

### Embedding model

- Library: **fastembed** (ONNX)
- Model: **`sentence-transformers/all-MiniLM-L6-v2`** (384-dim sentence embeddings)
- Pre-warmed at Docker build (`FASTEMBED_CACHE_PATH=/opt/fastembed-cache`) so air-gapped runtimes don't hit HuggingFace
- Batch interface: `embedder.embed(list_of_strings)` returns `np.ndarray[N, 384]`

### Qdrant payload schema

```json
{
  "framework": "asvs",
  "doc_id": "asvs-5.0::V5.1.3",
  "control_id": "V5.1.3",
  "section": "V5 Validation",
  "title": "Validate untrusted input on all server-side trust boundaries",
  "language": "generic",
  "chunk_index": 0,
  "source_url": "https://github.com/OWASP/ASVS/...",
  "version": "5.0"
}
```

Filter clauses used by callers:

| Caller                                | Filter expression                                                |
|---------------------------------------|------------------------------------------------------------------|
| Analysis agent during scan            | `framework = ?` (one per selected framework)                     |
| Chat advisor                          | `framework IN (?)` (the session's frameworks)                    |
| Framework cleanup on delete           | `framework = ?` (delete-by-payload)                              |
| CWE lookup                            | (separate collection `CWE_COLLECTION_NAME`, filter by `cwe_id`)  |

### Versioning

There is no implicit migration between framework versions. To bump ASVS from 5.0 to 5.1 the operator:

1. Creates a new framework row (or `PATCH`es `version` if the old one is to be retired).
2. Runs a fresh ingestion job — new Qdrant rows get `payload.version = "5.1"`.
3. Optionally deletes the old framework, which cascades the FK and triggers `RAGService.delete_by_framework()` to drop the stale vectors.

---

## Source files

- `src/app/api/v1/routers/admin_frameworks.py`
- `src/app/api/v1/routers/admin_rag.py`
- `src/app/core/services/admin_service.py`
- `src/app/core/services/rag_preprocessor_service.py`
- `src/app/infrastructure/rag/{embedder,qdrant_store,rag_client,factory,base}.py`
- `src/app/infrastructure/database/repositories/rag_job_repo.py`
- `src/app/infrastructure/database/models.py` (`Framework`, `Agent`, `FrameworkAgentMapping`, `RAGPreprocessingJob`)
- `secure-code-ui/src/pages/admin/FrameworkManagementPage.tsx`
- `secure-code-ui/src/pages/admin/FrameworkIngestionModal.tsx`
- `secure-code-ui/src/pages/compliance/CompliancePage.tsx`
- `secure-code-ui/src/shared/api/{frameworkService,ragService,complianceService}.ts`
