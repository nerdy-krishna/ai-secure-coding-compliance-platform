# 02 — Backend Architecture

Detailed view of every backend module, queue, store, and external dependency. Two-tier organization: **HTTP-facing app** (`sccap_app`) and **async worker** (`sccap_worker`), sharing Postgres, Qdrant and RabbitMQ.

---

## Diagram

```mermaid
flowchart TB
    %% ===== Edge =====
    Client[/"Browser SPA · CI agent · SCIM client"/]:::edge

    subgraph EdgeTier["Edge Tier (sccap_ui)"]
      Nginx["Nginx 1.25 (alpine)<br/>TLS 1.2/1.3, OCSP stapling<br/>limit_req: api=30 r/s · spa=120 r/s"]:::edge
      Certbot["Certbot · ACME v2<br/>renewal loop every 12 h"]:::edge
    end

    %% ===== App tier =====
    subgraph AppTier["FastAPI App Tier (sccap_app, uvicorn :8000)"]
      direction TB

      subgraph Middleware["Middleware stack"]
        CIDMW["correlation_id middleware<br/>(contextvars binding)"]:::app
        CORSMW["dynamic CORS middleware<br/>(allowed_origins from DB cache)"]:::app
        AuthMW["fastapi-users JWT<br/>CustomCookieJWTStrategy +<br/>SSE-token variant"]:::app
        AuditMW["SSO audit middleware<br/>(IP via TRUSTED_PROXY_CIDRS)"]:::app
        OTelMW["Langfuse · OTel spans"]:::app
      end

      subgraph Routers["API v1 Routers (/api/v1)"]
        direction LR
        R1["/auth/* · sso · webauthn"]:::app
        R2["/scim"]:::app
        R3["/scans · /scans/{id}/*<br/>(submit, approve, stream, cancel, archive, git-preview)"]:::app
        R4["/projects"]:::app
        R5["/chat/sessions/*"]:::app
        R6["/compliance/*"]:::app
        R7["/dashboard/stats · /search"]:::app
        R8["/setup · /refresh"]:::app
        R9["/admin/* (LLM, frameworks, agents, prompts,<br/>users, tenants, sso, scim, smtp,<br/>config, logs, findings, rule-sources, seed)"]:::app
        RMCP["MCP server (mounted)<br/>app/api/mcp/server.py"]:::app
      end

      subgraph Services["Core Services (src/app/core/services)"]
        direction LR
        SubmitSvc["ScanSubmissionService<br/>· SSRF guard<br/>· magic-byte check<br/>· tenant + project upsert<br/>· outbox write"]:::app
        QuerySvc["ScanQueryService"]:::app
        ChatSvc["ChatService<br/>· mask_secrets() in/out<br/>· session lifecycle"]:::app
        ComplianceSvc["ComplianceService"]:::app
        AdminSvc["AdminService"]:::app
        SystemCfg["SystemConfigService<br/>+ in-process cache,<br/>optimistic locking"]:::app
        SeedSvc["DefaultSeedService"]:::app
        RagPrepSvc["RAGPreprocessorService<br/>· ≤ $25/job · sem(10)"]:::app
      end

      subgraph Infra["Infrastructure modules (src/app/infrastructure)"]
        direction TB
        LLM["LLMClient + RateLimiter<br/>Pydantic AI 1.86<br/>LiteLLM cost map"]:::app
        RAG["RAGClient · Embedder<br/>QdrantStore"]:::app
        Pub["messaging.publisher<br/>messaging.outbox_sweeper"]:::app
        Repo["Repositories (SQLAlchemy 2.x async)"]:::app
        Obs["observability/langfuse_client<br/>observability/mask"]:::app
        Sched["Background tasks:<br/>outbox · findings_source · prescan_approval<br/>· retention · semgrep_sync · scan_progress_notifier"]:::app
      end
    end

    %% ===== Worker tier =====
    subgraph WorkerTier["LangGraph Worker (sccap_worker)"]
      direction TB
      Consumer["aio_pika consumer<br/>connect_robust + backoff<br/>thread cleanup on terminal"]:::app
      WF["LangGraph StateGraph<br/>AsyncPostgresSaver (checkpoints)"]:::app
      Scanners["Deterministic scanners<br/>Bandit · Semgrep 1.95 · Gitleaks 8.21 · OSV-Scanner 2.3"]:::app
      Agents["16+ Specialized Agents<br/>Auth · AccessCtl · Crypto · Validation · …<br/>+ generic_specialized_agent · chat_agent"]:::app
      Editor["Aider-style editor<br/>SEARCH/REPLACE · 3-retry loop<br/>tree-sitter syntax check"]:::app
    end

    %% ===== Data tier =====
    subgraph DataTier["Data Tier"]
      direction LR
      PG[("PostgreSQL 16<br/>scans · findings · projects · users<br/>chat_messages · llm_interactions<br/>frameworks · agents · prompt_templates<br/>system_configurations · tenants<br/>sso_providers · webauthn_credentials<br/>auth_audit_events · scim_tokens<br/>rag_preprocessing_jobs · semgrep_rules<br/>scan_events · scan_outbox · checkpoints")]:::data
      RMQ[/"RabbitMQ 3.12-management<br/>code_submission_queue<br/>analysis_approved_queue<br/>policy: max-length=100k, drop-head"/]:::data
      QD[("Qdrant<br/>SECURITY_GUIDELINES_COLLECTION<br/>CWE_COLLECTION_NAME<br/>per-framework payload metadata")]:::data
      Volumes[("Named volumes<br/>postgres_data · rabbitmq_data<br/>qdrant_data · loki-data · grafana-data")]:::data
    end

    %% ===== Observability tier =====
    subgraph ObsTier["Observability Tier"]
      Fluentd["Fluentd v1.18<br/>tcp/udp 24224<br/>2 GB file buffer · drop-oldest"]:::obs
      Loki["Grafana Loki 3.4.2<br/>boltdb-shipper<br/>retention LOKI_RETENTION_DAYS"]:::obs
      Graf["Grafana 11.5.2<br/>provisioned datasource + alerts"]:::obs
      DiskMon["disk-monitor sidecar<br/>(busybox · uid 65534)"]:::obs
      LF["Langfuse v3 (optional)<br/>postgres · clickhouse · redis<br/>minio · web · worker"]:::obs
    end

    %% ===== External =====
    ANTH{{Anthropic API}}:::ext
    OAI{{OpenAI API}}:::ext
    GG{{Google GenAI}}:::ext
    GIT{{GitHub/GitLab/Bitbucket<br/>HTTPS allowlist}}:::ext
    OSVDB{{OSV.dev DB}}:::ext
    SEMGCLD{{Semgrep Cloud}}:::ext
    OIDC{{OIDC IdP}}:::ext
    SAML{{SAML IdP}}:::ext
    SMTP{{SMTP relay}}:::ext

    %% ===== Wiring =====
    Client -- "HTTPS 443" --> Nginx
    Certbot -. "ACME-01 challenge files" .-> Nginx
    Nginx -- "upstream app:8000<br/>X-Forwarded-For + corr-id" --> Middleware
    Middleware --> Routers
    Routers --> Services
    Services --> Infra
    Routers --> RMCP

    Infra --> Repo
    Repo -- "asyncpg pool" --> PG
    Infra --> Pub
    Pub -. "AMQP 0-9-1 persistent · PUBLISH" .-> RMQ
    Infra --> RAG
    RAG -- "qdrant-client REST :6333" --> QD
    Infra --> LLM
    LLM -- "HTTPS · cache_control" --> ANTH
    LLM -- "HTTPS" --> OAI
    LLM -- "HTTPS" --> GG

    Routers -- "OIDC discovery + JWKS" --> OIDC
    Routers -- "SAML metadata + signed assertion" --> SAML
    Routers -- "git clone (HTTPS only)" --> GIT
    Services -- "SMTP/TLS :587" --> SMTP

    RMQ -. "consume · prefetch=1" .-> Consumer
    Consumer --> WF
    WF -- "checkpoint snapshot per node" --> PG
    WF --> Scanners
    Scanners -- "subprocess · stdin/stdout JSON" --> Agents
    WF --> Agents
    Agents --> Editor
    Agents -- "Pydantic AI structured output" --> LLM
    Scanners -- "OSV DB sync at build" --> OSVDB
    Routers -- "rule_source sync" --> SEMGCLD

    Sched -. "outbox sweep · interval 5 s" .-> RMQ
    Sched -. "retention sweep · daily" .-> PG

    AppTier -- "fluentd log driver<br/>tag docker.app.{{.Name}}" --> Fluentd
    WorkerTier -- "fluentd log driver<br/>tag docker.worker.{{.Name}}" --> Fluentd
    DiskMon -- "JSON lines · 30s" --> Fluentd
    Fluentd -- "HTTP push" --> Loki
    Loki -- "LogQL" --> Graf
    LLM -. "trace · OTel/Langfuse SDK" .-> LF

    %% ===== Classes =====
    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
    classDef obs  fill:#fef3c7,stroke:#b45309,color:#451a03;
    classDef ext  fill:#ffe4e6,stroke:#9f1239,color:#4c0519;
```

---

## Legend

### Middleware stack (executes in this order on each request)

| Component                    | File                                                          | Role                                                                                       |
|------------------------------|---------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `correlation_id middleware`  | `src/app/api/middleware/correlation.py`                       | Mints a UUID per request, binds it via `correlation_id_var` ContextVar for structured logs |
| dynamic CORS middleware      | `src/app/main.py` lifespan + `system_config` cache            | Reads `security.allowed_origins` from `system_configurations` and applies at request time   |
| fastapi-users JWT            | `src/app/api/v1/routers/auth_*.py`                            | `CustomCookieJWTStrategy` (HttpOnly refresh cookie, Bearer access) + a `sse:scan-stream` variant for SSE |
| SSO audit middleware         | `src/app/infrastructure/auth/audit.py`                        | Writes login/MFA outcomes to `auth_audit_events` with `X-Forwarded-For` honoring `TRUSTED_PROXY_CIDRS` |
| Langfuse / OTel              | `src/app/infrastructure/observability/langfuse_client.py`     | Emits spans for every LLM call when `LANGFUSE_ENABLED=true`                                |

### API Routers (route_prefix → file)

| Prefix                                  | File                                          | Highlights                                                                 |
|-----------------------------------------|-----------------------------------------------|----------------------------------------------------------------------------|
| `/auth/login-guard`, `/auth/sso`, `/auth/webauthn` | `auth_login_guard.py`, `sso.py`, `webauthn.py` | OIDC PKCE, SAML 2.0 (python3-saml), WebAuthn passkeys (py_webauthn)        |
| `/scim`                                 | `scim.py`                                     | RFC 7643/7644 — Users + Groups + filter parsing                            |
| `/scans`                                | `projects.py`                                 | Submit, approve, cancel, stream-token, SSE stream, prescan-findings, archive preview |
| `/projects`                             | `projects.py`                                 | List, history, delete                                                      |
| `/chat/sessions`                        | `chat.py`                                     | Create, list, ask, delete, context (RAG-driven)                            |
| `/compliance`                           | `compliance.py`                               | `/stats`, `/frameworks/{name}/controls`                                    |
| `/admin/*`                              | `admin_*.py` (12 files)                       | Full admin console — see diagram 11                                        |
| `/refresh`                              | `auth_*.py`                                   | Refresh-token cookie ↔ access JWT mint                                     |
| `/setup`                                | `setup.py`                                    | First-run wizard (admin user, LLM mode, default LLM config)                |
| MCP server                              | `app/api/mcp/server.py`                       | Exposes scan + chat tools to Claude Code / Cursor; reuses JWT auth         |

### Core services

| Class                       | Path                                                                  | Notes                                                                                              |
|-----------------------------|-----------------------------------------------------------------------|----------------------------------------------------------------------------------------------------|
| `ScanSubmissionService`     | `src/app/core/services/scan/submission.py`                            | Validates upload (≤5000 files, ≤200 MB total, magic-byte block), upserts project, snapshots files, writes `scan_outbox` row inside one transaction |
| `ScanQueryService`          | `src/app/core/services/scan/query.py`                                 | Paginated history + filtering by tenant + group-visible users                                       |
| `ChatService`               | `src/app/core/services/chat_service.py`                               | Session CRUD + redacted message persistence (`mask_secrets()` both ways)                            |
| `ComplianceService`         | `src/app/core/services/compliance_service.py`                         | Per-framework rollup: control_count, findings_matched, score                                       |
| `AdminService`              | `src/app/core/services/admin_service.py`                              | Framework + agent + prompt + SSO provider + tenant CRUD                                            |
| `SystemConfigService`       | (cache in `src/app/core/services/system_config_cache.py`)             | Hot cache + optimistic-version updates; rollback DB row if cache update fails (V02.3.3)             |
| `RAGPreprocessorService`    | `src/app/core/services/rag_preprocessor_service.py`                   | Document → enriched JSON → vectors; `Semaphore(10)`, `MAX_JOB_COST_USD=25`, `MAX_DOC_TEXT_CHARS=8000` |
| `DefaultSeedService`        | `src/app/core/services/default_seed_service.py`                       | Seeds ASVS, Proactive Controls, Cheatsheets, agents, prompt templates                              |

### Infrastructure modules

| Module                                   | Role                                                                                                          |
|------------------------------------------|---------------------------------------------------------------------------------------------------------------|
| `infrastructure/llm_client.py`           | Provider-agnostic call site (Anthropic, OpenAI, Google) using Pydantic AI; Anthropic prompt caching via `cache_control` |
| `infrastructure/llm_client_rate_limiter.py` | Per-provider asyncio token bucket; configured at startup via `initialize_rate_limiters()`                  |
| `infrastructure/rag/embedder.py`         | fastembed `all-MiniLM-L6-v2` — pre-warmed at Docker build (`FASTEMBED_CACHE_PATH=/opt/fastembed-cache`)        |
| `infrastructure/rag/qdrant_store.py`     | Wraps `qdrant-client`; upsert with metadata (`framework`, `control_id`, `section`, `language`)                 |
| `infrastructure/rag/rag_client.py`       | `search_by_framework`, `search_by_control_id`, `get_framework_stats`                                          |
| `infrastructure/messaging/publisher.py`  | `aio_pika.connect_robust`, `DeliveryMode.PERSISTENT`, allowlisted payload keys                                |
| `infrastructure/messaging/outbox_sweeper.py` | Polls `scan_outbox WHERE published_at IS NULL`, publishes, marks `published_at` / `failure_count`            |
| `infrastructure/database/models.py`      | 30+ SQLAlchemy 2.x models (see diagram 13)                                                                    |
| `infrastructure/database/repositories/*` | Per-aggregate repos: `ScanRepository`, `FindingRepository`, `RAGJobRepository`, etc.                          |
| `infrastructure/observability/mask.py`   | Regex-based PII/secret redaction applied to all LLM in/out + log fields                                       |
| `infrastructure/scanners/registry.py`    | Extension → scanner mapping (1 MiB regular cap, 10 MiB minified cap)                                          |
| `infrastructure/scanners/{bandit,semgrep,gitleaks,osv}_runner.py` | Subprocess wrappers (120–180 s timeouts) with Pydantic-validated JSON output           |
| `infrastructure/scanners/staging.py`     | Stages files to a temp dir with deterministic relative paths before scanner invocation                        |
| `infrastructure/workflows/*`             | LangGraph nodes + state types (see diagram 14)                                                                |

### Background sweepers / tasks (asyncio loops)

| Task                       | Cadence  | Purpose                                                                              |
|----------------------------|----------|--------------------------------------------------------------------------------------|
| `outbox_sweeper`           | ~5 s     | Publishes any unpublished `scan_outbox` row → durable RabbitMQ delivery               |
| `findings_source_sweeper`  | ~60 s    | Normalizes legacy `findings.source` values (bandit/semgrep/gitleaks/osv)             |
| `prescan_approval_sweeper` | ~60 s    | Auto-times-out `PENDING_PRESCAN_APPROVAL` scans after 30 min                         |
| `retention_sweeper`        | daily    | Deletes rows where `expires_at <= now()` in `llm_interactions`, `chat_messages`, etc. |
| `semgrep_sync_sweeper`     | hourly   | Pulls rules from Semgrep Cloud per active `SemgrepRuleSource`                        |
| `scan_progress_notifier`   | event-driven | Persists `ScanEvent` rows from LangGraph callbacks → SSE stream                  |

### Data tier

| Store         | Notes                                                                                                                          |
|---------------|--------------------------------------------------------------------------------------------------------------------------------|
| PostgreSQL 16 | `postgresql+asyncpg://`; Alembic migrations under `/alembic/versions/`. Holds business state **and** LangGraph `checkpoints` table |
| RabbitMQ 3.12 | Three named queues; `sccap-bounded-queues` policy enforces `max-length=100000` + `overflow=drop-head`                          |
| Qdrant        | SHA256-pinned, mandatory `QDRANT_API_KEY`, internal-only (no host port)                                                        |
| Volumes       | Persistent Docker named volumes — see diagram 12                                                                               |

### Observability tier (full detail in diagram 10)

| Service        | Role                                                                                                         |
|----------------|--------------------------------------------------------------------------------------------------------------|
| Fluentd        | Docker `fluentd` log driver target; ships to Loki; protects itself with file buffer + drop-oldest             |
| Loki           | Log store with retention compactor (`LOKI_RETENTION_DAYS`)                                                   |
| Grafana        | Dashboards + provisioned alerts (`sccap-host-disk-warn/crit`, `sccap-fluentd-buffer-overflow`)               |
| disk-monitor   | 30-second emitter of `df` output to Fluentd                                                                  |
| Langfuse v3    | Optional self-hosted LLM observability (Postgres + ClickHouse + Redis + MinIO + web + worker)                |

### Worker tier (full detail in diagram 14)

The worker runs the same Python package but a different entrypoint: `python -m app.workers.consumer`. It consumes a RabbitMQ message, looks up the scan row, then drives a LangGraph `StateGraph` whose 13 nodes do **prescan → cost gate → analyze → correlate → consolidate → verify → persist**. Each LLM call goes back through the same `LLMClient` used by the app tier so cost math, rate limits and prompt caching are unified.

---

## Source files

- `src/app/main.py`
- `src/app/api/v1/routers/` (all routers)
- `src/app/core/services/` (all services)
- `src/app/infrastructure/` (all subpackages)
- `src/app/workers/consumer.py`
- `src/app/infrastructure/workflows/`
- `docker-compose.yml`, `Dockerfile`
