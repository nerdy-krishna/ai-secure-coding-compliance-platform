# 01 — System Overview (C4 Context)

Top-level black-box view of SCCAP. Shows every actor that talks to the system, every external service the platform depends on, and the high-level capabilities exposed across the SCCAP container boundary.

---

## Diagram

```mermaid
flowchart LR
    %% =========================
    %% Human actors
    %% =========================
    Dev([End User / Developer]):::actor
    Admin([Tenant Admin / Superuser]):::actor
    Auditor([Compliance Auditor]):::actor
    CIBot([CI/CD Agent<br/>GitHub Actions / GitLab CI]):::actor

    %% =========================
    %% SCCAP platform boundary
    %% =========================
    subgraph SCCAP["SCCAP Platform (Docker Compose, single host)"]
      direction TB

      Edge["Nginx + Certbot<br/>(TLSv1.2/1.3, Let's Encrypt,<br/>rate-limited 30 r/s API · 120 r/s SPA)"]:::edge
      UI["React 18 + Vite SPA<br/>(secure-code-ui / nginx:alpine)"]:::edge
      API["FastAPI 0.115 / Uvicorn<br/>sccap_app · /api/v1/*"]:::app
      MCP["MCP Server<br/>app/api/mcp/server.py<br/>(tools for Claude Code / Cursor)"]:::app
      Worker["LangGraph Worker<br/>sccap_worker · aio-pika consumer"]:::app
      RMQ[/"RabbitMQ 3.12 · AMQP 0-9-1<br/>code_submission_queue<br/>analysis_approved_queue"/]:::data
      PG[("PostgreSQL 16<br/>30+ domain tables<br/>+ LangGraph checkpoints<br/>+ scan_outbox")]:::data
      QD[("Qdrant Vector DB<br/>SHA-pinned<br/>SECURITY_GUIDELINES<br/>CWE_COLLECTION")]:::data
      FB["fastembed (ONNX)<br/>all-MiniLM-L6-v2 · 384-dim"]:::app
      Obs["Observability<br/>Fluentd → Loki → Grafana<br/>+ optional Langfuse v3"]:::obs
    end

    %% =========================
    %% External systems
    %% =========================
    Anthropic{{Anthropic API<br/>Claude Opus 4.7 / Sonnet 4.6 / Haiku 4.5}}:::ext
    OpenAI{{OpenAI API}}:::ext
    Google{{Google GenAI · Gemini}}:::ext
    DeepSeek{{DeepSeek API}}:::ext
    XAI{{xAI Grok API}}:::ext
    OIDC{{OIDC IdP<br/>Okta / Auth0 / Entra ID / Google}}:::ext
    SAML{{SAML 2.0 IdP<br/>ADFS / Okta / PingFederate}}:::ext
    SMTP{{SMTP Relay<br/>SendGrid / SES / Mailgun}}:::ext
    Git{{Git Providers<br/>github.com · gitlab.com · bitbucket.org}}:::ext
    OSVDB{{OSV.dev<br/>vulnerability database}}:::ext
    Semgrep{{Semgrep Cloud<br/>rule sources}}:::ext
    LE{{Let's Encrypt<br/>ACME v2}}:::ext
    SCIMClient{{SCIM 2.0 Client<br/>Okta / OneLogin}}:::ext

    %% =========================
    %% Human → SCCAP edges
    %% =========================
    Dev -- "HTTPS · SPA · cookies (refresh) + Bearer JWT (access)" --> Edge
    Admin -- "HTTPS · admin console" --> Edge
    Auditor -- "HTTPS · /compliance, /admin/sso/audit" --> Edge
    CIBot -- "HTTPS · POST /api/v1/scans, POST /api/v1/scans/{id}/approve" --> Edge
    SCIMClient -- "HTTPS · /api/v1/scim · Bearer SCIM token" --> Edge

    %% =========================
    %% Internal edges
    %% =========================
    Edge -- "reverse proxy<br/>upstream app:8000" --> UI
    Edge -- "/api/v1/* → app:8000" --> API
    UI -- "axios · /api/v1/*<br/>SSE /scans/{id}/stream" --> API
    API -- "MCP over stdio/HTTP" --> MCP
    API -. "transactional publish<br/>scan_outbox sweeper" .-> RMQ
    RMQ -. "consume<br/>aio_pika robust" .-> Worker
    API -- "asyncpg + SQLAlchemy 2.x" --> PG
    Worker -- "asyncpg + SQLAlchemy 2.x" --> PG
    API -- "qdrant-client REST" --> QD
    Worker -- "qdrant-client REST" --> QD
    Worker -- "embed()" --> FB
    API -- "embed()" --> FB

    %% =========================
    %% SCCAP → External
    %% =========================
    API -- "HTTPS · OIDC discovery + token" --> OIDC
    API -- "HTTPS · SAML metadata + ACS" --> SAML
    API -- "SMTP TLS · 587" --> SMTP
    API -- "HTTPS · clone (HTTPS allowlist)" --> Git
    Worker -- "HTTPS · OSV-Scanner DB sync" --> OSVDB
    Worker -- "HTTPS · Pydantic AI · Anthropic SDK" --> Anthropic
    Worker -- "HTTPS · Pydantic AI · OpenAI SDK" --> OpenAI
    Worker -- "HTTPS · Pydantic AI · google-genai" --> Google
    Worker -- "HTTPS · Pydantic AI" --> DeepSeek
    Worker -- "HTTPS · Pydantic AI" --> XAI
    API -- "HTTPS · rule pull" --> Semgrep
    Edge -- "ACME challenge · /var/www/certbot" --> LE
    API -.-> Obs
    Worker -.-> Obs

    %% =========================
    %% Class styling
    %% =========================
    classDef actor fill:#fafafa,stroke:#475569,color:#0f172a,stroke-width:1px;
    classDef edge  fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app   fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data  fill:#dcfce7,stroke:#15803d,color:#052e16;
    classDef obs   fill:#fef3c7,stroke:#b45309,color:#451a03;
    classDef ext   fill:#ffe4e6,stroke:#9f1239,color:#4c0519;
```

---

## Legend

### Actors

| Actor                | Authentication                    | Primary surface                                                 |
|----------------------|-----------------------------------|------------------------------------------------------------------|
| End User / Developer | Email+password, OIDC, SAML, Passkey | Submit scans, view findings, chat with advisor, download SARIF   |
| Tenant Admin         | Same + `is_superuser=true`        | Admin console: users, frameworks, agents, prompts, system config |
| Compliance Auditor   | Read-only (group-scoped)          | `/compliance`, control coverage, SSO audit log                   |
| CI/CD Agent          | Service-account JWT or API key    | Headless scan submission and result polling                      |
| SCIM 2.0 Client      | Bearer SCIM token                 | Automated user/group provisioning (`/api/v1/scim`)               |

### SCCAP boundary

| Box                   | Container name        | Image / source                                       | Listens on        |
|-----------------------|-----------------------|------------------------------------------------------|-------------------|
| Nginx + Certbot       | `sccap_ui`            | `secure-code-ui/Dockerfile` (`builder` → `nginx:alpine`) | 80, 443           |
| React SPA             | (served by `sccap_ui`) | Vite 6.3 build → `/dist`                            | n/a (static)      |
| FastAPI app           | `sccap_app`           | `Dockerfile` target `api`                            | 8000 (internal)   |
| MCP Server            | mounted inside `sccap_app` | `src/app/api/mcp/server.py`                     | shares 8000       |
| LangGraph Worker      | `sccap_worker`        | `Dockerfile` target `worker`                         | none (consumer)   |
| RabbitMQ              | `sccap_rabbitmq`      | `rabbitmq:3.12-management`                           | 5672 AMQP, 15672 mgmt |
| PostgreSQL            | `sccap_db`            | `postgres:16`                                        | 5432              |
| Qdrant                | `sccap_qdrant`        | `qdrant/qdrant@sha256:9472…`                         | 6333 (internal)   |
| fastembed (in-proc)   | bundled in app+worker | `sentence-transformers/all-MiniLM-L6-v2` (ONNX)      | n/a (library)     |
| Observability         | `sccap_fluentd`, `sccap_loki`, `sccap_grafana`, optional `langfuse-*` | see diagram 10 | 24224, 3100, 3000, 3001 |

### External systems

| External           | Protocol          | Purpose                                                                 |
|--------------------|-------------------|-------------------------------------------------------------------------|
| Anthropic API      | HTTPS · Pydantic AI · Anthropic SDK | Claude Opus/Sonnet/Haiku for analysis & chat agents      |
| OpenAI API         | HTTPS · OpenAI SDK              | Alternative analysis / chat provider                                     |
| Google GenAI       | HTTPS · `google-genai`          | Alternative analysis / chat provider (Gemini)                            |
| DeepSeek API       | HTTPS · Pydantic AI             | Alternative analysis / chat provider                                     |
| xAI Grok API       | HTTPS · Pydantic AI             | Alternative analysis / chat provider                                     |
| OIDC IdP           | HTTPS · OIDC 1.0 + PKCE         | SSO login (Okta, Auth0, Entra ID, Google Workspace, …)                  |
| SAML 2.0 IdP       | HTTPS · SAML 2.0                | SSO login via `python3-saml`                                             |
| SMTP relay         | SMTP/STARTTLS · 587             | Password-reset, scan-completion, approval-reminder emails                |
| Git providers      | HTTPS · `git clone`             | Repo ingest (github.com, gitlab.com, bitbucket.org allowlist)            |
| OSV.dev            | HTTPS                           | Dependency vulnerability database used by OSV-Scanner                    |
| Semgrep Cloud      | HTTPS                           | Cloud-hosted rule sources sync'd into `semgrep_rules` table              |
| Let's Encrypt      | ACME v2 over HTTPS              | TLS cert provisioning + auto-renewal via Certbot                         |
| SCIM 2.0 client    | HTTPS · RFC 7644                | User/group provisioning from external IAM                                |

### Edge labels of note

- **`HTTPS · SPA · cookies (refresh) + Bearer JWT (access)`** — access tokens live in `localStorage` (V15.1.5 risk-accepted); refresh tokens are HttpOnly+Secure cookies set by `/auth/refresh`.
- **`transactional publish · scan_outbox sweeper`** — the API never publishes directly to RabbitMQ; it writes a row to `scan_outbox`, then `outbox_sweeper.py` publishes durably and marks the row sent.
- **`consume · aio_pika robust`** — the worker uses `aio_pika.connect_robust` with exponential backoff and a duplicate-delivery idempotency precheck against `scans.status`.
- **`MCP over stdio/HTTP`** — the same FastAPI process mounts an MCP server so external Claude Code or Cursor sessions can hit scan/chat tools with the user's JWT.

---

## Source files

- `docker-compose.yml`
- `src/app/main.py`
- `src/app/api/v1/routers/*` (every router)
- `src/app/workers/consumer.py`
- `src/app/infrastructure/messaging/{publisher,outbox_sweeper}.py`
- `secure-code-ui/Dockerfile`, `nginx-https.conf`, `nginx-entrypoint.sh`
- `.env.example`
