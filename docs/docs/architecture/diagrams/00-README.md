# SCCAP Architecture Diagrams

**SCCAP — Secure Coding & Compliance Automation Platform**

This directory contains the canonical, end-to-end architecture diagrams for SCCAP. Every functional capability in the platform — from raw source-code ingestion to final compliance report — is covered.

Diagrams are written in [Mermaid](https://mermaid.js.org/) so they render directly in GitHub, GitLab, mkdocs (with `mkdocs-mermaid2-plugin`), and most modern IDEs. Each page also carries a textual legend that names every box, edge, queue, table, stream, and protocol shown.

---

## Diagram Index

| #  | Diagram                                              | Scope                                                                                  |
|----|------------------------------------------------------|----------------------------------------------------------------------------------------|
| 01 | [System Overview (C4 Context)](./01-system-overview.md)              | Top-level black-box view: actors, external systems, SCCAP container boundary           |
| 02 | [Backend Architecture](./02-backend-architecture.md)                 | FastAPI app, LangGraph worker, RabbitMQ, Postgres, Qdrant, RAG, scanners, observability |
| 03 | [Frontend Architecture](./03-frontend-architecture.md)               | React 18 + Vite SPA, routing, state, services, SSE client, theming                     |
| 04 | [Audit Scan Flow](./04-audit-scan-flow.md)                            | End-to-end sequence: upload → prescan → profiling/cost gates → analyze → consolidate → persist |
| 05 | [Remediation Flow](./05-remediation-flow.md)                          | REMEDIATE in-graph patching: fix proposal, per-file merge agent, tree-sitter + Semgrep verification |
| 06 | [Chat Advisor Flow](./06-chat-advisor-flow.md)                        | Session lifecycle, RAG context assembly, LLM turn, masking, retention                  |
| 07 | [Framework Management & Ingestion](./07-framework-management.md)      | Framework CRUD, RAG preprocessing job lifecycle, Qdrant population                     |
| 08 | [Auth, SSO, SCIM, Tenancy](./08-auth-tenancy-sso.md)                  | JWT, OIDC, SAML 2.0, WebAuthn passkeys, SCIM 2.0, multi-tenant scoping                 |
| 09 | [Real-time SSE Streaming](./09-realtime-sse-streaming.md)             | Scan progress event pipeline, stream-token JWT, EventSource client                     |
| 10 | [Observability & Audit](./10-observability-audit.md)                  | Fluentd → Loki → Grafana, Langfuse v3, auth audit, log injection guards                |
| 11 | [Admin Console Operations](./11-admin-console.md)                     | System config, LLM configs, prompts, agents, scanner rules, seed data                  |
| 12 | [Infrastructure & Deployment](./12-infrastructure-deployment.md)      | docker-compose tiers, Nginx + Certbot, secrets, migrations, backups                    |
| 13 | [Data Model](./13-data-model.md)                                       | ER diagram for all 30+ Postgres tables, multi-tenant FKs, retention columns            |
| 14 | [LangGraph Worker State Machine](./14-langgraph-worker.md)            | Node graph, checkpointer, interrupts, resume payloads, queues                          |

---

## Legend Conventions

The same visual vocabulary is reused across all diagrams. Every page repeats the legend it needs, but the master conventions are:

### Shapes

| Shape           | Meaning                                                                                   |
|-----------------|-------------------------------------------------------------------------------------------|
| Rounded rectangle | Process / service / running container                                                   |
| Sharp rectangle | Code module, class, or function                                                           |
| Cylinder        | Data store (Postgres table, Qdrant collection, named Docker volume)                       |
| Parallelogram   | Queue, topic, stream, or event channel (RabbitMQ, SSE, Postgres `LISTEN/NOTIFY`)          |
| Hexagon         | External / third-party system (GitHub, OIDC IdP, SMTP relay, LLM provider API)            |
| Stadium         | Human actor (End User, Admin, Auditor, CI agent)                                          |
| Diamond         | Decision / gate (approval interrupt, policy check)                                        |

### Colors (class definitions reused per diagram)

| Class       | Color theme            | Used for                                                                    |
|-------------|------------------------|-----------------------------------------------------------------------------|
| `edge`      | Slate / cool blue      | Edge tier: Nginx, Certbot, CDN, browser                                     |
| `app`       | Indigo                 | App tier: FastAPI, worker, MCP server                                       |
| `data`      | Emerald                | Data tier: Postgres, RabbitMQ, Qdrant, Docker volumes                       |
| `obs`       | Amber                  | Observability tier: Fluentd, Loki, Grafana, Langfuse, alerting              |
| `ext`       | Rose                   | External systems: LLM providers, Git providers, IdPs, OSV, scanner upstream |
| `actor`     | Plain                  | Human actors / CI bots                                                      |
| `gate`      | Violet (dashed border) | Interrupt / approval gates                                                  |
| `secret`    | Red-tinted             | Secret material (Fernet-encrypted blobs, JWTs, OAuth tokens)                |

### Edge labels

- **Solid arrow** with label → synchronous call (HTTP, gRPC, function call)
- **Dashed arrow** → asynchronous event, message publish, fire-and-forget
- **Double arrow** → bidirectional channel (e.g., SSE keepalive, WebSocket)
- Arrow labels include the **wire protocol** (HTTPS, AMQP 0-9-1, SSE, AMQP-TLS) and the **payload kind** (JSON, JSONB, multipart, CycloneDX 1.5, HTML/CSV/PDF report, etc.)

### Glossary (terms used throughout)

| Term                     | Meaning                                                                                                          |
|--------------------------|------------------------------------------------------------------------------------------------------------------|
| **ASVS**                 | OWASP Application Security Verification Standard (5.0) — primary control catalog used by SCCAP                   |
| **LangGraph**            | Stateful agent orchestration framework (state graph + `AsyncPostgresSaver` checkpointer) used by the worker       |
| **AsyncPostgresSaver**   | LangGraph checkpointer that persists `WorkerState` snapshots into the `checkpoints` Postgres table                |
| **WorkerState**          | Typed Pydantic dict carried node-to-node through the scan workflow (files, findings, fixes, BOM, etc.)            |
| **Prescan**              | Deterministic SAST gate (Bandit, Semgrep, Gitleaks, OSV-Scanner) that runs before any LLM tokens are spent        |
| **Cost gate**            | LLM-cost approval interrupt; users see a $-estimate before agents are dispatched                                  |
| **Pydantic AI**          | Provider-agnostic structured-output layer (Anthropic, OpenAI, Google) with validation-with-retry                  |
| **LiteLLM cost map**     | Bundled JSON of model pricing (`LITELLM_LOCAL_MODEL_COST_MAP=true`) used offline for cost math                    |
| **Qdrant**               | Vector database (SHA-pinned `qdrant/qdrant`) backing all framework / CWE RAG retrieval                            |
| **fastembed**            | ONNX-based embedding library; SCCAP uses `sentence-transformers/all-MiniLM-L6-v2` (384-dim) pre-warmed at build  |
| **CycloneDX 1.5**        | SBOM format emitted by OSV-Scanner; stored in `Scan.bom_cyclonedx` JSONB                                          |
| **Merge agent** | The reasoning-LLM call (`_run_merge_agent`) that unifies overlapping per-file fix suggestions during `consolidate_and_patch` |
| **SSE**                  | Server-Sent Events; one-way stream from FastAPI to browser for scan progress                                      |
| **Stream-token JWT**     | Short-TTL (60 s) JWT bound to a scan_id, audience `sse:scan-stream`, used in the SSE URL fragment                 |
| **Transactional outbox** | `scan_outbox` table holding messages that *will* be published to RabbitMQ; swept by a background task            |
| **JIT provisioning**     | Just-in-time user creation on first SSO assertion when email is in `allowed_email_domains`                       |
| **Fernet**               | Symmetric AEAD scheme used to encrypt LLM API keys, SSO secrets, SMTP password at rest in Postgres                |
| **Langfuse v3**          | Optional self-hosted LLM observability stack (Postgres + ClickHouse + Redis + MinIO + web + worker)               |
| **MCP**                  | Model Context Protocol — `app/api/mcp/server.py` exposes scan + chat tools to external Claude Code / Cursor      |

---

## How to update these diagrams

1. Edit the relevant `.md` file in place.
2. Validate Mermaid syntax locally with `npx -y @mermaid-js/mermaid-cli@10 -i file.md -o /tmp/out.svg` or use the [Mermaid Live Editor](https://mermaid.live).
3. Re-run `mkdocs build` (from `/docs`) if you have `mkdocs-mermaid2-plugin` installed; otherwise GitHub will render natively.
4. Keep names consistent with the source of truth listed in each page's "Source files" footer.

---

## Source of truth

These diagrams were generated from a static analysis of the codebase as of **2026-05**. If a name, route, table, or queue is wrong, the source code wins — please open an issue and update the diagram in the same PR.
