# AGENTS.md — Pi project guide for SCCAP

Use this file as the Pi-first project context. Keep it concise; load deeper docs on demand.

## Project identity

Secure Coding Compliance Automation Platform (SCCAP): FastAPI backend, async SQLAlchemy/Postgres, RabbitMQ worker, LangGraph workflow, LiteLLM/Pydantic AI, Qdrant RAG, React/Vite/Ant Design frontend.

## Critical workflow rule

Backend/worker commands should run inside Docker. The backend `.env` uses service hostnames like `db`, `rabbitmq`, and `qdrant` that resolve inside compose networking.

Common commands:

```bash
docker compose up -d --build
docker compose logs -f app worker
docker compose exec app alembic upgrade head
docker compose exec app pytest
npm --prefix secure-code-ui run build
npm --prefix secure-code-ui run lint
```

## Docs to read before changing code

- Scan lifecycle / graph changes: `.agent/scanning_flow.md`
- File/module ownership: `.agent/project_structure.md`
- Architecture/doc index: `.agent/architecture_index.md`
- Operational/security notes: `.agent/devsecops_playbook.md`
- Current implementation guidance: `CLAUDE.md` remains the long-form source of project conventions.

## Scan workflow guardrails

- Submission path uses DB outbox; API should not publish scan messages inline.
- Worker resumes LangGraph threads through queues and checkpointer where applicable.
- Prescan approval and cost approval are two separate gates.
- Status strings live in `src/app/shared/lib/scan_status.py`.
- Queue names live in `src/app/config/config.py`.
- Any node/edge/status/event changes must update `.agent/scanning_flow.md`.

## Security and tenancy guardrails

- New list endpoints must use visibility scope (`get_visible_user_ids`) and pass it through service/repository layers.
- Do not store secrets plaintext. LLM/API/SMTP secrets are encrypted before DB persistence.
- Preserve audit logs (`scan_events`, `llm_interactions`) unless the task explicitly says otherwise.
- Log via `logging.getLogger(__name__)`; correlation IDs are attached by middleware/context.

## Preferred Pi workflow

- Use `/architecture-map <area>` before large changes.
- Use `/sccap-issue <issue-number>` for GitHub issue implementation.
- Use `/scan-flow-change <description>` for LangGraph/status/event changes.
- Use `/doc-sync <change-summary>` after graph/API/status/doc-impacting work.
- Installed global skills commonly used here: `/skill:grill-me`, `/skill:to-prd`, `/skill:to-issues`.
