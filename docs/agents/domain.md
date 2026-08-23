# Domain documentation

SCCAP uses a single-context domain-document layout spanning its backend, worker, scan workflow,
and frontend.

## Read before exploring or changing the application

- `CONTEXT.md` at the repository root, when present, for the shared domain glossary.
- Applicable architectural decisions under `docs/adr/`.
- `.agent/architecture_index.md`, `.agent/project_structure.md`, and the operational documents
  linked from them.
- `.agent/scanning_flow.md` before changing scan nodes, edges, statuses, events, approvals,
  messaging, or worker behavior.
- `CLAUDE.md` and `AGENTS.md` for current repository and security guardrails.

If `CONTEXT.md` or `docs/adr/` does not yet exist, proceed using the existing project vocabulary
and create or update those documents only when a domain term or architectural decision is
actually resolved.

## Consistency rules

- Use the scan-lifecycle terminology defined by the application and `scan_status.py`.
- Treat implementation, migrations, and verified behavior as authoritative when older planning
  documents disagree.
- Surface conflicts with an existing ADR instead of silently overriding it.
- Update operational documentation in the same change whenever behavior, status, event, route,
  or workflow semantics change.
