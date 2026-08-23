---
sidebar_position: 4
title: Adding New Agents
---

# Adding New Agents

Agents in SCCAP are small, single-purpose LLM wrappers. The most
common shape is a specialized agent that looks for a specific kind
of finding (SQL injection, SSRF, hardcoded secret, etc.) in a
chunk of code. This page walks through adding one.

Two parallel workflows:

1. **DB-driven** (no code): add the agent + prompt template from
   the Admin UI. Runs through the existing
   `generic_specialized_agent` template.
2. **Code-driven**: add a new agent module when the DB-driven path
   can't express your logic (e.g., you need to call a non-LLM tool).

## DB-driven agent

1. **Prompt template**: go to **Admin → Prompts → New template**.
   Fields:
   - `name` — e.g. `sqlimagent`.
   - `type` — the finding type string the orchestrator uses to
     dispatch (`SQL_INJECTION`, `SSRF`, etc.).
   - `template_text` — the prompt body. Use `{{ variable }}`
     placeholders for the runtime context
     (`{{ code_chunk }}`, `{{ repository_map }}`, etc.).
2. **Agent row**: go to **Admin → Agents → New agent** and name it.
3. **Framework mapping**: under **Admin → Frameworks →
   [framework-name] → Agents**, tick the new agent. The orchestrator
   will run it for scans tagged with that framework.
4. **Smoke-test**: submit a small scan against the framework +
   confirm the new agent's output appears in
   `Admin → Scans → LLM Interactions`.

That's it — no deploy needed. The orchestrator reads the agent
mapping on each scan and dispatches dynamically.

## Code-driven agent

When you need logic that can't live in a prompt template
(calling an external tool, merging multiple LLM calls into one
agent output, a non-text input), add a module under
`src/app/infrastructure/agents/`.

Canonical shape:

```python
# src/app/infrastructure/agents/my_agent.py
from app.infrastructure.llm_client import get_llm_client
from pydantic import BaseModel

AGENT_NAME = "my_agent"


class MyAgentResponse(BaseModel):
    finding_type: str
    severity: str
    description: str
    suggested_fix: str | None = None


async def run(code_chunk: str, llm_config_id, *, session_id=None):
    client = await get_llm_client(llm_config_id)
    prompt = build_prompt(code_chunk)
    response = await client.generate_structured_output(
        prompt, MyAgentResponse
    )
    return response
```

Important invariants:

- Every agent call goes through
  `llm_client.generate_structured_output`. That gives you Pydantic
  AI validation retries and consistent logging into
  `llm_interactions` for free.
- Return a validated Pydantic model (or an error string). **Don't**
  return raw text; downstream code treats the result as typed.
- Persist nothing directly; your caller (usually the worker
  orchestrator) owns the DB transaction.

After adding the module:

1. Register the agent in the admin table (same as the DB-driven
   path) so the orchestrator knows about it.
2. Wire it into the orchestrator's dispatch table if the new agent
   is called directly rather than via the `generic_specialized_agent`
   template.
3. Add a focused `unittest` regression under `tests/agents/`. Patch the
   LLM boundary with `AsyncMock`, and assert the typed input/output or routing
   contract rather than snapshotting prompt prose.

## Checklist

- [ ] Prompt template registered in DB.
- [ ] Agent row registered in DB.
- [ ] Framework → agent mapping updated (for every framework the
      agent applies to).
- [ ] Smoke scan run; output appears under Results → Pipeline & Logs → LLM Calls.
- [ ] Unit test added (if code-driven).
- [ ] README / docs updated if the agent introduces a new finding
      category.
