---
title: LLM Integration
sidebar_position: 6
---

# LLM Integration

SCCAP talks to LLMs through a provider-agnostic Pydantic AI layer.
Pydantic AI uses the native OpenAI, Anthropic, and Google SDKs (and
OpenAI-compatible transports for DeepSeek, xAI, and custom endpoints),
validates structured output, and preserves request-level usage metadata.
LiteLLM remains a local preflight token-estimation dependency; it is not
the post-call accounting authority.

## The `LLMConfiguration` row

Admins register each model they want to use under
**Admin → LLM Configurations**. Schema:

| Column | Notes |
| ------ | ----- |
| `name` | Human-readable label shown in the submit UI. |
| `provider` | `openai` / `anthropic` / `google` / `deepseek` / `xai` / `custom_openai` (lowercase). |
| `model_name` | Provider-native model id, e.g. `gpt-4o`, `claude-sonnet-4-5`, `gemini-2.5-flash`. |
| `tokenizer` | Optional override for LiteLLM's tokenizer selection. |
| `encrypted_api_key` | Fernet-encrypted at rest using `ENCRYPTION_KEY`. |
| `input_cost_per_million` | Legacy two-rate fallback used by estimates and simple text-only actuals when no versioned override exists. |
| `output_cost_per_million` | Legacy two-rate fallback; cache-bearing calls fail closed rather than applying this flat rate. |

## Two LLM slots per scan

A scan is configured with **two** `LLMConfiguration` rows — a
**utility** (cheap) slot and a **reasoning** (capable) slot — stored
as `Scan.utility_llm_config_id` and `Scan.reasoning_llm_config_id`.
The same model can sit in both, or they can be split. When the submit
omits the utility slot it defaults to the reasoning config.

Step-to-slot routing is centralised in `shared/lib/llm_slots.py` — no
node hard-codes a config id:

| Step | Slot |
| ---- | ---- |
| Per-file analysis | reasoning |
| Finding consolidation | reasoning |
| Per-file profiler | utility |

Patch planning and syntax verification are deterministic and do not call an LLM.

`resolve_llm_config_id(step, state)` picks the config; utility-slot
steps fall back to the reasoning config when the utility slot is
unset, so legacy scans keep working.

## Optional second reasoning LLM (#93)

A scan may also set `Scan.secondary_reasoning_llm_config_id`. When it
is present, the **analysis** step runs every routed agent on *both*
reasoning LLMs — the `shared/lib/analysis_dispatch.py` planner expands
agents across the two reasoning "lanes" — and the two findings sets
union in `consolidate_findings`. The intent is recall: two models have
uncorrelated blind spots, so a vulnerability one misses the other may
catch. The second LLM is confined to analysis; consolidation and the
profiler stay on the primary slots.

Each reasoning LLM gets its own `asyncio.Semaphore` concurrency pool
(two distinct configs ⇒ two pools, since they are usually different
providers with independent rate limits; the same config in both slots
⇒ one shared pool). `estimate_cost_node` prices the analysis pass on
both configs and the cost-approval gate shows a per-LLM breakdown. If
every secondary-LLM call fails the scan completes single-LLM and
records a `SECONDARY_LLM_DEGRADED` timeline event.

## Temperature

Temperature is per-stage — `Scan.stage_temperatures` holds a
`{profiler, analysis, consolidation, analysis_secondary}` map
chosen at submit time. `resolve_temperature` (and
`resolve_secondary_analysis_temperature` for the second reasoning
LLM's analysis pass) read it. An opt-in `Scan.disable_temperature`
flag makes both return `None` for every stage, so SCCAP sends no
temperature at all and each model uses its own provider default.

## Per-stage temperature

Each scan also carries a per-stage **temperature** map, chosen at
submit time and stored as `Scan.stage_temperatures` — three primary knobs
(`profiler` / `analysis` / `consolidation`), each defaulting
to **0.2**. The submit page keeps the controls read-only behind an
Edit button so they are not changed by accident.

`resolve_temperature(step, state)` (also in `shared/lib/llm_slots.py`)
maps an `LLMStep` to its stage temperature, falling back to 0.2 when
the map or a stage entry is missing or out of range.
`get_llm_client(llm_config_id, temperature=…)` applies it via
`ModelSettings`; reasoner models that reject an explicit temperature
are retried without it (the same fallback path as the tool-choice
retry). Cross-file validation reuses the `consolidation` temperature.

## Token counting

`src/app/shared/lib/cost_estimation.count_tokens(text, config)` is a
thin wrapper around `litellm.token_counter(model=config.model_name,
text=text)`. LiteLLM ships provider-native tokenizers (tiktoken for
OpenAI, Anthropic's official counter, Google's SDK, etc.) with a
tiktoken fallback; we don't maintain per-provider branches.

## Pre-call estimation

Preflight estimation returns an **expected** value and a **conservative upper
bound**. It does not use the old universal 25%-of-input assumption. For each
model configuration and stage, the last 200 provider-reported ledger events
feed a median expected output/request factor and a nearest-rank p90 upper
factor. Fewer than five usable observations selects a named, stage-specific
fallback; the response remains `confidence=low` and lists its assumptions.

Profiling counts the rendered system prompt, domain vocabulary, repository
structure, capped file content, and response schema. Analysis counts the
rendered system/domain instructions, RAG patterns, verified scanner context,
dependency context, line-numbered code, and structured-output schema for every
file × chunk × routed-agent × reasoning-lane request. Request-count factors
include structured-output retries and request-priced provider charges.

Pricing resolves the active effective-dated admin override first, then the
legacy complete two-rate configuration, then LiteLLM's bundled catalog. The
upper bound drives per-scan ceilings and high-value approval classification;
`total_estimated_cost` remains the expected-value compatibility projection.

Two cost gates run per scan: `estimate_profiling_cost` prices the
per-file profiling pass on the **utility** slot
(`PENDING_PROFILING_APPROVAL`), and `estimate_cost` prices the deep
analysis on the **reasoning** slot. Both gates surface expected/upper cost,
confidence, observation count, planned requests, and explicit assumptions in
the approval UI. The analysis estimate counts
tokens only against each file's routed agent set (the per-language
baseline floor unioned with the profile's applicable domains), so it
reflects the agents the file will actually be analysed by rather than
a worst-case full roster. `estimate_cost_two_slot` sums usage across
both slots at each config's own price.

When report generation completes, SCCAP compares the expected and upper-bound
analysis estimate with canonical provider-reported analysis usage. The
actual-token/cost variance and whether it stayed inside the upper bound are
stored under `scan.cost_details.estimate_variance`; those same immutable usage
events become observations for later estimates.

## Post-call usage and actual cost

`LLMClient.generate_structured_output` is the sole production model-call
boundary. Each caller supplies a stable `LLMUsageContext` for its scan,
chat, or RAG operation. After a successful provider response, the client
passes every Pydantic AI `ModelResponse` in the run to the canonical ledger;
structured-output retries therefore remain separate priced requests instead
of being flattened or lost.

The append-only data contract is:

| Table | Purpose |
| --- | --- |
| `llm_usage_events` | One idempotent logical run with operation/stage/agent/config and server-resolved user, tenant, and group attribution. |
| `llm_usage_requests` | One provider response, resolved model/version, provider response id, API flavor/tier/batch/region, normalized usage, bounded raw usage, and immutable price snapshot. |
| `llm_usage_line_items` | Fixed-precision billable category, quantity, unit, rate, modifier, currency, and amount. |
| `llm_price_overrides` | Effective-dated complete override versions managed through `GET/POST /api/v1/admin/llm-configs/{id}/price-overrides`. |

Normalization keeps inclusive totals and disjoint billable categories for
uncached input, cache read/write, reasoning or thought output, audio/image,
tool usage, and provider requests. Unknown model or category prices produce
`cost_status=unknown` and a null cost—not a fabricated zero. Event totals are
`NUMERIC(30,12)` and aggregate only when every request has an exact price in
one currency.

`llm_interactions.usage_event_id` is a compatibility projection for existing
scan/chat APIs. Its token and cost fields come from the immutable event at
write time. RAG job `actual_cost` follows the same projection and remains null
if any document cost is unknown. A queue or graph replay reuses the event and
legacy interaction row through the stable idempotency key.

## Pydantic AI integration

`src/app/infrastructure/llm_client.py`:

- `get_llm_client(llm_config_id, temperature=…)` returns an immutable
  `LLMClient` hydrated with the decrypted API key and resolved stage
  temperature.
- `generate_structured_output(prompt, ResponseModel)` runs the call
  through **Pydantic AI** so malformed outputs trigger an in-call
  retry loop with a typed error message.
- `llm_usage_capture.py` normalizes and prices each provider response
  before `LLMUsageRepository` writes the immutable ledger transaction.
- Ledger persistence failure never replays a successful provider call;
  it is logged as an accounting failure and the compatibility cost stays
  unknown to avoid double billing.

## Rate limiting

`src/app/infrastructure/llm_client_rate_limiter.py` initializes global
RPM / TPM buckets per provider at startup. Defaults are conservative
and easy to bump via system config. The orchestrator respects the
limit through a semaphore keyed on `CONCURRENT_LLM_LIMIT` (default 5)
plus the provider buckets — both have to grant the call for it to
proceed.

## Key rotation

Rotate `ENCRYPTION_KEY`:

1. Export the existing keys through the API (they come back
   encrypted).
2. Generate a new `ENCRYPTION_KEY`, update `.env`, restart the
   stack.
3. Re-enter API keys through the Admin UI. The old values won't
   decrypt against the new key, which is the desired outcome.

## Anthropic optimization mode

The `llm.optimization_mode` system_config value toggles between
`generic` (portable) and `anthropic_optimized` (prompt-caching +
tuned variants). Changing it invalidates Anthropic prompt caches on
the next scan; the admin UI shows a warning when you flip it.
