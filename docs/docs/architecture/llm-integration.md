---
title: LLM Integration
sidebar_position: 6
---

# LLM Integration

SCCAP talks to LLMs through a provider-agnostic layer built on
LangChain 1.x chat models, LiteLLM for token / cost math, and
Pydantic AI for structured output validation. Provider credentials
live in the database; everything else is stateless.

## The `LLMConfiguration` row

Admins register each model they want to use under
**Admin → LLM Configurations**. Schema:

| Column | Notes |
| ------ | ----- |
| `name` | Human-readable label shown in the submit UI. |
| `provider` | `openai` / `anthropic` / `google` / `deepseek` / `xai` (lowercase). |
| `model_name` | Provider-native model id, e.g. `gpt-4o`, `claude-sonnet-4-5`, `gemini-2.5-flash`. |
| `tokenizer` | Optional override for LiteLLM's tokenizer selection. |
| `encrypted_api_key` | Fernet-encrypted at rest using `ENCRYPTION_KEY`. |
| `input_cost_per_million` | Optional override (USD). Zero ⇒ use LiteLLM. |
| `output_cost_per_million` | Optional override (USD). Zero ⇒ use LiteLLM. |

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
| Remediation merge agent | reasoning |
| Per-file profiler | utility |
| Fix-snippet verification | utility |

`resolve_llm_config_id(step, state)` picks the config; utility-slot
steps fall back to the reasoning config when the utility slot is
unset, so legacy scans keep working.

## Per-stage temperature

Each scan also carries a per-stage **temperature** map, chosen at
submit time and stored as `Scan.stage_temperatures` — four knobs
(`profiler` / `analysis` / `consolidation` / `merge`), each defaulting
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

`estimate_cost_for_prompt(input_tokens, config,
predicted_output_ratio=0.25)` predicts a 25%-of-input response
(overridable per call) and prices it:

1. Compute the input + predicted-output token counts.
2. If the `LLMConfiguration` row has **non-zero** override values,
   use them (`(tokens / 1e6) * cost_per_million`).
3. Otherwise call `litellm.cost_per_token(model, prompt_tokens, ...)`
   against the bundled price map (offline-pinnable via
   `LITELLM_LOCAL_MODEL_COST_MAP=True`).

The result is persisted as `scan.cost_details` before the scan pauses
at `PENDING_COST_APPROVAL`.

Two cost gates run per scan: `estimate_profiling_cost` prices the
per-file profiling pass on the **utility** slot
(`PENDING_PROFILING_APPROVAL`), and `estimate_cost` prices the deep
analysis on the **reasoning** slot. The analysis estimate counts
tokens only against each file's routed agent set (the per-language
baseline floor unioned with the profile's applicable domains), so it
reflects the agents the file will actually be analysed by rather than
a worst-case full roster. `estimate_cost_two_slot` sums usage across
both slots at each config's own price.

## Post-call actuals

After each LLM call, the backend reads the standardized
`response.usage_metadata` (LangChain 1.x normalizes it across
providers) and calls `calculate_actual_cost(config, prompt_tokens,
completion_tokens)` with the **same** override-first, LiteLLM-fallback
pattern. Exact cost + token counts are persisted on the
`llm_interactions` row.

This makes the per-scan cost auditable from Admin → LLM Interactions
and feeds the Dashboard "monthly spend" tile
(`dashboard_service.get_stats → _scan_activity → cost stmt`).

## LangChain integration

`src/app/infrastructure/llm_client.py`:

- `get_llm_client(llm_config_id, temperature=…)` returns a
  provider-specific LangChain chat model — `ChatOpenAI`,
  `ChatAnthropic`, or `ChatGoogleGenerativeAI` — hydrated with the
  decrypted API key and the resolved per-stage temperature.
- `generate_structured_output(prompt, ResponseModel)` runs the call
  through **Pydantic AI** so malformed outputs trigger an in-call
  retry loop with a typed error message.
- `TokenUsageCallbackHandler` collects `usage_metadata` for every
  call and persists it along with the raw + parsed response as a
  single `llm_interactions` row.

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
