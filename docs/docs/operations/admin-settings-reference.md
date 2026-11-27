# Admin settings reference

Every value that can be changed from **Admin → System Config**, what it does, the
values it accepts, and when a change takes effect.

Resolution order is **database row → `.env` → the field default**, and every value is
clamped to the range below. A fresh install seeds each setting at its maximum so
nothing is throttled out of the box; lower them for the provider plan you actually
pay for. Secrets and deployment coordinates (database/broker hosts, credentials,
S3/KMS keys) are deliberately **not** here: they belong in `.env` on the host.

> This page is generated from `app/shared/lib/settings_catalog.py` — the same table
> the admin UI renders and the write path validates against. Run
> `python3 scripts/generate-settings-docs.py` after changing it.

## Throughput

How many model calls and scanner processes this platform runs at once. Always check these against your provider's requests- and tokens-per-minute: a limit above what the provider allows only moves the queue into the rate limiter.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Consolidation — concurrent model calls | `system.concurrency.consolidation_limit` | 1 … 100 | In-flight consolidation calls. These carry whole file contents (up to ~19k prompt tokens) and can take minutes each. | next scan |
| Cross-file validation — concurrent model calls | `system.concurrency.validation_limit` | 1 … 50 | In-flight cross-file validation calls, when that gate is enabled. | next scan |
| File profiling — concurrent model calls | `system.concurrency.profiler_limit` | 1 … 500 | In-flight profiling calls. Profiling runs one small call per file and is the slowest stage on a large repository. | next scan |
| SAST scanners — concurrent processes | `system.concurrency.scanner_limit` | 1 … 50 | Scanner subprocesses running at once during the pre-LLM pass. CPU bound: keep it at or below the number of cores. | next scan |
| Security agents — concurrent model calls | `system.concurrency.llm_limit` | 1 … 500 | In-flight model calls per reasoning lane during analysis. Each file's agents share this pool. Raise it with the provider limits, not above them. | next scan |

## Worker capacity

How much work one worker container takes on. Applied when the worker starts.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Drain timeout (seconds) | `system.worker.drain_timeout_seconds` | 1 … 570 | On shutdown, how long the worker keeps finishing in-flight work before it stops accepting new deliveries. | worker restart |
| Pre-LLM pipelines at once per worker | `system.worker.submission_slots` | 1 … 16 | Retrieval + prescan concurrency. These are the memory-hungry stages (repository map, staged source tree, scanner subprocesses). | worker restart |
| Queue messages held in flight | `system.worker.prefetch_count` | 1 … 20 | Broker prefetch per worker. Higher hides latency, lower is fairer. | worker restart |
| Report handoff wait (seconds) | `system.worker.report_handoff_timeout_seconds` | 1 … 60 | How long the analysis pool waits for the report pool to pick up a handoff before retrying the delivery. | worker restart |
| Scans analysed at once per worker | `system.worker.analysis_slots` | 1 … 32 | Each slot keeps a full scan state in memory. Two is comfortable on a 4 GB VM; raising it trades memory for parallelism across scans, not within one. | worker restart |

## Timeouts

How long a single call or a whole scan may take before it is abandoned.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Single model request timeout (seconds) | `system.llm.request_timeout_seconds` | 10 … 3600 s | One provider call may not exceed this. Without it a stalled response blocked the scan until the whole-scan timeout. | worker restart |
| Whole-scan timeout (seconds) | `system.scan.workflow_timeout_seconds` | 60 … 172800 s | Hard ceiling for one workflow invocation, including every retry and every human gate. A scan that exceeds it is marked FAILED. | worker restart |

## Sessions and access

Login lifetime and request-size limits for the API.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Access token lifetime (seconds) | `system.security.access_token_lifetime_seconds` | 60 … 86400 s | How long an issued access token is accepted. | API restart |
| Allow insecure cookies | `system.security.allow_insecure_cookies` | true / false | Only for plain-HTTP development. In production a session cookie without the Secure flag can be replayed over an intercepted connection. | API restart |
| Login request body limit (bytes) | `system.security.login_body_max_bytes` | 1024 … 1048576 bytes | Largest accepted body on the login endpoint. | API restart |
| Refresh token lifetime (seconds) | `system.security.refresh_token_lifetime_seconds` | 300 … 2592000 s | How long a session can be renewed without logging in again. | API restart |
| Session absolute lifetime (seconds) | `system.security.session_absolute_lifetime_seconds` | 300 … 604800 s | Ceiling on a session's total age, regardless of activity. | API restart |
| Session idle timeout (seconds) | `system.security.session_idle_lifetime_seconds` | 60 … 86400 s | A session unused for this long is expired. | API restart |
| Session touch interval (seconds) | `system.security.session_touch_interval_seconds` | 30 … 900 s | How often an active session's last-seen timestamp is written, to avoid a database write per request. | API restart |

## Evidence

Encrypted evidence retention and storage behaviour.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Also write legacy artifacts | `system.evidence.dual_write_legacy` | true / false | Keep writing the legacy artifact copies alongside evidence objects. | worker restart |
| Evidence retention (days) | `system.evidence.retention_days` | 1 … 3650 days | How long evidence objects are kept before the retention pass removes them. | worker restart |
| Evidence store enabled | `system.evidence.enabled` | true / false | Persist encrypted scanner/LLM evidence objects. Turning it off keeps new scans out of the store; existing evidence rows are untouched. | worker restart |

## Observability

Tracing exports and request logging detail.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Langfuse tracing | `system.observability.langfuse_enabled` | true / false | Send per-LLM-call traces to Langfuse. Requires its keys in .env. | API restart |
| Metric export interval (ms) | `system.observability.otel_metric_interval_millis` | 5000 … 300000 ms | How often metrics are pushed to the collector. | API restart |
| OpenTelemetry export | `system.observability.otel_enabled` | true / false | Export traces/metrics to the configured OTLP endpoint. | API restart |
| Slow request threshold (ms) | `system.observability.slow_request_ms` | 50 … 60000 ms | Requests slower than this are logged at WARNING and surfaced in the logs dashboard. | API restart |

## Pentest

Assessment behaviour for the pentest engine.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Automatically chain findings | `system.pentest.auto_chain` | true / false | Let the engine extend a finding into a follow-up step without asking. | worker restart |
| Severity ceiling for unmapped CWEs | `system.pentest.unknown_cwe_ceiling` | `info`, `low`, `medium`, `high`, `critical` | Severity assigned when a finding's CWE has no mapping in the catalog. | worker restart |
| Transcript compaction threshold (tokens) | `system.pentest.transcript_compact_tokens` | 4000 … 2000000 tokens | Older transcript turns are summarised once the run's transcript exceeds this. | worker restart |
| Transcript turns kept verbatim | `system.pentest.transcript_keep_turns` | 2 … 100 | Most recent transcript entries always kept unsummarised. | worker restart |

## Editor-only fields

These are edited on their own card rather than as a number in a section, and are
listed here so nothing the admin UI can change is undocumented.

| Setting | Key | Values | Effect | Takes effect |
|---|---|---|---|---|
| Application log level | `system.log_level` — `{"level": "INFO"}` | DEBUG / INFO / WARNING / ERROR / CRITICAL | Minimum level written to the process log. Warnings and errors are always kept. | immediately |
| LLM optimisation mode | `llm.optimization_mode` — `{"mode": …}` | `multi_provider`, `anthropic_optimized` | Prompt-cache strategy. Anthropic-optimised reorders the prompt for cache hits; changing it invalidates caches on the next scan. | next scan |
| Allowed CORS origins | `security.allowed_origins` | One origin per entry, scheme + host (+ port) | Extra origins allowed to call the API from a browser. The UI origin is always allowed. | immediately |
| Session lifetime | `security.session_lifetime_hours` — `{"hours": 24}` | 1 … 168 hours | Absolute session lifetime enforced at login. | immediately |
| Retention windows | `system.retention.llm_interaction_days`, `…chat_message_days`, `…rag_job_days` | 1 … 3650 days | How long LLM interaction, chat and RAG rows are kept before the retention sweep. | immediately |
| Feature flags | `features.<name>` | true / false | Enable or disable a gated capability (scan, pentest, chat, sso, scim, …). | immediately |
| Setup wizard state | `setup.*` | managed by the wizard | Whether first-run configuration is complete. Changing it re-opens the wizard. | immediately |

## Not configurable, by design

- **Credentials** — `SECRET_KEY`, `ENCRYPTION_KEY`, provider API keys, SMTP and
  S3/KMS secrets, VAPID keys. A web session must never be able to read or rotate a
  secret that is only stored in `.env`.
- **Deployment coordinates** — database/broker/Qdrant hosts and ports, queue names,
  bind paths, evidence bucket and endpoints, `ENVIRONMENT`. Changing these from the
  UI can move the process somewhere it cannot come back from.
