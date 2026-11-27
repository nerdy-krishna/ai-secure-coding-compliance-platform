"""The catalog of settings an administrator can manage from the UI.

One declarative table, used by everything that needs to know about these numbers:

* `runtime_settings` builds its resolution cache from it (DB row -> `.env` ->
  declared default, clamped to the range below);
* the API serves it at `GET /admin/system-config/catalog`, and the admin UI renders
  its sections, labels, help text and bounds - so the UI and the docs cannot drift;
* the write path validates against `kind`/`minimum`/`maximum`/`choices`, so a typo
  cannot set a timeout to zero or a concurrency limit past what the code can run;
* `scripts/generate-settings-docs.py` renders the reference page from it.

What is deliberately *absent*: credentials (`*_PASSWORD`, `SECRET_KEY`,
`ENCRYPTION_KEY`, S3/KMS keys, Langfuse keys) and deployment coordinates (database and
broker hosts, queue names, bind paths, TLS material). Those belong in `.env` on the
host, because changing them from a web session would either expose a secret or move the
process somewhere it cannot come back from.

`applies` is a promise, not decoration:

  "live"           a refresh loop re-points the running subsystem (rate limits)
  "next-scan"      read by the workflow node when it starts
  "worker-restart" applied when the worker container starts
  "app-restart"    applied when the API container starts
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Tuple


@dataclass(frozen=True)
class SettingDescriptor:
    key: str
    section: str
    label: str
    description: str
    kind: str = "int"  # int | bool | enum
    env: str | None = None  # attribute on `settings` this overrides
    unit: str | None = None
    minimum: float | None = None
    maximum: float | None = None
    default: Any = None
    applies: str = "next-scan"
    choices: Tuple[str, ...] = ()
    advanced: bool = field(default=False)


SECTIONS: Tuple[Tuple[str, str], ...] = (
    (
        "Throughput",
        "How many model calls and scanner processes this platform runs at once. Always "
        "check these against your provider's requests- and tokens-per-minute: a limit "
        "above what the provider allows only moves the queue into the rate limiter.",
    ),
    (
        "Worker capacity",
        "How much work one worker container takes on. Applied when the worker starts.",
    ),
    (
        "Timeouts",
        "How long a single call or a whole scan may take before it is abandoned.",
    ),
    (
        "Sessions and access",
        "Login lifetime and request-size limits for the API.",
    ),
    (
        "Evidence",
        "Encrypted evidence retention and storage behaviour.",
    ),
    (
        "Observability",
        "Tracing exports and request logging detail.",
    ),
    (
        "Pentest",
        "Assessment behaviour for the pentest engine.",
    ),
)


def _provider_rows() -> Tuple[SettingDescriptor, ...]:
    providers = (
        ("deepseek", "DeepSeek"),
        ("openai", "OpenAI"),
        ("anthropic", "Anthropic"),
        ("google", "Google"),
        ("xai", "xAI"),
        ("custom_openai", "Custom OpenAI-compatible"),
    )
    rows = []
    for provider, label in providers:
        upper = (
            f"{provider.upper()}" if provider != "custom_openai" else "CUSTOM_OPENAI"
        )
        rows.append(
            SettingDescriptor(
                key=f"system.ratelimit.{provider}.rpm",
                section="Provider rate limits",
                label=f"{label} — requests / minute",
                description=(
                    "Local guard, not a provider requirement. Requests this process may "
                    "send per minute. The worker applies a change within 30 seconds."
                ),
                env=f"{upper}_REQUESTS_PER_MINUTE",
                minimum=1,
                maximum=100_000,
                applies="live",
            )
        )
        rows.append(
            SettingDescriptor(
                key=f"system.ratelimit.{provider}.tpm",
                section="Provider rate limits",
                label=f"{label} — tokens / minute",
                description=(
                    "Local guard on prompt+completion tokens per minute. This is what "
                    "usually bounds a scan's wall clock: 500 files x ~17 calls x ~7.5k "
                    "tokens is ~64M tokens in total."
                ),
                env=f"{upper}_TOKENS_PER_MINUTE",
                minimum=1,
                maximum=10_000_000_000,
                applies="live",
            )
        )
    return tuple(rows)


DESCRIPTORS: Tuple[SettingDescriptor, ...] = (
    # ---- throughput ----------------------------------------------------
    SettingDescriptor(
        key="system.concurrency.llm_limit",
        section="Throughput",
        label="Security agents — concurrent model calls",
        description=(
            "In-flight model calls per reasoning lane during analysis. Each file's "
            "agents share this pool. Raise it with the provider limits, not above them."
        ),
        env="CONCURRENT_LLM_LIMIT",
        minimum=1,
        maximum=500,
        applies="next-scan",
    ),
    SettingDescriptor(
        key="system.concurrency.profiler_limit",
        section="Throughput",
        label="File profiling — concurrent model calls",
        description=(
            "In-flight profiling calls. Profiling runs one small call per file and is "
            "the slowest stage on a large repository."
        ),
        env="CONCURRENT_PROFILER_LIMIT",
        minimum=1,
        maximum=500,
        applies="next-scan",
    ),
    SettingDescriptor(
        key="system.concurrency.scanner_limit",
        section="Throughput",
        label="SAST scanners — concurrent processes",
        description=(
            "Scanner subprocesses running at once during the pre-LLM pass. CPU bound: "
            "keep it at or below the number of cores."
        ),
        env="CONCURRENT_SCANNER_LIMIT",
        minimum=1,
        maximum=50,
        applies="next-scan",
    ),
    SettingDescriptor(
        key="system.concurrency.consolidation_limit",
        section="Throughput",
        label="Consolidation — concurrent model calls",
        description=(
            "In-flight consolidation calls. These carry whole file contents (up to ~19k "
            "prompt tokens) and can take minutes each."
        ),
        env="CONCURRENT_CONSOLIDATION_LIMIT",
        minimum=1,
        maximum=100,
        applies="next-scan",
    ),
    SettingDescriptor(
        key="system.concurrency.validation_limit",
        section="Throughput",
        label="Cross-file validation — concurrent model calls",
        description="In-flight cross-file validation calls, when that gate is enabled.",
        env="CONCURRENT_VALIDATION_LIMIT",
        minimum=1,
        maximum=50,
        applies="next-scan",
    ),
    *_provider_rows(),
    # ---- worker capacity ----------------------------------------------
    SettingDescriptor(
        key="system.worker.analysis_slots",
        section="Worker capacity",
        label="Scans analysed at once per worker",
        description=(
            "Each slot keeps a full scan state in memory. Two is comfortable on a 4 GB "
            "VM; raising it trades memory for parallelism across scans, not within one."
        ),
        env="WORKER_ANALYSIS_SLOTS",
        minimum=1,
        maximum=32,
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.worker.submission_slots",
        section="Worker capacity",
        label="Pre-LLM pipelines at once per worker",
        description=(
            "Retrieval + prescan concurrency. These are the memory-hungry stages "
            "(repository map, staged source tree, scanner subprocesses)."
        ),
        env="WORKER_SUBMISSION_SLOTS",
        minimum=1,
        maximum=16,
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.worker.prefetch_count",
        section="Worker capacity",
        label="Queue messages held in flight",
        description="Broker prefetch per worker. Higher hides latency, lower is fairer.",
        env="WORKER_PREFETCH_COUNT",
        minimum=1,
        maximum=20,
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.worker.drain_timeout_seconds",
        section="Worker capacity",
        label="Drain timeout (seconds)",
        description=(
            "On shutdown, how long the worker keeps finishing in-flight work before it "
            "stops accepting new deliveries."
        ),
        env="WORKER_DRAIN_TIMEOUT_SECONDS",
        minimum=1,
        maximum=570,
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.worker.report_handoff_timeout_seconds",
        section="Worker capacity",
        label="Report handoff wait (seconds)",
        description=(
            "How long the analysis pool waits for the report pool to pick up a handoff "
            "before retrying the delivery."
        ),
        env="REPORT_HANDOFF_READY_TIMEOUT_SECONDS",
        minimum=1,
        maximum=60,
        applies="worker-restart",
        advanced=True,
    ),
    # ---- timeouts ------------------------------------------------------
    SettingDescriptor(
        key="system.scan.workflow_timeout_seconds",
        section="Timeouts",
        label="Whole-scan timeout (seconds)",
        description=(
            "Hard ceiling for one workflow invocation, including every retry and every "
            "human gate. A scan that exceeds it is marked FAILED."
        ),
        env="SCAN_WORKFLOW_TIMEOUT_SECONDS",
        unit="s",
        minimum=60,
        maximum=172_800,
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.llm.request_timeout_seconds",
        section="Timeouts",
        label="Single model request timeout (seconds)",
        description=(
            "One provider call may not exceed this. Without it a stalled response "
            "blocked the scan until the whole-scan timeout."
        ),
        env="LLM_REQUEST_TIMEOUT_SECONDS",
        unit="s",
        minimum=10,
        maximum=3600,
        applies="worker-restart",
    ),
    # ---- sessions ------------------------------------------------------
    SettingDescriptor(
        key="system.security.access_token_lifetime_seconds",
        section="Sessions and access",
        label="Access token lifetime (seconds)",
        description="How long an issued access token is accepted.",
        env="ACCESS_TOKEN_LIFETIME_SECONDS",
        unit="s",
        minimum=60,
        maximum=86_400,
        applies="app-restart",
    ),
    SettingDescriptor(
        key="system.security.refresh_token_lifetime_seconds",
        section="Sessions and access",
        label="Refresh token lifetime (seconds)",
        description="How long a session can be renewed without logging in again.",
        env="REFRESH_TOKEN_LIFETIME_SECONDS",
        unit="s",
        minimum=300,
        maximum=2_592_000,
        applies="app-restart",
    ),
    SettingDescriptor(
        key="system.security.session_absolute_lifetime_seconds",
        section="Sessions and access",
        label="Session absolute lifetime (seconds)",
        description="Ceiling on a session's total age, regardless of activity.",
        env="SESSION_ABSOLUTE_LIFETIME_SECONDS",
        unit="s",
        minimum=300,
        maximum=604_800,
        applies="app-restart",
    ),
    SettingDescriptor(
        key="system.security.session_idle_lifetime_seconds",
        section="Sessions and access",
        label="Session idle timeout (seconds)",
        description="A session unused for this long is expired.",
        env="SESSION_IDLE_LIFETIME_SECONDS",
        unit="s",
        minimum=60,
        maximum=86_400,
        applies="app-restart",
    ),
    SettingDescriptor(
        key="system.security.session_touch_interval_seconds",
        section="Sessions and access",
        label="Session touch interval (seconds)",
        description=(
            "How often an active session's last-seen timestamp is written, to avoid a "
            "database write per request."
        ),
        env="SESSION_TOUCH_INTERVAL_SECONDS",
        unit="s",
        minimum=30,
        maximum=900,
        applies="app-restart",
        advanced=True,
    ),
    SettingDescriptor(
        key="system.security.login_body_max_bytes",
        section="Sessions and access",
        label="Login request body limit (bytes)",
        description="Largest accepted body on the login endpoint.",
        env="LOGIN_BODY_MAX_BYTES",
        unit="bytes",
        minimum=1024,
        maximum=1_048_576,
        applies="app-restart",
        advanced=True,
    ),
    SettingDescriptor(
        key="system.security.allow_insecure_cookies",
        section="Sessions and access",
        label="Allow insecure cookies",
        description=(
            "Only for plain-HTTP development. In production a session cookie without "
            "the Secure flag can be replayed over an intercepted connection."
        ),
        kind="bool",
        env="ALLOW_INSECURE_COOKIES",
        applies="app-restart",
        advanced=True,
    ),
    # ---- evidence ------------------------------------------------------
    SettingDescriptor(
        key="system.evidence.enabled",
        section="Evidence",
        label="Evidence store enabled",
        description=(
            "Persist encrypted scanner/LLM evidence objects. Turning it off keeps new "
            "scans out of the store; existing evidence rows are untouched."
        ),
        kind="bool",
        env="EVIDENCE_STORE_ENABLED",
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.evidence.retention_days",
        section="Evidence",
        label="Evidence retention (days)",
        description="How long evidence objects are kept before the retention pass removes them.",
        env="EVIDENCE_RETENTION_DAYS",
        unit="days",
        minimum=1,
        maximum=3650,
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.evidence.dual_write_legacy",
        section="Evidence",
        label="Also write legacy artifacts",
        description="Keep writing the legacy artifact copies alongside evidence objects.",
        kind="bool",
        env="EVIDENCE_DUAL_WRITE_LEGACY",
        applies="worker-restart",
        advanced=True,
    ),
    # ---- observability -------------------------------------------------
    SettingDescriptor(
        key="system.observability.slow_request_ms",
        section="Observability",
        label="Slow request threshold (ms)",
        description="Requests slower than this are logged at WARNING and surfaced in the logs dashboard.",
        env="SLOW_REQUEST_MS",
        unit="ms",
        minimum=50,
        maximum=60_000,
        applies="app-restart",
    ),
    SettingDescriptor(
        key="system.observability.otel_enabled",
        section="Observability",
        label="OpenTelemetry export",
        description="Export traces/metrics to the configured OTLP endpoint.",
        kind="bool",
        env="OTEL_ENABLED",
        applies="app-restart",
    ),
    SettingDescriptor(
        key="system.observability.otel_metric_interval_millis",
        section="Observability",
        label="Metric export interval (ms)",
        description="How often metrics are pushed to the collector.",
        env="OTEL_METRIC_EXPORT_INTERVAL_MILLIS",
        unit="ms",
        minimum=5000,
        maximum=300_000,
        applies="app-restart",
        advanced=True,
    ),
    SettingDescriptor(
        key="system.observability.langfuse_enabled",
        section="Observability",
        label="Langfuse tracing",
        description="Send per-LLM-call traces to Langfuse. Requires its keys in .env.",
        kind="bool",
        env="LANGFUSE_ENABLED",
        applies="app-restart",
    ),
    # ---- pentest -------------------------------------------------------
    SettingDescriptor(
        key="system.pentest.auto_chain",
        section="Pentest",
        label="Automatically chain findings",
        description="Let the engine extend a finding into a follow-up step without asking.",
        kind="bool",
        env="PENTEST_AUTO_CHAIN",
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.pentest.unknown_cwe_ceiling",
        section="Pentest",
        label="Severity ceiling for unmapped CWEs",
        description="Severity assigned when a finding's CWE has no mapping in the catalog.",
        kind="enum",
        choices=("info", "low", "medium", "high", "critical"),
        env="PENTEST_UNKNOWN_CWE_CEILING",
        applies="worker-restart",
    ),
    SettingDescriptor(
        key="system.pentest.transcript_compact_tokens",
        section="Pentest",
        label="Transcript compaction threshold (tokens)",
        description="Older transcript turns are summarised once the run's transcript exceeds this.",
        env="PENTEST_TRANSCRIPT_COMPACT_TOKENS",
        unit="tokens",
        minimum=4000,
        maximum=2_000_000,
        applies="worker-restart",
        advanced=True,
    ),
    SettingDescriptor(
        key="system.pentest.transcript_keep_turns",
        section="Pentest",
        label="Transcript turns kept verbatim",
        description="Most recent transcript entries always kept unsummarised.",
        env="PENTEST_TRANSCRIPT_KEEP_TURNS",
        minimum=2,
        maximum=100,
        applies="worker-restart",
        advanced=True,
    ),
)

BY_KEY: Dict[str, SettingDescriptor] = {d.key: d for d in DESCRIPTORS}
BY_ENV: Dict[str, SettingDescriptor] = {d.env: d for d in DESCRIPTORS if d.env}


def section_order() -> Tuple[str, ...]:
    """Sections in display order, including one implied only by provider rows."""
    order = [name for name, _ in SECTIONS]
    for descriptor in DESCRIPTORS:
        if descriptor.section not in order:
            order.append(descriptor.section)
    return tuple(order)


def describe(key: str) -> SettingDescriptor | None:
    return BY_KEY.get(key)


def sections_payload() -> list[dict[str, Any]]:
    """The catalog in the shape the admin UI renders."""
    descriptions = dict(SECTIONS)
    payload: list[dict[str, Any]] = []
    for name in section_order():
        entries = [d for d in DESCRIPTORS if d.section == name]
        if not entries:
            continue
        payload.append(
            {
                "name": name,
                "description": descriptions.get(name, ""),
                "settings": [
                    {
                        "key": d.key,
                        "label": d.label,
                        "description": d.description,
                        "kind": d.kind,
                        "unit": d.unit,
                        "minimum": d.minimum,
                        "maximum": d.maximum,
                        "default": d.default,
                        "applies": d.applies,
                        "choices": list(d.choices),
                        "advanced": d.advanced,
                    }
                    for d in sorted(entries, key=lambda entry: entry.label)
                ],
            }
        )
    return payload
