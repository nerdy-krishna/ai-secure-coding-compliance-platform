# Observability and SLOs

SCCAP emits W3C-correlated operational traces and metrics via OTLP. Kubernetes
API pods use the instrumented ASGI wrapper; outbox payloads retain the request
trace context, publisher spans continue it in RabbitMQ headers, and workers
continue it across workflow, database, Qdrant, scanner, and provider spans.

## Privacy boundary

Only bounded identifiers and operational enums are allowlisted. Do not add
source text, prompts, responses, code, message bodies, credentials, SQL text or
parameters, vector documents, raw provider payloads, exception messages, or
stack traces. The application exporter and Collector both delete sensitive
keys; the application fails open if telemetry initialization or export fails.

Trace IDs are operational correlation, not authorization. Never accept a
tenant, scan, attempt, or outbox identity from trace attributes.

## Monthly objectives

| Service-level indicator | Objective |
| --- | --- |
| Authenticated API availability | 99.9% |
| Accepted submission plus outbox persistence p95 | under 2 seconds |
| Queue-to-start p95 under declared capacity | under 5 minutes |
| Approval resume p95 | under 60 seconds |
| Terminal workflow success, excluding policy/user blocks | at least 99% |
| SSE event freshness p95 | under 5 seconds |

The PrometheusRule alerts when a service consumes at least 2% of its monthly
error budget in one hour or 5% in six hours. For 99.9% availability these
correspond to 1.44% and 0.6% observed error ratios; for 99% workflow success,
14.4% and 6%. Latency alerts use 15-minute p95 windows. Queue-start is only an
SLO violation while declared database, broker, provider, and pool capacity are
available; dependency degradation still pages through its own runbook.

## Dashboard and triage

The chart provisions a Grafana dashboard ConfigMap and alerts for:

- queue depth and queue-head age for all pools;
- accepted persistence, queue-start, approval resume, and SSE p95 latency;
- terminal outcomes and cancellation volume;
- hourly LLM spend against `monitoring.llmSpendAlertUsdPerHour`.

For an API availability burn, compare API span errors with PostgreSQL and auth
latency. For queue age, compare backlog with KEDA desired/ready replicas and
pool saturation. For terminal errors, break down `scan.status`, workflow node,
and dependency class. For spend, use the immutable usage ledger as financial
authority; OTel counters are an operational early warning only.

The RabbitMQ detailed-metrics endpoint is higher cardinality than aggregate
metrics. Restrict it to the collector/KEDA network path and scrape only the
three SCCAP queues.
