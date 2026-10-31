# Observability and SLOs

SCCAP emits W3C-correlated operational traces and metrics via OTLP. Kubernetes
API pods use the instrumented ASGI wrapper; outbox payloads retain the request
trace context, publisher spans continue it in RabbitMQ headers, and workers
continue it across workflow, database, Qdrant, scanner, and provider spans.

## Log pipeline (Fluentd → Loki → Grafana)

The `log_stack` Compose profile runs the container log pipeline:

| Hop | What it does | Failure mode to know |
|---|---|---|
| Docker log driver | `app`, `worker`, `ui`, `pentest-engine` and `patch-validator` ship stdout/stderr to Fluentd on `localhost:24224` with a `docker.<service>.<container>` tag | The driver is resolved by the Docker daemon on the host, so `localhost` is the host, not the container |
| Fluentd | Parses the JSON line, extracts `service_name`, `level` and `logger_name` as Loki labels, buffers to `./fluentd/log/buffer` | The buffer lives in a bind mount and Fluentd runs as uid 100/gid 101: a root-owned `fluentd/log` makes the worker exit with `Permission denied @ dir_s_mkdir - /fluentd/log/buffer` and **every line is lost**. `setup.sh` hands that tree to the Fluentd user; the container healthcheck fails if the buffer is not writable |
| Loki | Stores the streams, labelled by service, level and logger | Queries need the tenant header when running more than one tenant |
| Grafana | `Loki` datasource pinned to uid `loki`, plus the provisioned **SCCAP · Logs** dashboard (`grafana/provisioning/dashboards/logs-overview.json`): volume by service, errors by service, error counts for the last hour, services reporting, and two live log browsers | Dashboards are file-provisioned; editing them in the UI does not persist |

Verify the whole chain in one command:

```bash
docker exec sccap_loki wget -qO- \
  --header="X-Scope-OrgID: anonymous" \
  "http://127.0.0.1:3100/loki/api/v1/query_range?query=%7Bservice_name%3D~%22.%2B%22%7D&limit=3"
```

A `status: success` with a non-empty `result` array means logs are flowing; an empty
array with a healthy Fluentd usually means the buffer directory is not writable.
Grafana itself should report the datasource as healthy under
*Connections → Data sources → Loki → Save & test*.

### What the applications log

One structured line per request, emitted by the application (not uvicorn, whose
unstructured access log is disabled to avoid a second line per request):

```json
{"timestamp":"…","level":"INFO","message":"http.request","logger_name":"app.main",
 "service_name":"app","correlation_id":"…","http_method":"GET",
 "http_route":"/api/v1/scans/{scan_id}/result","http_status":200,
 "duration_ms":12.4,"slow":false}
```

- **`http_route` is the route template**, not the URL — ids and search terms would
  make the stream unbounded.
- **Level follows the outcome**: 5xx is `ERROR`, 4xx and requests slower than
  `SLOW_REQUEST_MS` (default 2500) are `WARNING`, health checks and asset probes
  are `DEBUG` and are dropped by the collector.
- **`correlation_id`** joins every line a request produced across the API, worker
  and pentest engine.
- **`logger_name` is a field, not a Loki label.** Labels are `service_name` and
  `level` only; a label per logger multiplies streams and slows queries. Filter
  with `{service_name="app"} | json | logger_name="app.core.services.scan.query"`.

Verbosity is `LOG_LEVEL` (default `INFO`; `DEBUG` outside production), overridable
at runtime from *Admin → Platform → system.log_level*. HTTP clients, provider SDKs,
`watchfiles`, `filelock` and `asyncio` are pinned at `WARNING` so library chatter
cannot drown the application's own events.

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
