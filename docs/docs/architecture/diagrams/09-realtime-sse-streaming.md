# 09 — Real-time SSE Streaming

SCCAP uses **Server-Sent Events** (one-way, server → browser) for live scan progress. No WebSocket layer. This page documents the full streaming pipeline: from the LangGraph worker emitting a `ScanEvent` row to the SPA closing its `EventSource`.

---

## Diagram

```mermaid
flowchart LR
    %% ===== Worker side =====
    subgraph Worker["LangGraph Worker (sccap_worker)"]
      WF["StateGraph nodes<br/>(prescan, analyze, correlate, …)"]:::app
      Notif["scan_progress_notifier<br/>(callback registered on every node transition)"]:::app
    end

    subgraph DB["PostgreSQL"]
      direction TB
      SE[("scan_events v1<br/>cursor/id, scan + attempt,<br/>activity kind, stage/status,<br/>timestamp, safe details JSONB")]:::data
      Sc[("scans<br/>status column (state machine)")]:::data
      Bus[("Postgres LISTEN/NOTIFY<br/>channel sccap_scan_events")]:::data
    end

    subgraph App["FastAPI app (sccap_app)"]
      direction TB
      ST["POST /api/v1/scans/{id}/stream-token<br/>· checks scan ownership + tenant<br/>· mints JWT (aud=sse:scan-stream, exp 60 s,<br/>  scan_id-bound)"]:::app
      SSEH["GET /api/v1/scans/{id}/stream?access_token=…&cursor=…<br/>· validates SSE-aud JWT + cursor<br/>· opens text/event-stream response<br/>· keepalive comments"]:::app
      Pol["Stream loop<br/>· LISTEN sccap_scan_events (NOTIFY-driven)<br/>· cursor replay + fallback poll<br/>· emits scan_state on scans.status change"]:::app
    end

    %% ===== Edge / SPA =====
    Nginx["Nginx<br/>· proxy_buffering off for /stream<br/>· proxy_read_timeout 1h<br/>· X-Accel-Buffering: no"]:::edge

    subgraph SPA["React SPA · ScanRunningPage"]
      ES["EventSource(...)<br/>{ withCredentials: true }"]:::edge
      Handlers["es.addEventListener<br/>· scan_state<br/>· scan_event<br/>· done<br/>· error"]:::edge
      Retry["Fresh stream token + exponential reconnect<br/>last cursor round-tripped · stable-ID dedupe"]:::edge
    end

    %% ===== Wiring =====
    WF -- "callback per node transition" --> Notif
    Notif -- "INSERT scan_events" --> SE
    Notif -- "NOTIFY sccap_scan_events scan_id=…" --> Bus
    WF -- "UPDATE scans.status" --> Sc

    SPA -- "POST /stream-token" --> ST
    ST -- "stream JWT" --> SPA
    SPA -- "GET /stream?access_token=…<br/>Accept: text/event-stream" --> Nginx --> SSEH
    SSEH --> Pol
    Pol -- "LISTEN" --> Bus
    Bus -- "NOTIFY" --> Pol
    Pol -- "SELECT new rows" --> SE
    Pol -- "current status" --> Sc
    Pol -- "event: scan_state / scan_event / done<br/>data: { ... JSON ... }" --> SSEH
    SSEH -- "text/event-stream" --> Nginx --> ES --> Handlers
    Handlers --> Retry

    classDef edge fill:#e0f2fe,stroke:#0369a1,color:#082f49;
    classDef app  fill:#e0e7ff,stroke:#4338ca,color:#1e1b4b;
    classDef data fill:#dcfce7,stroke:#15803d,color:#052e16;
```

---

## Wire-format reference

```text
event: scan_state
data: {"scan_id":"…","status":"PENDING_COST_APPROVAL","cost_details":{"total_estimated_cost":1.42,"total_input_tokens":83000,"predicted_output_tokens":5200}}

event: scan_event
id: 42
data: {"schema_version":1,"cursor":"42","scan_id":"…","event_id":42,"attempt_id":"…","activity_kind":"llm_call","stage_name":"FILE_ANALYZED","status":"COMPLETED","timestamp":"2026-05-12T14:01:33.221Z","details":{"file_path":"src/auth.py","findings_count":3,"fixes_count":2}}

event: scan_event
data: {"scan_id":"…","event_id":43,"stage_name":"CORRELATING","status":"STARTED","timestamp":"2026-05-12T14:01:34.012Z"}

: keepalive
event: done
data: {"scan_id":"…","status":"COMPLETED"}
```

The single `:` line is an **SSE comment**, emitted on idle notification/poll intervals so intermediate proxies do not time the connection out.

---

## Legend

### Stream-token JWT

| Claim         | Value                                                          |
|---------------|----------------------------------------------------------------|
| `iss`         | SCCAP issuer                                                   |
| `sub`         | `user_id`                                                      |
| `aud`         | `sse:scan-stream` (distinct from the API audience `api`)       |
| `scan_id`     | The scan this token can stream                                 |
| `exp`         | issued time + 60 s                                             |
| `tenant_id`   | For cross-check against the scan's tenant                       |

The same access token cannot stream scans; the SSE endpoint refuses any JWT whose `aud != sse:scan-stream`. This is a deliberate split so a leaked access token cannot tail an arbitrary scan.

### Backend stream loop (`src/app/api/v1/routers/projects.py::stream_scan`)

```python
async def stream(scan_id, request):
    yield_keepalive_every = 15  # s
    fallback_interval     = 1   # s when no LISTEN/NOTIFY
    last_event_id         = validated_max(header_last_id, query_cursor)
    async with db.acquire() as conn:
        await conn.execute("LISTEN sccap_scan_events")
        while not await request.is_disconnected():
            # 1. drain any new scan_events past last_event_id
            new_rows = await fetch_new(scan_id, last_event_id)
            for row in new_rows:
                yield sse_event("scan_event", payload(row))
                last_event_id = row.id
            # 2. emit scan_state on status change
            ...
            # 3. terminal? Cancellation waits for durable COMPLETED acknowledgement.
            if terminal_ready(status, new_rows):
                yield sse_event("done", {...})
                break
            # 4. wait for NOTIFY or fallback poll
            await wait_notify_or(fallback_interval)
            await keepalive_if_due()
```

### `scan_events` table — write path

```mermaid
sequenceDiagram
    participant Node as LangGraph node
    participant Notif as scan_progress_notifier
    participant DB as Postgres

    Node->>Notif: workflow/scanner/LLM/retry/decision/cancellation activity
    Notif->>DB: redact + bound details<br/>INSERT versioned scan_events envelope<br/>RETURNING cursor/id
    Notif->>DB: NOTIFY sccap_scan_events, '{"scan_id":"...","event_id":...}'
```

### EventSource handling (frontend)

```ts
const { access_token } = await scanService.getStreamToken(scanId);
const url = `/api/v1/scans/${scanId}/stream?access_token=${access_token}`;
const es  = new EventSource(url, { withCredentials: true });

es.addEventListener("scan_state", (e) => setStatus(JSON.parse(e.data)));
es.addEventListener("scan_event", (e) => appendEvent(JSON.parse(e.data)));
es.addEventListener("done",       (_) => { es.close(); navigate(`/analysis/results/${scanId}`); });
es.addEventListener("error",      (_) => watchdog.bump());
```

- `withCredentials: true` so the refresh cookie travels (the Nginx/origin policy already permits it).
- Each activity carries a stable `activity_kind`; the UI can filter by kind and stage without parsing messages.
- Manual reconnects mint a fresh token, send the highest rendered cursor, and deduplicate seed/SSE/poll rows by event ID.

### Forceful cancellation

The API persists `CANCELLATION/REQUESTED` with the terminal status. A running worker checks that
flag every 250 ms, persists `OBSERVED`, terminates every registered scanner process group, cancels
the in-flight provider/workflow task, and persists `COMPLETED` with latency and the two-second SLO
result. Paused scans acknowledge all phases inline. The server emits `done` for `CANCELLED` only
after `COMPLETED` is present, so the operator sees the full acknowledgement sequence.

### Nginx-side tuning (`secure-code-ui/nginx-https.conf`)

```nginx
location /api/v1/ {
    proxy_pass http://app_backend;
    proxy_http_version 1.1;
    proxy_set_header Connection "";

    # SSE-friendly
    proxy_buffering         off;
    proxy_request_buffering off;
    proxy_read_timeout      3600s;
    add_header              X-Accel-Buffering no;
}
```

### Terminal events

`done` is emitted exactly once. The server breaks out of its loop after that, and the SPA closes the `EventSource` to release the connection. Reconnecting to a terminated scan produces a single `scan_state` event with the final status followed by `done`.

### Failure modes & resilience

| Failure                                  | Handling                                                                                                                     |
|------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| DB `LISTEN` connection drops              | Stream loop falls back to 1 s polling of `scan_events` + `scans.status`                                                       |
| Worker crashes mid-scan                   | Scan stays in non-terminal status until the orphan sweeper marks it `FAILED`; SSE keeps streaming keepalive comments         |
| User refreshes the page                   | EventSource closed by browser; on re-open the `Last-Event-ID` header is set automatically and the server resumes after that id |
| SSE token expires (60 s)                  | Endpoint returns 401 with `WWW-Authenticate: Bearer error="invalid_token"`; SPA requests a fresh stream-token and reopens     |
| Reverse-proxy buffering                   | `proxy_buffering off` + `X-Accel-Buffering: no` prevent Nginx from holding events                                            |
| LLM provider stalls                       | Cancellation cancels the provider/workflow task; ordinary provider timeouts remain visible as failed/retry activity          |

---

## Source files

- `src/app/api/v1/routers/projects.py` — `stream_scan_token`, `stream_scan`
- `src/app/infrastructure/messaging/scan_progress_notifier.py`
- `src/app/infrastructure/workflows/cancellation.py`
- `src/app/shared/lib/owned_subprocess.py`
- `src/app/infrastructure/database/models.py` — `ScanEvent`
- `secure-code-ui/src/pages/submission/ScanRunningPage.tsx`
- `secure-code-ui/src/shared/api/scanService.ts` — `getStreamToken`
- `secure-code-ui/nginx-https.conf`
