#!/usr/bin/env bash
# Diagnose one scan: what it is doing, what it was last doing, and what is stuck.
#
#   bash scripts/diagnose-scan.sh 8c729ec8
#
# Run from the checkout that owns the stack (the directory with docker-compose.yml).
# Read-only: prints state, never changes it. Paste the output when reporting a hang.
set -uo pipefail

SCAN_PREFIX="${1:-}"
if [ -z "$SCAN_PREFIX" ]; then
    echo "usage: bash scripts/diagnose-scan.sh <scan-id-prefix>" >&2
    exit 2
fi

DC="docker compose"
DB=(docker exec -i sccap_db psql -U postgres -d secure_coding_platform -X -P pager=off)

say() { printf '\n=== %s ===\n' "$1"; }
q()   { "${DB[@]}" -c "$1" 2>&1; }

say "scan $SCAN_PREFIX"
q "select id, status, created_at, completed_at,
          now() - created_at as age,
          (select max(timestamp) from scan_events e where e.scan_id = s.id) as last_event,
          now() - (select max(timestamp) from scan_events e where e.scan_id = s.id) as idle
   from scans s where s.id::text like '${SCAN_PREFIX}%';"

say "attempts (graph threads)"
q "select a.sequence, a.trigger, a.status, a.started_at,
          now() - a.started_at as running_for, a.graph_thread_id
   from scan_attempts a join scans s on s.id = a.scan_id
   where s.id::text like '${SCAN_PREFIX}%' order by a.sequence;"

say "last 25 events (gap_s = seconds since the previous event)"
q "select timestamp::time(0) as t, stage_name, status,
          round(extract(epoch from (timestamp - lag(timestamp) over (order by timestamp)))) as gap_s,
          left(coalesce(details::text,''), 110) as details
   from scan_events where scan_id::text like '${SCAN_PREFIX}%'
   order by timestamp desc limit 25;"

say "in-flight scan tasks (lease held = a worker is working on it)"
q "select task_type, status, attempts, lease_owner,
          lease_expires_at, now() > lease_expires_at as lease_expired,
          now() - updated_at as since_update, left(coalesce(last_error,''), 90) as last_error
   from scan_tasks where scan_id::text like '${SCAN_PREFIX}%'
     and status not in ('completed','skipped','failed')
   order by updated_at limit 20;"

say "llm usage events (recorded calls, newest first)"
q "select stage, agent_name, provider, requested_model, request_count,
          received_at, now() - received_at as age
   from llm_usage_events where scan_id::text like '${SCAN_PREFIX}%'
   order by received_at desc limit 10;"

say "llm_interactions (legacy ledger) count / errors"
q "select count(*) as calls, count(*) filter (where error is not null) as errored,
          sum(input_tokens) as input_tokens, sum(output_tokens) as output_tokens,
          round(sum(cost)::numeric, 4) as cost, max(timestamp) as newest
   from llm_interactions where scan_id::text like '${SCAN_PREFIX}%';"

say "worker rate-limiter / retry / failure lines (last 30m)"
$DC logs --since 30m worker 2>&1 \
    | grep -iE "rate_limiter|retry|backoff|429|timeout|failed|error" \
    | tail -20 | cut -c1-320

say "queue depths"
docker exec sccap_rabbitmq rabbitmqctl list_queues name messages consumers -q 2>/dev/null \
    | grep -E "code_submission|analysis_approved|report_export" || true

say "containers"
docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'sccap_(app|worker|rabbitmq|db)' || true

say "worker/app resource use (a spinning container shows high CPU here)"
docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' 2>/dev/null \
    | grep -E 'sccap_(app|worker)' || true

say "database sessions waiting on a lock"
q "select pid, state, wait_event_type, wait_event, now() - query_start as duration,
          left(query, 100) as query
   from pg_stat_activity
   where datname = current_database() and state <> 'idle'
   order by duration desc limit 10;"

say "done"
echo "Paste everything above. If the last event is older than a few minutes and a"
echo "scan_tasks row still holds a lease, the run is wedged inside that task."
