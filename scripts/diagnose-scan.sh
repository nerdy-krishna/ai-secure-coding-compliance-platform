#!/usr/bin/env bash
# "My scan is stuck and nothing is in its activity log" - gather the facts.
#
# Run from the install directory:  bash scripts/diagnose-scan.sh <scan-id>
#
# The scan page can only show what the *application* recorded. If the worker never
# received the message, nothing is attributable to the scan and the page is empty -
# which is indistinguishable from "the worker received it and did nothing". This
# prints the queue, the worker container and the delivery record so the two look
# different.
set -uo pipefail

SCAN_ID="${1:-}"
[ -n "$SCAN_ID" ] || { echo "usage: $0 <scan-id>   (the uuid in /analysis/scanning/<scan-id>)" >&2; exit 2; }

echo "=== worker / app containers ==============================================="
docker compose ps app worker rabbitmq 2>/dev/null || true
for c in sccap_worker sccap_app; do
    docker inspect -f '{{.Name}} status={{.State.Status}} restarts={{.RestartCount}} started={{.State.StartedAt}}' "$c" 2>/dev/null || echo "$c: not running"
done

echo
echo "=== queues (messages queued / consumers attached) ========================"
docker compose exec -T rabbitmq rabbitmqctl list_queues name messages consumers 2>/dev/null \
    | grep -E "^name|code_submission_queue|analysis_approved_queue|report_export_queue" || echo "rabbitmq not reachable"

echo
echo "=== scan + attempt + outbox record ======================================"
docker compose exec -T db psql -U "${POSTGRES_USER:-postgres}" -d "${POSTGRES_DB:-secure_coding_platform}" -c "
select s.status, s.created_at, s.current_attempt_id, s.error_message
from scans s where s.id = '$SCAN_ID';
select id, sequence, status, \"trigger\", started_at from scan_attempts where scan_id = '$SCAN_ID' order by sequence;
select id, queue_name, state, attempts, last_error, created_at, published_at
from scan_outbox where scan_id = '$SCAN_ID' order by created_at;
select stage_name, status, timestamp from scan_events where scan_id = '$SCAN_ID' order by id desc limit 12;" 2>/dev/null \
    || echo "db not reachable via 'docker compose exec db psql'"

echo
echo "=== worker log for this scan (Loki, last 2h) ============================"
echo "  Grafana/Loki query:  {service_name=\"worker\"} |= \"$SCAN_ID\""
if command -v curl >/dev/null 2>&1; then
    curl -sG 'http://127.0.0.1:3100/loki/api/v1/query_range' \
        --data-urlencode "query={service_name=\"worker\"} |= \"$SCAN_ID\"" \
        --data-urlencode 'limit=80' --data-urlencode 'direction=backward' 2>/dev/null \
        | python3 -c 'import json,sys
try:
    data=json.load(sys.stdin)
except Exception:
    sys.exit(0)
rows=[(v[0],v[1]) for s in data.get("data",{}).get("result",[]) for v in s.get("values",[])]
for ts,line in sorted(rows):
    print(line[:400])
if not rows:
    print("  (no worker log line mentions this scan - the worker never handled it)")' 2>/dev/null || true
fi

echo
echo "How to read this:"
echo "  queue consumers = 0            -> the worker is not attached to the queue"
echo "  messages > 0, consumers >= 1   -> the worker has it but is not processing it"
echo "  outbox state published, no worker log -> the message was lost after publish"
echo "  no scan_outbox row at all      -> the submission never committed its dispatch intent"
