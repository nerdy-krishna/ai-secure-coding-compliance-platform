#!/usr/bin/env bash
# "The scan stopped reporting progress" - identify what it is actually doing.
#
# Run from the install directory:  bash scripts/diagnose-stall.sh <scan-id>
#
# The activity log can only show what the application recorded. A node that is
# blocked on a database lock, a worker that was killed mid-node, or a scanner
# pass that emits nothing all look identical there: silence. This prints the state
# of the four things that can cause that silence.
set -uo pipefail

SCAN_ID="${1:-}"
[ -n "$SCAN_ID" ] || { echo "usage: $0 <scan-id>   (the uuid in /analysis/scanning/<scan-id>)" >&2; exit 2; }

PGUSER="${POSTGRES_USER:-postgres}"
PGDB="${POSTGRES_DB:-secure_coding_platform}"

psql_q() { docker compose exec -T db psql -U "$PGUSER" -d "$PGDB" -c "$1" 2>/dev/null; }

echo "=== worker health (a restart or an OOM kill loses the in-flight node) ========"
for c in sccap_worker sccap_app; do
    docker inspect -f '{{.Name}} status={{.State.Status}} restarts={{.RestartCount}} oom_killed={{.State.OOMKilled}} started={{.State.StartedAt}}' "$c" 2>/dev/null \
        || echo "$c: not running"
done
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}' sccap_worker sccap_app 2>/dev/null || true

echo
echo "=== last 12 events recorded for this scan ==================================="
psql_q "select id, stage_name, status, timestamp from scan_events
        where scan_id = '$SCAN_ID' order by id desc limit 12;"

echo
echo "=== scan row ================================================================"
psql_q "select status, updated_at, error_message from scans where id = '$SCAN_ID';"

echo
echo "=== blocked / long-running database work ===================================="
psql_q "select pid, state, wait_event_type, wait_event,
               now() - query_start as running_for,
               pg_blocking_pids(pid) as blocked_by,
               left(regexp_replace(query, '\s+', ' ', 'g'), 110) as query
        from pg_stat_activity
        where datname = current_database()
          and state <> 'idle'
          and (now() - query_start) > interval '20 seconds'
        order by running_for desc
        limit 10;"
echo "(an empty table here rules out a lock or a stuck query)"

echo
echo "=== LangGraph checkpoints for this scan (step + size) ======================"
psql_q "select checkpoint_id, metadata->>'step' as step,
               pg_size_pretty(pg_column_size(checkpoint)::bigint) as size,
               (checkpoint->'channel_values'->>'__start__') is not null as unused
        from checkpoints where thread_id = '$SCAN_ID'
        order by checkpoint_id desc limit 5;"
echo "(a checkpoint that grows by tens of MB per step is state bloat: findings and the"
echo " repository map are carried in it, and writing it can dominate the run)"

echo
echo "=== live worker stack (the node that is actually executing) ================"
if docker compose exec -T worker python -c "import py_spy" >/dev/null 2>&1; then
    docker compose exec -T worker py-spy dump --pid 1 2>/dev/null | head -40
else
    echo "  py-spy is not in the image. One-off install, read-only dump:"
    echo "    docker compose exec -T worker sh -c 'pip install -q py-spy && py-spy dump --pid 1' | head -40"
fi

echo
echo "How to read this:"
echo "  oom_killed=true / restarts grew   -> the worker died mid-node; resume the scan"
echo "  a blocked pid                     -> a lock from elsewhere is holding the node"
echo "  no events for the last stage only -> the node emits nothing; check its log lines"
echo "                                       ({service_name=\"worker\"} |= \"$SCAN_ID\")"
