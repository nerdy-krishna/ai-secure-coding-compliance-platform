#!/usr/bin/env bash
# Host-side executor for a UI-initiated update.
#
# Triggered by the sccap-update.path systemd unit when the API writes
# <repo>/.control/update-request. It runs the same code path an operator would
# (`setup.sh --update --yes`) and publishes progress to
# <repo>/.control/update-status.json, which GET /api/v1/system/update-status
# serves to the UI.
#
# Privilege boundary: the application container can only create a request file
# inside .control/. Deciding to run, and running, the update stays here on the
# host as root — a compromised web session cannot inject commands, only ask.
set -uo pipefail

REPO_DIR="${SCCAP_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
CONTROL_DIR="$REPO_DIR/.control"
REQUEST="$CONTROL_DIR/update-request"
STATUS="$CONTROL_DIR/update-status.json"
LOG="$CONTROL_DIR/update.log"

cd "$REPO_DIR" || exit 1
mkdir -p "$CONTROL_DIR"
# Consume the request immediately so a crash cannot re-trigger the unit.
[ -f "$REQUEST" ] && rm -f "$REQUEST"

write_status() {
    local phase="$1" message="${2:-}" exit_code="${3:-}"
    local from to
    from=$(git rev-parse HEAD 2>/dev/null || echo "")
    to=$(git rev-parse "origin/$(git rev-parse --abbrev-ref HEAD)" 2>/dev/null || echo "")
    cat > "$STATUS" <<EOF
{"phase": "${phase}", "message": "${message}", "exit_code": ${exit_code:-null},
 "from_commit": "${from}", "to_commit": "${to}",
 "updated_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "log": "update.log"}
EOF
    chmod 644 "$STATUS" 2>/dev/null || true
    chown 1001:1001 "$STATUS" 2>/dev/null || true
}

write_status running "update started" ""
: > "$LOG"
chmod 644 "$LOG" 2>/dev/null || true

if bash ./setup.sh --update --yes >> "$LOG" 2>&1; then
    write_status succeeded "update applied" 0
else
    write_status failed "update failed — see the log; ./setup.sh --rollback reverts" 1
fi
