#!/usr/bin/env bash
# Maintainer check for the `./setup.sh --update` rebuild scope.
#
# The update path rebuilds only the images a change can reach. Getting that map
# wrong in the *narrow* direction ships a stale image, so the boundaries are
# asserted here rather than discovered in production:
#
#   pentest-engine  runs app.infrastructure.pentesting.tool_worker.main and
#                   imports app.pentest, app.infrastructure.{database, llm_client,
#                   secrets}, app.shared.lib, app.config, app.assets - nothing
#                   from app.api, app.core or the scan workflow.
#   patch-validator ships exactly one application file:
#                   src/app/shared/lib/validation_sandbox_runner.py.
#
# Run it after editing `_sccap_services_for_changes`. Exit code 0 means every
# boundary still holds.
set -uo pipefail

REPO_DIR="${SCCAP_REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
cd "$REPO_DIR" || exit 1

eval "$(sed -n '/^_sccap_services_for_changes()/,/^}/p' setup.sh)"
eval "$(sed -n '/^_sccap_validate_only_services()/,/^}/p' setup.sh)"

if [ -z "$(printf '%s' "$(declare -f _sccap_services_for_changes)")" ]; then
    echo "[!] Could not extract _sccap_services_for_changes from setup.sh" >&2
    exit 1
fi

# Stub: the services this deployment has. `ps -a --services` decides whether the
# tools images participate at all, so it has to answer like compose does.
docker() {
    case "${1:-} ${2:-}" in
        "compose ps"|"compose config") printf 'db\napp\nworker\npentest-engine\npatch-validator\nui\n' ;;
        *) return 1 ;;
    esac
}

failures=0

check() {
    local label="$1" expected="$2" changed="$3" got
    got=$(_sccap_services_for_changes "$changed")
    if [ "$got" = "$expected" ]; then
        printf 'ok   %-52s -> %s\n' "$label" "${got:-<none>}"
    else
        printf 'FAIL %-52s -> %s (expected %s)\n' "$label" "${got:-<none>}" "${expected:-<none>}"
        failures=$((failures + 1))
    fi
}

check "api change"                        "app worker"                 "src/app/api/v1/routers/projects.py"
check "workflow node change"              "app worker"                 "src/app/infrastructure/workflows/nodes/retrieve.py"
check "scan service change"               "app worker"                 "src/app/core/services/scan/query.py"
check "alembic revision"                  "app worker"                 "alembic/current_versions/scan_0034_scan_log_lines.py"
check "shared lib (engine imports it)"    "app worker pentest-engine"  "src/app/shared/lib/scan_status.py"
check "database models"                   "app worker pentest-engine"  "src/app/infrastructure/database/models.py"
check "pentest engine code"               "app worker pentest-engine"  "src/app/pentest/tools/base.py"
check "validation runner only"            "app worker patch-validator" "src/app/shared/lib/validation_sandbox_runner.py"
check "dependencies (broad on purpose)"   "app worker pentest-engine patch-validator" "pyproject.toml"
check "dockerfile (broad on purpose)"     "app worker pentest-engine patch-validator" "Dockerfile"
check "ui"                                "ui"                         "secure-code-ui/src/pages/analysis/ResultsPage.tsx"
check "docs only (no image)"              ""                           "docs/docs/api-reference/code-analysis-endpoints.md"
check "compose only (no image)"           ""                           "docker-compose.yml"
check "mixed api + ui"                    "app worker ui"              $'src/app/main.py\nsecure-code-ui/src/App.tsx'

if [ "$(_sccap_validate_only_services 'app,worker')" != "app worker" ]; then
    echo "FAIL --only=app,worker was not accepted"
    failures=$((failures + 1))
else
    echo "ok   --only=app,worker"
fi
if _sccap_validate_only_services 'app,nope' >/dev/null 2>&1; then
    echo "FAIL --only accepted an unknown service"
    failures=$((failures + 1))
else
    echo "ok   --only rejects an unknown service"
fi

if [ "$failures" -ne 0 ]; then
    echo ""
    echo "[!] $failures scope check(s) failed" >&2
    exit 1
fi
echo ""
echo "[+] update rebuild scope is as documented"
