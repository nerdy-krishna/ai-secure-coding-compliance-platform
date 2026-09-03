#!/usr/bin/env bash
# Docker entrypoint for SCCAP API and worker containers.
# Exactly one API-owned process migrates. Worker-derived images only wait for
# the database to reach the image's Alembic head.
set -euo pipefail

cd /app

case "${SCCAP_MIGRATION_ROLE:-wait}" in
  owner)
    echo "[entrypoint] Running API-owned Alembic migrations..."
    alembic upgrade head
    echo "[entrypoint] Migrations complete."
    ;;
  wait)
    wait_seconds="${SCCAP_MIGRATION_WAIT_SECONDS:-300}"
    if [[ ! "$wait_seconds" =~ ^[1-9][0-9]*$ ]]; then
      echo "[entrypoint] Invalid SCCAP_MIGRATION_WAIT_SECONDS." >&2
      exit 64
    fi
    deadline=$((SECONDS + wait_seconds))
    echo "[entrypoint] Waiting for the migration owner to reach Alembic head..."
    until alembic current --check-heads >/dev/null 2>&1; do
      if (( SECONDS >= deadline )); then
        echo "[entrypoint] Timed out waiting for Alembic head." >&2
        exit 70
      fi
      sleep 2
    done
    echo "[entrypoint] Database is at Alembic head."
    ;;
  *)
    echo "[entrypoint] SCCAP_MIGRATION_ROLE must be owner or wait." >&2
    exit 64
    ;;
esac

# Hand off to the original command (uvicorn, worker, etc.)
exec "$@"
