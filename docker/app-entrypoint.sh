#!/usr/bin/env bash
# Docker entrypoint for the SCCAP app container.
# Runs Alembic migrations then starts the configured process.
set -euo pipefail

echo "[entrypoint] Running Alembic migrations..."
cd /app
alembic upgrade head
echo "[entrypoint] Migrations complete."

# Hand off to the original command (uvicorn, worker, etc.)
exec "$@"
