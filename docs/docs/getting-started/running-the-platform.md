---
title: Running the Platform
sidebar_position: 3
---

# Running the Platform

Everything below assumes you've completed the
[Installation Guide](./installation.md) and have a `.env` file at the
repo root.

## Day-to-day commands

All backend + worker commands run inside Docker — the backend's
`.env` assumes hostnames `db` and `rabbitmq` that only resolve inside
the compose network.

```bash
# Start / rebuild
docker compose up -d --build                   # rebuild + start all services
docker compose up -d                           # start without rebuilding
docker compose logs -f app worker              # tail backend + worker

# Stop
docker compose down                            # stop containers (keeps volumes)
docker compose down -v                         # also removes volumes (DESTRUCTIVE)
```

## Accessing the UI + APIs

| Surface | URL (default) |
| ------- | ------------- |
| Frontend (production build served by the `ui` container) | `http://localhost/` |
| Backend API | `http://localhost/api/v1/…` |
| Swagger UI | `http://localhost/docs` |
| ReDoc | `http://localhost/redoc` |
| Grafana | printed at the end of `setup.sh` (defaults to `http://localhost:3000`) |
| RabbitMQ management | `http://localhost:15672` (credentials in `.env`) |
| MCP server | `http://localhost/mcp` (JWT auth) |

The exact URLs scheme (`http` vs. `https`) and hostnames depend on the
answers you gave during `setup.sh`; the script prints a final
"Setup Complete!" block with the real values for your deployment.

## Frontend development

For a fast, hot-reloading dev loop run Vite from the host instead of
the bundled `ui` container:

```bash
cd secure-code-ui
npm install
npm run dev                 # Vite dev server on :5173
```

Add `http://localhost:5173` to the `ALLOWED_ORIGINS` env var in `.env`
(or to `security.allowed_origins` via Admin → Platform) or CORS will
block the preflight after setup has completed.

```bash
npm run build               # tsc -b && vite build
npm run lint                # eslint .
```

## Backend migrations

```bash
# Apply any new migrations
docker compose exec app poetry run alembic upgrade head

# Generate a new migration from model changes
docker compose exec app poetry run alembic revision --autogenerate -m "msg"

# Roll back the most recent migration
docker compose exec app poetry run alembic downgrade -1
```

`alembic/env.py` reads `ALEMBIC_DATABASE_URL` from `.env` and runs
migrations through `create_async_engine()`, so the URL must use the
asyncpg driver (`postgresql+asyncpg://…`) even though the Alembic CLI
itself is sync.

## Verification

The inherited executable test suites were removed on 2026-08-22. Run
the static, build, migration, and image checks documented in the
[Verification Strategy](../development/testing-strategy.md). Passing
those checks does not substitute for behavioral coverage; replacement
tests are added alongside reproduced defects and stable production
contracts.

## Lint / format / type-check

```bash
docker compose exec app poetry run ruff check src
docker compose exec app poetry run black src
docker compose exec app poetry run mypy src

# Frontend
cd secure-code-ui && npm run lint
```

## Viewing logs end-to-end

Every request gets an `X-Correlation-ID` that's attached to every log
entry. Open Grafana → Explore → Loki, pick the SCCAP data source, and
filter with:

```
{service_name="app"} |= "<correlation-id>"
```

See [Architecture → Observability](../architecture/backend-services.md)
for the full logging pipeline.
