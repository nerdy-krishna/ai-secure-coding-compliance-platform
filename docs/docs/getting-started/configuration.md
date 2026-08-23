# Configuration Guide

The SCCAP is configured primarily through environment variables defined in a `.env` file located in the project root.

> ⚠️ It is crucial to set up this file correctly before running the application.

Start by copying the example file to create your own local configuration:

```bash
cp .env.example .env
python3 scripts/bootstrap_env_secrets.py --env-file .env
```

> ❗ **Never commit your actual `.env` file with sensitive credentials to version control.**

The bootstrap command is also the safe upgrade path for an existing `.env`.
It generates missing or explicit placeholder secrets, preserves valid values,
writes the file atomically (mode `0600` on POSIX), and never prints secret
material. On Windows, keep the checkout under a user-restricted NTFS directory.
Run it after pulling a release and before `docker compose` so newly required
interpolation values are present.

---

## 🔐 `ENCRYPTION_KEY` (CRITICAL)

This is the **most important secret** for your installation. It's used to encrypt and decrypt all sensitive data stored in the database — especially the LLM API keys managed via the UI.

Generate it with:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Then add it to your `.env` file:

```env
ENCRYPTION_KEY=your-super-secret-generated-key-goes-here
```

---

## ⚙️ General Application Settings

| Variable | Description | Example | Notes |
| -------- | ----------- | ------- | ----- |
| `APP_PORT` | Port for the backend FastAPI app | `8000` | Ensure this port is available |
| `SECRET_KEY` | Used to sign JWT tokens | `your-random-secret` | Must be unique and strong |
| `ALLOWED_ORIGINS` | Allowed origins for CORS | `http://localhost:5173` | No trailing slash |
| `ACCESS_TOKEN_LIFETIME_SECONDS` | Non-browser Bearer token expiry | `3600` | The SPA does not persist this token |
| `REFRESH_TOKEN_LIFETIME_SECONDS` | Legacy compatibility refresh lifetime | `604800` | Still capped by the browser-session absolute deadline |
| `SESSION_IDLE_LIFETIME_SECONDS` | Browser inactivity deadline | `3600` | Activity can extend only this deadline |
| `SESSION_ABSOLUTE_LIFETIME_SECONDS` | Browser absolute deadline | `86400` | Rotation cannot extend it; hard maximum is 7 days |
| `SESSION_TOUCH_INTERVAL_SECONDS` | Minimum interval between activity writes | `300` | Reduces database write amplification |
| `SSL_DEV_INSECURE` | Explicit HTTP-only local-development opt-in | `false` | Uses `SCCAPSessionDev`; forbidden with `ENVIRONMENT=production` |

---

## 🗄️ PostgreSQL Database

| Variable | Description | Example | Notes |
| -------- | ----------- | ------- | ----- |
| `POSTGRES_USER` | DB username | `devuser_scp` | |
| `POSTGRES_PASSWORD` | DB password | `yoursecurepassword` | |
| `POSTGRES_DB` | DB name | `securecodedb_dev` | |
| `POSTGRES_HOST` | Host (for internal services) | `db` | Should match `docker-compose` service name |
| `POSTGRES_PORT` | Internal container port | `5432` | Default PostgreSQL port |
| `POSTGRES_PORT_HOST` | Local port mapped to PostgreSQL | `5432` | For connecting from local tools |
| `POSTGRES_HOST_ALEMBIC` | Host for Alembic (from CLI) | `localhost` | Always `localhost` for migrations |
| `ASYNC_DATABASE_URL` | API/worker runtime URL | `postgresql+asyncpg://sccap_app:...@db:5432/securecodedb` | Production login must be `NOSUPERUSER`, `NOBYPASSRLS`, and must not own forced-RLS tables |
| `ALEMBIC_DATABASE_URL` | Migration-owner URL | `postgresql+asyncpg://sccap_migrator:...@db:5432/securecodedb` | Keep out of the running API/worker environment after entrypoint migrations |

Production must use distinct migration and runtime PostgreSQL logins. The API
performs a startup preflight and refuses to run when either the active or
session login is a superuser, has `BYPASSRLS`, or owns a forced-RLS table. The
runtime login should be granted the migration-created `sccap_runtime` role (or
equivalent explicit DML privileges). Local Compose can continue deriving both
URLs from `POSTGRES_*`; it logs an unsafe-development warning because that
single owner login is not a production isolation boundary.

---

## 📬 RabbitMQ Message Queue

| Variable | Description | Example |
| -------- | ----------- | ------- |
| `RABBITMQ_DEFAULT_USER` | RabbitMQ username | `devuser_scp` |
| `RABBITMQ_DEFAULT_PASS` | RabbitMQ password | `yoursecurepassword` |
| `RABBITMQ_ERLANG_COOKIE` | Internal RabbitMQ node-authentication cookie; required by Compose and generated during setup/upgrade | generated value; do not share or log |
| `RABBITMQ_HOST` | RabbitMQ host (internal) | `rabbitmq` |
| `RABBITMQ_PORT` | AMQP port | `5672` |
| `RABBITMQ_MANAGEMENT_PORT` | Port for RabbitMQ UI | `15672` |

The worker subscribes to three queues (names are controlled by
`src/app/config/config.py`; most deployments leave them at the
defaults):

| Queue | Default name | Purpose |
| ----- | ------------ | ------- |
| `RABBITMQ_SUBMISSION_QUEUE` | `code_submission_queue` | New scan submissions (worker runs the audit pass and pauses at cost approval) |
| `RABBITMQ_APPROVAL_QUEUE` | `analysis_approved_queue` | User approved the cost estimate; worker resumes the paused LangGraph thread |

## Immutable evidence storage

Compose runs a dedicated local `evidence-minio` service. Production should point SCCAP at a private
S3-compatible bucket and use workload identity where possible.

| Variable | Purpose | Production requirement |
| --- | --- | --- |
| `EVIDENCE_STORE_ENABLED` | Enables encrypted object evidence | `true` |
| `EVIDENCE_S3_ENDPOINT_URL` | S3-compatible endpoint; omit for AWS S3 | TLS endpoint or AWS default |
| `EVIDENCE_S3_REGION` | Bucket/KMS region | Deployment region |
| `EVIDENCE_S3_BUCKET` | Dedicated private evidence bucket | Do not share with Langfuse or uploads |
| `EVIDENCE_S3_ACCESS_KEY_ID` / `EVIDENCE_S3_SECRET_ACCESS_KEY` | Static credentials for local/compatible stores | Prefer both omitted with workload identity |
| `EVIDENCE_KEY_PROVIDER` | Envelope-key provider: `local` or `aws_kms` | Must be `aws_kms` |
| `EVIDENCE_KMS_KEY_ID` | KMS key/alias used to generate and unwrap data keys | Required |
| `EVIDENCE_LOCAL_KEK` | Local-only key-encryption secret | Forbidden as the production provider |
| `EVIDENCE_RETENTION_DAYS` | Default retain-until interval | Set from policy |
| `EVIDENCE_DUAL_WRITE_LEGACY` | Also retain PostgreSQL JSON during migration | Enable only for expand/verify rollout |

Objects are encrypted before upload and downloads are application-mediated. Do not expose the
bucket publicly or issue direct presigned links. To migrate existing artifacts, keep dual-write on,
run `docker compose exec app python -m app.scripts.backfill_evidence_store`, verify coverage and
digests, then disable legacy writes in a later deployment. Legal holds must be released through the
governance repository/workflow; direct bucket deletion bypasses the audit trail.

---

## 🧠 Qdrant Vector Database

Replaced ChromaDB per ADR-008. The compose stack runs Qdrant in the
`qdrant` container; the app talks to it through the `VectorStore`
Protocol (`infrastructure/rag/qdrant_store.py`).

| Variable | Description | Example |
| -------- | ----------- | ------- |
| `QDRANT_HOST` | Internal hostname | `qdrant` |
| `QDRANT_PORT` | Internal container port (HTTP `6333`, gRPC `6334`) | `6333` |
| `QDRANT_API_KEY` | API key (required; matches `QDRANT__SERVICE__API_KEY` set on the container) | `change-me` |

---

## 💸 LiteLLM (Token counting + cost estimation)

| Variable | Description | Example | Notes |
| -------- | ----------- | ------- | ----- |
| `LITELLM_LOCAL_MODEL_COST_MAP` | Pin LiteLLM to its bundled model-price map instead of fetching it at runtime. | `True` | Recommended. Keeps scan-cost calculations offline. |

LiteLLM performs local pre-call token counting and estimate pricing.
Post-call actuals use provider-reported usage in the immutable usage
ledger. For negotiated contracts, superusers append a complete,
effective-dated price version under the LLM configuration API; the old
two-rate fields remain a text-only compatibility fallback. See
[Architecture → LLM Integration](../architecture/llm-integration.md)
for the full data flow.

---

## Immutable OSV advisory snapshot (optional)

OSV prescan can retain the legacy live service, but automatic promotion of an
OSV-originated fix or dependency-lockfile change requires an immutable local
advisory snapshot. SCCAP never downloads or refreshes that database during
promotion.

Prepare an OSV-Scanner v2 cache directory containing
`osv-scanner/<ecosystem>/all.zip`. Add a read-only `snapshot.json` at its root:

```json
{
  "schema_version": 1,
  "snapshot_id": "osv-2026-08-23T000000Z",
  "created_at": "2026-08-23T00:00:00Z",
  "files": [
    {
      "path": "osv-scanner/PyPI/all.zip",
      "size_bytes": 123456,
      "sha256": "<64 lowercase hex characters>"
    }
  ]
}
```

Every `all.zip` used by the snapshot must appear exactly once. Set
`OSV_OFFLINE_SNAPSHOT_HOST_DIR` to that directory and start Compose with both
files:

```bash
docker compose -f docker-compose.yml -f docker-compose.osv-offline.yml up -d worker
```

The override mounts the directory read-only. The worker verifies bounded path,
size, and SHA-256 evidence before and after each use, rejects symlinks and
worker-writable files, strips proxy credentials, and passes OSV explicit
offline/no-resolve flags. An invalid configured snapshot does not fall back to
live OSV matching. Without the override, OSV prescan remains visibly degraded
and affected patch promotion remains blocked.

---

## 🤖 Dynamic UI Configuration (Major Change)

> **LLM API keys and SMTP Settings are not stored in `.env`.**

The platform includes a secure **Admin Dashboard** for dynamic
configuration. After launching the app and logging in as the
**superuser** (the first registered user), you are routed to
`/setup` to:

- Add/remove LLM providers (OpenAI, Google, Anthropic, etc.) and
  securely enter API keys — encrypted at rest with your
  `ENCRYPTION_KEY`.
- Configure **SMTP Settings** for password-reset emails.
- Manage **System Settings** such as log verbosity, CORS origins, and
  the LLM optimization mode.

This keeps secrets out of source-controlled config files and lets
admins rotate credentials without redeploying.

---

Happy configuring! 🎛️
