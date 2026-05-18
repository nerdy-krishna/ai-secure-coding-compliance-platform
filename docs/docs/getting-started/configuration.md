# Configuration Guide

The SCCAP is configured primarily through environment variables defined in a `.env` file located in the project root.

> ⚠️ It is crucial to set up this file correctly before running the application.

Start by copying the example file to create your own local configuration:

```bash
cp .env.example .env
```

> ❗ **Never commit your actual `.env` file with sensitive credentials to version control.**

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
| `ACCESS_TOKEN_LIFETIME_SECONDS` | Access token expiry time | `1800` | 30 minutes |
| `REFRESH_TOKEN_LIFETIME_SECONDS` | Refresh token lifetime | `604800` | 7 days |

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

---

## 📬 RabbitMQ Message Queue

| Variable | Description | Example |
| -------- | ----------- | ------- |
| `RABBITMQ_DEFAULT_USER` | RabbitMQ username | `devuser_scp` |
| `RABBITMQ_DEFAULT_PASS` | RabbitMQ password | `yoursecurepassword` |
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

Every LLM interaction is priced through `litellm.token_counter(...)` +
`litellm.cost_per_token(...)`. The `llm_configurations` table lets
admins provide an override (non-zero `input_cost_per_million` /
`output_cost_per_million`) for bespoke endpoints (Azure, private
deployments); otherwise LiteLLM's community-maintained price map is
used. See
[Architecture → LLM Integration](../architecture/llm-integration.md)
for the full data flow.

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
