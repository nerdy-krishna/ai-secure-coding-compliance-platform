# src/app/config/config.py
import math
import urllib.parse
from typing import List, Literal, Optional

from pydantic import SecretStr, field_validator, model_validator, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore", frozen=True
    )

    # --- Database Configuration ---
    POSTGRES_USER: str
    POSTGRES_PASSWORD: SecretStr
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: int
    POSTGRES_HOST_ALEMBIC: str
    DB_ECHO: bool = False

    # Derived database URLs
    ASYNC_DATABASE_URL: Optional[str] = None
    ALEMBIC_DATABASE_URL: Optional[str] = None

    @field_validator("ASYNC_DATABASE_URL", mode="before")
    def assemble_async_db_connection(cls, v, info):
        if v:
            return v
        values = info.data
        pw_obj = values.get("POSTGRES_PASSWORD")
        pw = urllib.parse.quote(
            (
                pw_obj.get_secret_value()
                if hasattr(pw_obj, "get_secret_value")
                else (pw_obj or "")
            ),
            safe="",
        )
        user = urllib.parse.quote(values.get("POSTGRES_USER") or "", safe="")
        return f"postgresql+asyncpg://{user}:{pw}@{values.get('POSTGRES_HOST')}:{values.get('POSTGRES_PORT')}/{values.get('POSTGRES_DB')}"

    @field_validator("ALEMBIC_DATABASE_URL", mode="before")
    def assemble_alembic_db_connection(cls, v, info):
        if v:
            return v
        values = info.data
        pw_obj = values.get("POSTGRES_PASSWORD")
        pw = urllib.parse.quote(
            (
                pw_obj.get_secret_value()
                if hasattr(pw_obj, "get_secret_value")
                else (pw_obj or "")
            ),
            safe="",
        )
        user = urllib.parse.quote(values.get("POSTGRES_USER") or "", safe="")
        return f"postgresql+asyncpg://{user}:{pw}@{values.get('POSTGRES_HOST_ALEMBIC')}:{values.get('POSTGRES_PORT')}/{values.get('POSTGRES_DB')}"

    # --- RabbitMQ Configuration (UPDATED) ---
    RABBITMQ_DEFAULT_USER: str
    RABBITMQ_DEFAULT_PASS: SecretStr
    RABBITMQ_HOST: str
    RABBITMQ_URL: Optional[str] = None

    # Renamed CODE_QUEUE for clarity and added the new approval queue
    RABBITMQ_SUBMISSION_QUEUE: str = "code_submission_queue"
    RABBITMQ_APPROVAL_QUEUE: str = "analysis_approved_queue"
    RABBITMQ_REMEDIATION_QUEUE: str = "remediation_trigger_queue"

    @field_validator("RABBITMQ_URL", mode="before")
    def assemble_rabbitmq_connection(cls, v, info):
        if v:
            return v
        values = info.data
        pw_obj = values.get("RABBITMQ_DEFAULT_PASS")
        pw = urllib.parse.quote(
            (
                pw_obj.get_secret_value()
                if hasattr(pw_obj, "get_secret_value")
                else (pw_obj or "")
            ),
            safe="",
        )
        user = urllib.parse.quote(values.get("RABBITMQ_DEFAULT_USER") or "", safe="")
        return f"amqp://{user}:{pw}@{values.get('RABBITMQ_HOST')}/"

    # --- Email (SMTP) Configuration ---
    SMTP_HOST: Optional[str] = None
    SMTP_PORT: int = 587
    SMTP_USER: Optional[str] = None
    SMTP_PASSWORD: Optional[SecretStr] = None
    SMTP_FROM: Optional[str] = None
    SMTP_TLS: bool = True
    SMTP_SSL: bool = False

    # --- Security & Auth ---
    SECRET_KEY: SecretStr
    ENCRYPTION_KEY: SecretStr
    ENVIRONMENT: Literal["development", "staging", "production"] = "development"
    ACCESS_TOKEN_LIFETIME_SECONDS: int = 60 * 60  # 60 minutes
    REFRESH_TOKEN_LIFETIME_SECONDS: int = 60 * 60 * 24 * 7  # 7 days
    # Absolute session lifetime: hard ceiling on how long a single login
    # session can be extended via refresh-token rotation. Default 24 h.
    # Ceiling 7 d (matches REFRESH_TOKEN_LIFETIME_SECONDS — anything longer
    # would be meaningless because the refresh token itself has expired).
    # Admin can override at runtime via system_config["security.session_lifetime_hours"]
    # (see SystemConfigCache.session_lifetime_hours).
    SESSION_ABSOLUTE_LIFETIME_SECONDS: int = Field(
        default=60 * 60 * 24,
        ge=300,
        le=60 * 60 * 24 * 7,
    )

    ALLOWED_ORIGINS_STR: str = Field(alias="ALLOWED_ORIGINS")

    @property
    def ALLOWED_ORIGINS(self) -> List[str]:
        return [origin.strip() for origin in self.ALLOWED_ORIGINS_STR.split(",")]

    # Canonical public URL for the frontend — used when building absolute links
    # in emails (password reset, verification). Falls back to the first entry
    # in ALLOWED_ORIGINS if unset; fail-fast in production if neither is usable.
    FRONTEND_BASE_URL: Optional[str] = None

    # Canonical public URL for the API (split-origin deployments). When the
    # frontend and API live on different origins (e.g. ui.x.com + api.x.com),
    # SSO callback / ACS URIs must be built from this — registering them at
    # the IdP otherwise points back at the frontend host. Defaults to None →
    # SSO callbacks are built from `frontend_base_url` (single-origin deploys).
    API_BASE_URL: Optional[str] = None

    # Hard cap on the body size of POST /api/v1/auth/login (force-SSO
    # middleware buffers the body to replay it; cap at 64 KiB by default —
    # login bodies are tiny). Bumped via env for installs with non-standard
    # form sizes.
    LOGIN_BODY_MAX_BYTES: int = Field(default=64 * 1024, ge=1024, le=1_048_576)

    # Comma-separated list of CIDR blocks for trusted reverse proxies.
    # When the connecting peer (`request.client.host`) is in one of these
    # CIDRs, the SSO audit recorder honors `X-Forwarded-For` (rightmost-untrusted)
    # so audit rows carry the real client IP rather than the load balancer.
    # Default empty → never trust XFF (single-host deploys).
    TRUSTED_PROXY_CIDRS_STR: str = Field(default="", alias="TRUSTED_PROXY_CIDRS")

    @property
    def TRUSTED_PROXY_CIDRS(self) -> List[str]:
        return [c.strip() for c in self.TRUSTED_PROXY_CIDRS_STR.split(",") if c.strip()]

    @property
    def api_base_url(self) -> str:
        """Canonical API base URL. Falls back to ``frontend_base_url`` when
        ``API_BASE_URL`` is unset (single-origin deploys)."""
        if self.API_BASE_URL:
            return self.API_BASE_URL.rstrip("/")
        return self.frontend_base_url

    @property
    def frontend_base_url(self) -> str:
        """Canonical public URL for the frontend. Resolution order:

        1. ``FRONTEND_BASE_URL`` env var (explicit operator override).
        2. First entry of ``security.allowed_origins`` from the DB (the value
           setup persists at first-run; this is what the operator picked at
           setup time and is the right answer for password-reset links).
        3. First entry of the env-level ``ALLOWED_ORIGINS`` (back-compat for
           pre-setup boot — Vite dev server hint).
        4. ``http://localhost:5173`` for dev/test environments.
        """
        if self.FRONTEND_BASE_URL:
            return self.FRONTEND_BASE_URL.rstrip("/")
        # Prefer the setup-time-stored origin so email links use the canonical
        # host the operator entered at /setup, not the dev fallback.
        try:
            from app.core.config_cache import SystemConfigCache

            db_origins = SystemConfigCache.get_allowed_origins() or []
        except Exception:
            db_origins = []
        if db_origins and db_origins[0]:
            return db_origins[0].rstrip("/")
        env_origins = self.ALLOWED_ORIGINS
        if env_origins and env_origins[0]:
            return env_origins[0].rstrip("/")
        if self.ENVIRONMENT not in {"development", "local", "test"}:
            raise RuntimeError(
                "FRONTEND_BASE_URL is not set and ALLOWED_ORIGINS is empty. "
                "Configure one of them so email links can be built."
            )
        return "http://localhost:5173"

    # --- Rate Limiting (NEW) ---
    # Requests Per Minute (RPM) for each LLM provider.
    # Use Optional[int] = None to disable rate limiting for a provider instead of 0.
    OPENAI_REQUESTS_PER_MINUTE: int = Field(
        default=60, ge=1, description="Max RPM for OpenAI models."
    )
    OPENAI_TOKENS_PER_MINUTE: int = Field(
        default=30000, ge=1, description="Max TPM for OpenAI models."
    )
    GOOGLE_REQUESTS_PER_MINUTE: int = Field(
        default=60, ge=1, description="Max RPM for Google models."
    )
    GOOGLE_TOKENS_PER_MINUTE: int = Field(
        default=60000, ge=1, description="Max TPM for Google models."
    )
    ANTHROPIC_REQUESTS_PER_MINUTE: int = Field(
        default=30, ge=1, description="Max RPM for Anthropic models."
    )
    ANTHROPIC_TOKENS_PER_MINUTE: int = Field(
        default=20000, ge=1, description="Max TPM for Anthropic models."
    )

    # --- Worker ---
    # Hard upper bound for a single scan workflow invocation. If exceeded, the
    # workflow is cancelled, the scan marked FAILED, and the RabbitMQ message
    # NACK'd (without requeue) so it doesn't loop forever. Default: 2 hours.
    SCAN_WORKFLOW_TIMEOUT_SECONDS: int = Field(
        default=2 * 60 * 60, description="Max seconds a single scan workflow may run."
    )

    # --- RAG vector store (Qdrant only; ADR-008 supersedes ADR-007) ---
    QDRANT_HOST: str = "qdrant"
    QDRANT_PORT: int = 6333
    # The bundled docker-compose Qdrant has no TLS terminator — it
    # serves plain HTTP on the operator network. Default False so
    # local dev works out of the box. Set QDRANT_USE_TLS=true in .env
    # when an operator puts a TLS reverse proxy in front of Qdrant.
    # When True, qdrant_store.QdrantStore initialises the client with
    # https=True so the API key is never sent in cleartext.
    QDRANT_USE_TLS: bool = False
    # Mandatory. Validator below rejects empty + the .env.example
    # placeholder so a half-configured deploy fails fast at Settings
    # load time rather than 500-ing on the first scan.
    QDRANT_API_KEY: SecretStr

    @field_validator("QDRANT_API_KEY")
    def _validate_qdrant_api_key(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value() if hasattr(v, "get_secret_value") else str(v)
        if not raw:
            raise ValueError(
                "QDRANT_API_KEY is required. Set it in .env (see .env.example) "
                "and restart."
            )
        if raw == "change-me-qdrant-key":
            raise ValueError(
                "QDRANT_API_KEY is set to the .env.example placeholder "
                "('change-me-qdrant-key'). Generate a real key (e.g. "
                "`openssl rand -hex 32`) and put it in .env, then restart."
            )
        return v

    @field_validator("SECRET_KEY")
    def _validate_secret_key(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value() if hasattr(v, "get_secret_value") else str(v)
        if raw == "supersecretkey1234567890":
            raise ValueError(
                "SECRET_KEY is set to the .env.example placeholder; generate a real one "
                "via `python scripts/generate_secrets.py random` and put it in .env, then restart."
            )
        if len(raw) < 32:
            raise ValueError(
                "SECRET_KEY must be at least 32 characters (>=128 bits). "
                "Generate a real key via `python scripts/generate_secrets.py random`."
            )
        # Reject low-entropy keys (Shannon entropy < 3.5 bits/char)
        if raw:
            freq = {}
            for c in raw:
                freq[c] = freq.get(c, 0) + 1
            entropy = -sum(
                (f / len(raw)) * math.log2(f / len(raw)) for f in freq.values()
            )
            if entropy < 3.5:
                raise ValueError(
                    "SECRET_KEY has insufficient entropy. "
                    "Generate a real key via `python scripts/generate_secrets.py random`."
                )
        return v

    @field_validator("ENCRYPTION_KEY")
    def _validate_encryption_key(cls, v: SecretStr) -> SecretStr:
        from cryptography.fernet import Fernet  # noqa: PLC0415

        raw = v.get_secret_value() if hasattr(v, "get_secret_value") else str(v)
        if raw == "0" * 64:
            raise ValueError(
                "ENCRYPTION_KEY is set to an all-zero placeholder; generate a real Fernet key "
                'via `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.'
            )
        try:
            Fernet(raw.encode())
        except Exception:
            raise ValueError(
                "ENCRYPTION_KEY must be a valid 32-byte url-safe base64 Fernet key. "
                'Generate one via `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`.'
            )
        return v

    # --- Observability (Langfuse v3, optional) ---
    # Disabled by default; opt in by setting LANGFUSE_ENABLED=true plus the
    # public/secret keys minted from the self-hosted Langfuse UI. When
    # disabled, all instrumentation short-circuits — zero overhead, zero
    # network traffic. See `app.infrastructure.observability` and the run
    # `langfuse-otel-observability`.
    LANGFUSE_ENABLED: bool = False
    LANGFUSE_HOST: str = "https://langfuse-web:3000"
    LANGFUSE_PUBLIC_KEY: Optional[SecretStr] = None
    LANGFUSE_SECRET_KEY: Optional[SecretStr] = None

    @field_validator("LANGFUSE_HOST")
    def _validate_langfuse_host(cls, v: str) -> str:
        # Enforce https for non-loopback hosts; loopback may use http for local dev
        import ipaddress  # noqa: PLC0415

        loopback_hostnames = {"localhost", "127.0.0.1", "::1"}
        from urllib.parse import urlparse  # noqa: PLC0415

        parsed = urlparse(v)
        hostname = parsed.hostname or ""
        is_loopback = hostname in loopback_hostnames
        try:
            is_loopback = is_loopback or ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            pass
        if not is_loopback and not v.startswith("https://"):
            raise ValueError(
                "LANGFUSE_HOST must use https:// for non-loopback hosts to prevent "
                "LANGFUSE_PUBLIC_KEY/LANGFUSE_SECRET_KEY from leaking in plaintext."
            )
        return v

    @field_validator("FRONTEND_BASE_URL")
    def _validate_frontend_base_url(cls, v: Optional[str]) -> Optional[str]:
        if v and not v.startswith("https://"):
            raise ValueError(
                "FRONTEND_BASE_URL must use https:// in all environments to prevent "
                "insecure email links."
            )
        return v

    @field_validator("API_BASE_URL")
    def _validate_api_base_url(cls, v: Optional[str]) -> Optional[str]:
        # Mirror FRONTEND_BASE_URL: https-only when set. SSO callbacks are
        # registered at IdPs with this URL — http would let any IdP-issued
        # token / authorization-code reach SCCAP over an interceptable
        # channel. Most IdPs reject http redirect_uri anyway; this surfaces
        # the misconfiguration at startup instead of at first IdP call.
        if v and not v.startswith("https://"):
            raise ValueError(
                "API_BASE_URL must use https:// in all environments to prevent "
                "interception of SSO callback tokens."
            )
        return v

    @model_validator(mode="after")
    def _model_invariants(self) -> "Settings":
        # SMTP_TLS and SMTP_SSL are mutually exclusive (V02.2.3)
        if self.SMTP_TLS and self.SMTP_SSL:
            raise ValueError(
                "SMTP_TLS and SMTP_SSL are mutually exclusive; set only one."
            )
        # Production invariants (V13.4.2)
        if self.ENVIRONMENT == "production":
            if self.DB_ECHO:
                raise ValueError("DB_ECHO must be False in production.")
            if self.LANGFUSE_ENABLED and (
                self.LANGFUSE_PUBLIC_KEY is None or self.LANGFUSE_SECRET_KEY is None
            ):
                raise ValueError(
                    "LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY must be set when "
                    "LANGFUSE_ENABLED is True in production."
                )
        return self


settings = Settings()  # type: ignore
