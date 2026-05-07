# src/app/main.py

import asyncio
import logging
import logging.config
import os
import uuid
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from psycopg.errors import DuplicateColumn
from starlette.responses import JSONResponse

from app.api.v1.routers.projects import router as projects_router
from app.api.v1.routers.admin import llm_router
from app.api.v1.routers.admin_frameworks import framework_router
from app.api.v1.routers.admin_agents import agent_router
from app.api.v1.routers.admin_prompts import prompt_router
from app.api.v1.routers.admin_rag import rag_router
from app.api.v1.routers.admin_logs import router as logs_router
from app.api.v1.routers.chat import router as chat_router
from app.api.v1.routers.compliance import router as compliance_router
from app.api.v1.routers.refresh import router as refresh_router
from app.api.v1.routers.setup import router as setup_router
from app.api.v1.routers.admin_config import router as admin_config_router
from app.api.v1.routers.admin_smtp import router as admin_smtp_router
from app.api.v1.routers.admin_findings import router as admin_findings_router
from app.api.v1.routers.admin_groups import router as admin_groups_router
from app.api.v1.routers.admin_seed import router as admin_seed_router
from app.api.v1.routers.dashboard import router as dashboard_router
from app.api.v1.routers.search import router as search_router
from app.infrastructure.auth.backend import auth_backend
from app.infrastructure.auth.core import fastapi_users
from app.infrastructure.auth.schemas import UserRead, UserUpdate
from typing import Optional

from app.config.config import settings
from app.infrastructure.llm_client_rate_limiter import initialize_rate_limiters
from app.config.logging_config import LOGGING_CONFIG, correlation_id_var
from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

# Apply the logging configuration right at the start
logging.config.dictConfig(LOGGING_CONFIG)
logging.captureWarnings(True)

# Get the logger for this module
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # This code runs on application startup
    logger.info("Application startup...")

    # Initialize global rate limiters for LLM providers
    initialize_rate_limiters()

    if settings.ASYNC_DATABASE_URL:
        logger.info("Setting up database checkpointer tables...")
        try:
            # FIX: Convert the SQLAlchemy URL to a standard psycopg/asyncpg URL
            conn_str = settings.ASYNC_DATABASE_URL.replace(
                "postgresql+asyncpg", "postgresql"
            )

            async with AsyncPostgresSaver.from_conn_string(conn_str) as checkpointer:
                await checkpointer.setup()
            logger.info("Checkpointer tables setup complete.")
        except DuplicateColumn as e:
            logger.info(
                f"Checkpointer tables already exist, which is expected. Details: {e}. Continuing..."
            )
        except Exception as e:
            logger.error(
                f"Failed to setup checkpointer tables on startup: {e}", exc_info=True
            )
    else:
        logger.warning("Database URL not set, skipping checkpointer setup.")

    # --- Initialize System Configuration Cache ---
    from app.core.config_cache import SystemConfigCache
    from app.infrastructure.database.database import AsyncSessionLocal
    from app.infrastructure.database.repositories.system_config_repo import (
        SystemConfigRepository,
    )
    from app.api.v1.routers.setup import is_setup_completed
    from app.config.logging_config import update_logging_level

    # Lifespan-health observability (V14.1.2): announce hydration entry at
    # WARNING so the line survives even when admins set system.log_level to
    # ERROR (silencing INFO chatter). A matching WARNING summary fires after
    # the block completes, giving operators a guaranteed before/after pair.
    logger.warning("lifespan.cache_hydration.starting")
    # Defensive defaults — if the cache hydration block raises before
    # assigning these, the deferred-log-level apply path below stays sane.
    target_log_level: Optional[str] = "INFO"
    log_level_source = "fallback"
    try:
        async with AsyncSessionLocal() as session:
            # Check if setup is completed
            setup_done = await is_setup_completed(session)
            SystemConfigCache.set_setup_completed(setup_done)

            repo = SystemConfigRepository(session)

            # --- Resolve log level (apply LATER, after the lifespan summary) ---
            # The operator-configured log level is intentionally NOT applied
            # here. If we applied it now and the operator set ERROR, every
            # subsequent INFO/WARNING log line in the lifespan would be
            # filtered out — operators end up unable to confirm the cache
            # hydrated. We compute the target level here, finish the rest
            # of the lifespan at the default level, emit the
            # `lifespan.cache_hydration.done` health summary, and only THEN
            # call `update_logging_level(...)` (see end of this block).
            log_level_config = await repo.get_by_key("system.log_level")
            target_log_level: Optional[str] = None
            log_level_source = "default"
            if log_level_config and log_level_config.value:
                val = log_level_config.value
                if isinstance(val, dict) and "level" in val:
                    target_log_level = str(val["level"]).upper()
                else:
                    target_log_level = str(val).upper()
                log_level_source = "db"
            elif getattr(settings, "DEBUG", False):
                # V13.4.2: never auto-force DEBUG; DEBUG must be opt-in via
                # an explicit env/settings flag so a partially provisioned
                # host cannot leak request payloads / stack traces.
                target_log_level = "DEBUG"
                log_level_source = "settings.DEBUG"
            else:
                target_log_level = "INFO"
                log_level_source = "fallback"
            logger.info(
                "lifespan.log_level.resolved",
                extra={"level": target_log_level, "source": log_level_source},
            )

            if setup_done:
                # Load allowed origins from DB
                config = await repo.get_by_key("security.allowed_origins")
                cors_enabled_config = await repo.get_by_key("security.cors_enabled")

                # Load CORS Enabled status
                cors_enabled = False
                if cors_enabled_config and cors_enabled_config.value is not None:
                    val = cors_enabled_config.value
                    if isinstance(val, dict) and "enabled" in val:
                        cors_enabled = bool(val["enabled"])
                    else:
                        cors_enabled = bool(val)

                SystemConfigCache.set_cors_enabled(cors_enabled)
                logger.info(f"CORS Enabled: {cors_enabled}")

                if (
                    config
                    and isinstance(config.value, dict)
                    and "origins" in config.value
                ):
                    SystemConfigCache.set_allowed_origins(config.value["origins"])
                    logger.info(
                        f"Loaded allowed origins from DB: {config.value['origins']}"
                    )
                else:
                    # Fallback to env var if DB config missing but setup is done
                    allowed_origins_str = os.getenv(
                        "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
                    )
                    origins = [
                        o.strip() for o in allowed_origins_str.split(",") if o.strip()
                    ]
                    SystemConfigCache.set_allowed_origins(origins)
                    logger.info(f"Loaded allowed origins from ENV: {origins}")
                # Load SMTP configuration — try new multi-profile format first,
                # fall back to legacy system.smtp encrypted blob.
                smtp_loaded = False
                smtp_profiles_row = await repo.get_by_key("smtp.profiles")
                if smtp_profiles_row and isinstance(smtp_profiles_row.value, dict):
                    from app.api.v1.routers.admin_smtp import _reload_smtp_cache

                    active_id = smtp_profiles_row.value.get("active_id")
                    await _reload_smtp_cache(repo, active_id)
                    smtp_loaded = True
                    logger.info("Loaded SMTP configuration from smtp.profiles.")
                if not smtp_loaded:
                    smtp_config = await repo.get_by_key("system.smtp")
                    if smtp_config and isinstance(smtp_config.value, dict):
                        SystemConfigCache.set_smtp_config(smtp_config.value)
                        logger.info(
                            "Loaded SMTP configuration from legacy system.smtp key."
                        )
                    else:
                        SystemConfigCache.set_smtp_config(None)
                        logger.info("No SMTP configuration found in DB.")

                # Load LLM optimization mode from DB
                llm_mode_config = await repo.get_by_key("llm.optimization_mode")
                if llm_mode_config and llm_mode_config.value:
                    raw = llm_mode_config.value
                    mode_str = raw.get("mode") if isinstance(raw, dict) else str(raw)
                    if mode_str:
                        try:
                            SystemConfigCache.set_llm_mode(mode_str)
                        except ValueError as exc:
                            logger.warning(
                                "LLM optimization mode invalid in DB (%s); using default.",
                                exc,
                            )
                    logger.info(
                        f"LLM optimization mode: {SystemConfigCache.get_llm_mode()}"
                    )
                else:
                    logger.info(
                        f"No LLM optimization mode configured; defaulting to "
                        f"{SystemConfigCache.get_llm_mode()}."
                    )

                # V14.2.7 — load retention windows for chat / LLM-interaction / RAG-job.
                # Admins set these via /admin/system-config; falls back to in-code
                # defaults (DEFAULT_RETENTION_DAYS) if a key is absent.
                from app.core.config_cache import (
                    RETENTION_KIND_CHAT_MESSAGE,
                    RETENTION_KIND_LLM_INTERACTION,
                    RETENTION_KIND_RAG_JOB,
                )

                for retention_key, retention_kind in [
                    (
                        "system.retention.llm_interaction_days",
                        RETENTION_KIND_LLM_INTERACTION,
                    ),
                    (
                        "system.retention.chat_message_days",
                        RETENTION_KIND_CHAT_MESSAGE,
                    ),
                    ("system.retention.rag_job_days", RETENTION_KIND_RAG_JOB),
                ]:
                    cfg = await repo.get_by_key(retention_key)
                    if cfg and isinstance(cfg.value, dict) and "days" in cfg.value:
                        try:
                            SystemConfigCache.set_retention_days(
                                retention_kind, int(cfg.value["days"])
                            )
                        except (TypeError, ValueError):
                            logger.warning(
                                "Invalid retention days in DB for %s; using default.",
                                retention_key,
                            )
                logger.info(
                    "Retention windows: llm=%dd chat=%dd rag=%dd",
                    SystemConfigCache.get_retention_days(
                        RETENTION_KIND_LLM_INTERACTION
                    ),
                    SystemConfigCache.get_retention_days(RETENTION_KIND_CHAT_MESSAGE),
                    SystemConfigCache.get_retention_days(RETENTION_KIND_RAG_JOB),
                )

                # Session lifetime (admin override). Stored as
                # system_config["security.session_lifetime_hours"] = {"hours": N}.
                slh_cfg = await repo.get_by_key("security.session_lifetime_hours")
                if (
                    slh_cfg
                    and isinstance(slh_cfg.value, dict)
                    and "hours" in slh_cfg.value
                ):
                    try:
                        SystemConfigCache.set_session_lifetime_hours(
                            int(slh_cfg.value["hours"])
                        )
                    except (TypeError, ValueError):
                        logger.warning(
                            "Invalid security.session_lifetime_hours in DB; using settings default.",
                        )

                # M6: master-admin user id (escape hatch for force-SSO).
                ma_cfg = await repo.get_by_key("security.master_admin_user_id")
                if (
                    ma_cfg
                    and isinstance(ma_cfg.value, dict)
                    and "user_id" in ma_cfg.value
                ):
                    try:
                        SystemConfigCache.set_master_admin_user_id(
                            int(ma_cfg.value["user_id"])
                        )
                    except (TypeError, ValueError):
                        logger.warning(
                            "Invalid security.master_admin_user_id in DB; ignoring.",
                        )
                else:
                    # Backfill: if setup is done but master_admin_user_id is unset
                    # (e.g. the first user pre-dates this code), persist MIN(id) now.
                    from sqlalchemy import select, func
                    from app.infrastructure.database.models import User as _UserModel

                    res = await session.execute(select(func.min(_UserModel.id)))
                    min_id = res.scalar()
                    if min_id is not None:
                        from app.api.v1 import models as _api_models

                        await repo.set_value(
                            _api_models.SystemConfigurationCreate(
                                key="security.master_admin_user_id",
                                value={"user_id": int(min_id)},
                                description="Master admin user id (force-SSO escape hatch).",
                                is_secret=False,
                                encrypted=False,
                            )
                        )
                        SystemConfigCache.set_master_admin_user_id(int(min_id))
                        logger.info(
                            "Master-admin id backfilled from MIN(users.id) = %d",
                            int(min_id),
                        )

            else:
                logger.info("Setup not completed. Allowing all origins for setup mode.")
                SystemConfigCache.set_cors_enabled(True)  # Enable CORS for setup

            # V02.2.3: cross-validate combined config fields for consistency.
            if (
                SystemConfigCache.is_cors_enabled()
                and not SystemConfigCache.get_allowed_origins()
                and setup_done
            ):
                logger.warning("CORS enabled but allow-list empty; disabling CORS.")
                SystemConfigCache.set_cors_enabled(False)
    except Exception as e:
        # exc_info so the stack trace lands in Loki regardless of level
        # filtering downstream.
        logger.error(
            "lifespan.cache_hydration.failed", extra={"error": str(e)}, exc_info=True
        )
    # Final health summary at WARNING. Emitted before the operator-chosen
    # log level kicks in, so the line is always visible regardless of the
    # configured log level downstream.
    try:
        cors_state = "enabled" if SystemConfigCache.is_cors_enabled() else "disabled"
        origin_count = len(SystemConfigCache.get_allowed_origins() or [])
        smtp_loaded = SystemConfigCache.get_smtp_config() is not None
        master_id = SystemConfigCache.get_master_admin_user_id()
        slh = SystemConfigCache.get_session_lifetime_hours()
        logger.warning(
            "lifespan.cache_hydration.done",
            extra={
                "setup_completed": SystemConfigCache.is_setup_completed(),
                "cors": cors_state,
                "allowed_origin_count": origin_count,
                "smtp_loaded": smtp_loaded,
                "master_admin_user_id": master_id,
                "session_lifetime_hours": slh,
            },
        )
    except Exception:
        # Summary must NEVER fail the lifespan — observability shouldn't
        # block startup.
        logger.error("lifespan.cache_hydration.summary_failed", exc_info=True)

    # Now apply the operator-chosen log level — runtime traffic logs respect
    # it, but the lifespan health log lines above are guaranteed to have
    # been emitted at the default level first. Log BEFORE applying so the
    # message survives even when target_log_level == ERROR (otherwise the
    # WARNING is filtered immediately by the level change).
    try:
        if target_log_level:
            logger.warning(
                "lifespan.log_level.applying",
                extra={"level": target_log_level, "source": log_level_source},
            )
            update_logging_level(target_log_level)
    except Exception:
        logger.error(
            "lifespan.log_level.apply_failed",
            extra={"target": target_log_level},
            exc_info=True,
        )

    # --- Auto-seed defaults on empty DB ---
    # Single source of truth lives in default_seed_service. If the DB has
    # zero agents AND zero prompt templates we consider it a fresh install
    # and seed the canonical defaults (3 OWASP frameworks, 17 specialized
    # agents, their audit / remediation / chat prompts). If any of those
    # tables already have rows we leave them alone — admins can re-seed
    # from the Admin UI or via `POST /api/v1/admin/seed/defaults`.
    try:
        from app.core.services.default_seed_service import seed_if_empty

        async with AsyncSessionLocal() as session:
            result = await seed_if_empty(session)
            if result.frameworks_added or result.agents_added or result.templates_added:
                logger.info(
                    "Auto-seed inserted %d frameworks, %d agents, %d prompt "
                    "templates.",
                    result.frameworks_added,
                    result.agents_added,
                    result.templates_added,
                )
    except Exception as e:
        logger.error(f"Failed to auto-seed defaults: {e}")

    # --- Eager-build the vector store (ADR-008) ---
    # Warming the singleton at startup avoids the ~50–200 ms event-loop
    # stall the lazy path causes when the first concurrent caller hits
    # `threading.Lock` mid-request. Wrapped in try/except so a Qdrant
    # outage at boot doesn't block lifespan; the next caller retries
    # via the same lazy path. Threat-model G8.
    if os.getenv("RAG_VECTOR_STORE"):
        # Mitigation 6: ADR-008 dropped the flag entirely; warn the
        # operator that their .env line is no longer honored.
        logger.warning(
            "RAG_VECTOR_STORE is set in env but no longer used; the platform "
            "runs on Qdrant only (ADR-008). Remove the line from .env."
        )
    try:
        from app.infrastructure.rag.factory import get_vector_store

        get_vector_store()
        logger.info("Vector store ready (Qdrant)")
    except Exception as e:
        logger.warning(
            "Vector store eager-build failed; lazy retry on first call: %s",
            e,
        )

    # --- Start the outbox sweeper ---
    from app.infrastructure.messaging.outbox_sweeper import run_outbox_sweeper

    sweeper_stop = asyncio.Event()
    sweeper_task = asyncio.create_task(
        run_outbox_sweeper(sweeper_stop), name="outbox-sweeper"
    )

    # --- Start the prescan-approval auto-decline sweeper (ADR-009) ---
    # Transitions scans stuck in PENDING_PRESCAN_APPROVAL > 24h to
    # BLOCKED_USER_DECLINE. Runs on the API container since the worker
    # is the producer of the stuck state.
    from app.infrastructure.messaging.prescan_approval_sweeper import (
        run_prescan_approval_sweeper,
    )

    prescan_sweeper_stop = asyncio.Event()
    prescan_sweeper_task = asyncio.create_task(
        run_prescan_approval_sweeper(prescan_sweeper_stop),
        name="prescan-approval-sweeper",
    )

    # --- Start the findings.source backfill sweeper (Feature-7 B3) ---
    # Defensive catch for any `findings.source IS NULL` rows that
    # land after the initial backfill. With B1 in place (LLM agent
    # sets source="agent" at write time), this should be a no-op in
    # steady state — bounded UPDATE per hour, zero overhead when the
    # table is clean.
    from app.infrastructure.messaging.findings_source_sweeper import (
        run_findings_source_sweeper,
    )

    findings_source_sweeper_stop = asyncio.Event()
    findings_source_sweeper_task = asyncio.create_task(
        run_findings_source_sweeper(findings_source_sweeper_stop),
        name="findings-source-sweeper",
    )

    # --- Start the retention sweeper (V14.2.7) -------------------------------
    # Hourly: deletes rows whose `expires_at` is in the past from
    # llm_interactions / chat_messages / rag_preprocessing_jobs.
    from app.infrastructure.messaging.retention_sweeper import run_retention_sweeper

    retention_sweeper_stop = asyncio.Event()
    retention_sweeper_task = asyncio.create_task(
        run_retention_sweeper(retention_sweeper_stop),
        name="retention-sweeper",
    )

    # --- Semgrep ingestion: reset stuck runs + upsert config defaults ---
    try:
        from app.infrastructure.database.repositories.semgrep_rule_repo import (
            SemgrepRuleRepository,
        )

        async with AsyncSessionLocal() as db:
            async with db.begin():
                await SemgrepRuleRepository(db).reset_stuck_runs()

        # Upsert semgrep_ingestion.* system config keys with defaults so the
        # GET /admin/rule-sources/settings endpoint always has something to return.
        from app.infrastructure.database import models as db_models

        _SEMGREP_CONFIG_DEFAULTS = {
            "semgrep_ingestion.global_enabled": {"value": True},
            "semgrep_ingestion.workdir": {
                "value": "/tmp/sccap-semgrep-rules"
            },  # nosec B108 — configurable default, not a tmpfile call
            "semgrep_ingestion.sweep_interval_seconds": {"value": 900},
            "semgrep_ingestion.max_rules_per_scan": {"value": 5000},
            "semgrep_ingestion.allowed_licenses": {
                "licenses": [
                    "MIT",
                    "Apache-2.0",
                    "BSD-2-Clause",
                    "BSD-3-Clause",
                    "MPL-2.0",
                    "LGPL-2.0",
                    "LGPL-2.1",
                    "LGPL-3.0",
                    "Semgrep-Rules-License-1.0",
                ]
            },
        }
        from sqlalchemy import select as _sa_select

        async with AsyncSessionLocal() as db:
            async with db.begin():
                for key, default_val in _SEMGREP_CONFIG_DEFAULTS.items():
                    existing = await db.scalar(
                        _sa_select(db_models.SystemConfiguration).where(
                            db_models.SystemConfiguration.key == key
                        )
                    )
                    if existing is None:
                        db.add(
                            db_models.SystemConfiguration(key=key, value=default_val)
                        )
        logger.info("semgrep_ingestion: config defaults upserted")
    except Exception as exc:
        logger.error("semgrep_ingestion: startup init failed: %s", exc, exc_info=True)

    # --- Start the Semgrep sync sweeper ---
    from app.infrastructure.messaging.semgrep_sync_sweeper import (
        run_semgrep_sync_sweeper,
    )

    semgrep_sweeper_stop = asyncio.Event()
    semgrep_sweeper_task = asyncio.create_task(
        run_semgrep_sync_sweeper(semgrep_sweeper_stop),
        name="semgrep-sync-sweeper",
    )

    # --- Start the scan-progress LISTEN/NOTIFY bus (§3.10a) ---
    # Replaces the per-SSE-client 1 Hz Postgres poll with a single
    # LISTEN connection per app process that fans out scan-status /
    # scan-event notifications to in-process queues. SSE handlers
    # subscribe + await rather than poll.
    from app.infrastructure.messaging.scan_progress_notifier import (
        ScanProgressBus,
        set_scan_progress_bus,
    )

    progress_bus = ScanProgressBus()
    try:
        await progress_bus.start()
        set_scan_progress_bus(progress_bus)
    except Exception as e:
        logger.warning(
            "scan_progress: bus failed to start: %s; SSE handlers will "
            "fall back to polling.",
            e,
        )
        progress_bus = None

    yield

    # This code runs on shutdown
    logger.info("Application shutdown.")
    sweeper_stop.set()
    prescan_sweeper_stop.set()
    findings_source_sweeper_stop.set()
    retention_sweeper_stop.set()
    semgrep_sweeper_stop.set()
    if progress_bus is not None:
        try:
            await progress_bus.stop()
        except Exception as e:
            logger.warning(f"scan_progress: bus shutdown error: {e}")
    set_scan_progress_bus(None)
    try:
        await asyncio.wait_for(sweeper_task, timeout=5)
    except asyncio.TimeoutError:
        logger.warning("Outbox sweeper did not stop within 5s; cancelling.")
        sweeper_task.cancel()
    except Exception as e:
        logger.warning(f"Outbox sweeper shutdown error: {e}")
    try:
        await asyncio.wait_for(prescan_sweeper_task, timeout=5)
    except asyncio.TimeoutError:
        logger.warning("Prescan-approval sweeper did not stop within 5s; cancelling.")
        prescan_sweeper_task.cancel()
    except Exception as e:
        logger.warning(f"Prescan-approval sweeper shutdown error: {e}")
    try:
        await asyncio.wait_for(findings_source_sweeper_task, timeout=5)
    except asyncio.TimeoutError:
        logger.warning("findings_source_sweeper did not stop within 5s; cancelling.")
        findings_source_sweeper_task.cancel()
    except Exception as e:
        logger.warning(f"findings_source_sweeper shutdown error: {e}")
    try:
        await asyncio.wait_for(retention_sweeper_task, timeout=5)
    except asyncio.TimeoutError:
        logger.warning("retention_sweeper did not stop within 5s; cancelling.")
        retention_sweeper_task.cancel()
    except Exception as e:
        logger.warning(f"retention_sweeper shutdown error: {e}")
    try:
        await asyncio.wait_for(semgrep_sweeper_task, timeout=5)
    except asyncio.TimeoutError:
        logger.warning("semgrep_sync_sweeper did not stop within 5s; cancelling.")
        semgrep_sweeper_task.cancel()
    except Exception as e:
        logger.warning(f"semgrep_sync_sweeper shutdown error: {e}")

    from app.infrastructure.messaging.publisher import close_publisher

    try:
        await close_publisher()
    except Exception as e:
        logger.warning(f"Error during publisher shutdown: {e}")

    # Best-effort flush of any buffered Langfuse events. The helper is
    # itself fail-open; a Langfuse outage at shutdown drops in-memory
    # spans rather than blocking the API process from terminating.
    from app.infrastructure.observability import flush_langfuse

    try:
        flush_langfuse()
    except Exception as e:
        logger.warning(f"Error during Langfuse flush: {e}")


# --- FastMCP sub-app (Phase I.4) ---
# FastMCP requires its own lifespan for session initialisation. Compose it
# with ours via a combined context manager so FastAPI's lifespan kwarg sees
# a single entrypoint.
from app.api.mcp.server import mcp as _sccap_mcp_server  # noqa: E402

_mcp_app = _sccap_mcp_server.http_app(path="/")


@asynccontextmanager
async def _combined_lifespan(app: FastAPI):
    async with lifespan(app):
        async with _mcp_app.lifespan(app):
            yield


# V13.4.5: gate /docs, /redoc, /openapi.json behind environment.
# V13.4.6: avoid leaking real release versions in the public OpenAPI document.
_is_production = str(getattr(settings, "ENVIRONMENT", "")).lower() == "production"
app = FastAPI(
    title="SCCAP API",
    version="0",
    description="API for SCCAP — the Secure Coding & Compliance Automation Platform. Provides analysis, remediation, and compliance features.",
    lifespan=_combined_lifespan,
    docs_url=None if _is_production else "/docs",
    redoc_url=None if _is_production else "/redoc",
    openapi_url=None if _is_production else "/openapi.json",
)
# Mount the MCP sub-app. MCP clients connect to /mcp; the REST API keeps
# its /api/v1/* routes.
app.mount("/mcp", _mcp_app)


_CORR_ID_RE = __import__("re").compile(r"[A-Za-z0-9._:\-]{1,128}")


@app.middleware("http")
async def correlation_id_middleware(request: Request, call_next):
    # V02.2.1 / V04.2.4 / V04.2.5 / V14.2.4 / V16.4.1: validate the inbound
    # X-Correlation-ID against a positive allow-list (length-capped, no CRLF,
    # no control chars). Falls back to a fresh UUID when invalid or absent.
    raw = request.headers.get("X-Correlation-ID") or ""
    if raw and _CORR_ID_RE.fullmatch(raw):
        corr_id = raw
    else:
        corr_id = str(uuid.uuid4())

    # Set the ID in the context variable so our logger can access it
    correlation_id_var.set(corr_id)

    # Process the request
    response = await call_next(request)

    # Add the correlation ID to the response headers
    response.headers["X-Correlation-ID"] = corr_id

    # V14.3.2: prevent caching of authenticated API responses.
    if request.url.path.startswith("/api/v1/"):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")

    logger.info(
        "request.completed",
        extra={"path": request.url.path, "status": response.status_code},
    )
    return response


# --- Dynamic CORS Middleware Configuration ---
from starlette.middleware.base import BaseHTTPMiddleware  # noqa: E402
from app.core.config_cache import SystemConfigCache  # noqa: E402
from fastapi.responses import PlainTextResponse  # noqa: E402

_CORS_ALLOWED_HEADERS = (
    "Content-Type, Authorization, X-Correlation-ID, Accept, Origin, X-Requested-With"
)


def _is_valid_origin(value: str) -> bool:
    """V02.2.1: structural validation of an Origin URL."""
    try:
        from urllib.parse import urlparse

        p = urlparse(value)
        return p.scheme in ("http", "https") and bool(p.hostname) and not p.path
    except Exception:
        return False


def _resolve_allowed_origins() -> tuple[bool, list[str]]:
    """Returns (allow_all, allowed_origins) based on current setup state and cache.

    V03.4.2: pre-setup phase no longer reflects arbitrary origins; the allow-list
    is identical to the post-setup base allow-list to avoid wildcard-reflect-with-
    credentials.
    """
    # Base local/cloud origins from the env var are always permitted.
    allowed_origins_str = os.getenv(
        "ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173"
    )
    origins = [o.strip() for o in allowed_origins_str.split(",") if o.strip()]
    origins = [o for o in origins if _is_valid_origin(o)]

    if not SystemConfigCache.is_setup_completed():
        return False, origins

    # Admin-configured origins are additive, gated by the cors_enabled toggle.
    if SystemConfigCache.is_cors_enabled():
        db_origins = [
            o for o in SystemConfigCache.get_allowed_origins() if _is_valid_origin(o)
        ]
        origins.extend(db_origins)

    return False, origins


class DynamicCORSMiddleware(BaseHTTPMiddleware):
    """Single source of truth for CORS.

    Handles both OPTIONS preflight (short-circuit, no call_next) and regular
    responses (header injection after the inner handler runs) using one
    allow-list resolution.
    """

    async def dispatch(self, request: Request, call_next):
        _allow_all, allowed_origins = _resolve_allowed_origins()
        origin = request.headers.get("origin")
        # V03.4.2: never trust allow_all; always require origin to be in the list.
        origin_permitted = bool(origin) and origin in allowed_origins

        if request.method == "OPTIONS":
            if origin_permitted:
                response = PlainTextResponse(
                    "OK", media_type="text/plain; charset=utf-8"
                )
            else:
                # V16.3.3: log forbidden-origin preflight attempts.
                logger.warning(
                    "cors.preflight_rejected",
                    extra={
                        "origin": origin,
                        "path": request.url.path,
                        "method": request.method,
                    },
                )
                # No CORS headers on a rejected preflight; the browser will block.
                return PlainTextResponse(
                    "Forbidden",
                    status_code=403,
                    media_type="text/plain; charset=utf-8",
                )
        else:
            response = await call_next(request)

        if origin_permitted:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "*"
            response.headers["Access-Control-Allow-Headers"] = _CORS_ALLOWED_HEADERS

        # V03.4.1: HSTS unconditionally on every response.
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        # V03.4.4: prevent MIME sniffing.
        response.headers["X-Content-Type-Options"] = "nosniff"
        # V03.4.5: limit referrer leakage of sensitive paths.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        # V03.4.3 + V03.4.6: global CSP with frame-ancestors lock-down.
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'; "
            "script-src 'self' https://cdn.jsdelivr.net; "
            "style-src 'self' https://cdn.jsdelivr.net; "
            "img-src 'self' data: https://fastapi.tiangolo.com; "
            "connect-src 'self'"
        )
        # V03.4.8: COOP for HTML (docs/redoc) responses to prevent tabnabbing.
        if response.headers.get("content-type", "").startswith("text/html"):
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        return response


app.add_middleware(DynamicCORSMiddleware)
logger.info("Dynamic CORS Middleware configured.")


# --- Custom Exception Handler for 422 Errors ---
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    """Catches Pydantic validation errors and provides detailed logging."""
    safe_errors = [
        {"loc": e.get("loc"), "msg": e.get("msg"), "type": e.get("type")}
        for e in exc.errors()
    ]
    logger.error(
        "Pydantic Validation Error",
        extra={"errors": safe_errors, "url": str(request.url)},
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": "Request validation failed."},
    )


@app.exception_handler(Exception)
async def _last_resort_handler(request: Request, exc: Exception):
    """V16.5.4: last-resort handler — log details server-side, return generic message."""
    logger.error(
        "unhandled_exception",
        extra={"path": request.url.path},
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred."},
    )


# --- Include API Routers ---

# Main application router for submissions and results
app.include_router(projects_router, prefix="/api/v1", tags=["Submissions"])

# Router for managing LLM Configurations
app.include_router(
    llm_router, prefix="/api/v1/admin", tags=["Admin: LLM Configurations"]
)

# Router for managing Frameworks
app.include_router(framework_router, prefix="/api/v1/admin", tags=["Admin: Frameworks"])

# Router for managing Agents
app.include_router(agent_router, prefix="/api/v1/admin", tags=["Admin: Agents"])

# Router for managing Prompt Templates
app.include_router(
    prompt_router, prefix="/api/v1/admin", tags=["Admin: Prompt Templates"]
)

# Router for managing RAG
app.include_router(rag_router, prefix="/api/v1/admin", tags=["Admin: RAG Management"])

# Router for System Logs
app.include_router(logs_router, prefix="/api/v1/admin", tags=["Admin: System Logs"])

# Router for Chat
app.include_router(chat_router, prefix="/api/v1/chat", tags=["Chat"])

# Router for Compliance (per-framework rollups for the Compliance page)
app.include_router(compliance_router, prefix="/api/v1", tags=["Compliance"])

# Router for admin seed/restore-defaults
app.include_router(admin_seed_router, prefix="/api/v1", tags=["Admin: Seed"])

# Router for admin user-group CRUD (scan-scope membership)
app.include_router(admin_groups_router, prefix="/api/v1", tags=["Admin: User Groups"])
# Cross-tenant findings list with source filter (sast-prescan-followups Group D1).
app.include_router(admin_findings_router, prefix="/api/v1", tags=["Admin: Findings"])
app.include_router(dashboard_router, prefix="/api/v1", tags=["Dashboard"])
app.include_router(search_router, prefix="/api/v1", tags=["Search"])

from app.api.v1.routers.admin_users import router as admin_users_router  # noqa: E402
from app.api.v1.routers.admin_rule_sources import (  # noqa: E402
    router as rule_sources_router,
)
from app.api.v1.routers.scan_coverage import (  # noqa: E402
    router as scan_coverage_router,
)

app.include_router(admin_users_router, prefix="/api/v1")
app.include_router(
    rule_sources_router, prefix="/api/v1/admin", tags=["Admin: Rule Sources"]
)
app.include_router(scan_coverage_router, prefix="/api/v1", tags=["Scan Coverage"])


# --- Include FastAPI Users Authentication Routers ---
app.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

# Custom refresh endpoint (fastapi-users does not provide one with BearerTransport)

app.include_router(
    refresh_router,
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

# Enterprise SSO — public + admin routers + force-SSO login guard.
from app.api.v1.routers.sso import router as sso_router  # noqa: E402
from app.api.v1.routers.admin_sso import router as admin_sso_router  # noqa: E402
from app.api.v1.routers.auth_login_guard import (  # noqa: E402
    router as login_guard_router,
    ForceSsoMiddleware,
)

app.include_router(sso_router, prefix="/api/v1")
app.include_router(admin_sso_router, prefix="/api/v1")
app.include_router(login_guard_router, prefix="/api/v1")
app.add_middleware(ForceSsoMiddleware)

# WebAuthn / passkey endpoints (Chunk 5).
from app.api.v1.routers.webauthn import router as webauthn_router  # noqa: E402

app.include_router(webauthn_router, prefix="/api/v1")

# SCIM 2.0 (Chunk 6). Public SCIM endpoints under /scim/v2 (NOT /api/v1)
# because SCIM clients expect a spec-conformant URL hierarchy. Admin
# endpoints for token issuance live under /api/v1/admin/scim/tokens.
from app.api.v1.routers.scim import router as scim_router  # noqa: E402
from app.api.v1.routers.admin_scim import router as admin_scim_router  # noqa: E402

app.include_router(scim_router)
app.include_router(admin_scim_router, prefix="/api/v1")

# Tenant CRUD admin surface (Chunk 7) — superuser-only.
from app.api.v1.routers.admin_tenants import (  # noqa: E402
    router as admin_tenants_router,
)

app.include_router(admin_tenants_router, prefix="/api/v1")

app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/api/v1/auth",
    tags=["Authentication"],
)

app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/api/v1/users",
    tags=["Users"],
)

# Router for Initial Setup
app.include_router(
    setup_router,
    prefix="/api/v1/setup",
    tags=["Setup"],
)

# Router for System Configuration
app.include_router(
    admin_config_router,
    prefix="/api/v1",  # Prefix is defined in the router itself as /admin/system-config
)

# Router for SMTP profile management (multi-profile, separate from generic system-config)
app.include_router(admin_smtp_router, prefix="/api/v1")


# --- Root Endpoint ---
@app.get("/", tags=["Root"])
async def read_root():
    """A simple root endpoint to confirm the API is running."""
    return {"message": "Welcome to the SCCAP API!"}
