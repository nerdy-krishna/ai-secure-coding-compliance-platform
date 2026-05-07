"""Privileged first-run bootstrap router for the SCCAP platform.

Security notes (V14.1.2 / V15.1.5):
  * The POST /setup endpoint is intentionally unauthenticated and MUST only
    succeed when no user exists; ``is_setup_completed`` is the gate, but it
    is a best-effort TOCTOU check — the unique constraint on ``users.email``
    is the actual backstop against concurrent first-run requests.
  * ``admin_password`` and ``llm_api_key`` are SECRETS and MUST NEVER be
    logged or echoed in responses. ``admin_email`` is PII and MUST NOT be
    written into log messages other than as a structured ``extra`` field.
  * Failures while persisting CORS allowed_origins MUST log a redacted
    summary at WARN/ERROR level (no silent ``pass``) so operators can
    diagnose post-success drift between the DB and ``SystemConfigCache``.
"""

import logging
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.infrastructure.database.database import get_db
from app.infrastructure.database import models as db_models
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.auth import schemas as auth_schemas
from app.api.v1.schemas.setup import SetupRequest, SetupStatusResponse
from app.infrastructure.database.repositories.llm_config_repo import LLMConfigRepository
from app.infrastructure.database.repositories.system_config_repo import (
    SystemConfigRepository,
)
from app.api.v1 import models as api_models
from app.api.v1.dependencies import get_llm_config_repository

from app.config.logging_config import update_logging_level

logger = logging.getLogger(__name__)

router = APIRouter()


async def is_setup_completed(db: AsyncSession) -> bool:
    """Checks if any user exists in the database."""
    result = await db.execute(select(func.count(db_models.User.id)))
    count = result.scalar()
    return count > 0


@router.get("/status", response_model=SetupStatusResponse)
async def get_setup_status(db: AsyncSession = Depends(get_db)):
    """Check if the application setup is completed."""
    completed = await is_setup_completed(db)
    return SetupStatusResponse(is_setup_completed=completed)


@router.post("", status_code=status.HTTP_201_CREATED)
async def perform_setup(
    request: SetupRequest,
    db: AsyncSession = Depends(get_db),
    user_manager: UserManager = Depends(get_user_manager),
    llm_repo: LLMConfigRepository = Depends(get_llm_config_repository),
):
    """Perform the initial platform bootstrap.

    DANGEROUS / PRIVILEGED FUNCTIONALITY (V15.1.5):
      * This endpoint is unauthenticated and only safe because
        ``is_setup_completed`` gates it; once a user exists the endpoint
        becomes permanently inert.
      * The gate is best-effort under concurrent calls (TOCTOU between the
        ``is_setup_completed`` query and ``user_manager.create``); the
        unique constraint on ``users.email`` is the actual backstop.
      * Writes platform-wide config: creates the initial superuser, the
        default LLM configuration, and CORS / log-level / LLM-mode rows in
        ``system_config``; all four are mirrored into the process-local
        ``SystemConfigCache``.
    """
    if await is_setup_completed(db):
        logger.warning(
            "setup endpoint hit after platform already initialised",
            extra={"client_email": request.admin_email},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Setup already completed. Please login.",
        )

    # V06.2.11: reject passwords that contain context-specific tokens
    # (product name, role, deployment type, email local-part). This is a
    # cheap secondary check; primary password strength is enforced by the
    # UserManager / fastapi-users password helper.
    # admin_password is a Pydantic SecretStr; unwrap for the substring check.
    _pw_value = (
        request.admin_password.get_secret_value()
        if hasattr(request.admin_password, "get_secret_value")
        else (request.admin_password or "")
    )
    _pw_lower = _pw_value.lower()
    _ctx_tokens = {
        "sccap",
        "admin",
        "superuser",
        (request.admin_email or "").split("@")[0].lower(),
        (request.deployment_type or "").lower(),
    }
    _ctx_tokens.discard("")
    for _tok in _ctx_tokens:
        if _tok and _tok in _pw_lower:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    "Chosen password contains a context-specific term "
                    "(product name, role, or your email local-part); "
                    "pick a stronger one."
                ),
            )

    user_create = auth_schemas.UserCreate(
        # admin_email: PII - persisted plaintext, MUST NOT be logged here
        email=request.admin_email,
        # admin_password: SECRET - hashed by UserManager.password_helper before persist.
        # Unwrap the SecretStr; UserCreate expects a plain string.
        password=_pw_value,
        is_superuser=True,
        is_active=True,
        is_verified=True,
    )
    try:
        created_user = await user_manager.create(user_create, safe=False)
    except HTTPException:
        # fastapi-users raises HTTPException on duplicate / weak password;
        # let it propagate but record the bypass-attempt signal.
        logger.warning(
            "setup: superuser creation rejected by UserManager",
            extra={"email": request.admin_email},
        )
        raise
    except Exception:
        logger.error(
            "setup: superuser creation failed",
            extra={"email": request.admin_email},
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Superuser creation failed. See server logs for details.",
        )
    logger.info(
        "setup: initial superuser created",
        extra={"email": request.admin_email, "is_superuser": True},
    )

    # M6: persist the master-admin user id immediately so the force-SSO
    # escape hatch reads a stable constant (never recomputes MIN(users.id)
    # per request — that would silently transfer the escape hatch on master-
    # admin deletion).
    try:
        sys_conf_repo_master = SystemConfigRepository(db)
        await sys_conf_repo_master.set_value(
            api_models.SystemConfigurationCreate(
                key="security.master_admin_user_id",
                value={"user_id": int(created_user.id)},
                description=(
                    "Master admin user id. This user is the local-admin "
                    "escape hatch — they can always password-login even "
                    "when force-SSO is configured for their domain. "
                    "Deletion of this user is refused by admin_users."
                ),
                is_secret=False,
                encrypted=False,
            )
        )
        from app.core.config_cache import SystemConfigCache as _SCC

        _SCC.set_master_admin_user_id(int(created_user.id))
    except Exception:
        logger.error(
            "setup: failed to persist master_admin_user_id",
            extra={"user_id": getattr(created_user, "id", None)},
            exc_info=True,
        )

    # 2. Validate mode/provider compatibility and configure LLM.
    if (
        request.llm_optimization_mode == "anthropic_optimized"
        and request.llm_provider.lower() != "anthropic"
    ):
        logger.warning(
            "setup rejected - mode/provider mismatch",
            extra={
                "mode": request.llm_optimization_mode,
                "provider": request.llm_provider,
            },
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "LLM optimization mode 'anthropic_optimized' requires "
                "llm_provider='anthropic'. Pick a different mode or provider."
            ),
        )

    try:
        llm_create = api_models.LLMConfigurationCreate(
            name="Default Configuration",
            provider=request.llm_provider,
            model_name=request.llm_model,
            # llm_api_key: SECRET - Fernet-encrypted by LLMConfigRepository.create before persist
            api_key=request.llm_api_key,
            input_cost_per_million=0.0,  # Default, user can update later
            output_cost_per_million=0.0,
        )
        await llm_repo.create(llm_create)
    except Exception:
        # V13.4.6 / V16.5.1: do NOT echo str(e) to the unauthenticated caller —
        # it leaks driver / SQL / ORM messages. Log full traceback for SREs.
        # Note: In a real scenario, we might want to rollback the user creation here
        logger.error(
            "setup: failed to create default LLM configuration",
            exc_info=True,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to configure LLM. Check application logs.",
        )
    logger.info(
        "setup: default LLM configuration created",
        extra={
            "provider": request.llm_provider,
            "model": request.llm_model,
        },
    )

    # 3. Configure CORS (System Config)
    sys_conf_repo = SystemConfigRepository(db)

    # Determine CORS settings based on deployment type
    cors_enabled = True
    allowed_origins = []
    if request.deployment_type == "local":
        allowed_origins = [
            "http://localhost",
            "http://127.0.0.1",
            "http://localhost:5173",
        ]
    elif request.deployment_type == "cloud":
        # V02.2.3: cloud deployments MUST supply a frontend_url; otherwise
        # allowed_origins ends up empty and the platform completes setup
        # in a misconfigured state.
        if not request.frontend_url:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "deployment_type='cloud' requires a frontend_url so "
                    "the CORS allowlist can be populated."
                ),
            )
        # V01.3.3 / V13.2.4 / V02.2.1: validate the operator-supplied origin
        # before persisting it as the lone CORS allowed_origin. Reject
        # malformed values, javascript:, schemes other than http/https, and
        # entries with a path/query/fragment/userinfo or excessive length.
        _frontend_url = request.frontend_url.strip()
        if len(_frontend_url) > 2048:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="frontend_url is too long (max 2048 chars).",
            )
        _parsed = urlparse(_frontend_url)
        if (
            _parsed.scheme not in ("http", "https")
            or not _parsed.netloc
            or _parsed.path not in ("", "/")
            or _parsed.query
            or _parsed.fragment
            or "@" in _parsed.netloc  # rejects userinfo
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "frontend_url must be a valid http(s) URL with a host "
                    "and no path, query, fragment, or userinfo."
                ),
            )
        # Strip any trailing slash so the persisted origin matches the
        # browser-sent Origin header exactly.
        allowed_origins = [_frontend_url.rstrip("/")]

    # Save CORS Enabled setting
    cors_enabled_create = api_models.SystemConfigurationCreate(
        key="security.cors_enabled",
        value={"enabled": cors_enabled},
        description="Enable CORS for allowed origins",
        is_secret=False,
        encrypted=False,
    )
    await sys_conf_repo.set_value(cors_enabled_create)

    # Save Log Level setting (Default to INFO after setup)
    log_level_create = api_models.SystemConfigurationCreate(
        key="system.log_level",
        value={"level": "INFO"},
        description="System Log Level",
        is_secret=False,
        encrypted=False,
    )
    await sys_conf_repo.set_value(log_level_create)

    # Save LLM optimization mode
    llm_mode_create = api_models.SystemConfigurationCreate(
        key="llm.optimization_mode",
        value={"mode": request.llm_optimization_mode},
        description="Active LLM optimization mode (anthropic_optimized | multi_provider).",
        is_secret=False,
        encrypted=False,
    )
    await sys_conf_repo.set_value(llm_mode_create)

    # Update Runtime Config
    from app.core.config_cache import SystemConfigCache

    SystemConfigCache.set_cors_enabled(cors_enabled)
    SystemConfigCache.set_llm_mode(request.llm_optimization_mode)
    update_logging_level("INFO")

    if allowed_origins:
        try:
            # Create SystemConfigurationCreate object
            config_create = api_models.SystemConfigurationCreate(
                key="security.allowed_origins",
                value={"origins": allowed_origins},  # Store as JSON dict
                description="Allowed origins for CORS",
                is_secret=False,
                encrypted=False,
            )
            await sys_conf_repo.set_value(config_create)

            # Update Cache immediately so next request works
            SystemConfigCache.set_allowed_origins(allowed_origins)
        except Exception:
            # V16.3.4 / V16.5.3 / V14.1.2: never silently swallow this —
            # the DB write failed but the rest of setup succeeded, so the
            # SystemConfigCache is now out of sync with persisted state.
            # Operators need to see this so they can re-run / repair.
            logger.error(
                "setup: failed to persist CORS allowed_origins; " "cache not updated",
                extra={"origins": allowed_origins},
                exc_info=True,
            )

    logger.info(
        "setup: platform setup complete",
        extra={"deployment_type": request.deployment_type},
    )
    SystemConfigCache.set_setup_completed(True)

    return {"message": "Setup completed successfully"}
