# src/app/infrastructure/auth/manager.py
import hashlib
import logging
import re
import urllib.parse
from typing import Any, Optional

from fastapi import Depends, Request
from fastapi_users import BaseUserManager, IntegerIDMixin

from app.infrastructure.database.models import User
from app.infrastructure.auth.db import get_user_db
from app.config.config import settings

logger = logging.getLogger(__name__)


def _unwrap_secret(value: Any) -> str:
    """Unwrap a Pydantic SecretStr (or pass through plain str) for libraries
    (fastapi-users, jose, etc.) that need the raw token-signing secret."""
    if hasattr(value, "get_secret_value"):
        return value.get_secret_value()
    return str(value) if value is not None else ""


class UserManager(IntegerIDMixin, BaseUserManager[User, int]):
    # V06.4.3: Use dedicated secrets for reset and verification tokens, distinct
    # from the session signing SECRET_KEY. Set RESET_TOKEN_SECRET and
    # VERIFICATION_TOKEN_SECRET in .env; falls back to SECRET_KEY only if unset
    # (legacy compatibility — production deployments MUST set distinct secrets).
    reset_password_token_secret = _unwrap_secret(
        getattr(settings, "RESET_TOKEN_SECRET", settings.SECRET_KEY)
    )
    verification_token_secret = _unwrap_secret(
        getattr(settings, "VERIFICATION_TOKEN_SECRET", settings.SECRET_KEY)
    )

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        # V16.2.5/V16.4.1: omit raw email; use hashed form for correlation
        email_hash = hashlib.sha256(user.email.lower().encode()).hexdigest()[:12]
        logger.info(
            "user.registered",
            extra={
                "event": "user.registered",
                "user_id": user.id,
                "email_hash": email_hash,
            },
        )
        pass

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        # V16.2.5/V16.2.1: structured log — no token fragment, no raw email
        logger.info(
            "password.reset.requested",
            extra={"event": "password.reset.requested", "user_id": user.id},
        )

        from app.infrastructure.email_service import send_password_reset_email

        # V01.2.2/V01.3.3/V01.3.6/V02.2.1/V15.3.4: Only honour the Origin
        # header if its host matches the configured allowlist. This prevents
        # reset-URL poisoning via a forged Origin. Control characters, unknown
        # schemes, and hosts not in the allowlist all fall through to the
        # canonical frontend_base_url.
        reset_url_base = f"{settings.frontend_base_url}/reset-password"

        origin_header = request.headers.get("origin") if request else None
        if origin_header:
            # Reject control characters (CR/LF/NUL etc.)
            if not any(ord(c) < 32 for c in origin_header):
                parsed = urllib.parse.urlparse(origin_header)
                origin_scheme = parsed.scheme.lower()
                origin_host = parsed.netloc  # includes port if present

                # Build the set of allowed hosts from BOTH the env-level
                # ALLOWED_ORIGINS and the DB-stored security.allowed_origins
                # set at /setup. The latter is what the operator actually
                # configured — without it, an admin loading the UI from
                # http://localhost (port 80) would have their Origin
                # rejected and the link would fall back to the dev-port
                # http://localhost:5173 from env.
                allowed_origins: set = set(settings.ALLOWED_ORIGINS)
                try:
                    from app.core.config_cache import SystemConfigCache

                    db_origins = SystemConfigCache.get_allowed_origins() or []
                except Exception:
                    db_origins = []
                # Cache might be empty if lifespan hydration failed silently.
                # Do a fresh DB read as a last-resort fallback so a misconfigured
                # cache never causes a wrong-host email link.
                if not db_origins:
                    try:
                        from app.infrastructure.database.database import (
                            AsyncSessionLocal,
                        )
                        from app.infrastructure.database.repositories.system_config_repo import (  # noqa: E501
                            SystemConfigRepository,
                        )

                        async with AsyncSessionLocal() as _s:
                            _row = await SystemConfigRepository(_s).get_by_key(
                                "security.allowed_origins"
                            )
                            if (
                                _row
                                and isinstance(_row.value, dict)
                                and isinstance(_row.value.get("origins"), list)
                            ):
                                db_origins = list(_row.value["origins"])
                                # Re-hydrate the cache opportunistically so
                                # subsequent calls don't repeat the DB hit.
                                SystemConfigCache.set_allowed_origins(db_origins)
                    except Exception:
                        pass
                allowed_origins.update(db_origins)
                # Also accept the canonical frontend base URL
                allowed_origins.add(settings.frontend_base_url)
                # Normalise: strip trailing slashes for comparison
                allowed_stripped = {o.rstrip("/") for o in allowed_origins if o}

                # Require http or https scheme and netloc matches allowlist regex
                if (
                    origin_scheme in {"http", "https"}
                    and re.match(r"^[A-Za-z0-9.\-:]{1,255}$", origin_host)
                    and origin_header.rstrip("/") in allowed_stripped
                ):
                    reset_url_base = f"{origin_header.rstrip('/')}/reset-password"
                else:
                    logger.warning(
                        "password.reset.origin_rejected",
                        extra={
                            "event": "password.reset.origin_rejected",
                            "user_id": user.id,
                            "reason": "not in allowlist",
                        },
                    )

        # V16.3.4: catch dispatch failures so errors are logged and don't
        # silently swallow the failure without telemetry.
        try:
            await send_password_reset_email(user.email, token, reset_url_base)
        except Exception:
            logger.error(
                "password_reset_email.dispatch_failed",
                extra={
                    "event": "password_reset_email.dispatch_failed",
                    "user_id": user.id,
                },
                exc_info=True,
            )

    async def on_after_request_verify(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        # V16.2.5/V16.2.1: structured log — no token fragment, no raw email
        logger.info(
            "verification.requested",
            extra={"event": "verification.requested", "user_id": user.id},
        )
        pass


async def get_user_manager(user_db=Depends(get_user_db)):
    """
    FastAPI dependency to get an instance of the UserManager.
    """
    yield UserManager(user_db)
