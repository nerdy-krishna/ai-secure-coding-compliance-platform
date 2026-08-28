# src/app/infrastructure/auth/core.py
import logging
import uuid
from typing import AsyncGenerator, Optional

from fastapi import Depends, HTTPException, Query, Request, status
from fastapi_users import FastAPIUsers
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.auth.backend import (
    auth_backend,
    get_custom_cookie_jwt_strategy,
)
from app.infrastructure.auth.manager import UserManager, get_user_manager
from app.infrastructure.auth.session import (
    BrowserSessionService,
    InvalidCsrfRequest,
    SessionError,
    decode_session_credential,
    enforce_cookie_csrf,
)
from app.infrastructure.auth.sse_token import verify_scan_stream_token
from app.infrastructure.database.database import get_db
from app.infrastructure.database.models import User
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
)
from app.infrastructure.database.tenant_context import (
    apply_session_context,
    bind_principal,
    effective_tenant_id,
    reset_principal,
)
from app.shared.lib.permissions import PLATFORM_CONFIG_MANAGE

logger = logging.getLogger(__name__)

# This is the central object for FastAPI Users.
# It brings together the user manager and our single, correctly configured auth_backend.
# We also correctly specify that the User ID type is 'int'.
fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)

# Explicit bearer credentials remain supported for API clients. Browser calls may
# instead authenticate with the stateful HttpOnly session cookie below.
_optional_active_bearer_user = fastapi_users.current_user(
    optional=True,
    active=True,
)


async def current_active_user(
    request: Request,
    bearer_user: User | None = Depends(_optional_active_bearer_user),
    db: AsyncSession = Depends(get_db),
    strategy=Depends(get_custom_cookie_jwt_strategy),
) -> AsyncGenerator[User, None]:
    """Authenticate an active user via bearer token or browser session cookie.

    Bearer requests preserve the programmatic API contract. Cookie-authenticated
    unsafe requests additionally require an exact allowed Origin and a CSRF
    header bound to the server-side session family.
    """
    request.state.auth_session_id = None
    request.state.active_tenant_id = None
    if bearer_user is not None:
        user = bearer_user
    else:
        credential = request.cookies.get(strategy.browser_session_cookie_name)
        if not credential:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

        try:
            claims = decode_session_credential(credential)
            enforce_cookie_csrf(request, claims.session_id)
            session_row = await BrowserSessionService(db).authenticate(credential)
        except InvalidCsrfRequest as exc:
            logger.warning(
                "auth.browser_session.csrf_rejected",
                extra={"path": request.url.path, "reason": str(exc)},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF validation failed.",
            ) from exc
        except SessionError as exc:
            # Persist expiry-triggered revocation while malformed credentials remain
            # side-effect free.
            await db.commit()
            logger.warning(
                "auth.browser_session.rejected",
                extra={"path": request.url.path, "reason": type(exc).__name__},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED) from exc

        user = await db.get(User, session_row.user_id)
        tenant_matches = user is not None and user.tenant_id == session_row.tenant_id
        if user is None or not user.is_active or not tenant_matches:
            await BrowserSessionService(db).repo.revoke(
                session_row,
                reason=(
                    "user_inactive"
                    if user is None or not user.is_active
                    else "tenant_changed"
                ),
            )
            await db.commit()
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        request.state.auth_session_id = session_row.id
        request.state.active_tenant_id = session_row.active_tenant_id
        await db.commit()

    binding = bind_principal(
        tenant_id=effective_tenant_id(user.tenant_id),
        principal_kind="human",
        principal_id=str(user.id),
    )
    try:
        await apply_session_context(db)
        yield user
    finally:
        reset_principal(binding)


async def current_superuser(
    user: User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Compatibility name for the stable platform-configuration capability.

    Older global administration routers still import this dependency. It no
    longer authorizes from ``User.is_superuser``; removing the current database
    role assignment takes effect on the next request.
    """

    permissions = await AuthorizationRepository(db).permissions_for_user(
        user=user,
        tenant_id=effective_tenant_id(user.tenant_id),
    )
    if PLATFORM_CONFIG_MANAGE not in permissions:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
    return user


async def current_active_user_sse(
    request: Request,
    access_token: Optional[str] = Query(
        default=None,
        description=(
            "JWT access token. EventSource can't send the Authorization "
            "header, so SSE endpoints accept the token as a query param as "
            "an alternative. Short-TTL access tokens — safe enough."
        ),
    ),
    strategy=Depends(get_custom_cookie_jwt_strategy),
    user_manager: UserManager = Depends(get_user_manager),
) -> AsyncGenerator[User, None]:
    """SSE-friendly auth dependency.

    Tries the Authorization header first (same as `current_active_user`);
    falls back to the `?access_token=…` query parameter when missing.
    Raises 401 if neither yields a valid user.
    """
    auth_header = request.headers.get("Authorization") or request.headers.get(
        "authorization"
    )
    token: Optional[str] = None
    method: Optional[str] = None
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1]
        method = "header"
    elif access_token:
        token = access_token
        method = "query"

    client_ip = request.client.host if request.client else None

    # V02.2.1: Reject tokens that are excessively long or contain whitespace
    # before passing them to the JWT decoder.
    if token and (len(token) > 4096 or any(c.isspace() for c in token)):
        logger.warning(
            "sse.auth.rejected",
            extra={
                "reason": "token_format_invalid",
                "method": method,
                "has_token": True,
                "client_ip": client_ip,
            },
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    user: Optional[User] = None
    # Try the scan-stream-bound token format first. EventSource clients
    # request a token via POST /scans/{id}/stream-token and pass it as
    # ?access_token=…; that token is audience-tagged and bound to this
    # scan, so it CANNOT be substituted for a regular access token.
    # If verification fails (wrong audience / scan / signature / TTL)
    # we fall through to the regular fastapi-users access-token path
    # so curl smoke tests with a normal Bearer header still work.
    scan_id_str = request.path_params.get("scan_id") if request else None
    if token and scan_id_str:
        try:
            scan_id_uuid = uuid.UUID(scan_id_str)
            user_id, stream_tenant_id = verify_scan_stream_token(token, scan_id_uuid)
            user = await user_manager.get(user_id)
            request.state.sse_tenant_id = stream_tenant_id
            method = "sse_token"
        except (HTTPException, ValueError):
            user = None
        except Exception:
            logger.error(
                "sse.auth.sse_token_read_failed",
                extra={"method": "sse_token", "client_ip": client_ip},
                exc_info=True,
            )
            user = None

    if user is None and token:
        # V16.3.4: Catch unexpected errors from token decoding and log them.
        try:
            user = await strategy.read_token(token, user_manager)
        except Exception:
            logger.error(
                "sse.auth.token_read_failed",
                extra={"method": method, "client_ip": client_ip},
                exc_info=True,
            )
            user = None

    if user is None or not user.is_active:
        # V16.3.1 / V16.3.3: Log auth failures including which method was attempted.
        logger.warning(
            "sse.auth.rejected",
            extra={"method": method, "has_token": bool(token), "client_ip": client_ip},
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)

    # V16.3.1 / V16.3.3: Log successful auth with user id and method.
    logger.info(
        "sse.auth.success",
        extra={"user_id": user.id, "method": method, "client_ip": client_ip},
    )
    binding = bind_principal(
        tenant_id=getattr(
            request.state,
            "sse_tenant_id",
            effective_tenant_id(user.tenant_id),
        ),
        principal_kind="human",
        principal_id=str(user.id),
    )
    try:
        await apply_session_context(user_manager.user_db.session)
        yield user
    finally:
        reset_principal(binding)
