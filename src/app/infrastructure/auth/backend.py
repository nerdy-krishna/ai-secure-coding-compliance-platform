# src/app/infrastructure/auth/backend.py
import logging
import time
import uuid
from typing import Optional, Literal

import jwt
from fastapi import Response, Request
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users import models as fastapi_users_typing_models
from sqlalchemy.ext.asyncio import AsyncSession

# Import the centralized settings object
from app.config.config import settings
from app.infrastructure.auth.session import (
    BrowserSessionService,
    IssuedSession,
    SessionPolicy,
    issue_csrf_token,
)

logger = logging.getLogger(__name__)


def mark_auth_response_no_store(response: Response) -> None:
    """Prevent browsers and intermediaries from caching token responses."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


# Bearer Transport for Access Tokens (remains the same)
bearer_transport = BearerTransport(tokenUrl="/api/v1/auth/login")


# Custom JWT Strategy that uses the centralized settings
class CustomCookieJWTStrategy(
    JWTStrategy[fastapi_users_typing_models.UP, fastapi_users_typing_models.ID]
):
    """
    Custom JWT Strategy that writes the refresh token to an HttpOnly cookie
    and reads it from there.
    """

    def __init__(
        self,
        secret: str,
        lifetime_seconds: int,
        refresh_token_lifetime_seconds: int,
    ):
        super().__init__(
            secret=secret,
            lifetime_seconds=lifetime_seconds,
            token_audience=["fastapi-users:auth"],
        )
        self.refresh_token_lifetime_seconds = refresh_token_lifetime_seconds
        self.cookie_name = "SecureCodePlatformRefresh"
        self.cookie_path = "/"
        self.cookie_secure = not settings.ALLOW_INSECURE_COOKIES
        self.cookie_httponly = True
        self.cookie_samesite: Literal["lax", "strict", "none"] = "strict"
        # The __Host- prefix is accepted only for Secure cookies on `/` with
        # no Domain attribute. Local HTTP uses an unmistakably separate name.
        self.browser_session_cookie_name = (
            "__Host-SCCAPSession" if self.cookie_secure else "SCCAPSessionDev"
        )

        logger.info(
            "CustomCookieJWTStrategy initialized.",
            extra={
                "cookie_name": self.cookie_name,
                "cookie_path": self.cookie_path,
                "cookie_secure": self.cookie_secure,
                "cookie_httponly": self.cookie_httponly,
                "cookie_samesite": self.cookie_samesite,
                "max_age": self.refresh_token_lifetime_seconds,
            },
        )

    async def write_refresh_token(self, response: Response, token: str) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value=token,
            max_age=self.refresh_token_lifetime_seconds,
            path=self.cookie_path,
            secure=self.cookie_secure,
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,  # This will now pass type checking
        )

    async def write_browser_session(self, response: Response, credential: str) -> None:
        response.set_cookie(
            key=self.browser_session_cookie_name,
            value=credential,
            # Keep the browser cookie aligned with the server-side policy,
            # including the runtime security.session_lifetime_hours override.
            max_age=SessionPolicy.from_settings().absolute_seconds,
            path="/",
            secure=self.cookie_secure,
            httponly=True,
            samesite="strict",
        )

    async def issue_stateful_browser_session(
        self,
        response: Response,
        user,
        *,
        auth_method: str,
        assurance_level: str = "aal1",
        provider_id: uuid.UUID | None = None,
        provider_session_id: str | None = None,
        request: Request | None = None,
        db: AsyncSession | None = None,
    ) -> IssuedSession:
        """Create, audit, and set one stateful browser-session credential."""
        from app.infrastructure.auth.sso.audit import record
        from app.infrastructure.database.database import AsyncSessionLocal
        from app.infrastructure.database.models import User

        async def _create(active_db: AsyncSession, db_user) -> IssuedSession:
            issued = await BrowserSessionService(active_db).create(
                db_user,
                auth_method=auth_method,
                assurance_level=assurance_level,
                provider_id=provider_id,
                provider_session_id=provider_session_id,
                request=request,
            )
            await record(
                active_db,
                event="session.created",
                user_id=db_user.id,
                actor_user_id=db_user.id,
                session_id=issued.row.id,
                provider_id=provider_id,
                tenant_id=db_user.tenant_id,
                outcome="success",
                request=request,
                details={
                    "auth_method": auth_method,
                    "assurance_level": assurance_level,
                },
            )
            return issued

        if db is not None:
            issued = await _create(db, user)
        else:
            async with AsyncSessionLocal() as owned_db:
                db_user = await owned_db.get(User, user.id)
                if db_user is None or not db_user.is_active:
                    raise RuntimeError("Cannot create a session for an inactive user.")
                issued = await _create(owned_db, db_user)
                await owned_db.commit()
        await self.write_browser_session(response, issued.credential)
        response.headers["X-CSRF-Token"] = issue_csrf_token(issued.row.id)
        response.headers["Access-Control-Expose-Headers"] = "X-CSRF-Token"
        return issued

    async def issue_refresh_token(self, response: Response, user) -> None:
        """Mint the browser refresh credential for a newly authenticated user."""
        now_ts = int(time.time())
        refresh_token = jwt.encode(
            {
                "sub": str(user.id),
                "aud": self.token_audience,
                "typ": "refresh",
                "original_iat": now_ts,
                "exp": now_ts + self.refresh_token_lifetime_seconds,
            },
            self.encode_key,
            algorithm=self.algorithm,
        )
        await self.write_refresh_token(response, refresh_token)

    async def issue_session(
        self,
        response: Response,
        user,
        *,
        auth_method: str,
        assurance_level: str = "aal1",
        provider_id: uuid.UUID | None = None,
        provider_session_id: str | None = None,
        request: Request | None = None,
        db: AsyncSession | None = None,
    ) -> str:
        """Issue the access token and matching rotating refresh cookie."""
        access_token = await self.write_token(user)
        await self.issue_refresh_token(response, user)
        await self.issue_stateful_browser_session(
            response,
            user,
            auth_method=auth_method,
            assurance_level=assurance_level,
            provider_id=provider_id,
            provider_session_id=provider_session_id,
            request=request,
            db=db,
        )
        mark_auth_response_no_store(response)
        logger.info(
            "auth: refresh token issued",
            extra={
                "cookie_name": self.cookie_name,
                "max_age": self.refresh_token_lifetime_seconds,
                "secure": self.cookie_secure,
            },
        )
        return access_token

    async def read_refresh_token(self, request: Request) -> Optional[str]:
        token = request.cookies.get(self.cookie_name)
        if token:
            logger.debug(
                "auth: refresh token read from cookie",
                extra={"cookie_name": self.cookie_name},
            )
        else:
            logger.warning(
                "auth: refresh attempt with no cookie",
                extra={
                    "cookie_name": self.cookie_name,
                    "path": request.url.path,
                    "client_host": request.client.host if request.client else None,
                },
            )
        return token

    async def destroy_refresh_token(self, response: Response) -> None:
        response.set_cookie(
            key=self.cookie_name,
            value="",
            max_age=0,
            path=self.cookie_path,
            secure=self.cookie_secure,
            httponly=self.cookie_httponly,
            samesite=self.cookie_samesite,
        )

    async def destroy_browser_session(self, response: Response) -> None:
        response.set_cookie(
            key=self.browser_session_cookie_name,
            value="",
            max_age=0,
            path="/",
            secure=self.cookie_secure,
            httponly=True,
            samesite="strict",
        )


class RefreshCookieAuthenticationBackend(AuthenticationBackend):
    """FastAPI Users backend that completes the browser-session contract.

    ``AuthenticationBackend`` only asks a strategy for an access token. The
    SCCAP refresh endpoint therefore had no cookie to rotate after password
    login. SSO and WebAuthn minted one independently; this backend makes the
    password path equivalent and clears the cookie on logout.
    """

    async def login(self, strategy, user) -> Response:
        response = await super().login(strategy, user)
        await strategy.issue_refresh_token(response, user)
        await strategy.issue_stateful_browser_session(
            response,
            user,
            auth_method="password",
        )
        mark_auth_response_no_store(response)
        return response

    async def logout(self, strategy, user, token: str) -> Response:
        response = await super().logout(strategy, user, token)
        await strategy.destroy_refresh_token(response)
        await strategy.destroy_browser_session(response)
        response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
        mark_auth_response_no_store(response)
        logger.info(
            "auth: refresh token destroyed",
            extra={"cookie_name": strategy.cookie_name},
        )
        return response


def get_custom_cookie_jwt_strategy() -> CustomCookieJWTStrategy:
    """
    Returns the JWT strategy instance, configured from the central settings object.
    """
    # SECRET_KEY is a Pydantic SecretStr; unwrap for the JWT signing layer.
    _raw_secret = settings.SECRET_KEY
    _secret = (
        _raw_secret.get_secret_value()
        if hasattr(_raw_secret, "get_secret_value")
        else str(_raw_secret)
    )
    return CustomCookieJWTStrategy(
        secret=_secret,
        lifetime_seconds=settings.ACCESS_TOKEN_LIFETIME_SECONDS,
        refresh_token_lifetime_seconds=settings.REFRESH_TOKEN_LIFETIME_SECONDS,
    )


# This is our main authentication backend.
auth_backend = RefreshCookieAuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_custom_cookie_jwt_strategy,
)
