# src/app/api/v1/routers/refresh.py
"""
Custom /auth/refresh endpoint.

fastapi-users' get_auth_router() only provides /login and /logout.
This router adds a /refresh endpoint that:
  1. Reads the refresh token from the HttpOnly cookie
  2. Validates it (JWT decode + user lookup)
  3. Issues a new access token
  4. Rotates the refresh cookie
"""

import logging
from datetime import datetime, timezone

import jwt
from fastapi import APIRouter, Request, Response, HTTPException, status, Depends

from app.config.config import settings
from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.auth.manager import get_user_manager, UserManager

logger = logging.getLogger(__name__)

router = APIRouter()

COOKIE_NAME = "SecureCodePlatformRefresh"
ALGORITHM = "HS256"
AUDIENCE = "fastapi-users:auth"
REFRESH_TOKEN_TYPE = "refresh"


@router.post("/refresh")
async def refresh_access_token(
    request: Request,
    response: Response,
    user_manager: UserManager = Depends(get_user_manager),
):
    """
    Exchange a valid refresh token (HttpOnly cookie) for a new access token.
    Also rotates the refresh cookie for security.
    """
    refresh_token = request.cookies.get(COOKIE_NAME)

    if not refresh_token:
        logger.warning(
            "auth.refresh.no_cookie",
            extra={"ip": request.client.host if request.client else None},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No refresh token found.",
        )

    # SECRET_KEY is a Pydantic SecretStr; unwrap for jwt.decode.
    _secret_key = (
        settings.SECRET_KEY.get_secret_value()
        if hasattr(settings.SECRET_KEY, "get_secret_value")
        else str(settings.SECRET_KEY)
    )
    # Decode and validate the refresh token
    try:
        payload = jwt.decode(
            refresh_token,
            _secret_key,
            algorithms=[ALGORITHM],
            audience=AUDIENCE,
        )
    except jwt.ExpiredSignatureError:
        logger.warning("Refresh token has expired.")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired. Please log in again.",
        )
    except jwt.InvalidTokenError as e:
        logger.warning("auth.refresh.invalid_token", extra={"error": str(e)})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token.",
        )

    # Reject access tokens (or any token not explicitly typed as a refresh token)
    # to prevent access-token-as-refresh-token confusion attacks (V09.2.2).
    if payload.get("typ") != REFRESH_TOKEN_TYPE:
        logger.warning(
            "auth.refresh.wrong_token_type", extra={"typ": payload.get("typ")}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type.",
        )

    # Extract user ID from the token's 'sub' claim
    user_id_str = payload.get("sub")
    if not user_id_str:
        logger.warning("auth.refresh.missing_sub")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload.",
        )

    try:
        user_id = int(user_id_str)
    except (ValueError, TypeError):
        logger.warning("auth.refresh.bad_user_id", extra={"sub": user_id_str})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user identifier in token.",
        )

    # Look up the user
    user = await user_manager.get(user_id)
    if user is None or not user.is_active:
        logger.warning("auth.refresh.user_inactive", extra={"user_id": user_id})
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive.",
        )

    # Generate a new access token using the same strategy
    strategy = get_custom_cookie_jwt_strategy()
    new_access_token = await strategy.write_token(user)

    # Enforce absolute session lifetime (V07.3.2): propagate original_iat from
    # the inbound token so the session cannot be extended indefinitely by rotation.
    # Read admin override first (system_config[security.session_lifetime_hours]);
    # fall back to settings default (validated 5 min – 7 d).
    original_iat = payload.get("original_iat", datetime.now(timezone.utc).timestamp())
    from app.core.config_cache import SystemConfigCache

    cache_hours = SystemConfigCache.get_session_lifetime_hours()
    absolute_lifetime = (
        cache_hours * 3600
        if cache_hours is not None
        else settings.SESSION_ABSOLUTE_LIFETIME_SECONDS
    )
    if datetime.now(timezone.utc).timestamp() - original_iat > absolute_lifetime:
        logger.warning(
            "auth.refresh.session_lifetime_exceeded",
            extra={"event": "session.absolute_lifetime_exceeded", "user_id": user.id},
        )
        # M8: emit auth audit event so SOC 2 trace shows the forced logout.
        try:
            from app.infrastructure.auth.sso.audit import (
                EVENT_SESSION_LIFETIME_EXCEEDED,
                record_event,
            )

            await record_event(
                db=None,
                event=EVENT_SESSION_LIFETIME_EXCEEDED,
                user_id=user.id,
                provider_id=None,
                request=request,
                details={
                    "original_iat": original_iat,
                    "ceiling_seconds": absolute_lifetime,
                },
            )
        except Exception:
            # Audit failure must never block the rejection path.
            pass
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session lifetime exceeded; please log in again.",
        )

    # Chunk 4 — session-bind: when the user's primary OAuth provider has
    # bind_to_idp_session=True, mirror the IdP-asserted access-token expiry
    # as a second session ceiling. Caps blast radius of an IdP session
    # revocation we don't directly observe.
    try:
        from sqlalchemy import select as _select

        from app.infrastructure.auth.sso.encryption import decrypt_provider_config
        from app.infrastructure.auth.sso.models import OidcConfig
        from app.infrastructure.database.database import AsyncSessionLocal
        from app.infrastructure.database.models import OAuthAccount, SsoProvider

        async with AsyncSessionLocal() as _check_session:
            row = (
                await _check_session.execute(
                    _select(OAuthAccount, SsoProvider)
                    .join(SsoProvider, OAuthAccount.provider_id == SsoProvider.id)
                    .where(OAuthAccount.user_id == user.id)
                    .order_by(OAuthAccount.created_at.desc())
                )
            ).first()
            if row is not None:
                oauth_account, provider_row = row
                if (
                    provider_row.protocol == "oidc"
                    and oauth_account.idp_token_expires_at is not None
                ):
                    cfg_plain = decrypt_provider_config(provider_row.config_encrypted)
                    oidc_cfg = OidcConfig.model_validate(cfg_plain)
                    if oidc_cfg.bind_to_idp_session:
                        now_utc = datetime.now(timezone.utc)
                        if oauth_account.idp_token_expires_at < now_utc:
                            logger.warning(
                                "auth.refresh.idp_token_expired",
                                extra={
                                    "event": "session.idp_token_expired",
                                    "user_id": user.id,
                                    "provider_id": str(provider_row.id),
                                },
                            )
                            try:
                                from app.infrastructure.auth.sso.audit import (
                                    record_event,
                                )

                                await record_event(
                                    db=None,
                                    event="session.idp_token_expired",
                                    user_id=user.id,
                                    provider_id=provider_row.id,
                                    request=request,
                                    details={
                                        "idp_expires_at": (
                                            oauth_account.idp_token_expires_at.isoformat()
                                        ),
                                    },
                                )
                            except Exception:
                                pass
                            raise HTTPException(
                                status_code=status.HTTP_401_UNAUTHORIZED,
                                detail=(
                                    "IdP session expired; please log in again "
                                    "via your identity provider."
                                ),
                            )
    except HTTPException:
        raise
    except Exception:
        # Bind check is best-effort. A DB hiccup must NEVER lock users out.
        logger.warning(
            "auth.refresh.idp_bind_check_failed",
            extra={"user_id": user.id},
            exc_info=True,
        )

    # Rotate the refresh token by generating a new one and setting the cookie.
    # Include typ=REFRESH_TOKEN_TYPE to prevent access-token-as-refresh-token
    # confusion (V09.2.2) and carry original_iat for absolute-lifetime enforcement.
    new_refresh_payload = {
        "sub": str(user.id),
        "aud": AUDIENCE,
        "typ": REFRESH_TOKEN_TYPE,
        "original_iat": original_iat,
        "exp": datetime.now(timezone.utc).timestamp()
        + settings.REFRESH_TOKEN_LIFETIME_SECONDS,
    }
    new_refresh_token = jwt.encode(
        new_refresh_payload,
        _secret_key,
        algorithm=ALGORITHM,
    )
    await strategy.write_refresh_token(response, new_refresh_token)

    # M12: never log plaintext email — hash for correlation.
    import hashlib as _hashlib

    _email_hash = _hashlib.sha256(user.email.lower().encode()).hexdigest()[:12]
    logger.info(
        "auth.refresh.success",
        extra={"user_id": user.id, "email_hash": _email_hash},
    )

    return {
        "access_token": new_access_token,
        "token_type": "bearer",
    }
