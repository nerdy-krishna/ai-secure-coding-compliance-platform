"""Force-SSO guard for the password login path (M6).

This is a *thin* router that defines a single endpoint under
``/api/v1/auth/login-guard`` — the frontend calls it BEFORE submitting the
password login form. If the email's domain is in any provider's
``force_for_domains``, the response tells the frontend to redirect to that
provider's SSO login URL instead of submitting the password form.

We do NOT replace fastapi-users' ``/auth/login`` endpoint. That keeps the
existing JWT issuance flow intact. Instead we publish this preflight
endpoint and the frontend uses it to decide whether to render the
password fields. As a defense-in-depth measure, an additional middleware
(``ForceSsoMiddleware``) below ALSO blocks the actual ``POST /auth/login``
when force-SSO would apply, in case a misbehaving client bypasses the
preflight.

The master admin (the user with ``id == security.master_admin_user_id``)
is always exempt — they can password-login regardless of force-SSO.
"""

from __future__ import annotations

import json
import logging
from typing import Optional
from urllib.parse import parse_qs

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.config.config import settings
from app.core.config_cache import SystemConfigCache
from app.infrastructure.auth.sso import audit
from app.infrastructure.auth.sso.repository import SsoProviderRepository
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import AsyncSessionLocal, get_db

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/auth", tags=["Authentication: SSO"])


def _domain_of(email: str) -> str:
    parts = email.strip().lower().split("@", 1)
    return parts[1] if len(parts) == 2 else ""


async def _is_master_admin(session: AsyncSession, email: str) -> bool:
    """True iff the user with ``email`` is the master admin (escape hatch)."""
    master_id = SystemConfigCache.get_master_admin_user_id()
    if master_id is None:
        return False
    result = await session.execute(
        select(db_models.User.id).where(db_models.User.email == email.strip().lower())
    )
    user_id = result.scalar_one_or_none()
    if user_id is None:
        return False
    return int(user_id) == int(master_id)


async def _resolve_forced_provider(
    session: AsyncSession, email: str
) -> Optional[db_models.SsoProvider]:
    """If any enabled provider's ``force_for_domains`` matches the email's
    domain, return the first one. Otherwise None."""
    repo = SsoProviderRepository(session)
    rows = await repo.list_enabled()
    domain = _domain_of(email)
    if not domain:
        return None
    for row in rows:
        ff = row.force_for_domains or []
        if domain in {d.lower() for d in ff}:
            return row
    return None


@router.get("/login-guard")
async def login_guard(
    email: str = Query(..., min_length=3, max_length=320),
    db: AsyncSession = Depends(get_db),
):
    """Frontend preflight: returns ``{forced: bool, provider: {...}}``.

    The frontend uses this to hide the password field when SSO is forced.
    """
    if await _is_master_admin(db, email):
        return {"forced": False, "is_master_admin": True}
    provider = await _resolve_forced_provider(db, email)
    if provider is None:
        return {"forced": False}
    return {
        "forced": True,
        "provider": {
            "id": str(provider.id),
            "name": provider.name,
            "display_name": provider.display_name,
            "protocol": provider.protocol,
        },
    }


# ---------- defense-in-depth middleware --------------------------------------


def _extract_email_from_form_body(body: bytes, content_type: str) -> Optional[str]:
    """Best-effort parse of a form-encoded login body to retrieve the username.

    The fastapi-users login route uses OAuth2PasswordRequestForm — body shape
    is ``application/x-www-form-urlencoded`` with keys ``username``+``password``.
    """
    if not body:
        return None
    ct = content_type.lower()
    if "application/x-www-form-urlencoded" in ct:
        try:
            parsed = parse_qs(body.decode("utf-8"), keep_blank_values=False)
        except Exception:
            return None
        for key in ("username", "email"):
            vals = parsed.get(key)
            if vals and vals[0]:
                return vals[0]
        return None
    if "application/json" in ct:
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            return None
        if isinstance(data, dict):
            for key in ("username", "email"):
                v = data.get(key)
                if isinstance(v, str) and v:
                    return v
    return None


class ForceSsoMiddleware:
    """Pure-ASGI middleware that blocks ``POST /api/v1/auth/login`` when the
    email's domain is in any enabled provider's ``force_for_domains`` list.
    The master admin (``security.master_admin_user_id``) is always exempt.

    Implemented as raw ASGI (not BaseHTTPMiddleware) so we can read the
    request body and replay it to the downstream app — BaseHTTPMiddleware
    consumes the receive stream, which would break the password login flow
    for everyone (not just force-SSO matches). See threat-model F1.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        method = scope.get("method", "")
        path = scope.get("path", "")
        if method != "POST" or path != "/api/v1/auth/login":
            await self.app(scope, receive, send)
            return

        # Buffer the body. Default cap 64 KiB — login bodies are tiny;
        # anything larger is suspicious (DoS / oversize-body) and we let
        # the inner app handle it as 413 / 422. Operators can tune via
        # ``LOGIN_BODY_MAX_BYTES`` (Polish-2).
        body_bytes = b""
        more_body = True
        max_body = settings.LOGIN_BODY_MAX_BYTES
        while more_body:
            message = await receive()
            if message["type"] == "http.disconnect":
                # Client gave up; pass through so the inner app cleans up.
                replay_message = message

                async def disconnect_receive() -> Message:
                    return replay_message

                await self.app(scope, disconnect_receive, send)
                return
            if message["type"] != "http.request":
                # Unknown message types — just forward.
                await self.app(scope, receive, send)
                return
            body_bytes += message.get("body", b"")
            more_body = message.get("more_body", False)
            if len(body_bytes) > max_body:
                more_body = False
                break

        # Build the replay receive callable BEFORE doing any DB work, so we
        # can hand the body back to the downstream app even on error paths.
        replayed = False

        async def replay_receive() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {
                    "type": "http.request",
                    "body": body_bytes,
                    "more_body": False,
                }
            return {"type": "http.disconnect"}

        # Pull Content-Type for parsing.
        headers = dict(scope.get("headers") or [])
        content_type = headers.get(b"content-type", b"").decode("latin-1", "ignore")

        email_raw = _extract_email_from_form_body(body_bytes, content_type)
        if not email_raw or "@" not in email_raw:
            await self.app(scope, replay_receive, send)
            return
        email = email_raw.strip().lower()

        # Run the policy check.
        try:
            async with AsyncSessionLocal() as session:
                if await _is_master_admin(session, email):
                    await self.app(scope, replay_receive, send)
                    return
                provider = await _resolve_forced_provider(session, email)
                if provider is None:
                    await self.app(scope, replay_receive, send)
                    return
                # Block — emit audit row first (best-effort).
                try:
                    await audit.record(
                        session,
                        event=audit.EVENT_PASSWORD_LOGIN_BLOCKED,
                        provider_id=provider.id,
                        email=email,
                        details={"domain": _domain_of(email)},
                    )
                    await session.commit()
                except Exception:
                    logger.warning(
                        "force_sso.middleware.audit_failed",
                        extra={"path": path},
                        exc_info=True,
                    )
                blocked_payload = json.dumps(
                    {
                        "detail": "Use SSO for this domain",
                        "sso_provider_id": str(provider.id),
                        "sso_provider_name": provider.name,
                    }
                ).encode("utf-8")
        except Exception:
            # Fail open: if the policy check itself errors, let the login
            # request through. Audit logger errors must never lock users out.
            logger.warning(
                "force_sso.middleware.error",
                extra={"path": path},
                exc_info=True,
            )
            await self.app(scope, replay_receive, send)
            return

        # Send the 403 response directly via the ASGI send callable.
        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_403_FORBIDDEN,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(blocked_payload)).encode("ascii")),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": blocked_payload,
            }
        )


__all__ = ["router", "ForceSsoMiddleware"]
