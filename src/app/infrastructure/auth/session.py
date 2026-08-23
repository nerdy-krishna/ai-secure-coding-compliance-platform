"""Stateful browser-session credentials and lifecycle policy.

The wire credential is opaque application data, not a JWT and not a bearer
access token. Its MAC is checked before the session UUID is trusted, which
prevents guessed identifiers from becoming a session-revocation oracle.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.auth_session_repo import (
    AuthSessionRepository,
)


TOKEN_VERSION = "v1"
SECRET_BYTES = 32
_MAC_DOMAIN = b"sccap/browser-session/credential/v1\0"
_SECRET_DOMAIN = b"sccap/browser-session/secret/v1\0"
_METADATA_DOMAIN = b"sccap/browser-session/metadata/v1\0"
_CSRF_DOMAIN = b"sccap/browser-session/csrf/v1\0"
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


class SessionError(Exception):
    """Base class for browser-session trust failures."""


class InvalidSessionCredential(SessionError):
    pass


class SessionExpired(SessionError):
    pass


class SessionRevoked(SessionError):
    pass


class SessionReuseDetected(SessionError):
    pass


class InvalidCsrfRequest(SessionError):
    pass


class SessionLimitExceeded(SessionError):
    def __init__(self, limit: int):
        self.limit = limit
        super().__init__(f"Concurrent browser-session limit ({limit}) reached.")


@dataclass(frozen=True, slots=True)
class SessionTokenClaims:
    session_id: uuid.UUID
    generation: int
    secret: str


@dataclass(frozen=True, slots=True)
class IssuedSession:
    row: db_models.AuthSession
    credential: str


@dataclass(frozen=True, slots=True)
class SessionPolicy:
    idle_seconds: int
    absolute_seconds: int
    touch_interval_seconds: int

    @classmethod
    def from_settings(cls) -> "SessionPolicy":
        from app.core.config_cache import SystemConfigCache

        configured_hours = SystemConfigCache.get_session_lifetime_hours()
        return cls(
            idle_seconds=settings.SESSION_IDLE_LIFETIME_SECONDS,
            absolute_seconds=(
                configured_hours * 3600
                if configured_hours is not None
                else settings.SESSION_ABSOLUTE_LIFETIME_SECONDS
            ),
            touch_interval_seconds=settings.SESSION_TOUCH_INTERVAL_SECONDS,
        )


def _signing_key() -> bytes:
    value = settings.SECRET_KEY
    raw = value.get_secret_value() if hasattr(value, "get_secret_value") else str(value)
    return raw.encode("utf-8")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _new_secret() -> str:
    return _b64url(secrets.token_bytes(SECRET_BYTES))


def secret_digest(secret: str) -> str:
    return hmac.new(
        _signing_key(), _SECRET_DOMAIN + secret.encode(), hashlib.sha256
    ).hexdigest()


def privacy_digest(value: str) -> str:
    return hmac.new(
        _signing_key(), _METADATA_DOMAIN + value.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def provider_session_digest(value: str | None) -> str | None:
    return privacy_digest(value) if value else None


def encode_session_credential(
    session_id: uuid.UUID,
    generation: int,
    secret: str,
) -> str:
    body = f"{TOKEN_VERSION}.{session_id.hex}.{generation}.{secret}"
    mac = hmac.new(_signing_key(), _MAC_DOMAIN + body.encode(), hashlib.sha256).digest()
    return f"{body}.{_b64url(mac)}"


def decode_session_credential(value: str) -> SessionTokenClaims:
    try:
        version, session_hex, generation_raw, secret, supplied_mac = value.split(".")
        session_id = uuid.UUID(hex=session_hex)
        generation = int(generation_raw)
    except (AttributeError, TypeError, ValueError) as exc:
        raise InvalidSessionCredential("Malformed browser session credential.") from exc
    if version != TOKEN_VERSION or generation < 0 or len(secret) < 40:
        raise InvalidSessionCredential("Malformed browser session credential.")
    body = f"{version}.{session_hex}.{generation}.{secret}"
    expected = _b64url(
        hmac.new(_signing_key(), _MAC_DOMAIN + body.encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(expected, supplied_mac):
        raise InvalidSessionCredential("Invalid browser session credential.")
    return SessionTokenClaims(
        session_id=session_id, generation=generation, secret=secret
    )


def issue_csrf_token(session_id: uuid.UUID) -> str:
    """Return an unguessable, session-bound double-submit header value."""
    nonce = _b64url(secrets.token_bytes(SECRET_BYTES))
    body = f"{TOKEN_VERSION}.{session_id.hex}.{nonce}"
    mac = hmac.new(_signing_key(), _CSRF_DOMAIN + body.encode(), hashlib.sha256)
    return f"{body}.{_b64url(mac.digest())}"


def verify_csrf_token(value: str, session_id: uuid.UUID) -> None:
    try:
        version, session_hex, nonce, supplied_mac = value.split(".")
        token_session_id = uuid.UUID(hex=session_hex)
    except (AttributeError, TypeError, ValueError) as exc:
        raise InvalidCsrfRequest("Malformed CSRF token.") from exc
    if version != TOKEN_VERSION or token_session_id != session_id or len(nonce) < 40:
        raise InvalidCsrfRequest("Invalid CSRF token.")
    body = f"{version}.{session_hex}.{nonce}"
    expected = _b64url(
        hmac.new(_signing_key(), _CSRF_DOMAIN + body.encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(expected, supplied_mac):
        raise InvalidCsrfRequest("Invalid CSRF token.")


def _normalized_origin(value: str) -> str | None:
    try:
        parsed = urlsplit(value)
    except ValueError:
        return None
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password or parsed.path not in {"", "/"}:
        return None
    if parsed.query or parsed.fragment:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    default_port = (parsed.scheme == "http" and port == 80) or (
        parsed.scheme == "https" and port == 443
    )
    authority = parsed.hostname.lower()
    if port is not None and not default_port:
        authority = f"{authority}:{port}"
    return f"{parsed.scheme}://{authority}"


def allowed_browser_origins(request: Request) -> set[str]:
    """Resolve the exact origins trusted for credentialed browser requests."""
    from app.core.config_cache import SystemConfigCache

    candidates = set(settings.ALLOWED_ORIGINS)
    candidates.add(settings.frontend_base_url)
    if SystemConfigCache.is_cors_enabled():
        candidates.update(SystemConfigCache.get_allowed_origins())
    candidates.add(str(request.base_url).rstrip("/"))
    return {
        normalized
        for value in candidates
        if value and (normalized := _normalized_origin(value)) is not None
    }


def enforce_cookie_csrf(request: Request, session_id: uuid.UUID) -> None:
    """Require exact-origin and session-bound CSRF proof on unsafe methods."""
    if request.method.upper() in _SAFE_METHODS:
        return
    origin = _normalized_origin(request.headers.get("origin", ""))
    if origin is None or origin not in allowed_browser_origins(request):
        raise InvalidCsrfRequest("Request origin is not allowed.")
    token = request.headers.get("x-csrf-token", "")
    verify_csrf_token(token, session_id)


def _utc(value: datetime | None = None) -> datetime:
    now = value or datetime.now(timezone.utc)
    return now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)


def _coarse_device_label(request: Request | None) -> str | None:
    if request is None:
        return None
    ua = request.headers.get("user-agent", "")
    if not ua:
        return None
    browser = "Browser"
    for marker, name in (
        ("Edg/", "Edge"),
        ("Firefox/", "Firefox"),
        ("Chrome/", "Chrome"),
        ("Safari/", "Safari"),
    ):
        if marker in ua:
            browser = name
            break
    os_name = "Unknown OS"
    for marker, name in (
        ("Android", "Android"),
        ("iPhone", "iOS"),
        ("iPad", "iOS"),
        ("Windows", "Windows"),
        ("Macintosh", "macOS"),
        ("Linux", "Linux"),
    ):
        if marker in ua:
            os_name = name
            break
    return f"{browser} on {os_name}"[:128]


def _request_ip_hash(request: Request | None) -> str | None:
    if request is None or request.client is None or not request.client.host:
        return None
    # The trusted-proxy resolver remains the audit layer's responsibility.
    # This inventory hint deliberately hashes only the direct peer and never
    # trusts a caller-supplied forwarding header.
    return privacy_digest(request.client.host)


class BrowserSessionService:
    def __init__(
        self,
        db: AsyncSession,
        *,
        policy: SessionPolicy | None = None,
    ):
        self.db = db
        self.repo = AuthSessionRepository(db)
        self.policy = policy or SessionPolicy.from_settings()

    async def _enforce_concurrency_limit(
        self,
        user: db_models.User,
        *,
        request: Request | None,
        now: datetime,
    ) -> None:
        if user.tenant_id is None:
            return
        tenant = await self.db.get(db_models.Tenant, user.tenant_id)
        if tenant is None or tenant.session_concurrency_limit is None:
            return
        limit = tenant.session_concurrency_limit
        # Serialize the count-and-create decision per user. A tenant-wide lock
        # would turn unrelated users logging in at once into a bottleneck.
        await self.db.execute(
            select(db_models.User.id)
            .where(db_models.User.id == user.id)
            .with_for_update()
        )
        active = await self.repo.list_for_user(user.id)
        if len(active) < limit:
            return
        if tenant.session_concurrency_mode == "deny_new":
            from app.infrastructure.auth.sso.audit import record_in_new_session

            await record_in_new_session(
                event="session.concurrent_limit_denied",
                user_id=user.id,
                actor_user_id=user.id,
                tenant_id=user.tenant_id,
                outcome="denied",
                request=request,
                details={"limit": limit, "mode": "deny_new"},
            )
            raise SessionLimitExceeded(limit)

        revoke_count = len(active) - limit + 1
        oldest = sorted(active, key=lambda row: (row.created_at, str(row.id)))[
            :revoke_count
        ]
        for row in oldest:
            await self.repo.revoke(row, reason="concurrency_revoke_oldest", now=now)
        from app.infrastructure.auth.sso.audit import record

        await record(
            self.db,
            event="session.concurrent_limit_enforced",
            user_id=user.id,
            actor_user_id=user.id,
            tenant_id=user.tenant_id,
            outcome="success",
            request=request,
            details={
                "limit": limit,
                "mode": "revoke_oldest",
                "revoked_count": len(oldest),
            },
        )

    async def create(
        self,
        user: db_models.User,
        *,
        auth_method: str,
        assurance_level: str = "aal1",
        provider_id: uuid.UUID | None = None,
        provider_session_id: str | None = None,
        request: Request | None = None,
        now: datetime | None = None,
    ) -> IssuedSession:
        issued_at = _utc(now)
        await self._enforce_concurrency_limit(
            user,
            request=request,
            now=issued_at,
        )
        absolute_expires_at = issued_at + timedelta(
            seconds=self.policy.absolute_seconds
        )
        idle_expires_at = min(
            issued_at + timedelta(seconds=self.policy.idle_seconds),
            absolute_expires_at,
        )
        secret = _new_secret()
        row = await self.repo.create(
            user_id=user.id,
            tenant_id=user.tenant_id,
            provider_id=provider_id,
            auth_method=auth_method,
            provider_session_hash=provider_session_digest(provider_session_id),
            assurance_level=assurance_level,
            credential_secret_hash=secret_digest(secret),
            authenticated_at=issued_at,
            last_seen_at=issued_at,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            ip_hash=_request_ip_hash(request),
            device_label=_coarse_device_label(request),
        )
        return IssuedSession(
            row=row,
            credential=encode_session_credential(row.id, 0, secret),
        )

    async def rotate(
        self,
        credential: str,
        *,
        now: datetime | None = None,
    ) -> IssuedSession:
        claims = decode_session_credential(credential)
        current_time = _utc(now)
        row = await self.repo.get_for_update(claims.session_id)
        if row is None:
            raise InvalidSessionCredential("Unknown browser session.")
        if row.revoked_at is not None:
            raise SessionRevoked("Browser session has been revoked.")
        if current_time >= row.absolute_expires_at:
            await self.repo.revoke(row, reason="absolute_timeout", now=current_time)
            raise SessionExpired("Browser session absolute lifetime exceeded.")
        if current_time >= row.idle_expires_at:
            await self.repo.revoke(row, reason="idle_timeout", now=current_time)
            raise SessionExpired("Browser session inactivity lifetime exceeded.")
        if claims.generation < row.credential_generation:
            await self.repo.revoke(row, reason="credential_reuse", now=current_time)
            raise SessionReuseDetected("Browser session credential reuse detected.")
        if claims.generation != row.credential_generation or not hmac.compare_digest(
            secret_digest(claims.secret), row.credential_secret_hash
        ):
            raise InvalidSessionCredential("Invalid browser session credential.")

        new_secret = _new_secret()
        new_generation = row.credential_generation + 1
        row.credential_generation = new_generation
        row.credential_secret_hash = secret_digest(new_secret)
        row.last_seen_at = current_time
        row.idle_expires_at = min(
            current_time + timedelta(seconds=self.policy.idle_seconds),
            row.absolute_expires_at,
        )
        await self.db.flush()
        return IssuedSession(
            row=row,
            credential=encode_session_credential(row.id, new_generation, new_secret),
        )

    async def authenticate(
        self,
        credential: str,
        *,
        now: datetime | None = None,
    ) -> db_models.AuthSession:
        claims = decode_session_credential(credential)
        current_time = _utc(now)
        row = await self.repo.get_for_update(claims.session_id)
        if row is None:
            raise InvalidSessionCredential("Unknown browser session.")
        if row.revoked_at is not None:
            raise SessionRevoked("Browser session has been revoked.")
        if current_time >= row.absolute_expires_at:
            await self.repo.revoke(row, reason="absolute_timeout", now=current_time)
            raise SessionExpired("Browser session absolute lifetime exceeded.")
        if current_time >= row.idle_expires_at:
            await self.repo.revoke(row, reason="idle_timeout", now=current_time)
            raise SessionExpired("Browser session inactivity lifetime exceeded.")
        if claims.generation != row.credential_generation or not hmac.compare_digest(
            secret_digest(claims.secret), row.credential_secret_hash
        ):
            raise InvalidSessionCredential("Invalid browser session credential.")
        if current_time - row.last_seen_at >= timedelta(
            seconds=self.policy.touch_interval_seconds
        ):
            row.last_seen_at = current_time
            row.idle_expires_at = min(
                current_time + timedelta(seconds=self.policy.idle_seconds),
                row.absolute_expires_at,
            )
            await self.db.flush()
        return row
