"""Append-only audit recorder for ``auth_audit_events``.

Mitigations:
  * **M7** — DB trigger ``auth_audit_immutable`` rejects UPDATE/DELETE.
  * **M8** — Every audit ``details`` JSONB carries the request's
             ``correlation_id`` so an audit row can be stitched to Loki
             logs by ``X-Correlation-ID``.
  * **M12** — Email is hashed (sha256[:64]) before storage; never plaintext.

Convention:
  * ``record(...)`` accepts an ``AsyncSession`` and writes within the
    caller's transaction.
  * ``record_in_new_session(...)`` opens its own session — used in fail-
    open paths (e.g. session.absolute_lifetime_exceeded) where the caller
    doesn't have a session at hand.
"""

from __future__ import annotations

import hashlib
import ipaddress
import logging
import uuid
from typing import Any, Dict, Optional

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.infrastructure.database import models as db_models

try:
    from app.config.logging_config import correlation_id_var
except Exception:  # pragma: no cover — middleware missing in tests
    correlation_id_var = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def hash_email(email: Optional[str]) -> Optional[str]:
    """Hash an email address for audit storage. Returns None for None input."""
    if not email:
        return None
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:64]


def _peer_is_trusted_proxy(peer_host: Optional[str]) -> bool:
    """True iff ``peer_host`` (the connecting socket's IP) is inside any
    CIDR block in ``settings.TRUSTED_PROXY_CIDRS``.

    Empty allowlist → returns False unconditionally (default secure: never
    honor XFF unless the operator opts in). Malformed entries in the
    allowlist are skipped silently and logged once on first failure.
    """
    if not peer_host:
        return False
    try:
        peer_ip = ipaddress.ip_address(peer_host)
    except ValueError:
        return False
    for cidr in settings.TRUSTED_PROXY_CIDRS:
        try:
            net = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            logger.warning(
                "auth_audit.bad_trusted_proxy_cidr",
                extra={"cidr": cidr},
            )
            continue
        if peer_ip in net:
            return True
    return False


def _client_ip_from_request(request: Request) -> Optional[str]:
    """Resolve the real client IP, honoring ``X-Forwarded-For`` only when
    the connecting peer is a trusted proxy.

    Walks XFF *right-to-left*, dropping each address that is itself in the
    trusted-proxy allowlist; returns the first non-trusted hop. Each hop is
    validated as a parseable IP literal — non-IP garbage in the header is
    skipped (the audit table is ``String(45)`` and operators downstream pivot
    on this field). If every XFF entry is trusted or unparseable, falls back
    to the connecting peer.

    Note (operator caveat): some reverse proxies emit the client address as
    IPv4-mapped IPv6 (e.g. ``::ffff:10.0.0.5``). ``ipaddress.ip_address`` will
    parse this as an IPv6 address, which won't match a plain ``10.0.0.0/8``
    CIDR; either configure the proxy to emit native IPv4 or add the IPv6 form
    to ``TRUSTED_PROXY_CIDRS`` (e.g. ``::ffff:10.0.0.0/104``).

    See SOC 2 / ISO 27001 evidence: audit rows must carry the actual
    end-user IP, not the proxy / load-balancer.
    """
    peer = request.client.host if request.client else None
    if not _peer_is_trusted_proxy(peer):
        return peer
    xff_raw = request.headers.get("x-forwarded-for")
    if not xff_raw:
        return peer
    # Right-most non-trusted, *parseable-IP* entry wins. Non-IP strings are
    # skipped (a malicious or buggy proxy must not poison the audit row's
    # ip column with arbitrary text).
    hops = [h.strip() for h in xff_raw.split(",") if h.strip()]
    fallback_origin: Optional[str] = None
    for hop in reversed(hops):
        try:
            ipaddress.ip_address(hop)
        except ValueError:
            continue
        if not _peer_is_trusted_proxy(hop):
            return hop
        # First parseable+trusted hop — keep it as a fallback (the leftmost
        # parseable entry would normally be the origin in a multi-proxy chain).
        fallback_origin = fallback_origin or hop
    # All parseable hops were trusted proxies — return the rightmost trusted
    # one (closest to a real client we have visibility on); else fall back to
    # the connecting peer.
    return fallback_origin or peer


def _request_extras(request: Optional[Request]) -> Dict[str, Optional[str]]:
    if request is None:
        return {"ip": None, "user_agent": None}
    ip = _client_ip_from_request(request)
    ua_full = request.headers.get("user-agent")
    ua = ua_full[:512] if ua_full else None
    return {"ip": ip, "user_agent": ua}


def _correlation_id_safe() -> Optional[str]:
    if correlation_id_var is None:
        return None
    try:
        cid = correlation_id_var.get()  # type: ignore[union-attr]
    except Exception:
        return None
    return str(cid) if cid else None


async def record(
    session: AsyncSession,
    *,
    event: str,
    user_id: Optional[int] = None,
    provider_id: Optional[uuid.UUID] = None,
    email: Optional[str] = None,
    request: Optional[Request] = None,
    details: Optional[Dict[str, Any]] = None,
) -> db_models.AuthAuditEvent:
    """Insert one audit row in the caller's transaction."""
    extras = _request_extras(request)
    payload: Dict[str, Any] = dict(details or {})
    cid = _correlation_id_safe()
    if cid:
        payload.setdefault("correlation_id", cid)

    row = db_models.AuthAuditEvent(
        event=event,
        user_id=user_id,
        provider_id=provider_id,
        email_hash=hash_email(email),
        ip=extras["ip"],
        user_agent=extras["user_agent"],
        details=payload or None,
    )
    session.add(row)
    await session.flush()
    return row


async def record_in_new_session(
    *,
    event: str,
    user_id: Optional[int] = None,
    provider_id: Optional[uuid.UUID] = None,
    email: Optional[str] = None,
    request: Optional[Request] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Open a fresh AsyncSession to write an audit row.

    Used by fail-open call sites that don't have a session at hand
    (e.g. ``refresh.py`` on session-lifetime-exceeded). Failure here is
    swallowed — auditing must NEVER block the user-facing rejection path.
    """
    try:
        from app.infrastructure.database.database import AsyncSessionLocal

        async with AsyncSessionLocal() as session:
            await record(
                session,
                event=event,
                user_id=user_id,
                provider_id=provider_id,
                email=email,
                request=request,
                details=details,
            )
            await session.commit()
    except Exception:
        # F10: dropped audit rows are observable — Loki picks up
        # `metric_name` and the WARN→ERROR bump surfaces in oncall paging.
        logger.error(
            "auth_audit.record_in_new_session_failed",
            extra={
                "event": event,
                "user_id": user_id,
                "metric_name": "auth.audit.write_failed",
                "metric_kind": "counter",
                "fail_path": "new_session",
            },
            exc_info=True,
        )


# Convenience constants — keep the event names in one place to make
# grep-able and survive renames cleanly.
EVENT_SSO_LOGIN_SUCCESS = "sso.login.success"
EVENT_SSO_LOGIN_FAILURE = "sso.login.failure"
EVENT_SSO_PROVISIONED = "sso.provisioned"
EVENT_SSO_LINKED = "sso.linked"
EVENT_SSO_LOGOUT = "sso.logout"
EVENT_SSO_LINK_REFUSED = "sso.link.refused"
EVENT_SESSION_LIFETIME_EXCEEDED = "session.absolute_lifetime_exceeded"
EVENT_PASSWORD_LOGIN_BLOCKED = "auth.password_login.blocked_by_force_sso"
EVENT_PROVIDER_CREATED = "auth.provider.created"
EVENT_PROVIDER_UPDATED = "auth.provider.updated"
EVENT_PROVIDER_DELETED = "auth.provider.deleted"


async def record_event(
    db: Optional[AsyncSession],
    *,
    event: str,
    user_id: Optional[int] = None,
    provider_id: Optional[uuid.UUID] = None,
    email: Optional[str] = None,
    request: Optional[Request] = None,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    """Convenience entrypoint — uses the caller's session when present, else
    opens a fresh one. Used by ``refresh.py`` (no session) and by SSO
    routers (session in scope)."""
    if db is None:
        await record_in_new_session(
            event=event,
            user_id=user_id,
            provider_id=provider_id,
            email=email,
            request=request,
            details=details,
        )
        return
    try:
        await record(
            db,
            event=event,
            user_id=user_id,
            provider_id=provider_id,
            email=email,
            request=request,
            details=details,
        )
    except Exception:
        # F10: same metric as record_in_new_session — Loki / Grafana can
        # alert on a non-zero rate of `auth.audit.write_failed`.
        logger.error(
            "auth_audit.record_failed",
            extra={
                "event": event,
                "user_id": user_id,
                "metric_name": "auth.audit.write_failed",
                "metric_kind": "counter",
                "fail_path": "in_session",
            },
            exc_info=True,
        )
