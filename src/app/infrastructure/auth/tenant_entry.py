"""Short-lived, credential-bound grants for explicit platform tenant entry."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from typing import TypedDict

from fastapi import Request
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config.config import settings


HEADER_NAME = "X-SCCAP-Tenant-Entry"
MAX_AGE_SECONDS = 600
_SALT = "platform-tenant-entry-v1"


class TenantEntryClaims(TypedDict):
    version: int
    user_id: int
    tenant_id: str
    credential_fingerprint: str


def _secret() -> str:
    value = settings.SECRET_KEY
    return value.get_secret_value() if hasattr(value, "get_secret_value") else str(value)


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_secret(), salt=_SALT)


def _request_credential(request: Request) -> str:
    authorization = request.headers.get("authorization", "").strip()
    if authorization.lower().startswith("bearer "):
        return f"bearer:{authorization[7:].strip()}"
    for cookie_name in ("__Host-SCCAPSession", "SCCAPSessionDev"):
        value = request.cookies.get(cookie_name)
        if value:
            return f"cookie:{value}"
    raise BadSignature("authenticated credential unavailable")


def _credential_fingerprint(request: Request) -> str:
    return hmac.new(
        _secret().encode("utf-8"),
        f"tenant-entry-credential:{_request_credential(request)}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def issue_tenant_entry_grant(
    request: Request,
    *,
    user_id: int,
    tenant_id: uuid.UUID,
) -> str:
    claims: TenantEntryClaims = {
        "version": 1,
        "user_id": user_id,
        "tenant_id": str(tenant_id),
        "credential_fingerprint": _credential_fingerprint(request),
    }
    return _serializer().dumps(claims)


def consume_tenant_entry_grant(
    request: Request,
    token: str,
    *,
    user_id: int,
) -> uuid.UUID:
    payload = _serializer().loads(token, max_age=MAX_AGE_SECONDS)
    if not isinstance(payload, dict):
        raise BadSignature("tenant-entry grant has invalid shape")
    if payload.get("version") != 1 or payload.get("user_id") != user_id:
        raise BadSignature("tenant-entry grant principal mismatch")
    expected = _credential_fingerprint(request)
    received = payload.get("credential_fingerprint")
    if not isinstance(received, str) or not hmac.compare_digest(received, expected):
        raise BadSignature("tenant-entry grant credential mismatch")
    try:
        return uuid.UUID(str(payload["tenant_id"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise BadSignature("tenant-entry grant tenant is invalid") from exc


__all__ = [
    "BadSignature",
    "HEADER_NAME",
    "MAX_AGE_SECONDS",
    "SignatureExpired",
    "consume_tenant_entry_grant",
    "issue_tenant_entry_grant",
]
