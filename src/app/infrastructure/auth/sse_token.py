"""Short-lived, resource-bound JWTs for Code Scan and Pentesting SSE streams.

EventSource cannot send custom headers, so SSE endpoints accept the
token via `?access_token=<jwt>`. The risk of a query-string token is
that it shows up in nginx / proxy access logs (V14.2.1). This module
mitigates that with three constraints baked into the token:

- **Audience is `sse:scan-stream`** — the verifier rejects normal
  fastapi-users access tokens used here, and rejects these tokens
  at any non-SSE endpoint that calls `read_token()`. The two token
  classes can't be substituted for one another.
- **`scan_id` and `tenant_id` claims bind the token to one tenant scan.**
  The selected tenant comes from the authorized stream-token request. The verifier
  rejects a token presented at a different scan's stream URL — so a
  leaked token can't be replayed to read another scan.
- **60s TTL** — short enough that a token captured from an access log
  has a small replay window; long enough for the regular connect path
  on a slow client.

The HMAC secret is reused from `settings.SECRET_KEY` (same secret the
fastapi-users JWT strategy signs with). That keeps the secret-rotation
story simple — rotate one key, both classes invalidate together.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
from fastapi import HTTPException, status

from app.config.config import settings

logger = logging.getLogger(__name__)

AUDIENCE: str = "sse:scan-stream"
PENTEST_AUDIENCE: str = "sse:pentest-engagement"
DEFAULT_TTL_SECONDS: int = 60
_ALGORITHM: str = "HS256"


def _secret() -> str:
    """Pull the HMAC secret out of `settings.SECRET_KEY` (Pydantic SecretStr)."""
    raw = settings.SECRET_KEY
    return raw.get_secret_value() if hasattr(raw, "get_secret_value") else str(raw)


def mint_scan_stream_token(
    user_id: int,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> tuple[str, int]:
    """Mint a JWT bound to `(user_id, tenant_id, scan_id)` with a short TTL.

    Returns the encoded token plus the TTL in seconds (so the caller
    can echo it to the client without re-deriving).
    """
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "scan_id": str(scan_id),
        "tenant_id": str(tenant_id),
        "aud": AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    token = pyjwt.encode(payload, _secret(), algorithm=_ALGORITHM)
    return token, ttl_seconds


def verify_scan_stream_token(
    token: str,
    expected_scan_id: uuid.UUID,
) -> tuple[int, uuid.UUID]:
    """Verify a token and return its user and selected tenant.

    Raises HTTPException(401) on signature failure, audience mismatch,
    expiry, missing/wrong scan or tenant claims, or non-integer sub. The
    response body is intentionally generic so a caller can't probe
    which check failed.
    """
    try:
        decoded = pyjwt.decode(
            token,
            _secret(),
            algorithms=[_ALGORITHM],
            audience=AUDIENCE,
        )
    except pyjwt.InvalidTokenError:
        # Catches every signature/audience/expiry failure. We
        # deliberately don't differentiate in the error response.
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid stream token.",
        )

    claimed_scan_id = decoded.get("scan_id")
    if not claimed_scan_id or claimed_scan_id != str(expected_scan_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid stream token.",
        )
    try:
        return int(decoded.get("sub")), uuid.UUID(str(decoded.get("tenant_id")))
    except (TypeError, ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid stream token.",
        )


def mint_pentest_stream_token(
    user_id: int,
    engagement_id: uuid.UUID,
    tenant_id: uuid.UUID,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> tuple[str, int]:
    """Mint a short-lived token bound to one Pentesting engagement."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "engagement_id": str(engagement_id),
        "tenant_id": str(tenant_id),
        "aud": PENTEST_AUDIENCE,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
        "jti": str(uuid.uuid4()),
    }
    return pyjwt.encode(payload, _secret(), algorithm=_ALGORITHM), ttl_seconds


def verify_pentest_stream_token(
    token: str, expected_engagement_id: uuid.UUID
) -> tuple[int, uuid.UUID]:
    try:
        decoded = pyjwt.decode(
            token, _secret(), algorithms=[_ALGORITHM], audience=PENTEST_AUDIENCE
        )
        if decoded.get("engagement_id") != str(expected_engagement_id):
            raise pyjwt.InvalidTokenError
        return int(decoded["sub"]), uuid.UUID(str(decoded["tenant_id"]))
    except (pyjwt.InvalidTokenError, KeyError, TypeError, ValueError, AttributeError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid stream token.",
        )
