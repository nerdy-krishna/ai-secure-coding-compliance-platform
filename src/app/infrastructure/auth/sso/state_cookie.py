"""Signed, short-lived `__Host-sso_state` cookie carrying the OIDC/SAML
state required to validate a callback (M2).

Why a cookie and not an in-process LRU?
  * Multi-worker uvicorn breaks an in-process LRU because the callback
    can hit a different worker than ``/login``.
  * Browser cookies stick to the (top-level) site automatically.
  * ``__Host-`` prefix means the cookie is HTTPS-only, has no Domain
    attribute (host-only), and Path=/. We get CSRF-style binding for free.

Contents (signed via itsdangerous + ``settings.SECRET_KEY``):
  * ``provider_id``  — UUID of the SSO provider this flow targets
  * ``nonce``        — OIDC nonce (binding the id_token to this flow)
  * ``state``        — random opaque value (echoed back as ``?state=``)
  * ``return_to``    — relative path the frontend should land on after auth
  * ``code_verifier``— PKCE verifier (OIDC); empty for SAML
  * ``ts``           — issue time (epoch seconds; we reject after 10 min)

The cookie is set on ``/login`` and DELETED on ``/callback`` / ``/acs``
after successful validation. Failures don't clear it (the next request
will overwrite anyway).
"""

from __future__ import annotations

import secrets
import time
from typing import Optional, TypedDict

from fastapi import Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config.config import settings


COOKIE_NAME = "__Host-sso_state"
COOKIE_MAX_AGE_SECONDS = 600  # 10 minutes
_SALT = "sso-state-cookie-v1"


def _serializer() -> URLSafeTimedSerializer:
    secret = (
        settings.SECRET_KEY.get_secret_value()
        if hasattr(settings.SECRET_KEY, "get_secret_value")
        else str(settings.SECRET_KEY)
    )
    return URLSafeTimedSerializer(secret, salt=_SALT)


class SsoStateClaims(TypedDict):
    provider_id: str
    nonce: str
    state: str
    return_to: str
    code_verifier: str
    ts: int


def make_state(
    provider_id: str,
    return_to: str = "/analysis/results",
    code_verifier: str = "",
) -> tuple[str, SsoStateClaims]:
    """Generate state + nonce + (optional) PKCE verifier; return (cookie_value, claims).

    The cookie value is the *signed* envelope; the claims dict is what the
    caller embeds into the IdP authorize URL (``state=`` + ``nonce=``).
    """
    nonce = secrets.token_urlsafe(32)
    state = secrets.token_urlsafe(32)
    claims: SsoStateClaims = {
        "provider_id": str(provider_id),
        "nonce": nonce,
        "state": state,
        "return_to": return_to,
        "code_verifier": code_verifier,
        "ts": int(time.time()),
    }
    return _serializer().dumps(claims), claims


def set_state_cookie(response: Response, value: str) -> None:
    """Attach the signed state cookie. ``__Host-`` prefix forces HTTPS-only
    and strict Path=/ semantics (cookie is host-only, no Domain attribute).
    """
    response.set_cookie(
        key=COOKIE_NAME,
        value=value,
        max_age=COOKIE_MAX_AGE_SECONDS,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",  # SAML POST-binding back to /acs requires lax (not strict)
    )


def consume_state(cookie_value: str) -> SsoStateClaims:
    """Verify the signed cookie and return its claims.

    Raises:
        SignatureExpired: cookie older than ``COOKIE_MAX_AGE_SECONDS``.
        BadSignature: tampered or wrong-signature cookie.
        ValueError: claims shape is wrong.
    """
    if not cookie_value:
        raise BadSignature("missing state cookie")
    payload = _serializer().loads(cookie_value, max_age=COOKIE_MAX_AGE_SECONDS)
    if not isinstance(payload, dict):
        raise ValueError("state cookie payload is not a dict")
    required = {"provider_id", "nonce", "state", "return_to", "ts"}
    if not required.issubset(payload.keys()):
        raise ValueError(
            "state cookie payload missing keys: " f"{required - set(payload.keys())}"
        )
    return payload  # type: ignore[return-value]


def clear_state_cookie(response: Response) -> None:
    # Match the original cookie's attributes on deletion. RFC 6265 specifies
    # that browsers match on (name, path, domain) for cookie removal, but
    # some corporate proxies / older browsers also require the Secure /
    # SameSite attributes to align before honouring the deletion. Set them
    # explicitly to be safe.
    response.set_cookie(
        key=COOKIE_NAME,
        value="",
        max_age=0,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


__all__ = [
    "COOKIE_NAME",
    "SsoStateClaims",
    "make_state",
    "set_state_cookie",
    "consume_state",
    "clear_state_cookie",
    "BadSignature",
    "SignatureExpired",
    "Optional",
]
