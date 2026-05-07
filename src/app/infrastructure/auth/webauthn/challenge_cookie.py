"""Signed `__Host-webauthn_challenge` cookie for the begin/finish bridge.

The WebAuthn ceremony is a two-step exchange:

  begin   →  server issues a one-time random challenge + options
             (rp, user, pubKeyCredParams …); browser passes them to the
             authenticator
  finish  →  browser POSTs back the authenticator's signed assertion;
             server verifies the signature is over the challenge it
             issued

We persist the challenge between those two requests in a signed,
HttpOnly cookie. Multi-worker safe (no in-process state). 5-minute TTL
matches the SSO state cookie.

Two ceremony types share the same shape: registration and authentication.
We discriminate via a ``kind`` field so a stolen registration challenge
can't be replayed against the login finish endpoint.
"""

from __future__ import annotations

import secrets
import time
from typing import Literal, Optional, TypedDict

from fastapi import Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from app.config.config import settings


COOKIE_NAME = "__Host-webauthn_challenge"
COOKIE_MAX_AGE_SECONDS = 300  # 5 minutes
_SALT = "webauthn-challenge-cookie-v1"


def _serializer() -> URLSafeTimedSerializer:
    secret = (
        settings.SECRET_KEY.get_secret_value()
        if hasattr(settings.SECRET_KEY, "get_secret_value")
        else str(settings.SECRET_KEY)
    )
    return URLSafeTimedSerializer(secret, salt=_SALT)


WebAuthnCeremony = Literal["register", "login"]


class WebAuthnChallengeClaims(TypedDict):
    kind: WebAuthnCeremony
    # base64url-encoded challenge bytes (the same shape py_webauthn returns
    # in `options.challenge`).
    challenge: str
    # Bound to a user_id when registering (the register/begin endpoint
    # requires authenticated session so we know who's adding a passkey).
    # null on login flow because the user identifies themselves via the
    # asserted credential_id.
    user_id: Optional[int]
    ts: int


def make_challenge(
    *, kind: WebAuthnCeremony, user_id: Optional[int] = None
) -> tuple[str, bytes]:
    """Generate (cookie_value, raw_challenge_bytes).

    The cookie carries the base64url-encoded challenge; the raw bytes
    are what we hand to py_webauthn options builders.
    """
    raw = secrets.token_bytes(32)
    # py_webauthn expects bytes; the cookie stores a URL-safe representation.
    import base64

    encoded = base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
    claims: WebAuthnChallengeClaims = {
        "kind": kind,
        "challenge": encoded,
        "user_id": user_id,
        "ts": int(time.time()),
    }
    return _serializer().dumps(claims), raw


def set_challenge_cookie(response: Response, value: str) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=value,
        max_age=COOKIE_MAX_AGE_SECONDS,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def consume_challenge(
    cookie_value: Optional[str], expected_kind: WebAuthnCeremony
) -> WebAuthnChallengeClaims:
    """Verify cookie and ceremony type. Returns claims; raises on mismatch.

    Caller is responsible for clearing the cookie after a successful
    finish — this function does NOT modify the response.
    """
    if not cookie_value:
        raise BadSignature("missing webauthn challenge cookie")
    payload = _serializer().loads(cookie_value, max_age=COOKIE_MAX_AGE_SECONDS)
    if not isinstance(payload, dict) or "challenge" not in payload:
        raise ValueError("malformed webauthn challenge claims")
    if payload.get("kind") != expected_kind:
        # Cross-ceremony replay: a register challenge submitted to login,
        # or vice versa.
        raise ValueError(
            f"webauthn ceremony mismatch: cookie={payload.get('kind')!r} expected={expected_kind!r}"
        )
    return payload  # type: ignore[return-value]


def clear_challenge_cookie(response: Response) -> None:
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
    "WebAuthnCeremony",
    "WebAuthnChallengeClaims",
    "make_challenge",
    "set_challenge_cookie",
    "consume_challenge",
    "clear_challenge_cookie",
    "BadSignature",
    "SignatureExpired",
]
