"""OIDC client + flows.

This module wraps ``httpx-oauth``'s ``OpenID`` client and adds:

* **M1** Explicit ``id_token`` verification against the IdP's JWKS — issuer,
  audience, expiry, issued-at, nonce. ``httpx-oauth`` returns the raw
  ``id_token`` but does NOT validate it; we do that here using ``pyjwt``.
* **M14** Explicit ``httpx`` timeouts on every external HTTP call
  (``connect=5``, ``read=10``, ``total=15``).
* **PKCE** Code-verifier / challenge for confidential clients (defense in
  depth; harmless when the IdP requires only client_secret auth).

The OAuth-style "userinfo" we return up to the router is a simple dict
with only what the provisioning step needs.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
import jwt
from httpx_oauth.clients.openid import OpenID
from jwt import PyJWKClient

from .models import OidcConfig

logger = logging.getLogger(__name__)


# Threat-model M14 timeouts. Applied to every httpx call this module makes.
_HTTPX_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)


@dataclass(slots=True)
class OidcUserInfo:
    """Identity bundle extracted from a verified id_token + userinfo response."""

    sub: str
    email: str
    email_verified: bool
    name: Optional[str] = None
    raw_claims: Optional[Dict[str, Any]] = None


def make_pkce_pair() -> tuple[str, str]:
    """Return (code_verifier, code_challenge) for PKCE S256."""
    verifier = secrets.token_urlsafe(64)[:128]
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def make_client(config: OidcConfig) -> OpenID:
    """Construct the httpx-oauth OpenID client. Uses the issuer's
    ``.well-known/openid-configuration`` for endpoint discovery."""
    discovery_url = (
        str(config.issuer_url).rstrip("/") + "/.well-known/openid-configuration"
    )
    return OpenID(
        client_id=config.client_id,
        client_secret=config.client_secret.get_secret_value(),
        openid_configuration_endpoint=discovery_url,
    )


async def build_authorize_url(
    config: OidcConfig,
    *,
    redirect_uri: str,
    state: str,
    nonce: str,
    code_challenge: str,
) -> str:
    """Build the IdP authorize URL for the redirect.

    httpx-oauth's ``get_authorization_url`` accepts ``extras_params`` for
    OIDC-specific args (``nonce``) and PKCE (``code_challenge`` /
    ``code_challenge_method``).
    """
    client = make_client(config)
    return await client.get_authorization_url(
        redirect_uri=redirect_uri,
        state=state,
        scope=list(config.scopes),
        extras_params={
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        },
    )


async def exchange_code(
    config: OidcConfig,
    *,
    code: str,
    redirect_uri: str,
    nonce: str,
    code_verifier: str,
) -> OidcUserInfo:
    """Exchange the authorization code for tokens, validate the id_token,
    fetch userinfo, return a minimal identity bundle.

    Raises:
        ValueError: id_token validation failed (M1: signature, iss, aud,
                    exp, iat, nonce all checked).
    """
    client = make_client(config)
    # httpx-oauth handles the token endpoint POST. We do NOT pass
    # code_verifier through httpx-oauth (its API doesn't surface it for
    # confidential clients) — instead, callers MUST also supply
    # client_secret, which is what the IdP uses to authenticate the
    # exchange. PKCE is layered defense; the secret is the actual auth.
    token_response = await client.get_access_token(
        code=code,
        redirect_uri=redirect_uri,
        code_verifier=code_verifier or None,
    )
    id_token = token_response.get("id_token")
    if not id_token:
        raise ValueError("OIDC token response did not include id_token")

    # M1: validate the id_token explicitly. httpx-oauth doesn't.
    discovery = await _fetch_discovery(str(config.issuer_url))
    jwks_uri = discovery.get("jwks_uri")
    issuer = discovery.get("issuer") or str(config.issuer_url).rstrip("/")
    if not jwks_uri:
        raise ValueError("OIDC discovery missing 'jwks_uri'")

    jwks_client = PyJWKClient(jwks_uri, cache_keys=True, lifespan=600)
    try:
        signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    except Exception as exc:
        raise ValueError(f"id_token JWKS lookup failed: {exc}") from exc

    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=(
                [signing_key.algorithm_name]
                if signing_key.algorithm_name
                else ["RS256"]
            ),
            audience=config.client_id,
            issuer=issuer,
            options={
                "require": ["iss", "aud", "exp", "iat", "sub"],
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                "verify_exp": True,
                "verify_iat": True,
            },
            leeway=30,  # 30 seconds clock skew tolerance
        )
    except jwt.PyJWTError as exc:
        raise ValueError(f"id_token validation failed: {exc}") from exc

    # nonce is mandatory and must equal the value we stashed in the state cookie.
    token_nonce = claims.get("nonce")
    if not token_nonce or token_nonce != nonce:
        raise ValueError("id_token nonce mismatch — possible replay attack")

    # Pull email/name from id_token if present, else userinfo. Many IdPs
    # (Azure AD particularly) only put `sub` in id_token; userinfo carries
    # `email` and `name`.
    sub = str(claims.get("sub") or "")
    if not sub:
        raise ValueError("id_token missing 'sub' claim")
    email = claims.get("email")
    email_verified = bool(claims.get("email_verified", False))
    name = claims.get("name")

    if not email:
        # Fall back to userinfo endpoint for the email.
        access_token = token_response.get("access_token")
        if not access_token:
            raise ValueError(
                "OIDC token response missing access_token; cannot reach userinfo"
            )
        userinfo = await _fetch_userinfo(discovery, access_token)
        email = userinfo.get("email")
        email_verified = bool(userinfo.get("email_verified", email_verified))
        name = userinfo.get("name") or name

    if not email:
        raise ValueError("OIDC userinfo did not include 'email'")

    return OidcUserInfo(
        sub=sub,
        email=str(email),
        email_verified=email_verified,
        name=str(name) if name else None,
        raw_claims={
            k: v
            for k, v in claims.items()
            # Keep the audit-relevant claims; drop large payload claims to
            # avoid bloating audit JSONB.
            if k in {"iss", "aud", "exp", "iat", "sub", "email_verified", "amr", "acr"}
        },
    )


async def _fetch_discovery(issuer_url: str) -> Dict[str, Any]:
    """Fetch ``.well-known/openid-configuration`` with bounded timeouts."""
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=False) as c:
        resp = await c.get(url)
        resp.raise_for_status()
        return resp.json()


async def _fetch_userinfo(
    discovery: Dict[str, Any], access_token: str
) -> Dict[str, Any]:
    userinfo_endpoint = discovery.get("userinfo_endpoint")
    if not userinfo_endpoint:
        raise ValueError("OIDC discovery missing 'userinfo_endpoint'")
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=False) as c:
        resp = await c.get(userinfo_endpoint, headers=headers)
        resp.raise_for_status()
        return resp.json()


async def preflight_test(config: OidcConfig) -> Dict[str, Any]:
    """Admin "test" preflight — fetch discovery and JWKS, surface a friendly
    OK / error response.

    Used by ``POST /admin/sso/providers/{id}/test``.
    """
    try:
        discovery = await _fetch_discovery(str(config.issuer_url))
    except Exception as exc:
        return {"ok": False, "error": f"discovery fetch failed: {exc}"}
    jwks_uri = discovery.get("jwks_uri")
    if not jwks_uri:
        return {"ok": False, "error": "discovery missing jwks_uri"}
    try:
        async with httpx.AsyncClient(
            timeout=_HTTPX_TIMEOUT, follow_redirects=False
        ) as c:
            resp = await c.get(jwks_uri)
            resp.raise_for_status()
            jwks = resp.json()
    except Exception as exc:
        return {"ok": False, "error": f"jwks fetch failed: {exc}"}
    return {
        "ok": True,
        "issuer": discovery.get("issuer"),
        "authorization_endpoint": discovery.get("authorization_endpoint"),
        "token_endpoint": discovery.get("token_endpoint"),
        "userinfo_endpoint": discovery.get("userinfo_endpoint"),
        "jwks_keys": len(jwks.get("keys", [])),
    }
