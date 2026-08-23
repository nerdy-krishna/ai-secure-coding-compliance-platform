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
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
import jwt
from httpx_oauth.clients.openid import OpenID

from .models import OidcConfig, _reject_internal_or_loopback

logger = logging.getLogger(__name__)


# Threat-model M14 timeouts. Applied to every httpx call this module makes.
_HTTPX_TIMEOUT = httpx.Timeout(connect=5.0, read=10.0, write=5.0, pool=5.0)
_OIDC_ALLOWED_ALGORITHMS = frozenset(
    {"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}
)
_JWKS_CACHE_SECONDS = 600
_MAX_FEDERATION_DOCUMENT_BYTES = 1024 * 1024
_BACKCHANNEL_LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
_jwks_cache: dict[str, tuple[float, Dict[str, Any]]] = {}


@dataclass(slots=True)
class OidcUserInfo:
    """Identity bundle extracted from a verified id_token + userinfo response."""

    sub: str
    email: str
    email_verified: bool
    name: Optional[str] = None
    # Audit-friendly filtered subset (iss, aud, exp, iat, sub,
    # email_verified, amr, acr).
    raw_claims: Optional[Dict[str, Any]] = None
    # Full id_token + userinfo claims, merged. Carries the group claim
    # so `provisioning._sync_groups_from_idp` can extract a configurable
    # path. NEVER persisted to the audit table — only used in-process.
    full_claims: Optional[Dict[str, Any]] = None
    # UTC wall-clock expiry of the IdP-issued access token (id_token's
    # `exp` claim, which fastapi-users pyjwt validation already enforced).
    # Used by Chunk 4's session-bind feature to mirror the IdP's session
    # ceiling on the SCCAP refresh path. Optional because not every IdP
    # discloses an exp on the token endpoint response.
    idp_token_expires_at: Optional[datetime] = None


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
    discovery = _validate_discovery(config, discovery)
    claims = await _decode_provider_jwt(
        config,
        id_token,
        discovery=discovery,
        required_claims=["iss", "aud", "exp", "iat", "sub"],
        error_label="id_token",
    )

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

    # Always fetch userinfo when we have an access_token — it commonly
    # carries the groups claim (Okta, Auth0) even if the id_token doesn't.
    # Merge userinfo over id_token claims so the merged dict is the most
    # complete view of the IdP's assertions about this user.
    full_claims: Dict[str, Any] = dict(claims)
    access_token = token_response.get("access_token")
    if access_token:
        try:
            userinfo = await _fetch_userinfo(discovery, access_token)
            full_claims.update(userinfo)
            if not email:
                email = userinfo.get("email")
                email_verified = bool(userinfo.get("email_verified", email_verified))
                name = userinfo.get("name") or name
        except Exception:
            # Userinfo fetch is best-effort. id_token alone is enough to
            # mint a session if it carries email; group sync simply runs
            # without the userinfo half of the merge.
            logger.warning(
                "oidc.userinfo_fetch_failed", extra={"sub": sub}, exc_info=True
            )

    if not email:
        raise ValueError(
            "OIDC userinfo did not include 'email' (and id_token didn't either)"
        )

    # Compute the IdP-asserted access-token expiry (Chunk 4 — session-bind).
    # Prefer the explicit `expires_at` from the token response; fall back
    # to id_token's `exp` claim (already pyjwt-validated above so it's a
    # trusted UTC timestamp).
    idp_expires_at: Optional[datetime] = None
    expires_at_raw = token_response.get("expires_at") or claims.get("exp")
    if expires_at_raw is not None:
        try:
            idp_expires_at = datetime.fromtimestamp(
                int(expires_at_raw), tz=timezone.utc
            )
        except (TypeError, ValueError, OSError):
            idp_expires_at = None

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
        full_claims=full_claims,
        idp_token_expires_at=idp_expires_at,
    )


async def _fetch_discovery(issuer_url: str) -> Dict[str, Any]:
    """Fetch ``.well-known/openid-configuration`` with bounded timeouts."""
    url = issuer_url.rstrip("/") + "/.well-known/openid-configuration"
    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=False) as c:
        resp = await c.get(url)
        return _bounded_json_response(resp, label="OIDC discovery")


def _bounded_json_response(resp: httpx.Response, *, label: str) -> Dict[str, Any]:
    resp.raise_for_status()
    if len(resp.content) > _MAX_FEDERATION_DOCUMENT_BYTES:
        raise ValueError(f"{label} document exceeds size limit")
    payload = resp.json()
    if not isinstance(payload, dict):
        raise ValueError(f"{label} document must be a JSON object")
    return payload


def _validate_discovery(
    config: OidcConfig, discovery: Dict[str, Any]
) -> Dict[str, Any]:
    """Pin discovery to the configured issuer and public HTTPS endpoints."""
    configured_issuer = str(config.issuer_url).rstrip("/")
    discovered_issuer = str(discovery.get("issuer") or "").rstrip("/")
    if discovered_issuer != configured_issuer:
        raise ValueError("OIDC discovery issuer does not match configured issuer")
    for field in (
        "authorization_endpoint",
        "token_endpoint",
        "jwks_uri",
        "userinfo_endpoint",
        "end_session_endpoint",
    ):
        value = discovery.get(field)
        if value is None and field in {"authorization_endpoint", "token_endpoint", "jwks_uri"}:
            raise ValueError(f"OIDC discovery missing {field!r}")
        if value is not None:
            try:
                _reject_internal_or_loopback(str(value), field_name=field)
            except ValueError as exc:
                raise ValueError(f"OIDC discovery has unsafe {field}") from exc
    return discovery


async def _fetch_jwks(jwks_uri: str) -> Dict[str, Any]:
    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=False) as c:
        resp = await c.get(jwks_uri)
        return _bounded_json_response(resp, label="OIDC JWKS")


async def _load_jwks(jwks_uri: str, *, force_refresh: bool = False) -> Dict[str, Any]:
    now = time.monotonic()
    cached = _jwks_cache.get(jwks_uri)
    if not force_refresh and cached is not None and cached[0] > now:
        return cached[1]
    payload = await _fetch_jwks(jwks_uri)
    keys = payload.get("keys")
    if not isinstance(keys, list) or not keys or len(keys) > 100:
        raise ValueError("OIDC JWKS must contain between 1 and 100 keys")
    _jwks_cache[jwks_uri] = (now + _JWKS_CACHE_SECONDS, payload)
    return payload


def _select_jwk(jwks: Dict[str, Any], kid: str) -> Dict[str, Any] | None:
    for key in jwks.get("keys", []):
        if isinstance(key, dict) and key.get("kid") == kid:
            return key
    return None


async def _decode_provider_jwt(
    config: OidcConfig,
    token: str,
    *,
    discovery: Dict[str, Any],
    required_claims: list[str],
    error_label: str,
) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise ValueError(f"{error_label} header invalid") from exc
    algorithm = header.get("alg")
    kid = header.get("kid")
    if algorithm not in _OIDC_ALLOWED_ALGORITHMS or not isinstance(kid, str) or not kid:
        raise ValueError(f"{error_label} uses an unsupported algorithm or missing key id")

    jwks_uri = str(discovery["jwks_uri"])
    jwks = await _load_jwks(jwks_uri)
    jwk_dict = _select_jwk(jwks, kid)
    if jwk_dict is None:
        # A miss is the key-rotation signal. Refresh once before rejecting.
        jwks = await _load_jwks(jwks_uri, force_refresh=True)
        jwk_dict = _select_jwk(jwks, kid)
    if jwk_dict is None:
        raise ValueError(f"{error_label} signing key not found after JWKS refresh")
    if jwk_dict.get("alg") not in (None, algorithm):
        raise ValueError(f"{error_label} algorithm does not match signing key")
    try:
        signing_key = jwt.PyJWK.from_dict(jwk_dict, algorithm=algorithm).key
        return jwt.decode(
            token,
            signing_key,
            algorithms=[algorithm],
            audience=config.client_id,
            issuer=str(config.issuer_url).rstrip("/"),
            options={"require": required_claims},
            leeway=30,
        )
    except (jwt.PyJWTError, ValueError) as exc:
        raise ValueError(f"{error_label} validation failed") from exc


async def validate_logout_token(
    config: OidcConfig,
    logout_token: str,
    *,
    now: datetime | None = None,
) -> Dict[str, Any]:
    """Validate an OIDC Back-Channel Logout token before session revocation."""
    try:
        header = jwt.get_unverified_header(logout_token)
    except jwt.PyJWTError as exc:
        raise ValueError("logout_token header invalid") from exc
    if header.get("typ") != "logout+jwt":
        raise ValueError("logout_token typ must be logout+jwt")

    discovery = _validate_discovery(config, await _fetch_discovery(str(config.issuer_url)))
    claims = await _decode_provider_jwt(
        config,
        logout_token,
        discovery=discovery,
        required_claims=["iss", "aud", "iat", "events", "jti"],
        error_label="logout_token",
    )
    events = claims.get("events")
    if not isinstance(events, dict) or _BACKCHANNEL_LOGOUT_EVENT not in events:
        raise ValueError("logout_token missing back-channel logout event")
    if "nonce" in claims:
        raise ValueError("logout_token must not contain nonce")
    sid = claims.get("sid")
    sub = claims.get("sub")
    if not (isinstance(sid, str) and sid) and not (isinstance(sub, str) and sub):
        raise ValueError("logout_token must contain sid or sub")
    current = now or datetime.now(timezone.utc)
    issued = datetime.fromtimestamp(int(claims["iat"]), tz=timezone.utc)
    if abs((current - issued).total_seconds()) > 120:
        raise ValueError("logout_token is outside the accepted two-minute window")
    return claims


async def _fetch_userinfo(
    discovery: Dict[str, Any], access_token: str
) -> Dict[str, Any]:
    userinfo_endpoint = discovery.get("userinfo_endpoint")
    if not userinfo_endpoint:
        raise ValueError("OIDC discovery missing 'userinfo_endpoint'")
    headers = {"Authorization": f"Bearer {access_token}"}
    async with httpx.AsyncClient(timeout=_HTTPX_TIMEOUT, follow_redirects=False) as c:
        resp = await c.get(userinfo_endpoint, headers=headers)
        return _bounded_json_response(resp, label="OIDC userinfo")


async def preflight_test(config: OidcConfig) -> Dict[str, Any]:
    """Admin "test" preflight — fetch discovery and JWKS, surface a friendly
    OK / error response.

    Used by ``POST /admin/sso/providers/{id}/test``.
    """
    try:
        discovery = await _fetch_discovery(str(config.issuer_url))
    except Exception as exc:
        return {"ok": False, "error": f"discovery fetch failed: {exc}"}
    try:
        discovery = _validate_discovery(config, discovery)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}
    jwks_uri = str(discovery["jwks_uri"])
    try:
        async with httpx.AsyncClient(
            timeout=_HTTPX_TIMEOUT, follow_redirects=False
        ) as c:
            resp = await c.get(jwks_uri)
            jwks = _bounded_json_response(resp, label="OIDC JWKS")
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
