"""Pydantic models for the *decrypted* SSO provider configurations.

The on-disk shape is one Fernet-encrypted JSON blob inside
``sso_providers.config_encrypted``. These models constrain what we accept
into the blob (per protocol) and validate it on every load — defense in
depth against a tampered ``config_encrypted`` value.

Threat-model mitigations baked in here:

* **M10** ``OidcConfig.issuer_url`` rejects loopback / RFC1918 / link-local
  hosts and the EC2/GCP metadata service to prevent SSRF via the discovery
  endpoint fetch.
* **M3** ``SamlConfig`` defaults to ``want_assertions_signed=True``,
  ``want_messages_signed=True``, ``sign_requests=True``,
  ``reject_deprecated_alg=True``.
* **M11** Session lifetime configuration lives in ``Settings`` /
  ``SystemConfigCache``, not here.
"""

from __future__ import annotations

import ipaddress
from typing import Dict, List, Literal, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, SecretStr, field_validator


_BLOCKED_HOSTS = {
    # Cloud metadata services (SSRF gateway). Block by host string.
    "169.254.169.254",
    "metadata.google.internal",
    "metadata",
    # Common loopback aliases.
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
}


def _reject_internal_or_loopback(url: str) -> None:
    """Raise ``ValueError`` if ``url`` resolves to a private / loopback /
    link-local / metadata target. Used by both ``OidcConfig.issuer_url``
    and the admin "test" preflight."""
    parsed = urlparse(str(url))
    if parsed.scheme not in ("https",):
        # All real IdPs use HTTPS; HTTP is rejected to prevent token
        # interception (and protects developers from accidentally pointing
        # at an internal http://idp.local).
        raise ValueError(
            "issuer_url must use https:// (http is rejected to prevent token interception)"
        )
    host = (parsed.hostname or "").lower()
    if not host:
        raise ValueError("issuer_url must include a host")
    if host in _BLOCKED_HOSTS:
        raise ValueError(
            f"issuer_url host {host!r} is blocked (loopback / metadata service)"
        )
    # Try to parse as an IP address; if it parses, apply CIDR-based blocks.
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        # Hostname (not an IP literal) — accept after the deny-list check above.
        return
    if (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        raise ValueError(
            f"issuer_url IP {host} is loopback / private / link-local — blocked"
        )


class OidcConfig(BaseModel):
    """Decrypted shape of an OIDC provider config blob.

    The IdP discovery URL is derived from ``issuer_url`` per OIDC spec:
    ``{issuer_url}/.well-known/openid-configuration``. We validate the
    issuer URL up front so the discovery fetch (which we do during
    ``test`` and again at first ``authorize``) never SSRFs.
    """

    model_config = ConfigDict(extra="forbid")

    issuer_url: HttpUrl
    client_id: str = Field(..., min_length=1, max_length=512)
    client_secret: SecretStr
    scopes: List[str] = Field(
        default_factory=lambda: ["openid", "email", "profile"], max_length=20
    )
    # ``email_verified=True`` claim REQUIRED for JIT linking (M4). Set to
    # False only if the IdP guarantees email verification by integration
    # design (e.g. an internal Keycloak with verified-email-only flows).
    require_email_verified_claim: bool = True

    @field_validator("issuer_url", mode="after")
    @classmethod
    def _check_issuer_url_safe(cls, v: HttpUrl) -> HttpUrl:
        _reject_internal_or_loopback(str(v))
        return v

    @field_validator("scopes")
    @classmethod
    def _scopes_must_include_openid(cls, v: List[str]) -> List[str]:
        if "openid" not in v:
            raise ValueError("scopes must include 'openid' for OIDC")
        return v


class SamlConfig(BaseModel):
    """Decrypted shape of a SAML 2.0 provider config blob.

    Hardened defaults (M3): strict mode on, both messages and assertions
    must be signed, deprecated algorithms rejected. Operators can opt in
    to encrypted assertions when the IdP supports them.
    """

    model_config = ConfigDict(extra="forbid")

    idp_entity_id: str = Field(..., min_length=1, max_length=512)
    idp_sso_url: HttpUrl
    idp_slo_url: Optional[HttpUrl] = None
    # PEM-encoded X.509 cert (BEGIN/END CERTIFICATE wrapper required).
    idp_x509_cert: str = Field(..., min_length=64, max_length=16384)

    sp_entity_id: str = Field(..., min_length=1, max_length=512)
    sp_acs_url: HttpUrl  # Our /api/v1/auth/sso/{id}/acs URL
    sp_slo_url: Optional[HttpUrl] = None
    sp_x509_cert: Optional[str] = None
    sp_private_key: Optional[SecretStr] = None

    name_id_format: str = Field(
        default="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        max_length=256,
    )
    # SAML attribute (key) → our internal field (value). Defaults handle the
    # most common Okta / ADFS shapes.
    attribute_mapping: Dict[str, str] = Field(
        default_factory=lambda: {
            "email": "email",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": "email",
        },
    )

    sign_requests: bool = True
    want_assertions_signed: bool = True
    want_messages_signed: bool = True
    want_assertions_encrypted: bool = False
    reject_deprecated_alg: bool = True

    @field_validator("idp_x509_cert")
    @classmethod
    def _idp_cert_pem_check(cls, v: str) -> str:
        v = v.strip()
        if (
            "-----BEGIN CERTIFICATE-----" not in v
            or "-----END CERTIFICATE-----" not in v
        ):
            raise ValueError(
                "idp_x509_cert must be a PEM-formatted X.509 certificate "
                "(missing BEGIN/END CERTIFICATE markers)"
            )
        return v


# Discriminated union for runtime dispatch. The protocol value comes from
# ``SsoProvider.protocol`` and selects which model to instantiate.
SsoConfig = OidcConfig | SamlConfig
SsoProtocol = Literal["oidc", "saml"]


def parse_provider_config(protocol: str, payload: dict) -> SsoConfig:
    """Validate ``payload`` against the model for ``protocol``.

    Raises ``ValueError`` (via Pydantic) if the payload is malformed.
    Called both on admin write (before encryption) and on each load
    (after decryption) — load-time validation guards against a tampered
    ``config_encrypted`` value.
    """
    if protocol == "oidc":
        return OidcConfig.model_validate(payload)
    if protocol == "saml":
        return SamlConfig.model_validate(payload)
    raise ValueError(f"unknown SSO protocol: {protocol!r}")
