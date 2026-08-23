"""Fixture-backed protocol-boundary regression tests for enterprise SSO."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr

from app.infrastructure.auth.sso import oidc, saml
from app.infrastructure.auth.sso.models import OidcConfig, SamlConfig


def _rsa_fixture(kid: str) -> tuple[object, dict]:
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256", "use": "sig"})
    return private_key, jwk


def _oidc_config() -> OidcConfig:
    return OidcConfig(
        issuer_url="https://idp.example.test",
        client_id="sccap-client",
        client_secret=SecretStr("not-a-real-secret"),
    )


def _discovery() -> dict:
    return {
        "issuer": "https://idp.example.test",
        "authorization_endpoint": "https://idp.example.test/authorize",
        "token_endpoint": "https://idp.example.test/token",
        "userinfo_endpoint": "https://idp.example.test/userinfo",
        "jwks_uri": "https://keys.example.test/jwks.json",
    }


def _saml_config() -> SamlConfig:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test IdP")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    return SamlConfig(
        idp_entity_id="https://idp.example.test/metadata",
        idp_sso_url="https://idp.example.test/sso",
        idp_slo_url="https://idp.example.test/slo",
        idp_x509_cert=cert_pem,
        sp_entity_id="https://sccap.example.test/saml",
        sp_acs_url="https://sccap.example.test/api/v1/auth/sso/corp/acs",
        sp_slo_url="https://sccap.example.test/api/v1/auth/sso/corp/slo",
    )


class OidcBoundaryTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        oidc._jwks_cache.clear()

    def test_discovery_is_pinned_to_issuer_and_public_https_endpoints(self) -> None:
        config = _oidc_config()
        with self.assertRaisesRegex(ValueError, "issuer does not match"):
            oidc._validate_discovery(config, {**_discovery(), "issuer": "https://evil.test"})
        with self.assertRaisesRegex(ValueError, "unsafe jwks_uri"):
            oidc._validate_discovery(
                config,
                {**_discovery(), "jwks_uri": "http://169.254.169.254/keys"},
            )

    async def test_unknown_kid_refreshes_cached_jwks_once(self) -> None:
        old_key, old_jwk = _rsa_fixture("old")
        new_key, new_jwk = _rsa_fixture("new")
        now = datetime.now(timezone.utc)
        base_claims = {
            "iss": "https://idp.example.test",
            "aud": "sccap-client",
            "sub": "subject-1",
            "iat": now,
            "exp": now + timedelta(minutes=5),
        }
        old_token = jwt.encode(base_claims, old_key, algorithm="RS256", headers={"kid": "old"})
        new_token = jwt.encode(base_claims, new_key, algorithm="RS256", headers={"kid": "new"})
        fetch = AsyncMock(side_effect=[{"keys": [old_jwk]}, {"keys": [new_jwk]}])
        with patch.object(oidc, "_fetch_jwks", fetch):
            await oidc._decode_provider_jwt(
                _oidc_config(),
                old_token,
                discovery=_discovery(),
                required_claims=["iss", "aud", "sub", "iat", "exp"],
                error_label="id_token",
            )
            claims = await oidc._decode_provider_jwt(
                _oidc_config(),
                new_token,
                discovery=_discovery(),
                required_claims=["iss", "aud", "sub", "iat", "exp"],
                error_label="id_token",
            )
        self.assertEqual(claims["sub"], "subject-1")
        self.assertEqual(fetch.await_count, 2)

    async def test_backchannel_logout_requires_typed_signed_event_without_nonce(self) -> None:
        key, jwk = _rsa_fixture("logout-key")
        now = datetime.now(timezone.utc)
        claims = {
            "iss": "https://idp.example.test",
            "aud": "sccap-client",
            "iat": now,
            "jti": "logout-1",
            "sid": "idp-session-1",
            "events": {oidc._BACKCHANNEL_LOGOUT_EVENT: {}},
        }
        token = jwt.encode(
            claims,
            key,
            algorithm="RS256",
            headers={"kid": "logout-key", "typ": "logout+jwt"},
        )
        with (
            patch.object(oidc, "_fetch_discovery", AsyncMock(return_value=_discovery())),
            patch.object(oidc, "_fetch_jwks", AsyncMock(return_value={"keys": [jwk]})),
        ):
            decoded = await oidc.validate_logout_token(_oidc_config(), token, now=now)
        self.assertEqual(decoded["sid"], "idp-session-1")

        bad = jwt.encode(
            {**claims, "nonce": "cross-token-confusion"},
            key,
            algorithm="RS256",
            headers={"kid": "logout-key", "typ": "logout+jwt"},
        )
        oidc._jwks_cache.clear()
        with (
            patch.object(oidc, "_fetch_discovery", AsyncMock(return_value=_discovery())),
            patch.object(oidc, "_fetch_jwks", AsyncMock(return_value={"keys": [jwk]})),
            self.assertRaisesRegex(ValueError, "must not contain nonce"),
        ):
            await oidc.validate_logout_token(_oidc_config(), bad, now=now)


class SamlBoundaryTests(unittest.TestCase):
    def test_strict_signed_metadata_and_logout_settings(self) -> None:
        settings = saml._build_settings_dict(_saml_config())
        self.assertTrue(settings["strict"])
        self.assertTrue(settings["security"]["wantAssertionsSigned"])
        self.assertTrue(settings["security"]["wantMessagesSigned"])
        self.assertTrue(settings["security"]["logoutRequestSigned"])
        self.assertTrue(settings["security"]["logoutResponseSigned"])
        self.assertTrue(settings["security"]["rejectDeprecatedAlgorithm"])
        self.assertEqual(
            settings["sp"]["singleLogoutService"]["url"],
            "https://sccap.example.test/api/v1/auth/sso/corp/slo",
        )


if __name__ == "__main__":
    unittest.main()
