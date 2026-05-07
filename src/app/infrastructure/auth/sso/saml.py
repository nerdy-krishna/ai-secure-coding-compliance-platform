"""SAML 2.0 SP wrapper around python3-saml (OneLogin).

Hardening (M3):
  * ``strict=True`` always.
  * ``wantAssertionsSigned=True`` AND ``wantMessagesSigned=True`` by default
    (overridable per-provider, but discouraged).
  * ``rejectDeprecatedAlg=True`` to forbid SHA-1 etc.
  * Identity is read ONLY via ``OneLogin_Saml2_Auth.get_nameid()`` and
    ``get_attributes()`` AFTER ``is_valid()`` returns True. Never from raw XML.
  * ``Content-Length > 256 KiB`` is rejected at the router layer
    (``app.api.v1.routers.sso``) before we ever invoke this module.

We do NOT call ``onelogin.saml2.utils.OneLogin_Saml2_Utils.process_xml`` on
attacker-controlled XML except through the library's own validated entry
points. python3-saml internally uses defusedxml-style hardening.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from .models import SamlConfig

logger = logging.getLogger(__name__)


# python3-saml is heavy and has system-lib (xmlsec1) dependencies; import
# lazily so that environments without it still work for tests that don't
# touch SAML. Production images install the lib via the Dockerfile.
def _lazy_imports():  # pragma: no cover — wrapper around third-party imports
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
    from onelogin.saml2.settings import OneLogin_Saml2_Settings

    return OneLogin_Saml2_Auth, OneLogin_Saml2_Settings


@dataclass(slots=True)
class SamlIdentity:
    name_id: str
    name_id_format: str
    session_index: Optional[str]
    attributes: Dict[str, List[str]]


def _build_settings_dict(
    config: SamlConfig,
) -> Dict[str, Any]:
    """Translate a ``SamlConfig`` into the dict shape python3-saml expects."""
    sp_block: Dict[str, Any] = {
        "entityId": config.sp_entity_id,
        "assertionConsumerService": {
            "url": str(config.sp_acs_url),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "NameIDFormat": config.name_id_format,
    }
    if config.sp_slo_url:
        sp_block["singleLogoutService"] = {
            "url": str(config.sp_slo_url),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }
    if config.sp_x509_cert:
        sp_block["x509cert"] = config.sp_x509_cert
    if config.sp_private_key is not None:
        sp_block["privateKey"] = config.sp_private_key.get_secret_value()

    idp_block: Dict[str, Any] = {
        "entityId": config.idp_entity_id,
        "singleSignOnService": {
            "url": str(config.idp_sso_url),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        },
        "x509cert": config.idp_x509_cert,
    }
    if config.idp_slo_url:
        idp_block["singleLogoutService"] = {
            "url": str(config.idp_slo_url),
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }

    security: Dict[str, Any] = {
        "authnRequestsSigned": bool(config.sign_requests),
        "logoutRequestSigned": bool(config.sign_requests),
        "logoutResponseSigned": bool(config.sign_requests),
        "wantAssertionsSigned": bool(config.want_assertions_signed),
        "wantMessagesSigned": bool(config.want_messages_signed),
        "wantAssertionsEncrypted": bool(config.want_assertions_encrypted),
        "wantNameIdEncrypted": False,
        "rejectDeprecatedAlgorithm": bool(config.reject_deprecated_alg),
        "signMetadata": bool(config.sp_x509_cert and config.sp_private_key),
        "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
        "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
    }

    return {
        "strict": True,
        "debug": False,
        "sp": sp_block,
        "idp": idp_block,
        "security": security,
    }


def _request_data_from_starlette(request: Any) -> Dict[str, Any]:
    """Adapt a starlette/FastAPI ``Request`` to the dict shape python3-saml expects.

    Used in HTTP-Redirect (GET) flows. POST-binding (SAMLResponse on /acs)
    is handled by ``request_data_with_post`` below which accepts the parsed
    form body.
    """
    https = "on" if request.url.scheme == "https" else "off"
    server_port = request.url.port or (443 if https == "on" else 80)
    query_dict: Dict[str, str] = {}
    for k, v in request.query_params.multi_items():
        # python3-saml expects a flat dict; we keep the last occurrence.
        query_dict[k] = v
    return {
        "https": https,
        "http_host": request.url.hostname or "",
        "server_port": str(server_port),
        "script_name": request.url.path,
        "get_data": query_dict,
        "post_data": {},
    }


def _request_data_with_post(request: Any, post_form: Dict[str, str]) -> Dict[str, Any]:
    base = _request_data_from_starlette(request)
    base["post_data"] = post_form
    return base


def build_login_redirect(config: SamlConfig, request: Any, *, relay_state: str) -> str:
    """Construct the IdP redirect URL (HTTP-Redirect binding)."""
    OneLogin_Saml2_Auth, _ = _lazy_imports()
    settings_dict = _build_settings_dict(config)
    auth = OneLogin_Saml2_Auth(_request_data_from_starlette(request), settings_dict)
    return auth.login(return_to=relay_state)


def process_acs(
    config: SamlConfig, request: Any, *, post_form: Dict[str, str]
) -> SamlIdentity:
    """Process a SAML AssertionConsumerService POST. Validates assertion,
    extracts identity ONLY via the post-validation getters.

    Raises ``ValueError`` if the assertion is invalid or missing required claims.
    """
    OneLogin_Saml2_Auth, _ = _lazy_imports()
    settings_dict = _build_settings_dict(config)
    auth = OneLogin_Saml2_Auth(
        _request_data_with_post(request, post_form), settings_dict
    )
    auth.process_response()
    errors = auth.get_errors()
    if errors:
        # NEVER include attacker-controlled XML in the exception text — only
        # the python3-saml error tags (a small, finite enum).
        raise ValueError(f"SAML response invalid: {','.join(errors)}; reason redacted")
    if not auth.is_authenticated():
        raise ValueError("SAML response not authenticated")

    name_id = auth.get_nameid()
    name_id_format = auth.get_nameid_format() or config.name_id_format
    session_index = auth.get_session_index()
    attributes = auth.get_attributes() or {}

    if not name_id:
        raise ValueError("SAML response missing NameID")

    return SamlIdentity(
        name_id=str(name_id),
        name_id_format=str(name_id_format),
        session_index=str(session_index) if session_index else None,
        attributes={k: list(v) for k, v in attributes.items()},
    )


def build_logout_redirect(
    config: SamlConfig,
    request: Any,
    *,
    name_id: str,
    name_id_format: str,
    session_index: Optional[str],
    return_to: str,
) -> Optional[str]:
    """Construct a ``LogoutRequest`` redirect URL (HTTP-Redirect)."""
    if not config.idp_slo_url:
        return None
    OneLogin_Saml2_Auth, _ = _lazy_imports()
    settings_dict = _build_settings_dict(config)
    auth = OneLogin_Saml2_Auth(_request_data_from_starlette(request), settings_dict)
    return auth.logout(
        return_to=return_to,
        name_id=name_id,
        session_index=session_index,
        name_id_format=name_id_format,
    )


def process_slo(
    config: SamlConfig, request: Any, *, post_form: Dict[str, str]
) -> Dict[str, Any]:
    """Handle an inbound SAML LogoutRequest or LogoutResponse (POST-binding).

    Returns a small dict the router uses to decide whether to redirect the
    user (``url`` if a LogoutResponse needs to be sent back) or to
    terminate the session locally.
    """
    OneLogin_Saml2_Auth, _ = _lazy_imports()
    settings_dict = _build_settings_dict(config)
    auth = OneLogin_Saml2_Auth(
        _request_data_with_post(request, post_form), settings_dict
    )
    url = auth.process_slo(delete_session_cb=None)
    errors = auth.get_errors()
    if errors:
        raise ValueError(f"SAML SLO invalid: {','.join(errors)}")
    return {"redirect_url": url}


def metadata_xml(config: SamlConfig) -> bytes:
    """Build the SP metadata XML (Content-Type: application/samlmetadata+xml).

    If the config has ``sp_x509_cert`` AND ``sp_private_key`` the metadata
    is signed (``signMetadata=True`` is set in ``_build_settings_dict``).
    """
    _, OneLogin_Saml2_Settings = _lazy_imports()
    settings_dict = _build_settings_dict(config)
    saml_settings = OneLogin_Saml2_Settings(settings_dict, sp_validation_only=True)
    metadata = saml_settings.get_sp_metadata()
    errors = saml_settings.validate_metadata(metadata)
    if errors:
        raise ValueError(f"SAML SP metadata invalid: {','.join(errors)}")
    if isinstance(metadata, str):
        return metadata.encode("utf-8")
    return metadata


def preflight_test(config: SamlConfig) -> Dict[str, Any]:
    """Admin "test" preflight — ensure metadata can be built and the IdP
    cert parses. Cheap, doesn't reach the IdP.
    """
    try:
        metadata_xml(config)
    except Exception as exc:
        return {"ok": False, "error": f"SP metadata build failed: {exc}"}
    return {
        "ok": True,
        "sp_entity_id": config.sp_entity_id,
        "sp_acs_url": str(config.sp_acs_url),
        "sp_slo_url": str(config.sp_slo_url) if config.sp_slo_url else None,
        "idp_entity_id": config.idp_entity_id,
        "idp_sso_url": str(config.idp_sso_url),
    }


def map_attributes(
    config: SamlConfig, attributes: Dict[str, List[str]]
) -> Dict[str, str]:
    """Translate IdP-named SAML attributes into our internal flat shape.

    Returns a dict like ``{"email": "...", "name": "..."}``. Unknown
    attributes are dropped.
    """
    out: Dict[str, str] = {}
    for saml_key, internal_key in config.attribute_mapping.items():
        values = attributes.get(saml_key)
        if values:
            out[internal_key] = str(values[0])
    return out
