"""Public SSO router — `/api/v1/auth/sso/*`.

Endpoints:

* ``GET  /sso/providers``                 — list enabled providers (login page)
* ``GET  /sso/{name}/login``              — initiate auth (OIDC redirect or SAML AuthnRequest)
* ``GET  /sso/{name}/callback``           — OIDC code exchange, mint JWT, redirect to frontend
* ``POST /sso/{name}/acs``                — SAML AssertionConsumerService
* ``GET  /sso/{name}/metadata``           — SAML SP metadata XML
* ``POST /sso/{name}/slo``                — SAML LogoutRequest/Response (POST-binding)
* ``GET  /sso/{name}/slo``                — SAML LogoutRequest (HTTP-Redirect binding)

Provider lookup uses the URL-safe ``name`` slug (not the UUID) so admin URL
changes (slug edits) are visible in operator-facing IdP config screens.

Threat-model mitigations:
  * **M2** state cookie (``state_cookie.py``) instead of in-process LRU.
  * **M9** access token returned via URL fragment; Referrer-Policy + Cache-Control hardening on the redirect.
  * **M3** SAML POST size capped at 256 KiB before any parsing.
  * **M14** httpx timeouts inherited from ``oidc.py``.
  * Audit row written on every success / failure.
"""

from __future__ import annotations

import logging
import time
from typing import Optional, List

import jwt as _pyjwt
from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Path,
    Query,
    Request,
    Response,
    status,
)
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.auth.sso import audit, oidc, saml
from app.infrastructure.auth.sso.provisioning import (
    SsoProvisioningDenied,
    SsoProvisioningEmailUnverified,
    SsoProvisioningError,
    SsoProvisioningPending,
    SsoProvisioningSuperuserLink,
    provision_or_link_oidc,
    provision_or_link_saml,
)
from app.infrastructure.auth.sso.repository import SsoProviderRepository
from app.infrastructure.auth.sso.state_cookie import (
    COOKIE_NAME as STATE_COOKIE_NAME,
    BadSignature,
    SignatureExpired,
    clear_state_cookie,
    consume_state,
    make_state,
    set_state_cookie,
)
from app.infrastructure.database.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/sso", tags=["Authentication: SSO"])


# Maximum SAML POST body size (M3). Reject anything larger before invoking
# python3-saml's parser to bound XXE / DoS attack surface.
_SAML_MAX_BODY_BYTES = 256 * 1024


def _frontend_complete_url() -> str:
    """The page the user lands on after a successful SSO callback.

    Frontend reads the ``access_token`` from the URL fragment, then strips it.
    """
    return f"{settings.frontend_base_url.rstrip('/')}/auth/sso/complete"


def _api_callback_url(provider_name: str, suffix: str = "callback") -> str:
    """Build an absolute API URL the IdP must redirect / POST to.

    F12: when the deployment runs the API on a different origin than the
    frontend (e.g. ``api.x.com`` + ``ui.x.com``), ``API_BASE_URL`` overrides
    ``FRONTEND_BASE_URL`` for these paths. ``settings.api_base_url`` falls
    back to ``frontend_base_url`` for single-origin deploys.
    """
    return (
        f"{settings.api_base_url.rstrip('/')}/api/v1/auth/sso/"
        f"{provider_name}/{suffix}"
    )


def _redirect_to_frontend(
    *, access_token: str, response_extras: Optional[Response] = None
) -> RedirectResponse:
    """Return a RedirectResponse with the access token in the URL fragment.

    Sets ``Referrer-Policy: no-referrer``, ``Cache-Control: no-store`` so the
    URL-with-fragment isn't logged or cached (M9).
    """
    target = f"{_frontend_complete_url()}#access_token={access_token}&token_type=bearer"
    resp = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    # Carry over every Set-Cookie header from the staging response. We
    # iterate `raw` (a list of `(bytes, bytes)` tuples) so a future second
    # cookie write on the staging response — e.g. the refresh cookie + a
    # CSRF token — is preserved instead of being collapsed by `.items()`.
    if response_extras is not None:
        for hdr_name, hdr_value in response_extras.raw_headers:
            if hdr_name.lower() == b"set-cookie":
                resp.raw_headers.append((hdr_name, hdr_value))
    return resp


def _redirect_to_frontend_with_error(error_code: str) -> RedirectResponse:
    """Hop the user back to the SSO complete page with an error code in the
    fragment so the frontend can render a friendly message."""
    target = f"{_frontend_complete_url()}#error={error_code}"
    resp = RedirectResponse(url=target, status_code=status.HTTP_303_SEE_OTHER)
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


async def _issue_session(response: Response, user) -> str:
    """Mint an access token + set the refresh cookie. Returns the access token.

    The refresh cookie carries ``typ=refresh`` and ``original_iat=now`` so the
    session-lifetime ceiling check in ``/auth/refresh`` works correctly.
    """
    strategy = get_custom_cookie_jwt_strategy()
    access_token = await strategy.write_token(user)

    secret = (
        settings.SECRET_KEY.get_secret_value()
        if hasattr(settings.SECRET_KEY, "get_secret_value")
        else str(settings.SECRET_KEY)
    )
    now_ts = int(time.time())
    refresh_payload = {
        "sub": str(user.id),
        "aud": "fastapi-users:auth",
        "typ": "refresh",
        "original_iat": now_ts,
        "exp": now_ts + settings.REFRESH_TOKEN_LIFETIME_SECONDS,
    }
    refresh_token = _pyjwt.encode(refresh_payload, secret, algorithm="HS256")
    await strategy.write_refresh_token(response, refresh_token)
    return access_token


# ---------------------------------------------------------------------------
# GET /auth/sso/providers — public list
# ---------------------------------------------------------------------------


@router.get("/providers")
async def list_enabled_providers(
    email: Optional[str] = Query(default=None, max_length=320),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Return enabled providers visible on the login page.

    If ``?email=`` is provided, the response also flags any provider whose
    ``force_for_domains`` matches the email's domain so the frontend can hide
    the password field for that user (force-SSO UX).
    """
    repo = SsoProviderRepository(db)
    rows = await repo.list_enabled()
    items: list[dict] = [
        {
            "id": str(row.id),
            "name": row.name,
            "display_name": row.display_name,
            "protocol": row.protocol,
        }
        for row in rows
    ]
    forced: Optional[dict] = None
    if email:
        domain = email.strip().lower().split("@", 1)[-1] if "@" in email else ""
        if domain:
            for row in rows:
                ff = row.force_for_domains or []
                if domain in {d.lower() for d in ff}:
                    forced = {
                        "id": str(row.id),
                        "name": row.name,
                        "display_name": row.display_name,
                        "protocol": row.protocol,
                    }
                    break
    return {"providers": items, "forced_for_email": forced}


# ---------------------------------------------------------------------------
# GET /auth/sso/{name}/login — initiate
# ---------------------------------------------------------------------------


@router.get("/{name}/login")
async def initiate_login(
    request: Request,
    name: str = Path(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
    return_to: str = Query(default="/analysis/results", max_length=512),
    db: AsyncSession = Depends(get_db),
):
    """Initiate an SSO flow. Dispatches OIDC vs SAML on the provider's protocol."""
    repo = SsoProviderRepository(db)
    provider = await repo.get_by_name(name)
    if provider is None or not provider.enabled:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="provider not found"
        )

    bundle = await repo.get_with_config(provider.id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="provider config could not be loaded",
        )

    # Open-redirect guard: only allow same-origin relative paths in return_to.
    if not return_to.startswith("/") or return_to.startswith("//"):
        return_to = "/analysis/results"

    if provider.protocol == "oidc":
        cfg = bundle.config  # type: OidcConfig
        verifier, challenge = oidc.make_pkce_pair()
        cookie_value, claims = make_state(
            provider_id=str(provider.id),
            return_to=return_to,
            code_verifier=verifier,
        )
        redirect_uri = _api_callback_url(provider.name, "callback")
        url = await oidc.build_authorize_url(
            cfg,
            redirect_uri=redirect_uri,
            state=claims["state"],
            nonce=claims["nonce"],
            code_challenge=challenge,
        )
        resp = RedirectResponse(url=url, status_code=status.HTTP_302_FOUND)
        set_state_cookie(resp, cookie_value)
        return resp

    if provider.protocol == "saml":
        cfg = bundle.config  # type: SamlConfig
        cookie_value, claims = make_state(
            provider_id=str(provider.id),
            return_to=return_to,
        )
        login_url = saml.build_login_redirect(
            cfg, request=request, relay_state=claims["state"]
        )
        resp = RedirectResponse(url=login_url, status_code=status.HTTP_302_FOUND)
        set_state_cookie(resp, cookie_value)
        return resp

    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"unknown protocol: {provider.protocol!r}",
    )


# ---------------------------------------------------------------------------
# GET /auth/sso/{name}/callback — OIDC code exchange
# ---------------------------------------------------------------------------


@router.get("/{name}/callback")
async def oidc_callback(
    request: Request,
    name: str = Path(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    error: Optional[str] = Query(default=None),
    db: AsyncSession = Depends(get_db),
):
    if error:
        await audit.record_event(
            db,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            request=request,
            details={"reason": "idp_error", "idp_error": str(error)[:128]},
        )
        return _redirect_to_frontend_with_error("idp_error")

    if not code or not state:
        return _redirect_to_frontend_with_error("missing_code_or_state")

    cookie_value = request.cookies.get(STATE_COOKIE_NAME)
    if not cookie_value:
        return _redirect_to_frontend_with_error("missing_state_cookie")

    try:
        claims = consume_state(cookie_value)
    except SignatureExpired:
        return _redirect_to_frontend_with_error("state_expired")
    except (BadSignature, ValueError):
        return _redirect_to_frontend_with_error("state_tampered")

    if claims["state"] != state:
        return _redirect_to_frontend_with_error("state_mismatch")

    repo = SsoProviderRepository(db)
    provider = await repo.get_by_name(name)
    if provider is None or not provider.enabled or provider.protocol != "oidc":
        return _redirect_to_frontend_with_error("provider_not_found")
    if str(provider.id) != claims["provider_id"]:
        return _redirect_to_frontend_with_error("provider_mismatch")

    bundle = await repo.get_with_config(provider.id)
    if bundle is None:
        return _redirect_to_frontend_with_error("provider_config_unavailable")
    cfg = bundle.config  # type: OidcConfig

    redirect_uri = _api_callback_url(provider.name, "callback")
    try:
        userinfo = await oidc.exchange_code(
            cfg,
            code=code,
            redirect_uri=redirect_uri,
            nonce=claims["nonce"],
            code_verifier=claims.get("code_verifier", ""),
        )
    except ValueError as exc:
        await audit.record_event(
            db,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            request=request,
            details={"reason": "id_token_validation_failed", "msg": str(exc)[:200]},
        )
        return _redirect_to_frontend_with_error("token_validation_failed")

    try:
        identity = await provision_or_link_oidc(
            db,
            provider=provider,
            sub=userinfo.sub,
            email=userinfo.email,
            email_verified=userinfo.email_verified,
            request=request,
            require_email_verified=cfg.require_email_verified_claim,
        )
    except SsoProvisioningEmailUnverified:
        return _redirect_to_frontend_with_error("email_unverified_at_idp")
    except SsoProvisioningSuperuserLink:
        return _redirect_to_frontend_with_error("superuser_link_refused")
    except SsoProvisioningPending:
        # F3: the JIT-created (inactive) user + audit row are written in
        # the same transaction as the SsoProvisioningPending raise. We must
        # commit before redirecting, otherwise the rollback swallows the
        # whole approve-policy state and the admin never sees the request.
        await db.commit()
        return _redirect_to_frontend_with_error("pending_admin_approval")
    except SsoProvisioningDenied:
        return _redirect_to_frontend_with_error("denied")
    except SsoProvisioningError:
        return _redirect_to_frontend_with_error("provisioning_failed")

    # All checks pass — mint session.
    extras = Response()
    access_token = await _issue_session(extras, identity.user)
    await audit.record(
        db,
        event=audit.EVENT_SSO_LOGIN_SUCCESS,
        user_id=identity.user.id,
        provider_id=provider.id,
        email=userinfo.email,
        request=request,
        details={
            "is_new_user": identity.is_new_user,
            "is_new_link": identity.is_new_link,
        },
    )
    await db.commit()
    redirect = _redirect_to_frontend(access_token=access_token, response_extras=extras)
    clear_state_cookie(redirect)
    return redirect


# ---------------------------------------------------------------------------
# POST /auth/sso/{name}/acs — SAML AssertionConsumerService
# ---------------------------------------------------------------------------


@router.post("/{name}/acs")
async def saml_acs(
    request: Request,
    name: str = Path(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
    db: AsyncSession = Depends(get_db),
):
    # M3: bound SAML POST size before parsing. Content-Length isn't always
    # set; we also cap the raw body read.
    cl = request.headers.get("content-length")
    if cl:
        try:
            if int(cl) > _SAML_MAX_BODY_BYTES:
                return _redirect_to_frontend_with_error("saml_body_too_large")
        except ValueError:
            return _redirect_to_frontend_with_error("saml_body_invalid")

    body_bytes = await request.body()
    if len(body_bytes) > _SAML_MAX_BODY_BYTES:
        return _redirect_to_frontend_with_error("saml_body_too_large")

    form = await request.form()
    post_form: dict[str, str] = {k: v for k, v in form.items() if isinstance(v, str)}

    # RelayState carries our own state; the cookie pins it.
    relay_state = post_form.get("RelayState", "")
    cookie_value = request.cookies.get(STATE_COOKIE_NAME)
    if not cookie_value:
        return _redirect_to_frontend_with_error("missing_state_cookie")
    try:
        claims = consume_state(cookie_value)
    except SignatureExpired:
        return _redirect_to_frontend_with_error("state_expired")
    except (BadSignature, ValueError):
        return _redirect_to_frontend_with_error("state_tampered")
    if relay_state and claims["state"] != relay_state:
        return _redirect_to_frontend_with_error("relay_state_mismatch")

    repo = SsoProviderRepository(db)
    provider = await repo.get_by_name(name)
    if provider is None or not provider.enabled or provider.protocol != "saml":
        return _redirect_to_frontend_with_error("provider_not_found")
    if str(provider.id) != claims["provider_id"]:
        return _redirect_to_frontend_with_error("provider_mismatch")
    bundle = await repo.get_with_config(provider.id)
    if bundle is None:
        return _redirect_to_frontend_with_error("provider_config_unavailable")
    cfg = bundle.config  # type: SamlConfig

    try:
        identity_attrs = saml.process_acs(cfg, request, post_form=post_form)
    except ValueError as exc:
        await audit.record_event(
            db,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            request=request,
            details={"reason": "saml_assertion_invalid", "msg": str(exc)[:200]},
        )
        return _redirect_to_frontend_with_error("saml_assertion_invalid")

    mapped = saml.map_attributes(cfg, identity_attrs.attributes)
    email = (
        mapped.get("email") or identity_attrs.name_id
    )  # NameID often IS the email for emailAddress format
    if not email or "@" not in email:
        await audit.record_event(
            db,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            request=request,
            details={"reason": "saml_email_missing"},
        )
        return _redirect_to_frontend_with_error("saml_email_missing")

    try:
        identity = await provision_or_link_saml(
            db,
            provider=provider,
            name_id=identity_attrs.name_id,
            name_id_format=identity_attrs.name_id_format,
            email=email,
            session_index=identity_attrs.session_index,
            request=request,
        )
    except SsoProvisioningSuperuserLink:
        return _redirect_to_frontend_with_error("superuser_link_refused")
    except SsoProvisioningPending:
        # F3: the JIT-created (inactive) user + audit row are written in
        # the same transaction as the SsoProvisioningPending raise. We must
        # commit before redirecting, otherwise the rollback swallows the
        # whole approve-policy state and the admin never sees the request.
        await db.commit()
        return _redirect_to_frontend_with_error("pending_admin_approval")
    except SsoProvisioningDenied:
        return _redirect_to_frontend_with_error("denied")
    except SsoProvisioningError:
        return _redirect_to_frontend_with_error("provisioning_failed")

    extras = Response()
    access_token = await _issue_session(extras, identity.user)
    await audit.record(
        db,
        event=audit.EVENT_SSO_LOGIN_SUCCESS,
        user_id=identity.user.id,
        provider_id=provider.id,
        email=email,
        request=request,
        details={
            "is_new_user": identity.is_new_user,
            "is_new_link": identity.is_new_link,
        },
    )
    await db.commit()
    redirect = _redirect_to_frontend(access_token=access_token, response_extras=extras)
    clear_state_cookie(redirect)
    return redirect


# ---------------------------------------------------------------------------
# GET /auth/sso/{name}/metadata — SAML SP metadata XML
# ---------------------------------------------------------------------------


@router.get("/{name}/metadata")
async def saml_metadata(
    name: str = Path(..., min_length=1, max_length=64, pattern=r"^[a-zA-Z0-9_\-]+$"),
    db: AsyncSession = Depends(get_db),
):
    repo = SsoProviderRepository(db)
    provider = await repo.get_by_name(name)
    if provider is None or not provider.enabled or provider.protocol != "saml":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not found")
    bundle = await repo.get_with_config(provider.id)
    if bundle is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="config unavailable",
        )
    cfg = bundle.config  # type: SamlConfig
    try:
        xml_bytes = saml.metadata_xml(cfg)
    except Exception as exc:
        logger.error(
            "saml.metadata_build_failed",
            extra={"provider": provider.name, "err": type(exc).__name__},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="metadata build failed",
        )
    return Response(
        content=xml_bytes,
        media_type="application/samlmetadata+xml",
        headers={"Cache-Control": "public, max-age=300"},
    )


# Avoid an unused-import warning by re-exporting.
__all__: List[str] = ["router"]
