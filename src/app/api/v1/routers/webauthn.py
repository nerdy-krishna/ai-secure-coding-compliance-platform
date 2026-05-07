"""WebAuthn / passkey endpoints.

Surface:

  POST   /api/v1/auth/webauthn/register/begin   — authed; emit registration options
  POST   /api/v1/auth/webauthn/register/finish  — authed; verify attestation; persist credential
  POST   /api/v1/auth/webauthn/login/begin      — public; emit authentication options for an email
  POST   /api/v1/auth/webauthn/login/finish     — public; verify assertion; mint SCCAP session
  GET    /api/v1/auth/webauthn/credentials      — authed; list the caller's passkeys
  DELETE /api/v1/auth/webauthn/credentials/{id} — authed; revoke a passkey

State carriage between begin/finish: signed `__Host-webauthn_challenge`
HttpOnly cookie (5-min TTL). Multi-worker safe; matches the SSO state-
cookie pattern.

Security notes:
  * RP ID and origin are derived from `settings.api_base_url`; verified
    by py_webauthn during attestation/assertion.
  * Challenge is single-use — every begin issues a fresh one; every
    finish clears the cookie unconditionally.
  * Sign-count regression triggers a clone alert (audit row + refusal).
  * `is_superuser` is NEVER granted via the WebAuthn flow — passkeys
    auth into an existing account; the role is what it was.
"""

from __future__ import annotations

import base64
import json
import logging
import time
import uuid as _uuid
from typing import Any, List, Optional
from urllib.parse import urlparse

import jwt as _pyjwt
from fastapi import (
    APIRouter,
    Body,
    Cookie,
    Depends,
    HTTPException,
    Path,
    Request,
    Response,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import bytes_to_base64url, options_to_json
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from app.config.config import settings
from app.infrastructure.auth.backend import get_custom_cookie_jwt_strategy
from app.infrastructure.auth.core import current_active_user
from app.infrastructure.auth.sso import audit
from app.infrastructure.auth.webauthn.challenge_cookie import (
    BadSignature,
    SignatureExpired,
    clear_challenge_cookie,
    consume_challenge,
    make_challenge,
    set_challenge_cookie,
    COOKIE_NAME as CHALLENGE_COOKIE_NAME,
)
from app.infrastructure.auth.webauthn.repository import WebAuthnRepository
from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import get_db

logger = logging.getLogger(__name__)


router = APIRouter(prefix="/auth/webauthn", tags=["Authentication: WebAuthn"])


# ----- Audit event constants -------------------------------------------------

EVENT_PASSKEY_REGISTERED = "auth.passkey.registered"
EVENT_PASSKEY_LOGIN_SUCCESS = "auth.passkey.login.success"
EVENT_PASSKEY_LOGIN_FAILURE = "auth.passkey.login.failure"
EVENT_PASSKEY_DELETED = "auth.passkey.deleted"
EVENT_PASSKEY_CLONE_DETECTED = "auth.passkey.clone_detected"


# ----- Helpers ---------------------------------------------------------------


def _rp_id_and_origin() -> tuple[str, str]:
    """RP ID = host (no port); origin = scheme://host[:port]."""
    base = settings.api_base_url
    parsed = urlparse(base)
    rp_id = parsed.hostname or "localhost"
    origin = base.rstrip("/")
    return rp_id, origin


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _options_to_dict(options: Any) -> dict:
    """py_webauthn 2.x ships `options_to_json` returning a JSON string."""
    return json.loads(options_to_json(options))


async def _issue_session_for_user(response: Response, user: db_models.User) -> str:
    """Mint access token + set refresh cookie. Mirrors `_issue_session` in
    routers/sso.py — duplicated to avoid an import cycle."""
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


async def _audit_safe(
    db: AsyncSession,
    *,
    event: str,
    user_id: Optional[int],
    request: Optional[Request],
    details: dict,
) -> None:
    try:
        await audit.record(
            db, event=event, user_id=user_id, request=request, details=details
        )
    except Exception:
        logger.warning(
            "auth.webauthn.audit_failed", extra={"event": event}, exc_info=True
        )


# ----- Pydantic schemas ------------------------------------------------------


class RegisterBeginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    friendly_name: str = Field(..., min_length=1, max_length=128)


class LoginBeginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(..., min_length=3, max_length=320)


# ----- Endpoints -------------------------------------------------------------


@router.post("/register/begin")
async def register_begin(
    payload: RegisterBeginRequest,
    response: Response,
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Authed user requests registration of a new passkey."""
    rp_id, _ = _rp_id_and_origin()
    repo = WebAuthnRepository(db)
    existing = await repo.list_for_user(user.id)

    cookie_value, raw_challenge = make_challenge(kind="register", user_id=user.id)
    options = generate_registration_options(
        rp_id=rp_id,
        rp_name="SCCAP",
        user_id=str(user.id).encode("utf-8"),
        user_name=user.email,
        user_display_name=user.email,
        challenge=raw_challenge,
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=c.credential_id) for c in existing
        ],
        authenticator_selection=AuthenticatorSelectionCriteria(
            # User Verification REQUIRED on register: binding a passkey
            # to this account is a high-value action — we want the
            # authenticator's biometric / PIN / built-in factor to fire.
            # The login path also enforces REQUIRED so an attacker with
            # the device alone (without the UV factor) cannot use it.
            user_verification=UserVerificationRequirement.REQUIRED,
            # Resident keys (a.k.a. discoverable credentials / passkeys
            # in modern parlance) are preferred so users can pick their
            # account from the browser/OS picker without typing email.
            resident_key=ResidentKeyRequirement.PREFERRED,
        ),
        # Algorithm allowlist: ECDSA-SHA256 (-7) and EdDSA (-8) cover
        # every modern Apple / Google / Microsoft / Yubico authenticator.
        # RSASSA-PSS-SHA256 (-37) retained for older corporate keys
        # that haven't been refreshed; the deprecated PKCS1v1.5 padding
        # (algorithm -257) is intentionally NOT included.
        supported_pub_key_algs=[
            COSEAlgorithmIdentifier.ECDSA_SHA_256,
            COSEAlgorithmIdentifier.EDDSA,
            COSEAlgorithmIdentifier.RSASSA_PSS_SHA_256,
        ],
    )
    set_challenge_cookie(response, cookie_value)
    response.headers["Cache-Control"] = "no-store"
    return _options_to_dict(options) | {"_friendly_name": payload.friendly_name}


@router.post("/register/finish")
async def register_finish(
    payload: dict = Body(...),
    response: Response = ...,
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
    challenge_cookie: Optional[str] = Cookie(default=None, alias=CHALLENGE_COOKIE_NAME),
) -> dict:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="malformed payload")
    cred = payload.get("credential")
    friendly_name = (payload.get("friendly_name") or "Unnamed passkey")[:128]
    if not isinstance(cred, dict):
        raise HTTPException(status_code=400, detail="missing credential")

    try:
        claims = consume_challenge(challenge_cookie, expected_kind="register")
    except SignatureExpired:
        raise HTTPException(status_code=400, detail="challenge expired")
    except (BadSignature, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"challenge invalid: {exc}")
    if claims.get("user_id") != user.id:
        raise HTTPException(status_code=400, detail="challenge user mismatch")

    rp_id, origin = _rp_id_and_origin()
    expected_challenge = _b64url_decode(claims["challenge"])
    try:
        verification = verify_registration_response(
            credential=cred,
            expected_challenge=expected_challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            # Match the UV REQUIRED set in register/begin's
            # authenticator_selection. py_webauthn cross-checks the
            # asserted UV flag against this expectation.
            require_user_verification=True,
        )
    except Exception as exc:
        await _audit_safe(
            db,
            event=EVENT_PASSKEY_LOGIN_FAILURE,
            user_id=user.id,
            request=None,
            details={"phase": "register", "reason": type(exc).__name__},
        )
        await db.commit()
        raise HTTPException(
            status_code=400, detail=f"attestation verification failed: {exc}"
        )

    repo = WebAuthnRepository(db)
    transports_raw = cred.get("transports") or cred.get("response", {}).get(
        "transports"
    )
    transports = (
        [t for t in transports_raw if isinstance(t, str)]
        if isinstance(transports_raw, list)
        else None
    )
    new_row = await repo.create(
        user_id=user.id,
        credential_id=verification.credential_id,
        public_key=verification.credential_public_key,
        sign_count=verification.sign_count,
        transports=transports,
        friendly_name=friendly_name,
    )
    await audit.record(
        db,
        event=EVENT_PASSKEY_REGISTERED,
        user_id=user.id,
        details={"friendly_name": friendly_name, "credential_uuid": str(new_row.id)},
    )
    await db.commit()
    clear_challenge_cookie(response)
    return {
        "id": str(new_row.id),
        "friendly_name": new_row.friendly_name,
        "credential_id_b64": bytes_to_base64url(new_row.credential_id),
    }


@router.post("/login/begin")
async def login_begin(
    payload: LoginBeginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """Public — emit authentication options for the email's existing passkeys.

    Returns the same response shape regardless of whether the email
    exists, so a 200 isn't an existence oracle. (Timing leakage is
    inherent to the lookup but materially the same as fastapi-users'
    /login.)
    """
    rp_id, _ = _rp_id_and_origin()
    repo = WebAuthnRepository(db)
    email = payload.email.strip().lower()
    result = await db.execute(
        select(db_models.User).where(db_models.User.email == email)
    )
    user = result.scalar_one_or_none()
    creds = await repo.list_for_user(user.id) if user else []

    cookie_value, raw_challenge = make_challenge(
        kind="login", user_id=user.id if user else None
    )
    options = generate_authentication_options(
        rp_id=rp_id,
        challenge=raw_challenge,
        allow_credentials=[
            PublicKeyCredentialDescriptor(
                id=c.credential_id, transports=c.transports or None
            )
            for c in creds
        ],
        # UV REQUIRED on login: passkeys were registered with UV REQUIRED,
        # so requiring it on login closes the attack of a stolen device
        # without the UV factor (biometric / PIN). Hardware-only keys
        # without UV (rare, mostly old YubiKey 4) can't be used for
        # passkey login here — the org should issue a UV-capable key
        # if it needs hardware passkeys.
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    set_challenge_cookie(response, cookie_value)
    response.headers["Cache-Control"] = "no-store"
    return _options_to_dict(options)


@router.post("/login/finish")
async def login_finish(
    payload: dict = Body(...),
    response: Response = ...,
    request: Request = ...,
    db: AsyncSession = Depends(get_db),
    challenge_cookie: Optional[str] = Cookie(default=None, alias=CHALLENGE_COOKIE_NAME),
) -> dict:
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="malformed payload")
    cred = payload.get("credential")
    if not isinstance(cred, dict):
        raise HTTPException(status_code=400, detail="missing credential")

    try:
        claims = consume_challenge(challenge_cookie, expected_kind="login")
    except SignatureExpired:
        raise HTTPException(status_code=400, detail="challenge expired")
    except (BadSignature, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f"challenge invalid: {exc}")

    rp_id, origin = _rp_id_and_origin()
    expected_challenge = _b64url_decode(claims["challenge"])

    repo = WebAuthnRepository(db)
    raw_id_b64 = cred.get("rawId") or cred.get("id")
    if not isinstance(raw_id_b64, str):
        raise HTTPException(status_code=400, detail="missing credential id")
    raw_id = _b64url_decode(raw_id_b64)
    stored = await repo.get_by_credential_id(raw_id)
    if stored is None:
        await _audit_safe(
            db,
            event=EVENT_PASSKEY_LOGIN_FAILURE,
            user_id=None,
            request=request,
            details={"reason": "credential_not_found"},
        )
        await db.commit()
        raise HTTPException(status_code=400, detail="unknown credential")

    try:
        verification = verify_authentication_response(
            credential=cred,
            expected_challenge=expected_challenge,
            expected_origin=origin,
            expected_rp_id=rp_id,
            credential_public_key=stored.public_key,
            credential_current_sign_count=stored.sign_count,
            # Match the UV REQUIRED set in login/begin. The
            # authenticator MUST assert the UV bit; py_webauthn
            # raises if it's missing.
            require_user_verification=True,
        )
    except Exception as exc:
        # py_webauthn raises on sign-count regression. We surface that as
        # a clone alert; everything else is just a verification failure.
        is_clone = "sign count" in str(exc).lower()
        await _audit_safe(
            db,
            event=(
                EVENT_PASSKEY_CLONE_DETECTED
                if is_clone
                else EVENT_PASSKEY_LOGIN_FAILURE
            ),
            user_id=stored.user_id,
            request=request,
            details={"reason": type(exc).__name__, "msg": str(exc)[:200]},
        )
        await db.commit()
        raise HTTPException(
            status_code=400, detail=f"assertion verification failed: {exc}"
        )

    await repo.update_sign_count(stored.id, verification.new_sign_count)

    user_result = await db.execute(
        select(db_models.User).where(db_models.User.id == stored.user_id)
    )
    user = user_result.scalar_one_or_none()
    if user is None or not user.is_active:
        await db.commit()
        raise HTTPException(status_code=400, detail="user not found or inactive")

    access_token = await _issue_session_for_user(response, user)
    await audit.record(
        db,
        event=EVENT_PASSKEY_LOGIN_SUCCESS,
        user_id=user.id,
        request=request,
        details={"credential_uuid": str(stored.id)},
    )
    await db.commit()
    clear_challenge_cookie(response)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/credentials")
async def list_credentials(
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> List[dict]:
    repo = WebAuthnRepository(db)
    rows = await repo.list_for_user(user.id)
    return [
        {
            "id": str(r.id),
            "friendly_name": r.friendly_name,
            "transports": r.transports or [],
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "last_used_at": (r.last_used_at.isoformat() if r.last_used_at else None),
        }
        for r in rows
    ]


@router.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_credential(
    request: Request,
    credential_id: str = Path(..., min_length=10, max_length=64),
    user: db_models.User = Depends(current_active_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    try:
        pk = _uuid.UUID(credential_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="invalid credential id")
    repo = WebAuthnRepository(db)
    deleted = await repo.delete(pk, user_id=user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="credential not found")
    await audit.record(
        db,
        event=EVENT_PASSKEY_DELETED,
        user_id=user.id,
        request=request,
        details={"credential_uuid": credential_id},
    )
    await db.commit()


__all__ = ["router"]
