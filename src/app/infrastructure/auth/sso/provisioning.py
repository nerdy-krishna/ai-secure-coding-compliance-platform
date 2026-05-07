"""JIT provisioning + account-linking with policy + threat-model controls.

Mitigations:

* **M4** — Account linking REQUIRES a verified-email signal:
  * OIDC: ``email_verified=True`` claim.
  * SAML: a signed ``Email`` (or mapped) attribute. The signed-assertion
    requirement is enforced upstream by ``saml.process_acs``; here we just
    need the attribute to be present.
  Linking to a *pre-existing superuser account* is REFUSED entirely — the
  admin must use the Users page to manually link an SSO subject to an
  existing admin (or never link at all).
* **M5** — JIT-created users get ``is_superuser=False`` HARD-CODED. We
  never read superuser bits from any IdP claim. The first-user-ever rule
  (smallest ``users.id``) still applies and is checked separately by
  ``setup.py`` — an SSO JIT-create cannot promote a non-first user.

Policy values for ``SsoProvider.jit_policy``:
  * ``"auto"``    — create the user automatically with ``is_active=True``.
  * ``"approve"`` — create with ``is_active=False``; admin approves later.
  * ``"deny"``    — refuse provisioning entirely.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from dataclasses import dataclass
from typing import Optional

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models

from . import audit
from .repository import SsoProviderRepository

logger = logging.getLogger(__name__)


class SsoProvisioningError(Exception):
    """Base — generic SSO provisioning rejection."""


class SsoProvisioningDenied(SsoProvisioningError):
    """JIT policy is ``deny``, or domain is not in ``allowed_email_domains``."""


class SsoProvisioningPending(SsoProvisioningError):
    """User was created but is awaiting admin approval (``jit_policy=approve``)."""


class SsoProvisioningEmailUnverified(SsoProvisioningError):
    """Identity provider did not assert ``email_verified=True``."""


class SsoProvisioningSuperuserLink(SsoProvisioningError):
    """Refuses to link an SSO subject to a pre-existing superuser account.

    Operators must manually link superusers via the user-management UI
    (admin acknowledges the security implications of granting an external
    IdP authority over an admin account)."""


@dataclass(slots=True)
class ProvisionedIdentity:
    """Result of a successful provision_or_link call."""

    user: db_models.User
    is_new_user: bool
    is_new_link: bool


def _normalize_email(email: str) -> str:
    return email.strip().lower()


def _domain_of(email: str) -> str:
    parts = _normalize_email(email).split("@", 1)
    return parts[1] if len(parts) == 2 else ""


def _domain_allowed(provider: db_models.SsoProvider, email: str) -> bool:
    allowed = provider.allowed_email_domains
    if not allowed:
        return True
    return _domain_of(email) in {d.lower() for d in allowed}


async def _find_user_by_email(
    session: AsyncSession, email: str
) -> Optional[db_models.User]:
    norm = _normalize_email(email)
    result = await session.execute(
        select(db_models.User).where(db_models.User.email == norm)
    )
    return result.scalar_one_or_none()


async def _create_jit_user(
    session: AsyncSession,
    email: str,
    *,
    is_active: bool,
) -> db_models.User:
    """JIT-create a SCCAP user from SSO claims.

    Critical:
      * **M5** ``is_superuser=False`` is HARD-CODED here. We do NOT read
        this from any claim.
      * **F3** Bypasses ``UserCreate`` schema-and-``manager.create()``
        because the schema declares ``is_active = Field(default=True,
        exclude=True)``: even when we pass ``is_active=False`` the field
        is stripped on serialization and fastapi-users lands the user as
        active. We need the JIT-policy ``approve`` flow to actually
        produce inactive users awaiting admin approval, so we hash the
        password directly and INSERT via the user repo.

    The password is a random 64-char URL-safe token — the user cannot
    accidentally auth via password until an admin issues a reset. This
    prevents an SSO-only account from being "locked out" if the IdP is
    later disabled (admin can reset and let them in via password).
    """
    from app.infrastructure.auth.db import get_user_db
    from app.infrastructure.auth.manager import UserManager

    norm = _normalize_email(email)
    sentinel_password = secrets.token_urlsafe(64)

    user_db_gen = get_user_db(session)
    user_db = await user_db_gen.__anext__()
    try:
        manager = UserManager(user_db)
        # password_helper.hash() is the same path manager.create() uses.
        hashed_password = manager.password_helper.hash(sentinel_password)
        user_dict = {
            "email": norm,
            "hashed_password": hashed_password,
            # M5: hard-coded; defense in depth — if a future refactor adds
            # a JSON-mass-assignment path, this dict must STILL set False.
            "is_active": is_active,
            "is_superuser": False,
            "is_verified": True,
        }
        user = await user_db.create(user_dict)
    finally:
        try:
            await user_db_gen.aclose()
        except Exception:
            pass
    return user


async def provision_or_link_oidc(
    session: AsyncSession,
    *,
    provider: db_models.SsoProvider,
    sub: str,
    email: str,
    email_verified: bool,
    request: Optional[Request] = None,
    require_email_verified: bool = True,
) -> ProvisionedIdentity:
    """Resolve an OIDC subject to a SCCAP User — link, JIT-create, or refuse."""
    norm_email = _normalize_email(email)
    if not _domain_allowed(provider, norm_email):
        await audit.record(
            session,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            email=norm_email,
            request=request,
            details={"reason": "domain_not_allowed", "domain": _domain_of(norm_email)},
        )
        raise SsoProvisioningDenied(
            f"email domain not in allowed list for provider {provider.name!r}"
        )

    repo = SsoProviderRepository(session)
    existing_link = await repo.find_oauth_account(provider.id, sub)
    if existing_link is not None:
        # Returning user — no further checks (the link was vetted on creation).
        result = await session.execute(
            select(db_models.User).where(db_models.User.id == existing_link.user_id)
        )
        user = result.scalar_one_or_none()
        if user is None:
            # Defensive: link points at a deleted user. Refuse.
            raise SsoProvisioningError("oauth_accounts row points at missing user")
        return ProvisionedIdentity(user=user, is_new_user=False, is_new_link=False)

    # No link yet. Look up by email.
    if require_email_verified and not email_verified:
        await audit.record(
            session,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            email=norm_email,
            request=request,
            details={"reason": "email_unverified_at_idp"},
        )
        raise SsoProvisioningEmailUnverified(
            "IdP did not assert email_verified=True; refusing to link or create"
        )

    user = await _find_user_by_email(session, norm_email)
    if user is not None:
        # Refuse to silently link to a pre-existing admin (M4).
        if user.is_superuser:
            await audit.record(
                session,
                event=audit.EVENT_SSO_LINK_REFUSED,
                user_id=user.id,
                provider_id=provider.id,
                email=norm_email,
                request=request,
                details={"reason": "preexisting_superuser_account"},
            )
            raise SsoProvisioningSuperuserLink(
                "linking SSO subjects to pre-existing superuser accounts is refused; "
                "manual link required"
            )
        await repo.create_oauth_link(
            user_id=user.id,
            provider_id=provider.id,
            account_id=sub,
            account_email=norm_email,
        )
        await audit.record(
            session,
            event=audit.EVENT_SSO_LINKED,
            user_id=user.id,
            provider_id=provider.id,
            email=norm_email,
            request=request,
        )
        return ProvisionedIdentity(user=user, is_new_user=False, is_new_link=True)

    # JIT-create branch.
    if provider.jit_policy == "deny":
        await audit.record(
            session,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            email=norm_email,
            request=request,
            details={"reason": "jit_policy_deny"},
        )
        raise SsoProvisioningDenied("provider jit_policy=deny; no auto-provisioning")

    is_active = provider.jit_policy != "approve"
    user = await _create_jit_user(session, norm_email, is_active=is_active)
    await repo.create_oauth_link(
        user_id=user.id,
        provider_id=provider.id,
        account_id=sub,
        account_email=norm_email,
    )
    await audit.record(
        session,
        event=audit.EVENT_SSO_PROVISIONED,
        user_id=user.id,
        provider_id=provider.id,
        email=norm_email,
        request=request,
        details={"jit_policy": provider.jit_policy, "is_active": is_active},
    )
    if not is_active:
        raise SsoProvisioningPending(
            "user provisioned but awaiting admin approval (jit_policy=approve)"
        )
    return ProvisionedIdentity(user=user, is_new_user=True, is_new_link=True)


async def provision_or_link_saml(
    session: AsyncSession,
    *,
    provider: db_models.SsoProvider,
    name_id: str,
    name_id_format: str,
    email: str,
    session_index: Optional[str],
    request: Optional[Request] = None,
) -> ProvisionedIdentity:
    """Resolve a SAML NameID + email-attribute to a SCCAP User.

    SAML's identity provider is, by signed-assertion contract, asserting
    the email attribute. There is no separate ``email_verified`` claim;
    the cryptographic signature is the verification — which is enforced
    upstream by ``saml.process_acs``.
    """
    norm_email = _normalize_email(email)
    if not _domain_allowed(provider, norm_email):
        await audit.record(
            session,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            email=norm_email,
            request=request,
            details={"reason": "domain_not_allowed", "domain": _domain_of(norm_email)},
        )
        raise SsoProvisioningDenied(
            f"email domain not in allowed list for provider {provider.name!r}"
        )

    repo = SsoProviderRepository(session)
    existing = await repo.find_saml_subject(provider.id, name_id)
    if existing is not None:
        # Update session_index for SLO.
        if session_index != existing.session_index:
            await repo.update_saml_session_index(existing.id, session_index)
        result = await session.execute(
            select(db_models.User).where(db_models.User.id == existing.user_id)
        )
        user = result.scalar_one_or_none()
        if user is None:
            raise SsoProvisioningError("saml_subjects row points at missing user")
        return ProvisionedIdentity(user=user, is_new_user=False, is_new_link=False)

    user = await _find_user_by_email(session, norm_email)
    if user is not None:
        if user.is_superuser:
            await audit.record(
                session,
                event=audit.EVENT_SSO_LINK_REFUSED,
                user_id=user.id,
                provider_id=provider.id,
                email=norm_email,
                request=request,
                details={"reason": "preexisting_superuser_account"},
            )
            raise SsoProvisioningSuperuserLink(
                "linking SSO subjects to pre-existing superuser accounts is refused"
            )
        await repo.create_saml_link(
            user_id=user.id,
            provider_id=provider.id,
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
        )
        await audit.record(
            session,
            event=audit.EVENT_SSO_LINKED,
            user_id=user.id,
            provider_id=provider.id,
            email=norm_email,
            request=request,
        )
        return ProvisionedIdentity(user=user, is_new_user=False, is_new_link=True)

    if provider.jit_policy == "deny":
        await audit.record(
            session,
            event=audit.EVENT_SSO_LOGIN_FAILURE,
            provider_id=provider.id,
            email=norm_email,
            request=request,
            details={"reason": "jit_policy_deny"},
        )
        raise SsoProvisioningDenied("provider jit_policy=deny; no auto-provisioning")

    is_active = provider.jit_policy != "approve"
    user = await _create_jit_user(session, norm_email, is_active=is_active)
    await repo.create_saml_link(
        user_id=user.id,
        provider_id=provider.id,
        name_id=name_id,
        name_id_format=name_id_format,
        session_index=session_index,
    )
    await audit.record(
        session,
        event=audit.EVENT_SSO_PROVISIONED,
        user_id=user.id,
        provider_id=provider.id,
        email=norm_email,
        request=request,
        details={"jit_policy": provider.jit_policy, "is_active": is_active},
    )
    if not is_active:
        raise SsoProvisioningPending(
            "user provisioned but awaiting admin approval (jit_policy=approve)"
        )
    return ProvisionedIdentity(user=user, is_new_user=True, is_new_link=True)


# Re-export uuid for convenience (callers want to type provider_id).
__all__ = [
    "ProvisionedIdentity",
    "SsoProvisioningError",
    "SsoProvisioningDenied",
    "SsoProvisioningPending",
    "SsoProvisioningEmailUnverified",
    "SsoProvisioningSuperuserLink",
    "provision_or_link_oidc",
    "provision_or_link_saml",
    "uuid",
]
