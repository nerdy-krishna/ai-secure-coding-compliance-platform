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
from typing import Dict, List, Optional

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
      * **F9 (CLOSED)** Side-effects from ``manager.on_after_register``
        cannot fire on this path because we go through ``user_db.create``
        directly — ``UserManager.create()``'s ``await self.on_after_register
        (...)`` is never called. The user is committed by the caller's
        transaction; no welcome email or post-register hook executes
        before the audit row + commit. If a future change reintroduces
        ``manager.create()`` here, F9 must be re-evaluated (the hook
        would fire pre-commit and could leak a user before the audit row
        is durable).

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


def _extract_groups_from_claims(
    claims: Optional[dict], path: Optional[str]
) -> List[str]:
    """Walk a dotted-path into ``claims`` and return the value as a list of strings.

    Supports nested objects (Keycloak ``realm_access.roles``,
    ``resource_access.<client>.roles``) and top-level keys (Okta-style
    ``groups``). If the path doesn't resolve, the value isn't a list, or
    any element isn't a string, returns an empty list.

    Never raises — group sync is best-effort and must NEVER break login.
    """
    if not claims or not path:
        return []
    cursor: object = claims
    for segment in path.split("."):
        if not isinstance(cursor, dict):
            return []
        cursor = cursor.get(segment)
        if cursor is None:
            return []
    if not isinstance(cursor, list):
        return []
    return [str(g) for g in cursor if isinstance(g, str)]


async def _sync_groups_from_idp(
    session: AsyncSession,
    *,
    user: db_models.User,
    provider: db_models.SsoProvider,
    idp_groups: List[str],
    group_mapping: Dict[str, str],
    request: Optional[Request],
) -> None:
    """Additively sync user's user_groups membership from IdP group claims.

    For each IdP group in ``idp_groups``, look up its mapped SCCAP group
    name in ``group_mapping`` and ensure the user is a member of that
    group. **Never removes** existing memberships — operators retain full
    control over group revocation via the User Groups admin UI.

    Failures are logged + audited but never raised — the SSO login itself
    succeeds even if group sync hits a database hiccup.
    """
    if not idp_groups or not group_mapping:
        return
    from app.infrastructure.database.repositories.user_group_repo import (
        UserGroupRepository,
    )

    repo = UserGroupRepository(session)
    try:
        existing_groups = await repo.list_groups_for_user(user.id)
        existing_names = {g.name for g in existing_groups}
        all_groups = await repo.list_groups()
        groups_by_name = {g.name: g for g in all_groups}
    except Exception:
        logger.warning(
            "auth.group_sync.lookup_failed",
            extra={"user_id": user.id, "provider_id": str(provider.id)},
            exc_info=True,
        )
        return

    for idp_group in idp_groups:
        mapped = group_mapping.get(idp_group)
        if mapped is None:
            # Track unmapped IdP group names for operator visibility (drift signal).
            try:
                await audit.record(
                    session,
                    event=audit.EVENT_GROUP_UNMAPPED,
                    user_id=user.id,
                    provider_id=provider.id,
                    request=request,
                    details={"idp_group": idp_group},
                )
            except Exception:
                pass
            continue
        if mapped in existing_names:
            continue  # already a member; idempotent
        target = groups_by_name.get(mapped)
        if target is None:
            # Mapping points at a SCCAP group that doesn't exist. Audit
            # but don't fail — admin should fix the mapping.
            try:
                await audit.record(
                    session,
                    event=audit.EVENT_GROUP_UNMAPPED,
                    user_id=user.id,
                    provider_id=provider.id,
                    request=request,
                    details={
                        "idp_group": idp_group,
                        "reason": "mapped_target_missing",
                        "target": mapped,
                    },
                )
            except Exception:
                pass
            continue
        try:
            await repo.add_member(target.id, user.id)
            await audit.record(
                session,
                event=audit.EVENT_GROUP_MAPPED,
                user_id=user.id,
                provider_id=provider.id,
                request=request,
                details={"idp_group": idp_group, "sccap_group": mapped},
            )
        except Exception:
            logger.warning(
                "auth.group_sync.add_member_failed",
                extra={
                    "user_id": user.id,
                    "provider_id": str(provider.id),
                    "target_group": mapped,
                },
                exc_info=True,
            )


async def provision_or_link_oidc(
    session: AsyncSession,
    *,
    provider: db_models.SsoProvider,
    sub: str,
    email: str,
    email_verified: bool,
    request: Optional[Request] = None,
    require_email_verified: bool = True,
    raw_claims: Optional[dict] = None,
    group_claim_path: Optional[str] = None,
    group_mapping: Optional[Dict[str, str]] = None,
) -> ProvisionedIdentity:
    """Resolve an OIDC subject to a SCCAP User — link, JIT-create, or refuse.

    When ``group_claim_path`` and ``group_mapping`` are provided, the
    user's `user_groups` membership is additively synced from IdP claims
    after the user is established. ``is_superuser`` is NEVER affected.
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
        # Re-sync group memberships on every login so directory drift
        # (new groups added at the IdP) propagates without a re-link.
        await _sync_groups_from_idp(
            session,
            user=user,
            provider=provider,
            idp_groups=_extract_groups_from_claims(raw_claims, group_claim_path),
            group_mapping=group_mapping or {},
            request=request,
        )
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
        await _sync_groups_from_idp(
            session,
            user=user,
            provider=provider,
            idp_groups=_extract_groups_from_claims(raw_claims, group_claim_path),
            group_mapping=group_mapping or {},
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
    # First-login group sync.
    await _sync_groups_from_idp(
        session,
        user=user,
        provider=provider,
        idp_groups=_extract_groups_from_claims(raw_claims, group_claim_path),
        group_mapping=group_mapping or {},
        request=request,
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
    saml_attributes: Optional[Dict[str, List[str]]] = None,
    group_attribute: Optional[str] = None,
    group_mapping: Optional[Dict[str, str]] = None,
) -> ProvisionedIdentity:
    """Resolve a SAML NameID + email-attribute to a SCCAP User.

    SAML's identity provider is, by signed-assertion contract, asserting
    the email attribute. There is no separate ``email_verified`` claim;
    the cryptographic signature is the verification — which is enforced
    upstream by ``saml.process_acs``.

    When ``group_attribute`` and ``group_mapping`` are provided, the user's
    `user_groups` membership is additively synced from the SAML attribute
    values after the user is established. ``is_superuser`` is NEVER
    affected by group sync.
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

    # Resolve IdP-asserted groups once for use in every branch below.
    idp_groups: List[str] = []
    if saml_attributes and group_attribute:
        raw = saml_attributes.get(group_attribute) or []
        idp_groups = [g for g in raw if isinstance(g, str)]

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
        await _sync_groups_from_idp(
            session,
            user=user,
            provider=provider,
            idp_groups=idp_groups,
            group_mapping=group_mapping or {},
            request=request,
        )
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
        await _sync_groups_from_idp(
            session,
            user=user,
            provider=provider,
            idp_groups=idp_groups,
            group_mapping=group_mapping or {},
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
    await _sync_groups_from_idp(
        session,
        user=user,
        provider=provider,
        idp_groups=idp_groups,
        group_mapping=group_mapping or {},
        request=request,
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
