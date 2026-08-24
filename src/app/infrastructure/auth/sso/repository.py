"""Async CRUD for the ``sso_providers`` table.

Always returns the *decrypted* config to in-process callers via the
``SsoProviderWithConfig`` named tuple. Never returns the encrypted bytes
to wire-level callers — admin routes must use the redacted-secrets schemas
in ``app.api.v1.routers.admin_sso``.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.secrets.scoped import (
    decrypt_scoped_secret,
    encrypt_scoped_secret,
)

from .models import SsoConfig, parse_provider_config


@dataclass(slots=True)
class SsoProviderWithConfig:
    """In-process representation of an SSO provider with its decrypted config."""

    row: db_models.SsoProvider
    config: SsoConfig


class SsoProviderRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def list_all(self, *, tenant_id: uuid.UUID) -> List[db_models.SsoProvider]:
        """All providers in one explicit tenant (enabled + disabled)."""
        result = await self.session.execute(
            select(db_models.SsoProvider)
            .where(db_models.SsoProvider.tenant_id == tenant_id)
            .order_by(db_models.SsoProvider.created_at)
        )
        return list(result.scalars().all())

    async def list_enabled(
        self, *, tenant_id: uuid.UUID
    ) -> List[db_models.SsoProvider]:
        """Enabled providers in one explicit tenant."""
        result = await self.session.execute(
            select(db_models.SsoProvider)
            .where(
                db_models.SsoProvider.enabled.is_(True),
                db_models.SsoProvider.tenant_id == tenant_id,
            )
            .order_by(db_models.SsoProvider.created_at)
        )
        return list(result.scalars().all())

    async def get_by_id(
        self,
        provider_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID | None = None,
    ) -> Optional[db_models.SsoProvider]:
        stmt = select(db_models.SsoProvider).where(
            db_models.SsoProvider.id == provider_id
        )
        if tenant_id is not None:
            stmt = stmt.where(db_models.SsoProvider.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_by_name(
        self,
        name: str,
        *,
        tenant_id: uuid.UUID | None = None,
    ) -> Optional[db_models.SsoProvider]:
        stmt = select(db_models.SsoProvider).where(db_models.SsoProvider.name == name)
        if tenant_id is not None:
            stmt = stmt.where(db_models.SsoProvider.tenant_id == tenant_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def get_with_config(
        self,
        provider_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID | None = None,
    ) -> Optional[SsoProviderWithConfig]:
        row = await self.get_by_id(provider_id, tenant_id=tenant_id)
        if row is None:
            return None
        secret = await decrypt_scoped_secret(
            row.config_encrypted.decode(),
            scope={
                "kind": "sso_provider",
                "tenant_id": str(row.tenant_id),
                "id": str(row.id),
            },
        )
        if secret.persisted_value is not None:
            row.config_encrypted = secret.persisted_value.encode()
            await self.session.commit()
        plaintext = json.loads(secret.plaintext)
        cfg = parse_provider_config(row.protocol, plaintext)
        return SsoProviderWithConfig(row=row, config=cfg)

    async def create(
        self,
        *,
        name: str,
        display_name: str,
        protocol: str,
        config_plain: Dict[str, Any],
        enabled: bool = True,
        allowed_email_domains: Optional[List[str]] = None,
        force_for_domains: Optional[List[str]] = None,
        jit_policy: str = "auto",
        tenant_id: uuid.UUID | None = None,
    ) -> db_models.SsoProvider:
        # Validate the config plaintext BEFORE encryption.
        parse_provider_config(protocol, config_plain)
        provider_id = uuid.uuid4()
        row = db_models.SsoProvider(
            id=provider_id,
            name=name,
            display_name=display_name,
            protocol=protocol,
            enabled=enabled,
            config_encrypted=(
                await encrypt_scoped_secret(
                    json.dumps(config_plain, ensure_ascii=False, separators=(",", ":")),
                    scope={
                        "kind": "sso_provider",
                        "tenant_id": str(tenant_id),
                        "id": str(provider_id),
                    },
                )
            ).encode(),
            allowed_email_domains=allowed_email_domains,
            force_for_domains=force_for_domains,
            jit_policy=jit_policy,
            tenant_id=tenant_id,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def update_fields(
        self,
        provider_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
        display_name: Optional[str] = None,
        enabled: Optional[bool] = None,
        config_plain: Optional[Dict[str, Any]] = None,
        protocol: Optional[str] = None,  # used only when config_plain provided
        allowed_email_domains: Optional[List[str]] = None,
        force_for_domains: Optional[List[str]] = None,
        jit_policy: Optional[str] = None,
    ) -> Optional[db_models.SsoProvider]:
        row = await self.get_by_id(provider_id, tenant_id=tenant_id)
        if row is None:
            return None
        if display_name is not None:
            row.display_name = display_name
        if enabled is not None:
            row.enabled = enabled
        if config_plain is not None:
            # Re-validate against the (possibly-updated) protocol before encryption.
            parse_provider_config(protocol or row.protocol, config_plain)
            row.config_encrypted = (
                await encrypt_scoped_secret(
                    json.dumps(config_plain, ensure_ascii=False, separators=(",", ":")),
                    scope={
                        "kind": "sso_provider",
                        "tenant_id": str(row.tenant_id),
                        "id": str(row.id),
                    },
                )
            ).encode()
        if allowed_email_domains is not None:
            row.allowed_email_domains = allowed_email_domains or None
        if force_for_domains is not None:
            row.force_for_domains = force_for_domains or None
        if jit_policy is not None:
            row.jit_policy = jit_policy
        await self.session.flush()
        return row

    async def delete(self, provider_id: uuid.UUID, *, tenant_id: uuid.UUID) -> bool:
        row = await self.get_by_id(provider_id, tenant_id=tenant_id)
        if row is None:
            return False
        await self.session.delete(row)
        await self.session.flush()
        return True

    # --- linking lookups ----------------------------------------------------

    async def find_oauth_account(
        self, provider_id: uuid.UUID, account_id: str, *, tenant_id: uuid.UUID
    ) -> Optional[db_models.OAuthAccount]:
        result = await self.session.execute(
            select(db_models.OAuthAccount).where(
                db_models.OAuthAccount.provider_id == provider_id,
                db_models.OAuthAccount.account_id == account_id,
                db_models.OAuthAccount.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def find_saml_subject(
        self, provider_id: uuid.UUID, name_id: str, *, tenant_id: uuid.UUID
    ) -> Optional[db_models.SamlSubject]:
        result = await self.session.execute(
            select(db_models.SamlSubject).where(
                db_models.SamlSubject.provider_id == provider_id,
                db_models.SamlSubject.name_id == name_id,
                db_models.SamlSubject.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def create_oauth_link(
        self,
        *,
        user_id: int,
        provider_id: uuid.UUID,
        account_id: str,
        account_email: str,
        idp_token_expires_at: Optional[datetime] = None,
        tenant_id: uuid.UUID,
    ) -> db_models.OAuthAccount:
        row = db_models.OAuthAccount(
            user_id=user_id,
            provider_id=provider_id,
            account_id=account_id,
            account_email=account_email,
            idp_token_expires_at=idp_token_expires_at,
            tenant_id=tenant_id,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def update_oauth_token_expiry(
        self,
        oauth_account_id: uuid.UUID,
        idp_token_expires_at: Optional[datetime],
        *,
        tenant_id: uuid.UUID,
    ) -> None:
        """Refresh `oauth_accounts.idp_token_expires_at` on a returning login.

        Called by the OIDC callback for the bind-to-IdP-session feature
        (Chunk 4) so each successful sign-in pushes the SCCAP session
        ceiling forward in lock-step with the IdP-issued access-token.
        """
        await self.session.execute(
            update(db_models.OAuthAccount)
            .where(
                db_models.OAuthAccount.id == oauth_account_id,
                db_models.OAuthAccount.tenant_id == tenant_id,
            )
            .values(idp_token_expires_at=idp_token_expires_at)
        )
        await self.session.flush()

    async def create_saml_link(
        self,
        *,
        user_id: int,
        provider_id: uuid.UUID,
        name_id: str,
        name_id_format: str,
        session_index: Optional[str] = None,
        tenant_id: uuid.UUID,
    ) -> db_models.SamlSubject:
        row = db_models.SamlSubject(
            user_id=user_id,
            provider_id=provider_id,
            name_id=name_id,
            name_id_format=name_id_format,
            session_index=session_index,
            tenant_id=tenant_id,
        )
        self.session.add(row)
        await self.session.flush()
        return row

    async def update_saml_session_index(
        self,
        subject_id: uuid.UUID,
        session_index: Optional[str],
        *,
        tenant_id: uuid.UUID,
    ) -> None:
        await self.session.execute(
            update(db_models.SamlSubject)
            .where(
                db_models.SamlSubject.id == subject_id,
                db_models.SamlSubject.tenant_id == tenant_id,
            )
            .values(session_index=session_index)
        )
        await self.session.flush()
