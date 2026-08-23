"""Real-PostgreSQL tenant-domain, JIT, and mapping assurance contracts."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, select

from app.infrastructure.auth.sso.provisioning import (
    SsoProvisioningDenied,
    provision_or_link_oidc,
)
from app.infrastructure.auth.sso.repository import SsoProviderRepository
from app.infrastructure.auth.sso.replay import claim_message_once
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    RoleAssignment,
    SsoProvider,
    Tenant,
    TenantVerifiedDomain,
    User,
    UserGroup,
    UserGroupMembership,
)
from app.shared.lib.permissions import ANALYST
from tests.integration.support import integration_test


@integration_test
class FederationProvisioningIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.domain = f"{suffix}.example.com"
        self.group_name = f"Engineering-{suffix}"
        async with AsyncSessionLocal() as db:
            tenant = Tenant(slug=f"federation-{suffix}", display_name="Federation Test")
            db.add(tenant)
            await db.flush()
            owner = User(
                email=f"owner-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(f"A7!{uuid4()}z"),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant.id,
            )
            db.add(owner)
            await db.flush()
            db.add(
                TenantVerifiedDomain(
                    tenant_id=tenant.id,
                    domain=self.domain,
                    verification_token_hash="a" * 64,
                    status="verified",
                )
            )
            group = UserGroup(
                name=self.group_name,
                description="fixture",
                created_by=owner.id,
                tenant_id=tenant.id,
            )
            db.add(group)
            provider = await SsoProviderRepository(db).create(
                name=f"federation-{suffix}",
                display_name="Federation Test",
                protocol="oidc",
                config_plain={
                    "issuer_url": "https://idp.example.test",
                    "client_id": "integration-client",
                    "client_secret": "integration-secret",
                },
                allowed_email_domains=[self.domain],
                jit_policy="auto",
                tenant_id=tenant.id,
            )
            await db.commit()
            self.tenant_id = tenant.id
            self.owner_id = owner.id
            self.provider_id = provider.id
            self.group_id = group.id

    async def asyncTearDown(self) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(delete(UserGroup).where(UserGroup.id == self.group_id))
            await db.execute(
                delete(User).where(
                    (User.tenant_id == self.tenant_id) | (User.id == self.owner_id)
                )
            )
            await db.execute(delete(SsoProvider).where(SsoProvider.id == self.provider_id))
            await db.execute(delete(Tenant).where(Tenant.id == self.tenant_id))
            await db.commit()
        await engine.dispose()

    async def test_verified_domain_jit_and_group_mapping_are_tenant_bound(self) -> None:
        email = f"jit-user@{self.domain}"
        async with AsyncSessionLocal() as db:
            provider = await db.get(SsoProvider, self.provider_id)
            identity = await provision_or_link_oidc(
                db,
                provider=provider,
                sub="subject-jit",
                email=email,
                email_verified=True,
                raw_claims={"groups": ["idp-engineering", "unmapped"]},
                group_claim_path="groups",
                group_mapping={"idp-engineering": self.group_name},
            )
            await db.commit()
            self.assertTrue(identity.is_new_user)
            self.assertEqual(identity.user.tenant_id, self.tenant_id)
            self.assertFalse(identity.user.is_superuser)
            role = await db.scalar(
                select(RoleAssignment.role_key).where(
                    RoleAssignment.user_id == identity.user.id,
                    RoleAssignment.tenant_id == self.tenant_id,
                )
            )
            self.assertEqual(role, ANALYST)
            membership = await db.scalar(
                select(UserGroupMembership).where(
                    UserGroupMembership.group_id == self.group_id,
                    UserGroupMembership.user_id == identity.user.id,
                )
            )
            self.assertIsNotNone(membership)

    async def test_unverified_domain_cannot_link_or_jit(self) -> None:
        async with AsyncSessionLocal() as db:
            provider = await db.get(SsoProvider, self.provider_id)
            provider.allowed_email_domains = ["unverified.example.com"]
            with self.assertRaises(SsoProvisioningDenied):
                await provision_or_link_oidc(
                    db,
                    provider=provider,
                    sub="subject-denied",
                    email="user@unverified.example.com",
                    email_verified=True,
                )
            await db.rollback()
            created = await db.scalar(
                select(User).where(User.email == "user@unverified.example.com")
            )
            self.assertIsNone(created)

    async def test_federation_message_id_is_claimed_only_once(self) -> None:
        async with AsyncSessionLocal() as db:
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=5)
            first = await claim_message_once(
                db,
                provider_id=self.provider_id,
                kind="saml_assertion",
                message_id="assertion-fixture-1",
                expires_at=expires_at,
            )
            second = await claim_message_once(
                db,
                provider_id=self.provider_id,
                kind="saml_assertion",
                message_id="assertion-fixture-1",
                expires_at=expires_at,
            )
            await db.commit()
        self.assertTrue(first)
        self.assertFalse(second)


if __name__ == "__main__":
    unittest.main()
