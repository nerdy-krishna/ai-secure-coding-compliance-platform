"""Live exact-domain public SSO discovery contract."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from sqlalchemy import delete

from app.infrastructure.auth.sso.repository import SsoProviderRepository
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import SsoProvider, Tenant, TenantVerifiedDomain
from tests.integration.support import integration_test


@integration_test
class PublicSsoDiscoveryIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        self.domains = [f"a-{suffix}.example.com", f"b-{suffix}.example.com"]
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        async with AsyncSessionLocal() as db:
            tenants = [
                Tenant(slug=f"sso-public-a-{suffix}", display_name="SSO Public A"),
                Tenant(slug=f"sso-public-b-{suffix}", display_name="SSO Public B"),
            ]
            db.add_all(tenants)
            await db.flush()
            db.add_all(
                [
                    TenantVerifiedDomain(
                        tenant_id=tenant.id,
                        domain=domain,
                        verification_token_hash=str(index + 1) * 64,
                        status="verified",
                    )
                    for index, (tenant, domain) in enumerate(zip(tenants, self.domains))
                ]
            )
            repo = SsoProviderRepository(db)
            providers = []
            for index, tenant in enumerate(tenants):
                providers.append(
                    await repo.create(
                        name=f"public-{index}-{suffix}",
                        display_name=f"Public Provider {index}",
                        protocol="oidc",
                        config_plain={
                            "issuer_url": f"https://idp-{index}.example.test",
                            "client_id": f"client-{index}",
                            "client_secret": f"secret-{index}",
                        },
                        allowed_email_domains=[self.domains[index]],
                        force_for_domains=[self.domains[index]],
                        jit_policy="auto",
                        tenant_id=tenant.id,
                    )
                )
            await db.commit()
            self.tenant_ids = [tenant.id for tenant in tenants]
            self.provider_ids = [provider.id for provider in providers]
            self.provider_names = [provider.name for provider in providers]
        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(SsoProvider).where(SsoProvider.id.in_(self.provider_ids))
            )
            await db.execute(
                delete(TenantVerifiedDomain).where(
                    TenantVerifiedDomain.tenant_id.in_(self.tenant_ids)
                )
            )
            await db.execute(delete(Tenant).where(Tenant.id.in_(self.tenant_ids)))
            await db.commit()
        await engine.dispose()

    async def test_discovery_never_lists_across_verified_domains(self) -> None:
        undisclosed = await self.client.get("/api/v1/auth/sso/providers")
        self.assertEqual(undisclosed.status_code, 200, undisclosed.text)
        self.assertEqual(undisclosed.json()["providers"], [])

        tenant_a = await self.client.get(
            "/api/v1/auth/sso/providers",
            params={"email": f"person@{self.domains[0]}"},
        )
        self.assertEqual(tenant_a.status_code, 200, tenant_a.text)
        self.assertEqual(
            [row["name"] for row in tenant_a.json()["providers"]],
            [self.provider_names[0]],
        )
        self.assertNotIn(self.provider_names[1], tenant_a.text)

        guard = await self.client.get(
            "/api/v1/auth/login-guard",
            params={"email": f"person@{self.domains[0]}"},
        )
        self.assertEqual(guard.status_code, 200, guard.text)
        self.assertTrue(guard.json()["forced"])
        self.assertEqual(guard.json()["provider"]["name"], self.provider_names[0])
        self.assertNotIn(self.provider_names[1], guard.text)

        unknown = await self.client.get(
            "/api/v1/auth/sso/providers",
            params={"email": "person@unknown.example.com"},
        )
        self.assertEqual(unknown.status_code, 200, unknown.text)
        self.assertEqual(unknown.json()["providers"], [])
