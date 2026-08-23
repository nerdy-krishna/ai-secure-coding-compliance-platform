"""Public HTTP integration contract for tenant-scoped scan visibility."""

from __future__ import annotations

import os
import unittest
from uuid import uuid4

import httpx
from fastapi_users.password import PasswordHelper
from sqlalchemy import delete

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    Project,
    RoleAssignment,
    Scan,
    Tenant,
    User,
    UserGroup,
    UserGroupMembership,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.shared.lib.scan_status import STATUS_COMPLETED
from app.shared.lib.permissions import ANALYST, PLATFORM_OWNER
from tests.integration.support import integration_test


@integration_test
class PublicTenantVisibilityIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.base_url = os.getenv(
            "SCCAP_INTEGRATION_BASE_URL", "http://127.0.0.1:8000"
        ).rstrip("/")
        self.password = f"A7!{uuid4()}z"
        password_hash = PasswordHelper().hash(self.password)
        suffix = uuid4().hex

        async with AsyncSessionLocal() as db:
            owner_tenant = Tenant(
                slug=f"integration-owner-{suffix}",
                display_name=f"Integration owner {suffix}",
            )
            foreign_tenant = Tenant(
                slug=f"integration-foreign-{suffix}",
                display_name=f"Integration foreign {suffix}",
            )
            db.add_all([owner_tenant, foreign_tenant])
            await db.flush()

            owner = User(
                email=f"integration-owner-{suffix}@example.com",
                hashed_password=password_hash,
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=owner_tenant.id,
            )
            foreign_user = User(
                email=f"integration-foreign-{suffix}@example.com",
                hashed_password=password_hash,
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=foreign_tenant.id,
            )
            superuser = User(
                email=f"integration-superuser-{suffix}@example.com",
                hashed_password=password_hash,
                is_active=True,
                is_superuser=True,
                is_verified=True,
                tenant_id=foreign_tenant.id,
            )
            db.add_all([owner, foreign_user, superuser])
            await db.flush()
            db.add_all(
                [
                    RoleAssignment(
                        user_id=owner.id,
                        tenant_id=owner_tenant.id,
                        role_key=ANALYST,
                    ),
                    RoleAssignment(
                        user_id=foreign_user.id,
                        tenant_id=foreign_tenant.id,
                        role_key=ANALYST,
                    ),
                    RoleAssignment(
                        user_id=superuser.id,
                        tenant_id=None,
                        role_key=PLATFORM_OWNER,
                    ),
                ]
            )

            # Deliberately put the two regular users in one group. This makes
            # the owner visible through the legacy group scope and proves the
            # tenant boundary remains the decisive authorization check.
            group = UserGroup(
                name=f"integration-cross-tenant-{suffix}",
                description="Cross-tenant visibility regression fixture",
                created_by=foreign_user.id,
                tenant_id=foreign_tenant.id,
            )
            db.add(group)
            await db.flush()
            db.add_all(
                [
                    UserGroupMembership(group_id=group.id, user_id=owner.id),
                    UserGroupMembership(group_id=group.id, user_id=foreign_user.id),
                ]
            )

            project = Project(
                user_id=owner.id,
                tenant_id=owner_tenant.id,
                name=f"integration-tenant-project-{suffix}",
            )
            scan = Scan(
                project=project,
                user_id=owner.id,
                tenant_id=owner_tenant.id,
                scan_type="AUDIT",
                status=STATUS_COMPLETED,
                frameworks=[],
                summary={},
            )
            db.add_all([project, scan])
            await db.commit()

            self.owner_email = owner.email
            self.foreign_email = foreign_user.email
            self.superuser_email = superuser.email
            self.user_ids = [owner.id, foreign_user.id, superuser.id]
            self.tenant_ids = [owner_tenant.id, foreign_tenant.id]
            self.group_id = group.id
            self.project_id = project.id
            self.scan_id = scan.id

        self.client = httpx.AsyncClient(base_url=self.base_url, timeout=15.0)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(UserGroupMembership).where(
                    UserGroupMembership.group_id == self.group_id
                )
            )
            await db.execute(delete(UserGroup).where(UserGroup.id == self.group_id))
            await db.execute(
                delete(RoleAssignment).where(RoleAssignment.user_id.in_(self.user_ids))
            )
            await db.commit()
            await ScanRepository(db).delete_project(self.project_id)
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(delete(Tenant).where(Tenant.id.in_(self.tenant_ids)))
            await db.commit()
        await engine.dispose()

    async def _authorization(self, email: str) -> dict[str, str]:
        response = await self.client.post(
            "/api/v1/auth/login",
            data={"username": email, "password": self.password},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return {"Authorization": f"Bearer {response.json()['access_token']}"}

    async def test_result_is_tenant_scoped_without_superuser_bypass(self) -> None:
        endpoint = f"/api/v1/scans/{self.scan_id}/result"

        owner = await self.client.get(
            endpoint, headers=await self._authorization(self.owner_email)
        )
        self.assertEqual(owner.status_code, 200, owner.text)

        foreign = await self.client.get(
            endpoint, headers=await self._authorization(self.foreign_email)
        )
        self.assertEqual(foreign.status_code, 404, foreign.text)

        superuser = await self.client.get(
            endpoint, headers=await self._authorization(self.superuser_email)
        )
        self.assertEqual(superuser.status_code, 404, superuser.text)


if __name__ == "__main__":
    unittest.main()
