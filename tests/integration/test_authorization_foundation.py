"""Real-PostgreSQL contracts for Task 17's authorization foundation."""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi_users.password import PasswordHelper
from sqlalchemy import delete, update
from sqlalchemy.exc import DBAPIError

from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    AuthorizationActionRequest,
    AuthorizationAuditEvent,
    RoleAssignment,
    Tenant,
    User,
)
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationConflictError,
    AuthorizationDeniedError,
    AuthorizationRepository,
    payload_digest,
    target_fingerprint,
)
from app.shared.lib.permissions import (
    ANALYST,
    PLATFORM_OWNER,
    SECURITY_APPROVER,
    WAIVER_APPROVE,
    WAIVER_REQUEST,
)
from tests.integration.support import integration_test


@integration_test
class AuthorizationFoundationIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        async with AsyncSessionLocal() as db:
            tenant = Tenant(slug=f"authz-{suffix}", display_name="Authorization Test")
            db.add(tenant)
            await db.flush()
            users = [
                User(
                    email=f"authz-{kind}-{suffix}@example.com",
                    hashed_password=PasswordHelper().hash(f"A7!{uuid4()}z"),
                    is_active=True,
                    is_superuser=(kind == "platform"),
                    is_verified=True,
                    tenant_id=tenant.id,
                )
                for kind in ("requester", "approver-a", "approver-b", "platform")
            ]
            db.add_all(users)
            await db.flush()
            requester, approver_a, approver_b, platform = users
            db.add_all(
                [
                    RoleAssignment(
                        user_id=requester.id,
                        tenant_id=tenant.id,
                        role_key=ANALYST,
                    ),
                    RoleAssignment(
                        user_id=approver_a.id,
                        tenant_id=tenant.id,
                        role_key=SECURITY_APPROVER,
                    ),
                    RoleAssignment(
                        user_id=approver_b.id,
                        tenant_id=tenant.id,
                        role_key=SECURITY_APPROVER,
                    ),
                    RoleAssignment(
                        user_id=platform.id,
                        tenant_id=None,
                        role_key=PLATFORM_OWNER,
                    ),
                ]
            )
            await db.commit()
            self.tenant_id = tenant.id
            self.user_ids = [user.id for user in users]
            self.requester_id = requester.id
            self.approver_a_id = approver_a.id
            self.approver_b_id = approver_b.id
            self.platform_id = platform.id

    async def asyncTearDown(self) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(AuthorizationActionRequest).where(
                    AuthorizationActionRequest.tenant_id == self.tenant_id
                )
            )
            await db.execute(
                delete(RoleAssignment).where(
                    RoleAssignment.user_id.in_(self.user_ids)
                )
            )
            await db.execute(delete(User).where(User.id.in_(self.user_ids)))
            await db.execute(delete(Tenant).where(Tenant.id == self.tenant_id))
            await db.commit()
        await engine.dispose()

    async def _create_request(self, idempotency_key: str) -> tuple:
        payload = {"finding_id": "private-target", "expires": "2026-09-01"}
        digest = payload_digest(payload)
        fingerprint = target_fingerprint(
            resource_type="finding_waiver", target_id="private-target"
        )
        async with AsyncSessionLocal() as db:
            row = await AuthorizationRepository(db).create_action_request(
                tenant_id=self.tenant_id,
                requester_user_id=self.requester_id,
                requester_permission=WAIVER_REQUEST,
                approver_permission=WAIVER_APPROVE,
                target_type="finding_waiver",
                target_fingerprint_value=fingerprint,
                payload_digest_value=digest,
                idempotency_key=idempotency_key,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            )
            await db.commit()
            return row.id, digest, fingerprint

    async def test_role_resolution_is_tenant_scoped_and_platform_is_explicit(self) -> None:
        async with AsyncSessionLocal() as db:
            requester = await db.get(User, self.requester_id)
            platform = await db.get(User, self.platform_id)
            repo = AuthorizationRepository(db)
            requester_permissions = await repo.permissions_for_user(
                user=requester, tenant_id=self.tenant_id
            )
            platform_permissions = await repo.permissions_for_user(
                user=platform, tenant_id=self.tenant_id
            )
        self.assertIn(WAIVER_REQUEST, requester_permissions)
        self.assertNotIn(WAIVER_APPROVE, requester_permissions)
        self.assertIn(WAIVER_APPROVE, platform_permissions)

    async def test_idempotency_is_bound_to_immutable_payload(self) -> None:
        key = f"waiver:{uuid4()}"
        request_id, digest, fingerprint = await self._create_request(key)
        async with AsyncSessionLocal() as db:
            same = await AuthorizationRepository(db).create_action_request(
                tenant_id=self.tenant_id,
                requester_user_id=self.requester_id,
                requester_permission=WAIVER_REQUEST,
                approver_permission=WAIVER_APPROVE,
                target_type="finding_waiver",
                target_fingerprint_value=fingerprint,
                payload_digest_value=digest,
                idempotency_key=key,
                expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
            )
            self.assertEqual(same.id, request_id)
            with self.assertRaises(AuthorizationConflictError):
                await AuthorizationRepository(db).create_action_request(
                    tenant_id=self.tenant_id,
                    requester_user_id=self.requester_id,
                    requester_permission=WAIVER_REQUEST,
                    approver_permission=WAIVER_APPROVE,
                    target_type="finding_waiver",
                    target_fingerprint_value=fingerprint,
                    payload_digest_value="0" * 64,
                    idempotency_key=key,
                    expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
                )

    async def test_distinct_actor_and_concurrent_decision_have_one_winner(self) -> None:
        request_id, _digest, _fingerprint = await self._create_request(
            f"waiver:{uuid4()}"
        )
        async with AsyncSessionLocal() as db:
            with self.assertRaises(AuthorizationDeniedError):
                await AuthorizationRepository(db).decide_action_request(
                    request_id=request_id,
                    tenant_id=self.tenant_id,
                    approver_user_id=self.requester_id,
                    approver_permissions={WAIVER_APPROVE},
                    requester_permissions={WAIVER_REQUEST},
                    approved=True,
                    reason="self approval must fail",
                )

        async def decide(approver_id: int) -> str:
            async with AsyncSessionLocal() as db:
                try:
                    await AuthorizationRepository(db).decide_action_request(
                        request_id=request_id,
                        tenant_id=self.tenant_id,
                        approver_user_id=approver_id,
                        approver_permissions={WAIVER_APPROVE},
                        requester_permissions={WAIVER_REQUEST},
                        approved=True,
                        reason="independent security review",
                    )
                    await db.commit()
                    return "approved"
                except AuthorizationConflictError:
                    await db.rollback()
                    return "conflict"

        outcomes = await asyncio.gather(
            decide(self.approver_a_id), decide(self.approver_b_id)
        )
        self.assertEqual(sorted(outcomes), ["approved", "conflict"])
        async with AsyncSessionLocal() as db:
            row = await db.get(AuthorizationActionRequest, request_id)
            self.assertEqual(row.status, "approved")
            self.assertIn(
                row.approver_user_id, {self.approver_a_id, self.approver_b_id}
            )

    async def test_execution_revalidates_permissions_and_exact_payload(self) -> None:
        request_id, digest, _fingerprint = await self._create_request(
            f"waiver:{uuid4()}"
        )
        async with AsyncSessionLocal() as db:
            repo = AuthorizationRepository(db)
            await repo.decide_action_request(
                request_id=request_id,
                tenant_id=self.tenant_id,
                approver_user_id=self.approver_a_id,
                approver_permissions={WAIVER_APPROVE},
                requester_permissions={WAIVER_REQUEST},
                approved=True,
                reason="reviewed",
            )
            await db.commit()
        async with AsyncSessionLocal() as db:
            with self.assertRaises(AuthorizationDeniedError):
                await AuthorizationRepository(db).mark_executed(
                    request_id=request_id,
                    tenant_id=self.tenant_id,
                    payload_digest_value="f" * 64,
                    requester_permissions={WAIVER_REQUEST},
                    approver_permissions={WAIVER_APPROVE},
                )
            row = await AuthorizationRepository(db).mark_executed(
                request_id=request_id,
                tenant_id=self.tenant_id,
                payload_digest_value=digest,
                requester_permissions={WAIVER_REQUEST},
                approver_permissions={WAIVER_APPROVE},
            )
            await db.commit()
            self.assertEqual(row.status, "executed")

    async def test_authorization_audit_is_append_only(self) -> None:
        async with AsyncSessionLocal() as db:
            repo = AuthorizationRepository(db)
            event = repo.record_audit(
                tenant_id=self.tenant_id,
                principal_kind="human",
                principal_id=str(self.requester_id),
                permission=WAIVER_REQUEST,
                resource_type="finding_waiver",
                target_fingerprint_value=target_fingerprint(
                    resource_type="finding_waiver", target_id="private-target"
                ),
                outcome="requested",
                reason_code="second_actor_required",
            )
            await db.flush()
            with self.assertRaises(DBAPIError):
                await db.execute(
                    update(AuthorizationAuditEvent)
                    .where(AuthorizationAuditEvent.id == event.id)
                    .values(outcome="allowed")
                )
            await db.rollback()
