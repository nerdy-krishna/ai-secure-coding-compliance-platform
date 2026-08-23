"""Real-PostgreSQL contracts for Task 17's authorization foundation."""

from __future__ import annotations

import asyncio
import unittest
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from fastapi_users.password import PasswordHelper
import sqlalchemy as sa
from sqlalchemy import delete, select, text, update
from sqlalchemy.exc import DBAPIError

from app.config.config import settings
from app.infrastructure.database.database import AsyncSessionLocal, engine
from app.infrastructure.database.models import (
    AuthorizationActionRequest,
    AuthorizationAuditEvent,
    Finding,
    Project,
    RoleAssignment,
    Scan,
    ScanEvent,
    ScanOutbox,
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
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.role_posture import inspect_database_role_posture
from app.infrastructure.database.tenant_context import bind_principal, reset_principal
from app.infrastructure.messaging.worker_identity import resolve_trusted_scan_delivery
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

    async def test_tenant_context_is_reapplied_after_commit(self) -> None:
        binding = bind_principal(
            tenant_id=self.tenant_id,
            principal_kind="human",
            principal_id=str(self.requester_id),
        )
        try:
            async with AsyncSessionLocal() as db:
                first = (
                    await db.execute(
                        text(
                            "SELECT current_setting('app.tenant_id'), "
                            "current_setting('app.principal_kind'), "
                            "current_setting('app.principal_id'), "
                            "current_setting('app.system_scope')"
                        )
                    )
                ).one()
                await db.commit()
                second = (
                    await db.execute(
                        text(
                            "SELECT current_setting('app.tenant_id'), "
                            "current_setting('app.principal_kind'), "
                            "current_setting('app.principal_id'), "
                            "current_setting('app.system_scope')"
                        )
                    )
                ).one()
            expected = (
                str(self.tenant_id),
                "human",
                str(self.requester_id),
                "off",
            )
            self.assertEqual(tuple(first), expected)
            self.assertEqual(tuple(second), expected)
        finally:
            reset_principal(binding)

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


@integration_test
class TenantRlsIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        suffix = uuid4().hex[:12]
        async with AsyncSessionLocal() as db:
            tenant_a = Tenant(slug=f"rls-a-{suffix}", display_name="RLS Tenant A")
            tenant_b = Tenant(slug=f"rls-b-{suffix}", display_name="RLS Tenant B")
            db.add_all([tenant_a, tenant_b])
            await db.flush()
            user_a = User(
                email=f"rls-a-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(f"A7!{uuid4()}z"),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant_a.id,
            )
            user_b = User(
                email=f"rls-b-{suffix}@example.com",
                hashed_password=PasswordHelper().hash(f"A7!{uuid4()}z"),
                is_active=True,
                is_superuser=False,
                is_verified=True,
                tenant_id=tenant_b.id,
            )
            db.add_all([user_a, user_b])
            await db.flush()
            project_a = Project(
                user_id=user_a.id,
                tenant_id=tenant_a.id,
                name=f"rls-project-a-{suffix}",
            )
            project_b = Project(
                user_id=user_b.id,
                tenant_id=tenant_b.id,
                name=f"rls-project-b-{suffix}",
            )
            db.add_all([project_a, project_b])
            await db.flush()
            scan_a = Scan(
                project_id=project_a.id,
                user_id=user_a.id,
                tenant_id=tenant_a.id,
                scan_type="AUDIT",
                status="QUEUED",
            )
            scan_b = Scan(
                project_id=project_b.id,
                user_id=user_b.id,
                tenant_id=tenant_b.id,
                scan_type="AUDIT",
                status="QUEUED",
            )
            db.add_all([scan_a, scan_b])
            await db.flush()
            db.add_all(
                [
                    ScanEvent(
                        scan_id=scan_a.id,
                        stage_name="RLS_TEST",
                        status="STARTED",
                    ),
                    ScanEvent(
                        scan_id=scan_b.id,
                        stage_name="RLS_TEST",
                        status="STARTED",
                    ),
                ]
            )
            outbox = await ScanOutboxRepository(db).enqueue(
                scan_id=scan_a.id,
                queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
                payload={
                    "scan_id": str(scan_a.id),
                    "correlation_id": f"rls-test-{suffix}",
                },
                commit=False,
            )
            await db.commit()
            self.tenant_a_id = tenant_a.id
            self.tenant_b_id = tenant_b.id
            self.user_a_id = user_a.id
            self.user_b_id = user_b.id
            self.project_a_id = project_a.id
            self.project_b_id = project_b.id
            self.scan_a_id = scan_a.id
            self.scan_b_id = scan_b.id
            self.outbox_id = outbox.id
            self.delivery_body = dict(outbox.payload)
            self.delivery_body.pop("correlation_id", None)

    async def asyncTearDown(self) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(
                delete(ScanEvent).where(
                    ScanEvent.scan_id.in_([self.scan_a_id, self.scan_b_id])
                )
            )
            await db.execute(
                delete(Finding).where(
                    Finding.scan_id.in_([self.scan_a_id, self.scan_b_id])
                )
            )
            await db.execute(
                delete(Scan).where(Scan.id.in_([self.scan_a_id, self.scan_b_id]))
            )
            await db.execute(
                delete(Project).where(
                    Project.id.in_([self.project_a_id, self.project_b_id])
                )
            )
            await db.execute(
                delete(User).where(User.id.in_([self.user_a_id, self.user_b_id]))
            )
            await db.execute(
                delete(Tenant).where(
                    Tenant.id.in_([self.tenant_a_id, self.tenant_b_id])
                )
            )
            await db.commit()
        await engine.dispose()

    async def test_nonowner_runtime_role_filters_parent_and_child_rows(self) -> None:
        binding = bind_principal(
            tenant_id=self.tenant_a_id,
            principal_kind="human",
            principal_id=str(self.user_a_id),
        )
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(text("SET LOCAL ROLE sccap_runtime"))
                scans = list((await db.scalars(select(Scan))).all())
                events = list((await db.scalars(select(ScanEvent))).all())
            self.assertEqual([row.id for row in scans], [self.scan_a_id])
            self.assertEqual([row.scan_id for row in events], [self.scan_a_id])
        finally:
            reset_principal(binding)

    async def test_runtime_role_rejects_cross_tenant_write_and_parent_reference(self) -> None:
        binding = bind_principal(
            tenant_id=self.tenant_a_id,
            principal_kind="human",
            principal_id=str(self.user_a_id),
        )
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(text("SET LOCAL ROLE sccap_runtime"))
                with self.assertRaises(DBAPIError):
                    await db.execute(
                        sa.insert(Project).values(
                            id=uuid4(),
                            user_id=self.user_a_id,
                            tenant_id=self.tenant_b_id,
                            name=f"cross-tenant-{uuid4()}",
                        )
                    )
                await db.rollback()

            async with AsyncSessionLocal() as db:
                await db.execute(text("SET LOCAL ROLE sccap_runtime"))
                with self.assertRaises(DBAPIError):
                    await db.execute(
                        sa.insert(Finding).values(
                            scan_id=self.scan_b_id,
                            tenant_id=self.tenant_a_id,
                            file_path="private.py",
                            title="Cross-tenant reference",
                            description="must fail",
                            remediation="must fail",
                            severity="High",
                            confidence="High",
                            finding_bucket="consolidated",
                        )
                    )
                await db.rollback()
        finally:
            reset_principal(binding)

    async def test_explicit_system_scope_can_dispatch_across_tenants(self) -> None:
        binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="integration-dispatcher",
            system_scope=True,
        )
        try:
            async with AsyncSessionLocal() as db:
                await db.execute(text("SET LOCAL ROLE sccap_runtime"))
                scan_ids = set((await db.scalars(select(Scan.id))).all())
            self.assertTrue({self.scan_a_id, self.scan_b_id}.issubset(scan_ids))
        finally:
            reset_principal(binding)

    async def test_runtime_role_is_nobypassrls_and_not_table_owner(self) -> None:
        async with AsyncSessionLocal() as db:
            row = (
                await db.execute(
                    text(
                        "SELECT r.rolsuper, r.rolbypassrls, "
                        "pg_get_userbyid(c.relowner) = 'sccap_runtime' "
                        "FROM pg_roles r CROSS JOIN pg_class c "
                        "WHERE r.rolname = 'sccap_runtime' "
                        "AND c.oid = 'scans'::regclass"
                    )
                )
            ).one()
        self.assertEqual(tuple(row), (False, False, False))

    async def test_worker_delivery_resolves_only_exact_durable_outbox_payload(
        self,
    ) -> None:
        trusted = await resolve_trusted_scan_delivery(
            scan_id=self.scan_a_id,
            queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
            body=self.delivery_body,
        )
        self.assertIsNotNone(trusted)
        self.assertEqual(trusted.tenant_id, self.tenant_a_id)
        self.assertEqual(trusted.outbox_id, self.outbox_id)
        self.assertFalse(trusted.legacy_payload)

        forged_tenant = dict(self.delivery_body)
        forged_tenant["tenant_id"] = str(self.tenant_b_id)
        self.assertIsNone(
            await resolve_trusted_scan_delivery(
                scan_id=self.scan_a_id,
                queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
                body=forged_tenant,
            )
        )
        self.assertIsNone(
            await resolve_trusted_scan_delivery(
                scan_id=self.scan_b_id,
                queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
                body=self.delivery_body,
            )
        )

    async def test_worker_delivery_supports_exact_legacy_payload_during_rollout(
        self,
    ) -> None:
        legacy_payload = {
            "scan_id": str(self.scan_a_id),
            "action": "legacy-rollout-test",
        }
        async with AsyncSessionLocal() as db:
            row = ScanOutbox(
                scan_id=self.scan_a_id,
                queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
                payload=legacy_payload,
            )
            db.add(row)
            await db.commit()
            legacy_outbox_id = row.id

        trusted = await resolve_trusted_scan_delivery(
            scan_id=self.scan_a_id,
            queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
            body=legacy_payload,
        )
        self.assertIsNotNone(trusted)
        self.assertEqual(trusted.tenant_id, self.tenant_a_id)
        self.assertEqual(trusted.outbox_id, legacy_outbox_id)
        self.assertTrue(trusted.legacy_payload)

    async def test_role_posture_inspection_distinguishes_active_and_login_roles(
        self,
    ) -> None:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SET LOCAL ROLE sccap_runtime"))
            posture = await inspect_database_role_posture(db)

        self.assertEqual(posture.current_user, "sccap_runtime")
        self.assertFalse(posture.current_superuser)
        self.assertFalse(posture.current_bypassrls)
        self.assertEqual(posture.session_user, "postgres")
        self.assertTrue(posture.session_superuser)
        self.assertTrue(posture.session_bypassrls)
        self.assertFalse(posture.owns_forced_rls_table)
