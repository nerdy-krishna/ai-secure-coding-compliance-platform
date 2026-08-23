import unittest
from uuid import uuid4

from app.infrastructure.database.tenant_context import (
    bind_principal,
    effective_tenant_id,
    principal_id_var,
    principal_kind_var,
    principal_scope,
    reset_principal,
    system_scope_var,
    tenant_id_var,
)
from app.infrastructure.database.role_posture import DatabaseRolePosture


class TenantContextTests(unittest.TestCase):
    def test_legacy_null_is_confined_to_seeded_default_tenant(self) -> None:
        self.assertEqual(
            str(effective_tenant_id(None)),
            "00000000-0000-0000-0000-000000000001",
        )

    def test_human_binding_requires_and_restores_explicit_tenant(self) -> None:
        tenant_id = uuid4()
        binding = bind_principal(
            tenant_id=tenant_id,
            principal_kind="human",
            principal_id="42",
        )
        self.assertEqual(tenant_id_var.get(), tenant_id)
        self.assertEqual(principal_kind_var.get(), "human")
        self.assertEqual(principal_id_var.get(), "42")
        self.assertFalse(system_scope_var.get())
        reset_principal(binding)
        self.assertIsNone(tenant_id_var.get())
        self.assertEqual(principal_kind_var.get(), "anonymous")

    def test_role_posture_rejects_owner_bypass_and_superuser(self) -> None:
        safe = DatabaseRolePosture(
            current_user="sccap_app",
            session_user="sccap_app",
            current_superuser=False,
            current_bypassrls=False,
            session_superuser=False,
            session_bypassrls=False,
            owns_forced_rls_table=False,
        )
        self.assertEqual(safe.unsafe_reasons(), ())
        unsafe = DatabaseRolePosture(
            current_user="postgres",
            session_user="postgres",
            current_superuser=True,
            current_bypassrls=True,
            session_superuser=True,
            session_bypassrls=True,
            owns_forced_rls_table=True,
        )
        self.assertEqual(
            unsafe.unsafe_reasons(),
            ("superuser", "bypassrls", "owns_forced_rls_table"),
        )

    def test_only_system_principal_can_receive_system_scope(self) -> None:
        with self.assertRaises(ValueError):
            bind_principal(
                tenant_id=uuid4(),
                principal_kind="human",
                principal_id="42",
                system_scope=True,
            )
        with self.assertRaises(ValueError):
            bind_principal(
                tenant_id=None,
                principal_kind="service_principal",
                principal_id="svc",
            )

        binding = bind_principal(
            tenant_id=None,
            principal_kind="system",
            principal_id="outbox-dispatcher",
            system_scope=True,
        )
        self.assertTrue(system_scope_var.get())
        reset_principal(binding)

    def test_principal_scope_restores_context_after_exception(self) -> None:
        tenant_id = uuid4()
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with principal_scope(
                tenant_id=tenant_id,
                principal_kind="service_principal",
                principal_id="scan-worker",
            ):
                self.assertEqual(tenant_id_var.get(), tenant_id)
                raise RuntimeError("stop")
        self.assertIsNone(tenant_id_var.get())
        self.assertEqual(principal_kind_var.get(), "anonymous")
