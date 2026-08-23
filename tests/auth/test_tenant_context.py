import unittest
from uuid import uuid4

from app.infrastructure.database.tenant_context import (
    bind_principal,
    effective_tenant_id,
    principal_id_var,
    principal_kind_var,
    reset_principal,
    system_scope_var,
    tenant_id_var,
)


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
