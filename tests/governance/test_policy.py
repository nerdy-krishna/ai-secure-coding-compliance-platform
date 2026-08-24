from __future__ import annotations

import unittest
import uuid
from types import SimpleNamespace

from app.infrastructure.governance.contracts import (
    RetentionActionResult,
    StoreActionResult,
)
from app.infrastructure.governance.retention import (
    DEFAULT_RETENTION_POLICY,
    validate_tenant_override,
)
from app.infrastructure.governance.service import normalize_scope
from app.infrastructure.governance.service import GovernanceService


class GovernancePolicyTests(unittest.TestCase):
    def test_approved_retention_snapshot(self) -> None:
        self.assertEqual(
            DEFAULT_RETENTION_POLICY.snapshot(),
            {
                "transactional_days": 365,
                "audit_days": 365,
                "evidence_days": 365,
                "llm_days": 30,
                "vector_days": 365,
                "logs_days": 30,
                "backups_days": 35,
                "version": "task22-approved-v1",
            },
        )

    def test_scope_is_uuid_bound_and_tenant_exact(self) -> None:
        tenant = uuid.uuid4()
        self.assertEqual(
            normalize_scope("tenant", str(tenant), tenant),
            {"scope_type": "tenant", "scope_id": str(tenant)},
        )
        with self.assertRaises(ValueError):
            normalize_scope("tenant", str(uuid.uuid4()), tenant)
        with self.assertRaises(ValueError):
            normalize_scope("scan", "*", tenant)
        scan_id = uuid.uuid4()
        self.assertEqual(
            normalize_scope("scan", "{" + str(scan_id).upper() + "}", tenant)[
                "scope_id"
            ],
            str(scan_id),
        )

    def test_tenant_overrides_allow_privacy_shortening_but_protect_evidence(
        self,
    ) -> None:
        validate_tenant_override("llm", 7)
        validate_tenant_override("logs", 7)
        validate_tenant_override("evidence", 730)
        with self.assertRaisesRegex(ValueError, "cannot be shorter"):
            validate_tenant_override("evidence", 30)
        with self.assertRaisesRegex(ValueError, "fixed"):
            validate_tenant_override("transactional", 730)
        with self.assertRaisesRegex(ValueError, "fixed"):
            validate_tenant_override("audit", 730)

    def test_store_results_reject_extra_or_inconsistent_fields(self) -> None:
        operation_id = uuid.uuid4()
        result = {
            "schema_version": 1,
            "store": "postgres",
            "kind": "delete",
            "operation_id": operation_id,
            "matched_count": 2,
            "applied_count": 3,
            "content_sha256": "a" * 64,
            "artifact_ref": "governance/result.json",
        }
        with self.assertRaises(ValueError):
            StoreActionResult.model_validate(result)
        result["applied_count"] = 2
        result["plaintext"] = "must-not-persist"
        with self.assertRaises(ValueError):
            StoreActionResult.model_validate(result)
        backup = dict(result)
        backup.pop("plaintext")
        backup["store"] = "backups"
        self.assertEqual(
            RetentionActionResult.model_validate(backup).store,
            "backups",
        )


class _PolicyRows:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class _PolicyDb:
    async def scalars(self, _statement):
        return _PolicyRows(
            [
                SimpleNamespace(data_class="llm", retention_days=7),
                SimpleNamespace(data_class="evidence", retention_days=730),
            ]
        )


class EffectivePolicyTests(unittest.IsolatedAsyncioTestCase):
    async def test_operation_snapshot_contains_effective_tenant_overrides(self) -> None:
        service = object.__new__(GovernanceService)
        service.db = _PolicyDb()
        service.retention = DEFAULT_RETENTION_POLICY
        snapshot = await service._effective_retention_snapshot(uuid.uuid4())
        self.assertEqual(snapshot["llm_days"], 7)
        self.assertEqual(snapshot["evidence_days"], 730)
        self.assertEqual(snapshot["tenant_overrides"], {"llm": 7, "evidence": 730})
