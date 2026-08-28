from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class DatabaseMetadataContractTests(unittest.TestCase):
    def test_migration_environment_loads_split_metadata_modules(self) -> None:
        environment_source = (ROOT / "alembic" / "env.py").read_text()

        self.assertIn(
            "import app.infrastructure.governance.models",
            environment_source,
        )
        self.assertIn("register_schema_contracts()", environment_source)

    def test_runtime_and_migration_models_share_one_metadata_registry(self) -> None:
        from app.infrastructure.database.base import Base as metadata_base
        from app.infrastructure.database.database import Base as runtime_base
        from app.infrastructure.database import models
        from app.infrastructure.governance import models as governance_models
        from app.infrastructure.database.schema_contracts import (
            register_schema_contracts,
        )

        self.assertIsNotNone(governance_models)
        register_schema_contracts()

        self.assertIs(runtime_base, metadata_base)
        self.assertIs(models.User.metadata, metadata_base.metadata)
        self.assertIs(models.Scan.metadata, metadata_base.metadata)
        self.assertIn("scan_outbox", metadata_base.metadata.tables)
        self.assertIn("governance_operations", metadata_base.metadata.tables)
        self.assertIn("offline_bundle_deployments", metadata_base.metadata.tables)
        index_names = {
            index.name
            for table in metadata_base.metadata.tables.values()
            for index in table.indexes
        }
        constraint_names = {
            constraint.name
            for table in metadata_base.metadata.tables.values()
            for constraint in table.constraints
        }
        self.assertTrue(
            {
                "uq_approval_gates_one_active_per_scan",
                "ix_auth_audit_events_ts_desc",
                "ix_semgrep_rules_languages_gin",
                "uq_rule_foundry_active_deployment",
                "ix_scan_outbox_unpublished",
            }.issubset(index_names)
        )
        self.assertTrue(
            {
                "ck_integration_outbox_attempts",
                "ck_scan_events_activity_kind",
                "ck_scans_source_type",
                "ck_usage_budget_policies_caps_nonnegative",
            }.issubset(constraint_names)
        )


if __name__ == "__main__":
    unittest.main()
