from __future__ import annotations

import unittest


class DatabaseMetadataContractTests(unittest.TestCase):
    def test_runtime_and_migration_models_share_one_metadata_registry(self) -> None:
        from app.infrastructure.database.base import Base as metadata_base
        from app.infrastructure.database.database import Base as runtime_base
        from app.infrastructure.database import models

        self.assertIs(runtime_base, metadata_base)
        self.assertIs(models.User.metadata, metadata_base.metadata)
        self.assertIs(models.Scan.metadata, metadata_base.metadata)
        self.assertIn("scan_outbox", metadata_base.metadata.tables)


if __name__ == "__main__":
    unittest.main()
