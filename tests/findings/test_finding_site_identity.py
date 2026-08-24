from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from uuid import uuid4

from app.shared.lib.finding_governance import finding_site_identity


class FindingSiteIdentityTests(unittest.TestCase):
    def test_migration_backfill_matches_runtime_retry_identity(self) -> None:
        migration_path = (
            Path(__file__).resolve().parents[2]
            / "alembic/versions/2026_08_24_1200_preserve_finding_lineage_sites.py"
        )
        spec = importlib.util.spec_from_file_location(
            "task33_lineage_site_migration", migration_path
        )
        assert spec is not None and spec.loader is not None
        migration = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(migration)

        canonical_id = uuid4()
        raw_id = uuid4()
        ranges = [
            {
                "file_path": "src/app.py",
                "line_number": 30,
                "snippet": "danger(value)",
                "primary": True,
                "start_line": 30,
                "end_line": 30,
                "start_column": 1,
                "end_column": 14,
            }
        ]
        backfilled = migration._site_identity(
            canonical_finding_id=str(canonical_id),
            raw_finding_id=str(raw_id),
            exact_ranges=ranges,
            fallback_identity=None,
        )
        retried = finding_site_identity(
            canonical_finding_id=canonical_id,
            raw_finding_id=raw_id,
            exact_site_ranges=ranges,
        )
        self.assertEqual(backfilled, retried)

    def test_exact_site_not_database_row_id_controls_identity(self) -> None:
        ranges = [{"file_path": "src/app.py", "start_line": 3, "end_line": 3}]
        first = finding_site_identity(
            exact_site_ranges=ranges,
            fallback_identity=101,
        )
        recreated = finding_site_identity(
            exact_site_ranges=ranges,
            fallback_identity=202,
        )
        second_site = finding_site_identity(
            exact_site_ranges=[
                {"file_path": "src/app.py", "start_line": 30, "end_line": 30}
            ],
            fallback_identity=101,
        )
        self.assertEqual(first, recreated)
        self.assertNotEqual(first, second_site)


if __name__ == "__main__":
    unittest.main()
