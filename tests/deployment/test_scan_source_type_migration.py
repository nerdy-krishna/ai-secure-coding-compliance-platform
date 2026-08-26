"""Regression contract for pasted-code scan source-type schema support."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest.mock import patch


MIGRATION_PATH = (
    Path(__file__).resolve().parents[2]
    / "alembic"
    / "versions"
    / "2026_08_26_2210_allow_paste_scan_source_type.py"
)


class ScanSourceTypeMigrationTests(unittest.TestCase):
    def test_upgrade_replaces_the_constraint_with_paste_support(self) -> None:
        spec = importlib.util.spec_from_file_location(
            "allow_paste_scan_source_type", MIGRATION_PATH
        )
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        migration = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(migration)

        with (
            patch.object(migration.op, "drop_constraint") as drop_constraint,
            patch.object(migration.op, "create_check_constraint") as create_constraint,
        ):
            migration.upgrade()

        drop_constraint.assert_called_once_with(
            "ck_scans_source_type", "scans", type_="check"
        )
        create_constraint.assert_called_once_with(
            "ck_scans_source_type",
            "scans",
            "source_type IS NULL OR source_type IN ('upload', 'archive', 'git', 'paste')",
        )
