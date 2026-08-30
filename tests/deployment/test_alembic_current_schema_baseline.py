from __future__ import annotations

import importlib.util
import inspect
import re
import unittest
from hashlib import sha256
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

ROOT = Path(__file__).resolve().parents[2]
MIGRATION_PATH = (
    ROOT / "alembic" / "current_versions" / "2026_08_28_0000_current_schema_baseline.py"
)
BASELINE_PATH = ROOT / "alembic" / "baselines" / "2026_08_28_current_schema.sql"
BASELINE_ROOT = "4d5e6f708192"
FOUNDATION1_HEAD = "92a3b4c5d6e7"
CURRENT_HEAD = "d6e7f8091a2b"
PENTEST_REFERENCE_MIGRATION_PATH = (
    ROOT
    / "alembic"
    / "current_versions"
    / "2026_08_30_0500_harden_pentest_reference_integrity.py"
)
ACTIVE_CHAIN = (
    ("d6e7f8091a2b", "c5d6e7f8091a"),
    ("c5d6e7f8091a", "b4c5d6e7f809"),
    ("b4c5d6e7f809", "a3b4c5d6e7f8"),
    ("a3b4c5d6e7f8", FOUNDATION1_HEAD),
    ("92a3b4c5d6e7", "8192a3b4c5d6"),
    ("8192a3b4c5d6", "708192a3b4c5"),
    ("708192a3b4c5", "6f708192a3b4"),
    ("6f708192a3b4", "5e6f7081a2b3"),
    ("5e6f7081a2b3", BASELINE_ROOT),
    (BASELINE_ROOT, None),
)


def _load_migration():
    spec = importlib.util.spec_from_file_location(
        "sccap_current_baseline", MIGRATION_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _load_pentest_reference_migration():
    spec = importlib.util.spec_from_file_location(
        "sccap_pentest_reference_integrity", PENTEST_REFERENCE_MIGRATION_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AlembicCurrentSchemaBaselineTests(unittest.TestCase):
    def test_active_tree_preserves_the_baseline_root_identity(self) -> None:
        config = Config(str(ROOT / "alembic.ini"))
        script = ScriptDirectory.from_config(config)
        revisions = list(script.walk_revisions())

        self.assertEqual(script.get_heads(), [CURRENT_HEAD])
        self.assertEqual(
            tuple(
                (revision.revision, revision.down_revision) for revision in revisions
            ),
            ACTIVE_CHAIN,
        )

    def test_legacy_revisions_are_retained_but_not_active(self) -> None:
        legacy_revisions = list((ROOT / "alembic" / "versions").glob("*.py"))
        self.assertGreaterEqual(len(legacy_revisions), 122)
        self.assertNotIn(
            str(ROOT / "alembic" / "versions"),
            Config(str(ROOT / "alembic.ini")).get_main_option("version_locations"),
        )

    def test_frozen_snapshot_digest_and_postgres_statement_parser(self) -> None:
        module = _load_migration()
        payload = BASELINE_PATH.read_bytes()
        sql = payload.decode("utf-8")
        statements = list(module._iter_sql_statements(sql))

        self.assertEqual(sha256(payload).hexdigest(), module._BASELINE_SHA256)
        self.assertGreater(len(statements), 500)
        self.assertTrue(any("CREATE FUNCTION" in item for item in statements))
        self.assertTrue(any("RAISE EXCEPTION" in item for item in statements))
        self.assertFalse(any(item.rstrip().endswith("\\") for item in statements))

    def test_snapshot_preserves_schema_security_and_bootstrap_contracts(self) -> None:
        sql = BASELINE_PATH.read_text()

        self.assertEqual(
            len(re.findall(r"^CREATE TABLE public\.", sql, re.MULTILINE)), 95
        )
        self.assertEqual(
            len(re.findall(r"^CREATE FUNCTION public\.", sql, re.MULTILINE)), 12
        )
        self.assertEqual(len(re.findall(r"^CREATE TRIGGER ", sql, re.MULTILINE)), 121)
        self.assertEqual(len(re.findall(r"^CREATE POLICY ", sql, re.MULTILINE)), 70)
        self.assertEqual(
            len(re.findall(r" FORCE ROW LEVEL SECURITY;", sql, re.MULTILINE)), 70
        )
        self.assertEqual(
            len(re.findall(r" ENABLE ROW LEVEL SECURITY;", sql, re.MULTILINE)), 70
        )
        self.assertIn("CREATE ROLE sccap_runtime", sql)
        self.assertIn("GRANT USAGE ON SCHEMA public TO sccap_runtime", sql)
        self.assertTrue(sql.rstrip().endswith("SET search_path = public;"))
        self.assertIn("00000000-0000-0000-0000-000000000001", sql)
        self.assertIn("CREATE TABLE public.tenant_retention_policies", sql)
        self.assertIn("active_tenant_id uuid", sql)

    def test_snapshot_excludes_runtime_owned_or_sensitive_state(self) -> None:
        sql = BASELINE_PATH.read_text()
        for excluded_table in (
            "alembic_version",
            "checkpoints",
            "checkpoint_blobs",
            "checkpoint_writes",
            "checkpoint_migrations",
        ):
            self.assertNotIn(f"CREATE TABLE public.{excluded_table}", sql)
        self.assertNotIn("COPY public.", sql)
        self.assertNotIn('INSERT INTO public."user"', sql)
        self.assertNotRegex(
            sql, re.compile(r"^\\(?:restrict|unrestrict)", re.MULTILINE)
        )

    def test_pentest_reference_hardening_is_additive_and_n_minus_one_safe(
        self,
    ) -> None:
        migration = _load_pentest_reference_migration()
        upgrade_source = inspect.getsource(migration.upgrade).lower()

        self.assertEqual(migration.revision, FOUNDATION1_HEAD)
        self.assertEqual(migration.down_revision, "8192a3b4c5d6")
        self.assertIn("create or replace function", upgrade_source)
        self.assertNotIn("create table", upgrade_source)
        self.assertNotIn("drop table", upgrade_source)
        self.assertNotIn("alter table", upgrade_source)
        self.assertNotIn("add_column", upgrade_source)
        self.assertNotIn("drop_column", upgrade_source)


if __name__ == "__main__":
    unittest.main()
