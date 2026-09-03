"""Compose services that migrate must see the same live revision tree."""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]


class ComposeMigrationMountTests(unittest.TestCase):
    def test_api_and_worker_mount_live_alembic_revisions(self) -> None:
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())

        for service_name in ("app", "worker"):
            volumes = compose["services"][service_name]["volumes"]
            self.assertTrue(
                any(
                    str(volume).startswith("./alembic:/app/alembic")
                    for volume in volumes
                ),
                f"{service_name} does not mount live Alembic revisions",
            )
            self.assertTrue(
                any(
                    str(volume).startswith("./alembic.ini:/app/alembic.ini")
                    for volume in volumes
                ),
                f"{service_name} does not mount live alembic.ini",
            )

    def test_api_is_the_only_migration_owner_and_workers_wait(self) -> None:
        dockerfile = (ROOT / "Dockerfile").read_text()
        entrypoint = (ROOT / "docker" / "app-entrypoint.sh").read_text()

        self.assertIn("SCCAP_MIGRATION_ROLE=wait", dockerfile)
        self.assertIn('case "${SCCAP_MIGRATION_ROLE', entrypoint)
        self.assertIn("alembic current --check-heads", entrypoint)
        self.assertEqual(entrypoint.count("alembic upgrade head"), 1)
        compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
        self.assertIn(
            "SCCAP_MIGRATION_ROLE=owner",
            compose["services"]["app"]["environment"],
        )

    def test_local_report_worker_inherits_wait_only_migration_role(self) -> None:
        compose = yaml.safe_load(
            (ROOT / "docker-compose.pentesting-local.yml").read_text()
        )
        report_worker = compose["services"]["pentest-report-worker"]
        self.assertEqual(report_worker["build"]["target"], "worker")
        environment = report_worker.get("environment", {})
        self.assertNotEqual(environment.get("SCCAP_MIGRATION_ROLE"), "owner")


if __name__ == "__main__":
    unittest.main()
