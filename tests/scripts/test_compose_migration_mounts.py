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


if __name__ == "__main__":
    unittest.main()
