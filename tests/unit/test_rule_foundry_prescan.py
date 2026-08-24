from __future__ import annotations

import unittest

from app.infrastructure.database.repositories.scanner_coverage_repo import (
    CoverageOutcome,
)
from app.infrastructure.workflows.nodes.prescan import _degrade_promoted_pack_coverage


class RuleFoundryPrescanCoverageTests(unittest.TestCase):
    def test_promoted_pack_failure_degrades_status_and_canonical_coverage(self) -> None:
        outcomes = [
            CoverageOutcome(
                scanner_name="semgrep",
                input_path="app.py",
                status="clean",
                provenance_status="verified",
            ),
            CoverageOutcome(
                scanner_name="gitleaks",
                input_path="app.py",
                status="clean",
                provenance_status="verified",
            ),
        ]
        statuses = {"semgrep": {"status": "completed", "finding_count": 0}}

        _degrade_promoted_pack_coverage(
            scanner_name="semgrep",
            input_paths={"app.py"},
            coverage_outcomes=outcomes,
            scanner_statuses=statuses,
            provenance_status="verified",
        )

        semgrep = next(row for row in outcomes if row.scanner_name == "semgrep")
        gitleaks = next(row for row in outcomes if row.scanner_name == "gitleaks")
        self.assertEqual(statuses["semgrep"]["status"], "degraded")
        self.assertEqual(statuses["semgrep"]["foundry_promoted_pack"], "failed")
        self.assertEqual(semgrep.status, "failed")
        self.assertEqual(semgrep.reason_code, "foundry_promoted_pack_failed")
        self.assertEqual(gitleaks.status, "clean")


if __name__ == "__main__":
    unittest.main()
