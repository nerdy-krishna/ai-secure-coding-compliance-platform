"""Reports must carry degraded coverage even when there are no findings."""

from __future__ import annotations

import csv
import io
import json
import unittest
from uuid import uuid4

from app.api.v1.models import (
    AnalysisResultDetailResponse,
    ScannerCoverageEntryResponse,
    ScannerCoverageManifestResponse,
)
from app.core.services.report.csv_report import render_csv
from app.core.services.report.html_report import render_html
from app.core.services.report.sarif_report import render_sarif


class ScannerCoverageReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.result = AnalysisResultDetailResponse(
            status="COMPLETED",
            project_id=uuid4(),
            project_name="partial-coverage",
            scanner_coverage=ScannerCoverageManifestResponse(
                attempt_id=uuid4(),
                overall_status="degraded",
                is_complete=False,
                counts={"clean": 1, "timeout": 1},
                entries=[
                    ScannerCoverageEntryResponse(
                        id=uuid4(),
                        scanner_name="semgrep",
                        input_path="src/app.py",
                        status="timeout",
                        reason="Scanner timed out.",
                    )
                ],
            ),
        )

    def test_html_never_describes_degraded_zero_findings_as_clean(self) -> None:
        report = render_html(self.result)

        self.assertIn("Scanner coverage", report)
        self.assertIn("DEGRADED", report)
        self.assertIn("not a clean bill of health", report)

    def test_csv_and_sarif_carry_coverage_without_finding_rows(self) -> None:
        csv_rows = list(csv.DictReader(io.StringIO(render_csv(self.result))))
        self.assertTrue(csv_rows)
        self.assertTrue(all(row["record_type"] == "coverage" for row in csv_rows))
        self.assertEqual(csv_rows[0]["coverage_status"], "degraded")

        sarif = json.loads(render_sarif(self.result))
        coverage = sarif["runs"][0]["properties"]["sccapScannerCoverage"]
        self.assertEqual(coverage["overall_status"], "degraded")
        self.assertFalse(coverage["is_complete"])

    def test_governance_semantics_are_shared_by_html_csv_and_sarif(self) -> None:
        self.result.finding_governance = {
            "counts": {"new": 2, "fixed": 1, "unchanged": 3, "reintroduced": 1},
            "items": [],
            "policy_evaluation": {
                "outcome": "fail",
                "coverage_complete": False,
                "blocking_fingerprints": ["a" * 64],
                "waived_fingerprints": ["b" * 64],
            },
        }
        html = render_html(self.result)
        self.assertIn("Finding governance", html)
        self.assertIn("FAIL", html)
        self.assertIn("reintroduced: 1", html)

        csv_header = render_csv(self.result).splitlines()[0]
        self.assertIn("baseline_state", csv_header)
        self.assertIn("finding_fingerprint", csv_header)

        sarif = json.loads(render_sarif(self.result))
        governance = sarif["runs"][0]["properties"]["sccapFindingGovernance"]
        self.assertEqual(governance["counts"]["fixed"], 1)
        self.assertEqual(governance["policy_evaluation"]["outcome"], "fail")


if __name__ == "__main__":
    unittest.main()
