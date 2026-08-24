from __future__ import annotations

import csv
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from uuid import uuid4

from app.api.v1.models import (
    AnalysisResultDetailResponse,
    RemediationCandidateCounts,
    RemediationFileCounts,
    RemediationSummaryResponse,
    SummaryReportResponse,
)
from app.core.services.report.csv_report import render_csv
from app.core.services.report.html_report import render_html
from app.core.services.report.sarif_report import render_sarif
from app.shared.lib.patch_artifact import render_patch_export


class ActionableRemediationReportTests(unittest.TestCase):
    def setUp(self) -> None:
        scan_id = uuid4()
        candidate_id = uuid4()
        self.patch_plan = {
            "schema_version": 2,
            "scan_id": str(scan_id),
            "files": [
                {
                    "file_path": "src/app.py",
                    "source_snapshot_hash": "a" * 64,
                    "output_hash": "b" * 64,
                    "status": "manual_review_required",
                    "hunks": [],
                    "conflict_components": [],
                    "requirements": [
                        {
                            "candidate_id": str(candidate_id),
                            "required_imports": ["from secure import safe"],
                            "required_dependencies": ["secure-lib==1.0"],
                            "configuration_changes": ["Set SECURE_MODE=true"],
                            "migration_changes": ["Apply 0042_secure.sql"],
                            "required_commands": ["pytest -q"],
                            "manual_steps": ["Review the remaining conflict."],
                        }
                    ],
                    "validation_checks": [
                        {
                            "stage": "python_pytest",
                            "profile": "python_pytest",
                            "status": "not_run",
                            "blocking": True,
                            "tool": "pytest",
                            "tool_version": "pytest 9.0",
                            "completed_at": "2026-08-24T12:00:00Z",
                            "detail": "Conflict blocked the profile.",
                        }
                    ],
                    "unified_diff": "--- a/src/app.py\n+++ b/src/app.py\n",
                }
            ],
            "candidate_decisions": [],
        }
        self.result = AnalysisResultDetailResponse(
            status="COMPLETED",
            project_id=uuid4(),
            project_name="partial",
            scan_type="REMEDIATE",
            patch_plan=self.patch_plan,
            summary_report=SummaryReportResponse(
                submission_id=scan_id,
                project_id=uuid4(),
                scan_type="REMEDIATE",
                remediation=RemediationSummaryResponse(
                    outcome="partial_remediation",
                    candidates=RemediationCandidateCounts(
                        proposed=2, validated=1, applied=1, unverified=1
                    ),
                    files=RemediationFileCounts(total=2, planned=1, manual_review=1),
                ),
            ),
        )

    def test_reports_make_partial_state_requirements_and_not_run_truthful(self) -> None:
        html = render_html(self.result)
        self.assertIn("PARTIAL REMEDIATION", html)
        self.assertIn("pytest -q", html)
        self.assertIn("not_run", html)
        self.assertNotIn("<b>passed</b>", html)

        rows = list(csv.DictReader(io.StringIO(render_csv(self.result))))
        command = next(
            row
            for row in rows
            if row["record_type"] == "patch_requirement"
            and row["requirement_type"] == "command"
        )
        self.assertEqual(command["requirement_value"], "pytest -q")
        evidence = next(
            row for row in rows if row["record_type"] == "validation_evidence"
        )
        self.assertEqual(evidence["validation_outcome"], "not_run")
        self.assertEqual(evidence["validation_tool_version"], "pytest 9.0")

        sarif = json.loads(render_sarif(self.result))
        properties = sarif["runs"][0]["properties"]
        self.assertEqual(
            properties["sccapRemediation"]["outcome"], "partial_remediation"
        )
        self.assertEqual(
            properties["sccapPatchPlan"]["files"][0]["requirements"][0][
                "required_commands"
            ],
            ["pytest -q"],
        )

    def test_patch_export_comes_from_persisted_artifact(self) -> None:
        exported = render_patch_export(self.patch_plan)
        self.assertIn("# Required command: pytest -q", exported)
        self.assertIn("# Manual step: Review the remaining conflict.", exported)
        self.assertIn("REVIEW-ONLY CONTENT (NOT APPLY-READY)", exported)
        self.assertIn("# --- a/src/app.py", exported)
        self.assertNotIn("\n--- a/src/app.py", exported)

        planned = json.loads(json.dumps(self.patch_plan))
        planned["files"][0]["status"] = "planned"
        planned_export = render_patch_export(planned)
        self.assertIn("\n--- a/src/app.py", planned_export)
        self.assertNotIn("REVIEW-ONLY CONTENT (NOT APPLY-READY)", planned_export)

    def test_patch_export_cannot_activate_multiline_metadata_or_review_diff(
        self,
    ) -> None:
        injected = (
            "operator note\r\n"
            "--- a/victim.txt\r\n"
            "+++ b/victim.txt\r\n"
            "@@ -1 +1 @@\r\n"
            "-secret\r\n"
            "+owned"
        )
        payload = json.loads(json.dumps(self.patch_plan))
        planned = payload["files"][0]
        planned["status"] = "planned"
        planned["file_path"] = f"safe.txt\r\n{injected}"
        planned["requirements"][0]["required_commands"] = [injected]
        planned["requirements"][0]["manual_steps"] = [injected]
        planned["unified_diff"] = (
            "--- a/safe.txt\n" "+++ b/safe.txt\n" "@@ -1 +1 @@\n" "-old\n" "+new\n"
        )
        review_only = json.loads(json.dumps(planned))
        review_only["file_path"] = f"victim.txt\n{injected}"
        review_only["status"] = "manual_review_required"
        review_only["unified_diff"] = (
            "--- a/victim.txt\n"
            "+++ b/victim.txt\n"
            "@@ -1 +1 @@\n"
            "-secret\n"
            "+owned\n"
        )
        payload["files"].append(review_only)

        exported = render_patch_export(payload)
        active_old_headers = [
            line for line in exported.splitlines() if line.startswith("--- ")
        ]
        self.assertEqual(active_old_headers, ["--- a/safe.txt"])
        self.assertNotIn("\n--- a/victim.txt", exported)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "safe.txt").write_text("old\n", encoding="utf-8")
            (root / "victim.txt").write_text("secret\n", encoding="utf-8")
            patch_path = root / "artifact.patch"
            patch_path.write_text(exported, encoding="utf-8")

            checked = subprocess.run(
                ["git", "apply", "--check", str(patch_path)],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            applied = subprocess.run(
                ["git", "apply", str(patch_path)],
                cwd=root,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertEqual((root / "safe.txt").read_text(encoding="utf-8"), "new\n")
            self.assertEqual(
                (root / "victim.txt").read_text(encoding="utf-8"), "secret\n"
            )

    def test_audit_report_disclaims_generated_source_fix(self) -> None:
        audit = self.result.model_copy(deep=True)
        audit.scan_type = "AUDIT"
        audit.patch_plan = None
        assert audit.summary_report is not None
        audit.summary_report.scan_type = "AUDIT"
        audit.summary_report.remediation = None
        html = render_html(audit)
        self.assertIn("No generated code patch was produced or applied", html)


if __name__ == "__main__":
    unittest.main()
