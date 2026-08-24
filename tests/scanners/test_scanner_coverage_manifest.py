"""Deterministic scanner coverage and policy-degradation regressions."""

from __future__ import annotations

import unittest
from types import SimpleNamespace
from uuid import uuid4

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database.repositories.scanner_coverage_repo import (
    coverage_policy_outcome,
    summarize_coverage,
)
from app.infrastructure.workflows.nodes.global_consolidate import _merge_cluster


def _entry(status: str, entry_id: str) -> SimpleNamespace:
    return SimpleNamespace(status=status, id=entry_id)


class ScannerCoverageManifestTests(unittest.TestCase):
    def test_partial_degradation_is_never_reported_complete(self) -> None:
        entries = [_entry("clean", "clean"), _entry("timeout", "timeout")]
        manifest = summarize_coverage(entries)

        self.assertEqual(manifest["overall_status"], "degraded")
        self.assertFalse(manifest["is_complete"])
        self.assertEqual(manifest["counts"]["clean"], 1)
        self.assertEqual(manifest["counts"]["timeout"], 1)

    def test_total_degradation_is_never_reported_clean(self) -> None:
        entries = [_entry("failed", "one"), _entry("truncated", "two")]
        manifest = summarize_coverage(entries)

        self.assertEqual(manifest["overall_status"], "degraded")
        self.assertFalse(manifest["is_complete"])
        self.assertEqual(manifest["counts"]["failed"], 1)
        self.assertEqual(manifest["counts"]["truncated"], 1)

    def test_only_clean_or_completed_entries_are_complete(self) -> None:
        manifest = summarize_coverage(
            [_entry("clean", "one"), _entry("completed", "two")]
        )

        self.assertEqual(manifest["overall_status"], "complete")
        self.assertTrue(manifest["is_complete"])

    def test_policy_fail_and_explicit_waiver_share_exact_matching_entries(self) -> None:
        entries = [_entry("clean", "one"), _entry("timeout", "two")]

        failed, failed_matches = coverage_policy_outcome(
            entries, ["failed", "timeout"], waive=False
        )
        waived, waived_matches = coverage_policy_outcome(
            entries, ["failed", "timeout"], waive=True
        )

        self.assertEqual(failed, "fail")
        self.assertEqual(waived, "waived")
        self.assertEqual([item.id for item in failed_matches], ["two"])
        self.assertEqual([item.id for item in waived_matches], ["two"])

    def test_normalized_merge_unions_scanner_coverage_lineage(self) -> None:
        first_id, second_id = uuid4(), uuid4()

        def finding(path: str, coverage_id):
            return VulnerabilityFinding(
                coverage_entry_id=coverage_id,
                coverage_entry_ids=[coverage_id],
                title="Shared vulnerable dependency",
                description="The same vulnerable dependency is used here.",
                severity="High",
                line_number=1,
                remediation="Upgrade the dependency.",
                confidence="High",
                file_path=path,
                source="osv",
                references=[],
            )

        merged = _merge_cluster(
            [finding("services/a.lock", first_id), finding("services/b.lock", second_id)]
        )

        self.assertEqual(set(merged.coverage_entry_ids), {first_id, second_id})
        self.assertIn(merged.coverage_entry_id, {first_id, second_id})


if __name__ == "__main__":
    unittest.main()
