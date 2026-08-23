import unittest
import uuid
from unittest.mock import AsyncMock, patch

from app.core.schemas import FixResult, FixSuggestion, VulnerabilityFinding
from app.shared.lib.finding_lineage_identity import (
    anchor_fingerprint,
    canonical_finding_id,
    fix_candidate_id,
    govern_fix_candidates,
    patch_fingerprint,
    raw_finding_id,
)
from app.infrastructure.workflows.nodes.consolidate import consolidate_and_patch_node
from app.shared.lib.patch_planner import PatchValidationCheck, source_hash


SCAN_ID = uuid.UUID("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
SNAPSHOT = "b" * 64


def finding(raw_id: uuid.UUID, line: int) -> VulnerabilityFinding:
    return VulnerabilityFinding(
        raw_finding_id=raw_id,
        title="SQL injection",
        description="Unsafe query",
        severity="High",
        line_number=line,
        remediation="Parameterize it",
        confidence="High",
        references=[],
        file_path="app.py",
        source_snapshot_hash=SNAPSHOT,
    )


def candidate(raw_id: uuid.UUID, line: int, replacement: str) -> FixResult:
    suggestion = FixSuggestion(
        description="Use a bound parameter",
        original_snippet="db.execute(query)",
        code=replacement,
    )
    anchor = anchor_fingerprint(
        file_path="app.py",
        source_snapshot_hash=SNAPSHOT,
        line_number=line,
        original_snippet=suggestion.original_snippet,
    )
    patch = patch_fingerprint(anchor=anchor, replacement_code=replacement)
    raw = finding(raw_id, line)
    return FixResult(
        finding=raw,
        suggestion=suggestion,
        candidate_id=fix_candidate_id(raw_id=raw_id, patch=patch),
        raw_finding_id=raw_id,
        source_snapshot_hash=SNAPSHOT,
        anchor_fingerprint=anchor,
        patch_fingerprint=patch,
    )


class FindingFixLineageTests(unittest.TestCase):
    def test_raw_identity_is_replay_stable_and_not_presentation_based(self):
        first = raw_finding_id(SCAN_ID, "task:file:chunk:lane:model", 2)
        replay = raw_finding_id(SCAN_ID, "task:file:chunk:lane:model", 2)
        self.assertEqual(first, replay)
        self.assertNotEqual(
            first, raw_finding_id(SCAN_ID, "task:file:chunk:lane:model", 3)
        )

    def test_canonical_identity_is_order_independent(self):
        one = raw_finding_id(SCAN_ID, "agent-a", 0)
        two = raw_finding_id(SCAN_ID, "agent-b", 0)
        self.assertEqual(
            canonical_finding_id([one, two]), canonical_finding_id([two, one])
        )

    def test_duplicates_collapse_but_same_patch_at_second_site_survives(self):
        raw_one = raw_finding_id(SCAN_ID, "agent-a", 0)
        raw_duplicate = raw_finding_id(SCAN_ID, "agent-b", 0)
        raw_second_site = raw_finding_id(SCAN_ID, "agent-a", 1)
        root_one = canonical_finding_id([raw_one, raw_duplicate])
        root_two = canonical_finding_id([raw_second_site])
        final_one = finding(raw_one, 10)
        final_one.canonical_finding_id = root_one
        final_two = finding(raw_second_site, 30)
        final_two.canonical_finding_id = root_two

        governed = govern_fix_candidates(
            [
                candidate(raw_one, 10, "db.execute(query, params)"),
                candidate(raw_duplicate, 10, "db.execute(query, params)"),
                candidate(raw_second_site, 30, "db.execute(query, params)"),
            ],
            [
                {
                    "raw_finding_id": str(raw_one),
                    "canonical_finding_id": str(root_one),
                    "status": "merged",
                },
                {
                    "raw_finding_id": str(raw_duplicate),
                    "canonical_finding_id": str(root_one),
                    "status": "merged",
                },
                {
                    "raw_finding_id": str(raw_second_site),
                    "canonical_finding_id": str(root_two),
                    "status": "passthrough",
                },
            ],
            [final_one, final_two],
        )
        self.assertEqual(
            sorted(item.disposition for item in governed),
            ["duplicate", "selected", "selected"],
        )
        self.assertNotEqual(
            governed[0].patch_fingerprint, governed[2].patch_fingerprint
        )

    def test_dropped_false_positive_candidate_cannot_be_selected(self):
        raw = raw_finding_id(SCAN_ID, "agent-a", 0)
        governed = govern_fix_candidates(
            [candidate(raw, 10, "safe()")],
            [
                {
                    "raw_finding_id": str(raw),
                    "status": "dropped",
                    "false_positive_reason": "Already parameterized",
                }
            ],
            [],
        )
        self.assertEqual(governed[0].disposition, "rejected")

    def test_competing_same_anchor_patches_require_manual_review(self):
        raw_one = raw_finding_id(SCAN_ID, "agent-a", 0)
        raw_two = raw_finding_id(SCAN_ID, "agent-b", 0)
        root = canonical_finding_id([raw_one, raw_two])
        final = finding(raw_one, 10)
        final.canonical_finding_id = root
        governed = govern_fix_candidates(
            [candidate(raw_one, 10, "safe_a()"), candidate(raw_two, 10, "safe_b()")],
            [
                {
                    "raw_finding_id": str(raw_one),
                    "canonical_finding_id": str(root),
                    "status": "merged",
                },
                {
                    "raw_finding_id": str(raw_two),
                    "canonical_finding_id": str(root),
                    "status": "merged",
                },
            ],
            [final],
        )
        self.assertEqual({item.disposition for item in governed}, {"conflict"})
        self.assertEqual(final.fix_selection_status, "manual_review_required")
        self.assertIsNone(final.fixes)


class PatchPlanGovernanceTests(unittest.IsolatedAsyncioTestCase):
    async def test_suggest_and_remediate_build_byte_identical_validation_plans(self):
        raw = raw_finding_id(SCAN_ID, "agent-a", 0)
        selected = candidate(raw, 1, "safe()")
        selected.canonical_finding_id = canonical_finding_id([raw])
        selected.disposition = "selected"
        selected.validation_status = "passed"
        source = "def safe():\n    return True\n\ndb.execute(query)\n"
        snapshot = source_hash(source)
        selected.source_snapshot_hash = snapshot
        selected.finding.source_snapshot_hash = snapshot
        sandbox_pass = PatchValidationCheck(
            stage="python_compile",
            status="passed",
            tool="python",
            detail="Fixture compile passed.",
            return_code=0,
        )

        async def run(scan_type):
            item = selected.model_copy(deep=True)
            with patch(
                "app.infrastructure.workflows.nodes.consolidate.run_sandbox_validation",
                new=AsyncMock(return_value=[sandbox_pass.model_copy(deep=True)]),
            ):
                return await consolidate_and_patch_node(
                    {
                        "scan_id": SCAN_ID,
                        "scan_type": scan_type,
                        "fix_candidates": [item],
                        "live_codebase": {"app.py": source},
                        "initial_file_map": {"app.py": snapshot},
                    }
                )

        suggested = await run("SUGGEST")
        remediated = await run("REMEDIATE")
        self.assertEqual(suggested["patch_plan"], remediated["patch_plan"])
        self.assertEqual(suggested["patched_files"], remediated["patched_files"])

    async def test_rejected_candidate_never_enters_remediation_patch_plan(self):
        raw = raw_finding_id(SCAN_ID, "agent-a", 0)
        rejected = candidate(raw, 10, "safe()")
        rejected.disposition = "rejected"
        rejected.validation_status = "failed"
        result = await consolidate_and_patch_node(
            {
                "scan_id": SCAN_ID,
                "scan_type": "REMEDIATE",
                "fix_candidates": [rejected],
            }
        )
        self.assertEqual(result["patch_plan"]["files"], [])
        self.assertNotIn("final_file_map", result)

    async def test_blocking_sandbox_failure_rejects_candidate_before_promotion(self):
        raw = raw_finding_id(SCAN_ID, "agent-a", 0)
        selected = candidate(raw, 1, "safe()")
        selected.canonical_finding_id = canonical_finding_id([raw])
        selected.disposition = "selected"
        selected.validation_status = "passed"
        source = "def safe():\n    return True\n\ndb.execute(query)\n"
        snapshot = source_hash(source)
        selected.source_snapshot_hash = snapshot
        selected.finding.source_snapshot_hash = snapshot

        failed = PatchValidationCheck(
            stage="python_pytest",
            status="failed",
            tool="python",
            detail="Allowlisted tests failed.",
            return_code=1,
            duration_ms=12,
            output="1 failed",
        )
        with patch(
            "app.infrastructure.workflows.nodes.consolidate.run_sandbox_validation",
            new=AsyncMock(return_value=[failed]),
        ):
            result = await consolidate_and_patch_node(
                {
                    "scan_id": SCAN_ID,
                    "scan_type": "SUGGEST",
                    "fix_candidates": [selected],
                    "live_codebase": {"app.py": source},
                    "initial_file_map": {"app.py": snapshot},
                }
            )

        self.assertEqual(
            result["patch_plan"]["files"][0]["status"], "manual_review_required"
        )
        self.assertEqual(
            result["patch_plan"]["files"][0]["validation_checks"][-1]["output"],
            "1 failed",
        )
        self.assertEqual(selected.disposition, "rejected")
        self.assertEqual(selected.validation_status, "failed")
        self.assertEqual(selected.applicability_status, "validation_failed")


if __name__ == "__main__":
    unittest.main()
