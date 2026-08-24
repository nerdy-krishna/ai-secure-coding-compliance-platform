from datetime import datetime, timedelta, timezone
import unittest

from app.shared.lib.finding_governance import (
    GatePolicy,
    classify_baseline,
    evaluate_gate,
    exact_ranges,
    finding_fingerprint,
    waiver_is_eligible,
)


class FindingGovernanceSemanticsTests(unittest.TestCase):
    def finding(self, **overrides):
        value = {
            "source": "semgrep",
            "scanner_rule_id": "python.sql.injection",
            "file_path": "src/db.py",
            "line_number": 41,
            "vulnerable_snippet": "cursor.execute(query)",
            "title": "SQL injection",
            "severity": "High",
            "confidence": "High",
        }
        value.update(overrides)
        return value

    def test_identity_survives_line_drift_but_not_source_site_change(self):
        baseline = finding_fingerprint(self.finding())
        self.assertEqual(baseline, finding_fingerprint(self.finding(line_number=99)))
        self.assertNotEqual(
            baseline, finding_fingerprint(self.finding(file_path="src/other.py"))
        )

    def test_baseline_states_are_deterministic(self):
        states, fixed = classify_baseline(
            {"same", "brand-new", "old-again"},
            {"same", "gone"},
            {"same", "gone", "old-again"},
        )
        self.assertEqual(
            states,
            {"brand-new": "new", "old-again": "reintroduced", "same": "unchanged"},
        )
        self.assertEqual(fixed, {"gone"})

    def test_exact_ranges_include_consolidated_sites(self):
        ranges = exact_ranges(
            self.finding(
                affected_locations=[
                    {
                        "file_path": "src/db2.py",
                        "line_number": 7,
                        "snippet": "bad()\nagain()",
                    }
                ]
            )
        )
        self.assertEqual(ranges[0]["start_line"], 41)
        self.assertEqual(ranges[1]["end_line"], 8)

    def test_gate_uses_severity_confidence_coverage_and_waiver(self):
        finding = self.finding()
        fingerprint = finding_fingerprint(finding)
        policy = GatePolicy()
        failed = evaluate_gate([finding], policy=policy, coverage_complete=False)
        self.assertEqual(failed["outcome"], "fail")
        self.assertTrue(failed["coverage_failed"])
        passed = evaluate_gate(
            [finding],
            policy=policy,
            coverage_complete=True,
            waived_fingerprints={fingerprint},
        )
        self.assertEqual(passed["outcome"], "pass")

    def test_expiring_waiver_fails_minimum_remaining_policy(self):
        now = datetime.now(timezone.utc)
        policy = GatePolicy(minimum_waiver_remaining_hours=24)
        self.assertFalse(
            waiver_is_eligible(
                expires_at=now + timedelta(hours=23), policy=policy, now=now
            )
        )
        self.assertTrue(
            waiver_is_eligible(
                expires_at=now + timedelta(hours=25), policy=policy, now=now
            )
        )


if __name__ == "__main__":
    unittest.main()
