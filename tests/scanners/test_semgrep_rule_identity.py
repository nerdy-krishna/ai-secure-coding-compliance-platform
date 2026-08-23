import unittest
from pathlib import Path

from app.infrastructure.scanners.semgrep_runner import (
    _SemgrepResult,
    _semgrep_finding_to_vulnerability,
)
from app.infrastructure.scanners.bandit_runner import (
    _BanditResult,
    _bandit_finding_to_vulnerability,
)
from app.infrastructure.scanners.gitleaks_runner import (
    _GitleaksResult,
    _gitleaks_finding_to_vulnerability,
)


class SemgrepRuleIdentityTests(unittest.TestCase):
    def test_native_check_id_survives_canonical_finding_conversion(self):
        staged = Path("/tmp/sccap-test/app.py")
        raw = _SemgrepResult.model_validate(
            {
                "check_id": "community.python.lang.security.audit.eval-detected",
                "path": str(staged),
                "start": {"line": 7},
                "extra": {
                    "severity": "ERROR",
                    "message": "eval detected",
                    "metadata": {"cwe": ["CWE-95"]},
                },
            }
        )
        finding = _semgrep_finding_to_vulnerability(
            raw,
            {staged.resolve(): "src/app.py"},
        )
        self.assertEqual(
            finding.scanner_rule_id,
            "community.python.lang.security.audit.eval-detected",
        )
        self.assertEqual((finding.file_path, finding.line_number), ("src/app.py", 7))

    def test_bandit_test_id_survives_canonical_finding_conversion(self):
        staged = Path("/tmp/sccap-test/app.py")
        raw = _BanditResult.model_validate(
            {
                "filename": str(staged),
                "line_number": 11,
                "test_id": "B608",
                "issue_severity": "MEDIUM",
                "issue_confidence": "HIGH",
                "issue_text": "SQL string construction",
                "issue_cwe": {"id": 89},
            }
        )
        finding = _bandit_finding_to_vulnerability(
            raw,
            {staged.resolve(): "src/app.py"},
        )
        self.assertEqual(finding.scanner_rule_id, "B608")
        self.assertEqual((finding.file_path, finding.line_number), ("src/app.py", 11))

    def test_gitleaks_rule_id_survives_without_secret_fields(self):
        staged = Path("/tmp/sccap-test/.env")
        raw = _GitleaksResult.model_validate(
            {
                "RuleID": "generic-api-key",
                "File": str(staged),
                "StartLine": 3,
                "Description": "Generic API key",
                "Secret": "must-not-survive",
                "Match": "must-not-survive",
            }
        )
        finding = _gitleaks_finding_to_vulnerability(
            raw,
            {staged.resolve(): ".env"},
        )
        self.assertEqual(finding.scanner_rule_id, "generic-api-key")
        self.assertNotIn("must-not-survive", finding.model_dump_json())


if __name__ == "__main__":
    unittest.main()
