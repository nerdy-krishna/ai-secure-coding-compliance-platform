import hashlib
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from app.core.services.semgrep_ingestion.parser import semgrep_rule_content_hash
from app.infrastructure.scanners.provenance import (
    _SCANNER_SPECS,
    _expected_binary_sha256,
    SemgrepRuleBindingError,
    build_scanner_provenance,
    build_semgrep_rule_provenance,
    parse_semgrep_rule_binding,
)


class ScannerProvenanceContracts(unittest.TestCase):
    def test_architecture_specific_native_binary_digests(self) -> None:
        self.assertEqual(
            _expected_binary_sha256(_SCANNER_SPECS["gitleaks"], machine="aarch64"),
            "b337056f2c68bef812b378f2841225f1e52f87a293fe0c457507634defdc6fb8",
        )
        self.assertEqual(
            _expected_binary_sha256(_SCANNER_SPECS["osv"], machine="arm64"),
            "fa46ad2b3954db5d5335303d45de921613393285d9a93c140b63b40e35e9ce50",
        )
        self.assertEqual(
            _expected_binary_sha256(_SCANNER_SPECS["osv"], machine="x86_64"),
            "bb30c580afe5e757d3e959f4afd08a4795ea505ef84c46962b9a738aa573b41b",
        )

    def test_binary_and_config_digests_are_verified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "scanner"
            config = Path(tmp) / "rules.toml"
            binary.write_bytes(b"scanner-binary")
            config.write_bytes(b"pinned-config")
            binary_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            config_digest = hashlib.sha256(config.read_bytes()).hexdigest()

            provenance = build_scanner_provenance(
                scanner="example",
                binary_path=binary,
                detected_version="1.2.3",
                expected_version="1.2.3",
                expected_binary_sha256=binary_digest,
                config_path=config,
                expected_config_sha256=config_digest,
            )

        self.assertEqual(provenance["status"], "verified")
        self.assertTrue(provenance["immutable"])
        self.assertEqual(provenance["binary"]["sha256"], binary_digest)
        self.assertEqual(provenance["configuration"]["sha256"], config_digest)

    def test_mismatch_is_explicitly_degraded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "scanner"
            binary.write_bytes(b"unexpected")
            provenance = build_scanner_provenance(
                scanner="example",
                binary_path=binary,
                detected_version="2.0.0",
                expected_version="1.2.3",
                expected_binary_sha256="0" * 64,
            )

        self.assertEqual(provenance["status"], "degraded")
        self.assertFalse(provenance["immutable"])
        self.assertIn("binary_digest_mismatch", provenance["reasons"])
        self.assertIn("version_mismatch", provenance["reasons"])

    def test_semgrep_rules_are_order_independent_and_commit_resolved(self) -> None:
        source_id = "a8a47f72-cb5e-4977-8ef2-c9e75d16dcb6"
        source = SimpleNamespace(
            id=source_id,
            slug="community",
            repo_url="https://github.com/semgrep/semgrep-rules",
            branch="develop",
            last_commit_sha="a" * 40,
        )
        z_body = {"id": "z-rule", "pattern": "eval(...)"}
        a_body = {"id": "a-rule", "pattern": "exec(...)"}
        rules = [
            SimpleNamespace(
                namespaced_id="community.z-rule",
                content_hash=semgrep_rule_content_hash(z_body),
                source_id=source_id,
                license_spdx="MIT",
                raw_yaml=z_body,
            ),
            SimpleNamespace(
                namespaced_id="community.a-rule",
                content_hash=semgrep_rule_content_hash(a_body),
                source_id=source_id,
                license_spdx="MIT",
                raw_yaml=a_body,
            ),
        ]

        first = build_semgrep_rule_provenance(rules, [source])
        second = build_semgrep_rule_provenance(list(reversed(rules)), [source])

        self.assertEqual(first["status"], "verified")
        self.assertTrue(first["immutable"])
        self.assertEqual(first["ruleset_sha256"], second["ruleset_sha256"])
        self.assertEqual(first["sources"][0]["resolved_commit_sha"], "a" * 40)
        self.assertEqual(first["rules"][0]["id"], "community.a-rule")

    def test_semgrep_mutable_alias_without_commit_is_degraded(self) -> None:
        source_id = "8ac61653-d1fe-4a6d-a42f-8b54d14e946f"
        rule = SimpleNamespace(
            namespaced_id="custom.rule",
            content_hash="d" * 64,
            source_id=source_id,
            license_spdx="Apache-2.0",
            raw_yaml=None,
        )
        source = SimpleNamespace(
            id=source_id,
            slug="custom",
            repo_url="https://example.invalid/rules",
            branch="main",
            last_commit_sha=None,
        )

        provenance = build_semgrep_rule_provenance([rule], [source])

        self.assertEqual(provenance["status"], "degraded")
        self.assertFalse(provenance["immutable"])
        self.assertIn("source_commit_missing:custom", provenance["reasons"])

    def test_semgrep_replay_binding_rejects_tampered_ruleset_digest(self) -> None:
        source_id = "8ac61653-d1fe-4a6d-a42f-8b54d14e946f"
        source = SimpleNamespace(
            id=source_id,
            slug="custom",
            repo_url="https://example.invalid/rules",
            branch="main",
            last_commit_sha="a" * 40,
        )
        body = {"id": "rule", "pattern": "eval(...)"}
        rule = SimpleNamespace(
            namespaced_id="custom.rule",
            content_hash=semgrep_rule_content_hash(body),
            source_id=source_id,
            license_spdx="MIT",
            raw_yaml=body,
        )
        provenance = build_semgrep_rule_provenance([rule], [source])
        provenance["ruleset_sha256"] = "e" * 64
        payload = {
            "schema_version": 1,
            "scanner_statuses": {
                "semgrep": {
                    "status": "completed",
                    "native_report_available": True,
                }
            },
            "toolchain_provenance": {"semgrep": {"rules": provenance}},
        }

        with self.assertRaisesRegex(
            SemgrepRuleBindingError, "semgrep_ruleset_digest_mismatch"
        ):
            parse_semgrep_rule_binding(payload)


if __name__ == "__main__":
    unittest.main()
