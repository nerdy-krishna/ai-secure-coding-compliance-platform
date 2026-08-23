import unittest
from contextlib import asynccontextmanager, contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from app.core.schemas import FixResult, FixSuggestion, VulnerabilityFinding
from app.core.services.semgrep_ingestion.parser import semgrep_rule_content_hash
from app.infrastructure.scanners.provenance import build_semgrep_rule_provenance
from app.infrastructure.workflows.nodes.verify import (
    _matches_baseline,
    _replacement_line_window,
    _requires_osv_replay,
    _run_builtin_scanner_replay,
    _run_semgrep_replay,
    _shifted_line,
    _still_detected,
)
from app.shared.lib.patch_planner import (
    FilePatchPlan,
    PlannedPatchHunk,
    ResolvedPatchRange,
)


def semgrep_finding(rule_id: str, line: int, cwe: str = "CWE-95"):
    return VulnerabilityFinding(
        title="Semgrep eval",
        description="eval",
        severity="High",
        line_number=line,
        remediation="remove eval",
        confidence="High",
        references=[],
        file_path="src/app.py",
        source="semgrep",
        scanner_rule_id=rule_id,
        cwe=cwe,
    )


class PatchSecurityReplayTests(unittest.TestCase):
    def test_same_cwe_different_rule_is_not_the_originating_finding(self):
        original = semgrep_finding("rules.eval", 10)
        post = semgrep_finding("rules.other", 10)
        self.assertFalse(_still_detected(original, [post], (10, 10)))

    def test_same_rule_elsewhere_in_file_does_not_fail_resolved_site(self):
        original = semgrep_finding("rules.eval", 10)
        post = semgrep_finding("rules.eval", 80)
        self.assertFalse(_still_detected(original, [post], (10, 12)))

    def test_same_rule_at_resolved_site_is_still_detected(self):
        original = semgrep_finding("rules.eval", 10)
        post = semgrep_finding("rules.eval", 12)
        self.assertTrue(_still_detected(original, [post], (10, 10)))

    def test_legacy_finding_keeps_file_cwe_fallback(self):
        original = semgrep_finding("rules.eval", 10)
        original.scanner_rule_id = None
        post = semgrep_finding("rules.other", 40)
        self.assertTrue(_still_detected(original, [post]))

    def test_baseline_match_accounts_for_lines_added_by_prior_hunk(self):
        original = semgrep_finding("rules.eval", 20)
        post = semgrep_finding("rules.eval", 22)
        plan = FilePatchPlan(
            file_path="src/app.py",
            source_snapshot_hash="a" * 64,
            output_hash="b" * 64,
            status="planned",
            hunks=[
                PlannedPatchHunk(
                    patch_hunk_id=uuid4(),
                    candidate_ids=[uuid4()],
                    resolved_range=ResolvedPatchRange(
                        start_byte=0,
                        end_byte=4,
                        start_line=3,
                        start_column=1,
                        end_line=3,
                        end_column=5,
                    ),
                    context_fingerprint="c" * 64,
                    original_text="old\n",
                    replacement_text="one\ntwo\nthree\n",
                )
            ],
        )
        self.assertEqual(_shifted_line(20, plan), 22)
        self.assertTrue(_matches_baseline(post, [original], plan))

    def test_origin_window_accounts_for_lines_added_by_prior_hunk(self):
        original = semgrep_finding("rules.eval", 20)
        candidate = FixResult(
            finding=original,
            suggestion=FixSuggestion(
                description="Replace eval",
                original_snippet="eval(value)",
                code="safe(value)",
            ),
            candidate_id=uuid4(),
            resolved_range=ResolvedPatchRange(
                start_byte=100,
                end_byte=111,
                start_line=20,
                start_column=1,
                end_line=20,
                end_column=12,
            ),
        )
        plan = FilePatchPlan(
            file_path="src/app.py",
            source_snapshot_hash="a" * 64,
            output_hash="b" * 64,
            status="planned",
            hunks=[
                PlannedPatchHunk(
                    patch_hunk_id=uuid4(),
                    candidate_ids=[uuid4()],
                    resolved_range=ResolvedPatchRange(
                        start_byte=0,
                        end_byte=4,
                        start_line=3,
                        start_column=1,
                        end_line=3,
                        end_column=5,
                    ),
                    context_fingerprint="c" * 64,
                    original_text="old\n",
                    replacement_text="one\ntwo\nthree\nfour\nfive\n",
                )
            ],
        )
        shifted = semgrep_finding("rules.eval", 24)
        window = _replacement_line_window(candidate, plan)
        self.assertEqual(window, (24, 24))
        self.assertTrue(_still_detected(original, [shifted], window))

    def test_different_rule_at_changed_site_is_a_regression(self):
        original = semgrep_finding("rules.eval", 10)
        post = semgrep_finding("rules.command", 10)
        plan = FilePatchPlan(
            file_path="src/app.py",
            source_snapshot_hash="a" * 64,
            output_hash="b" * 64,
            status="planned",
        )
        self.assertFalse(_matches_baseline(post, [original], plan))

    def test_native_rule_matcher_is_scanner_agnostic(self):
        original = semgrep_finding("generic-api-key", 5, "CWE-798")
        original.source = "gitleaks"
        post = semgrep_finding("generic-api-key", 5, "CWE-798")
        post.source = "gitleaks"
        self.assertTrue(_still_detected(original, [post], (5, 5)))

    def test_osv_origin_matches_stable_cve_not_generic_cwe(self):
        original = semgrep_finding("unused", 0, "CWE-1104")
        original.source = "osv"
        original.scanner_rule_id = None
        original.cve_id = "CVE-2026-0001"
        same_cwe = semgrep_finding("unused", 0, "CWE-1104")
        same_cwe.source = "osv"
        same_cwe.scanner_rule_id = None
        same_cwe.cve_id = "CVE-2026-9999"
        persistent = same_cwe.model_copy(update={"cve_id": "CVE-2026-0001"})

        self.assertFalse(_still_detected(original, [same_cwe], (1, 1)))
        self.assertTrue(_still_detected(original, [persistent], (1, 1)))

    def test_dependency_lockfile_change_requires_osv_regression_replay(self):
        self.assertTrue(_requires_osv_replay("package-lock.json", []))
        self.assertTrue(_requires_osv_replay("deps/requirements-prod.txt", []))
        self.assertFalse(_requires_osv_replay("src/app.py", []))


class BuiltinScannerReplayTests(unittest.IsolatedAsyncioTestCase):
    def _semgrep_binding_fixture(self):
        source_id = uuid4()
        raw_yaml = {
            "id": "danger",
            "languages": ["python"],
            "message": "unsafe",
            "severity": "ERROR",
            "pattern": "eval(...)",
        }
        digest = semgrep_rule_content_hash(raw_yaml)
        source = SimpleNamespace(
            id=source_id,
            slug="rules",
            repo_url="https://example.invalid/rules",
            branch="main",
            last_commit_sha="a" * 40,
            enabled=True,
        )
        rule = SimpleNamespace(
            namespaced_id="rules.danger",
            content_hash=digest,
            source_id=source_id,
            license_spdx="MIT",
            enabled=True,
            raw_yaml=raw_yaml,
            source=source,
        )
        provenance = build_semgrep_rule_provenance([rule], [source])
        payload = {
            "schema_version": 1,
            "scanner_statuses": {
                "semgrep": {
                    "status": "completed",
                    "native_report_available": True,
                }
            },
            "toolchain_provenance": {
                "semgrep": {"rules": provenance},
            },
        }
        return rule, SimpleNamespace(version=3, payload=payload)

    def _binding_repositories(self, artifact, rules):
        artifact_repo = MagicMock()
        artifact_repo.get_by_type = AsyncMock(return_value=artifact)
        artifact_repo.resolve_payload = AsyncMock(return_value=artifact.payload)
        return artifact_repo

    async def test_semgrep_internal_timeout_is_not_infrastructure_error(self):
        timeout_finding = semgrep_finding("unused", 0)
        timeout_finding.scanner_rule_id = None
        timeout_finding.title = "Semgrep scanner timed out"

        @contextmanager
        def staged(_files):
            with TemporaryDirectory() as directory:
                yield Path(directory), {}

        @asynccontextmanager
        async def materialized(_rules):
            yield Path("/tmp/semgrep-rules")

        rule, artifact = self._semgrep_binding_fixture()
        artifact_repo = self._binding_repositories(artifact, [rule])
        session_factory = MagicMock()
        session_factory.return_value.__aenter__ = AsyncMock(return_value=object())
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "app.infrastructure.workflows.nodes.verify.AsyncSessionLocal",
                session_factory,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.ScanArtifactRepository",
                return_value=artifact_repo,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.materialize_rules",
                new=materialized,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.stage_files",
                new=staged,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.run_semgrep",
                new=AsyncMock(return_value=[timeout_finding]),
            ),
        ):
            check, findings = await _run_semgrep_replay(
                {"src/app.py": "pass\n"}, scan_id=uuid4()
            )
        self.assertEqual(check.status, "timeout")
        self.assertEqual(findings, [timeout_finding])

    async def test_semgrep_replay_uses_only_scan_bound_rules(self):
        rule, artifact = self._semgrep_binding_fixture()
        artifact_repo = self._binding_repositories(artifact, [rule])
        captured = []

        @asynccontextmanager
        async def materialized(rules):
            captured.extend(item.namespaced_id for item in rules)
            yield Path("/tmp/semgrep-rules")

        async def clean_run(_staged, _paths, config_path=None, report_collector=None):
            self.assertIsNotNone(config_path)
            report_collector({"results": [], "errors": []})
            return []

        session_factory = MagicMock()
        session_factory.return_value.__aenter__ = AsyncMock(return_value=object())
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "app.infrastructure.workflows.nodes.verify.AsyncSessionLocal",
                session_factory,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.ScanArtifactRepository",
                return_value=artifact_repo,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.materialize_rules",
                new=materialized,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.run_semgrep",
                new=clean_run,
            ),
        ):
            check, findings = await _run_semgrep_replay(
                {"src/app.py": "pass\n"}, scan_id=uuid4()
            )

        self.assertEqual(check.status, "passed")
        self.assertEqual(findings, [])
        self.assertEqual(captured, [rule.namespaced_id])
        self.assertIn('"scanner_report_artifact_version": 3', check.output)

    async def test_replay_uses_historical_body_after_live_rule_drift(self):
        rule, artifact = self._semgrep_binding_fixture()
        original_body = dict(rule.raw_yaml)
        rule.raw_yaml = {**rule.raw_yaml, "message": "mutated live rule"}
        rule.enabled = False
        artifact_repo = self._binding_repositories(artifact, [])
        captured = []

        @asynccontextmanager
        async def materialized(rules):
            captured.extend((item.namespaced_id, item.raw_yaml) for item in rules)
            yield Path("/tmp/semgrep-rules")

        @contextmanager
        def staged(_files):
            with TemporaryDirectory() as directory:
                yield Path(directory), {}

        async def clean_run(_staged, _paths, config_path=None, report_collector=None):
            report_collector({"results": [], "errors": []})
            return []

        session_factory = MagicMock()
        session_factory.return_value.__aenter__ = AsyncMock(return_value=object())
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "app.infrastructure.workflows.nodes.verify.AsyncSessionLocal",
                session_factory,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.ScanArtifactRepository",
                return_value=artifact_repo,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.materialize_rules",
                new=materialized,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.stage_files",
                new=staged,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.run_semgrep", new=clean_run
            ),
        ):
            check, _ = await _run_semgrep_replay(
                {"src/app.py": "pass\n"}, scan_id=uuid4()
            )
        self.assertEqual(check.status, "passed")
        self.assertEqual(captured, [(rule.namespaced_id, original_body)])

    async def test_missing_semgrep_provenance_blocks_replay(self):
        artifact = SimpleNamespace(
            version=1,
            payload={"schema_version": 1, "toolchain_provenance": {}},
        )
        artifact_repo = self._binding_repositories(artifact, [])
        session_factory = MagicMock()
        session_factory.return_value.__aenter__ = AsyncMock(return_value=object())
        session_factory.return_value.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "app.infrastructure.workflows.nodes.verify.AsyncSessionLocal",
                session_factory,
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify.ScanArtifactRepository",
                return_value=artifact_repo,
            ),
        ):
            check, _ = await _run_semgrep_replay(
                {"src/app.py": "pass\n"}, scan_id=uuid4()
            )
        self.assertEqual(check.status, "not_run")
        self.assertIn("semgrep_provenance_missing", check.detail)

    async def test_missing_bandit_report_is_not_implicit_success(self):
        with (
            patch(
                "app.infrastructure.workflows.nodes.verify.run_bandit",
                new=AsyncMock(return_value=[]),
            ),
            patch(
                "app.infrastructure.workflows.nodes.verify._bandit_binary",
                return_value="/definitely/missing/bandit",
            ),
        ):
            check, findings = await _run_builtin_scanner_replay(
                {"src/app.py": "pass\n"}, "bandit"
            )
        self.assertEqual(findings, [])
        self.assertEqual(check.status, "tool_missing")

    async def test_parsed_empty_bandit_report_is_a_pass(self):
        async def clean_run(_staged, _paths, report_collector=None):
            report_collector({"results": [], "errors": []})
            return []

        with patch(
            "app.infrastructure.workflows.nodes.verify.run_bandit",
            new=clean_run,
        ):
            check, findings = await _run_builtin_scanner_replay(
                {"src/app.py": "pass\n"}, "bandit"
            )
        self.assertEqual(findings, [])
        self.assertEqual(check.status, "passed")

    async def test_bandit_native_errors_are_infrastructure_failure(self):
        async def error_run(_staged, _paths, report_collector=None):
            report_collector({"results": [], "errors": [{"reason": "parse"}]})
            return []

        with patch(
            "app.infrastructure.workflows.nodes.verify.run_bandit",
            new=error_run,
        ):
            check, _ = await _run_builtin_scanner_replay(
                {"src/app.py": "broken"}, "bandit"
            )
        self.assertEqual(check.status, "infrastructure_error")


if __name__ == "__main__":
    unittest.main()
