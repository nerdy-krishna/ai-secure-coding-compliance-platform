from __future__ import annotations

import hashlib
import unittest
from decimal import Decimal
from types import SimpleNamespace

from app.infrastructure.signing.digest_signer import LocalTestDigestSigner
from app.core.services.rule_foundry_service import (
    RuleFoundryService,
    RuleFoundryStateError,
)
from app.core.services.rule_foundry_quality import (
    QualityEvaluationError,
    SandboxQualityEvaluator,
)
from app.shared.lib.rule_foundry import (
    QualityMetrics,
    RuleFoundryPolicyError,
    assert_quality_gates,
    assert_shadow_gate,
    canonical_digest,
    decide_representability,
    sustained_promoted_failure_requires_review,
)


def passing_metrics(**overrides) -> QualityMetrics:
    values = {
        "vulnerable_total": 2,
        "vulnerable_detected": 2,
        "fixed_total": 2,
        "fixed_clean": 2,
        "negative_total": 2,
        "negative_clean": 2,
        "duplicate_stable_identities": 0,
        "deterministic_run_hashes": ("a" * 64, "a" * 64, "a" * 64),
        "performance_fixture_count": 1,
        "churn_fixture_count": 1,
        "churn_stable": 1,
        "baseline_median_ms": Decimal("100"),
        "candidate_median_ms": Decimal("200"),
        "p95_file_ms": Decimal("499.999"),
    }
    values.update(overrides)
    return QualityMetrics(**values)


class RuleFoundryPolicyTests(unittest.IsolatedAsyncioTestCase):
    def test_tool_routing_is_explicit_and_semantic_findings_remain_ai(self) -> None:
        self.assertEqual(
            decide_representability(
                predicate_kind="secret_pattern",
                bounded=True,
                uses_project_specific_names=False,
                requires_hidden_runtime_state=False,
            ).registry_kind,
            "gitleaks",
        )
        self.assertEqual(
            decide_representability(
                predicate_kind="dependency_advisory",
                bounded=True,
                uses_project_specific_names=False,
                requires_hidden_runtime_state=False,
            ).registry_kind,
            "osv",
        )
        semantic = decide_representability(
            predicate_kind="ast",
            bounded=True,
            uses_project_specific_names=True,
            requires_hidden_runtime_state=False,
        )
        self.assertFalse(semantic.static_representable)
        self.assertEqual(semantic.registry_kind, "ai_dataflow")
        self.assertIn("project-specific", semantic.reason or "")

    def test_exact_quality_boundaries(self) -> None:
        assert_quality_gates(passing_metrics())
        with self.assertRaises(RuleFoundryPolicyError):
            assert_quality_gates(
                passing_metrics(candidate_median_ms=Decimal("200.001"))
            )
        with self.assertRaises(RuleFoundryPolicyError):
            assert_quality_gates(passing_metrics(p95_file_ms=Decimal("500")))
        with self.assertRaises(RuleFoundryPolicyError):
            assert_quality_gates(
                passing_metrics(deterministic_run_hashes=("a", "a", "b"))
            )

    def test_shadow_gate_requires_100_files_at_no_more_than_one_percent(self) -> None:
        assert_shadow_gate(eligible_files=100, unexpected_matches=1)
        with self.assertRaises(RuleFoundryPolicyError):
            assert_shadow_gate(eligible_files=99, unexpected_matches=0)
        with self.assertRaises(RuleFoundryPolicyError):
            assert_shadow_gate(eligible_files=100, unexpected_matches=2)

    def test_promoted_failure_threshold_requires_three_distinct_scans(self) -> None:
        self.assertFalse(sustained_promoted_failure_requires_review(1))
        self.assertFalse(sustained_promoted_failure_requires_review(2))
        self.assertTrue(sustained_promoted_failure_requires_review(3))

    async def test_canonical_payload_is_repeatable_and_signature_verifies(self) -> None:
        _body_a, digest_a = canonical_digest({"b": 2, "a": 1})
        _body_b, digest_b = canonical_digest({"a": 1, "b": 2})
        self.assertEqual(digest_a, digest_b)
        signer = LocalTestDigestSigner()
        signature = await signer.sign_sha256(bytes.fromhex(digest_a))
        self.assertTrue(await signer.verify_sha256(bytes.fromhex(digest_a), signature))
        self.assertFalse(
            await signer.verify_sha256(hashlib.sha256(b"changed").digest(), signature)
        )

    async def test_missing_sandbox_tool_fails_closed(self) -> None:
        evaluator = SandboxQualityEvaluator(baseline_median_ms=Decimal("100"))
        with self.assertRaisesRegex(QualityEvaluationError, "unavailable"):
            await evaluator._run_process("/definitely-not-a-rule-scanner")

    async def test_gitleaks_scans_only_fixture_source_not_generated_config(
        self,
    ) -> None:
        evaluator = SandboxQualityEvaluator(baseline_median_ms=Decimal("100"))
        observed_args: tuple[str, ...] = ()

        async def capture(*args: str, allow_nonzero: bool = False) -> str:
            nonlocal observed_args
            observed_args = args
            self.assertTrue(allow_nonzero)
            return ""

        evaluator._run_process = capture  # type: ignore[method-assign]
        matches = await evaluator._run_gitleaks(
            {"id": "candidate", "regex": "generated-secret"},
            {"name": "negative", "language": "text", "content": "clean"},
        )
        self.assertEqual(matches, [])
        source = observed_args[observed_args.index("--source") + 1]
        config = observed_args[observed_args.index("--config") + 1]
        self.assertTrue(source.endswith("/source"))
        self.assertFalse(config.startswith(source + "/"))

    async def test_signed_version_rejects_payload_or_digest_tampering(self) -> None:
        signer = LocalTestDigestSigner()
        _encoded, digest = canonical_digest({"rule": {"id": "safe"}})
        signature = await signer.sign_sha256(bytes.fromhex(digest))
        service = RuleFoundryService(
            repo=None,  # type: ignore[arg-type]
            authz_repo=None,  # type: ignore[arg-type]
            signer=signer,
        )
        version = SimpleNamespace(
            canonical_payload={"rule": {"id": "safe"}},
            payload_sha256=digest,
            signature=signature.signature_b64,
            signature_algorithm=signature.algorithm,
            signing_key_id=signature.key_id,
        )
        await service._verify_version(version)
        version.canonical_payload = {"rule": {"id": "tampered"}}
        with self.assertRaisesRegex(RuleFoundryStateError, "digest"):
            await service._verify_version(version)
        version.canonical_payload = {"rule": {"id": "safe"}}
        version.payload_sha256 = "0" * 64
        with self.assertRaisesRegex(RuleFoundryStateError, "digest"):
            await service._verify_version(version)


if __name__ == "__main__":
    unittest.main()
