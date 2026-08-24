from __future__ import annotations

import os
import unittest
from decimal import Decimal

from app.core.services.rule_foundry_quality import SandboxQualityEvaluator


@unittest.skipUnless(
    os.getenv("SCCAP_RUN_TOOLCHAIN") == "1",
    "set SCCAP_RUN_TOOLCHAIN=1 inside the API image",
)
class RuleFoundryToolchainIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_pinned_gitleaks_positive_negative_and_deterministic_identity(
        self,
    ) -> None:
        evaluator = SandboxQualityEvaluator(baseline_median_ms=Decimal("1000"))
        rule = {
            "id": "sccap-foundry-smoke",
            "description": "Task18 native runtime smoke",
            "regex": "rf-secret-[0-9]{8}",
        }
        vulnerable = {
            "name": "vulnerable",
            "language": "text",
            "content": "token = rf-secret-12345678\n",
        }
        negative = {
            "name": "negative",
            "language": "text",
            "content": "token = definitely-clean\n",
        }

        first = await evaluator._run_gitleaks(rule, vulnerable)
        second = await evaluator._run_gitleaks(rule, vulnerable)
        clean = await evaluator._run_gitleaks(rule, negative)

        self.assertEqual(len(first), 1)
        self.assertEqual(first, second)
        self.assertEqual(clean, [])


if __name__ == "__main__":
    unittest.main()
