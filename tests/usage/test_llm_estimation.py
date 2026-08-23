import unittest
from types import SimpleNamespace

from app.shared.lib.cost_estimation import (
    estimate_cost_for_prompt,
    estimate_cost_two_slot,
)
from app.shared.lib.llm_estimation import UsageObservation, calibrate_estimate


class LLMEstimateCalibrationTests(unittest.TestCase):
    def test_two_slot_contract_aggregates_total_input_tokens(self) -> None:
        config = SimpleNamespace(
            id="cfg",
            provider="openai",
            model_name="test-model",
            input_cost_per_million=1.0,
            output_cost_per_million=2.0,
        )

        result = estimate_cost_two_slot(
            reasoning_config=config,
            reasoning_input_tokens=700,
            utility_config=config,
            utility_input_tokens=300,
            output_token_percentage=0.25,
        )

        self.assertEqual(result["total_input_tokens"], 1_000)
        self.assertEqual(result["slots"]["reasoning"]["total_input_tokens"], 700)
        self.assertEqual(result["slots"]["utility"]["total_input_tokens"], 300)

    def test_sparse_history_uses_named_stage_fallback_and_retry_bound(self) -> None:
        calibration = calibrate_estimate("analysis", [])

        self.assertEqual(calibration.source, "conservative_stage_fallback")
        self.assertEqual(calibration.confidence, "low")
        self.assertEqual(calibration.expected_output_ratio, 0.40)
        self.assertEqual(calibration.upper_request_multiplier, 2.0)
        self.assertTrue(calibration.assumptions)

    def test_observed_history_uses_median_and_p90(self) -> None:
        observations = [
            UsageObservation(100, output, requests)
            for output, requests in [
                (10, 1),
                (20, 1),
                (30, 1),
                (40, 2),
                (90, 3),
            ]
        ]

        calibration = calibrate_estimate("analysis", observations)

        self.assertEqual(calibration.source, "canonical_usage_ledger")
        self.assertAlmostEqual(calibration.expected_output_ratio, 0.30)
        self.assertAlmostEqual(calibration.upper_output_ratio, 0.90)
        self.assertEqual(calibration.expected_request_multiplier, 1.0)
        self.assertEqual(calibration.upper_request_multiplier, 3.0)

    def test_cost_contract_exposes_expected_and_conservative_envelopes(self) -> None:
        config = SimpleNamespace(
            id="cfg",
            provider="openai",
            model_name="test-model",
            input_cost_per_million=1.0,
            output_cost_per_million=2.0,
        )
        result = estimate_cost_for_prompt(
            config,
            1_000,
            calibration=calibrate_estimate("file_profiling", []),
            stage="file_profiling",
        )

        self.assertEqual(result["total_input_tokens"], 1_000)
        self.assertEqual(result["predicted_output_tokens"], 150)
        self.assertEqual(result["upper_bound_input_tokens"], 2_000)
        self.assertEqual(result["upper_bound_output_tokens"], 700)
        self.assertEqual(result["expected_request_count"], 1)
        self.assertEqual(result["upper_bound_request_count"], 2)
        self.assertGreater(
            result["upper_bound_estimated_cost"], result["expected_estimated_cost"]
        )
        self.assertEqual(
            result["total_estimated_cost"], result["expected_estimated_cost"]
        )


if __name__ == "__main__":
    unittest.main()
