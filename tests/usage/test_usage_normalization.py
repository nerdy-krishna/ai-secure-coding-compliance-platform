"""Provider usage must retain disjoint billable categories."""

from __future__ import annotations

import unittest

from pydantic_ai.usage import RequestUsage

from app.shared.lib.llm_usage import normalize_request_usage


class UsageNormalizationTests(unittest.TestCase):
    def test_openai_cached_and_reasoning_tokens_remain_disjoint(self) -> None:
        usage = RequestUsage(
            input_tokens=1_000,
            cache_read_tokens=400,
            output_tokens=300,
            details={"reasoning_tokens": 100},
        )

        normalized = normalize_request_usage("openai", usage)

        self.assertEqual(normalized.input_tokens, 1_000)
        self.assertEqual(normalized.uncached_input_tokens, 600)
        self.assertEqual(normalized.cache_read_tokens, 400)
        self.assertEqual(normalized.reasoning_tokens, 100)
        self.assertEqual(normalized.non_reasoning_output_tokens, 200)
        self.assertEqual(normalized.quality_state, "normalized")

    def test_anthropic_cache_write_and_read_are_not_flattened(self) -> None:
        usage = RequestUsage(
            input_tokens=1_200,
            cache_write_tokens=300,
            cache_read_tokens=500,
            output_tokens=80,
            details={
                "cache_creation_input_tokens": 300,
                "cache_read_input_tokens": 500,
            },
        )

        normalized = normalize_request_usage("anthropic", usage)

        self.assertEqual(normalized.uncached_input_tokens, 400)
        self.assertEqual(normalized.cache_write_tokens, 300)
        self.assertEqual(normalized.cache_read_tokens, 500)
        self.assertEqual(normalized.output_tokens, 80)

    def test_gemini_thought_cache_tool_and_modality_usage_is_preserved(self) -> None:
        usage = RequestUsage(
            input_tokens=900,
            cache_read_tokens=200,
            input_audio_tokens=120,
            cache_audio_read_tokens=40,
            output_tokens=450,
            details={
                "thoughts_tokens": 150,
                "tool_use_prompt_tokens": 50,
                "image_prompt_tokens": 75,
                "audio_candidates_tokens": 30,
            },
        )

        normalized = normalize_request_usage("google", usage)

        self.assertEqual(normalized.reasoning_tokens, 150)
        self.assertEqual(normalized.tool_request_tokens, 50)
        self.assertEqual(normalized.input_audio_tokens, 120)
        self.assertEqual(normalized.cache_audio_read_tokens, 40)
        self.assertEqual(normalized.output_audio_tokens, 30)
        self.assertEqual(normalized.image_input_tokens, 75)
        self.assertEqual(normalized.provider_details["thoughts_tokens"], 150)
        quantities = normalized.billable_quantities()
        self.assertEqual(
            sum(quantities[key] for key in quantities if "output" not in key), 900
        )
        self.assertEqual(
            quantities["non_reasoning_output"]
            + quantities["reasoning_output"]
            + quantities["output_audio"]
            + quantities["image_output"],
            450,
        )

    def test_invalid_overlapping_counts_are_unknown_not_silently_clamped(self) -> None:
        usage = RequestUsage(
            input_tokens=100,
            cache_read_tokens=80,
            cache_write_tokens=40,
            output_tokens=10,
        )

        normalized = normalize_request_usage("anthropic", usage)

        self.assertEqual(normalized.quality_state, "unknown")
        self.assertEqual(normalized.uncached_input_tokens, 0)
        self.assertIn("overlapping_input_categories", normalized.quality_reasons)
