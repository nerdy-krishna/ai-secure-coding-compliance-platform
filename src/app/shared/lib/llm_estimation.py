"""Calibrate preflight LLM envelopes from the canonical usage ledger.

The estimator deliberately keeps statistics simple and explainable.  A model/stage
pair uses the median as its expected case and the nearest-rank p90 as its upper
case.  Until enough production observations exist, an explicit stage fallback is
used instead of presenting a universal output-token guess as measured fact.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
from statistics import median
from typing import Iterable


@dataclass(frozen=True)
class UsageObservation:
    input_tokens: int
    output_tokens: int
    request_count: int


@dataclass(frozen=True)
class EstimateCalibration:
    stage: str
    source: str
    confidence: str
    sample_count: int
    expected_output_ratio: float
    upper_output_ratio: float
    expected_request_multiplier: float
    upper_request_multiplier: float
    assumptions: tuple[str, ...]

    def as_dict(self) -> dict[str, object]:
        result = asdict(self)
        result["assumptions"] = list(self.assumptions)
        return result


# Ratios are intentionally stage-specific. Structured profiler responses are
# small, while analysis can return several detailed findings and fixes.
_FALLBACKS: dict[str, tuple[float, float, float, float]] = {
    "file_profiling": (0.15, 0.35, 1.0, 2.0),
    "analysis": (0.40, 0.90, 1.0, 2.0),
    "rag_preprocessing": (0.20, 0.50, 1.0, 2.0),
    "generic": (0.35, 0.80, 1.0, 2.0),
}


def _nearest_rank(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    rank = max(1, math.ceil(percentile * len(ordered)))
    return ordered[rank - 1]


def calibrate_estimate(
    stage: str,
    observations: Iterable[UsageObservation],
) -> EstimateCalibration:
    """Return explainable expected and conservative factors for one stage."""
    usable = [
        item
        for item in observations
        if item.input_tokens > 0 and item.output_tokens >= 0 and item.request_count > 0
    ]
    fallback = _FALLBACKS.get(stage, _FALLBACKS["generic"])
    if len(usable) < 5:
        expected_ratio, upper_ratio, expected_requests, upper_requests = fallback
        return EstimateCalibration(
            stage=stage,
            source="conservative_stage_fallback",
            confidence="low",
            sample_count=len(usable),
            expected_output_ratio=expected_ratio,
            upper_output_ratio=upper_ratio,
            expected_request_multiplier=expected_requests,
            upper_request_multiplier=upper_requests,
            assumptions=(
                f"Fewer than 5 usable {stage} observations exist for this model configuration.",
                "The upper bound includes one complete retry of every planned request.",
                "Provider-specific message serialization may add tokens beyond locally rendered prompts.",
            ),
        )

    output_ratios = [item.output_tokens / item.input_tokens for item in usable]
    request_counts = [float(item.request_count) for item in usable]
    expected_ratio = min(4.0, float(median(output_ratios)))
    upper_ratio = min(
        4.0,
        max(_nearest_rank(output_ratios, 0.90), expected_ratio * 1.25),
    )
    expected_requests = max(1.0, float(median(request_counts)))
    upper_requests = max(
        expected_requests,
        min(4.0, _nearest_rank(request_counts, 0.90)),
    )
    confidence = (
        "high" if len(usable) >= 50 else "medium" if len(usable) >= 20 else "low"
    )
    return EstimateCalibration(
        stage=stage,
        source="canonical_usage_ledger",
        confidence=confidence,
        sample_count=len(usable),
        expected_output_ratio=expected_ratio,
        upper_output_ratio=upper_ratio,
        expected_request_multiplier=expected_requests,
        upper_request_multiplier=upper_requests,
        assumptions=(
            "Expected values use the historical median for this model configuration and stage.",
            "Upper-bound values use the historical p90 and are not a billing guarantee.",
            "Provider-specific message serialization may add tokens beyond locally rendered prompts.",
        ),
    )
