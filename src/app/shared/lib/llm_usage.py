"""Provider-neutral, request-granular LLM usage and price primitives.

The provider response remains authoritative. This module converts Pydantic AI's
inclusive usage contract into explicit, non-overlapping billing quantities and
prices them with immutable Decimal snapshots. Missing pricing is unknown, never
silently zero.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import ROUND_HALF_EVEN, Decimal
from types import MappingProxyType
from typing import Any, Literal, Mapping, Protocol


_MONEY_QUANTUM = Decimal("0.000000000001")
_DETAIL_LIMIT = 128
BILLABLE_CATEGORIES = frozenset(
    {
        "uncached_input",
        "cache_read_input",
        "cache_write_input",
        "input_audio",
        "cache_audio_read",
        "image_input",
        "non_reasoning_output",
        "reasoning_output",
        "output_audio",
        "image_output",
        "provider_request",
    }
)


class RequestUsageLike(Protocol):
    input_tokens: int
    cache_write_tokens: int
    cache_read_tokens: int
    input_audio_tokens: int
    cache_audio_read_tokens: int
    output_tokens: int
    details: Mapping[str, int]


@dataclass(frozen=True)
class NormalizedUsage:
    provider: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    uncached_input_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int
    reasoning_tokens: int
    non_reasoning_output_tokens: int
    input_audio_tokens: int
    uncached_audio_input_tokens: int
    cache_audio_read_tokens: int
    output_audio_tokens: int
    image_input_tokens: int
    image_output_tokens: int
    tool_request_tokens: int
    provider_details: Mapping[str, int]
    usage_source: Literal["provider", "estimated", "reconciled"]
    quality_state: Literal["exact", "normalized", "estimated", "unknown"]
    quality_reasons: tuple[str, ...] = ()

    def billable_quantities(self) -> Mapping[str, int]:
        """Return non-overlapping token categories for request pricing."""

        uncached_text = max(
            0,
            self.uncached_input_tokens
            - self.uncached_audio_input_tokens
            - self.image_input_tokens,
        )
        non_reasoning_text_output = max(
            0,
            self.non_reasoning_output_tokens
            - self.output_audio_tokens
            - self.image_output_tokens,
        )
        return {
            "uncached_input": uncached_text,
            "cache_read_input": max(
                0, self.cache_read_tokens - self.cache_audio_read_tokens
            ),
            "cache_write_input": self.cache_write_tokens,
            "input_audio": self.uncached_audio_input_tokens,
            "cache_audio_read": self.cache_audio_read_tokens,
            "image_input": self.image_input_tokens,
            "non_reasoning_output": non_reasoning_text_output,
            "reasoning_output": self.reasoning_tokens,
            "output_audio": self.output_audio_tokens,
            "image_output": self.image_output_tokens,
        }


@dataclass(frozen=True)
class Rate:
    amount: Decimal
    unit: Literal["million_tokens", "thousand_requests", "second", "byte_month"]
    modifier: Decimal = Decimal("1")


@dataclass(frozen=True)
class PriceSnapshot:
    source: str
    effective_at: datetime
    currency: str
    rates: Mapping[str, Rate]
    catalog_metadata: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "rates", MappingProxyType(dict(self.rates)))
        object.__setattr__(
            self,
            "catalog_metadata",
            MappingProxyType(dict(self.catalog_metadata)),
        )


@dataclass(frozen=True)
class PriceLineItem:
    category: str
    quantity: Decimal
    unit: str
    rate: Decimal
    modifier: Decimal
    currency: str
    amount: Decimal
    source: str
    effective_at: datetime


@dataclass(frozen=True)
class PricedUsage:
    cost_status: Literal["exact", "unknown"]
    currency: str | None
    total_amount: Decimal | None
    line_items: tuple[PriceLineItem, ...]
    missing_categories: tuple[str, ...] = ()


def _nonnegative_int(value: object) -> int:
    try:
        result = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return max(0, result)


def _first_detail(details: Mapping[str, int], *keys: str) -> int:
    return max((_nonnegative_int(details.get(key)) for key in keys), default=0)


def normalize_request_usage(
    provider: str,
    usage: RequestUsageLike,
    *,
    usage_source: Literal["provider", "estimated", "reconciled"] = "provider",
) -> NormalizedUsage:
    """Normalize one provider request without losing provider-specific detail."""

    bounded_details = {
        str(key)[:128]: _nonnegative_int(value)
        for key, value in list((usage.details or {}).items())[:_DETAIL_LIMIT]
        if isinstance(value, (int, float))
    }
    details: Mapping[str, int] = MappingProxyType(bounded_details)

    input_tokens = _nonnegative_int(usage.input_tokens)
    output_tokens = _nonnegative_int(usage.output_tokens)
    cache_read = _nonnegative_int(usage.cache_read_tokens)
    cache_write = _nonnegative_int(usage.cache_write_tokens)
    input_audio = _nonnegative_int(usage.input_audio_tokens)
    cache_audio = _nonnegative_int(usage.cache_audio_read_tokens)
    output_audio = _first_detail(
        details,
        "audio_candidates_tokens",
        "audio_output_tokens",
        "output_audio_tokens",
    )
    image_input = _first_detail(
        details,
        "image_prompt_tokens",
        "image_input_tokens",
    )
    image_output = _first_detail(
        details,
        "image_candidates_tokens",
        "image_output_tokens",
    )
    reasoning = _first_detail(
        details,
        "reasoning_tokens",
        "thoughts_tokens",
        "reasoning_token_count",
    )
    tool_request_tokens = _first_detail(
        details,
        "tool_use_prompt_tokens",
        "tool_request_tokens",
    )

    reasons: list[str] = []
    uncached_input = input_tokens - cache_read - cache_write
    if uncached_input < 0:
        reasons.append("overlapping_input_categories")
        uncached_input = 0
    if reasoning > output_tokens:
        reasons.append("reasoning_exceeds_output")
    if cache_audio > input_audio or cache_audio > cache_read:
        reasons.append("audio_cache_exceeds_parent")
    if output_audio + image_output + reasoning > output_tokens:
        reasons.append("overlapping_output_categories")

    if usage_source == "estimated":
        quality_state: Literal["exact", "normalized", "estimated", "unknown"] = (
            "estimated"
        )
    elif reasons:
        quality_state = "unknown"
    else:
        quality_state = "normalized"

    return NormalizedUsage(
        provider=provider.lower(),
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        total_tokens=input_tokens + output_tokens,
        uncached_input_tokens=uncached_input,
        cache_read_tokens=cache_read,
        cache_write_tokens=cache_write,
        reasoning_tokens=min(reasoning, output_tokens),
        non_reasoning_output_tokens=max(0, output_tokens - reasoning),
        input_audio_tokens=input_audio,
        uncached_audio_input_tokens=max(0, input_audio - cache_audio),
        cache_audio_read_tokens=cache_audio,
        output_audio_tokens=output_audio,
        image_input_tokens=image_input,
        image_output_tokens=image_output,
        tool_request_tokens=tool_request_tokens,
        provider_details=details,
        usage_source=usage_source,
        quality_state=quality_state,
        quality_reasons=tuple(reasons),
    )


def _amount(quantity: int, rate: Rate) -> Decimal:
    divisor = {
        "million_tokens": Decimal("1000000"),
        "thousand_requests": Decimal("1000"),
        "second": Decimal("1"),
        "byte_month": Decimal("1"),
    }[rate.unit]
    return (Decimal(quantity) * rate.amount * rate.modifier / divisor).quantize(
        _MONEY_QUANTUM, rounding=ROUND_HALF_EVEN
    )


def price_normalized_usage(
    usage: NormalizedUsage,
    snapshot: PriceSnapshot | None,
) -> PricedUsage:
    """Price one normalized request; incomplete snapshots fail closed."""

    if snapshot is None or usage.quality_state == "unknown":
        return PricedUsage("unknown", None, None, ())

    quantities = {k: v for k, v in usage.billable_quantities().items() if v > 0}
    if "provider_request" in snapshot.rates:
        quantities["provider_request"] = 1
    missing = tuple(sorted(set(quantities) - set(snapshot.rates)))
    if missing:
        return PricedUsage(
            "unknown",
            snapshot.currency,
            None,
            (),
            missing_categories=missing,
        )

    line_items = tuple(
        PriceLineItem(
            category=category,
            quantity=Decimal(quantity),
            unit=rate.unit,
            rate=rate.amount,
            modifier=rate.modifier,
            currency=snapshot.currency,
            amount=_amount(quantity, rate),
            source=snapshot.source,
            effective_at=snapshot.effective_at,
        )
        for category, quantity in sorted(quantities.items())
        for rate in (snapshot.rates[category],)
    )
    total = sum((item.amount for item in line_items), start=Decimal("0")).quantize(
        _MONEY_QUANTUM,
        rounding=ROUND_HALF_EVEN,
    )
    return PricedUsage(
        "exact",
        snapshot.currency,
        total,
        line_items,
    )
