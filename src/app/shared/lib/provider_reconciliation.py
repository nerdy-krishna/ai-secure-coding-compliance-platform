"""Provider-billing normalization and deterministic discrepancy classification.

This module is deliberately provider-transport agnostic.  Connectors convert their
responses into :class:`UsageSlice`; comparison never reads credentials and never
mutates the canonical SCCAP usage ledger.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Iterable, Literal


Classification = Literal[
    "matched",
    "missing_event",
    "duplicate_event",
    "token_category_mismatch",
    "price_catalog_mismatch",
    "provider_adjustment_credit",
    "timing_lag",
    "unresolved",
]


def utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("reconciliation timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def normalize_text(value: str | None, *, fallback: str = "unknown") -> str:
    normalized = (value or "").strip().lower()
    return normalized or fallback


def normalize_model(value: str | None) -> str:
    model = normalize_text(value)
    # Gateways commonly qualify the same provider model with a provider prefix.
    for prefix in ("openai/", "azure/"):
        if model.startswith(prefix):
            return model[len(prefix) :]
    return model


def opaque_dimension(value: str | None) -> str:
    """Stable non-secret join key for API key/project identifiers."""
    if not value:
        return "unattributed"
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()[:24]


@dataclass(frozen=True, slots=True)
class UsageSlice:
    provider: str
    window_start: datetime
    window_end: datetime
    model: str | None = None
    project: str | None = None
    api_key: str | None = None
    service_tier: str | None = None
    is_batch: bool | None = None
    currency: str = "USD"
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    reasoning_tokens: int = 0
    cost_micro_usd: int = 0
    external_id: str | None = None
    kind: str = "usage"
    late_arrival: bool = False
    duplicate_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        start, end = utc(self.window_start), utc(self.window_end)
        if end <= start:
            raise ValueError("usage window end must be after start")
        for name in (
            "input_tokens",
            "output_tokens",
            "cache_read_tokens",
            "cache_write_tokens",
            "reasoning_tokens",
            "duplicate_count",
        ):
            if getattr(self, name) < 0:
                raise ValueError(f"{name} must be non-negative")
        object.__setattr__(self, "window_start", start)
        object.__setattr__(self, "window_end", end)
        object.__setattr__(self, "provider", normalize_text(self.provider))
        object.__setattr__(self, "model", normalize_model(self.model))
        object.__setattr__(self, "service_tier", normalize_text(self.service_tier))
        object.__setattr__(self, "currency", self.currency.strip().upper())
        if self.currency != "USD":
            raise ValueError("only USD provider billing is currently supported")

    @property
    def dimension_key(self) -> str:
        payload = {
            "provider": self.provider,
            "start": self.window_start.isoformat(),
            "end": self.window_end.isoformat(),
            "model": self.model,
            "tier": self.service_tier,
            "batch": bool(self.is_batch),
            "currency": self.currency,
            "measure": "cost" if self.kind in ("cost", "credit") else "usage",
        }
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @property
    def tokens(self) -> dict[str, int]:
        return {
            "input": self.input_tokens,
            "output": self.output_tokens,
            "cache_read": self.cache_read_tokens,
            "cache_write": self.cache_write_tokens,
            "reasoning": self.reasoning_tokens,
        }


def merge_slices(rows: Iterable[UsageSlice]) -> dict[str, UsageSlice]:
    merged: dict[str, UsageSlice] = {}
    item_ids: dict[str, list[str]] = {}
    project_ids: dict[str, set[str]] = {}
    api_key_ids: dict[str, set[str]] = {}
    for row in rows:
        key = row.dimension_key
        project_ids.setdefault(key, set()).add(opaque_dimension(row.project))
        api_key_ids.setdefault(key, set()).add(opaque_dimension(row.api_key))
        previous = merged.get(key)
        if previous is None:
            item_ids[key] = [row.external_id] if row.external_id else []
            merged[key] = replace(
                row,
                metadata={
                    **row.metadata,
                    "external_ids": tuple(item_ids[key][:100]),
                    "project_ids": tuple(sorted(project_ids[key])),
                    "api_key_ids": tuple(sorted(api_key_ids[key])),
                },
            )
            continue
        item_ids[key].extend([row.external_id] if row.external_id else [])
        merged[key] = UsageSlice(
            provider=row.provider,
            window_start=row.window_start,
            window_end=row.window_end,
            model=row.model,
            project=row.project,
            api_key=row.api_key,
            service_tier=row.service_tier,
            is_batch=row.is_batch,
            currency=row.currency,
            input_tokens=previous.input_tokens + row.input_tokens,
            output_tokens=previous.output_tokens + row.output_tokens,
            cache_read_tokens=previous.cache_read_tokens + row.cache_read_tokens,
            cache_write_tokens=previous.cache_write_tokens + row.cache_write_tokens,
            reasoning_tokens=previous.reasoning_tokens + row.reasoning_tokens,
            cost_micro_usd=previous.cost_micro_usd + row.cost_micro_usd,
            external_id=None,
            kind=(
                "credit"
                if previous.kind == "credit" or row.kind == "credit"
                else "cost"
                if previous.kind == "cost" or row.kind == "cost"
                else "usage"
            ),
            late_arrival=previous.late_arrival or row.late_arrival,
            duplicate_count=previous.duplicate_count + row.duplicate_count,
            metadata={
                "external_ids": tuple(item_ids[key][:100]),
                "project_ids": tuple(sorted(project_ids[key])),
                "api_key_ids": tuple(sorted(api_key_ids[key])),
            },
        )
    return merged


@dataclass(frozen=True, slots=True)
class Comparison:
    dimension_key: str
    classification: Classification
    canonical: UsageSlice | None
    provider: UsageSlice | None
    variance_micro_usd: int
    within_tolerance: bool
    details: dict[str, Any]


def compare_usage(
    canonical_rows: Iterable[UsageSlice],
    provider_rows: Iterable[UsageSlice],
    *,
    absolute_tolerance_micro_usd: int,
    percentage_tolerance: Decimal,
) -> list[Comparison]:
    if absolute_tolerance_micro_usd < 0 or percentage_tolerance < 0:
        raise ValueError("reconciliation tolerances must be non-negative")
    canonical = merge_slices(canonical_rows)
    provider = merge_slices(provider_rows)
    comparisons: list[Comparison] = []
    for key in sorted(canonical.keys() | provider.keys()):
        ours, theirs = canonical.get(key), provider.get(key)
        ours_cost = ours.cost_micro_usd if ours else 0
        provider_cost = theirs.cost_micro_usd if theirs else 0
        variance = provider_cost - ours_cost
        pct_limit = int(
            (Decimal(abs(provider_cost)) * percentage_tolerance / Decimal("100"))
            .to_integral_value()
        )
        within = abs(variance) <= max(absolute_tolerance_micro_usd, pct_limit)
        token_delta = {
            category: (theirs.tokens.get(category, 0) if theirs else 0)
            - (ours.tokens.get(category, 0) if ours else 0)
            for category in ("input", "output", "cache_read", "cache_write", "reasoning")
        }

        if theirs and (theirs.kind == "credit" or theirs.cost_micro_usd < 0):
            classification: Classification = "provider_adjustment_credit"
        elif theirs and theirs.late_arrival:
            classification = "timing_lag"
        elif ours is None and theirs is not None:
            classification = "missing_event"
        elif ours is not None and theirs is None:
            classification = "unresolved"
        elif ours and ours.duplicate_count > 0:
            classification = "duplicate_event"
        elif any(token_delta.values()):
            classification = "token_category_mismatch"
        elif not within:
            classification = "price_catalog_mismatch"
        elif ours is not None and theirs is not None:
            classification = "matched"
        else:
            classification = "unresolved"
        comparisons.append(
            Comparison(
                dimension_key=key,
                classification=classification,
                canonical=ours,
                provider=theirs,
                variance_micro_usd=variance,
                within_tolerance=within,
                details={"token_delta": token_delta, "tolerance_micro_usd": max(absolute_tolerance_micro_usd, pct_limit)},
            )
        )
    return comparisons


__all__ = ["Comparison", "UsageSlice", "compare_usage", "merge_slices", "opaque_dimension"]
