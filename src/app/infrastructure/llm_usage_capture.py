"""Capture Pydantic AI request usage and persist it through the canonical ledger."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from genai_prices.types import TieredPrices
from pydantic_ai.messages import ModelResponse

from app.infrastructure.database import AsyncSessionLocal as async_session_factory
from app.infrastructure.database.repositories.llm_usage_repo import (
    LLMUsageContext,
    LLMPriceOverrideRepository,
    LLMUsageRepository,
    LLMUsageRequestWrite,
)
from app.shared.lib.llm_usage import (
    PriceSnapshot,
    Rate,
    normalize_request_usage,
    price_normalized_usage,
)


def _run_usage(run_result: Any) -> Any:
    """Read Pydantic AI's property API while tolerating pre-migration doubles."""

    usage = run_result.usage
    if hasattr(usage, "input_tokens"):
        return usage
    if callable(usage):
        return usage()
    return usage


def _effective_at(config: Any) -> datetime:
    value = getattr(config, "updated_at", None) or getattr(config, "created_at", None)
    if not isinstance(value, datetime):
        return datetime.now(timezone.utc)
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _admin_snapshot(config: Any) -> PriceSnapshot | None:
    try:
        input_rate = Decimal(str(config.input_cost_per_million or 0))
        output_rate = Decimal(str(config.output_cost_per_million or 0))
    except (AttributeError, TypeError, ValueError):
        return None
    if input_rate <= 0 and output_rate <= 0:
        return None
    if input_rate <= 0 or output_rate <= 0:
        # A partial override is not allowed to mix with catalog categories.
        return PriceSnapshot(
            source=f"admin:llm_config:{config.id}:incomplete",
            effective_at=_effective_at(config),
            currency="USD",
            rates={},
            catalog_metadata={"incomplete_override": True},
        )
    return PriceSnapshot(
        source=f"admin:llm_config:{config.id}:legacy",
        effective_at=_effective_at(config),
        currency="USD",
        rates={
            "uncached_input": Rate(input_rate, "million_tokens"),
            "image_input": Rate(input_rate, "million_tokens"),
            "non_reasoning_output": Rate(output_rate, "million_tokens"),
            "reasoning_output": Rate(output_rate, "million_tokens"),
            "image_output": Rate(output_rate, "million_tokens"),
        },
        catalog_metadata={"legacy_two_rate_override": True},
    )


def _resolve_rate(value: Any, total_input_tokens: int) -> Decimal | None:
    if value is None:
        return None
    if isinstance(value, TieredPrices):
        selected = value.base
        for tier in value.tiers:
            if total_input_tokens >= tier.start:
                selected = tier.price
        return Decimal(selected)
    return Decimal(value)


def _catalog_snapshot(response: ModelResponse) -> PriceSnapshot | None:
    try:
        calculation = response.cost()
    except (AssertionError, LookupError, ValueError):
        return None
    price = calculation.model_price
    total_input = int(response.usage.input_tokens or 0)
    category_fields = {
        "uncached_input": price.input_mtok,
        "image_input": price.input_mtok,
        "cache_write_input": price.cache_write_mtok,
        "cache_read_input": price.cache_read_mtok,
        "input_audio": price.input_audio_mtok,
        "cache_audio_read": price.cache_audio_read_mtok,
        "non_reasoning_output": price.output_mtok,
        "reasoning_output": price.output_mtok,
        "image_output": price.output_mtok,
        "output_audio": price.output_audio_mtok,
    }
    rates = {
        category: Rate(rate, "million_tokens")
        for category, raw_rate in category_fields.items()
        if (rate := _resolve_rate(raw_rate, total_input)) is not None
    }
    if price.requests_kcount is not None:
        rates["provider_request"] = Rate(
            Decimal(price.requests_kcount), "thousand_requests"
        )
    updated = calculation.auto_update_timestamp
    effective_at = updated or response.timestamp
    if effective_at.tzinfo is None:
        effective_at = effective_at.replace(tzinfo=timezone.utc)
    return PriceSnapshot(
        source="genai-prices",
        effective_at=effective_at,
        currency="USD",
        rates=rates,
        catalog_metadata={
            "provider": response.provider_name,
            "provider_url": response.provider_url,
            "resolved_model": response.model_name,
            "catalog_auto_update_timestamp": updated.isoformat() if updated else None,
        },
    )


def _price_snapshot(
    response: ModelResponse,
    config: Any,
    effective_override: PriceSnapshot | None = None,
) -> PriceSnapshot | None:
    if effective_override is not None:
        return effective_override
    admin = _admin_snapshot(config)
    return admin if admin is not None else _catalog_snapshot(response)


def build_request_writes(
    run_result: Any,
    config: Any,
    effective_override: PriceSnapshot | None = None,
) -> tuple[LLMUsageRequestWrite, ...]:
    """Extract and price each provider response in one Pydantic AI run."""

    responses = [
        message
        for message in run_result.new_messages()
        if isinstance(message, ModelResponse)
    ]
    writes: list[LLMUsageRequestWrite] = []
    for index, response in enumerate(responses, start=1):
        provider = response.provider_name or str(config.provider).lower()
        normalized = normalize_request_usage(provider, response.usage)
        snapshot = _price_snapshot(response, config, effective_override)
        provider_details = response.provider_details or {}
        writes.append(
            LLMUsageRequestWrite(
                request_index=index,
                normalized=normalized,
                priced=price_normalized_usage(normalized, snapshot),
                requested_model=str(config.model_name),
                resolved_model=response.model_name,
                provider_response_id=response.provider_response_id,
                received_at=response.timestamp,
                provider_usage={
                    "input_tokens": normalized.input_tokens,
                    "output_tokens": normalized.output_tokens,
                    "cache_read_tokens": normalized.cache_read_tokens,
                    "cache_write_tokens": normalized.cache_write_tokens,
                    "input_audio_tokens": normalized.input_audio_tokens,
                    "cache_audio_read_tokens": normalized.cache_audio_read_tokens,
                    "details": dict(normalized.provider_details),
                },
                price_snapshot=snapshot,
                api_flavor=(
                    str(provider_details["api_flavor"])
                    if provider_details.get("api_flavor") is not None
                    else None
                ),
                service_tier=(
                    str(provider_details["service_tier"])
                    if provider_details.get("service_tier") is not None
                    else None
                ),
                is_batch=(
                    bool(provider_details["batch"])
                    if provider_details.get("batch") is not None
                    else None
                ),
                region=(
                    str(provider_details["region"])
                    if provider_details.get("region") is not None
                    else None
                ),
            )
        )
    return tuple(writes)


async def record_run_usage(
    *,
    run_result: Any,
    context: LLMUsageContext,
    config: Any,
    effective_override: PriceSnapshot | None = None,
) -> tuple[uuid.UUID, Decimal | None, bool]:
    requests = build_request_writes(run_result, config, effective_override)
    if not requests:
        raise ValueError("successful LLM run exposed no provider response usage")
    run_usage = _run_usage(run_result)
    async with async_session_factory() as db:
        result = await LLMUsageRepository(db).record(
            context=context,
            llm_config_id=config.id,
            provider=str(config.provider).lower(),
            requested_model=str(config.model_name),
            tool_call_count=int(run_usage.tool_calls or 0),
            requests=requests,
        )
    return result.event.id, result.event.total_cost, result.created


async def load_active_price_override(config_id: uuid.UUID) -> PriceSnapshot | None:
    """Freeze the active admin price version before contacting a provider."""
    async with async_session_factory() as db:
        return await LLMPriceOverrideRepository(db).active_snapshot(config_id)
