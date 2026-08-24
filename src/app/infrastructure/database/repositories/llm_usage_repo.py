"""Append-only persistence for immutable LLM usage events."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Literal, Sequence

from sqlalchemy import select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.shared.lib.llm_usage import (
    BILLABLE_CATEGORIES,
    NormalizedUsage,
    PriceSnapshot,
    PricedUsage,
    Rate,
)
from app.shared.lib.llm_estimation import UsageObservation


_RAW_USAGE_MAX_BYTES = 64 * 1024
_QUALITY_ORDER = {"exact": 0, "normalized": 1, "estimated": 2, "unknown": 3}


def build_usage_idempotency_key(
    *,
    operation_kind: Literal["scan", "chat", "rag"],
    operation_id: str | uuid.UUID,
    stage: str,
    agent_name: str,
    unit_key: str,
    llm_config_id: str | uuid.UUID,
) -> str:
    """Build a bounded, non-sensitive identity for one logical model call.

    Paths, chat contents, and document identifiers may contain tenant data, so
    only the operation/stage prefix remains readable. Everything identifying
    the individual work unit is represented by a canonical SHA-256 digest.
    """
    payload = json.dumps(
        {
            "agent_name": agent_name,
            "llm_config_id": str(llm_config_id),
            "operation_id": str(operation_id),
            "operation_kind": operation_kind,
            "stage": stage,
            "unit_key": unit_key,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(payload).hexdigest()
    return f"{operation_kind}:{operation_id}:{stage}:{digest}"


@dataclass(frozen=True)
class LLMUsageContext:
    operation_kind: Literal["scan", "chat", "rag"]
    operation_id: str
    stage: str
    agent_name: str
    idempotency_key: str
    scan_id: uuid.UUID | None = None
    chat_session_id: uuid.UUID | None = None
    rag_job_id: uuid.UUID | None = None
    scan_task_id: uuid.UUID | None = None
    actor_user_id: int | None = None


@dataclass(frozen=True)
class LLMUsageRequestWrite:
    request_index: int
    normalized: NormalizedUsage
    priced: PricedUsage
    requested_model: str
    resolved_model: str | None
    provider_response_id: str | None
    received_at: datetime
    provider_usage: dict[str, Any]
    price_snapshot: PriceSnapshot | None = None
    api_flavor: str | None = None
    service_tier: str | None = None
    is_batch: bool | None = None
    region: str | None = None


@dataclass(frozen=True)
class LLMUsageRecordResult:
    event: db_models.LLMUsageEvent
    created: bool


def _bounded_json(payload: dict[str, Any]) -> dict[str, Any]:
    encoded = json.dumps(
        payload,
        default=str,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if len(encoded) <= _RAW_USAGE_MAX_BYTES:
        return payload
    return {
        "_truncated": True,
        "original_size_bytes": len(encoded),
        "sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _snapshot_json(snapshot: PriceSnapshot | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None
    return {
        "source": snapshot.source,
        "effective_at": snapshot.effective_at.isoformat(),
        "currency": snapshot.currency,
        "rates": {
            category: {
                "amount": str(rate.amount),
                "unit": rate.unit,
                "modifier": str(rate.modifier),
            }
            for category, rate in sorted(snapshot.rates.items())
        },
        "catalog_metadata": _bounded_json(dict(snapshot.catalog_metadata)),
    }


def _parse_override_rates(payload: dict[str, Any]) -> dict[str, Rate]:
    rates: dict[str, Rate] = {}
    if set(payload) != BILLABLE_CATEGORIES:
        raise ValueError(
            "price override must contain the complete billable category set"
        )
    for category, value in payload.items():
        if not isinstance(value, dict):
            raise ValueError(f"price override category {category} must be an object")
        amount = Decimal(str(value["amount"]))
        modifier = Decimal(str(value.get("modifier", "1")))
        unit = value["unit"]
        if amount < 0 or modifier < 0:
            raise ValueError("price override amount and modifier must be non-negative")
        if unit not in {
            "million_tokens",
            "thousand_requests",
            "second",
            "byte_month",
        }:
            raise ValueError(f"unsupported price unit: {unit}")
        expected_unit = (
            "thousand_requests" if category == "provider_request" else "million_tokens"
        )
        if unit != expected_unit:
            raise ValueError(
                f"price override category {category} must use {expected_unit}"
            )
        rates[category] = Rate(
            amount=amount,
            unit=unit,
            modifier=modifier,
        )
    return rates


def _override_snapshot(row: db_models.LLMPriceOverride) -> PriceSnapshot:
    rates = _parse_override_rates(row.rates)
    return PriceSnapshot(
        source=f"admin:{row.source}:version:{row.id}",
        effective_at=row.effective_from,
        currency=row.currency,
        rates=rates,
        catalog_metadata={"price_override_id": str(row.id)},
    )


class LLMPriceOverrideRepository:
    """Append and resolve non-overlapping complete admin price versions."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_for_config(
        self, llm_config_id: uuid.UUID
    ) -> list[db_models.LLMPriceOverride]:
        return list(
            (
                await self.db.scalars(
                    select(db_models.LLMPriceOverride)
                    .where(db_models.LLMPriceOverride.llm_config_id == llm_config_id)
                    .order_by(db_models.LLMPriceOverride.effective_from.desc())
                )
            ).all()
        )

    async def active_snapshot(
        self,
        llm_config_id: uuid.UUID,
        *,
        at: datetime | None = None,
    ) -> PriceSnapshot | None:
        effective_at = at or datetime.now(timezone.utc)
        row = await self.db.scalar(
            select(db_models.LLMPriceOverride)
            .where(
                db_models.LLMPriceOverride.llm_config_id == llm_config_id,
                db_models.LLMPriceOverride.effective_from <= effective_at,
                (
                    db_models.LLMPriceOverride.effective_to.is_(None)
                    | (db_models.LLMPriceOverride.effective_to > effective_at)
                ),
            )
            .order_by(db_models.LLMPriceOverride.effective_from.desc())
            .limit(1)
        )
        return _override_snapshot(row) if row is not None else None

    async def append(
        self,
        *,
        llm_config_id: uuid.UUID,
        rates: dict[str, Any],
        currency: str,
        source: str,
        created_by_user_id: int,
        effective_from: datetime | None = None,
    ) -> db_models.LLMPriceOverride:
        starts_at = effective_from or datetime.now(timezone.utc)
        config = await self.db.scalar(
            select(db_models.LLMConfiguration)
            .where(db_models.LLMConfiguration.id == llm_config_id)
            .with_for_update()
        )
        if config is None:
            raise ValueError("LLM configuration not found")
        if set(rates) != BILLABLE_CATEGORIES:
            missing = sorted(BILLABLE_CATEGORIES - set(rates))
            extra = sorted(set(rates) - BILLABLE_CATEGORIES)
            raise ValueError(
                f"price override categories must be complete; missing={missing}, extra={extra}"
            )
        _parse_override_rates(rates)
        active = await self.db.scalar(
            select(db_models.LLMPriceOverride)
            .where(
                db_models.LLMPriceOverride.llm_config_id == llm_config_id,
                db_models.LLMPriceOverride.effective_to.is_(None),
            )
            .with_for_update()
        )
        if active is not None:
            if starts_at <= active.effective_from:
                raise ValueError(
                    "new price version must start after the active version"
                )
            active.effective_to = starts_at
        row = db_models.LLMPriceOverride(
            llm_config_id=llm_config_id,
            rates=rates,
            currency=currency.upper(),
            source=source,
            effective_from=starts_at,
            created_by_user_id=created_by_user_id,
        )
        self.db.add(row)
        await self.db.commit()
        await self.db.refresh(row)
        return row


class LLMUsageRepository:
    """Record one logical run once, including every request and line item."""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def reserve_provider_call(
        self,
        *,
        idempotency_key: str,
        scan_id: uuid.UUID,
        llm_config_id: uuid.UUID,
        stage: str,
    ) -> uuid.UUID | None:
        """Claim a logical provider call once before any billable request."""
        owner_token = uuid.uuid4()
        attempt_id = await self.db.scalar(
            select(db_models.Scan.current_attempt_id).where(
                db_models.Scan.id == scan_id
            )
        )
        inserted = await self.db.scalar(
            pg_insert(db_models.LLMCallReservation)
            .values(
                id=uuid.uuid4(),
                idempotency_key=idempotency_key,
                owner_token=owner_token,
                scan_id=scan_id,
                attempt_id=attempt_id,
                llm_config_id=llm_config_id,
                stage=stage,
                status="reserved",
            )
            .on_conflict_do_nothing(index_elements=["idempotency_key"])
            .returning(db_models.LLMCallReservation.owner_token)
        )
        await self.db.commit()
        return inserted

    async def has_provider_call_reservation(self, *, idempotency_key: str) -> bool:
        return (
            await self.db.scalar(
                select(db_models.LLMCallReservation.id).where(
                    db_models.LLMCallReservation.idempotency_key == idempotency_key
                )
            )
        ) is not None

    async def finish_provider_call_reservation(
        self,
        *,
        idempotency_key: str,
        owner_token: uuid.UUID,
        status: Literal["completed", "failed"],
        usage_event_id: uuid.UUID | None,
    ) -> bool:
        result = await self.db.execute(
            update(db_models.LLMCallReservation)
            .where(
                db_models.LLMCallReservation.idempotency_key == idempotency_key,
                db_models.LLMCallReservation.owner_token == owner_token,
                db_models.LLMCallReservation.status == "reserved",
            )
            .values(
                status=status,
                usage_event_id=usage_event_id,
                completed_at=datetime.now(timezone.utc),
            )
        )
        await self.db.commit()
        return bool(result.rowcount)

    async def get_retained_interaction(self, *, idempotency_key: str) -> tuple[
        db_models.LLMUsageEvent | None,
        db_models.LLMInteraction | None,
    ]:
        """Load the canonical usage event and its retained audit projection.

        The left join deliberately distinguishes a never-run logical call from
        a paid call whose interaction is missing, incomplete, or expired.  A
        caller may invoke the provider only for the former case.
        """
        row = (
            await self.db.execute(
                select(db_models.LLMUsageEvent, db_models.LLMInteraction)
                .outerjoin(
                    db_models.LLMInteraction,
                    db_models.LLMInteraction.usage_event_id
                    == db_models.LLMUsageEvent.id,
                )
                .where(db_models.LLMUsageEvent.idempotency_key == idempotency_key)
            )
        ).one_or_none()
        if row is None:
            return None, None
        return row[0], row[1]

    async def recent_estimation_observations(
        self,
        *,
        llm_config_id: uuid.UUID,
        stage: str,
        limit: int = 200,
    ) -> list[UsageObservation]:
        """Read bounded, provider-reported history for preflight calibration.

        Estimated/unknown usage is intentionally excluded so an estimate never
        trains on another estimate. Aggregate event tokens include retries and
        structured-output repair calls; ``request_count`` makes that expansion
        explicit to the range calculator.
        """
        rows = (
            await self.db.execute(
                select(
                    db_models.LLMUsageEvent.input_tokens,
                    db_models.LLMUsageEvent.output_tokens,
                    db_models.LLMUsageEvent.request_count,
                )
                .where(
                    db_models.LLMUsageEvent.llm_config_id == llm_config_id,
                    db_models.LLMUsageEvent.stage == stage,
                    db_models.LLMUsageEvent.usage_source.in_(
                        ("provider", "reconciled")
                    ),
                    db_models.LLMUsageEvent.quality_state.in_(("exact", "normalized")),
                    db_models.LLMUsageEvent.input_tokens > 0,
                )
                .order_by(db_models.LLMUsageEvent.created_at.desc())
                .limit(max(1, min(limit, 1000)))
            )
        ).all()
        return [
            UsageObservation(
                input_tokens=int(row.input_tokens),
                output_tokens=int(row.output_tokens),
                request_count=int(row.request_count),
            )
            for row in rows
        ]

    async def measure_scan_estimate_variance(
        self,
        *,
        scan_id: uuid.UUID,
        stage: str,
        commit: bool = True,
    ) -> dict[str, Any] | None:
        """Attach actual-vs-expected feedback to a completed scan estimate."""
        scan = await self.db.scalar(
            select(db_models.Scan).where(db_models.Scan.id == scan_id).with_for_update()
        )
        if scan is None or not scan.cost_details:
            return None
        events = list(
            (
                await self.db.scalars(
                    select(db_models.LLMUsageEvent).where(
                        db_models.LLMUsageEvent.scan_id == scan_id,
                        db_models.LLMUsageEvent.stage == stage,
                    )
                )
            ).all()
        )
        if not events:
            return None

        details = dict(scan.cost_details)
        actual_input_tokens = sum(int(event.input_tokens) for event in events)
        actual_output_tokens = sum(int(event.output_tokens) for event in events)
        exact_costs = [
            event.total_cost
            for event in events
            if event.cost_status == "exact" and event.total_cost is not None
        ]
        actual_cost = (
            sum(exact_costs, Decimal("0")) if len(exact_costs) == len(events) else None
        )
        expected_raw = details.get("expected_estimated_cost")
        if expected_raw is None:
            expected_raw = details.get("total_estimated_cost")
        expected_cost = (
            Decimal(str(expected_raw))
            if expected_raw is not None and not isinstance(expected_raw, bool)
            else None
        )
        upper_raw = details.get("upper_bound_estimated_cost")
        upper_cost = (
            Decimal(str(upper_raw))
            if upper_raw is not None and not isinstance(upper_raw, bool)
            else None
        )

        feedback: dict[str, Any] = {
            "stage": stage,
            "actual_input_tokens": actual_input_tokens,
            "actual_output_tokens": actual_output_tokens,
            "usage_event_count": len(events),
            "actual_cost_status": "exact" if actual_cost is not None else "unknown",
            "actual_cost": float(actual_cost) if actual_cost is not None else None,
        }
        if actual_cost is not None and expected_cost is not None:
            variance = actual_cost - expected_cost
            feedback["cost_variance"] = float(variance)
            feedback["cost_variance_percent"] = (
                float((variance / expected_cost) * Decimal("100"))
                if expected_cost > 0
                else None
            )
            feedback["within_upper_bound"] = (
                actual_cost <= upper_cost if upper_cost is not None else None
            )
        details["estimate_variance"] = feedback
        scan.cost_details = details
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return feedback

    async def _resolve_attribution(
        self, context: LLMUsageContext
    ) -> tuple[int | None, uuid.UUID | None, list[uuid.UUID]]:
        user_id: int | None = None
        tenant_id: uuid.UUID | None = None
        if context.operation_kind == "scan":
            if context.scan_id is None:
                raise ValueError("scan usage context requires scan_id")
            row = (
                await self.db.execute(
                    select(db_models.Scan.user_id, db_models.Scan.tenant_id).where(
                        db_models.Scan.id == context.scan_id
                    )
                )
            ).one_or_none()
        elif context.operation_kind == "chat":
            if context.chat_session_id is not None:
                row = (
                    await self.db.execute(
                        select(
                            db_models.ChatSession.user_id,
                            db_models.ChatSession.tenant_id,
                        ).where(db_models.ChatSession.id == context.chat_session_id)
                    )
                ).one_or_none()
            elif context.actor_user_id is not None:
                # Authenticated one-shot channels (for example MCP) have no
                # durable chat session. Resolve their attribution from the
                # server-side user identity, never from client-supplied tenancy.
                row = (
                    await self.db.execute(
                        select(db_models.User.id, db_models.User.tenant_id).where(
                            db_models.User.id == context.actor_user_id
                        )
                    )
                ).one_or_none()
            else:
                raise ValueError(
                    "chat usage context requires chat_session_id or actor_user_id"
                )
        else:
            if context.rag_job_id is None:
                raise ValueError("rag usage context requires rag_job_id")
            row = (
                await self.db.execute(
                    select(
                        db_models.RAGPreprocessingJob.user_id,
                        db_models.User.tenant_id,
                    )
                    .join(
                        db_models.User,
                        db_models.User.id == db_models.RAGPreprocessingJob.user_id,
                    )
                    .where(db_models.RAGPreprocessingJob.id == context.rag_job_id)
                )
            ).one_or_none()
        if row is None:
            raise ValueError("usage operation does not exist")
        user_id, tenant_id = row
        group_ids = list(
            (
                await self.db.scalars(
                    select(db_models.UserGroupMembership.group_id)
                    .join(
                        db_models.UserGroup,
                        db_models.UserGroup.id
                        == db_models.UserGroupMembership.group_id,
                    )
                    .where(
                        db_models.UserGroupMembership.user_id == user_id,
                        db_models.UserGroup.tenant_id == tenant_id,
                    )
                    .order_by(db_models.UserGroupMembership.group_id)
                )
            ).all()
        )
        return user_id, tenant_id, group_ids

    async def record(
        self,
        *,
        context: LLMUsageContext,
        llm_config_id: uuid.UUID,
        provider: str,
        requested_model: str,
        tool_call_count: int,
        requests: Sequence[LLMUsageRequestWrite],
    ) -> LLMUsageRecordResult:
        if not requests:
            raise ValueError("at least one provider request is required")
        if len(context.idempotency_key) > 512:
            raise ValueError("usage idempotency key exceeds 512 characters")
        expected_indexes = list(range(1, len(requests) + 1))
        if [request.request_index for request in requests] != expected_indexes:
            raise ValueError("usage request indexes must be contiguous and one-based")

        existing = await self.db.scalar(
            select(db_models.LLMUsageEvent).where(
                db_models.LLMUsageEvent.idempotency_key == context.idempotency_key
            )
        )
        if existing is not None:
            return LLMUsageRecordResult(existing, created=False)

        user_id, tenant_id, group_ids = await self._resolve_attribution(context)
        attempt_id = None
        if context.scan_id is not None:
            attempt_id = await self.db.scalar(
                select(db_models.Scan.current_attempt_id).where(
                    db_models.Scan.id == context.scan_id
                )
            )
        request_costs = [request.priced.total_amount for request in requests]
        currencies = {
            request.priced.currency
            for request in requests
            if request.priced.currency is not None
        }
        all_exact = len(currencies) == 1 and all(
            request.priced.cost_status == "exact" and cost is not None
            for request, cost in zip(requests, request_costs)
        )
        total_cost = (
            sum((cost for cost in request_costs if cost is not None), Decimal("0"))
            if all_exact
            else None
        )
        qualities = [request.normalized.quality_state for request in requests]
        quality_state = max(qualities, key=_QUALITY_ORDER.__getitem__)
        event_id = uuid.uuid4()
        event_values = {
            "id": event_id,
            "idempotency_key": context.idempotency_key,
            "operation_kind": context.operation_kind,
            "operation_id": context.operation_id,
            "scan_id": context.scan_id,
            "attempt_id": attempt_id,
            "chat_session_id": context.chat_session_id,
            "rag_job_id": context.rag_job_id,
            "scan_task_id": context.scan_task_id,
            "stage": context.stage,
            "agent_name": context.agent_name,
            "llm_config_id": llm_config_id,
            "user_id": user_id,
            "tenant_id": tenant_id,
            "group_ids": group_ids,
            "provider": provider,
            "requested_model": requested_model,
            "resolved_models": sorted(
                {
                    request.resolved_model
                    for request in requests
                    if request.resolved_model
                }
            ),
            "request_count": len(requests),
            "tool_call_count": max(0, tool_call_count),
            "input_tokens": sum(r.normalized.input_tokens for r in requests),
            "output_tokens": sum(r.normalized.output_tokens for r in requests),
            "total_tokens": sum(r.normalized.total_tokens for r in requests),
            "cache_read_tokens": sum(r.normalized.cache_read_tokens for r in requests),
            "cache_write_tokens": sum(
                r.normalized.cache_write_tokens for r in requests
            ),
            "reasoning_tokens": sum(r.normalized.reasoning_tokens for r in requests),
            "usage_source": (
                requests[0].normalized.usage_source
                if len({r.normalized.usage_source for r in requests}) == 1
                else "reconciled"
            ),
            "quality_state": quality_state,
            "cost_status": "exact" if all_exact else "unknown",
            "currency": requests[0].priced.currency if all_exact else None,
            "total_cost": total_cost,
        }
        inserted_id = await self.db.scalar(
            pg_insert(db_models.LLMUsageEvent)
            .values(**event_values)
            .on_conflict_do_nothing(index_elements=["idempotency_key"])
            .returning(db_models.LLMUsageEvent.id)
        )
        if inserted_id is None:
            await self.db.rollback()
            event = await self.db.scalar(
                select(db_models.LLMUsageEvent).where(
                    db_models.LLMUsageEvent.idempotency_key == context.idempotency_key
                )
            )
            if event is None:  # pragma: no cover - defensive split-brain guard
                raise RuntimeError("usage idempotency conflict row disappeared")
            return LLMUsageRecordResult(event, created=False)

        for request in requests:
            request_id = uuid.uuid4()
            normalized = request.normalized
            priced = request.priced
            self.db.add(
                db_models.LLMUsageRequest(
                    id=request_id,
                    usage_event_id=event_id,
                    request_index=request.request_index,
                    provider_response_id=request.provider_response_id,
                    provider=normalized.provider,
                    requested_model=request.requested_model,
                    resolved_model=request.resolved_model,
                    api_flavor=request.api_flavor,
                    service_tier=request.service_tier,
                    is_batch=request.is_batch,
                    region=request.region,
                    input_tokens=normalized.input_tokens,
                    output_tokens=normalized.output_tokens,
                    total_tokens=normalized.total_tokens,
                    uncached_input_tokens=normalized.uncached_input_tokens,
                    cache_read_tokens=normalized.cache_read_tokens,
                    cache_write_tokens=normalized.cache_write_tokens,
                    reasoning_tokens=normalized.reasoning_tokens,
                    input_audio_tokens=normalized.input_audio_tokens,
                    output_audio_tokens=normalized.output_audio_tokens,
                    image_input_tokens=normalized.image_input_tokens,
                    image_output_tokens=normalized.image_output_tokens,
                    tool_request_tokens=normalized.tool_request_tokens,
                    provider_usage=_bounded_json(request.provider_usage),
                    usage_source=normalized.usage_source,
                    quality_state=normalized.quality_state,
                    quality_reasons=list(normalized.quality_reasons),
                    price_snapshot=_snapshot_json(request.price_snapshot),
                    cost_status=priced.cost_status,
                    currency=priced.currency,
                    total_cost=priced.total_amount,
                    received_at=request.received_at,
                )
            )
            # No ORM relationships are declared on these append-only rows; flush the
            # parent explicitly so SQLAlchemy cannot batch a line item ahead of it.
            await self.db.flush()
            for index, item in enumerate(priced.line_items, start=1):
                self.db.add(
                    db_models.LLMUsageLineItem(
                        usage_request_id=request_id,
                        line_index=index,
                        **asdict(item),
                    )
                )
        await self.db.commit()
        event = await self.db.get(db_models.LLMUsageEvent, event_id)
        if event is None:  # pragma: no cover - defensive
            raise RuntimeError("inserted usage event could not be reloaded")
        return LLMUsageRecordResult(event, created=True)
