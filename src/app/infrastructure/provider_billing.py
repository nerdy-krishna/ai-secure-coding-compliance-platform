"""Read-only provider billing connectors.

Only provider usage/cost endpoints are called.  Credentials are supplied by the
service after decryption and are never retained on the connector object or logged.
"""

from __future__ import annotations

import json
import hashlib
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal
from typing import Any, Protocol

import httpx

from app.shared.lib.provider_reconciliation import UsageSlice


class ProviderBillingUnavailable(RuntimeError):
    """The provider could not return a complete billing window."""


@dataclass(frozen=True, slots=True)
class ProviderPage:
    rows: tuple[UsageSlice, ...]
    next_cursor: str | None


class ProviderBillingClient(Protocol):
    async def fetch_page(
        self, *, window_start: datetime, window_end: datetime, cursor: str | None
    ) -> ProviderPage: ...


class OpenAIOrganizationBillingClient:
    """Minimal OpenAI organization usage reader using a read-only admin key."""

    _USAGE_URL = "https://api.openai.com/v1/organization/usage/completions"
    _COST_URL = "https://api.openai.com/v1/organization/costs"

    def __init__(
        self,
        *,
        api_key: str,
        project_ids: tuple[str, ...] = (),
        client: httpx.AsyncClient | None = None,
    ) -> None:
        if not api_key:
            raise ValueError("provider billing API key is required")
        self._api_key = api_key
        self._project_ids = project_ids
        self._client = client

    async def fetch_page(
        self, *, window_start: datetime, window_end: datetime, cursor: str | None
    ) -> ProviderPage:
        state = json.loads(cursor) if cursor else {}
        if not isinstance(state, dict):
            raise ProviderBillingUnavailable("invalid_pagination_cursor")
        common_params: list[tuple[str, str | int]] = [
            ("start_time", int(window_start.timestamp())),
            ("end_time", int(window_end.timestamp())),
            ("bucket_width", "1d"),
            ("limit", 31),
        ]
        common_params.extend(
            ("project_ids[]", project_id) for project_id in self._project_ids
        )
        usage_params = [
            *common_params,
            ("group_by[]", "model"),
            ("group_by[]", "project_id"),
            ("group_by[]", "api_key_id"),
            ("group_by[]", "service_tier"),
            ("group_by[]", "batch"),
        ]
        cost_params = [
            *common_params,
            ("group_by[]", "project_id"),
            ("group_by[]", "api_key_id"),
            ("group_by[]", "line_item"),
        ]
        if state.get("usage"):
            usage_params.append(("page", state["usage"]))
        if state.get("cost"):
            cost_params.append(("page", state["cost"]))
        usage_payload = (
            {}
            if state.get("usage_done")
            else await self._fetch_json(self._USAGE_URL, usage_params)
        )
        cost_payload = (
            {}
            if state.get("cost_done")
            else await self._fetch_json(self._COST_URL, cost_params)
        )
        rows: list[UsageSlice] = []
        for bucket in usage_payload.get("data", ()):
            provider_bucket_start = datetime.fromtimestamp(
                int(bucket["start_time"]), tz=window_start.tzinfo
            )
            provider_bucket_end = datetime.fromtimestamp(
                int(bucket["end_time"]), tz=window_start.tzinfo
            )
            for item in bucket.get("results", ()):
                rows.append(
                    UsageSlice(
                        provider="openai",
                        window_start=window_start,
                        window_end=window_end,
                        model=item.get("model"),
                        project=item.get("project_id"),
                        api_key=item.get("api_key_id"),
                        service_tier=item.get("service_tier"),
                        is_batch=item.get("batch"),
                        input_tokens=int(item.get("input_tokens", 0)),
                        output_tokens=int(item.get("output_tokens", 0)),
                        cache_read_tokens=int(item.get("input_cached_tokens", 0)),
                        reasoning_tokens=int(item.get("output_reasoning_tokens", 0)),
                        cost_micro_usd=0,
                        external_id=item.get("id")
                        or _stable_item_id(
                            "usage",
                            bucket.get("start_time"),
                            bucket.get("end_time"),
                            item,
                        ),
                        metadata={
                            "provider_bucket_start": provider_bucket_start.isoformat(),
                            "provider_bucket_end": provider_bucket_end.isoformat(),
                        },
                    )
                )
        for bucket in cost_payload.get("data", ()):
            for item in bucket.get("results", ()):
                amount = item.get("amount") or {}
                value = amount.get("value", 0) if isinstance(amount, dict) else amount
                currency = (
                    amount.get("currency", "usd") if isinstance(amount, dict) else "usd"
                )
                micro_usd = _micro_usd(value)
                line_item = str(item.get("line_item") or "")
                rows.append(
                    UsageSlice(
                        provider="openai",
                        window_start=window_start,
                        window_end=window_end,
                        model=None,
                        project=item.get("project_id"),
                        api_key=item.get("api_key_id"),
                        currency=currency,
                        cost_micro_usd=micro_usd,
                        external_id=_stable_item_id(
                            "cost",
                            bucket.get("start_time"),
                            bucket.get("end_time"),
                            item,
                        ),
                        kind=(
                            "credit"
                            if micro_usd < 0 or "credit" in line_item.lower()
                            else "cost"
                        ),
                        metadata={
                            "line_item": line_item[:100],
                            "provider_bucket_start": datetime.fromtimestamp(
                                int(bucket["start_time"]), tz=window_start.tzinfo
                            ).isoformat(),
                            "provider_bucket_end": datetime.fromtimestamp(
                                int(bucket["end_time"]), tz=window_start.tzinfo
                            ).isoformat(),
                        },
                    )
                )
        next_state = {
            "usage": usage_payload.get("next_page"),
            "usage_done": not bool(usage_payload.get("has_more")),
            "cost": cost_payload.get("next_page"),
            "cost_done": not bool(cost_payload.get("has_more")),
        }
        next_cursor = (
            None
            if next_state["usage_done"] and next_state["cost_done"]
            else json.dumps(next_state, sort_keys=True, separators=(",", ":"))
        )
        return ProviderPage(rows=tuple(rows), next_cursor=next_cursor)

    async def _fetch_json(
        self, url: str, params: list[tuple[str, str | int]]
    ) -> dict[str, Any]:
        headers = {"Authorization": f"Bearer {self._api_key}"}
        try:
            if self._client is not None:
                response = await self._client.get(url, params=params, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, dict):
                raise TypeError("provider payload is not an object")
            return payload
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            raise ProviderBillingUnavailable(type(exc).__name__) from exc


def _micro_usd(value: Any) -> int:
    try:
        return int((Decimal(str(value)) * Decimal("1000000")).to_integral_value())
    except Exception:
        return 0


def _stable_item_id(kind: str, start: Any, end: Any, item: dict[str, Any]) -> str:
    # Hash raw attribution instead of persisting provider project/API-key IDs.
    payload = json.dumps(
        {"kind": kind, "start": start, "end": end, "item": item},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


async def fetch_all_pages(
    client: ProviderBillingClient,
    *,
    window_start: datetime,
    window_end: datetime,
    max_pages: int = 100,
) -> tuple[list[UsageSlice], int]:
    rows: list[UsageSlice] = []
    cursor: str | None = None
    seen: set[str] = set()
    pages = 0
    while True:
        page = await client.fetch_page(
            window_start=window_start, window_end=window_end, cursor=cursor
        )
        pages += 1
        rows.extend(page.rows)
        if page.next_cursor is None:
            return rows, pages
        if pages >= max_pages or page.next_cursor in seen:
            raise ProviderBillingUnavailable("pagination_incomplete")
        seen.add(page.next_cursor)
        cursor = page.next_cursor


__all__ = [
    "OpenAIOrganizationBillingClient",
    "ProviderBillingClient",
    "ProviderBillingUnavailable",
    "ProviderPage",
    "fetch_all_pages",
]
