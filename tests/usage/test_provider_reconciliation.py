from __future__ import annotations

import unittest
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from types import SimpleNamespace

import httpx

from app.core.services.provider_reconciliation_service import (
    ProviderReconciliationService,
)
from app.infrastructure.database.repositories.provider_reconciliation_repo import (
    encrypt_credentials,
)
from app.infrastructure.provider_billing import (
    OpenAIOrganizationBillingClient,
    ProviderBillingUnavailable,
    ProviderPage,
    fetch_all_pages,
)
from app.shared.lib.provider_reconciliation import UsageSlice, compare_usage


START = datetime(2026, 8, 23, tzinfo=timezone.utc)
END = START + timedelta(days=1)


def usage(**overrides) -> UsageSlice:
    values = {
        "provider": "openai",
        "window_start": START,
        "window_end": END,
        "model": "openai/gpt-5",
        "project": "project-secret-id",
        "api_key": "key-secret-id",
        "service_tier": "Default",
        "is_batch": False,
        "input_tokens": 100,
        "output_tokens": 20,
        "cache_read_tokens": 40,
        "cost_micro_usd": 1200,
    }
    values.update(overrides)
    return UsageSlice(**values)


class FixtureClient:
    def __init__(self, pages: list[ProviderPage] | None = None, *, unavailable=False):
        self.pages = pages or []
        self.unavailable = unavailable
        self.calls = 0

    async def fetch_page(self, *, window_start, window_end, cursor):
        del window_start, window_end, cursor
        self.calls += 1
        if self.unavailable:
            raise ProviderBillingUnavailable("fixture_outage")
        return self.pages[self.calls - 1]


class ProviderReconciliationClassificationTests(unittest.TestCase):
    def compare(self, ours, theirs):
        return compare_usage(
            ours,
            theirs,
            absolute_tolerance_micro_usd=10,
            percentage_tolerance=Decimal("1"),
        )[0]

    def test_normalizes_model_tier_currency_and_cache_categories(self):
        result = self.compare(
            [usage(project=None, api_key=None)],
            [usage(model="GPT-5", service_tier="default", currency="usd")],
        )
        self.assertEqual("matched", result.classification)
        self.assertEqual(0, result.details["token_delta"]["cache_read"])

    def test_late_arrival_and_credit_are_classified_without_repricing(self):
        late = self.compare([], [usage(late_arrival=True)])
        self.assertEqual("timing_lag", late.classification)
        credit = self.compare([], [usage(kind="credit", cost_micro_usd=-500)])
        self.assertEqual("provider_adjustment_credit", credit.classification)

    def test_duplicate_and_price_mismatch_are_distinct(self):
        duplicate = self.compare([usage(duplicate_count=1)], [usage()])
        self.assertEqual("duplicate_event", duplicate.classification)
        price = self.compare([usage()], [usage(cost_micro_usd=3000)])
        self.assertEqual("price_catalog_mismatch", price.classification)

    def test_token_category_mismatch_precedes_price_mismatch(self):
        result = self.compare([usage()], [usage(cache_read_tokens=0, cost_micro_usd=3000)])
        self.assertEqual("token_category_mismatch", result.classification)


class ProviderPaginationTests(unittest.IsolatedAsyncioTestCase):
    async def test_openai_fixture_combines_usage_and_cost_endpoints(self):
        def handler(request: httpx.Request) -> httpx.Response:
            self.assertEqual("Bearer read-only-admin-key", request.headers["Authorization"])
            if request.url.path.endswith("/usage/completions"):
                payload = {
                    "data": [
                        {
                            "start_time": int(START.timestamp()),
                            "end_time": int(END.timestamp()),
                            "results": [
                                {
                                    "model": "gpt-5",
                                    "project_id": "project-id",
                                    "api_key_id": "api-key-id",
                                    "service_tier": "default",
                                    "batch": False,
                                    "input_tokens": 100,
                                    "output_tokens": 20,
                                    "input_cached_tokens": 40,
                                }
                            ],
                        }
                    ],
                    "has_more": False,
                    "next_page": None,
                }
            else:
                payload = {
                    "data": [
                        {
                            "start_time": int(START.timestamp()),
                            "end_time": int(END.timestamp()),
                            "results": [
                                {
                                    "project_id": "project-id",
                                    "api_key_id": "api-key-id",
                                    "line_item": "service credit",
                                    "amount": {"value": -0.25, "currency": "usd"},
                                }
                            ],
                        }
                    ],
                    "has_more": False,
                    "next_page": None,
                }
            return httpx.Response(200, json=payload)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            client = OpenAIOrganizationBillingClient(
                api_key="read-only-admin-key", client=http
            )
            page = await client.fetch_page(
                window_start=START, window_end=END, cursor=None
            )
        self.assertIsNone(page.next_cursor)
        self.assertEqual(2, len(page.rows))
        self.assertEqual(40, page.rows[0].cache_read_tokens)
        self.assertEqual("credit", page.rows[1].kind)
        self.assertEqual(-250000, page.rows[1].cost_micro_usd)

    async def test_fetches_all_pages(self):
        client = FixtureClient(
            [
                ProviderPage(rows=(usage(external_id="one"),), next_cursor="next"),
                ProviderPage(rows=(usage(external_id="two"),), next_cursor=None),
            ]
        )
        rows, pages = await fetch_all_pages(client, window_start=START, window_end=END)
        self.assertEqual(2, pages)
        self.assertEqual(2, len(rows))

    async def test_rejects_cyclic_pagination(self):
        client = FixtureClient(
            [
                ProviderPage(rows=(), next_cursor="next"),
                ProviderPage(rows=(), next_cursor="next"),
            ]
        )
        with self.assertRaisesRegex(ProviderBillingUnavailable, "pagination_incomplete"):
            await fetch_all_pages(client, window_start=START, window_end=END)


class DummyDB:
    def __init__(self):
        self.commits = 0

    async def commit(self):
        self.commits += 1


class FixtureRepository:
    def __init__(self):
        self.db = DummyDB()
        self.runs = {}
        self.completed = 0
        self.failed = 0
        self.connector = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=uuid.uuid4(),
            provider="openai",
            provider_project_ids=[],
            credentials_encrypted=encrypt_credentials({"api_key": "fixture-read-only-key"}),
            enabled=True,
            absolute_tolerance_micro_usd=10,
            percentage_tolerance=Decimal("1"),
            poll_interval_minutes=60,
        )

    async def get_connector(self, **kwargs):
        return self.connector if kwargs["connector_id"] == self.connector.id else None

    async def existing_run(self, *, idempotency_key):
        return self.runs.get(idempotency_key)

    async def canonical_slices(self, **kwargs):
        return [usage(project=None, api_key=None)]

    async def record_completed_run(self, **kwargs):
        self.completed += 1
        row = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=self.connector.tenant_id,
            connector_id=self.connector.id,
            status="completed",
        )
        self.runs[kwargs["idempotency_key"]] = row
        return row

    async def record_failed_run(self, **kwargs):
        self.failed += 1
        row = SimpleNamespace(
            id=uuid.uuid4(),
            tenant_id=self.connector.tenant_id,
            connector_id=self.connector.id,
            status="failed",
        )
        self.runs[kwargs["idempotency_key"]] = row
        return row

    async def mark_connector_ran(self, connector, *, now, verified):
        connector.last_run_at = now
        connector.verified = verified


class ProviderReconciliationServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_duplicate_run_is_idempotent_and_does_not_refetch(self):
        repo = FixtureRepository()
        client = FixtureClient([ProviderPage(rows=(usage(),), next_cursor=None)])
        service = ProviderReconciliationService(repo, client_factory=lambda *_: client)
        arguments = dict(
            connector_id=repo.connector.id,
            tenant_id=repo.connector.tenant_id,
            window_start=START,
            window_end=END,
            trigger_kind="manual",
            created_by_user_id=1,
            idempotency_key="same-run",
        )
        first = await service.run(**arguments)
        second = await service.run(**arguments)
        self.assertIs(first, second)
        self.assertEqual(1, client.calls)
        self.assertEqual(1, repo.completed)

    async def test_provider_outage_records_failed_append_only_run(self):
        repo = FixtureRepository()
        client = FixtureClient(unavailable=True)
        service = ProviderReconciliationService(repo, client_factory=lambda *_: client)
        run = await service.run(
            connector_id=repo.connector.id,
            tenant_id=repo.connector.tenant_id,
            window_start=START,
            window_end=END,
            trigger_kind="scheduled",
            created_by_user_id=None,
            idempotency_key="outage-run",
        )
        self.assertEqual("failed", run.status)
        self.assertEqual(1, repo.failed)


if __name__ == "__main__":
    unittest.main()
