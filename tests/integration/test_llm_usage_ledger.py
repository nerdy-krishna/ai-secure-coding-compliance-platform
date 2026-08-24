"""PostgreSQL contracts for immutable, idempotent LLM usage persistence."""

from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from unittest.mock import AsyncMock, patch
from uuid import uuid4

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic_ai.usage import RequestUsage

from app.infrastructure.database import models as db_models
from app.infrastructure.database.database import engine
from app.infrastructure.database.repositories.llm_usage_repo import (
    LLMUsageContext,
    LLMPriceOverrideRepository,
    LLMUsageRepository,
    LLMUsageRequestWrite,
    build_usage_idempotency_key,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.scan_attempt_repo import (
    ScanAttemptRepository,
)
from app.core.schemas import (
    FixResult,
    FixSuggestion,
    LLMInteraction,
    VulnerabilityFinding,
)
from app.infrastructure.agents.patch_evidence_validator import PatchEvidenceValidator
from app.shared.lib.patch_planner import ResolvedPatchRange
from app.shared.lib.llm_usage import (
    BILLABLE_CATEGORIES,
    PriceSnapshot,
    Rate,
    normalize_request_usage,
    price_normalized_usage,
)
from tests.integration.support import integration_test


def _patch_candidate(*, candidate_id=None, file_path="src/query.py") -> FixResult:
    suggestion = FixSuggestion(
        description="Use a parameterized query.",
        original_snippet='cursor.execute("SELECT " + user_input)',
        code='cursor.execute("SELECT ?", (user_input,))',
    )
    return FixResult(
        finding=VulnerabilityFinding(
            title="SQL injection",
            description="Untrusted input is concatenated into a query.",
            severity="High",
            line_number=2,
            remediation="Use a parameterized query.",
            confidence="High",
            references=[],
            file_path=file_path,
            vulnerable_snippet=suggestion.original_snippet,
            fixes=suggestion,
        ),
        suggestion=suggestion,
        candidate_id=candidate_id or uuid4(),
        resolved_range=ResolvedPatchRange(
            start_byte=15,
            end_byte=59,
            start_line=2,
            start_column=1,
            end_line=2,
            end_column=45,
        ),
    )


@integration_test
class LLMUsageLedgerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.connection = await engine.connect()
        self.outer_transaction = await self.connection.begin()
        async with self._session() as db:
            user = db_models.User(
                email=f"usage-ledger-{uuid4()}@example.invalid",
                hashed_password="not-a-real-password-hash",
                is_active=True,
                is_superuser=False,
                is_verified=True,
            )
            db.add(user)
            await db.flush()
            group = db_models.UserGroup(
                name=f"usage-group-{uuid4()}",
                created_by=user.id,
            )
            db.add(group)
            await db.flush()
            db.add(db_models.UserGroupMembership(group_id=group.id, user_id=user.id))
            config = db_models.LLMConfiguration(
                name=f"usage-config-{uuid4()}",
                provider="openai",
                model_name="gpt-test-version",
                encrypted_api_key="encrypted-test-placeholder",
                input_cost_per_million=Decimal("2"),
                output_cost_per_million=Decimal("8"),
            )
            db.add(config)
            project = db_models.Project(
                name=f"usage-project-{uuid4()}",
                user_id=user.id,
            )
            db.add(project)
            await db.flush()
            scan = db_models.Scan(
                project_id=project.id,
                user_id=user.id,
                scan_type="AUDIT",
            )
            db.add(scan)
            await db.flush()
            attempt = await ScanAttemptRepository(db).create_initial(
                scan, actor_user_id=user.id, commit=False
            )
            chat_session = db_models.ChatSession(
                user_id=user.id,
                llm_config_id=config.id,
                title="Usage ledger test chat",
                frameworks=[],
            )
            db.add(chat_session)
            await db.commit()
            self.user_id = user.id
            self.group_id = group.id
            self.config_id = config.id
            self.scan_id = scan.id
            self.attempt_id = attempt.id
            self.chat_session_id = chat_session.id

    async def asyncTearDown(self) -> None:
        await self.outer_transaction.rollback()
        await self.connection.close()
        await engine.dispose()

    def _session(self) -> AsyncSession:
        return AsyncSession(
            bind=self.connection,
            expire_on_commit=False,
            join_transaction_mode="create_savepoint",
        )

    def _request(
        self, index: int, usage: RequestUsage, response_id: str
    ) -> LLMUsageRequestWrite:
        normalized = normalize_request_usage("openai", usage)
        snapshot = PriceSnapshot(
            source="catalog:test-v1",
            effective_at=datetime(2026, 8, 1, tzinfo=timezone.utc),
            currency="USD",
            rates={
                "uncached_input": Rate(Decimal("2"), "million_tokens"),
                "cache_read_input": Rate(Decimal("0.5"), "million_tokens"),
                "non_reasoning_output": Rate(Decimal("8"), "million_tokens"),
                "reasoning_output": Rate(Decimal("8"), "million_tokens"),
            },
        )
        return LLMUsageRequestWrite(
            request_index=index,
            normalized=normalized,
            priced=price_normalized_usage(normalized, snapshot),
            requested_model="gpt-test",
            resolved_model="gpt-test-version",
            provider_response_id=response_id,
            received_at=datetime.now(timezone.utc),
            provider_usage={
                "details": dict(normalized.provider_details),
                "oversized_fixture": "x" * 70_000,
            },
            price_snapshot=snapshot,
            api_flavor="responses",
            service_tier="default",
            is_batch=False,
            region="us",
        )

    async def test_retry_requests_are_priced_once_and_replay_is_idempotent(
        self,
    ) -> None:
        context = LLMUsageContext(
            operation_kind="scan",
            operation_id=str(self.scan_id),
            stage="analysis",
            agent_name="SecurityAgent",
            idempotency_key=f"scan:{self.scan_id}:analysis:file.py:config:{self.config_id}",
            scan_id=self.scan_id,
        )
        requests = (
            self._request(
                1,
                RequestUsage(
                    input_tokens=1_000,
                    cache_read_tokens=400,
                    output_tokens=300,
                    details={"reasoning_tokens": 100},
                ),
                "response-1",
            ),
            self._request(
                2,
                RequestUsage(input_tokens=200, output_tokens=40),
                "response-2",
            ),
        )

        async with self._session() as db:
            repository = LLMUsageRepository(db)
            first = await repository.record(
                context=context,
                llm_config_id=self.config_id,
                provider="openai",
                requested_model="gpt-test",
                tool_call_count=1,
                requests=requests,
            )
            replay = await repository.record(
                context=context,
                llm_config_id=self.config_id,
                provider="openai",
                requested_model="gpt-test",
                tool_call_count=1,
                requests=requests,
            )

            self.assertTrue(first.created)
            self.assertFalse(replay.created)
            self.assertEqual(first.event.id, replay.event.id)
            self.assertEqual(first.event.request_count, 2)
            self.assertEqual(first.event.user_id, self.user_id)
            self.assertEqual(first.event.group_ids, [self.group_id])
            self.assertEqual(first.event.attempt_id, self.attempt_id)
            self.assertEqual(first.event.cost_status, "exact")
            self.assertIsInstance(first.event.total_cost, Decimal)

            event_count = await db.scalar(
                select(func.count())
                .select_from(db_models.LLMUsageEvent)
                .where(db_models.LLMUsageEvent.llm_config_id == self.config_id)
            )
            request_rows = list(
                (
                    await db.scalars(
                        select(db_models.LLMUsageRequest)
                        .where(
                            db_models.LLMUsageRequest.usage_event_id == first.event.id
                        )
                        .order_by(db_models.LLMUsageRequest.request_index)
                    )
                ).all()
            )
            self.assertEqual(event_count, 1)
            self.assertEqual(len(request_rows), 2)
            self.assertEqual(request_rows[0].provider_usage.get("_truncated"), True)

            observations = await repository.recent_estimation_observations(
                llm_config_id=self.config_id,
                stage="analysis",
            )
            self.assertEqual(len(observations), 1)
            self.assertEqual(observations[0].input_tokens, 1_200)
            self.assertEqual(observations[0].output_tokens, 340)
            self.assertEqual(observations[0].request_count, 2)
            self.assertEqual(
                await repository.recent_estimation_observations(
                    llm_config_id=self.config_id,
                    stage="file_profiling",
                ),
                [],
            )

            scan = await db.get(db_models.Scan, self.scan_id)
            self.assertIsNotNone(scan)
            scan.cost_details = {  # type: ignore[union-attr]
                "expected_estimated_cost": 0.004,
                "upper_bound_estimated_cost": 0.006,
            }
            await db.commit()
            feedback = await repository.measure_scan_estimate_variance(
                scan_id=self.scan_id,
                stage="analysis",
                commit=False,
            )
            self.assertIsNotNone(feedback)
            self.assertEqual(feedback["actual_input_tokens"], 1_200)  # type: ignore[index]
            self.assertEqual(feedback["actual_output_tokens"], 340)  # type: ignore[index]
            self.assertTrue(feedback["within_upper_bound"])  # type: ignore[index]
            await db.rollback()
            scan = await db.get(db_models.Scan, self.scan_id)
            self.assertIsNotNone(scan)
            self.assertNotIn("estimate_variance", scan.cost_details)  # type: ignore[union-attr]

            feedback = await repository.measure_scan_estimate_variance(
                scan_id=self.scan_id,
                stage="analysis",
            )
            self.assertIsNotNone(feedback)
            self.assertTrue(feedback["within_upper_bound"])  # type: ignore[index]

            original_total = first.event.total_cost
            config = await db.get(db_models.LLMConfiguration, self.config_id)
            self.assertIsNotNone(config)
            config.input_cost_per_million = Decimal("999")  # type: ignore[union-attr]
            config.output_cost_per_million = Decimal("999")  # type: ignore[union-attr]
            await db.commit()
            await db.refresh(first.event)
            self.assertEqual(first.event.total_cost, original_total)

            projection = LLMInteraction(
                scan_id=self.scan_id,
                usage_event_id=first.event.id,
                agent_name="SecurityAgent",
                llm_config_id=self.config_id,
                raw_response="structured response",
                cost=float(original_total),
            )
            first_projection = await ScanRepository(db).save_llm_interaction(projection)
            replay_projection = await ScanRepository(db).save_llm_interaction(
                projection
            )
            self.assertEqual(first_projection.id, replay_projection.id)
            projection_count = await db.scalar(
                select(func.count())
                .select_from(db_models.LLMInteraction)
                .where(db_models.LLMInteraction.usage_event_id == first.event.id)
            )
            self.assertEqual(projection_count, 1)

    async def test_pre_provider_reservation_is_one_shot_and_attempt_bound(self) -> None:
        key = f"scan:{self.scan_id}:patch_evidence_reanalysis:reservation"
        async with self._session() as db:
            repository = LLMUsageRepository(db)
            owner = await repository.reserve_provider_call(
                idempotency_key=key,
                scan_id=self.scan_id,
                llm_config_id=self.config_id,
                stage="patch_evidence_reanalysis",
            )
            duplicate = await repository.reserve_provider_call(
                idempotency_key=key,
                scan_id=self.scan_id,
                llm_config_id=self.config_id,
                stage="patch_evidence_reanalysis",
            )
            self.assertIsNotNone(owner)
            self.assertIsNone(duplicate)
            row = await db.scalar(
                select(db_models.LLMCallReservation).where(
                    db_models.LLMCallReservation.idempotency_key == key
                )
            )
            self.assertEqual(row.attempt_id, self.attempt_id)
            self.assertEqual(row.status, "reserved")
            self.assertTrue(
                await repository.finish_provider_call_reservation(
                    idempotency_key=key,
                    owner_token=owner,
                    status="failed",
                    usage_event_id=None,
                )
            )
            self.assertIsNone(
                await repository.reserve_provider_call(
                    idempotency_key=key,
                    scan_id=self.scan_id,
                    llm_config_id=self.config_id,
                    stage="patch_evidence_reanalysis",
                )
            )

    async def test_patch_evidence_restart_reuses_retained_structured_verdict(
        self,
    ) -> None:
        candidate = _patch_candidate()
        key = build_usage_idempotency_key(
            operation_kind="scan",
            operation_id=self.scan_id,
            stage="patch_evidence_reanalysis",
            agent_name="PatchEvidenceValidator",
            unit_key=str(candidate.candidate_id),
            llm_config_id=self.config_id,
        )
        context = LLMUsageContext(
            operation_kind="scan",
            operation_id=str(self.scan_id),
            stage="patch_evidence_reanalysis",
            agent_name="PatchEvidenceValidator",
            idempotency_key=key,
            scan_id=self.scan_id,
        )
        async with self._session() as db:
            usage = await LLMUsageRepository(db).record(
                context=context,
                llm_config_id=self.config_id,
                provider="openai",
                requested_model="gpt-test",
                tool_call_count=0,
                requests=(
                    self._request(
                        1,
                        RequestUsage(input_tokens=100, output_tokens=20),
                        "patch-evidence-response-1",
                    ),
                ),
            )
            await ScanRepository(db).save_llm_interaction(
                LLMInteraction(
                    scan_id=self.scan_id,
                    usage_event_id=usage.event.id,
                    file_path=candidate.finding.file_path,
                    agent_name="PatchEvidenceValidator",
                    llm_config_id=self.config_id,
                    prompt_template_name="patch_evidence_reanalysis_v1",
                    prompt_context={
                        "candidate_id": str(candidate.candidate_id),
                        "scope": "resolved_file_context",
                    },
                    raw_response="[structured]",
                    parsed_output={
                        "verdict": "resolved",
                        "rationale": "The query now binds untrusted input.",
                        "evidence": ["AFTER line 2 uses a placeholder."],
                        "residual_risk": None,
                    },
                )
            )

        restarted_client = AsyncMock()
        restarted = PatchEvidenceValidator(
            restarted_client,
            scan_id=self.scan_id,
            llm_config_id=self.config_id,
        )
        with patch(
            "app.infrastructure.agents.patch_evidence_validator.AsyncSessionLocal",
            new=self._session,
        ):
            verdict = await restarted.validate(
                candidate,
                original_file='cursor.execute("SELECT " + user_input)',
                patched_file='cursor.execute("SELECT ?", (user_input,))',
            )

        self.assertEqual(verdict.verdict, "resolved")
        self.assertTrue(verdict.completed)
        restarted_client.generate_structured_output.assert_not_awaited()

    async def test_patch_evidence_restart_fails_closed_for_orphaned_usage(
        self,
    ) -> None:
        candidate = _patch_candidate()
        key = build_usage_idempotency_key(
            operation_kind="scan",
            operation_id=self.scan_id,
            stage="patch_evidence_reanalysis",
            agent_name="PatchEvidenceValidator",
            unit_key=str(candidate.candidate_id),
            llm_config_id=self.config_id,
        )
        async with self._session() as db:
            await LLMUsageRepository(db).record(
                context=LLMUsageContext(
                    operation_kind="scan",
                    operation_id=str(self.scan_id),
                    stage="patch_evidence_reanalysis",
                    agent_name="PatchEvidenceValidator",
                    idempotency_key=key,
                    scan_id=self.scan_id,
                ),
                llm_config_id=self.config_id,
                provider="openai",
                requested_model="gpt-test",
                tool_call_count=0,
                requests=(
                    self._request(
                        1,
                        RequestUsage(input_tokens=100, output_tokens=20),
                        "patch-evidence-orphaned-response",
                    ),
                ),
            )

        restarted_client = AsyncMock()
        restarted = PatchEvidenceValidator(
            restarted_client,
            scan_id=self.scan_id,
            llm_config_id=self.config_id,
        )
        with patch(
            "app.infrastructure.agents.patch_evidence_validator.AsyncSessionLocal",
            new=self._session,
        ):
            verdict = await restarted.validate(
                candidate,
                original_file="before",
                patched_file="after",
            )

        self.assertEqual(verdict.verdict, "uncertain")
        self.assertFalse(verdict.completed)
        restarted_client.generate_structured_output.assert_not_awaited()

    async def test_one_shot_chat_is_attributed_without_fake_session(self) -> None:
        operation_id = uuid4()
        context = LLMUsageContext(
            operation_kind="chat",
            operation_id=str(operation_id),
            stage="advisor_response",
            agent_name="SecurityAdvisorAgent",
            idempotency_key=f"chat:{operation_id}:advisor_response:test",
            actor_user_id=self.user_id,
        )
        async with self._session() as db:
            result = await LLMUsageRepository(db).record(
                context=context,
                llm_config_id=self.config_id,
                provider="openai",
                requested_model="gpt-test",
                tool_call_count=0,
                requests=(
                    self._request(
                        1,
                        RequestUsage(input_tokens=50, output_tokens=10),
                        "chat-response-1",
                    ),
                ),
            )

            self.assertEqual(result.event.operation_id, str(operation_id))
            self.assertEqual(result.event.user_id, self.user_id)
            self.assertIsNone(result.event.chat_session_id)

    async def test_complete_price_overrides_roll_forward_without_rewriting_history(
        self,
    ) -> None:
        def rates(amount: str) -> dict[str, dict[str, str]]:
            return {
                category: {
                    "amount": amount,
                    "unit": (
                        "thousand_requests"
                        if category == "provider_request"
                        else "million_tokens"
                    ),
                    "modifier": "1",
                }
                for category in BILLABLE_CATEGORIES
            }

        first_start = datetime.now(timezone.utc) - timedelta(minutes=2)
        second_start = datetime.now(timezone.utc) - timedelta(minutes=1)
        async with self._session() as db:
            repository = LLMPriceOverrideRepository(db)
            first = await repository.append(
                llm_config_id=self.config_id,
                rates=rates("1"),
                currency="USD",
                source="contract-test-v1",
                created_by_user_id=self.user_id,
                effective_from=first_start,
            )
            second = await repository.append(
                llm_config_id=self.config_id,
                rates=rates("2"),
                currency="USD",
                source="contract-test-v2",
                created_by_user_id=self.user_id,
                effective_from=second_start,
            )

            await db.refresh(first)
            historical = await repository.active_snapshot(
                self.config_id,
                at=first_start + timedelta(seconds=1),
            )
            current = await repository.active_snapshot(self.config_id)
            self.assertEqual(first.effective_to, second_start)
            self.assertIsNotNone(historical)
            self.assertIsNotNone(current)
            self.assertEqual(
                historical.catalog_metadata["price_override_id"], str(first.id)  # type: ignore[union-attr]
            )
            self.assertEqual(
                current.catalog_metadata["price_override_id"], str(second.id)  # type: ignore[union-attr]
            )

            with self.assertRaisesRegex(ValueError, "complete"):
                await repository.append(
                    llm_config_id=self.config_id,
                    rates={"uncached_input": rates("3")["uncached_input"]},
                    currency="USD",
                    source="invalid-partial",
                    created_by_user_id=self.user_id,
                )


if __name__ == "__main__":
    unittest.main()
