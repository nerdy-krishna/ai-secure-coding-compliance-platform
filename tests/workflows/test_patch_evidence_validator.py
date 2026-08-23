"""Contracts for evidence-scoped LLM patch re-analysis."""

from __future__ import annotations

import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock
from uuid import uuid4

from app.core.schemas import FixResult, FixSuggestion, VulnerabilityFinding
from app.infrastructure.agents.patch_evidence_validator import (
    PatchEvidenceValidator,
    PatchEvidenceVerdict,
    _EvidenceResponse,
    _RetainedVerdict,
)
from app.infrastructure.llm_client import AgentLLMResult
from app.infrastructure.workflows.nodes.verify import _run_llm_evidence_reanalysis
from app.shared.lib.patch_planner import ResolvedPatchRange


def _candidate() -> FixResult:
    suggestion = FixSuggestion(
        description="Use a parameterized query.",
        original_snippet='cursor.execute("SELECT " + user_input)',
        code='cursor.execute("SELECT ?", (user_input,))',
    )
    finding = VulnerabilityFinding(
        title="SQL injection",
        description="Untrusted input is concatenated into a query.",
        severity="High",
        line_number=2,
        remediation="Use a parameterized query.",
        confidence="High",
        references=[],
        file_path="src/query.py",
        vulnerable_snippet=suggestion.original_snippet,
        fixes=suggestion,
    )
    return FixResult(
        finding=finding,
        suggestion=suggestion,
        candidate_id=uuid4(),
        resolved_range=ResolvedPatchRange(
            start_byte=15,
            end_byte=59,
            start_line=2,
            start_column=1,
            end_line=2,
            end_column=45,
        ),
    )


def _result(
    parsed=None,
    error=None,
    *,
    usage_event_id=None,
    usage_event_created=True,
) -> AgentLLMResult:
    return AgentLLMResult(
        raw_output="[structured]",
        parsed_output=parsed,
        error=error,
        cost=0.001,
        prompt_tokens=100,
        completion_tokens=20,
        total_tokens=120,
        latency_ms=5,
        usage_event_id=usage_event_id or uuid4(),
        usage_event_created=usage_event_created,
    )


class PatchEvidenceValidatorTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.client = AsyncMock()
        self.validator = PatchEvidenceValidator(
            self.client,
            scan_id=uuid4(),
            llm_config_id=uuid4(),
        )
        self.validator._load_retained_verdict = AsyncMock(  # type: ignore[method-assign]
            return_value=_RetainedVerdict(usage_exists=False)
        )
        self.validator._save_interaction = AsyncMock(  # type: ignore[method-assign]
            return_value=True
        )
        self.validator._reserve_provider_call = AsyncMock(  # type: ignore[method-assign]
            return_value=uuid4()
        )
        self.validator._finish_provider_call = AsyncMock(  # type: ignore[method-assign]
            return_value=True
        )

    async def test_positive_verdict_requires_concrete_evidence(self) -> None:
        self.client.generate_structured_output.return_value = _result(
            _EvidenceResponse(
                verdict="resolved",
                rationale="The query is parameterized.",
                evidence=[],
            )
        )
        verdict = await self.validator.validate(
            _candidate(),
            original_file="def run(user_input):\n    "
            'cursor.execute("SELECT " + user_input)\n',
            patched_file="def run(user_input):\n    "
            'cursor.execute("SELECT ?", (user_input,))\n',
        )
        self.assertEqual(verdict.verdict, "uncertain")
        self.assertTrue(verdict.completed)

    async def test_resolved_verdict_uses_scan_usage_identity(self) -> None:
        self.client.generate_structured_output.return_value = _result(
            _EvidenceResponse(
                verdict="resolved",
                rationale="User input is now bound as a value.",
                evidence=["AFTER line 2 uses a placeholder and parameter tuple."],
            )
        )
        candidate = _candidate()
        verdict = await self.validator.validate(
            candidate,
            original_file='cursor.execute("SELECT " + user_input)',
            patched_file='cursor.execute("SELECT ?", (user_input,))',
        )
        self.assertEqual(verdict.verdict, "resolved")
        self.assertEqual(len(verdict.evidence), 1)
        call = self.client.generate_structured_output.await_args.kwargs
        self.assertEqual(call["usage_context"].stage, "patch_evidence_reanalysis")
        self.assertIn("<UNTRUSTED_EVIDENCE>", call["prompt"])
        self.assertIn("AFTER CONTEXT", call["prompt"])

    async def test_provider_exception_is_incomplete_uncertain(self) -> None:
        self.client.generate_structured_output.side_effect = RuntimeError("offline")
        verdict = await self.validator.validate(
            _candidate(), original_file="before", patched_file="after"
        )
        self.assertEqual(verdict.verdict, "uncertain")
        self.assertFalse(verdict.completed)

    async def test_after_context_uses_shifted_patch_location(self) -> None:
        self.client.generate_structured_output.return_value = _result(
            _EvidenceResponse(
                verdict="resolved",
                rationale="The shifted replacement is parameterized.",
                evidence=["AFTER line 6 uses a placeholder."],
            )
        )
        candidate = _candidate()
        patched = "\n".join(
            [
                "header_one",
                "header_two",
                "header_three",
                "def run(user_input):",
                "    prepare()",
                '    cursor.execute("SELECT ?", (user_input,))',
            ]
        )
        await self.validator.validate(
            candidate,
            original_file='cursor.execute("SELECT " + user_input)',
            patched_file=patched,
            patched_start_line=6,
        )
        prompt = self.client.generate_structured_output.await_args.kwargs["prompt"]
        self.assertIn("patched_location: src/query.py:6-6", prompt)
        self.assertIn('     6:     cursor.execute("SELECT ?", (user_input,))', prompt)

    async def test_missing_canonical_usage_event_blocks_positive_verdict(self) -> None:
        result = _result(
            _EvidenceResponse(
                verdict="resolved",
                rationale="The unsafe path is removed.",
                evidence=["AFTER uses a parameter binding."],
            )
        )
        result = result._replace(usage_event_id=None)
        self.client.generate_structured_output.return_value = result
        verdict = await self.validator.validate(
            _candidate(), original_file="before", patched_file="after"
        )
        self.assertEqual(verdict.verdict, "uncertain")
        self.assertFalse(verdict.completed)

    async def test_retained_verdict_is_reused_without_provider_call(self) -> None:
        retained = PatchEvidenceVerdict(
            "resolved",
            "The parameter binding removes string concatenation.",
            ("AFTER line 2 binds user input as a value.",),
        )
        self.validator._load_retained_verdict.return_value = _RetainedVerdict(  # type: ignore[attr-defined]
            usage_exists=True,
            verdict=retained,
        )

        verdict = await self.validator.validate(
            _candidate(), original_file="before", patched_file="after"
        )

        self.assertEqual(verdict, retained)
        self.client.generate_structured_output.assert_not_awaited()
        self.validator._save_interaction.assert_not_awaited()  # type: ignore[attr-defined]

    async def test_usage_without_complete_interaction_fails_without_provider(
        self,
    ) -> None:
        self.validator._load_retained_verdict.return_value = _RetainedVerdict(  # type: ignore[attr-defined]
            usage_exists=True
        )

        verdict = await self.validator.validate(
            _candidate(), original_file="before", patched_file="after"
        )

        self.assertEqual(verdict.verdict, "uncertain")
        self.assertFalse(verdict.completed)
        self.client.generate_structured_output.assert_not_awaited()

    async def test_idempotency_loser_cannot_project_second_verdict(self) -> None:
        self.client.generate_structured_output.return_value = _result(
            _EvidenceResponse(
                verdict="resolved",
                rationale="A second response claims the path is fixed.",
                evidence=["AFTER line 2 binds a value."],
            ),
            usage_event_created=False,
        )

        verdict = await self.validator.validate(
            _candidate(), original_file="before", patched_file="after"
        )

        self.assertEqual(verdict.verdict, "uncertain")
        self.assertFalse(verdict.completed)
        self.validator._save_interaction.assert_not_awaited()  # type: ignore[attr-defined]

    def test_expired_interaction_is_not_trusted_for_replay(self) -> None:
        candidate = _candidate()
        usage_event_id = uuid4()
        interaction = SimpleNamespace(
            usage_event_id=usage_event_id,
            scan_id=self.validator._scan_id,
            file_path=candidate.finding.file_path,
            agent_name="PatchEvidenceValidator",
            llm_config_id=self.validator._llm_config_id,
            prompt_template_name="patch_evidence_reanalysis_v1",
            prompt_context={
                "candidate_id": str(candidate.candidate_id),
                "scope": "resolved_file_context",
            },
            error=None,
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )

        self.assertFalse(
            self.validator._interaction_matches(interaction, candidate, usage_event_id)
        )

    async def test_verdicts_remain_distinct_in_patch_check(self) -> None:
        validator = AsyncMock()
        validator.validate.return_value = PatchEvidenceVerdict(
            "not_resolved",
            "The same concatenation remains.",
            ("AFTER line 2 still concatenates user input.",),
        )
        check = await _run_llm_evidence_reanalysis(
            validator,
            _candidate(),
            original_file="before",
            patched_file="after",
        )
        self.assertEqual(check.status, "failed")
        self.assertTrue(check.blocking)
        self.assertEqual(json.loads(check.output or "{}")["verdict"], "not_resolved")


if __name__ == "__main__":
    unittest.main()
