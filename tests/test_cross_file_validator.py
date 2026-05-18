"""CrossFileValidator — cross-file finding verdicts (#81 / PRD #75).

The reasoning LLM is mocked: the validator takes an injected client,
so these tests exercise verdict shaping and the fail-safes without any
real LLM call.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from app.core.schemas import VulnerabilityFinding
from app.infrastructure.agents.cross_file_validator import (
    CrossFileValidator,
    CrossFileVerdict,
    _ValidationResponse,
)
from app.shared.analysis_tools.cross_file_slicer import CodeSlice, CrossFileSlices


def _finding(**over) -> VulnerabilityFinding:
    base = dict(
        title="SQL injection",
        description="Untrusted input concatenated into a query.",
        severity="High",
        line_number=4,
        remediation="Use parameterised queries.",
        confidence="Medium",
        file_path="db/queries.py",
        references=[],
        agent_name="InjectionAgent",
    )
    base.update(over)
    return VulnerabilityFinding(**base)


def _slices() -> CrossFileSlices:
    return CrossFileSlices(
        callers=[
            CodeSlice(
                file_path="api/handler.py",
                symbol_name="handle_login",
                code="def handle_login(req):\n    return run_query(escape(req.user))",
            )
        ],
        input_context=[],
    )


class _FakeClient:
    """Stand-in reasoning LLM client."""

    def __init__(self, response=None, error=None, raises=False):
        self._response = response
        self._error = error
        self._raises = raises

    async def generate_structured_output(
        self, prompt, response_model, system_prompt=None
    ):
        if self._raises:
            raise RuntimeError("reasoning LLM unreachable")
        return SimpleNamespace(parsed_output=self._response, error=self._error)


def _validate(client, finding=None, slices=None) -> CrossFileVerdict:
    validator = CrossFileValidator(client)
    return asyncio.run(validator.validate(finding or _finding(), slices or _slices()))


# --------------------------------------------------------------------------
# Verdict shaping
# --------------------------------------------------------------------------


def test_mitigated_verdict_carries_its_rationale():
    rationale = "handle_login wraps the input in escape() before run_query."
    verdict = _validate(
        _FakeClient(_ValidationResponse(status="mitigated", rationale=rationale))
    )
    assert verdict.status == "mitigated"
    assert verdict.rationale == rationale


def test_confirmed_verdict_is_returned():
    verdict = _validate(
        _FakeClient(
            _ValidationResponse(
                status="confirmed",
                rationale="The caller passes req.user straight through unescaped.",
            )
        )
    )
    assert verdict.status == "confirmed"
    assert "req.user" in verdict.rationale


def test_unconfirmed_verdict_is_returned():
    verdict = _validate(
        _FakeClient(
            _ValidationResponse(status="unconfirmed", rationale="Inconclusive.")
        )
    )
    assert verdict.status == "unconfirmed"


# --------------------------------------------------------------------------
# Fail-safes — never `mitigated` on error / empty input
# --------------------------------------------------------------------------


def test_llm_error_fails_safe_to_unconfirmed():
    verdict = _validate(_FakeClient(raises=True))
    assert verdict.status == "unconfirmed"
    assert verdict.rationale  # carries the fail-safe explanation


def test_llm_result_error_fails_safe_to_unconfirmed():
    verdict = _validate(_FakeClient(response=None, error="rate limited"))
    assert verdict.status == "unconfirmed"


def test_empty_slices_fail_safe_to_unconfirmed():
    verdict = _validate(_FakeClient(), slices=CrossFileSlices())
    assert verdict.status == "unconfirmed"


def test_mitigated_without_rationale_is_downgraded():
    """A 'mitigated' verdict that cites no evidence is not trusted."""
    verdict = _validate(
        _FakeClient(_ValidationResponse(status="mitigated", rationale="   "))
    )
    assert verdict.status == "unconfirmed"


# --------------------------------------------------------------------------
# Non-destructive — only a verdict, never a finding
# --------------------------------------------------------------------------


def test_validator_returns_a_verdict_and_never_mutates_the_finding():
    finding = _finding(severity="High")
    validator = CrossFileValidator(
        _FakeClient(
            _ValidationResponse(status="mitigated", rationale="caller sanitises it")
        )
    )
    result = asyncio.run(validator.validate(finding, _slices()))
    assert isinstance(result, CrossFileVerdict)
    # The validator emits a verdict only — the finding is untouched.
    assert finding.severity == "High"
    assert finding.cross_file_status is None
