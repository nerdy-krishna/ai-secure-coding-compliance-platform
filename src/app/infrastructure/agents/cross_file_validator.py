"""CrossFileValidator — re-judge a finding against its cross-file context (#81).

The parallel analysis pass reasons over one file at a time. A finding
can therefore look real in isolation but be neutralised by an upstream
caller that sanitises the input, or be confirmed by the way a related
file feeds it untrusted data. Cross-file validation (PRD #75) closes
that gap: for each *eligible* consolidated finding the
`CrossFileSlicer` extracts the targeted caller / input-context slices,
and this module asks the reasoning LLM for a verdict over them.

The verdict is **non-destructive** — it never changes a finding's
severity and never deletes a finding. It only annotates:

- ``confirmed``   — the cross-file evidence supports the finding;
- ``mitigated``   — an upstream caller / sanitiser neutralises it;
- ``unconfirmed`` — inconclusive. This is also the fail-safe: empty
  slices or any LLM error resolve to ``unconfirmed``, never
  ``mitigated``.

The client is injected so the module is unit-testable with a fake
reasoning LLM.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Literal, Optional

from pydantic import BaseModel, Field

from app.infrastructure.llm_client import LLMClient, get_llm_client
from app.shared.analysis_tools.cross_file_slicer import CrossFileSlices

logger = logging.getLogger(__name__)

# Fail-safe rationale — used when slices are empty or the LLM errors.
# Never paired with a `mitigated` / `confirmed` status.
_FAILSAFE_RATIONALE = (
    "Cross-file validation was inconclusive — no usable cross-file "
    "evidence or the validation call did not complete. The finding is "
    "left as-is for manual review."
)

_SYSTEM_PROMPT = (
    "You are a senior application-security engineer validating a "
    "single vulnerability finding against the code that connects to "
    "it across other files. You are given the finding and two kinds "
    "of cross-file evidence: the functions that call the finding's "
    "enclosing function (callers), and the cross-file functions that "
    "function itself invokes (input context). Decide whether that "
    "evidence confirms the finding, shows it is mitigated upstream, "
    "or is inconclusive. You never change the finding's severity and "
    "you never invent a new finding — you only return a verdict. A "
    "'mitigated' or 'confirmed' verdict MUST cite the specific "
    "cross-file evidence it relies on. When the evidence does not "
    "clearly settle the question, return 'unconfirmed'."
)


@dataclass(frozen=True)
class CrossFileVerdict:
    """The cross-file validation verdict for one finding."""

    status: Literal["confirmed", "mitigated", "unconfirmed"]
    rationale: str


class _ValidationResponse(BaseModel):
    """Structured output the reasoning LLM returns."""

    status: Literal["confirmed", "mitigated", "unconfirmed"] = Field(
        description=(
            "confirmed = cross-file evidence supports the finding; "
            "mitigated = an upstream caller / sanitiser neutralises it; "
            "unconfirmed = the evidence does not settle the question."
        )
    )
    rationale: str = Field(
        max_length=4_000,
        description=(
            "Plain-language justification. For 'mitigated' / 'confirmed' "
            "it must cite the specific caller / input-context evidence."
        ),
    )


class CrossFileValidator:
    """Validates one finding against its cross-file slices."""

    def __init__(self, client: LLMClient):
        self._client = client

    async def validate(
        self, finding: object, slices: CrossFileSlices
    ) -> CrossFileVerdict:
        """Return a `CrossFileVerdict` for a finding given its slices.

        Empty slices, an LLM transport error, a parse failure, or a
        `mitigated` / `confirmed` verdict that cites no evidence all
        fail safe to `unconfirmed` — the finding is never silently
        downgraded.
        """
        if slices.is_empty:
            return CrossFileVerdict("unconfirmed", _FAILSAFE_RATIONALE)

        try:
            result = await self._client.generate_structured_output(
                prompt=self._build_prompt(finding, slices),
                response_model=_ValidationResponse,
                system_prompt=_SYSTEM_PROMPT,
            )
        except Exception as exc:  # noqa: BLE001 — fail safe, never raise
            logger.warning(
                "cross_file_validator: validation raised for %s: %s",
                getattr(finding, "title", "<finding>"),
                exc,
            )
            return CrossFileVerdict("unconfirmed", _FAILSAFE_RATIONALE)

        if result.error or result.parsed_output is None:
            logger.warning(
                "cross_file_validator: validation failed for %s: %s",
                getattr(finding, "title", "<finding>"),
                result.error,
            )
            return CrossFileVerdict("unconfirmed", _FAILSAFE_RATIONALE)

        response: _ValidationResponse = result.parsed_output
        rationale = (response.rationale or "").strip()
        # A non-`unconfirmed` verdict must carry cited evidence — an
        # empty rationale is treated as inconclusive, never mitigated.
        if response.status != "unconfirmed" and not rationale:
            return CrossFileVerdict("unconfirmed", _FAILSAFE_RATIONALE)
        return CrossFileVerdict(response.status, rationale or _FAILSAFE_RATIONALE)

    @staticmethod
    def _build_prompt(finding: object, slices: CrossFileSlices) -> str:
        title = getattr(finding, "title", "<finding>")
        severity = getattr(finding, "severity", "?")
        file_path = getattr(finding, "file_path", "?")
        line = getattr(finding, "line_number", 0)
        description = (getattr(finding, "description", "") or "")[:1_500]
        snippet = getattr(finding, "vulnerable_snippet", None)

        def _render(label: str, code_slices) -> str:
            if not code_slices:
                return f"{label}: (none found)\n"
            blocks = [
                f"--- {label} #{i}: {s.symbol_name} in {s.file_path} ---\n{s.code}"
                for i, s in enumerate(code_slices, start=1)
            ]
            return "\n".join(blocks) + "\n"

        snippet_block = f"\nVulnerable snippet:\n{snippet}\n" if snippet else ""
        return (
            f"Finding: {title}\n"
            f"Severity: {severity}\n"
            f"Location: {file_path}:{line}\n"
            f"Description: {description}\n"
            f"{snippet_block}\n"
            "Cross-file evidence below. CALLERS are functions in other "
            "files that call the finding's enclosing function; INPUT "
            "CONTEXT is the cross-file functions that function itself "
            "calls.\n\n"
            f"{_render('CALLER', slices.callers)}\n"
            f"{_render('INPUT CONTEXT', slices.input_context)}\n"
            "Return a verdict:\n"
            "- status: 'confirmed' if the evidence shows the finding is "
            "exploitable as reported; 'mitigated' if an upstream caller "
            "or sanitiser neutralises it; 'unconfirmed' if the evidence "
            "does not settle it.\n"
            "- rationale: cite the specific caller / input-context "
            "evidence for a 'mitigated' or 'confirmed' verdict."
        )


async def create_cross_file_validator(
    reasoning_llm_config_id, temperature: Optional[float] = None
) -> CrossFileValidator:
    """Build a `CrossFileValidator` backed by the scan's reasoning slot.

    `temperature` (#78) is the consolidation stage's per-scan
    temperature — cross-file validation is a consolidation-class
    judgement call.
    """
    client = await get_llm_client(
        llm_config_id=reasoning_llm_config_id, temperature=temperature
    )
    if client is None:
        raise RuntimeError(
            f"Reasoning LLM config {reasoning_llm_config_id} could not be "
            "loaded for cross-file validation."
        )
    return CrossFileValidator(client)
