"""FindingConsolidator — one meaningful finding per real issue (#72).

After the parallel analysis pass every file carries a pile of raw
findings: the same root-cause bug reported by several agents, near-
duplicates at different lines, false positives, non-actionable noise.
The FindingConsolidator feeds a file's source code and *all* of its
raw findings to the reasoning LLM in a single pass and gets back:

- merged root findings — one per real underlying vulnerability, each
  leading with the root cause and its fix, noting the findings it
  subsumes, carrying `affected_locations` for every manifestation
  site, `corroborating_agents`, and a CVSS re-assessed for the root
  cause; and
- a set of dropped findings — false positives, fully-subsumed
  duplicates, non-actionable noise. The quality gate is qualitative;
  there is no severity floor.

The consolidator is the replacement for the old exact-key
`correlate_findings` node. The client is injected so the module is
unit-testable with a fake reasoning LLM.
"""

from __future__ import annotations

import logging
from typing import List, Optional

import cvss
from pydantic import BaseModel, Field

from app.core.schemas import AffectedLocation, VulnerabilityFinding
from app.infrastructure.llm_client import LLMClient, get_llm_client

logger = logging.getLogger(__name__)

# Source content above this many characters is truncated before being
# sent to the reasoning model — bounds per-file token spend.
_MAX_SOURCE_CHARS = 48_000

_SYSTEM_PROMPT = (
    "You are a senior application-security engineer consolidating raw "
    "scanner and agent findings for a single source file. You merge "
    "findings that describe the same underlying vulnerability into one "
    "root finding, and you drop findings that are false positives, "
    "fully subsumed by another, or non-actionable noise. You apply no "
    "severity floor — a real Low-severity issue is kept, a noisy "
    "Critical-labelled false positive is dropped."
)


def _band_for_score(score: float) -> str:
    """Map a CVSS base score to its severity band."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score > 0.0:
        return "Low"
    return "Informational"


class _ConsolidatedLocation(BaseModel):
    line_number: int = Field(ge=0)
    snippet: Optional[str] = Field(default=None, max_length=20_000)


class _MergedFinding(BaseModel):
    """One root finding the LLM merged from >=1 raw findings."""

    subsumed_finding_numbers: List[int] = Field(
        description="1-based numbers of the raw findings this merges."
    )
    title: str = Field(max_length=200)
    description: str = Field(
        max_length=8_000,
        description="Leads with the root cause; briefly notes subsumed findings.",
    )
    remediation: str = Field(max_length=8_000)
    cvss_vector: str = Field(
        description="CVSS 3.1 vector re-assessed for the root cause."
    )
    primary_line_number: int = Field(
        ge=0, description="The fix-anchor line for the root cause."
    )
    affected_locations: List[_ConsolidatedLocation] = Field(
        default_factory=list,
        description="Every site this vulnerability manifests.",
    )


class _ConsolidationResponse(BaseModel):
    merged_findings: List[_MergedFinding] = Field(default_factory=list)
    dropped_finding_numbers: List[int] = Field(
        default_factory=list,
        description="1-based numbers of raw findings dropped by the quality gate.",
    )


class FindingConsolidator:
    """Consolidates a file's raw findings via the reasoning LLM slot."""

    def __init__(self, client: LLMClient):
        self._client = client

    async def consolidate_file(
        self,
        file_path: str,
        source_code: str,
        findings: List[VulnerabilityFinding],
    ) -> List[VulnerabilityFinding]:
        """Consolidate one file's raw findings into root findings.

        Returns the merged/kept findings, each with `id` cleared (the
        consolidated set is written fresh by `save_results_node`). On
        any LLM error the raw findings are returned unchanged (with
        `corroborating_agents` seeded) so a consolidation failure never
        loses findings.
        """
        if not findings:
            return []

        try:
            result = await self._client.generate_structured_output(
                prompt=self._build_prompt(file_path, source_code, findings),
                response_model=_ConsolidationResponse,
                system_prompt=_SYSTEM_PROMPT,
            )
        except Exception as exc:  # noqa: BLE001 — never lose findings
            logger.warning(
                "finding_consolidator: consolidation raised for %s: %s",
                file_path,
                exc,
            )
            return [_passthrough(f) for f in findings]

        if result.error or result.parsed_output is None:
            logger.warning(
                "finding_consolidator: consolidation failed for %s: %s",
                file_path,
                result.error,
            )
            return [_passthrough(f) for f in findings]

        response: _ConsolidationResponse = result.parsed_output
        n = len(findings)

        def _valid(numbers: List[int]) -> List[int]:
            # 1-based, in range, deduplicated, order-preserving.
            seen: set[int] = set()
            out: List[int] = []
            for num in numbers:
                if 1 <= num <= n and num not in seen:
                    seen.add(num)
                    out.append(num)
            return out

        consolidated: List[VulnerabilityFinding] = []
        covered: set[int] = set()

        for merged in response.merged_findings:
            subsumed_nums = _valid(merged.subsumed_finding_numbers)
            if not subsumed_nums:
                continue
            covered.update(subsumed_nums)
            subsumed = [findings[i - 1] for i in subsumed_nums]
            consolidated.append(_build_merged_finding(merged, subsumed, file_path))

        dropped = set(_valid(response.dropped_finding_numbers)) - covered
        # Findings the LLM neither merged nor dropped — keep them rather
        # than silently lose a finding to an incomplete response.
        orphans = [
            findings[i - 1]
            for i in range(1, n + 1)
            if i not in covered and i not in dropped
        ]
        consolidated.extend(_passthrough(f) for f in orphans)

        logger.info(
            "finding_consolidator: %s — %d raw -> %d consolidated "
            "(%d merged, %d dropped, %d passthrough)",
            file_path,
            n,
            len(consolidated),
            len(response.merged_findings),
            len(dropped),
            len(orphans),
        )
        return consolidated

    @staticmethod
    def _build_prompt(
        file_path: str,
        source_code: str,
        findings: List[VulnerabilityFinding],
    ) -> str:
        snippet = source_code[:_MAX_SOURCE_CHARS]
        truncated = len(source_code) > _MAX_SOURCE_CHARS
        lines = []
        for idx, f in enumerate(findings, start=1):
            origin = f.source or f.agent_name or "agent"
            lines.append(
                f"[{idx}] {f.title} | severity={f.severity} "
                f"| line={f.line_number} | source={origin}\n"
                f"    {f.description[:600]}"
            )
        findings_block = "\n".join(lines)
        return (
            f"File: {file_path}\n\n"
            f"Raw findings ({len(findings)}), numbered:\n{findings_block}\n\n"
            "Consolidate these findings. Return:\n"
            "1. merged_findings — one entry per real underlying "
            "vulnerability. Merge every raw finding that describes the "
            "same root cause into one entry; list their numbers in "
            "subsumed_finding_numbers. The description must lead with "
            "the root cause and its fix and briefly note the findings "
            "it subsumes. Populate affected_locations with every site "
            "the issue manifests. Re-assess cvss_vector for the root "
            "cause.\n"
            "2. dropped_finding_numbers — raw findings that are false "
            "positives, fully subsumed duplicates, or non-actionable "
            "noise. Apply no severity floor.\n\n"
            "Every raw finding number must appear in exactly one of "
            "subsumed_finding_numbers or dropped_finding_numbers.\n\n"
            f"--- SOURCE{' (truncated)' if truncated else ''} ---\n"
            f"{snippet}\n"
            "--- END SOURCE ---"
        )


def _passthrough(finding: VulnerabilityFinding) -> VulnerabilityFinding:
    """Return a finding unchanged except `id` cleared and
    `corroborating_agents` seeded from `agent_name`.

    Used for findings the consolidator could not process (LLM error)
    or that the LLM neither merged nor dropped."""
    out = finding.model_copy(deep=True)
    out.id = None
    if not out.corroborating_agents and out.agent_name:
        out.corroborating_agents = [out.agent_name]
    return out


def _build_merged_finding(
    merged: _MergedFinding,
    subsumed: List[VulnerabilityFinding],
    file_path: str,
) -> VulnerabilityFinding:
    """Assemble one merged `VulnerabilityFinding` from the LLM's merge
    instruction plus the metadata of the raw findings it subsumes."""
    _rank = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
    base = max(subsumed, key=lambda f: _rank.get(f.severity, 0))

    # Re-assessed CVSS: parse the LLM vector deterministically. On a
    # bad vector, fall back to the highest-severity subsumed finding's
    # CVSS so we never emit a mismatched score/vector pair.
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    try:
        cvss_score = float(cvss.CVSS3(merged.cvss_vector).base_score)
        cvss_vector = merged.cvss_vector
    except Exception:
        logger.warning(
            "finding_consolidator: bad CVSS vector %r — inheriting from base",
            merged.cvss_vector,
        )
        cvss_score = base.cvss_score
        cvss_vector = base.cvss_vector

    severity = _band_for_score(cvss_score) if cvss_score is not None else base.severity

    # Union the agent provenance across every subsumed finding.
    agents: set[str] = set()
    for f in subsumed:
        if f.agent_name:
            agents.add(f.agent_name)
        for a in f.corroborating_agents or []:
            agents.add(a)

    # Union the reasoning-LLM provenance the same way (#94): the merged
    # finding was detected by every LLM that detected any subsumed one.
    # Two entries ⇒ both models in a dual-LLM scan independently found
    # the same root cause.
    detected_llms: set[str] = set()
    for f in subsumed:
        for llm in f.detected_by_llms or []:
            detected_llms.add(llm)

    # First real CWE among the subsumed findings (SAST-emitted only).
    cwe = next((f.cwe for f in subsumed if f.cwe), None)

    affected = [
        AffectedLocation(line_number=loc.line_number, snippet=loc.snippet)
        for loc in merged.affected_locations
    ]

    return VulnerabilityFinding(
        id=None,
        cwe=cwe,
        title=merged.title,
        description=merged.description,
        severity=severity,
        line_number=merged.primary_line_number,
        remediation=merged.remediation,
        confidence="High" if len(subsumed) > 1 else base.confidence,
        references=base.references,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        file_path=file_path,
        vulnerable_snippet=base.vulnerable_snippet,
        affected_locations=affected or None,
        fixes=base.fixes,
        source=base.source,
        cve_id=base.cve_id,
        agent_name=base.agent_name,
        corroborating_agents=sorted(agents) or None,
        detected_by_llms=sorted(detected_llms) or None,
        is_applied_in_remediation=any(f.is_applied_in_remediation for f in subsumed),
    )


async def create_finding_consolidator(
    reasoning_llm_config_id, temperature: Optional[float] = None
) -> FindingConsolidator:
    """Build a `FindingConsolidator` backed by the scan's reasoning slot.

    `temperature` (#78) is the consolidation stage's per-scan temperature.
    """
    client = await get_llm_client(
        llm_config_id=reasoning_llm_config_id, temperature=temperature
    )
    if client is None:
        raise RuntimeError(
            f"Reasoning LLM config {reasoning_llm_config_id} could not be "
            "loaded for finding consolidation."
        )
    return FindingConsolidator(client)
