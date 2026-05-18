"""FileProfiler — structured per-file understanding (#71).

Before analysis, every file is run through the FileProfiler on the
*utility* LLM slot. The profiler produces a `FileProfile`:

- a natural-language `summary` of what the file does,
- the `security_relevant_operations` it performs (auth, crypto, file
  I/O, network calls, deserialization, …),
- the `applicable_domains` — which of the scan's framework agent-domain
  vocabulary the file is relevant to.

The profile is the shared file-understanding artifact persisted on
`Scan.file_profiles` and consumed downstream by content-based routing
(#73) and consolidation (#72).

`applicable_domains` is always filtered down to the supplied domain
vocabulary, so a hallucinated domain name from the LLM never escapes
this module.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from app.core.schemas import FileProfile
from app.infrastructure.llm_client import LLMClient, get_llm_client

logger = logging.getLogger(__name__)

# File content above this many characters is truncated before being
# sent to the utility model — a profile only needs the shape of the
# file, not every line, and this bounds utility-slot token spend.
_MAX_CONTENT_CHARS = 48_000

# Caps for the deterministic structural block (#77) — it is grounding
# context, not the payload, so it stays small.
_MAX_STRUCT_IMPORTS = 80
_MAX_STRUCT_SYMBOLS = 120
_MAX_STRUCT_CHARS = 4_000

_SYSTEM_PROMPT = (
    "You are a security code profiler. Given one source file, you "
    "produce a concise structured profile used to route the file to "
    "the right security analysis agents. You never invent domain names "
    "— you only choose from the domain list you are given."
)


def _structural_block(repo_summary: Optional[Any]) -> str:
    """Format a file's deterministic tree-sitter structure — imports and
    symbols — into a compact, capped grounding block (#77).

    `repo_summary` is duck-typed for `.imports` (list of str) and
    `.symbols` (each with `.name`, `.type`, `.line_number`); a `None`
    summary (parse failure / unknown language) yields an empty string
    and the block is simply omitted from the prompt.
    """
    if repo_summary is None:
        return ""
    imports = list(getattr(repo_summary, "imports", []) or [])[:_MAX_STRUCT_IMPORTS]
    symbols = list(getattr(repo_summary, "symbols", []) or [])[:_MAX_STRUCT_SYMBOLS]
    if not imports and not symbols:
        return ""
    lines = ["--- FILE STRUCTURE (deterministic, from tree-sitter) ---"]
    if imports:
        lines.append("imports: " + ", ".join(str(i) for i in imports))
    if symbols:
        rendered = ", ".join(
            f"{getattr(s, 'type', '?')} {getattr(s, 'name', '?')} "
            f"(line {getattr(s, 'line_number', 0)})"
            for s in symbols
        )
        lines.append("symbols: " + rendered)
    lines.append("--- END FILE STRUCTURE ---")
    return "\n".join(lines)[:_MAX_STRUCT_CHARS]


class _FileProfileLLMResponse(BaseModel):
    """Raw structured output from the utility model.

    `applicable_domains` is validated/filtered against the real domain
    vocabulary by `FileProfiler.profile_file` after the call returns.
    """

    summary: str = Field(default="", max_length=8_000)
    security_relevant_operations: List[str] = Field(default_factory=list)
    applicable_domains: List[str] = Field(default_factory=list)


class FileProfiler:
    """Profiles individual files using a utility-slot LLM client.

    The client is injected so the profiler is unit-testable with a
    fake client; `create_file_profiler` builds the production
    instance from a `utility_llm_config_id`.
    """

    def __init__(self, client: LLMClient):
        self._client = client

    async def profile_file(
        self,
        file_path: str,
        content: str,
        domain_vocabulary: Dict[str, str],
        repo_summary: Optional[Any] = None,
    ) -> FileProfile:
        """Produce a `FileProfile` for one file.

        `domain_vocabulary` maps domain name → description; the returned
        `applicable_domains` is always a subset of its keys. `repo_summary`
        is the file's tree-sitter repository-map entry (imports + symbols);
        when provided it is added to the prompt as deterministic
        structural grounding (#77) so the profiler's situational picks
        are more stable run to run. On any LLM error a minimal fallback
        profile is returned so a single bad file never aborts the scan.
        """
        snippet = content[:_MAX_CONTENT_CHARS]
        truncated = len(content) > _MAX_CONTENT_CHARS
        vocab_block = (
            "\n".join(
                f"- {name}: {desc}" for name, desc in sorted(domain_vocabulary.items())
            )
            or "(no domains configured)"
        )
        structure = _structural_block(repo_summary)
        structure_section = f"{structure}\n\n" if structure else ""

        prompt = (
            f"File path: {file_path}\n\n"
            f"Available security domains (choose only from these names):\n"
            f"{vocab_block}\n\n"
            f"{structure_section}"
            "Profile this file. Return:\n"
            "1. summary — 2-4 sentences on what the file does.\n"
            "2. security_relevant_operations — short phrases for the "
            "security-sensitive things it does (e.g. 'reads request "
            "parameters', 'builds SQL queries', 'verifies JWT'). Empty "
            "list if none.\n"
            "3. applicable_domains — the domain NAMES from the list "
            "above that this file is relevant to. Empty list if none "
            "apply.\n\n"
            f"--- FILE CONTENT{' (truncated)' if truncated else ''} ---\n"
            f"{snippet}\n"
            "--- END FILE CONTENT ---"
        )

        try:
            result = await self._client.generate_structured_output(
                prompt=prompt,
                response_model=_FileProfileLLMResponse,
                system_prompt=_SYSTEM_PROMPT,
            )
        except Exception as exc:  # noqa: BLE001 — never abort the scan
            logger.warning("file_profiler: profiling raised for %s: %s", file_path, exc)
            return _fallback_profile(file_path)

        if result.error or result.parsed_output is None:
            logger.warning(
                "file_profiler: profiling failed for %s: %s",
                file_path,
                result.error,
            )
            return _fallback_profile(file_path)

        raw = result.parsed_output
        # Filter hallucinated domains — keep only real vocabulary names.
        valid = [d for d in raw.applicable_domains if d in domain_vocabulary]
        dropped = set(raw.applicable_domains) - set(valid)
        if dropped:
            logger.info(
                "file_profiler: dropped %d non-vocabulary domain(s) for %s: %s",
                len(dropped),
                file_path,
                sorted(dropped),
            )
        return FileProfile(
            summary=raw.summary,
            security_relevant_operations=raw.security_relevant_operations,
            applicable_domains=valid,
        )


def _fallback_profile(file_path: str) -> FileProfile:
    """Minimal profile used when the utility model can't profile a file.

    Empty domains means content-based routing will fall back to its
    extension-based default for this file — safe and non-blocking.
    """
    return FileProfile(
        summary=f"Profile unavailable for {file_path} (profiler error).",
        security_relevant_operations=[],
        applicable_domains=[],
    )


async def create_file_profiler(
    utility_llm_config_id, temperature: Optional[float] = None
) -> FileProfiler:
    """Build a `FileProfiler` backed by the scan's utility LLM slot.

    `temperature` (#78) is the profiler stage's per-scan temperature.
    """
    client = await get_llm_client(
        llm_config_id=utility_llm_config_id, temperature=temperature
    )
    if client is None:
        raise RuntimeError(
            f"Utility LLM config {utility_llm_config_id} could not be loaded "
            "for file profiling."
        )
    return FileProfiler(client)
