"""`consolidate_and_patch` worker-graph node + tightly-scoped helpers.

Three helpers live here because they have no other consumer:
- `_verify_syntax_with_treesitter` — quick parse check used after the
  merge agent returns a candidate code block.
- `_run_merge_agent` — LLM call that merges multiple conflicting fix
  suggestions into a single drop-in replacement.
- `_resolve_file_fix_conflicts` — per-file overlap detection +
  conflict resolution; calls `_run_merge_agent`.

The string name registered via `workflow.add_node("consolidate_and_patch", ...)`
is part of the LangGraph checkpointer's on-disk contract — do not rename.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, List, Optional

from sqlalchemy import select

from app.core.schemas import FixResult, FixSuggestion, MergedFixResponse
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.models import CweOwaspMapping
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.llm_client import get_llm_client
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.files import get_language_from_filename
from app.shared.lib.llm_slots import (
    LLMStep,
    resolve_llm_config_id,
    resolve_temperature,
)

try:
    from tree_sitter_languages import get_parser as ts_get_parser

    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

logger = logging.getLogger(__name__)


def _verify_syntax_with_treesitter(full_code: str, filename: str) -> bool:
    """Quick syntax check using tree-sitter. Returns True if code parses without errors."""
    if not HAS_TREE_SITTER:
        return True  # Skip check if tree-sitter not available

    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".go": "go",
        ".rb": "ruby",
        ".rs": "rust",
        ".c": "c",
        ".cpp": "cpp",
        ".cs": "c_sharp",
        ".php": "php",
        ".swift": "swift",
        ".kt": "kotlin",
    }
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    lang = lang_map.get(ext)
    if not lang:
        return True  # Unknown language, skip check

    try:
        parser = ts_get_parser(lang)
        tree = parser.parse(full_code.encode("utf-8"))
        return not tree.root_node.has_error
    except Exception as e:
        logger.warning("Tree-sitter syntax check failed for %s: %s", filename, e)
        return True  # Don't block on tree-sitter errors


async def _run_merge_agent(
    reasoning_llm_config_id: uuid.UUID,
    code_block: str,
    conflicting_fixes: List[FixResult],
    code_to_search_in: str,
    temperature: Optional[float] = None,
) -> Optional[FixResult]:
    """
    Invokes an LLM to merge multiple conflicting fix suggestions into a single, superior fix.
    Includes verification, syntax checking, and retry logic.

    `temperature` (#78) is the merge stage's per-scan temperature.
    """
    llm_client = await get_llm_client(reasoning_llm_config_id, temperature=temperature)
    if not llm_client:
        return None

    logger.debug(
        "_run_merge_agent: filename=%s code_block_chars=%d conflicts=%d",
        (conflicting_fixes[0].finding.file_path or "") if conflicting_fixes else "",
        len(code_block),
        len(conflicting_fixes),
    )

    # Use the highest-priority finding as the basis for the merged finding metadata
    winner = conflicting_fixes[0]
    filename = winner.finding.file_path or ""

    suggestions_str = ""
    for i, fix in enumerate(conflicting_fixes):
        suggestions_str += f"--- Suggestion {i + 1} (Severity: {fix.finding.severity}, CWE: {fix.finding.cwe}) ---\n"
        suggestions_str += f"Description: {fix.finding.description}\n"
        suggestions_str += f"Fix:\n```\n{fix.suggestion.code}\n```\n\n"

    prompt = f"""
You are an expert security engineer. Your task is to merge multiple suggested fixes into a single, cohesive, and secure block of code.

RULES:
1. The final code must address ALL the identified vulnerabilities if possible.
2. If fixes are mutually exclusive, prioritize the change that resolves the highest severity vulnerability.
3. PRESERVE all existing comments unless they pose a security risk (e.g., hardcoded secrets).
4. Produce the most optimized, idiomatic code possible — do not just concatenate fixes.
5. Ensure any imports or dependencies referenced in the fix already exist in the file context.
6. Do NOT introduce new vulnerabilities (e.g., removing error handling, weakening validation).
7. The merged code MUST be syntactically valid and ready to compile/run.

ORIGINAL VULNERABLE CODE BLOCK:

{code_block}

CONFLICTING SUGGESTIONS:
{suggestions_str}

Respond ONLY with a valid JSON object conforming to the MergedFixResponse schema.
The `merged_code` you provide must be a surgical, drop-in replacement for the ORIGINAL VULNERABLE CODE BLOCK. It must ONLY contain the specific lines that are changing. Do not include surrounding, unchanged code like function definitions or block delimiters.
Crucially, the `original_snippet_for_replacement` field in your JSON response MUST be an EXACT, character-for-character copy of the 'ORIGINAL VULNERABLE CODE BLOCK' provided above.
The `merged_code` field should contain ONLY the final, corrected code that will replace the original block. DO NOT include the original code in the `merged_code` field.
"""
    # Single-shot merge. The old 3-attempt retry loop was weak-model scaffolding;
    # a modern reasoning model that fails once is very unlikely to succeed on
    # attempt 3, and the retries wasted tokens + latency. On failure we fall
    # back to the highest-priority fix and surface the unmerged group as
    # NEEDS_MANUAL_REVIEW via the caller's fallback path.
    response = await llm_client.generate_structured_output(prompt, MergedFixResponse)

    if not (
        response.parsed_output
        and isinstance(response.parsed_output, MergedFixResponse)
        and response.parsed_output.original_snippet_for_replacement in code_to_search_in
    ):
        logger.warning(
            "Merge agent did not produce a verifiable snippet for %s. "
            "Conflicts: %d fixes, CWEs: %r. Falling back to highest priority fix.",
            filename,
            len(conflicting_fixes),
            [f.finding.cwe for f in conflicting_fixes],
        )
        return None

    merged_code = response.parsed_output.merged_code
    original_snippet = response.parsed_output.original_snippet_for_replacement

    # No-op guard: the merged code must actually change something.
    if merged_code.strip() == original_snippet.strip():
        logger.warning(
            "Merge agent returned a fix identical to the original for %s. "
            "Falling back to highest priority fix.",
            filename,
        )
        return None

    # Syntax check before committing to a replacement.
    candidate_code = code_to_search_in.replace(original_snippet, merged_code, 1)
    if not _verify_syntax_with_treesitter(candidate_code, filename):
        logger.warning(
            "Merge agent produced syntactically invalid code for %s. "
            "Falling back to highest priority fix.",
            filename,
        )
        return None

    # Build the merged FixResult carrying the explanation from each input fix.
    merged_finding = winner.finding.model_copy(deep=True)
    conflicts_summary = "The following conflicting suggestions were considered:\n"
    for i, fix in enumerate(conflicting_fixes):
        conflicts_summary += (
            f"- Suggestion {i + 1} (CWE: {fix.finding.cwe}, "
            f"Severity: {fix.finding.severity}): {fix.finding.remediation}\n"
        )
    final_explanation = (
        f"{conflicts_summary}\nMerge Reasoning:\n{response.parsed_output.explanation}"
    )
    merged_finding.description = final_explanation

    merged_suggestion = FixSuggestion(
        description=final_explanation,
        original_snippet=original_snippet,
        code=merged_code,
    )
    logger.info("Merge agent succeeded for %s with syntax-verified code.", filename)
    return FixResult(finding=merged_finding, suggestion=merged_suggestion)


async def _resolve_file_fix_conflicts(
    file_fixes: List[FixResult],
    file_content: str,
    reasoning_llm_config_id: uuid.UUID,
    owasp_rank_map: Dict[str, int],
    scan_id: uuid.UUID,
    merge_temperature: Optional[float] = None,
) -> List[FixResult]:
    """Given all proposed fixes for one file, return the non-overlapping set to apply.

    Extracted from the old `consolidation_node` (per-file loop) so the new
    single-pass `consolidate_and_patch_node` can call it over files in parallel
    after the analyze step has collected every fix against original content.

    Low-confidence and snippet-less fixes are dropped. Overlapping fixes are
    sent to the merge agent; non-overlapping fixes pass through unchanged.
    """
    if not file_fixes:
        return []

    sorted_fixes = sorted(file_fixes, key=lambda f: f.finding.line_number)
    fixes_to_apply: List[FixResult] = []
    confidence_map = {"High": 3, "Medium": 2, "Low": 1}

    i = 0
    while i < len(sorted_fixes):
        current_fix = sorted_fixes[i]

        if (current_fix.finding.confidence or "Medium").capitalize() == "Low":
            i += 1
            continue

        start_line = current_fix.finding.line_number
        if not current_fix.suggestion.original_snippet:
            i += 1
            continue
        end_line = (
            start_line + len(current_fix.suggestion.original_snippet.splitlines()) - 1
        )

        conflict_group = [current_fix]
        conflict_window_end_line = end_line
        j = i + 1
        while j < len(sorted_fixes):
            next_fix = sorted_fixes[j]
            if next_fix.finding.line_number <= conflict_window_end_line:
                if (
                    next_fix.finding.confidence or "Medium"
                ).capitalize() != "Low" and next_fix.suggestion.original_snippet:
                    conflict_group.append(next_fix)
                    conflict_window_end_line = max(
                        conflict_window_end_line,
                        next_fix.finding.line_number
                        + len(next_fix.suggestion.original_snippet.splitlines())
                        - 1,
                    )
                j += 1
            else:
                break

        winner: Optional[FixResult] = None
        if len(conflict_group) > 1:
            logger.info(
                "Resolving conflict among %d fixes via Merge Agent for scan %s.",
                len(conflict_group),
                scan_id,
            )
            conflict_group.sort(
                key=lambda f: (
                    f.finding.cvss_score or 0,
                    owasp_rank_map.get(f.finding.cwe, 99),
                    confidence_map.get(
                        (f.finding.confidence or "Medium").capitalize(), 0
                    ),
                ),
                reverse=True,
            )
            if file_content:
                min_line = min(f.finding.line_number for f in conflict_group)
                max_line = max(
                    f.finding.line_number
                    + len(f.suggestion.original_snippet.splitlines())
                    - 1
                    for f in conflict_group
                )
                code_lines = file_content.splitlines(keepends=True)
                original_block = "".join(code_lines[min_line - 1 : max_line])

                winner = await _run_merge_agent(
                    reasoning_llm_config_id,
                    original_block,
                    conflict_group,
                    file_content,
                    temperature=merge_temperature,
                )

            # Fall back to highest-priority if merge agent fails or context missing.
            if not winner:
                winner = conflict_group[0]
        else:
            winner = current_fix

        if winner:
            winner.finding.is_applied_in_remediation = True
            fixes_to_apply.append(winner)

        i = j

    return fixes_to_apply


async def consolidate_and_patch_node(state: WorkerState) -> Dict[str, Any]:
    """Terminal consolidation for REMEDIATE scans.

    Runs after `correlate_findings`. Groups the `proposed_fixes` collected by
    the single-pass analyzer by file, resolves per-file conflicts (line-range
    overlap detection + merge agent), applies the resolved fixes to the
    ORIGINAL file content in one pass, and builds the final file_map for the
    POST_REMEDIATION snapshot saved by `save_results_node`.

    For AUDIT mode this is a no-op. For SUGGEST mode we keep the correlated
    findings with their embedded `fixes` field (so the UI shows suggested
    fixes) but do not build a POST_REMEDIATION snapshot.
    """
    scan_id = state["scan_id"]
    scan_type = state["scan_type"]

    if scan_type != "REMEDIATE":
        return {}

    proposed_fixes = state.get("proposed_fixes") or []
    if not proposed_fixes:
        return {}

    # Consolidation + the remediation merge agent run on the reasoning
    # slot (#69) — code-quality-sensitive work. The merge agent uses the
    # merge stage's per-scan temperature (#78).
    reasoning_llm_id = resolve_llm_config_id(LLMStep.CONSOLIDATION, state)
    if not reasoning_llm_id:
        return {
            "error_message": "consolidate_and_patch requires reasoning_llm_config_id."
        }
    merge_temperature = resolve_temperature(LLMStep.MERGE_AGENT, state)

    live_codebase = state.get("live_codebase") or {}
    initial_file_map = state.get("initial_file_map") or {}

    # Group proposed fixes by file (they can only conflict within a file).
    fixes_by_file: Dict[str, List[FixResult]] = {}
    for fix in proposed_fixes:
        fp = fix.finding.file_path or ""
        if not fp:
            continue
        fixes_by_file.setdefault(fp, []).append(fix)

    # Pre-compute the OWASP rank map once for all files' conflict resolution.
    async with AsyncSessionLocal() as session:
        cwe_ids = list({f.finding.cwe for f in proposed_fixes if f.finding.cwe})
        owasp_rank_map: Dict[str, int] = {}
        if cwe_ids:
            stmt = select(CweOwaspMapping).where(CweOwaspMapping.cwe_id.in_(cwe_ids))
            result = await session.execute(stmt)
            owasp_rank_map = {
                mapping.cwe_id: mapping.owasp_rank for mapping in result.scalars().all()
            }

    final_file_map = dict(initial_file_map)
    applied_signatures: set[str] = set()
    # Patched-file content keyed by relative path. Used by the §3.9
    # patch-verifier node downstream so it can re-run Semgrep against
    # the post-remediation code without re-fetching by hash.
    patched_files: Dict[str, str] = {}

    # Patch + persist per file. The loop is sequential to keep the merge-agent
    # calls under our rate limiter's natural flow; parallelizing here would
    # require threading the semaphore through and the cost/latency win is
    # small vs. the analysis phase's many-agents-per-file parallelism.
    async with AsyncSessionLocal() as db:
        async with db.begin():
            repo = ScanRepository(db)
            for file_path, file_fixes in fixes_by_file.items():
                file_content = live_codebase.get(file_path)
                if not file_content:
                    continue

                resolved = await _resolve_file_fix_conflicts(
                    file_fixes,
                    file_content,
                    reasoning_llm_id,
                    owasp_rank_map,
                    scan_id,
                    merge_temperature=merge_temperature,
                )
                if not resolved:
                    continue

                # Apply fixes in line-number order against the ORIGINAL content
                # (single pass — not iterative cross-file). Each fix's
                # original_snippet is expected to match the original file; if a
                # second fix's snippet already got replaced by an earlier one,
                # the merge agent should have been involved.
                patched_content = file_content
                file_was_patched = False
                for fix in sorted(resolved, key=lambda f: f.finding.line_number):
                    snippet = fix.suggestion.original_snippet
                    if snippet and snippet in patched_content:
                        patched_content = patched_content.replace(
                            snippet, fix.suggestion.code, 1
                        )
                        applied_signatures.add(
                            f"{file_path}|{fix.finding.cwe}|{fix.finding.line_number}"
                        )
                        file_was_patched = True

                new_hashes = await repo.get_or_create_source_files(
                    [
                        {
                            "path": file_path,
                            "content": patched_content,
                            "language": get_language_from_filename(file_path),
                        }
                    ]
                )
                final_file_map[file_path] = new_hashes[0]
                if file_was_patched:
                    patched_files[file_path] = patched_content

    # Propagate the applied flag onto the post-correlation findings so the
    # UI and downstream reporting can distinguish applied vs. dropped fixes.
    findings = list(state.get("findings", []))
    for f in findings:
        sig = f"{f.file_path}|{f.cwe}|{f.line_number}"
        if sig in applied_signatures:
            f.is_applied_in_remediation = True

    logger.info(
        "consolidate_and_patch for scan %s: patched %d findings across %d files.",
        scan_id,
        len(applied_signatures),
        len([p for p in final_file_map if p in fixes_by_file]),
    )

    return {
        "findings": findings,
        "final_file_map": final_file_map,
        "patched_files": patched_files,
    }
