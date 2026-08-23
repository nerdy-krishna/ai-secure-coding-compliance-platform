"""Deterministic patch planning and REMEDIATE snapshot promotion."""

from __future__ import annotations

import ast
import logging
from collections import Counter
from typing import Any, Dict, List

from app.core.schemas import FixResult
from app.infrastructure.validation.sandbox_client import (
    run_sandbox_validation,
    select_validation_profiles,
)
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.dependency_requirements import (
    build_dependency_inventory,
    validate_candidate_dependencies,
)
from app.shared.lib.import_requirements import (
    build_static_import_inventory,
    validate_candidate_imports,
)
from app.shared.lib.patch_planner import (
    CandidatePatchDecision,
    PatchPlanBudget,
    PatchValidationCheck,
    PatchPlanArtifact,
    plan_file_patch,
)

try:
    from tree_sitter_languages import get_parser as ts_get_parser

    HAS_TREE_SITTER = True
except ImportError:
    ts_get_parser = None
    HAS_TREE_SITTER = False

logger = logging.getLogger(__name__)


def build_validation_summary(
    *, scan_type: str, all_candidates: List[FixResult], file_plans, decisions
) -> Dict[str, Any]:
    del decisions  # Candidate state is authoritative across governance and planning.
    check_counts = Counter(
        check.status for plan in file_plans for check in plan.validation_checks
    )
    candidate_counts: Counter[str] = Counter()
    for candidate in all_candidates:
        if candidate.applicability_status == "validation_unavailable":
            category = "unverified"
        elif (
            candidate.disposition == "duplicate"
            or candidate.applicability_status == "duplicate"
        ):
            category = "deduplicated"
        elif (
            candidate.disposition == "conflict"
            or candidate.applicability_status == "conflict"
        ):
            category = "conflicted"
        elif (
            candidate.disposition == "rejected"
            or candidate.validation_status == "failed"
        ):
            category = "rejected"
        elif (
            candidate.disposition == "selected"
            and candidate.applicability_status == "planned"
            and candidate.validation_status == "passed"
        ):
            category = "validated"
        else:
            # Pending, unresolved, and otherwise non-terminal candidates must
            # never disappear from the reconciliation or imply validation.
            category = "unverified"
        candidate_counts[category] += 1

    applied = sum(
        1
        for candidate in all_candidates
        if candidate.is_applied
        and candidate.disposition == "selected"
        and candidate.applicability_status == "planned"
        and candidate.validation_status == "passed"
    )
    manual = sum(1 for plan in file_plans if plan.status == "manual_review_required")
    incomplete = sum(
        candidate_counts[key] for key in ("conflicted", "rejected", "unverified")
    )
    if scan_type == "SUGGEST":
        outcome = (
            "advisory_manual_review" if manual or incomplete else "advisory_validated"
        )
    elif applied and (manual or incomplete):
        outcome = "partial_remediation"
    elif applied:
        outcome = "remediation_validated"
    elif all_candidates:
        outcome = "manual_review_required"
    else:
        outcome = "no_candidates"
    return {
        "outcome": outcome,
        "candidates": {
            "proposed": len(all_candidates),
            "planned": candidate_counts["validated"],
            "validated": candidate_counts["validated"],
            "deduplicated": candidate_counts["deduplicated"],
            "conflicted": candidate_counts["conflicted"],
            "rejected": candidate_counts["rejected"],
            "unverified": candidate_counts["unverified"],
            "applied": applied,
        },
        "files": {
            "total": len(file_plans),
            "planned": sum(1 for plan in file_plans if plan.status == "planned"),
            "manual_review": manual,
        },
        "validation_checks": dict(sorted(check_counts.items())),
    }


def _verify_syntax_with_treesitter(
    full_code: str, filename: str
) -> PatchValidationCheck:
    """Return explicit parser evidence; unavailable/error never means pass."""
    lang_map = {
        ".py": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "tsx",
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
    language = lang_map.get(ext)
    if not language:
        return PatchValidationCheck(
            stage="syntax",
            status="skipped",
            tool="tree-sitter",
            detail=f"No allowlisted tree-sitter parser is configured for {ext or 'this file type'}.",
        )
    if not HAS_TREE_SITTER:
        if language == "python":
            try:
                ast.parse(full_code)
            except SyntaxError:
                return PatchValidationCheck(
                    stage="syntax",
                    status="failed",
                    tool="python:ast",
                    detail="Python AST parsing reported syntax errors in the patched file.",
                )
            except Exception as exc:  # pragma: no cover - defensive runtime seam
                return PatchValidationCheck(
                    stage="syntax",
                    status="infrastructure_error",
                    tool="python:ast",
                    detail=f"Python AST parsing raised {type(exc).__name__}.",
                )
            return PatchValidationCheck(
                stage="syntax",
                status="passed",
                tool="python:ast",
                detail="Python AST parsed the complete patched file without errors.",
            )
        return PatchValidationCheck(
            stage="syntax",
            status="tool_missing",
            tool=f"tree-sitter:{language}",
            detail="tree-sitter language parsers are not installed.",
        )
    try:
        parser = ts_get_parser(language)
        tree = parser.parse(full_code.encode("utf-8"))
        if tree.root_node.has_error:
            return PatchValidationCheck(
                stage="syntax",
                status="failed",
                tool=f"tree-sitter:{language}",
                detail="tree-sitter reported syntax errors in the patched file.",
            )
        return PatchValidationCheck(
            stage="syntax",
            status="passed",
            tool=f"tree-sitter:{language}",
            detail="tree-sitter parsed the complete patched file without errors.",
        )
    except Exception as exc:  # pragma: no cover - optional parser runtime
        logger.warning("Tree-sitter syntax check failed for %s: %s", filename, exc)
        return PatchValidationCheck(
            stage="syntax",
            status="infrastructure_error",
            tool=f"tree-sitter:{language}",
            detail=f"tree-sitter raised {type(exc).__name__} while parsing.",
        )


async def consolidate_and_patch_node(state: WorkerState) -> Dict[str, Any]:
    """Plan SUGGEST/REMEDIATE patches; promote only REMEDIATE outputs.

    Every anchor is resolved against the immutable original source hash. Exact
    ranges drive duplicate/conflict detection and atomic descending-offset
    application. Ambiguous/missing/overlapping candidates become explicit
    decisions and never fall back to first-occurrence replacement.
    """
    scan_id = state["scan_id"]
    scan_type = state["scan_type"]
    if scan_type not in {"SUGGEST", "REMEDIATE"}:
        return {}

    all_candidates: List[FixResult] = list(state.get("fix_candidates") or [])
    fix_candidates: List[FixResult] = [
        candidate
        for candidate in all_candidates
        if candidate.disposition == "selected"
        and candidate.validation_status == "passed"
        and candidate.canonical_finding_id is not None
    ]
    if not fix_candidates:
        summary = build_validation_summary(
            scan_type=scan_type,
            all_candidates=all_candidates,
            file_plans=[],
            decisions=[],
        )
        return {
            "patch_plan": PatchPlanArtifact(scan_id=scan_id).model_dump(mode="json"),
            "patch_validation_summary": summary,
        }

    live_codebase = state.get("live_codebase") or {}
    initial_file_map = state.get("initial_file_map") or {}
    dependency_inventory = build_dependency_inventory(live_codebase)
    import_inventory = build_static_import_inventory(
        live_codebase, dependency_inventory
    )
    candidates_by_file: Dict[str, List[FixResult]] = {}
    for candidate in fix_candidates:
        candidates_by_file.setdefault(candidate.finding.file_path, []).append(candidate)

    file_plans = []
    decisions: list[CandidatePatchDecision] = []
    planned_outputs: dict[str, str] = {}
    plan_budget = PatchPlanBudget()
    for file_path, candidates in sorted(candidates_by_file.items()):
        source = live_codebase.get(file_path)
        expected_hash = initial_file_map.get(file_path)
        if source is None or expected_hash is None:
            for candidate in candidates:
                candidate.disposition = "rejected"
                candidate.applicability_status = "snapshot_mismatch"
                candidate.decision_reason = (
                    "Original source content or snapshot hash is unavailable."
                )
                decisions.append(
                    CandidatePatchDecision(
                        candidate_id=candidate.candidate_id,
                        status="snapshot_mismatch",
                        reason=candidate.decision_reason,
                    )
                )
            continue
        plan, file_decisions, patched = plan_file_patch(
            file_path=file_path,
            source=source,
            expected_source_hash=expected_hash,
            candidates=candidates,
            syntax_validator=_verify_syntax_with_treesitter,
            dependency_validator=lambda candidate: validate_candidate_dependencies(
                candidate, dependency_inventory
            ),
            import_validator=lambda candidate: validate_candidate_imports(
                candidate, import_inventory
            ),
            allow_low_value=bool(state.get("deep_vendor_scan")),
            plan_budget=plan_budget,
        )
        file_plans.append(plan)
        decisions.extend(file_decisions)
        if plan.hunks:
            planned_outputs[file_path] = patched

    # Compiler/test validation always sees an isolated copy of the original
    # snapshot with exactly one planned file changed. SUGGEST and REMEDIATE use
    # this byte-identical path; only promotion below differs by scan type.
    plans_by_path = {plan.file_path: plan for plan in file_plans}
    candidates_by_id = {
        str(candidate.candidate_id): candidate for candidate in fix_candidates
    }
    decisions_by_id = {str(decision.candidate_id): decision for decision in decisions}
    for file_path, patched_content in list(planned_outputs.items()):
        validation_tree = dict(live_codebase)
        validation_tree[file_path] = patched_content
        profiles = select_validation_profiles(validation_tree)
        if profiles:
            sandbox_checks = await run_sandbox_validation(
                validation_tree,
                profiles,
            )
        else:
            sandbox_checks = [
                PatchValidationCheck(
                    stage="sandbox_profile",
                    status="skipped",
                    tool="sccap-patch-validator",
                    detail="No allowlisted compiler/test profile matches this repository.",
                )
            ]
        plan = plans_by_path[file_path]
        plan.validation_checks.extend(sandbox_checks)
        blocking_failures = [
            check
            for check in sandbox_checks
            if check.blocking and check.status != "passed"
        ]
        if not blocking_failures:
            continue
        planned_outputs.pop(file_path, None)
        plan.status = "manual_review_required"
        candidate_ids = {
            str(candidate_id)
            for hunk in plan.hunks
            for candidate_id in hunk.candidate_ids
        }
        confirmed_failure = any(check.status == "failed" for check in blocking_failures)
        detail = "; ".join(check.detail for check in blocking_failures)[:4000]
        for candidate_id in candidate_ids:
            candidate = candidates_by_id[candidate_id]
            candidate.disposition = "rejected" if confirmed_failure else "conflict"
            candidate.validation_status = "failed" if confirmed_failure else "not_run"
            candidate.applicability_status = (
                "validation_failed" if confirmed_failure else "validation_unavailable"
            )
            candidate.decision_reason = detail
            decision = decisions_by_id[candidate_id]
            decision.status = (
                "validation_failed" if confirmed_failure else "validation_unavailable"
            )
            decision.reason = detail

    patch_plan = PatchPlanArtifact(
        scan_id=scan_id,
        files=file_plans,
        candidate_decisions=decisions,
    ).model_dump(mode="json")
    validation_summary = build_validation_summary(
        scan_type=scan_type,
        all_candidates=all_candidates,
        file_plans=file_plans,
        decisions=decisions,
    )
    logger.info(
        "patch_planner: scan_id=%s type=%s files=%d hunks=%d applied=%d conflicts=%d",
        scan_id,
        scan_type,
        len(file_plans),
        sum(len(plan.hunks) for plan in file_plans),
        0,
        sum(len(plan.conflict_components) for plan in file_plans),
    )
    result: Dict[str, Any] = {
        "findings": list(state.get("findings", [])),
        "fix_candidates": state.get("fix_candidates") or [],
        "patch_plan": patch_plan,
        "patch_validation_summary": validation_summary,
        # These are validated candidate outputs, not yet promoted content.
        # verify_patches applies the security regression gate first.
        "patched_files": planned_outputs,
    }
    return result
