"""Pre-promotion security replay for planned remediation patches.

The LangGraph node name ``verify_patches`` is a persisted checkpoint contract
and must not be renamed. Both SUGGEST and REMEDIATE traverse this node. It
replays Semgrep, Bandit, and Gitleaks against an original tree with one planned
file changed; only REMEDIATE promotes files whose compiler/test and security
gates passed.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List, Sequence

from app.core.schemas import FixResult, VulnerabilityFinding
from app.infrastructure.agents.patch_evidence_validator import (
    PatchEvidenceValidator,
    create_patch_evidence_validator,
)
from app.core.services.semgrep_ingestion.materializer import materialize_rules
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_artifact_repo import (
    ARTIFACT_TYPE_SCANNER_REPORTS,
    ScanArtifactRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.scanners.bandit_runner import _bandit_binary, run_bandit
from app.infrastructure.scanners.gitleaks_runner import _gitleaks_binary, run_gitleaks
from app.infrastructure.scanners.osv_offline_replay import run_offline_osv_replay
from app.infrastructure.scanners.provenance import (
    SemgrepRuleBindingError,
    parse_semgrep_rule_binding,
)
from app.infrastructure.scanners.semgrep_rules import derive_semgrep_languages
from app.infrastructure.scanners.semgrep_runner import _semgrep_binary, run_semgrep
from app.infrastructure.scanners.staging import stage_files
from app.infrastructure.observability import mask
from app.infrastructure.workflows.nodes.consolidate import build_validation_summary
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.files import get_language_from_filename
from app.shared.lib.llm_slots import LLMStep, resolve_llm_config_id, resolve_temperature
from app.shared.lib.patch_planner import (
    CandidatePatchDecision,
    FilePatchPlan,
    PatchPlanArtifact,
    PatchValidationCheck,
)

logger = logging.getLogger(__name__)

MAX_PATCHED_FILES = 5_000
MAX_FINDINGS = 50_000
MAX_TOTAL_BYTES = 100 * 1024 * 1024
SEMGREP_VERIFY_TIMEOUT_SECONDS = 300
DETERMINISTIC_SOURCES = {"semgrep", "bandit", "gitleaks", "osv"}
REPLAYABLE_SOURCES = {"semgrep", "bandit", "gitleaks", "osv"}

_DEPENDENCY_MANIFEST_NAMES = frozenset(
    {
        "cargo.lock",
        "composer.lock",
        "gemfile.lock",
        "go.sum",
        "gradle.lockfile",
        "package-lock.json",
        "packages.lock.json",
        "pipfile.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "pom.xml",
        "pubspec.lock",
        "yarn.lock",
    }
)


def _requires_osv_replay(file_path: str, candidates: Sequence[FixResult]) -> bool:
    """Run OSV for originating CVEs and dependency-manifest changes."""
    if any(candidate.finding.source == "osv" for candidate in candidates):
        return True
    name = Path(file_path).name.lower()
    return name in _DEPENDENCY_MANIFEST_NAMES or (
        name.startswith("requirements") and name.endswith(".txt")
    )


def _still_detected(
    finding: VulnerabilityFinding,
    post_findings: List[VulnerabilityFinding],
    resolved_lines: tuple[int, int] | None = None,
) -> bool:
    """Match an originating native scanner rule at its resolved patch site."""
    for post in post_findings:
        if post.file_path != finding.file_path:
            continue
        if post.source != finding.source:
            continue
        if finding.source == "osv" and finding.cve_id:
            if post.cve_id != finding.cve_id:
                continue
        elif finding.scanner_rule_id:
            if post.scanner_rule_id != finding.scanner_rule_id:
                continue
        elif post.cwe != finding.cwe:
            continue
        if resolved_lines is not None and finding.source != "osv":
            start_line, end_line = resolved_lines
            if not max(1, start_line - 2) <= post.line_number <= end_line + 2:
                continue
        return True
    return False


def _replacement_line_window(
    candidate: FixResult, plan: FilePatchPlan | None = None
) -> tuple[int, int] | None:
    if candidate.resolved_range is None:
        return None
    start = candidate.resolved_range.start_line
    if plan is not None:
        start = _shifted_line(start, plan)
    replacement_lines = max(1, len(candidate.suggestion.code.splitlines()))
    return start, start + replacement_lines - 1


def _shifted_line(original_line: int, plan: FilePatchPlan) -> int:
    delta = 0
    for hunk in plan.hunks:
        if hunk.resolved_range.end_line < original_line:
            delta += hunk.replacement_text.count("\n") - hunk.original_text.count("\n")
    return max(0, original_line + delta)


def _matches_baseline(
    post: VulnerabilityFinding,
    baseline: Sequence[VulnerabilityFinding],
    plan: FilePatchPlan,
) -> bool:
    """Account for deterministic line shifts when comparing replay output."""
    for original in baseline:
        if original.source != post.source or original.file_path != post.file_path:
            continue
        if original.source == "osv" and original.cve_id:
            if original.cve_id != post.cve_id:
                continue
        elif original.scanner_rule_id:
            if original.scanner_rule_id != post.scanner_rule_id:
                continue
        elif original.cwe != post.cwe:
            continue
        if abs(_shifted_line(original.line_number, plan) - post.line_number) <= 2:
            return True
    return False


async def _run_semgrep_replay(
    files: Dict[str, str],
    *,
    scan_id: Any,
) -> tuple[PatchValidationCheck, List[VulnerabilityFinding]]:
    started = time.monotonic()
    languages = derive_semgrep_languages(files)
    if not languages:
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status="skipped",
                tool="semgrep",
                detail="No Semgrep-supported language exists in the validation tree.",
            ),
            [],
        )
    total_bytes = sum(len(content.encode("utf-8")) for content in files.values())
    if total_bytes > MAX_TOTAL_BYTES:
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status="infrastructure_error",
                tool="semgrep",
                detail="Validation tree exceeds the 100 MiB replay limit.",
            ),
            [],
        )
    try:
        async with AsyncSessionLocal() as db:
            artifacts = ScanArtifactRepository(db)
            artifact = await artifacts.get_by_type(
                scan_id, ARTIFACT_TYPE_SCANNER_REPORTS
            )
            if artifact is None:
                raise SemgrepRuleBindingError("scanner_report_artifact_missing")
            payload = await artifacts.resolve_payload(artifact, audit=False)
            binding = parse_semgrep_rule_binding(payload)
            expected = binding["rules"]
            if not expected:
                raise SemgrepRuleBindingError("prescan_selected_no_semgrep_rules")
            rules = [
                SimpleNamespace(
                    namespaced_id=rule_id,
                    raw_yaml=expected[rule_id]["body"],
                )
                for rule_id in sorted(expected)
            ]
            replay_binding = {
                "scanner_report_artifact_version": artifact.version,
                "attempt_id": str(getattr(artifact, "attempt_id", "legacy")),
                "selected_rule_count": binding["selected_rule_count"],
                "ruleset_sha256": binding["ruleset_sha256"],
            }
        reports: list[Dict[str, Any]] = []
        with stage_files(files) as (staged_dir, original_paths):
            async with materialize_rules(rules) as config_path:
                findings = await asyncio.wait_for(
                    run_semgrep(
                        staged_dir,
                        original_paths,
                        config_path=config_path,
                        report_collector=reports.append,
                    ),
                    timeout=SEMGREP_VERIFY_TIMEOUT_SECONDS,
                )
    except SemgrepRuleBindingError as exc:
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status="not_run",
                tool="semgrep",
                detail=(
                    "Semgrep replay could not bind the exact prescan ruleset "
                    f"({exc}). Automatic promotion is blocked."
                ),
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            [],
        )
    except asyncio.TimeoutError:
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status="timeout",
                tool="semgrep",
                detail="Semgrep replay exceeded 300 seconds.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            [],
        )
    except Exception as exc:  # noqa: BLE001 - failure becomes explicit evidence
        logger.warning("Semgrep patch replay failed: %s", exc)
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status="infrastructure_error",
                tool="semgrep",
                detail=f"Semgrep replay raised {type(exc).__name__}.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            [],
        )
    if any(
        finding.scanner_rule_id is None and "timed out" in finding.title.lower()
        for finding in findings
    ):
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status="timeout",
                tool="semgrep",
                detail="Semgrep reported an internal scan timeout.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            findings,
        )
    if not reports:
        status = (
            "tool_missing"
            if not _binary_available(_semgrep_binary())
            else "infrastructure_error"
        )
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status=status,
                tool="semgrep",
                detail="Semgrep did not produce a valid replay report.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            findings,
        )
    if reports[0].get("errors"):
        return (
            PatchValidationCheck(
                stage="semgrep_security_replay",
                status="infrastructure_error",
                tool="semgrep",
                detail="Semgrep replay reported scan or parse errors.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            findings,
        )
    return (
        PatchValidationCheck(
            stage="semgrep_security_replay",
            status="passed",
            tool="semgrep",
            detail=f"Semgrep replay completed with {len(findings)} finding(s).",
            return_code=0,
            duration_ms=int((time.monotonic() - started) * 1000),
            output=json.dumps(replay_binding, sort_keys=True),
        ),
        findings,
    )


def _binary_available(binary: str) -> bool:
    candidate = Path(binary)
    if candidate.is_absolute() or "/" in binary:
        return candidate.is_file() and os.access(candidate, os.X_OK)
    return shutil.which(binary) is not None


async def _run_builtin_scanner_replay(
    files: Dict[str, str], source: str
) -> tuple[PatchValidationCheck, List[VulnerabilityFinding]]:
    """Run Bandit or Gitleaks and require a successfully parsed native report."""
    started = time.monotonic()
    reports: list[Any] = []
    tool = source
    binary = _bandit_binary() if source == "bandit" else _gitleaks_binary()
    try:
        with stage_files(files) as (staged_dir, original_paths):
            if source == "bandit":
                findings = await asyncio.wait_for(
                    run_bandit(
                        staged_dir,
                        original_paths,
                        report_collector=reports.append,
                    ),
                    timeout=SEMGREP_VERIFY_TIMEOUT_SECONDS,
                )
            elif source == "gitleaks":
                findings = await asyncio.wait_for(
                    run_gitleaks(
                        staged_dir,
                        original_paths,
                        report_collector=reports.append,
                    ),
                    timeout=SEMGREP_VERIFY_TIMEOUT_SECONDS,
                )
            else:  # pragma: no cover - internal allowlist guard
                raise ValueError("unsupported replay scanner")
    except asyncio.TimeoutError:
        return (
            PatchValidationCheck(
                stage=f"{source}_security_replay",
                status="timeout",
                tool=tool,
                detail=f"{source.title()} replay exceeded 300 seconds.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            [],
        )
    except Exception as exc:  # noqa: BLE001 - failure becomes explicit evidence
        logger.warning("%s patch replay failed: %s", source, exc)
        return (
            PatchValidationCheck(
                stage=f"{source}_security_replay",
                status="infrastructure_error",
                tool=tool,
                detail=f"{source.title()} replay raised {type(exc).__name__}.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            [],
        )
    if any(
        finding.scanner_rule_id is None and "timed out" in finding.title.lower()
        for finding in findings
    ):
        return (
            PatchValidationCheck(
                stage=f"{source}_security_replay",
                status="timeout",
                tool=tool,
                detail=f"{source.title()} reported an internal scan timeout.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            findings,
        )
    if not reports:
        status = (
            "tool_missing" if not _binary_available(binary) else "infrastructure_error"
        )
        return (
            PatchValidationCheck(
                stage=f"{source}_security_replay",
                status=status,
                tool=tool,
                detail=f"{source.title()} did not produce a valid replay report.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            findings,
        )
    if source == "bandit" and isinstance(reports[0], dict) and reports[0].get("errors"):
        return (
            PatchValidationCheck(
                stage="bandit_security_replay",
                status="infrastructure_error",
                tool="bandit",
                detail="Bandit replay reported scan or parse errors.",
                duration_ms=int((time.monotonic() - started) * 1000),
            ),
            findings,
        )
    return (
        PatchValidationCheck(
            stage=f"{source}_security_replay",
            status="passed",
            tool=tool,
            detail=f"{source.title()} replay completed with {len(findings)} finding(s).",
            return_code=0,
            duration_ms=int((time.monotonic() - started) * 1000),
        ),
        findings,
    )


async def _run_osv_replay(
    files: Dict[str, str],
) -> tuple[PatchValidationCheck, List[VulnerabilityFinding]]:
    """Run strict OSV replay against a manifest-hashed offline snapshot."""
    try:
        with stage_files(files) as (staged_dir, original_paths):
            result = await run_offline_osv_replay(staged_dir, original_paths)
    except Exception as exc:  # noqa: BLE001 - explicit fail-closed evidence
        logger.warning("Offline OSV patch replay failed: %s", type(exc).__name__)
        return (
            PatchValidationCheck(
                stage="osv_security_replay",
                status="infrastructure_error",
                tool="osv",
                detail=f"Offline OSV replay raised {type(exc).__name__}.",
            ),
            [],
        )
    output = None
    if result.snapshot_provenance is not None:
        output = json.dumps(
            {"advisory_database": result.snapshot_provenance},
            ensure_ascii=False,
            sort_keys=True,
        )
    return (
        PatchValidationCheck(
            stage="osv_security_replay",
            status=result.status,
            blocking=True,
            tool="osv",
            detail=result.detail[:4_000],
            return_code=result.return_code,
            duration_ms=result.duration_ms,
            output=output,
        ),
        result.findings,
    )


def _candidate_ids(plan: FilePatchPlan) -> set[str]:
    return {
        str(candidate_id) for hunk in plan.hunks for candidate_id in hunk.candidate_ids
    }


def _block_file(
    *,
    plan: FilePatchPlan,
    candidates: Sequence[FixResult],
    decisions: Sequence[CandidatePatchDecision],
    check: PatchValidationCheck,
) -> None:
    plan.status = "manual_review_required"
    confirmed = check.status == "failed"
    decision_by_id = {str(item.candidate_id): item for item in decisions}
    for candidate in candidates:
        candidate.disposition = "rejected" if confirmed else "conflict"
        candidate.validation_status = "failed" if confirmed else "not_run"
        candidate.applicability_status = (
            "validation_failed" if confirmed else "validation_unavailable"
        )
        candidate.decision_reason = check.detail[:4000]
        decision = decision_by_id.get(str(candidate.candidate_id))
        if decision is not None:
            decision.status = (
                "validation_failed" if confirmed else "validation_unavailable"
            )
            decision.reason = candidate.decision_reason


async def _run_llm_evidence_reanalysis(
    validator: PatchEvidenceValidator,
    candidate: FixResult,
    *,
    original_file: str,
    patched_file: str,
    patched_start_line: int | None = None,
) -> PatchValidationCheck:
    """Map a structured LLM verdict onto an explicit patch-gate check."""
    started = time.monotonic()
    verdict = await validator.validate(
        candidate,
        original_file=original_file,
        patched_file=patched_file,
        patched_start_line=patched_start_line,
    )
    status = {
        "resolved": "passed",
        "not_resolved": "failed",
        "uncertain": "not_run" if verdict.completed else "infrastructure_error",
    }[verdict.verdict]
    payload = mask(
        {
            "candidate_id": str(candidate.candidate_id),
            "verdict": verdict.verdict,
            "rationale": verdict.rationale,
            "evidence": list(verdict.evidence),
            "residual_risk": verdict.residual_risk,
        }
    )
    return PatchValidationCheck(
        stage="llm_evidence_reanalysis",
        status=status,
        blocking=True,
        tool="reasoning-llm",
        detail=(
            f"Candidate {candidate.candidate_id}: evidence re-analysis verdict "
            f"was {verdict.verdict}. {mask(verdict.rationale)}"
        )[:4_000],
        return_code=0 if status == "passed" else None,
        duration_ms=int((time.monotonic() - started) * 1000),
        output=json.dumps(payload, ensure_ascii=False, sort_keys=True),
    )


async def verify_patches_node(state: WorkerState) -> Dict[str, Any]:
    """Replay security checks and promote only passing REMEDIATE files."""
    scan_type = state["scan_type"]
    if scan_type not in {"SUGGEST", "REMEDIATE"}:
        return {}
    patched_files = dict(state.get("patched_files") or {})
    if not patched_files:
        return {}
    if len(patched_files) > MAX_PATCHED_FILES:
        raise ValueError("patch validation exceeds the file-count limit")

    artifact = PatchPlanArtifact.model_validate(state.get("patch_plan") or {})
    plans_by_path = {plan.file_path: plan for plan in artifact.files}
    all_candidates = list(state.get("fix_candidates") or [])
    candidates_by_id = {
        str(candidate.candidate_id): candidate
        for candidate in all_candidates
        if candidate.candidate_id is not None
    }
    baseline = list(state.get("findings") or [])[:MAX_FINDINGS]
    live_codebase = dict(state.get("live_codebase") or {})
    promotable = dict(patched_files)
    evidence_validator: PatchEvidenceValidator | None = None
    evidence_validator_initialised = False
    evidence_validator_error: PatchValidationCheck | None = None

    for file_path, patched_content in sorted(patched_files.items()):
        plan = plans_by_path[file_path]
        plan_candidates = [
            candidates_by_id[candidate_id]
            for candidate_id in _candidate_ids(plan)
            if candidate_id in candidates_by_id
        ]
        unsupported_origins = sorted(
            {
                candidate.finding.source
                for candidate in plan_candidates
                if candidate.finding.source in DETERMINISTIC_SOURCES
                and candidate.finding.source not in REPLAYABLE_SOURCES
            }
        )
        if unsupported_origins:
            replay_check = PatchValidationCheck(
                stage="originating_tool_replay",
                status="not_run",
                tool=", ".join(unsupported_origins),
                detail="Stable pre-promotion replay is not implemented for this originating scanner.",
            )
            plan.validation_checks.append(replay_check)
            promotable.pop(file_path, None)
            _block_file(
                plan=plan,
                candidates=plan_candidates,
                decisions=artifact.candidate_decisions,
                check=replay_check,
            )
            continue

        validation_tree = dict(live_codebase)
        validation_tree[file_path] = patched_content
        replay_results = [
            (
                "semgrep",
                await _run_semgrep_replay(
                    validation_tree,
                    scan_id=state["scan_id"],
                ),
            ),
            (
                "gitleaks",
                await _run_builtin_scanner_replay(validation_tree, "gitleaks"),
            ),
        ]
        if any(path.lower().endswith(".py") for path in validation_tree):
            replay_results.append(
                (
                    "bandit",
                    await _run_builtin_scanner_replay(validation_tree, "bandit"),
                )
            )
        if _requires_osv_replay(file_path, plan_candidates):
            replay_results.append(("osv", await _run_osv_replay(validation_tree)))

        blocking_checks: list[PatchValidationCheck] = []
        for source, (replay_check, post_findings) in replay_results:
            if replay_check.status == "passed":
                persistent = [
                    candidate
                    for candidate in plan_candidates
                    if candidate.finding.source == source
                    and _still_detected(
                        candidate.finding,
                        post_findings,
                        _replacement_line_window(candidate, plan),
                    )
                ]
                introduced = [
                    finding
                    for finding in post_findings
                    if finding.file_path == file_path
                    and not _matches_baseline(finding, baseline, plan)
                ]
                if persistent or introduced:
                    replay_check.status = "failed"
                    replay_check.return_code = 1
                    replay_check.detail = (
                        f"{source.title()} replay found {len(persistent)} persistent "
                        f"originating rule(s) and {len(introduced)} newly introduced "
                        "finding(s)."
                    )
            plan.validation_checks.append(replay_check)
            if replay_check.blocking and replay_check.status != "passed":
                blocking_checks.append(replay_check)

        if blocking_checks:
            confirmed_failure = any(
                check.status == "failed" for check in blocking_checks
            )
            aggregate_check = PatchValidationCheck(
                stage="security_replay",
                status="failed" if confirmed_failure else blocking_checks[0].status,
                tool=", ".join(
                    sorted(
                        {
                            check.tool
                            for check in blocking_checks
                            if check.tool is not None
                        }
                    )
                )
                or None,
                detail="; ".join(check.detail for check in blocking_checks)[:4000],
            )
            promotable.pop(file_path, None)
            _block_file(
                plan=plan,
                candidates=plan_candidates,
                decisions=artifact.candidate_decisions,
                check=aggregate_check,
            )
            continue

        llm_candidates = [
            candidate
            for candidate in plan_candidates
            if candidate.finding.source not in DETERMINISTIC_SOURCES
        ]
        llm_checks: list[PatchValidationCheck] = []
        if llm_candidates:
            if not evidence_validator_initialised:
                evidence_validator_initialised = True
                reasoning_llm_id = resolve_llm_config_id(LLMStep.PATCH_EVIDENCE, state)
                if reasoning_llm_id is None:
                    evidence_validator_error = PatchValidationCheck(
                        stage="llm_evidence_reanalysis",
                        status="tool_missing",
                        blocking=True,
                        tool="reasoning-llm",
                        detail=(
                            "LLM-originated fixes require evidence re-analysis, but "
                            "the scan has no reasoning LLM configuration."
                        ),
                    )
                else:
                    try:
                        evidence_validator = await create_patch_evidence_validator(
                            reasoning_llm_id,
                            scan_id=state["scan_id"],
                            temperature=resolve_temperature(
                                LLMStep.PATCH_EVIDENCE, state
                            ),
                        )
                    except Exception as exc:  # noqa: BLE001 - fail closed
                        logger.warning(
                            "Could not initialise patch evidence validator: %s",
                            type(exc).__name__,
                        )
                        evidence_validator_error = PatchValidationCheck(
                            stage="llm_evidence_reanalysis",
                            status="infrastructure_error",
                            blocking=True,
                            tool="reasoning-llm",
                            detail=(
                                "The reasoning LLM could not be initialised for "
                                "patch evidence re-analysis."
                            ),
                        )

            if evidence_validator_error is not None:
                llm_checks.append(evidence_validator_error.model_copy(deep=True))
            elif evidence_validator is not None:
                original_file = live_codebase.get(file_path)
                if original_file is None:
                    llm_checks.append(
                        PatchValidationCheck(
                            stage="llm_evidence_reanalysis",
                            status="not_run",
                            blocking=True,
                            tool="reasoning-llm",
                            detail=(
                                "The immutable original file was unavailable for "
                                "evidence-scoped patch re-analysis."
                            ),
                        )
                    )
                else:
                    for candidate in llm_candidates:
                        shifted_window = _replacement_line_window(candidate, plan)
                        llm_checks.append(
                            await _run_llm_evidence_reanalysis(
                                evidence_validator,
                                candidate,
                                original_file=original_file,
                                patched_file=patched_content,
                                patched_start_line=(
                                    shifted_window[0] if shifted_window else None
                                ),
                            )
                        )

            plan.validation_checks.extend(llm_checks)
            llm_blocking = [
                check
                for check in llm_checks
                if check.blocking and check.status != "passed"
            ]
            if llm_blocking:
                aggregate_check = PatchValidationCheck(
                    stage="llm_evidence_reanalysis",
                    status=(
                        "failed"
                        if any(check.status == "failed" for check in llm_blocking)
                        else llm_blocking[0].status
                    ),
                    blocking=True,
                    tool="reasoning-llm",
                    detail="; ".join(check.detail for check in llm_blocking)[:4_000],
                )
                promotable.pop(file_path, None)
                _block_file(
                    plan=plan,
                    candidates=plan_candidates,
                    decisions=artifact.candidate_decisions,
                    check=aggregate_check,
                )
                continue

        for candidate in plan_candidates:
            # This file survived every blocking deterministic replay and, when
            # required, LLM evidence re-analysis. Persist the candidate-level
            # outcome explicitly instead of leaving the planner's pre-gate
            # `not_run` state attached to a promoted candidate.
            candidate.validation_status = "passed"
            if candidate.finding.source in REPLAYABLE_SOURCES:
                candidate.finding.fix_verified = True

    final_file_map = dict(state.get("initial_file_map") or {})
    applied_candidate_ids: set[str] = set()
    applied_canonical_ids: set[str] = set()
    if scan_type == "REMEDIATE" and promotable:
        async with AsyncSessionLocal() as db:
            async with db.begin():
                repo = ScanRepository(db)
                for file_path, patched_content in sorted(promotable.items()):
                    hashes = await repo.get_or_create_source_files(
                        [
                            {
                                "path": file_path,
                                "content": patched_content,
                                "language": get_language_from_filename(file_path),
                            }
                        ],
                        commit=False,
                    )
                    final_file_map[file_path] = hashes[0]

        passing_ids = {
            candidate_id
            for plan in artifact.files
            if plan.file_path in promotable
            for candidate_id in _candidate_ids(plan)
        }
        for candidate in all_candidates:
            if str(candidate.candidate_id) not in passing_ids:
                continue
            candidate.is_applied = True
            applied_candidate_ids.add(str(candidate.candidate_id))
            if candidate.canonical_finding_id:
                applied_canonical_ids.add(str(candidate.canonical_finding_id))
            if candidate.finding.source in REPLAYABLE_SOURCES:
                candidate.finding.fix_verified = True

        for finding in baseline:
            if (
                finding.canonical_finding_id
                and str(finding.canonical_finding_id) in applied_canonical_ids
            ):
                finding.is_applied_in_remediation = True
                # Promotion changes the finding's effective disposition. Persist
                # this alongside the promoted snapshot so risk is computed from
                # the code that actually survived every blocking check.
                finding.disposition = "remediated"
                if finding.source in REPLAYABLE_SOURCES:
                    finding.fix_verified = True

    summary = build_validation_summary(
        scan_type=scan_type,
        all_candidates=all_candidates,
        file_plans=artifact.files,
        decisions=artifact.candidate_decisions,
    )
    result: Dict[str, Any] = {
        "findings": baseline,
        "fix_candidates": all_candidates,
        "patch_plan": artifact.model_dump(mode="json"),
        "patch_validation_summary": summary,
        "patched_files": promotable if scan_type == "REMEDIATE" else {},
    }
    if scan_type == "REMEDIATE":
        # An all-failed plan has no post-remediation snapshot. Returning the
        # unchanged original map would make downstream readers believe a
        # remediation tree was produced when nothing passed promotion.
        result["final_file_map"] = final_file_map if promotable else None

    async with AsyncSessionLocal() as db:
        await ScanRepository(db).create_scan_event(
            scan_id=state["scan_id"],
            stage_name="PATCH_VERIFICATION",
            status="COMPLETED",
            details={
                "validated_files": len(promotable),
                "manual_review_files": len(artifact.files) - len(promotable),
                "applied_candidates": len(applied_candidate_ids),
            },
        )
    return result
