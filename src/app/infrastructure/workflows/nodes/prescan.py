"""Deterministic SAST pre-pass + the prescan-approval gate cluster.

Four nodes live here:
- `deterministic_prescan_node` runs Bandit + Semgrep + Gitleaks + OSV
  in parallel against the staged tree, persists the BOM, and seeds
  `WorkerState.findings` with `source="<scanner>"` rows.
- `pending_prescan_approval_node` is the human-in-the-loop pause when
  any findings landed; it persists state then calls `interrupt()`.
- `user_decline_node` is the terminal route when the operator chose
  Stop on the prescan card (status `BLOCKED_USER_DECLINE`).
- `blocked_pre_llm_node` is the terminal route when the operator
  declined the Critical-secret override modal (status
  `BLOCKED_PRE_LLM`).

The string names registered via `workflow.add_node(...)` in
`worker_graph.py` are part of the LangGraph checkpointer's on-disk
contract — do not rename.
"""

from __future__ import annotations

import asyncio
import copy
import logging
import time
import uuid
from typing import Any, Dict, List, Optional

from langgraph.types import interrupt

from app.config.config import settings
from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.scanner_coverage_repo import (
    CoverageOutcome,
    CoveragePlanItem,
    DEGRADED_COVERAGE_STATES,
    ScannerCoverageRepository,
)
from app.infrastructure.database.repositories.approval_gate_repo import (
    ApprovalGateRepository,
    approval_gate_payload,
)
from app.infrastructure.scanners.bandit_runner import run_bandit
from app.infrastructure.scanners.gitleaks_runner import run_gitleaks
from app.infrastructure.scanners.osv_runner import run_osv
from app.infrastructure.scanners.registry import (
    MINIFIED_BYTE_LIMIT,
    is_minified,
    scanners_for_file,
)
from app.infrastructure.scanners.report_artifact import (
    bounded_native_report,
    scanner_completion_status,
)
from app.infrastructure.scanners.provenance import (
    build_semgrep_rule_provenance,
    collect_runtime_provenance,
)
from app.infrastructure.scanners.semgrep_rules import derive_semgrep_languages
from app.infrastructure.scanners.semgrep_runner import run_semgrep
from app.infrastructure.scanners.staging import stage_files
from app.infrastructure.observability import mark_error, span
from app.infrastructure.workflows.state import WorkerState
from app.infrastructure.workflows.budget import release_scan_budget
from app.shared.lib.file_classification import should_skip_semgrep
from app.shared.lib.finding_lineage_identity import raw_finding_id
from app.shared.lib.scan_progress import (
    EV_COMPLETED,
    EV_FAILED,
    EV_STARTED,
    EV_WAITING,
    STAGE_PRESCAN_REVIEW,
)
from app.shared.lib.scan_status import (
    STATUS_BLOCKED_PRE_LLM,
    STATUS_BLOCKED_USER_DECLINE,
)

logger = logging.getLogger(__name__)


async def _emit_scan_activity(
    scan_id: Any,
    stage_name: str,
    event_status: str,
    details: Optional[Dict[str, Any]] = None,
    activity_kind: Optional[str] = None,
) -> None:
    """Best-effort durable activity event; never fail scanner execution."""
    try:
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).record_scan_event(
                scan_id,
                stage_name,
                event_status,
                details=details,
                activity_kind=activity_kind,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "prescan activity emit failed scan_id=%s stage=%s: %s",
            scan_id,
            stage_name,
            exc,
        )


# Bounds parallel SAST scanner subprocess invocations in the
# `deterministic_prescan_node`. Mirrors the LLM-side cap so a worker
# busy with a large prescan cannot saturate the host.
# Default overridden by settings.CONCURRENT_SCANNER_LIMIT.
_CONCURRENT_SCANNER_LIMIT = settings.CONCURRENT_SCANNER_LIMIT
# Files larger than this are skipped during the prescan (M6 — defense
# against pathological inputs that pin scanner CPU).
# Per-file size cap for the SAST prescan. Was 1 MiB; raised to
# 10 MiB so legitimately-large source files are no longer silently
# skipped. Files above this cap (vendored bundles, generated code,
# etc.) get a logged warning AND a Low-severity placeholder finding
# so the user sees that scanners ran but couldn't process the file
# — silent skip was the failure mode the user reported.
PRESCAN_FILE_BYTE_LIMIT = 10 * 1024 * 1024
# Maximum number of files passed to the prescan loop (V02.4.1 — caps
# prescan walltime on hostile submissions with many small files).
PRESCAN_MAX_FILES = 10_000


def _degrade_promoted_pack_coverage(
    *,
    scanner_name: str,
    input_paths: set[str],
    coverage_outcomes: List[CoverageOutcome],
    scanner_statuses: Dict[str, Dict[str, Any]],
    provenance_status: str,
) -> None:
    """Make a promoted foundry-pack failure visible in canonical coverage."""

    scanner_statuses[scanner_name] = {
        **scanner_statuses.get(scanner_name, {}),
        "status": "degraded",
        "foundry_promoted_pack": "failed",
    }
    replacement = {
        path: CoverageOutcome(
            scanner_name=scanner_name,
            input_path=path,
            status="failed",
            reason_code="foundry_promoted_pack_failed",
            reason="A promoted tenant rule pack failed; scanner coverage is incomplete.",
            provenance_status=provenance_status,
            details={"pack": "tenant_foundry", "mode": "promoted"},
        )
        for path in input_paths
    }
    retained = [
        outcome
        for outcome in coverage_outcomes
        if not (
            outcome.scanner_name == scanner_name
            and outcome.input_path in replacement
        )
    ]
    retained.extend(replacement.values())
    coverage_outcomes[:] = retained


async def deterministic_prescan_node(state: WorkerState) -> Dict[str, Any]:
    """Deterministic SAST pre-pass.

    Runs bundled SAST scanners (currently Bandit; Semgrep + Gitleaks
    are deferred follow-ups) against the ORIGINAL_SUBMISSION snapshot
    BEFORE the LLM-driven analysis. Findings flow into
    ``WorkerState.findings`` with ``confidence="High"`` and
    ``source="<scanner>"`` so they (a) seed the LLM agents with
    high-confidence ground truth, (b) get deduped by
    ``correlate_findings_node`` against any LLM-emitted overlap, and
    (c) are persisted with provenance via ``Finding.source``.

    Per the sast-prescan threat model:
    - MUST NOT call ``interrupt()``; the cost-approval pause stays at
      ``estimate_cost_node`` (M8).
    - Pathological inputs are bounded by a per-file size cap and a
      per-scanner timeout enforced inside the wrapper (M6).
    - Files are staged into a ``tempfile`` sandbox with sanitized
      basenames so user-controlled paths cannot drive scanner argv
      or trigger config auto-discovery (M1, M2, M3).
    - Scanner findings are persisted immediately so the checkpointer
      doesn't have to round-trip a potentially large list across the
      cost-approval interrupt.
    """

    scan_id = state["scan_id"]
    files: Dict[str, str] = state.get("files") or {}
    file_profiles: Dict[str, Any] = state.get("file_profiles") or {}
    deep_vendor_scan = bool(state.get("deep_vendor_scan"))
    await _emit_scan_activity(
        scan_id,
        "DETERMINISTIC_PRESCAN",
        EV_STARTED,
        {"files_total": len(files)},
    )
    if not files:
        logger.info("deterministic_prescan: no files for scan %s; skipping", scan_id)
        await _emit_scan_activity(
            scan_id,
            "DETERMINISTIC_PRESCAN",
            EV_COMPLETED,
            {
                "files_total": 0,
                "coverage_status": "unavailable",
                "message": "No submitted files to scan.",
            },
        )
        return {}

    # File-eligibility filter (M6 + N2). The policy is "scan
    # everything that has at least one byte and a scanner that knows
    # the extension." Empty files contribute nothing and would just
    # noise up the staging area; oversized files (>10 MiB) still get
    # capped because Semgrep's parse walltime grows superlinearly on
    # pathological minified bundles. Both skip paths log a clear
    # reason so the user can see WHY a file wasn't scanned —
    # previously the cap silently dropped legitimate source files.
    eligible: Dict[str, str] = {}
    coverage_plan: Dict[tuple[str, str], CoveragePlanItem] = {}
    for path, content in files.items():
        planned_scanners = scanners_for_file(path)
        if not planned_scanners:
            coverage_plan[("registry", path)] = CoveragePlanItem(
                scanner_name="registry",
                input_path=path,
                status="unsupported",
                reason_code="unsupported_file_type",
                reason="No deterministic scanner supports this input type.",
            )
            continue
        if not content:
            logger.debug(
                "deterministic_prescan: skipping zero-byte file scan_id=%s path=%s",
                scan_id,
                path,
            )
            for scanner_name in planned_scanners:
                coverage_plan[(scanner_name, path)] = CoveragePlanItem(
                    scanner_name=scanner_name,
                    input_path=path,
                    status="skipped",
                    reason_code="empty_input",
                    reason="The input was empty.",
                )
            continue
        size = len(content.encode("utf-8", "replace"))
        cap = MINIFIED_BYTE_LIMIT if is_minified(path) else PRESCAN_FILE_BYTE_LIMIT
        if size > cap:
            logger.warning(
                "deterministic_prescan: skipping oversize file scan_id=%s path=%s bytes=%d cap=%d",
                scan_id,
                path,
                size,
                cap,
            )
            for scanner_name in planned_scanners:
                coverage_plan[(scanner_name, path)] = CoveragePlanItem(
                    scanner_name=scanner_name,
                    input_path=path,
                    status="truncated",
                    reason_code="input_size_limit",
                    reason="The input exceeded the deterministic scanner size limit.",
                    details={"input_bytes": size, "limit_bytes": cap},
                )
            continue
        eligible[path] = content
        for scanner_name in planned_scanners:
            coverage_plan[(scanner_name, path)] = CoveragePlanItem(
                scanner_name=scanner_name,
                input_path=path,
            )

    if len(eligible) > PRESCAN_MAX_FILES:
        logger.warning(
            "deterministic_prescan: clamping %d→%d files",
            len(eligible),
            PRESCAN_MAX_FILES,
        )
        retained = dict(list(eligible.items())[:PRESCAN_MAX_FILES])
        for path in set(eligible) - set(retained):
            for scanner_name in scanners_for_file(path):
                coverage_plan[(scanner_name, path)] = CoveragePlanItem(
                    scanner_name=scanner_name,
                    input_path=path,
                    status="skipped",
                    reason_code="prescan_file_limit",
                    reason="The scan exceeded the deterministic prescan file-count limit.",
                    details={"limit": PRESCAN_MAX_FILES},
                )
        eligible = retained

    if not eligible:
        if coverage_plan:
            try:
                async with AsyncSessionLocal() as db:
                    await ScannerCoverageRepository(db).plan(
                        scan_id, coverage_plan.values()
                    )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "deterministic_prescan: coverage plan persistence failed "
                    "scan_id=%s err=%s",
                    scan_id,
                    exc,
                )
        logger.info(
            "deterministic_prescan: no scanner-eligible files for scan %s; skipping",
            scan_id,
        )
        await _emit_scan_activity(
            scan_id,
            "DETERMINISTIC_PRESCAN",
            EV_COMPLETED,
            {
                "files_total": len(files),
                "coverage_status": "degraded",
                "message": "No files were eligible for the configured scanners.",
            },
        )
        return {}

    # Derive languages from eligible file extensions and select matching
    # Semgrep rules from the DB. If 0 rules are found, Semgrep is skipped
    # for this scan rather than falling back to the bundled pack.
    semgrep_eligible = {
        path: content
        for path, content in eligible.items()
        if not should_skip_semgrep(
            file_profiles.get(path) or {}, deep_vendor_scan=deep_vendor_scan
        )
    }
    languages = derive_semgrep_languages(semgrep_eligible.keys())
    _semgrep_rules = []
    _semgrep_sources = []
    _foundry_promoted_semgrep = []
    _foundry_shadow_semgrep = []
    _foundry_promoted_gitleaks = []
    _foundry_shadow_gitleaks = []
    _foundry_promoted_osv = []
    _foundry_shadow_osv = []
    if languages:
        try:
            from app.core.services.semgrep_ingestion.selector import (
                select_rules_for_scan,
            )

            async with AsyncSessionLocal() as _db:
                _semgrep_rules = await select_rules_for_scan(
                    languages=languages,
                    technologies=[],
                    db=_db,
                )
                from app.core.services.rule_foundry_runtime import load_active_rules

                _scan = await _db.get(db_models.Scan, uuid.UUID(str(scan_id)))
                if _scan is not None:
                    _foundry_rules = await load_active_rules(
                        db=_db,
                        tenant_id=_scan.tenant_id,
                        registry_kind="semgrep",
                    )
                    _foundry_promoted_semgrep = [
                        rule for rule in _foundry_rules if rule.mode == "promoted"
                    ]
                    _foundry_shadow_semgrep = [
                        rule for rule in _foundry_rules if rule.mode == "shadow"
                    ]
                _semgrep_sources = list(
                    {
                        str(rule.source_id): rule.source
                        for rule in _semgrep_rules
                        if getattr(rule, "source", None) is not None
                    }.values()
                )
            if not _semgrep_rules:
                logger.info(
                    "deterministic_prescan: semgrep skipped — 0 ingested rules for "
                    "scan_id=%s languages=%s",
                    scan_id,
                    languages,
                )
        except Exception as _exc:
            logger.warning(
                "deterministic_prescan: semgrep rule selection failed, skipping semgrep "
                "scan_id=%s err=%s",
                scan_id,
                _exc,
            )

    try:
        from app.core.services.rule_foundry_runtime import load_active_rules

        async with AsyncSessionLocal() as _db:
            _scan = await _db.get(db_models.Scan, uuid.UUID(str(scan_id)))
            if _scan is not None:
                for _registry in ("gitleaks", "osv"):
                    _active = await load_active_rules(
                        db=_db,
                        tenant_id=_scan.tenant_id,
                        registry_kind=_registry,
                    )
                    if _registry == "gitleaks":
                        _foundry_promoted_gitleaks = [r for r in _active if r.mode == "promoted"]
                        _foundry_shadow_gitleaks = [r for r in _active if r.mode == "shadow"]
                    else:
                        _foundry_promoted_osv = [r for r in _active if r.mode == "promoted"]
                        _foundry_shadow_osv = [r for r in _active if r.mode == "shadow"]
    except Exception as _exc:  # noqa: BLE001 - tenant rules fail closed
        logger.warning(
            "rule_foundry.runtime_selection_failed scan_id=%s err=%s",
            scan_id,
            _exc,
        )

    for path in eligible:
        if "semgrep" not in scanners_for_file(path):
            continue
        if path not in semgrep_eligible:
            coverage_plan[("semgrep", path)] = CoveragePlanItem(
                scanner_name="semgrep",
                input_path=path,
                status="skipped",
                reason_code="file_classification_policy",
                reason="Semgrep was skipped by file classification policy.",
            )
        elif not _semgrep_rules:
            coverage_plan[("semgrep", path)] = CoveragePlanItem(
                scanner_name="semgrep",
                input_path=path,
                status="skipped",
                reason_code="no_selected_rules",
                reason="No ingested Semgrep rules matched this input language.",
            )

    coverage_plan[("osv", "<repository>")] = CoveragePlanItem(
        scanner_name="osv", input_path="<repository>"
    )
    try:
        async with AsyncSessionLocal() as db:
            coverage_entries = await ScannerCoverageRepository(db).plan(
                scan_id, coverage_plan.values()
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "deterministic_prescan: coverage plan persistence failed scan_id=%s err=%s",
            scan_id,
            exc,
        )
        coverage_entries = {}

    # Single shared semaphore covers all SAST scanner subprocesses in
    # this prescan invocation (N9). Each scanner walks the staged tree
    # itself, so we get one subprocess.run call per scanner per scan,
    # not per file. OSV-Scanner (ADR-009) joins as the fourth scanner;
    # it returns a (findings, bom) tuple instead of just findings.
    scanner_limit = _CONCURRENT_SCANNER_LIMIT
    native_reports: Dict[str, Any] = {}
    scanner_statuses: Dict[str, Dict[str, Any]] = {}
    coverage_outcomes: List[CoverageOutcome] = [
        CoverageOutcome(
            scanner_name=item.scanner_name,
            input_path=item.input_path,
            status=item.status,
            reason_code=item.reason_code,
            reason=item.reason,
            details=item.details,
        )
        for item in coverage_plan.values()
        if item.status != "planned"
    ]
    toolchain_provenance = copy.deepcopy(collect_runtime_provenance())
    semgrep_rule_provenance = build_semgrep_rule_provenance(
        _semgrep_rules, _semgrep_sources
    )
    toolchain_provenance["semgrep"]["rules"] = semgrep_rule_provenance
    if semgrep_rule_provenance["status"] == "degraded":
        toolchain_provenance["semgrep"]["status"] = "degraded"
        toolchain_provenance["semgrep"]["immutable"] = False
        toolchain_provenance["semgrep"]["reasons"] = sorted(
            set(toolchain_provenance["semgrep"]["reasons"])
            | set(semgrep_rule_provenance["reasons"])
        )

    def _report_collector(scanner_name: str):
        def collect(payload: Any) -> None:
            native_reports[scanner_name] = bounded_native_report(payload)

        return collect

    try:
        from app.shared.lib.concurrency_limits import get_concurrency_limit

        async with AsyncSessionLocal() as _db:
            scanner_limit = await get_concurrency_limit(_db, "CONCURRENT_SCANNER_LIMIT")
    except Exception:
        pass
    semaphore = asyncio.Semaphore(scanner_limit)
    prescan_findings: List[VulnerabilityFinding] = []
    bom_cyclonedx: Optional[Dict[str, Any]] = None
    try:
        with stage_files(eligible) as (staged_dir, original_paths):

            async def _gated(coro_factory):
                async with semaphore:
                    return await coro_factory()

            async def _with_activity(
                scanner_name, coro_factory, *, expected_to_run: bool = True
            ):
                started_at = time.perf_counter()
                await _emit_scan_activity(
                    scan_id,
                    "SCANNER_RUN",
                    EV_STARTED,
                    {"scanner": scanner_name, "files_total": len(eligible)},
                )
                try:
                    with span(
                        "sccap.scanner.run",
                        {"scan.id": scan_id, "scanner.name": scanner_name},
                    ) as current:
                        try:
                            result = await _gated(coro_factory)
                        except BaseException as exc:
                            mark_error(current, exc)
                            raise
                except BaseException:
                    await _emit_scan_activity(
                        scan_id,
                        "SCANNER_RUN",
                        EV_FAILED,
                        {
                            "scanner": scanner_name,
                            "elapsed_ms": int(
                                (time.perf_counter() - started_at) * 1000
                            ),
                            "message": "Scanner failed; the scan continues with reduced coverage.",
                        },
                    )
                    raise
                scanner_findings = result[0] if scanner_name == "osv" else result
                outcome = scanner_completion_status(
                    expected_to_run,
                    scanner_name in native_reports,
                )
                provenance_status = toolchain_provenance[scanner_name]["status"]
                if outcome == "completed" and provenance_status == "degraded":
                    outcome = "degraded"
                details: Dict[str, Any] = {
                    "scanner": scanner_name,
                    "findings_count": len(scanner_findings or []),
                    "elapsed_ms": int((time.perf_counter() - started_at) * 1000),
                    "scanner_status": outcome,
                    "provenance_status": provenance_status,
                }
                if outcome == "skipped":
                    details["message"] = (
                        "Scanner skipped because no applicable rules or files were available."
                    )
                elif outcome == "degraded":
                    details["message"] = (
                        "Scanner evidence or immutable provenance is incomplete; "
                        "deterministic coverage is reduced."
                    )
                await _emit_scan_activity(
                    scan_id,
                    "SCANNER_RUN",
                    EV_FAILED if outcome == "degraded" else EV_COMPLETED,
                    details,
                    activity_kind=(
                        "degradation" if outcome == "degraded" else "scanner"
                    ),
                )
                return result

            if _semgrep_rules and semgrep_eligible:
                from app.core.services.semgrep_ingestion.materializer import (
                    materialize_rules as _mat,
                )

                async def _run_semgrep_materialized():
                    with stage_files(semgrep_eligible) as (
                        semgrep_dir,
                        semgrep_original_paths,
                    ):
                        async with _mat(_semgrep_rules) as _cfg_dir:
                            return await run_semgrep(
                                semgrep_dir,
                                semgrep_original_paths,
                                config_path=_cfg_dir,
                                report_collector=_report_collector("semgrep"),
                            )

                semgrep_task = _with_activity("semgrep", _run_semgrep_materialized)
            else:
                # 0 ingested rules or all files policy-skipped — pass None so run_semgrep returns [] without subprocess
                semgrep_task = _with_activity(
                    "semgrep",
                    lambda: run_semgrep(
                        staged_dir,
                        original_paths,
                        config_path=None,
                        report_collector=_report_collector("semgrep"),
                    ),
                    expected_to_run=False,
                )

            scanner_tasks = [
                _with_activity(
                    "bandit",
                    lambda: run_bandit(
                        staged_dir,
                        original_paths,
                        report_collector=_report_collector("bandit"),
                    ),
                ),
                semgrep_task,
                _with_activity(
                    "gitleaks",
                    lambda: run_gitleaks(
                        staged_dir,
                        original_paths,
                        report_collector=_report_collector("gitleaks"),
                    ),
                ),
                _with_activity(
                    "osv",
                    lambda: run_osv(
                        staged_dir,
                        original_paths,
                        scan_id=scan_id,
                        report_collector=_report_collector("osv"),
                    ),
                ),
            ]
            results = await asyncio.gather(*scanner_tasks, return_exceptions=True)
            for scanner_name, result in zip(
                ("bandit", "semgrep", "gitleaks", "osv"), results
            ):
                if isinstance(result, BaseException):
                    # Per-scanner failure is non-fatal (N15-style at the
                    # per-scanner level) — log + skip + continue with the
                    # other scanners' findings.
                    logger.warning(
                        "deterministic_prescan: scanner=%s failed scan_id=%s err=%s",
                        scanner_name,
                        scan_id,
                        result,
                    )
                    scanner_statuses[scanner_name] = {
                        "status": "failed",
                        "error_class": result.__class__.__name__,
                        "provenance": toolchain_provenance[scanner_name],
                    }
                    final_status = (
                        "timeout"
                        if isinstance(result, (asyncio.TimeoutError, TimeoutError))
                        or "timeout" in result.__class__.__name__.lower()
                        else "failed"
                    )
                    for item in coverage_plan.values():
                        if item.scanner_name == scanner_name and item.status == "planned":
                            coverage_outcomes.append(
                                CoverageOutcome(
                                    scanner_name=scanner_name,
                                    input_path=item.input_path,
                                    status=final_status,
                                    reason_code=f"scanner_{final_status}",
                                    reason=(
                                        "Scanner timed out before completing this input."
                                        if final_status == "timeout"
                                        else "Scanner failed before completing this input."
                                    ),
                                    provenance_status=toolchain_provenance[scanner_name][
                                        "status"
                                    ],
                                )
                            )
                    continue
                if scanner_name == "osv":
                    # OSV returns (findings, bom_cyclonedx_dict).
                    osv_findings, bom = result
                    prescan_findings.extend(osv_findings)
                    bom_cyclonedx = bom
                    finding_count = len(osv_findings)
                else:
                    prescan_findings.extend(result)
                    finding_count = len(result)
                execution_status = scanner_completion_status(
                    not (
                        scanner_name == "semgrep"
                        and not (_semgrep_rules and semgrep_eligible)
                    ),
                    scanner_name in native_reports,
                )
                provenance = toolchain_provenance[scanner_name]
                status_with_provenance = (
                    "degraded"
                    if execution_status == "completed"
                    and provenance["status"] == "degraded"
                    else execution_status
                )
                scanner_statuses[scanner_name] = {
                    "status": status_with_provenance,
                    "finding_count": finding_count,
                    "native_report_available": scanner_name in native_reports,
                    "provenance": provenance,
                }
                report = native_reports.get(scanner_name)
                report_truncated = bool(
                    isinstance(report, dict)
                    and (report.get("truncated") or report.get("available") is False)
                )
                scanner_inputs = [
                    item.input_path
                    for item in coverage_plan.values()
                    if item.scanner_name == scanner_name and item.status == "planned"
                ]
                findings_by_path: Dict[str, int] = {}
                scanner_findings = osv_findings if scanner_name == "osv" else result
                for finding in scanner_findings:
                    findings_by_path[finding.file_path] = (
                        findings_by_path.get(finding.file_path, 0) + 1
                    )
                for input_path in scanner_inputs:
                    input_findings = (
                        finding_count
                        if scanner_name == "osv"
                        else findings_by_path.get(input_path, 0)
                    )
                    coverage_outcomes.append(
                        CoverageOutcome(
                            scanner_name=scanner_name,
                            input_path=input_path,
                            status=(
                                "truncated"
                                if report_truncated
                                else "completed"
                                if input_findings
                                else "clean"
                            ),
                            reason_code=(
                                "native_evidence_truncated" if report_truncated else None
                            ),
                            reason=(
                                "Native scanner evidence exceeded its persistence bound."
                                if report_truncated
                                else None
                            ),
                            finding_count=input_findings,
                            native_evidence_available=(
                                scanner_name in native_reports and not report_truncated
                            ),
                            provenance_status=provenance["status"],
                        )
                    )

            # Tenant foundry rules execute separately from the global pack so
            # shadow matches can never enter findings/policy. Signed promoted
            # versions do enter findings; bounded shadow counts are emitted
            # through a failure-isolated trusted hook.
            if (
                _foundry_promoted_semgrep
                or _foundry_shadow_semgrep
                or _foundry_promoted_gitleaks
                or _foundry_shadow_gitleaks
                or _foundry_promoted_osv
                or _foundry_shadow_osv
            ):
                from app.core.services.rule_foundry_runtime import (
                    build_promoted_osv_findings,
                    osv_observation_counts,
                    record_promoted_degradation_safely,
                    record_shadow_observation_safely,
                    retain_promoted_findings,
                )
                from app.core.services.semgrep_ingestion.materializer import (
                    materialize_rules as _mat,
                )

                async def _run_foundry_semgrep(foundry_rules):
                    with stage_files(semgrep_eligible) as (
                        foundry_dir,
                        foundry_original_paths,
                    ):
                        materialized = [rule.as_semgrep_rule() for rule in foundry_rules]
                        async with _mat(materialized) as foundry_config:
                            return await run_semgrep(
                                foundry_dir,
                                foundry_original_paths,
                                config_path=foundry_config,
                            )

                if _foundry_promoted_semgrep:
                    try:
                        promoted_findings = await _gated(
                            lambda: _run_foundry_semgrep(_foundry_promoted_semgrep)
                        )
                        prescan_findings.extend(
                            retain_promoted_findings(
                                _foundry_promoted_semgrep, promoted_findings
                            )
                        )
                    except Exception:  # noqa: BLE001 - scanner failure isolation
                        _degrade_promoted_pack_coverage(
                            scanner_name="semgrep",
                            input_paths=set(semgrep_eligible),
                            coverage_outcomes=coverage_outcomes,
                            scanner_statuses=scanner_statuses,
                            provenance_status=toolchain_provenance["semgrep"]["status"],
                        )
                        await _emit_scan_activity(
                            scan_id,
                            "SCANNER_RUN",
                            EV_FAILED,
                            {
                                "scanner": "semgrep",
                                "pack": "tenant_foundry",
                                "mode": "promoted",
                                "message": "Promoted tenant rule pack failed; coverage is reduced.",
                            },
                            activity_kind="degradation",
                        )
                        await record_promoted_degradation_safely(
                            rules=_foundry_promoted_semgrep,
                            scan_id=uuid.UUID(str(scan_id)),
                            reason_code="scanner_execution_failed",
                        )
                        logger.warning(
                            "rule_foundry.promoted_semgrep_failed scan_id=%s",
                            scan_id,
                            exc_info=True,
                        )
                if _foundry_shadow_semgrep:
                    try:
                        shadow_findings = await _gated(
                            lambda: _run_foundry_semgrep(_foundry_shadow_semgrep)
                        )
                        for foundry_rule in _foundry_shadow_semgrep:
                            rule_id = (
                                f"foundry.{foundry_rule.candidate_id}."
                                f"{foundry_rule.version_id}"
                            )
                            unexpected_files = {
                                finding.file_path
                                for finding in shadow_findings
                                if finding.scanner_rule_id == rule_id
                            }
                            await record_shadow_observation_safely(
                                rule=foundry_rule,
                                scan_id=uuid.UUID(str(scan_id)),
                                eligible_files=len(semgrep_eligible),
                                unexpected_matches=len(unexpected_files),
                            )
                    except Exception:  # noqa: BLE001 - shadow never breaks scans
                        logger.warning(
                            "rule_foundry.shadow_semgrep_failed scan_id=%s",
                            scan_id,
                            exc_info=True,
                        )

                async def _run_foundry_gitleaks(foundry_rules):
                    from app.core.services.rule_foundry_materializer import (
                        materialize_gitleaks_rules,
                    )

                    with stage_files(eligible) as (
                        foundry_dir,
                        foundry_original_paths,
                    ):
                        async with materialize_gitleaks_rules(foundry_rules) as config:
                            return await run_gitleaks(
                                foundry_dir,
                                foundry_original_paths,
                                config_path=config,
                            )

                if _foundry_promoted_gitleaks:
                    try:
                        promoted_findings = await _gated(
                            lambda: _run_foundry_gitleaks(_foundry_promoted_gitleaks)
                        )
                        prescan_findings.extend(
                            retain_promoted_findings(
                                _foundry_promoted_gitleaks, promoted_findings
                            )
                        )
                    except Exception:  # noqa: BLE001 - scanner failure isolation
                        _degrade_promoted_pack_coverage(
                            scanner_name="gitleaks",
                            input_paths=set(eligible),
                            coverage_outcomes=coverage_outcomes,
                            scanner_statuses=scanner_statuses,
                            provenance_status=toolchain_provenance["gitleaks"]["status"],
                        )
                        await _emit_scan_activity(
                            scan_id,
                            "SCANNER_RUN",
                            EV_FAILED,
                            {
                                "scanner": "gitleaks",
                                "pack": "tenant_foundry",
                                "mode": "promoted",
                                "message": "Promoted tenant rule pack failed; coverage is reduced.",
                            },
                            activity_kind="degradation",
                        )
                        await record_promoted_degradation_safely(
                            rules=_foundry_promoted_gitleaks,
                            scan_id=uuid.UUID(str(scan_id)),
                            reason_code="scanner_execution_failed",
                        )
                        logger.warning(
                            "rule_foundry.promoted_gitleaks_failed scan_id=%s",
                            scan_id,
                            exc_info=True,
                        )
                if _foundry_shadow_gitleaks:
                    try:
                        shadow_findings = await _gated(
                            lambda: _run_foundry_gitleaks(_foundry_shadow_gitleaks)
                        )
                        for foundry_rule in _foundry_shadow_gitleaks:
                            rule_id = (
                                f"foundry.{foundry_rule.candidate_id}."
                                f"{foundry_rule.version_id}"
                            )
                            unexpected_files = {
                                finding.file_path
                                for finding in shadow_findings
                                if finding.scanner_rule_id == rule_id
                            }
                            await record_shadow_observation_safely(
                                rule=foundry_rule,
                                scan_id=uuid.UUID(str(scan_id)),
                                eligible_files=len(eligible),
                                unexpected_matches=len(unexpected_files),
                            )
                    except Exception:  # noqa: BLE001 - shadow never breaks scans
                        logger.warning(
                            "rule_foundry.shadow_gitleaks_failed scan_id=%s",
                            scan_id,
                            exc_info=True,
                        )

                if _foundry_promoted_osv:
                    try:
                        prescan_findings.extend(
                            build_promoted_osv_findings(
                                _foundry_promoted_osv, bom_cyclonedx
                            )
                        )
                    except Exception:  # noqa: BLE001 - scanner failure isolation
                        _degrade_promoted_pack_coverage(
                            scanner_name="osv",
                            input_paths={"<repository>"},
                            coverage_outcomes=coverage_outcomes,
                            scanner_statuses=scanner_statuses,
                            provenance_status=toolchain_provenance["osv"]["status"],
                        )
                        await _emit_scan_activity(
                            scan_id,
                            "SCANNER_RUN",
                            EV_FAILED,
                            {
                                "scanner": "osv",
                                "pack": "tenant_foundry",
                                "mode": "promoted",
                                "message": "Promoted tenant rule pack failed; coverage is reduced.",
                            },
                            activity_kind="degradation",
                        )
                        await record_promoted_degradation_safely(
                            rules=_foundry_promoted_osv,
                            scan_id=uuid.UUID(str(scan_id)),
                            reason_code="advisory_match_failed",
                        )
                        logger.warning(
                            "rule_foundry.promoted_osv_failed scan_id=%s",
                            scan_id,
                            exc_info=True,
                        )
                for foundry_rule in _foundry_shadow_osv:
                    try:
                        eligible_components, matched_components = osv_observation_counts(
                            foundry_rule, bom_cyclonedx
                        )
                        await record_shadow_observation_safely(
                            rule=foundry_rule,
                            scan_id=uuid.UUID(str(scan_id)),
                            eligible_files=eligible_components,
                            unexpected_matches=matched_components,
                        )
                    except Exception:  # noqa: BLE001 - shadow never breaks scans
                        logger.warning(
                            "rule_foundry.shadow_osv_failed scan_id=%s candidate_id=%s",
                            scan_id,
                            foundry_rule.candidate_id,
                            exc_info=True,
                        )
        logger.info(
            "deterministic_prescan: scan_id=%s eligible_files=%d findings=%d bom=%s",
            scan_id,
            len(eligible),
            len(prescan_findings),
            "present" if bom_cyclonedx else "absent",
        )
    except Exception as exc:  # noqa: BLE001
        # N15: prescan-fail policy — never block the LLM analysis on a
        # prescan crash. Log and continue with whatever we collected.
        # The scanner stdout / exception text is NOT embedded in
        # `Scan.error_message` (it could carry secret-shaped content).
        logger.warning(
            "deterministic_prescan: scan_id=%s prescan_failed continuing without findings: %s",
            scan_id,
            exc,
        )
        await _emit_scan_activity(
            scan_id,
            "DETERMINISTIC_PRESCAN",
            EV_FAILED,
            {
                "message": "Prescan failed; continuing with reduced deterministic coverage."
            },
        )
        try:
            failed_outcomes = [
                CoverageOutcome(
                    scanner_name=item.scanner_name,
                    input_path=item.input_path,
                    status="failed",
                    reason_code="prescan_orchestration_failure",
                    reason="Prescan orchestration failed before this input completed.",
                )
                for item in coverage_plan.values()
                if item.status == "planned"
            ]
            async with AsyncSessionLocal() as db:
                await ScannerCoverageRepository(db).record_outcomes(
                    scan_id, [*coverage_outcomes, *failed_outcomes]
                )
        except Exception as coverage_exc:  # noqa: BLE001
            logger.warning(
                "deterministic_prescan: failed to persist crash coverage scan_id=%s: %s",
                scan_id,
                coverage_exc,
            )
        return {"findings": [], "bom_cyclonedx": None}

    try:
        async with AsyncSessionLocal() as db:
            coverage_entries = await ScannerCoverageRepository(db).record_outcomes(
                scan_id, coverage_outcomes
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "deterministic_prescan: coverage outcome persistence failed scan_id=%s: %s",
            scan_id,
            exc,
        )

    # Persist the BOM column eagerly so it survives the upcoming
    # interrupt(); LangGraph state writes happen via the checkpointer
    # but the BOM is bulk JSONB and we want it on the Scan row for
    # admin / compliance lookups even if the scan never resumes.
    if bom_cyclonedx is not None:
        try:
            async with AsyncSessionLocal() as db:
                await ScanRepository(db).update_bom_cyclonedx(scan_id, bom_cyclonedx)
        except Exception as e:
            logger.warning(
                "deterministic_prescan: failed to persist BOM scan_id=%s err=%s",
                scan_id,
                e,
            )

    # Persist the raw JSON emitted by each deterministic scanner as one
    # versioned artifact. Gitleaks is invoked with --redact; every report is
    # size-bounded before this write. The artifact remains scan-scoped and is
    # exposed only through the authenticated scanner-report endpoint.
    try:
        from app.infrastructure.database.repositories.scan_artifact_repo import (
            ARTIFACT_TYPE_SCANNER_REPORTS,
            ScanArtifactRepository,
        )

        async with AsyncSessionLocal() as db:
            await ScanArtifactRepository(db).create_next_version(
                scan_id=scan_id,
                artifact_type=ARTIFACT_TYPE_SCANNER_REPORTS,
                payload={
                    "schema_version": 2,
                    "scan_id": str(scan_id),
                    "reports": native_reports,
                    "scanner_statuses": scanner_statuses,
                    "toolchain_provenance": toolchain_provenance,
                    "coverage_entry_ids": {
                        scanner_name: sorted(
                            str(entry.id)
                            for (entry_scanner, _), entry in coverage_entries.items()
                            if entry_scanner == scanner_name
                        )
                        for scanner_name in native_reports
                    },
                },
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "deterministic_prescan: scanner report persistence failed scan_id=%s: %s",
            scan_id,
            exc,
        )

    source_counts: Dict[str, int] = {}
    lineage_counts: Dict[str, int] = {}
    original_file_map = state.get("initial_file_map") or {}
    for finding in prescan_findings:
        source = finding.source or "unknown"
        source_counts[source] = source_counts.get(source, 0) + 1
        producer_key = f"scanner:{source}:{finding.file_path}"
        occurrence_index = lineage_counts.get(producer_key, 0)
        lineage_counts[producer_key] = occurrence_index + 1
        finding.raw_finding_id = finding.raw_finding_id or raw_finding_id(
            scan_id, producer_key, occurrence_index
        )
        finding.source_snapshot_hash = (
            finding.source_snapshot_hash or original_file_map.get(finding.file_path)
        )
        coverage_entry = coverage_entries.get((source, finding.file_path))
        if coverage_entry is None and source == "osv":
            coverage_entry = coverage_entries.get(("osv", "<repository>"))
        finding.coverage_entry_id = (
            coverage_entry.id if coverage_entry is not None else None
        )
        finding.coverage_entry_ids = (
            [coverage_entry.id] if coverage_entry is not None else []
        )
    await _emit_scan_activity(
        scan_id,
        "DETERMINISTIC_PRESCAN",
        EV_COMPLETED,
        {
            "files_total": len(eligible),
            "findings_count": len(prescan_findings),
            "categories": source_counts,
            "coverage_status": (
                "degraded"
                if any(
                    entry.status in DEGRADED_COVERAGE_STATES
                    for entry in coverage_entries.values()
                )
                else "complete"
            ),
        },
    )

    # Persist the deterministic findings HERE — exactly once per scan.
    # This used to live inside `pending_prescan_approval_node` (just
    # before its `interrupt()`), but LangGraph re-enters interrupted
    # nodes from the top on resume, so the body ran a second time
    # whenever the operator clicked Continue / Stop on the prescan
    # card and `save_findings` inserted the same rows a second time.
    # The downstream `user_decline_node` / `blocked_pre_llm_node` then
    # ran a third save, and `save_results_node` (SUGGEST/AUDIT) a
    # fourth — every prescan finding ended up duped 3-4× in the DB.
    # Keeping the persist in this node, which never re-enters because
    # it has no `interrupt()`, fixes the lot. `save_findings` also
    # hydrates `id` back onto each schema so the downstream nodes can
    # detect "already persisted" rows and skip re-inserting them.
    if prescan_findings:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)
            await repo.save_findings(scan_id, prescan_findings, finding_bucket="sast")
            gate = await ApprovalGateRepository(db).create_or_get_pending(
                scan_id=scan_id,
                kind="prescan_approval",
                node_name="pending_prescan_approval",
                display_name="Review deterministic scanner findings",
                purpose=(
                    "Review deterministic evidence before any LLM profiling or "
                    "security-analysis spend."
                ),
                evidence={
                    "findings": sorted(
                        [
                            {
                                "raw_finding_id": str(f.raw_finding_id),
                                "source": f.source,
                                "scanner_rule_id": f.scanner_rule_id,
                                "file_path": f.file_path,
                                "line_number": f.line_number,
                                "severity": f.severity,
                            }
                            for f in prescan_findings
                        ],
                        key=lambda item: (
                            item["file_path"],
                            item["line_number"] or 0,
                            item["source"] or "",
                            item["raw_finding_id"],
                        ),
                    ),
                    "has_critical_secret": any(
                        f.source == "gitleaks"
                        and (f.severity or "").lower() == "critical"
                        for f in prescan_findings
                    ),
                },
                commit=False,
            )
            # Emit the prescan-gate WAITING event here — this node runs
            # exactly once and never re-enters, so the gate marker is
            # written before the bare `pending_prescan_approval` node
            # owns the interrupt() (#84). Parks status at
            # PENDING_PRESCAN_APPROVAL.
            gate_data = approval_gate_payload(gate)
            await repo.record_scan_event(
                scan_id,
                STAGE_PRESCAN_REVIEW,
                EV_WAITING,
                details=gate_data,
            )

            return {
                "findings": prescan_findings,
                "bom_cyclonedx": bom_cyclonedx,
                "active_approval_gate": gate_data,
            }

    return {"findings": prescan_findings, "bom_cyclonedx": bom_cyclonedx}


async def blocked_pre_llm_node(state: WorkerState) -> Dict[str, Any]:
    """Terminal node reached when the operator declines an override on
    a Critical Gitleaks finding (i.e. clicked Continue on the prescan-
    approval card with a Critical secret present, then clicked No on
    the override modal). Pre-ADR-009 this was an auto-route from
    `_route_after_prescan`; now it is reachable only via user-decline-
    of-override. Persists the triggering finding and sets the scan
    status to ``BLOCKED_PRE_LLM``.

    Also runs the LangGraph checkpointer-thread cleanup so this scan's
    paused state doesn't leak ~50 KB per declined attempt (M5 / G7).

    MUST NOT call ``interrupt()`` — this is a terminal route.
    """
    scan_id = state["scan_id"]
    findings = state.get("findings") or []
    triggering = next(
        (
            f
            for f in findings
            if getattr(f, "source", None) == "gitleaks"
            and (f.severity or "").lower() == "critical"
        ),
        None,
    )
    if triggering is not None:
        logger.warning(
            "blocked_pre_llm: scan_id=%s trigger=gitleaks rule=%s file=%s line=%d",
            scan_id,
            triggering.title,
            triggering.file_path,
            triggering.line_number,
        )
    else:
        logger.warning(
            "blocked_pre_llm: scan_id=%s trigger=unknown (no critical gitleaks finding on state)",
            scan_id,
        )

    # Findings were already persisted by `deterministic_prescan_node`;
    # do NOT re-save here (would dupe rows). Just flip the status.
    async with AsyncSessionLocal() as db:
        await release_scan_budget(db, scan_id, reason="blocked_pre_llm")
        await ScanRepository(db).update_status(scan_id, STATUS_BLOCKED_PRE_LLM)
    return {}


async def user_decline_node(state: WorkerState) -> Dict[str, Any]:
    """Terminal node reached when the operator clicks Stop on the
    prescan-approval card (regardless of finding severity). Distinct
    from `blocked_pre_llm_node` so the operator can distinguish
    "I rejected the secret" from "I just don't want to pay for an LLM
    scan right now".

    The deterministic findings are already persisted by
    ``deterministic_prescan_node`` so the operator can review them on
    the scan-results page even though no LLM augmentation ran (ADR-009
    / G7). This node only updates the status.
    """
    scan_id = state["scan_id"]
    findings = state.get("findings") or []
    logger.info(
        "user_decline: scan_id=%s findings=%d (operator chose Stop on prescan card)",
        scan_id,
        len(findings),
    )
    async with AsyncSessionLocal() as db:
        await release_scan_budget(db, scan_id, reason="user_declined")
        await ScanRepository(db).update_status(scan_id, STATUS_BLOCKED_USER_DECLINE)
    return {}


async def pending_prescan_approval_node(state: WorkerState) -> Dict[str, Any]:
    """Pause point for human review of the deterministic-prescan output.

    Replaces the pre-ADR-009 Critical-Gitleaks auto-block with a user-
    driven approval gate that fires whenever ``findings`` is non-empty
    after the deterministic pre-pass. The graph state is serialized
    into the Postgres checkpointer (LangGraph native interrupt); on
    resume, the payload (``approved`` + ``override_critical_secret``)
    drives the next route.

    Persists the deterministic findings BEFORE pausing so the scan-
    running page can render them while the worker is parked.
    """
    scan_id = state["scan_id"]
    findings = state.get("findings") or []
    has_critical_secret = any(
        getattr(f, "source", None) == "gitleaks"
        and (f.severity or "").lower() == "critical"
        for f in findings
    )

    # Bare interrupt gate (#84). The `deterministic_prescan` work node
    # already persisted the findings and emitted the
    # `PRESCAN_REVIEW/WAITING` event (parking status at
    # PENDING_PRESCAN_APPROVAL). This node has NO pre-interrupt side
    # effects, so a LangGraph resume — which re-runs the interrupted
    # node from the top — re-fires nothing that could duplicate an
    # event or clobber `scans.status`.
    logger.info(
        "pending_prescan_approval: scan_id=%s findings=%d critical_secret=%s — gated",
        scan_id,
        len(findings),
        has_critical_secret,
    )

    # Native LangGraph human-in-the-loop gate. The resume payload from
    # `Command(resume={"kind": "prescan_approval", ...})` lands as the
    # return value here.
    gate_data = state.get("active_approval_gate") or {}
    if not gate_data.get("gate_id"):
        async with AsyncSessionLocal() as db:
            gate = await ApprovalGateRepository(db).get_active_for_scan(scan_id)
            if gate is not None:
                gate_data = approval_gate_payload(gate)
    if not gate_data.get("gate_id"):
        return {"error_message": "Prescan approval gate identity is missing."}
    approval_payload = interrupt(
        {
            **gate_data,
            "scan_id": str(scan_id),
            "findings_count": len(findings),
            "has_critical_secret": has_critical_secret,
        }
    )
    logger.info(
        "pending_prescan_approval: scan_id=%s resumed payload=%s",
        scan_id,
        approval_payload,
    )
    if approval_payload.get("gate_id") != gate_data["gate_id"]:
        return {"error_message": "Stale prescan approval gate payload rejected."}
    async with AsyncSessionLocal() as db:
        if not await ApprovalGateRepository(db).mark_resumed(
            uuid.UUID(gate_data["gate_id"])
        ):
            return {"error_message": "Prescan gate resume claim is no longer active."}
    # V02.4.1 anti-automation: bump the persisted resume-attempt counter on
    # every resume from this gate. The cap is enforced in
    # `_route_after_prescan_approval`. The increment must happen in this node
    # (not the routing function) so the checkpointer actually persists it.
    resume_attempts = (state.get("resume_attempts") or 0) + 1
    return {
        "prescan_approval": approval_payload or {},
        "resume_attempts": resume_attempts,
    }
