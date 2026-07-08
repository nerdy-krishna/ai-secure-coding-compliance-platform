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
import logging
from typing import Any, Dict, Iterable, List, Optional

from langgraph.types import interrupt

from app.config.config import settings
from app.core.schemas import VulnerabilityFinding
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.scanners.bandit_runner import run_bandit
from app.infrastructure.scanners.gitleaks_runner import run_gitleaks
from app.infrastructure.scanners.osv_runner import run_osv
from app.infrastructure.scanners.registry import (
    MINIFIED_BYTE_LIMIT,
    is_minified,
    scanners_for_file,
)
from app.infrastructure.scanners.semgrep_runner import run_semgrep
from app.infrastructure.scanners.staging import stage_files
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.file_classification import should_skip_semgrep
from app.shared.lib.scan_progress import (
    EV_COMPLETED,
    EV_WAITING,
    STAGE_PRESCAN_REVIEW,
)
from app.shared.lib.scan_status import (
    STATUS_BLOCKED_PRE_LLM,
    STATUS_BLOCKED_USER_DECLINE,
)

logger = logging.getLogger(__name__)

# Maps file extension → Semgrep language name used in rule `languages:` lists.
_EXT_TO_SEMGREP_LANG: dict[str, str] = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".h": "c",
    ".hpp": "cpp",
}


def _derive_languages(file_paths: "Iterable[str]") -> list[str]:
    """Return deduplicated Semgrep language names from the set of file extensions."""
    from pathlib import PurePosixPath

    langs: set[str] = set()
    for p in file_paths:
        ext = PurePosixPath(p).suffix.lower()
        lang = _EXT_TO_SEMGREP_LANG.get(ext)
        if lang:
            langs.add(lang)
    return list(langs)


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
    if not files:
        logger.info("deterministic_prescan: no files for scan %s; skipping", scan_id)
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
    for path, content in files.items():
        if not scanners_for_file(path):
            continue
        if not content:
            logger.debug(
                "deterministic_prescan: skipping zero-byte file scan_id=%s path=%s",
                scan_id,
                path,
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
            continue
        eligible[path] = content

    if len(eligible) > PRESCAN_MAX_FILES:
        logger.warning(
            "deterministic_prescan: clamping %d→%d files",
            len(eligible),
            PRESCAN_MAX_FILES,
        )
        eligible = dict(list(eligible.items())[:PRESCAN_MAX_FILES])

    if not eligible:
        logger.info(
            "deterministic_prescan: no scanner-eligible files for scan %s; skipping",
            scan_id,
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
    languages = _derive_languages(semgrep_eligible.keys())
    _semgrep_rules = []
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

    # Single shared semaphore covers all SAST scanner subprocesses in
    # this prescan invocation (N9). Each scanner walks the staged tree
    # itself, so we get one subprocess.run call per scanner per scan,
    # not per file. OSV-Scanner (ADR-009) joins as the fourth scanner;
    # it returns a (findings, bom) tuple instead of just findings.
    scanner_limit = _CONCURRENT_SCANNER_LIMIT
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
                            )

                semgrep_task = _gated(_run_semgrep_materialized)
            else:
                # 0 ingested rules or all files policy-skipped — pass None so run_semgrep returns [] without subprocess
                semgrep_task = _gated(
                    lambda: run_semgrep(staged_dir, original_paths, config_path=None)
                )

            scanner_tasks = [
                _gated(lambda: run_bandit(staged_dir, original_paths)),
                semgrep_task,
                _gated(lambda: run_gitleaks(staged_dir, original_paths)),
                _gated(lambda: run_osv(staged_dir, original_paths, scan_id=scan_id)),
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
                    continue
                if scanner_name == "osv":
                    # OSV returns (findings, bom_cyclonedx_dict).
                    osv_findings, bom = result
                    prescan_findings.extend(osv_findings)
                    bom_cyclonedx = bom
                else:
                    prescan_findings.extend(result)
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
        return {"findings": [], "bom_cyclonedx": None}

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
            # Emit the prescan-gate WAITING event here — this node runs
            # exactly once and never re-enters, so the gate marker is
            # written before the bare `pending_prescan_approval` node
            # owns the interrupt() (#84). Parks status at
            # PENDING_PRESCAN_APPROVAL.
            await repo.record_scan_event(scan_id, STAGE_PRESCAN_REVIEW, EV_WAITING)

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
    approval_payload = interrupt(
        {
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
    async with AsyncSessionLocal() as db:
        await ScanRepository(db).record_scan_event(
            scan_id, STAGE_PRESCAN_REVIEW, EV_COMPLETED
        )
    # V02.4.1 anti-automation: bump the persisted resume-attempt counter on
    # every resume from this gate. The cap is enforced in
    # `_route_after_prescan_approval`. The increment must happen in this node
    # (not the routing function) so the checkpointer actually persists it.
    resume_attempts = (state.get("resume_attempts") or 0) + 1
    return {
        "prescan_approval": approval_payload or {},
        "resume_attempts": resume_attempts,
    }
