"""Global deterministic consolidation for repeated multi-file findings."""

from __future__ import annotations

import logging
import uuid
from collections import defaultdict
from typing import Dict, List, Tuple

from app.core.schemas import AffectedLocation, FixResult, VulnerabilityFinding
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.finding_lineage_identity import canonical_finding_id
from app.infrastructure.workflows.nodes.consolidate import (
    _verify_syntax_with_treesitter,
)
from app.shared.lib.patch_planner import validate_candidate_replacement

logger = logging.getLogger(__name__)

STAGE_GLOBAL_CONSOLIDATION = "GLOBAL_CONSOLIDATION"


def _cluster_key(finding: VulnerabilityFinding) -> Tuple[str, str, str, str]:
    return (
        (finding.source or "agent").lower(),
        (finding.cwe or "").lower(),
        finding.title.strip().lower(),
        finding.remediation.strip().lower()[:300],
    )


def _location_for(finding: VulnerabilityFinding) -> AffectedLocation:
    return AffectedLocation(
        file_path=finding.file_path,
        line_number=finding.line_number,
        snippet=finding.vulnerable_snippet,
    )


def _merge_cluster(items: List[VulnerabilityFinding]) -> VulnerabilityFinding:
    primary = items[0].model_copy(deep=True)
    locations = []
    seen = set()
    for item in items:
        for loc in [_location_for(item)] + list(item.affected_locations or []):
            key = (loc.file_path or item.file_path, loc.line_number, loc.snippet or "")
            if key in seen:
                continue
            seen.add(key)
            if loc.file_path is None:
                loc.file_path = item.file_path
            locations.append(loc)
    primary.affected_locations = locations
    raw_ids = sorted(
        {
            raw_id
            for item in items
            for raw_id in (
                item.contributing_raw_finding_ids
                or ([item.raw_finding_id] if item.raw_finding_id else [])
            )
        },
        key=str,
    )
    primary.contributing_raw_finding_ids = raw_ids
    coverage_ids = sorted(
        {
            coverage_id
            for item in items
            for coverage_id in (
                item.coverage_entry_ids
                or (
                    [item.coverage_entry_id]
                    if item.coverage_entry_id is not None
                    else []
                )
            )
        },
        key=str,
    )
    primary.coverage_entry_ids = coverage_ids
    primary.coverage_entry_id = coverage_ids[0] if coverage_ids else None
    if raw_ids:
        primary.canonical_finding_id = canonical_finding_id(raw_ids)
    primary.id = None
    return primary


async def global_consolidate_findings_node(
    state: WorkerState,
) -> Dict[str, object]:
    findings: List[VulnerabilityFinding] = state.get("findings") or []
    if not findings:
        await _emit_event(
            state["scan_id"],
            {"input_count": 0, "output_count": 0, "merged_clusters": 0},
        )
        return {"findings": [], "fix_candidates": [], "finding_lineage": []}

    clusters: Dict[Tuple[str, str, str, str], List[VulnerabilityFinding]] = defaultdict(
        list
    )
    for finding in findings:
        clusters[_cluster_key(finding)].append(finding)

    output: List[VulnerabilityFinding] = []
    canonical_remap: dict[str, uuid.UUID] = {}
    merged_clusters = 0
    for items in clusters.values():
        files = {item.file_path for item in items}
        if len(items) > 1 and len(files) > 1:
            merged = _merge_cluster(items)
            output.append(merged)
            for item in items:
                if item.canonical_finding_id:
                    canonical_remap[str(item.canonical_finding_id)] = (
                        merged.canonical_finding_id
                    )
            merged_clusters += 1
        else:
            output.extend(items)

    logger.info(
        "global_consolidation: scan_id=%s %d -> %d merged_clusters=%d",
        state["scan_id"],
        len(findings),
        len(output),
        merged_clusters,
    )
    await _emit_event(
        state["scan_id"],
        {
            "input_count": len(findings),
            "output_count": len(output),
            "merged_clusters": merged_clusters,
        },
    )
    fix_candidates: List[FixResult] = [
        candidate.model_copy(deep=True)
        for candidate in (state.get("fix_candidates") or [])
    ]
    for candidate in fix_candidates:
        remapped = canonical_remap.get(str(candidate.canonical_finding_id))
        if remapped:
            candidate.canonical_finding_id = remapped

    live_codebase = state.get("live_codebase") or {}
    initial_file_map = state.get("initial_file_map") or {}
    for candidate in fix_candidates:
        if candidate.disposition != "selected":
            continue
        file_path = candidate.finding.file_path
        content = live_codebase.get(file_path)
        snapshot_hash = initial_file_map.get(file_path)
        if not content or snapshot_hash != candidate.source_snapshot_hash:
            candidate.validation_status = "failed"
            candidate.disposition = "rejected"
            candidate.decision_reason = (
                "Original source snapshot is unavailable or no longer matches."
            )
            continue
        decision = validate_candidate_replacement(
            candidate=candidate,
            file_path=file_path,
            source=content,
            expected_source_hash=snapshot_hash,
            syntax_validator=_verify_syntax_with_treesitter,
        )
        if decision.status == "planned":
            candidate.validation_status = "passed"
            candidate.resolved_range = decision.resolved_range
            candidate.context_fingerprint = decision.context_fingerprint
        else:
            candidate.validation_status = "failed"
            candidate.disposition = "rejected"
            candidate.applicability_status = decision.status
            candidate.decision_reason = decision.reason

    candidates_by_canonical: dict[str, list[FixResult]] = defaultdict(list)
    for candidate in fix_candidates:
        if candidate.canonical_finding_id:
            candidates_by_canonical[str(candidate.canonical_finding_id)].append(
                candidate
            )
    for finding in output:
        candidates = candidates_by_canonical.get(str(finding.canonical_finding_id), [])
        passed = sorted(
            (
                candidate
                for candidate in candidates
                if candidate.disposition == "selected"
                and candidate.validation_status == "passed"
            ),
            key=lambda item: str(item.candidate_id or ""),
        )
        if passed:
            finding.fix_selection_status = "selected"
            finding.fixes = passed[0].suggestion
        elif candidates and finding.fix_selection_status == "selected":
            finding.fix_selection_status = "none"
            finding.fixes = None

    finding_lineage = [dict(row) for row in (state.get("finding_lineage") or [])]
    for row in finding_lineage:
        remapped = canonical_remap.get(str(row.get("canonical_finding_id")))
        if remapped:
            row["canonical_finding_id"] = str(remapped)

    return {
        "findings": output,
        "fix_candidates": fix_candidates,
        "finding_lineage": finding_lineage,
    }


async def _emit_event(scan_id, details: Dict[str, int]) -> None:
    try:
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).create_scan_event(
                scan_id=scan_id,
                stage_name=STAGE_GLOBAL_CONSOLIDATION,
                status="COMPLETED",
                details=details,
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning("global_consolidation event emit failed: %s", exc)
