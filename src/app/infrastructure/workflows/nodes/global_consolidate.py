"""Global deterministic consolidation for repeated multi-file findings."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Dict, List, Tuple

from app.core.schemas import AffectedLocation, VulnerabilityFinding
from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState

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
    primary.id = None
    return primary


async def global_consolidate_findings_node(
    state: WorkerState,
) -> Dict[str, List[VulnerabilityFinding]]:
    findings: List[VulnerabilityFinding] = state.get("findings") or []
    if not findings:
        await _emit_event(
            state["scan_id"],
            {"input_count": 0, "output_count": 0, "merged_clusters": 0},
        )
        return {"findings": []}

    clusters: Dict[Tuple[str, str, str, str], List[VulnerabilityFinding]] = defaultdict(
        list
    )
    for finding in findings:
        clusters[_cluster_key(finding)].append(finding)

    output: List[VulnerabilityFinding] = []
    merged_clusters = 0
    for items in clusters.values():
        files = {item.file_path for item in items}
        if len(items) > 1 and len(files) > 1:
            output.append(_merge_cluster(items))
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
    return {"findings": output}


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
