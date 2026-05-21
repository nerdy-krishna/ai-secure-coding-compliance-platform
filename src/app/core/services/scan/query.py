"""Scan-query service: read paths + scoped delete operations.

Split out of `core/services/scan_service.py` (2026-04-26). Method
bodies are verbatim copies — no logic change.

Note: the two delete methods live here (rather than in lifecycle)
because they share the read-side authorization model
(superuser-only) and the discovery groups them with the query
service. The superuser guards remain the FIRST statements of each
method (M6 / G-split-6).
"""

from __future__ import annotations

import logging
import uuid
from itertools import groupby
from operator import attrgetter
from typing import Dict, List, Optional

from fastapi import HTTPException, status
from sqlalchemy import func, select

from app.api.v1 import models as api_models
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.scan_task_repo import ScanTaskRepository
from app.shared.lib.files import get_language_from_filename
from app.shared.lib.risk_score import compute_cvss_aggregate, scoreable_findings
from app.shared.lib.scan_status import (
    ACTIVE_SCAN_STATUSES,
    COMPLETED_SCAN_STATUSES,
    STATUS_PENDING_APPROVAL,
)

logger = logging.getLogger(__name__)

MAX_PAGE_SIZE = 100
_VALID_SORT_ORDERS = {"asc", "desc"}


def _scan_metrics(scan: db_models.Scan) -> Dict[str, object]:
    """Finding-metrics overview for a scan-list row (#86).

    Pulls the risk score and the per-severity / total finding counts
    from the already-loaded `Scan.risk_score` column and `Scan.summary`
    JSONB — no per-scan findings query. Returns Nones for scans that
    never produced a final report.
    """
    summary = (scan.summary or {}).get("summary") or {}
    severity_counts = summary.get("severity_counts")
    total = summary.get("total_findings_count")
    # Resume is always available for FAILED scans; for CANCELLED it
    # depends on durable-task artifacts (validated by the endpoint).
    can_resume = scan.status in ("FAILED", "CANCELLED")

    # Active processing time: use scan events timestamps rather than
    # created_at → completed_at, which includes dormant periods when
    # the scan was stopped and later resumed.  Falls back to wall
    # clock when no events exist.
    active_seconds: float | None = None
    if scan.events:
        timestamps = [e.timestamp for e in scan.events if e.timestamp is not None]
        if len(timestamps) >= 2:
            active_seconds = (max(timestamps) - min(timestamps)).total_seconds()
        elif len(timestamps) == 1 and scan.completed_at:
            active_seconds = (scan.completed_at - timestamps[0]).total_seconds()

    return {
        "risk_score": scan.risk_score,
        "total_findings": total if isinstance(total, int) else None,
        "severity_counts": (
            severity_counts if isinstance(severity_counts, dict) else None
        ),
        "has_resumable_artifacts": can_resume,
        "active_processing_seconds": active_seconds,
    }


class ScanQueryService:
    """Read-side scan service.

    No outbox dep; only reads from `ScanRepository`. Two superuser-only
    delete methods live here because their authorization model matches
    the read-side scope (admin-only) and the discovery groups them
    with the query surface.
    """

    def __init__(self, repo: ScanRepository):
        self.repo = repo

    async def get_scan_status(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> db_models.Scan:
        """Retrieves the status and basic details of a scan."""
        logger.info(
            "Getting scan status.",
            extra={"scan_id": str(scan_id), "actor_user_id": str(user.id)},
        )
        try:
            scan = await self.repo.get_scan(scan_id)
        except Exception:
            logger.error(
                "scan-query: read failed",
                extra={"scan_id": str(scan_id), "actor_user_id": str(user.id)},
                exc_info=True,
            )
            raise
        if not scan:
            logger.warning("Scan not found.", extra={"scan_id": str(scan_id)})
            raise HTTPException(status_code=404, detail="Scan not found")
        if scan.user_id != user.id and not user.is_superuser:
            logger.warning(
                "scan-query: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "action": "get_scan_status",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )
        return scan

    async def get_scan_result(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        include_source: bool = False,
    ) -> api_models.AnalysisResultDetailResponse:
        """
        Constructs the detailed analysis result for a given scan, including findings,
        code snapshots, and reports.

        Pass ``include_source=True`` to hydrate ``original_code_map`` /
        ``fixed_code_map``; omit it (the default) to return metadata +
        findings only without fetching source bodies.
        """
        logger.info(
            "scan-query: full result requested",
            extra={"actor_user_id": str(user.id), "scan_id": str(scan_id)},
        )
        try:
            scan = await self.repo.get_scan_with_details(scan_id)
        except Exception:
            logger.error(
                "scan-query: read failed",
                extra={"scan_id": str(scan_id), "actor_user_id": str(user.id)},
                exc_info=True,
            )
            raise

        if not scan or (scan.user_id != user.id and not user.is_superuser):
            logger.warning(
                "scan-query: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "action": "get_result",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        logger.debug(
            "[DEBUG] Fetched scan from DB.",
            extra={
                "scan_id": str(scan_id),
                "findings_count": len(scan.findings),
                "has_summary": bool(scan.summary),
            },
        )

        original_code_map = {}
        fixed_code_map = {}
        original_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
            None,
        )
        remediated_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "POST_REMEDIATION"), None
        )

        if include_source:
            if original_snapshot:
                hashes = list(original_snapshot.file_map.values())
                content_map = await self.repo.get_source_files_by_hashes(hashes)
                original_code_map = {
                    path: content_map.get(h, "")
                    for path, h in original_snapshot.file_map.items()
                }

            if remediated_snapshot:
                hashes = list(remediated_snapshot.file_map.values())
                content_map = await self.repo.get_source_files_by_hashes(hashes)
                fixed_code_map = {
                    path: content_map.get(h, "")
                    for path, h in remediated_snapshot.file_map.items()
                }

        summary_report_response = None
        if scan.summary:
            files_analyzed_map: Dict[str, api_models.SubmittedFileReportItem] = {}

            # Use repository_map (if available) to initialize the file list
            # This ensures we account for skipped files.
            repository_map = scan.repository_map or {}
            all_files_in_scan = repository_map.get("files", {})

            for file_path, file_summary_dict in all_files_in_scan.items():
                skipped_reason = None
                if file_summary_dict.get("errors"):
                    skipped_reason = file_summary_dict["errors"][0]

                files_analyzed_map[file_path] = api_models.SubmittedFileReportItem(
                    file_path=file_path,
                    findings=[],
                    language=get_language_from_filename(file_path),
                    skipped_reason=skipped_reason,
                )

            # FIX: Use a robust groupby to associate findings with files.
            # Sort findings by file_path to prepare for grouping.
            sorted_findings = sorted(
                [
                    f
                    for f in scan.findings
                    if getattr(f, "finding_bucket", "consolidated") == "consolidated"
                ],
                key=attrgetter("file_path"),
            )

            # Group findings by file_path and populate the map.
            for file_path, group in groupby(
                sorted_findings, key=attrgetter("file_path")
            ):
                if file_path in files_analyzed_map:
                    findings_for_file = [
                        api_models.VulnerabilityFindingResponse.from_orm(f)
                        for f in group
                    ]
                    files_analyzed_map[file_path].findings.extend(findings_for_file)

            summary_dict = scan.summary.get("summary", {})
            risk_score_dict = scan.summary.get("overall_risk_score", {})

            # Recompute the risk score fresh from findings so the results
            # page always reflects the current formula, not a stale
            # persisted value from when the scan completed.
            active_findings = scoreable_findings(scan.findings)
            if active_findings:
                fresh_score = compute_cvss_aggregate(
                    active_findings, scan_id=str(scan_id)
                )
                risk_score_dict = dict(risk_score_dict, score=fresh_score)

            summary_report_response = api_models.SummaryReportResponse(
                submission_id=scan.id,
                project_id=scan.project_id,
                project_name=scan.project.name if scan.project else "N/A",
                scan_type=scan.scan_type,
                selected_frameworks=scan.frameworks or [],
                analysis_timestamp=scan.completed_at,
                summary=api_models.SummaryResponse(**summary_dict),
                overall_risk_score=api_models.OverallRiskScoreResponse(
                    **risk_score_dict
                ),
                files_analyzed=list(files_analyzed_map.values()),
            )

        # --- ADD THIS LOGGING BLOCK ---
        if summary_report_response:
            total_findings_in_response = sum(
                len(f.findings) for f in summary_report_response.files_analyzed
            )
            logger.debug(
                "[DEBUG] Assembled final response.",
                extra={
                    "scan_id": str(scan_id),
                    "files_in_report": len(summary_report_response.files_analyzed),
                    "total_findings_in_response": total_findings_in_response,
                },
            )
        # --- END LOGGING BLOCK ---

        # Per-source finding counts (sast-prescan-followups Group D2).
        # Computed in the service layer (N8) so the repo stays a thin
        # data-access shim. NULL `source` is bucketed as "agent" to
        # cover legacy LLM-emitted rows.
        source_counts = await self.repo.count_findings_by_source(scan_id)

        # The LLM configs the scan ran with, by role. Utility falls back
        # to the reasoning slot when it was left unset (mirrors
        # `resolve_llm_config_id`); the second analysis LLM appears only
        # when the scan opted into it.
        from app.infrastructure.database.repositories.llm_config_repo import (
            LLMConfigRepository,
        )

        llm_repo = LLMConfigRepository(self.repo.db)
        llm_slots = [
            ("Reasoning LLM", scan.reasoning_llm_config_id),
            (
                "Utility LLM",
                scan.utility_llm_config_id or scan.reasoning_llm_config_id,
            ),
            ("2nd Analysis LLM", scan.secondary_reasoning_llm_config_id),
        ]
        llms_used: List[api_models.LLMUsageItem] = []
        _cfg_cache: Dict[uuid.UUID, object] = {}
        for category, cfg_id in llm_slots:
            if not cfg_id:
                continue
            cfg = _cfg_cache.get(cfg_id)
            if cfg is None:
                cfg = await llm_repo.get_by_id(cfg_id)
                if cfg is not None:
                    _cfg_cache[cfg_id] = cfg
            if cfg is not None:
                llms_used.append(
                    api_models.LLMUsageItem(
                        category=category,
                        name=cfg.name,
                        provider=cfg.provider,
                        model_name=cfg.model_name,
                    )
                )

        # Consolidation tally — pulled from the latest CONSOLIDATING
        # timeline event's details (worker-emitted).
        consolidation_stats = None
        for ev in reversed(scan.events or []):
            if (
                ev.stage_name == "CONSOLIDATING"
                and ev.status == "COMPLETED"
                and ev.details
            ):
                d = ev.details
                consolidation_stats = api_models.ConsolidationStats(
                    raw_count=d.get("raw_count", 0),
                    consolidated_count=d.get(
                        "consolidated_count", d.get("finding_count", 0)
                    ),
                    merged_roots=d.get("merged_roots", 0),
                    merged_inputs=d.get("merged_inputs", 0),
                    dropped=d.get("dropped", 0),
                )
                break

        task_counts = await ScanTaskRepository(self.repo.db).count_by_status_for_scan(
            scan_id
        )

        return api_models.AnalysisResultDetailResponse(
            status=scan.status,
            project_id=scan.project_id,
            project_name=scan.project.name if scan.project else "N/A",
            summary_report=summary_report_response,
            original_code_map=original_code_map or None,
            fixed_code_map=fixed_code_map or None,
            source_counts=source_counts,
            cost_details=scan.cost_details,
            cross_file_validation=bool(scan.cross_file_validation),
            deep_vendor_scan=bool(scan.deep_vendor_scan),
            llms_used=llms_used,
            consolidation_stats=consolidation_stats,
            scan_type=scan.scan_type,
            disable_temperature=bool(scan.disable_temperature),
            stage_temperatures=scan.stage_temperatures,
            source_type=scan.source_type,
            has_resumable_artifacts=sum(task_counts.values()) > 0,
            repository_url=(scan.project.repository_url if scan.project else None),
            events=[api_models.ScanEventItem.from_orm(e) for e in (scan.events or [])],
        )

    async def get_paginated_scans_for_project(
        self,
        project_id: uuid.UUID,
        user: db_models.User,
        skip: int,
        limit: int,
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> api_models.PaginatedScanHistoryResponse:
        """Retrieves a paginated list of scan history for a project.

        Authorization mirrors the rest of this service: superusers see
        every project; regular users see projects they own or projects
        owned by peers in a shared group (per the H.2 visibility scope).
        """
        skip = max(int(skip), 0)
        limit = min(max(int(limit), 1), MAX_PAGE_SIZE)
        project = await self.repo.get_project_by_id(project_id)
        is_owner = bool(project) and project.user_id == user.id
        is_admin = user.is_superuser
        is_peer = (
            bool(project)
            and visible_user_ids is not None
            and project.user_id in visible_user_ids
        )
        if not project or not (is_owner or is_admin or is_peer):
            logger.warning(
                "scan-query: authorization denied",
                extra={
                    "project_id": str(project_id),
                    "actor_user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "action": "get_project_scans",
                },
            )
            raise HTTPException(
                status_code=404, detail="Project not found or not authorized."
            )

        total = await self.repo.get_scans_count_for_project(
            project_id, tenant_id=tenant_id
        )
        scans_raw = await self.repo.get_paginated_scans_for_project(
            project_id, skip, limit, tenant_id=tenant_id
        )

        # Build ScanHistoryItem explicitly — `project_name` lives on the
        # related Project row, not on Scan, so `from_orm(scan)` raises a
        # `project_name: Field required` ValidationError. Mirrors the
        # construction pattern used in `get_paginated_user_scans` and
        # `get_user_scan_history` further down this file.
        history_items = [
            api_models.ScanHistoryItem(
                id=scan.id,
                project_id=scan.project_id,
                project_name=scan.project.name,
                scan_type=scan.scan_type,
                status=scan.status,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                cost_details=scan.cost_details,
                events=[api_models.ScanEventItem.from_orm(e) for e in scan.events],
                **_scan_metrics(scan),
            )
            for scan in scans_raw
        ]
        return api_models.PaginatedScanHistoryResponse(items=history_items, total=total)

    async def get_paginated_user_scans(
        self,
        user_id: int,
        skip: int,
        limit: int,
        search: Optional[str],
        sort_order: str,
        status: Optional[str],
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> api_models.PaginatedScanHistoryResponse:
        """Retrieves a paginated list of all scans visible to the caller."""
        skip = max(int(skip), 0)
        limit = min(max(int(limit), 1), MAX_PAGE_SIZE)
        if sort_order not in _VALID_SORT_ORDERS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid sort_order. Must be one of: {sorted(_VALID_SORT_ORDERS)}",
            )
        if search is not None and len(search) > 200:
            raise HTTPException(status_code=400, detail="search too long")

        status_filters = []
        if status:
            if status == "In Progress":
                # ACTIVE_SCAN_STATUSES includes PENDING_COST_APPROVAL, which the
                # UI filters out of "In Progress" (it has its own pill), so drop it.
                status_filters = [
                    s for s in ACTIVE_SCAN_STATUSES if s != STATUS_PENDING_APPROVAL
                ]
            elif status == "Completed":
                status_filters = list(COMPLETED_SCAN_STATUSES)
            elif status != "All":
                status_filters = [status.upper().replace(" ", "_")]

        try:
            total = await self.repo.get_scans_count_for_user(
                user_id,
                search,
                status_filters,
                visible_user_ids=visible_user_ids,
                tenant_id=tenant_id,
            )
            scans_raw = await self.repo.get_paginated_scans_for_user(
                user_id,
                skip,
                limit,
                search,
                sort_order,
                status_filters,
                visible_user_ids=visible_user_ids,
                tenant_id=tenant_id,
            )
        except Exception:
            logger.error(
                "scan-query: read failed",
                extra={"actor_user_id": str(user_id)},
                exc_info=True,
            )
            raise

        history_items = [
            api_models.ScanHistoryItem(
                id=scan.id,
                project_id=scan.project_id,
                project_name=scan.project.name,
                scan_type=scan.scan_type,
                status=scan.status,
                created_at=scan.created_at,
                completed_at=scan.completed_at,
                cost_details=scan.cost_details,
                events=[api_models.ScanEventItem.from_orm(e) for e in scan.events],
                **_scan_metrics(scan),
            )
            for scan in scans_raw
        ]
        return api_models.PaginatedScanHistoryResponse(items=history_items, total=total)

    async def search_projects(
        self,
        user_id: int,
        query: str,
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> List[str]:
        """Searches project names for autocomplete (scoped to caller)."""
        projects = await self.repo.search_projects_by_name(
            user_id=user_id,
            name_query=query,
            visible_user_ids=visible_user_ids,
            tenant_id=tenant_id,
        )
        return [project.name for project in projects]

    async def get_llm_interactions_for_scan(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> List[api_models.LLMInteractionResponse]:
        """Gets all LLM interactions for a given scan, ensuring user has
        access. Each interaction is enriched with the resolved LLM
        display name so the LLM-logs page can filter by model."""
        logger.info(
            "scan-query: LLM interactions requested",
            extra={"actor_user_id": str(user.id), "scan_id": str(scan_id)},
        )
        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            logger.warning(
                "scan-query: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "action": "llm_interactions",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        interactions = await self.repo.get_llm_interactions_for_scan(scan_id)

        # Resolve each interaction's LLM config id to its display name so
        # the UI can group/filter logs by model. Batched + cached.
        from app.infrastructure.database.repositories.llm_config_repo import (
            LLMConfigRepository,
        )

        llm_repo = LLMConfigRepository(self.repo.db)
        name_cache: Dict[uuid.UUID, Optional[str]] = {}
        responses: List[api_models.LLMInteractionResponse] = []
        for inter in interactions:
            resp = api_models.LLMInteractionResponse.from_orm(inter)
            cfg_id = inter.llm_config_id
            if cfg_id is not None:
                if cfg_id not in name_cache:
                    cfg = await llm_repo.get_by_id(cfg_id)
                    name_cache[cfg_id] = cfg.name if cfg is not None else None
                resp.llm_name = name_cache[cfg_id]
            responses.append(resp)
        return responses

    async def get_findings_debug(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> api_models.ScanFindingsDebugResponse:
        """Return raw and consolidated findings for agent debugging."""
        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        # Bucket findings
        sast: list[api_models.VulnerabilityFindingResponse] = []
        raw_llm: list[api_models.VulnerabilityFindingResponse] = []
        consolidated: list[api_models.VulnerabilityFindingResponse] = []
        for f in scan.findings:
            resp = api_models.VulnerabilityFindingResponse.from_orm(f)
            bucket = getattr(f, "finding_bucket", "consolidated")
            if bucket == "sast":
                sast.append(resp)
            elif bucket == "raw_llm":
                raw_llm.append(resp)
            else:
                consolidated.append(resp)

        # Sankey: SAST → raw_llm → consolidated flow counts.
        sast_count = len(sast)
        raw_count = len(raw_llm)
        cons_count = len(consolidated)
        nodes = [
            api_models.SankeyNode(id="sast", label=f"SAST ({sast_count})"),
            api_models.SankeyNode(id="raw_llm", label=f"Raw LLM ({raw_count})"),
            api_models.SankeyNode(
                id="consolidated", label=f"Consolidated ({cons_count})"
            ),
        ]
        links = [
            api_models.SankeyLink(
                source="sast", target="consolidated", value=sast_count
            ),
            api_models.SankeyLink(
                source="raw_llm", target="consolidated", value=raw_count
            ),
        ]

        return api_models.ScanFindingsDebugResponse(
            sast_findings=sast,
            raw_llm_findings=raw_llm,
            consolidated_findings=consolidated,
            sankey_nodes=nodes,
            sankey_links=links,
        )

    async def get_paginated_projects(
        self,
        user_id: int,
        skip: int,
        limit: int,
        search: Optional[str],
        visible_user_ids: Optional[List[int]] = None,
        tenant_id: Optional[uuid.UUID] = None,
    ) -> api_models.PaginatedProjectHistoryResponse:
        """Retrieves a paginated list of projects visible to the caller."""
        skip = max(int(skip), 0)
        limit = min(max(int(limit), 1), MAX_PAGE_SIZE)
        if search is not None and len(search) > 200:
            raise HTTPException(status_code=400, detail="search too long")
        try:
            total = await self.repo.get_projects_count(
                user_id,
                search,
                visible_user_ids=visible_user_ids,
                tenant_id=tenant_id,
            )
            projects = await self.repo.get_paginated_projects(
                user_id,
                skip,
                limit,
                search,
                visible_user_ids=visible_user_ids,
                tenant_id=tenant_id,
            )
        except Exception:
            logger.error(
                "scan-query: read failed",
                extra={"actor_user_id": str(user_id)},
                exc_info=True,
            )
            raise

        project_items: List[api_models.ProjectHistoryItem] = []
        latest_terminal_scan_by_project: Dict[uuid.UUID, uuid.UUID] = {}

        for project in projects:
            scans_raw = await self.repo.get_paginated_scans_for_project(
                project.id, 0, 5
            )  # Fetch latest 5 scans for preview
            scans = [
                api_models.ScanHistoryItem(
                    id=s.id,
                    project_id=s.project_id,
                    project_name=s.project.name,
                    scan_type=s.scan_type,
                    status=s.status,
                    created_at=s.created_at,
                    completed_at=s.completed_at,
                    cost_details=s.cost_details,
                    events=[api_models.ScanEventItem.from_orm(e) for e in s.events],
                    **_scan_metrics(s),
                )
                for s in scans_raw
            ]
            latest_terminal = next(
                (s for s in scans_raw if s.status in COMPLETED_SCAN_STATUSES),
                None,
            )
            if latest_terminal is not None:
                latest_terminal_scan_by_project[project.id] = latest_terminal.id

            project_item = api_models.ProjectHistoryItem(
                id=project.id,
                name=project.name,
                repository_url=project.repository_url,
                created_at=project.created_at,
                updated_at=project.updated_at,
                scans=scans,
            )
            project_items.append(project_item)

        stats_by_scan = await self._aggregate_project_stats(
            list(latest_terminal_scan_by_project.values())
        )
        for item in project_items:
            scan_id = latest_terminal_scan_by_project.get(item.id)
            if scan_id is None:
                continue
            item.stats = stats_by_scan.get(scan_id)

        return api_models.PaginatedProjectHistoryResponse(
            items=project_items, total=total
        )

    async def _aggregate_project_stats(
        self, scan_ids: List[uuid.UUID]
    ) -> Dict[uuid.UUID, api_models.ProjectStats]:
        """One query, grouped by (scan_id, severity), keyed back by scan_id.

        `fixes_ready` is "findings with an AI fix suggestion that hasn't been
        applied yet" — same definition as the dashboard rollup, scoped to a
        single scan instead of the whole visibility set.
        """
        if not scan_ids:
            return {}

        sev_stmt = (
            select(
                db_models.Finding.scan_id,
                func.lower(db_models.Finding.severity).label("sev"),
                func.count(db_models.Finding.id),
            )
            .where(db_models.Finding.scan_id.in_(scan_ids))
            .where(db_models.Finding.is_applied_in_remediation.is_(False))
            .group_by(db_models.Finding.scan_id, func.lower(db_models.Finding.severity))
        )
        fixes_stmt = (
            select(
                db_models.Finding.scan_id,
                func.count(db_models.Finding.id),
            )
            .where(db_models.Finding.scan_id.in_(scan_ids))
            .where(db_models.Finding.is_applied_in_remediation.is_(False))
            .where(db_models.Finding.fixes.is_not(None))
            .group_by(db_models.Finding.scan_id)
        )

        sev_rows = (await self.repo.db.execute(sev_stmt)).all()
        fix_rows = (await self.repo.db.execute(fixes_stmt)).all()

        severity_aliases = {
            "info": "informational",
            "informational": "informational",
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }

        counts: Dict[uuid.UUID, Dict[str, int]] = {
            scan_id: {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "informational": 0,
            }
            for scan_id in scan_ids
        }
        for scan_id, raw_sev, count in sev_rows:
            if raw_sev is None:
                continue
            key = severity_aliases.get(raw_sev)
            if key:
                counts[scan_id][key] += int(count)

        fixes: Dict[uuid.UUID, int] = {scan_id: 0 for scan_id in scan_ids}
        for scan_id, count in fix_rows:
            fixes[scan_id] = int(count)

        result: Dict[uuid.UUID, api_models.ProjectStats] = {}
        for scan_id in scan_ids:
            open_buckets = counts[scan_id]
            weighted = (
                open_buckets["critical"] * 15
                + open_buckets["high"] * 6
                + open_buckets["medium"] * 2
                + open_buckets["low"] * 1
            )
            risk_score = max(5, 100 - min(95, weighted))
            result[scan_id] = api_models.ProjectStats(
                risk_score=risk_score,
                open_findings=api_models.ProjectOpenFindings(**open_buckets),
                fixes_ready=fixes[scan_id],
            )
        return result

    async def delete_scan_by_id(self, scan_id: uuid.UUID, user: db_models.User):
        """Deletes a single scan, checking for superuser privileges."""
        if not user.is_superuser:
            logger.warning(
                "scan-query: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "action": "delete_scan",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superusers can delete scans.",
            )

        scan = await self.repo.get_scan(scan_id)
        if not scan:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found."
            )

        await self.repo.delete_scan(scan_id)
        logger.info(
            "scan-query: scan deleted",
            extra={"actor_user_id": str(user.id), "scan_id": str(scan_id)},
        )

    async def delete_project_by_id(self, project_id: uuid.UUID, user: db_models.User):
        """Deletes a project and all its associated scans, for superusers only."""
        if not user.is_superuser:
            logger.warning(
                "scan-query: authorization denied",
                extra={
                    "actor_user_id": str(user.id),
                    "is_superuser": user.is_superuser,
                    "action": "delete_project",
                    "project_id": str(project_id),
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only superusers can delete projects.",
            )

        project = await self.repo.get_project_by_id(project_id)
        if not project:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Project not found."
            )

        await self.repo.delete_project(project_id)
        logger.info(
            "scan-query: project deleted",
            extra={"actor_user_id": str(user.id), "project_id": str(project_id)},
        )
