"""Deterministic file-classification worker-graph node."""

from __future__ import annotations

import logging
from typing import Any, Dict

from app.infrastructure.database import AsyncSessionLocal
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.workflows.state import WorkerState
from app.shared.lib.file_classification import CATEGORY_UNKNOWN, classify_file
from app.shared.lib.scan_progress import EV_COMPLETED, EV_STARTED

logger = logging.getLogger(__name__)

STAGE_FILE_CLASSIFICATION = "CLASSIFYING_FILES"


async def classify_files_node(state: WorkerState) -> Dict[str, Any]:
    scan_id = state["scan_id"]
    files: Dict[str, str] = state.get("files") or {}
    existing_profiles: Dict[str, Any] = state.get("file_profiles") or {}

    try:
        async with AsyncSessionLocal() as db:
            await ScanRepository(db).record_scan_event(
                scan_id, STAGE_FILE_CLASSIFICATION, EV_STARTED
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "classify_files: start event failed scan_id=%s err=%s", scan_id, exc
        )

    classifications: Dict[str, Any] = {}
    warning_count = 0
    submitted_paths = set(files.keys())
    for path, content in files.items():
        try:
            metadata = classify_file(path, content, submitted_paths=submitted_paths)
        except Exception as exc:  # noqa: BLE001
            logger.warning(
                "classify_files: fail-open path=%s scan_id=%s err=%s",
                path,
                scan_id,
                exc,
            )
            metadata = {
                "classification": CATEGORY_UNKNOWN,
                "coverage_policy": {
                    "llm_profile": True,
                    "llm_analysis": True,
                    "semgrep": True,
                    "gitleaks": True,
                    "dependency_intel": False,
                },
                "coverage_warnings": ["classification_failed_open"],
                "evidence": ["classification_error"],
            }
        warning_count += len(metadata.get("coverage_warnings") or [])
        classifications[path] = metadata

    merged_profiles: Dict[str, Any] = dict(existing_profiles)
    for path, metadata in classifications.items():
        current = dict(merged_profiles.get(path) or {})
        current.update(metadata)
        merged_profiles[path] = current
    merged_profiles["_classification_policy"] = {
        "version": "file-classification-v1",
        "files_total": len(files),
        "warnings_total": warning_count,
    }

    try:
        async with AsyncSessionLocal() as db:
            repo = ScanRepository(db)
            await repo.update_scan_artifacts(
                scan_id, {"file_profiles": merged_profiles}
            )
            await repo.record_scan_event(
                scan_id,
                STAGE_FILE_CLASSIFICATION,
                EV_COMPLETED,
                details={
                    "files_total": len(files),
                    "warnings_total": warning_count,
                    "categories": _category_counts(classifications),
                },
            )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "classify_files: persist event failed scan_id=%s err=%s", scan_id, exc
        )

    return {"file_profiles": merged_profiles}


def _category_counts(classifications: Dict[str, Any]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for metadata in classifications.values():
        category = str(metadata.get("classification") or CATEGORY_UNKNOWN)
        counts[category] = counts.get(category, 0) + 1
    return counts
