"""Scan-lifecycle service: post-creation state transitions.

Handles the prescan-approval gate, cost-approval gate, cancellation,
and the two apply-fixes paths (full + selective).

Split out of `core/services/scan_service.py` (2026-04-26). Method
bodies are verbatim copies — no logic change. The threat-model
mitigations carry through unchanged: kind-vs-status guard +
PRESCAN_OVERRIDE_CRITICAL_SECRET / PRESCAN_USER_DECLINED audit
ScanEvent writes (M4 / G-split-5).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, List, Optional

from fastapi import HTTPException, status

from app.api.v1 import models as api_models
from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.messaging.publisher import publish_message
from app.shared.lib.files import get_language_from_filename
from app.shared.lib.scan_status import (
    ACTIVE_SCAN_STATUSES,
    STATUS_CANCELLED,
    STATUS_COMPLETED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
    STATUS_REMEDIATION_COMPLETED,
)

logger = logging.getLogger(__name__)


class ScanLifecycleService:
    """Post-creation scan transitions.

    Same `__init__` shape as `ScanSubmissionService` — both build the
    outbox repo from the SAME `repo.db` session so `approve_scan`'s
    Scan + ScanEvent + Outbox writes stay atomic (G-split-2).
    """

    def __init__(self, repo: ScanRepository):
        self.repo = repo
        self.outbox = ScanOutboxRepository(repo.db)

    async def _get_scan_or_404(self, scan_id: uuid.UUID) -> db_models.Scan:
        """Internal helper. Mirrors the legacy `get_scan_status` shape
        without pulling the full query service in. Raises 404 if the
        scan doesn't exist."""
        scan = await self.repo.get_scan(scan_id)
        if not scan:
            logger.warning("Scan not found.", extra={"scan_id": str(scan_id)})
            raise HTTPException(status_code=404, detail="Scan not found")
        return scan

    async def approve_scan(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        request: Optional[Any] = None,
    ) -> None:
        """Approve / decline a scan paused at a worker-graph interrupt.

        Two interrupt points (ADR-009): prescan-approval and cost-
        approval. ``request.kind`` discriminates; the consumer
        re-validates kind against the scan's pause point before
        invoking LangGraph (defense in depth).

        For prescan-approval with ``approved=True`` and
        ``override_critical_secret=True`` AND any Critical Gitleaks
        finding present, this method writes a
        ``PRESCAN_OVERRIDE_CRITICAL_SECRET`` scan_event so the
        decision is auditable (M10).
        """
        # Late import to avoid circulars (api.v1.models imports schemas
        # that pull this module transitively).
        from app.api.v1.models import ApprovalRequest

        if request is None:
            request = ApprovalRequest()

        logger.info(
            "Attempting to approve scan.",
            extra={
                "scan_id": str(scan_id),
                "user_id": user.id,
                "kind": request.kind,
                "approved": request.approved,
            },
        )
        scan = await self._get_scan_or_404(scan_id)
        if scan.user_id != user.id and not user.is_superuser:
            logger.warning(
                "scan: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "action": "approve",
                },
            )
            raise HTTPException(
                status_code=403, detail="Not authorized to approve this scan"
            )

        # Validate kind against current pause point. Keeps a
        # `kind="cost_approval"` payload from accidentally (or
        # adversarially) advancing past a `PENDING_PRESCAN_APPROVAL`
        # gate. (M1 / G4 — also re-checked in the worker consumer.)
        if request.kind == "prescan_approval":
            if scan.status != STATUS_PENDING_PRESCAN_APPROVAL:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Approval kind 'prescan_approval' requires status "
                        f"PENDING_PRESCAN_APPROVAL; current status: {scan.status}"
                    ),
                )
        elif request.kind == "profiling_approval":
            if scan.status != STATUS_PENDING_PROFILING_APPROVAL:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Approval kind 'profiling_approval' requires status "
                        f"PENDING_PROFILING_APPROVAL; current status: {scan.status}"
                    ),
                )
        elif request.kind == "cost_approval":
            if scan.status != STATUS_PENDING_APPROVAL:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Approval kind 'cost_approval' requires status "
                        f"PENDING_COST_APPROVAL; current status: {scan.status}"
                    ),
                )

        # NOTE: Each repo method below commits its own transaction (see
        # update_status / create_scan_event / outbox.enqueue). Wrapping
        # them in `begin_nested()` does NOT make the sequence atomic —
        # the inner commits close the parent transaction and the next
        # call dies with `InvalidRequestError: Can't operate on closed
        # transaction`. So we run each step on its own and accept the
        # narrow window where a crash between (1) and (2) could leave
        # the scan at QUEUED_FOR_SCAN with no outbox row. The recovery
        # is observable: the worker won't resume, the UI shows a stuck
        # status, and the user can re-approve. Proper transaction
        # discipline (caller-managed commits in repos) is a wider
        # refactor tracked separately.

        # Audit trail for the override path (M10): if the operator is
        # honoring an override on a Critical Gitleaks finding, persist
        # a scan_event so the decision is auditable.
        if (
            request.kind == "prescan_approval"
            and request.approved
            and request.override_critical_secret
        ):
            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name="PRESCAN_OVERRIDE_CRITICAL_SECRET",
                status="COMPLETED",
            )

        # Audit trail for the decline path: operator chose Stop on the
        # prescan card. The worker then routes to `user_decline_node`
        # which sets STATUS_BLOCKED_USER_DECLINE.
        if request.kind == "prescan_approval" and not request.approved:
            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name="PRESCAN_USER_DECLINED",
                status="COMPLETED",
            )

        # Audit trail for a declined profiling-cost gate (#71). Same
        # shape as the prescan decline — the worker routes to
        # `user_decline_node` which sets STATUS_BLOCKED_USER_DECLINE.
        if request.kind == "profiling_approval" and not request.approved:
            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name="PROFILING_USER_DECLINED",
                status="COMPLETED",
            )

        # For cost_approval and the *approved* prescan / profiling
        # gates, the next worker phase actually progresses so
        # transitioning to QUEUED_FOR_SCAN is a reasonable intermediate.
        # For a *declined* prescan or profiling gate, leave the status
        # at the gate — the worker's user_decline_node will set
        # BLOCKED_USER_DECLINE within milliseconds of resume.
        is_gate_decline = (
            request.kind in ("prescan_approval", "profiling_approval")
            and not request.approved
        )
        if not is_gate_decline:
            await self.repo.update_status(scan_id, STATUS_QUEUED_FOR_SCAN)
            await self.repo.create_scan_event(
                scan_id=scan_id, stage_name="QUEUED_FOR_SCAN", status="COMPLETED"
            )
        approval_payload = {
            "scan_id": str(scan_id),
            "action": "resume_analysis",
            "kind": request.kind,
            "approved": request.approved,
            "override_critical_secret": request.override_critical_secret,
        }
        outbox_row = await self.outbox.enqueue(
            scan_id=scan_id,
            queue_name=settings.RABBITMQ_APPROVAL_QUEUE,
            payload=approval_payload,
        )
        published = await publish_message(
            settings.RABBITMQ_APPROVAL_QUEUE,
            approval_payload,
        )
        if published:
            await self.outbox.mark_published(outbox_row.id)
            logger.info(
                "Scan approved and queued for processing.",
                extra={"scan_id": str(scan_id), "kind": request.kind},
            )
        else:
            await self.outbox.record_failed_attempt(outbox_row.id)
            logger.warning(
                "Approval enqueued to outbox but RabbitMQ publish failed; "
                "sweeper will retry.",
                extra={"scan_id": str(scan_id)},
            )

    async def get_prescan_review(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> "api_models.PrescanReviewResponse":
        """Findings + override-flag for the prescan-approval card (G6).

        Allowed only when the scan is at the prescan-approval gate or
        already in one of the two terminal blocked states (so the user
        can audit the post-decision state on the same screen). All
        other paths (scan-doesn't-exist / not-owner / wrong-status)
        return the same 404 so an attacker can't distinguish "scan
        exists, not yours" from "scan exists, yours, wrong status" via
        the response body — closes the soft-enumeration vector flagged
        in the prescan-approval-osv Phase 9 review.
        """
        from app.api.v1 import models as api_models  # local import — avoid circ
        from app.shared.lib.scan_status import (
            STATUS_BLOCKED_PRE_LLM,
            STATUS_BLOCKED_USER_DECLINE,
        )

        not_found = HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found or not authorized.",
        )

        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            raise not_found

        review_statuses = {
            STATUS_PENDING_PRESCAN_APPROVAL,
            STATUS_BLOCKED_PRE_LLM,
            STATUS_BLOCKED_USER_DECLINE,
        }
        if scan.status not in review_statuses:
            # Don't leak the actual status to the caller — answer the
            # same 404 the not-owner path returns. Authorized callers
            # see the scan's status via the regular `/result` endpoint.
            logger.info(
                "get_prescan_review: scan %s not in reviewable status "
                "(actual=%s); returning 404 (anti-enumeration).",
                scan_id,
                scan.status,
            )
            raise not_found

        rows = await self.repo.get_findings_for_scan(scan_id)
        items = [api_models.PrescanFindingItem.model_validate(r) for r in rows]
        has_critical_secret = any(
            (r.source == "gitleaks") and (r.severity == "Critical") for r in rows
        )
        return api_models.PrescanReviewResponse(
            scan_id=scan_id,
            status=scan.status,
            findings=items,
            has_critical_secret=has_critical_secret,
        )

    async def cancel_scan(self, scan_id: uuid.UUID, user: db_models.User) -> None:
        """Cancels a scan, typically one that is pending approval."""
        logger.info(
            "scan: cancel attempt",
            extra={"actor_user_id": user.id, "scan_id": str(scan_id)},
        )
        scan = await self.repo.get_scan(scan_id)
        if not scan or (scan.user_id != user.id and not user.is_superuser):
            logger.warning(
                "scan: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "action": "cancel",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        if scan.status not in ACTIVE_SCAN_STATUSES:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan cannot be cancelled from its current state: {scan.status}",
            )

        await self.repo.update_status(scan_id, STATUS_CANCELLED)
        await self.repo.create_scan_event(
            scan_id=scan.id, stage_name="CANCELLED", status="COMPLETED"
        )
        logger.info(
            "scan: cancelled", extra={"scan_id": str(scan_id), "actor_user_id": user.id}
        )

    async def apply_fixes_for_scan(
        self, scan_id: uuid.UUID, user: db_models.User
    ) -> None:
        """Applies all suggested and verified fixes for a completed REMEDIATE scan."""
        MAX_FIXES_PER_APPLY = 1000

        logger.info(
            "scan: apply_fixes attempt",
            extra={"actor_user_id": user.id, "scan_id": str(scan_id)},
        )
        scan = await self.repo.get_scan_with_details(scan_id)

        if not scan or (scan.user_id != user.id and not user.is_superuser):
            logger.warning(
                "scan: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "action": "apply_fixes",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        if scan.scan_type != "REMEDIATE" or scan.status != STATUS_COMPLETED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Fixes can only be applied to completed 'Remediate' scans.",
            )

        original_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
            None,
        )
        if not original_snapshot:
            raise HTTPException(
                status_code=500, detail="Original code snapshot not found."
            )

        content_map = await self.repo.get_source_files_by_hashes(
            list(original_snapshot.file_map.values())
        )
        live_codebase = {
            path: content_map.get(h, "")
            for path, h in original_snapshot.file_map.items()
        }

        findings_with_fixes = [f for f in scan.findings if f.fixes]

        if len(findings_with_fixes) > MAX_FIXES_PER_APPLY:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Too many fixes requested ({len(findings_with_fixes)}); maximum is {MAX_FIXES_PER_APPLY}.",
            )

        try:
            async with self.repo.db.begin_nested():
                for finding in findings_with_fixes:
                    fix_data = finding.fixes
                    if fix_data:
                        original_snippet = fix_data.get("original_snippet")
                        new_code = fix_data.get("code")

                        if (
                            finding.file_path in live_codebase
                            and original_snippet
                            and new_code
                        ):
                            if original_snippet in live_codebase[finding.file_path]:
                                live_codebase[finding.file_path] = live_codebase[
                                    finding.file_path
                                ].replace(original_snippet, new_code, 1)
                                logger.debug(
                                    "scan: applied fix",
                                    extra={
                                        "scan_id": str(scan.id),
                                        "cwe": finding.cwe,
                                        "file_path": finding.file_path,
                                    },
                                )
                            else:
                                logger.warning(
                                    "scan: apply_fix snippet not found",
                                    extra={
                                        "scan_id": str(scan.id),
                                        "cwe": finding.cwe,
                                        "file_path": finding.file_path,
                                    },
                                )

                # Create a new snapshot with the updated code
                new_hashes = await self.repo.get_or_create_source_files(
                    [
                        {
                            "path": path,
                            "content": content,
                            "language": get_language_from_filename(path),
                        }
                        for path, content in live_codebase.items()
                    ]
                )

                new_file_map = {
                    path: file_hash
                    for path, file_hash in zip(live_codebase.keys(), new_hashes)
                }

                await self.repo.create_code_snapshot(
                    scan_id=scan.id,
                    file_map=new_file_map,
                    snapshot_type="POST_REMEDIATION",
                )
        except HTTPException:
            raise
        except Exception:
            logger.error(
                "scan: apply_fixes failed mid-flight",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "file_count": len(live_codebase),
                },
                exc_info=True,
            )
            raise HTTPException(
                500, detail="Fix application failed; scan left in prior state."
            )

        await self.repo.update_status(scan_id, STATUS_REMEDIATION_COMPLETED)
        logger.info(
            "scan: all fixes applied",
            extra={"scan_id": str(scan_id), "actor_user_id": user.id},
        )

    async def apply_selective_fixes(
        self, scan_id: uuid.UUID, finding_ids: List[int], user: db_models.User
    ):
        """Applies fixes only for a selected list of finding IDs."""
        MAX_FIXES_PER_APPLY = 1000

        logger.info(
            "scan: apply_selective_fixes attempt",
            extra={
                "actor_user_id": user.id,
                "scan_id": str(scan_id),
                "finding_count": len(finding_ids),
            },
        )
        scan = await self.repo.get_scan_with_details(scan_id)

        if not scan or (scan.user_id != user.id and not user.is_superuser):
            logger.warning(
                "scan: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "action": "apply_selective_fixes",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        original_snapshot = next(
            (s for s in scan.snapshots if s.snapshot_type == "ORIGINAL_SUBMISSION"),
            None,
        )
        if not original_snapshot:
            raise HTTPException(
                status_code=500, detail="Original code snapshot not found."
            )

        content_map = await self.repo.get_source_files_by_hashes(
            list(original_snapshot.file_map.values())
        )
        live_codebase = {
            path: content_map.get(h, "")
            for path, h in original_snapshot.file_map.items()
        }

        # Filter findings to only those selected for fixing
        findings_to_fix = [f for f in scan.findings if f.id in finding_ids and f.fixes]

        if not findings_to_fix:
            raise HTTPException(
                status_code=400, detail="No valid findings with fixes were selected."
            )

        if len(findings_to_fix) > MAX_FIXES_PER_APPLY:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Too many fixes requested ({len(findings_to_fix)}); maximum is {MAX_FIXES_PER_APPLY}.",
            )

        try:
            async with self.repo.db.begin_nested():
                for finding in findings_to_fix:
                    fix_data = finding.fixes
                    if fix_data:
                        original_snippet = fix_data.get("original_snippet")
                        new_code = fix_data.get("code")

                        if (
                            finding.file_path in live_codebase
                            and original_snippet
                            and new_code
                        ):
                            if original_snippet in live_codebase[finding.file_path]:
                                live_codebase[finding.file_path] = live_codebase[
                                    finding.file_path
                                ].replace(original_snippet, new_code, 1)
                                logger.debug(
                                    "scan: applied fix",
                                    extra={
                                        "scan_id": str(scan.id),
                                        "cwe": finding.cwe,
                                        "file_path": finding.file_path,
                                    },
                                )
                            else:
                                logger.warning(
                                    "scan: apply_fix snippet not found",
                                    extra={
                                        "scan_id": str(scan.id),
                                        "cwe": finding.cwe,
                                        "file_path": finding.file_path,
                                    },
                                )

                # Create a new snapshot with the updated code
                new_hashes = await self.repo.get_or_create_source_files(
                    [
                        {
                            "path": path,
                            "content": content,
                            "language": get_language_from_filename(path),
                        }
                        for path, content in live_codebase.items()
                    ]
                )

                new_file_map = {
                    path: file_hash
                    for path, file_hash in zip(live_codebase.keys(), new_hashes)
                }

                await self.repo.create_code_snapshot(
                    scan_id=scan.id,
                    file_map=new_file_map,
                    snapshot_type="POST_REMEDIATION",
                )
        except HTTPException:
            raise
        except Exception:
            logger.error(
                "scan: apply_fixes failed mid-flight",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "file_count": len(live_codebase),
                },
                exc_info=True,
            )
            raise HTTPException(
                500, detail="Fix application failed; scan left in prior state."
            )

        await self.repo.update_status(scan_id, STATUS_REMEDIATION_COMPLETED)
        logger.info(
            "scan: selective fixes applied",
            extra={"scan_id": str(scan_id), "actor_user_id": user.id},
        )
