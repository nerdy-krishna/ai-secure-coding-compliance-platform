"""Scan-lifecycle service: post-creation state transitions.

Handles the prescan-approval gate, cost-approval gate, and scan
cancellation.

Split out of `core/services/scan_service.py` (2026-04-26). Method
bodies are verbatim copies — no logic change. The threat-model
mitigations carry through unchanged: kind-vs-status guard +
PRESCAN_OVERRIDE_CRITICAL_SECRET / PRESCAN_USER_DECLINED audit
ScanEvent writes (M4 / G-split-5).
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Optional

from fastapi import HTTPException, status

from app.api.v1 import models as api_models
from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.messaging.publisher import publish_message
from app.shared.lib.scan_status import (
    ACTIVE_SCAN_STATUSES,
    STATUS_CANCELLED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED_FOR_SCAN,
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

    async def set_finding_disposition(
        self,
        scan_id: uuid.UUID,
        finding_id: int,
        user: db_models.User,
        request: "api_models.FindingDispositionUpdateRequest",
        visible_user_ids: Optional[list[int]] = None,
    ) -> "api_models.FindingDispositionResponse":
        """Set a finding's triage disposition (PRD #96 / #97).

        Authorization follows the H.2 visibility model: any user who can
        view the scan can triage its findings (`visible_user_ids is None`
        ⇒ admin, sees everything). The transition is validated against
        `finding_disposition`; the change + an audit event are persisted
        atomically by the repository.
        """
        from app.shared.lib import finding_disposition as fd

        await self._get_triageable_scan_or_404(scan_id, user, visible_user_ids)

        # Reverting a finding to the untriaged `open` state is a delete,
        # not an add — restricted to superusers (PRD #96). Regular users
        # add and change dispositions; only admins clear them.
        if request.disposition == fd.OPEN and not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=("Only an administrator can clear a finding's " "disposition."),
            )

        finding = await self.repo.get_finding(finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found for this scan.",
            )

        current = finding.disposition or fd.DEFAULT_DISPOSITION
        try:
            fd.validate_transition(current, request.disposition, request.note)
        except fd.DispositionError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
            )

        note = request.note.strip() if request.note else None
        updated, new_score = await self.repo.apply_finding_disposition(
            finding,
            new_disposition=request.disposition,
            actor_user_id=user.id,
            note=note,
        )
        logger.info(
            "scan: finding disposition set",
            extra={
                "scan_id": str(scan_id),
                "finding_id": finding_id,
                "actor_user_id": user.id,
                "old_disposition": current,
                "new_disposition": request.disposition,
            },
        )
        return api_models.FindingDispositionResponse(
            finding_id=updated.id,
            disposition=updated.disposition,
            disposition_by=updated.disposition_by,
            disposition_at=updated.disposition_at,
            disposition_note=updated.disposition_note,
            scan_risk_score=new_score,
        )

    async def _get_triageable_scan_or_404(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        visible_user_ids: Optional[list[int]],
    ) -> db_models.Scan:
        """Fetch a scan the caller is allowed to triage (PRD #96).

        Authorization follows the H.2 visibility model: any user who can
        view the scan can triage its findings (`visible_user_ids is
        None` ⇒ admin, sees everything). A scan outside the caller's
        scope is reported as 404, not 403, so triage cannot be used to
        probe for scan existence.
        """
        scan = await self._get_scan_or_404(scan_id)
        if visible_user_ids is not None and scan.user_id not in visible_user_ids:
            logger.warning(
                "scan: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "action": "triage_findings",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )
        return scan

    async def set_finding_dispositions_bulk(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        request: "api_models.BulkFindingDispositionUpdateRequest",
        visible_user_ids: Optional[list[int]] = None,
    ) -> "api_models.BulkFindingDispositionResponse":
        """Apply one disposition (and one note) to many findings of a
        scan in a single transaction (PRD #96 / #100).

        Validation is all-or-nothing: the target disposition and the
        note requirement are checked once up front, and every requested
        finding id must belong to the scan — otherwise the whole batch
        is rejected and nothing is written. A finding already in the
        target disposition is skipped (no redundant audit row), but its
        presence is not an error.
        """
        from app.shared.lib import finding_disposition as fd

        await self._get_triageable_scan_or_404(scan_id, user, visible_user_ids)

        if not fd.is_valid_disposition(request.disposition):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown disposition {request.disposition!r}.",
            )
        if request.disposition == fd.OPEN and not user.is_superuser:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=("Only an administrator can clear a finding's " "disposition."),
            )
        if fd.note_required(request.disposition) and not (
            request.note and request.note.strip()
        ):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "A justification note is required to mark findings "
                    f"{request.disposition!r}."
                ),
            )

        requested_ids = list(dict.fromkeys(request.finding_ids))
        findings = await self.repo.get_findings_by_ids(scan_id, requested_ids)
        if len(findings) != len(requested_ids):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or more findings were not found for this scan.",
            )

        # Skip findings already in the target state — a no-op transition
        # must not land a redundant row in the audit log.
        to_change = [
            f
            for f in findings
            if (f.disposition or fd.DEFAULT_DISPOSITION) != request.disposition
        ]
        note = request.note.strip() if request.note else None
        if not to_change:
            scan = await self._get_scan_or_404(scan_id)
            return api_models.BulkFindingDispositionResponse(
                updated_count=0,
                disposition=request.disposition,
                scan_risk_score=scan.risk_score,
            )

        count, new_score = await self.repo.apply_finding_dispositions(
            scan_id,
            to_change,
            new_disposition=request.disposition,
            actor_user_id=user.id,
            note=note,
        )
        logger.info(
            "scan: bulk finding disposition set",
            extra={
                "scan_id": str(scan_id),
                "actor_user_id": user.id,
                "new_disposition": request.disposition,
                "updated_count": count,
            },
        )
        return api_models.BulkFindingDispositionResponse(
            updated_count=count,
            disposition=request.disposition,
            scan_risk_score=new_score,
        )

    async def get_finding_disposition_history(
        self,
        scan_id: uuid.UUID,
        finding_id: int,
        user: db_models.User,
        visible_user_ids: Optional[list[int]] = None,
    ) -> "list[api_models.FindingDispositionEventResponse]":
        """The disposition-change history for a finding, oldest first
        (PRD #96 / #100). Same H.2 scope as the triage write paths."""
        await self._get_triageable_scan_or_404(scan_id, user, visible_user_ids)
        finding = await self.repo.get_finding(finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found for this scan.",
            )
        events = await self.repo.get_disposition_events(finding_id)
        return [
            api_models.FindingDispositionEventResponse.model_validate(e) for e in events
        ]

    async def clear_finding_disposition(
        self,
        scan_id: uuid.UUID,
        finding_id: int,
        user: db_models.User,
    ) -> "api_models.FindingDispositionResponse":
        """Delete a finding's triage disposition — reset it to the
        untriaged `open` state and wipe its disposition-event history
        (PRD #96). Superuser-only; the router enforces that via the
        `current_superuser` dependency, so no H.2 scope check is needed
        here (admins see every scan)."""
        await self._get_scan_or_404(scan_id)
        finding = await self.repo.get_finding(finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Finding not found for this scan.",
            )
        updated, new_score = await self.repo.clear_finding_disposition(finding)
        logger.info(
            "scan: finding disposition cleared",
            extra={
                "scan_id": str(scan_id),
                "finding_id": finding_id,
                "actor_user_id": user.id,
            },
        )
        return api_models.FindingDispositionResponse(
            finding_id=updated.id,
            disposition=updated.disposition,
            disposition_by=updated.disposition_by,
            disposition_at=updated.disposition_at,
            disposition_note=updated.disposition_note,
            scan_risk_score=new_score,
        )

    async def clear_finding_dispositions_bulk(
        self,
        scan_id: uuid.UUID,
        finding_ids: list[int],
        user: db_models.User,
    ) -> "api_models.BulkFindingDispositionResponse":
        """Bulk-delete triage dispositions — reset many findings of a
        scan to untriaged and wipe their history (PRD #96). Superuser-
        only; the router enforces that. All-or-nothing: every requested
        id must belong to the scan. Findings already untriaged are
        skipped (nothing to delete) but are not an error."""
        await self._get_scan_or_404(scan_id)

        requested_ids = list(dict.fromkeys(finding_ids))
        findings = await self.repo.get_findings_by_ids(scan_id, requested_ids)
        if len(findings) != len(requested_ids):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or more findings were not found for this scan.",
            )

        to_clear = [f for f in findings if (f.disposition or "open") != "open"]
        if not to_clear:
            scan = await self._get_scan_or_404(scan_id)
            return api_models.BulkFindingDispositionResponse(
                updated_count=0,
                disposition="open",
                scan_risk_score=scan.risk_score,
            )

        count, new_score = await self.repo.clear_finding_dispositions(scan_id, to_clear)
        logger.info(
            "scan: bulk finding disposition cleared",
            extra={
                "scan_id": str(scan_id),
                "actor_user_id": user.id,
                "cleared_count": count,
            },
        )
        return api_models.BulkFindingDispositionResponse(
            updated_count=count,
            disposition="open",
            scan_risk_score=new_score,
        )
