"""Scan-lifecycle service: post-creation state transitions.

Handles the prescan-approval gate, cost-approval gate, and scan
cancellation.

Split out of `core/services/scan_service.py` (2026-04-26). The threat-model
mitigations include the kind-vs-status guard +
PRESCAN_OVERRIDE_CRITICAL_SECRET / PRESCAN_USER_DECLINED audit
ScanEvent writes (M4 / G-split-5).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import HTTPException, status

from app.api.v1 import models as api_models
from app.config.config import settings
from app.config.logging_config import correlation_id_var
from app.infrastructure.database import models as db_models
from app.core.services.scan.task_ledger import ScanTaskLedgerService
from app.infrastructure.database.repositories.scan_outbox_repo import (
    ScanOutboxRepository,
)
from app.infrastructure.database.repositories.approval_gate_repo import (
    ApprovalGateRepository,
)
from app.infrastructure.database.repositories.scan_repo import ScanRepository
from app.infrastructure.database.repositories.scan_attempt_repo import (
    ScanAttemptRepository,
)
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationConflictError,
    AuthorizationDeniedError,
    AuthorizationRepository,
    payload_digest,
    target_fingerprint,
)
from app.shared.lib.permissions import (
    SCAN_APPROVE,
    SCAN_APPROVE_SELF,
    WAIVER_APPROVE,
    WAIVER_REQUEST,
)
from app.shared.lib.scan_visibility import can_view_scan
from app.shared.lib.scan_status import (
    ACTIVE_SCAN_STATUSES,
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_PENDING_APPROVAL,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_QUEUED,
    STATUS_QUEUED_FOR_SCAN,
)
from app.shared.lib.scan_task_status import STATUS_SCAN_TASK_COMPLETED

logger = logging.getLogger(__name__)

_APPROVAL_GATE_STATUS = {
    "prescan_approval": STATUS_PENDING_PRESCAN_APPROVAL,
    "profiling_approval": STATUS_PENDING_PROFILING_APPROVAL,
    "cost_approval": STATUS_PENDING_APPROVAL,
}
_NO_RUNNING_WORK_CANCELLATION_STATUSES = {
    STATUS_QUEUED,
    STATUS_PENDING_PRESCAN_APPROVAL,
    STATUS_PENDING_PROFILING_APPROVAL,
    STATUS_PENDING_APPROVAL,
}


class ScanLifecycleService:
    """Post-creation scan transitions.

    Same `__init__` shape as `ScanSubmissionService` — both build the
    outbox repo from the SAME `repo.db` session so `approve_scan`'s
    Scan + ScanEvent + Outbox writes stay atomic (G-split-2).
    """

    def __init__(self, repo: ScanRepository):
        self.repo = repo
        self.outbox = ScanOutboxRepository(repo.db)
        self.gates = ApprovalGateRepository(repo.db)

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
        *,
        idempotency_key: Optional[str] = None,
        permissions: frozenset[str],
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> db_models.ApprovalGate:
        """Approve / decline a scan paused at a worker-graph interrupt.

        Three interrupt points: prescan approval, profiling-cost approval,
        and full-analysis cost approval. ``request.kind`` discriminates; the consumer
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
        idempotency_key = idempotency_key or str(uuid.uuid4())
        if len(idempotency_key) > 128:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="X-Idempotency-Key must be at most 128 characters.",
            )

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
        if not can_view_scan(
            scan,
            user,
            visible_user_ids=visible_user_ids,
            tenant_id=tenant_id,
        ):
            logger.warning(
                "scan: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "action": "approve",
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        sod_mode = await AuthorizationRepository(
            self.repo.db
        ).separation_of_duties_mode(tenant_id=tenant_id)
        has_tenant_approval = SCAN_APPROVE in permissions
        has_self_approval = SCAN_APPROVE_SELF in permissions
        if has_tenant_approval:
            if sod_mode == "critical" and scan.user_id == user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="A distinct authorized approver is required.",
                )
        elif not (
            has_self_approval and sod_mode == "off" and scan.user_id == user.id
        ):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Not authorized to decide this scan gate.",
            )

        conflict_audit_committed = False
        try:
            # Compatibility clients may omit gate_id, but only while exactly one
            # pending gate exists. The row lock makes decision + event + outbox a
            # single one-shot transaction.
            gate = None
            if request.gate_id is not None:
                gate = await self.gates.lock_for_decision(request.gate_id)
            else:
                pending = await self.gates.get_pending_for_scan(scan_id)
                if pending is not None:
                    gate = await self.gates.lock_for_decision(pending.gate_id)
                else:
                    prior = await self.gates.get_by_decision_key(
                        scan_id, idempotency_key
                    )
                    if prior is not None:
                        gate = await self.gates.lock_for_decision(prior.gate_id)
                    elif scan.status == _APPROVAL_GATE_STATUS[request.kind]:
                        legacy_contract = {
                            "prescan_approval": (
                                "pending_prescan_approval",
                                "Review deterministic scanner findings",
                                "Review deterministic evidence before LLM work.",
                            ),
                            "profiling_approval": (
                                "profiling_cost_gate",
                                "Approve file profiling cost",
                                "Approve utility-model file profiling.",
                            ),
                            "cost_approval": (
                                "cost_gate",
                                "Approve full security analysis cost",
                                "Approve the full security-analysis estimate.",
                            ),
                        }[request.kind]
                        pending = await self.gates.create_or_get_pending(
                            scan_id=scan_id,
                            kind=request.kind,
                            node_name=legacy_contract[0],
                            display_name=legacy_contract[1],
                            purpose=legacy_contract[2],
                            evidence={
                                "legacy_upgrade_gate": True,
                                "status": scan.status,
                                "cost_details": scan.cost_details,
                            },
                            commit=False,
                        )
                        gate = await self.gates.lock_for_decision(pending.gate_id)

            if gate is None or gate.scan_id != scan_id:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="No matching active approval gate exists for this scan.",
                )
            if gate.kind != request.kind:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Gate {gate.gate_id} requires kind '{gate.kind}', not "
                        f"'{request.kind}'."
                    ),
                )
            if gate.state != "pending":
                same_request = (
                    gate.decision_idempotency_key == idempotency_key
                    and gate.decision is request.approved
                    and gate.override_critical_secret
                    is request.override_critical_secret
                )
                if same_request:
                    return gate
                if gate.decision is not None and gate.decision != request.approved:
                    await self.repo.create_scan_event(
                        scan_id=scan_id,
                        stage_name="APPROVAL_DECISION_REJECTED",
                        status="REJECTED",
                        details={
                            "gate_id": str(gate.gate_id),
                            "gate_sequence": gate.sequence,
                            "kind": gate.kind,
                            "recorded_decision": gate.decision,
                            "requested_decision": request.approved,
                            "actor_user_id": user.id,
                            "reason": "first_decision_wins",
                        },
                    )
                    conflict_audit_committed = True
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail=(
                            "This gate already has a different durable decision; "
                            "the first decision wins."
                        ),
                    )
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This approval gate was already decided.",
                )

            if (
                request.gate_version is not None
                and gate.version != request.gate_version
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Approval gate version changed; refresh before deciding.",
                )
            if (
                request.evidence_hash is not None
                and gate.evidence_hash != request.evidence_hash
            ):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Approval evidence changed; refresh before deciding.",
                )

            # Validate kind against the current pause point after locking the
            # durable gate. A stale gate can never approve a later occurrence.
            expected_status = _APPROVAL_GATE_STATUS[request.kind]
            if scan.status != expected_status:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"Gate {gate.gate_id} requires status {expected_status}; "
                        f"current status: {scan.status}"
                    ),
                )

            # Claim the gate with compare-and-set. Approved and declined
            # decisions both become queued durable work, preventing a second
            # click from enqueueing the same resume while RabbitMQ is down.
            changed = await self.repo.update_status(
                scan_id,
                STATUS_QUEUED_FOR_SCAN,
                allowed_current_statuses=(expected_status,),
                commit=False,
            )
            if not changed:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Scan state changed before the approval could be applied.",
                )

            if (
                request.kind == "prescan_approval"
                and request.approved
                and request.override_critical_secret
            ):
                await self.repo.create_scan_event(
                    scan_id=scan_id,
                    stage_name="PRESCAN_OVERRIDE_CRITICAL_SECRET",
                    status="COMPLETED",
                    commit=False,
                )

            decline_stage = {
                "prescan_approval": "PRESCAN_USER_DECLINED",
                "profiling_approval": "PROFILING_USER_DECLINED",
                "cost_approval": "COST_USER_DECLINED",
            }.get(request.kind)
            if not request.approved and decline_stage:
                await self.repo.create_scan_event(
                    scan_id=scan_id,
                    stage_name=decline_stage,
                    status="COMPLETED",
                    commit=False,
                )

            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name="QUEUED_FOR_SCAN",
                status="COMPLETED",
                details={
                    "gate_id": str(gate.gate_id),
                    "gate_sequence": gate.sequence,
                    "kind": request.kind,
                    "approved": request.approved,
                    "evidence_hash": gate.evidence_hash,
                    "actor_user_id": user.id,
                },
                commit=False,
            )
            await self.gates.record_decision(
                gate,
                actor_user_id=user.id,
                approved=request.approved,
                override_critical_secret=request.override_critical_secret,
                idempotency_key=idempotency_key,
            )
            approval_payload = {
                "scan_id": str(scan_id),
                "gate_id": str(gate.gate_id),
                "gate_version": gate.version,
                "gate_sequence": gate.sequence,
                "node_name": gate.node_name,
                "evidence_hash": gate.evidence_hash,
                "action": "resume_analysis",
                "kind": request.kind,
                "approved": request.approved,
                "override_critical_secret": request.override_critical_secret,
                "user_id": user.id,
                "correlation_id": correlation_id_var.get(),
            }
            await self.outbox.enqueue(
                scan_id=scan_id,
                queue_name=settings.RABBITMQ_APPROVAL_QUEUE,
                payload=approval_payload,
                idempotency_key=f"approval-gate:{gate.gate_id}",
                commit=False,
            )
            await self.repo.db.commit()
            logger.info(
                "Scan decision committed for outbox dispatch.",
                extra={
                    "scan_id": str(scan_id),
                    "kind": request.kind,
                    "approved": request.approved,
                },
            )
            return gate
        except HTTPException:
            if not conflict_audit_committed:
                await self.repo.db.rollback()
            raise
        except Exception:
            await self.repo.db.rollback()
            logger.error(
                "scan: approval transaction failed",
                extra={"scan_id": str(scan_id), "kind": request.kind},
                exc_info=True,
            )
            raise

    async def resume_or_restart_scan(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        request: "api_models.ScanRunControlRequest",
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> dict[str, Any]:
        """Manually requeue a failed/cancelled scan.

        ``resume`` keeps durable task artifacts so later workflow nodes can
        reuse completed work. ``restart`` deletes task artifacts and derived
        final outputs, while preserving the original submitted snapshot,
        scan events, and LLM interactions for auditability.
        """
        mode = request.mode
        logger.info(
            "scan: manual run-control attempt",
            extra={"scan_id": str(scan_id), "actor_user_id": user.id, "mode": mode},
        )
        scan = await self._get_scan_or_404(scan_id)
        if not can_view_scan(
            scan,
            user,
            visible_user_ids=visible_user_ids,
            tenant_id=tenant_id,
        ):
            logger.warning(
                "scan: authorization denied",
                extra={
                    "scan_id": str(scan_id),
                    "actor_user_id": user.id,
                    "action": mode,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Scan not found or not authorized.",
            )

        pending_statuses = {
            STATUS_PENDING_PRESCAN_APPROVAL,
            STATUS_PENDING_PROFILING_APPROVAL,
            STATUS_PENDING_APPROVAL,
        }
        if scan.status in pending_statuses:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=(
                    "Scan is pending approval; use the existing approval flow "
                    "instead of manual resume/restart."
                ),
            )
        if scan.status not in {STATUS_FAILED, STATUS_CANCELLED}:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Scan cannot be {mode}ed from its current state: {scan.status}",
            )

        task_ledger = ScanTaskLedgerService(self.repo.db)
        artifact_counts = await task_ledger.summarize_scan_tasks(scan_id)
        artifact_total = sum(artifact_counts.values())
        completed_artifacts = artifact_counts.get(STATUS_SCAN_TASK_COMPLETED, 0)

        if scan.status == STATUS_CANCELLED and mode == "resume" and artifact_total == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cancelled scan has no resumable artifacts.",
            )

        try:
            changed = await self.repo.reset_scan_for_manual_run(
                scan_id,
                status=STATUS_QUEUED,
                clear_final_outputs=(mode == "restart"),
                allowed_current_statuses=(scan.status,),
                commit=False,
            )
            if not changed:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Scan state changed before run control could be applied.",
                )

            deleted_tasks = 0
            deleted_findings = 0
            deleted_snapshots = 0
            if mode == "restart":
                await self.gates.close_active(scan_id, state="cancelled", commit=False)
                deleted_tasks = await task_ledger.delete_scan_tasks(
                    scan_id, commit=False
                )
                deleted_findings = await self.repo.delete_findings_for_scan(
                    scan_id, commit=False
                )
                deleted_snapshots = await self.repo.delete_derived_snapshots_for_scan(
                    scan_id, commit=False
                )
                artifact_counts = {}
                artifact_total = 0
                completed_artifacts = 0

            attempts = ScanAttemptRepository(self.repo.db)
            if mode == "restart":
                attempt = await attempts.create_restart(
                    scan_id, actor_user_id=user.id, commit=False
                )
            else:
                attempt = await attempts.activate_resume(scan_id, commit=False)

            boundary_stage = (
                "MANUAL_RESUME_REQUESTED"
                if mode == "resume"
                else "MANUAL_RESTART_REQUESTED"
            )
            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name=boundary_stage,
                status="COMPLETED",
                details={
                    "mode": mode,
                    "attempt_id": str(attempt.id),
                    "attempt_sequence": attempt.sequence,
                    "actor_user_id": user.id,
                    "artifact_counts": artifact_counts,
                    "artifact_total": artifact_total,
                    "completed_artifacts": completed_artifacts,
                    "deleted_tasks": deleted_tasks,
                    "deleted_findings": deleted_findings,
                    "deleted_derived_snapshots": deleted_snapshots,
                    "approvals_preserved": True,
                },
                commit=False,
            )
            if mode == "resume":
                await self.repo.create_scan_event(
                    scan_id=scan_id,
                    stage_name="RESUME_ARTIFACT_EVALUATION",
                    status="COMPLETED",
                    details={
                        "artifact_counts": artifact_counts,
                        "artifact_total": artifact_total,
                        "completed_artifacts": completed_artifacts,
                        "reusable_artifacts": completed_artifacts,
                    },
                    commit=False,
                )

            await self.repo.create_scan_event(
                scan_id=scan_id,
                stage_name="QUEUED",
                status="COMPLETED",
                details={"mode": mode, "manual_run_control": True},
                commit=False,
            )

            payload = {
                "scan_id": str(scan_id),
                "attempt_id": str(attempt.id),
                "action": f"manual_{mode}",
                "mode": mode,
                "correlation_id": correlation_id_var.get(),
            }
            await self.outbox.enqueue(
                scan_id=scan_id,
                queue_name=settings.RABBITMQ_SUBMISSION_QUEUE,
                payload=payload,
                commit=False,
            )
            await self.repo.db.commit()
        except HTTPException:
            await self.repo.db.rollback()
            raise
        except Exception:
            await self.repo.db.rollback()
            logger.error(
                "scan: manual run-control transaction failed",
                extra={"scan_id": str(scan_id), "mode": mode},
                exc_info=True,
            )
            raise

        return {
            "message": f"Scan {mode} queued for processing.",
            "scan_id": str(scan_id),
            "mode": mode,
            "artifact_counts": artifact_counts,
            "deleted_tasks": deleted_tasks,
            "deleted_findings": deleted_findings,
            "deleted_derived_snapshots": deleted_snapshots,
        }

    async def get_prescan_review(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
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
        if not scan or not can_view_scan(
            scan,
            user,
            visible_user_ids=visible_user_ids,
            tenant_id=tenant_id,
        ):
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

    async def cancel_scan(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> None:
        """Cancels a scan, typically one that is pending approval."""
        logger.info(
            "scan: cancel attempt",
            extra={"actor_user_id": user.id, "scan_id": str(scan_id)},
        )
        scan = await self.repo.get_scan(scan_id)
        if not scan or not can_view_scan(
            scan,
            user,
            visible_user_ids=visible_user_ids,
            tenant_id=tenant_id,
        ):
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

        prior_status = scan.status
        try:
            changed = await self.repo.update_status(
                scan_id,
                STATUS_CANCELLED,
                allowed_current_statuses=ACTIVE_SCAN_STATUSES,
                commit=False,
            )
            if not changed:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Scan state changed before cancellation could be applied.",
                )
            await self.repo.create_scan_event(
                scan_id=scan.id,
                stage_name="CANCELLATION",
                status="REQUESTED",
                details={
                    "phase": "requested",
                    "actor_user_id": user.id,
                    "slo_ms": 2000,
                },
                activity_kind="cancellation",
                commit=False,
            )
            if prior_status in _NO_RUNNING_WORK_CANCELLATION_STATUSES:
                await self.repo.create_scan_event(
                    scan_id=scan.id,
                    stage_name="CANCELLATION",
                    status="OBSERVED",
                    details={
                        "phase": "observed",
                        "latency_ms": 0,
                        "slo_ms": 2000,
                        "within_slo": True,
                        "terminated_processes": 0,
                    },
                    activity_kind="cancellation",
                    commit=False,
                )
                await self.repo.create_scan_event(
                    scan_id=scan.id,
                    stage_name="CANCELLATION",
                    status="COMPLETED",
                    details={
                        "phase": "completed",
                        "latency_ms": 0,
                        "slo_ms": 2000,
                        "within_slo": True,
                        "terminated_processes": 0,
                    },
                    activity_kind="cancellation",
                    commit=False,
                )
            await self.gates.close_active(scan_id, state="cancelled", commit=False)
            attempt = await ScanAttemptRepository(self.repo.db).mark_current_terminal(
                scan_id, status="cancelled", commit=False
            )
            if attempt is not None:
                from app.infrastructure.database.repositories.evidence_repo import (
                    EvidenceRepository,
                )

                await EvidenceRepository(self.repo.db).finalize_attempt(
                    attempt.id, actor_user_id=user.id, commit=False
                )
            await self.repo.db.commit()
        except HTTPException:
            await self.repo.db.rollback()
            raise
        except Exception:
            await self.repo.db.rollback()
            logger.error(
                "scan: cancellation transaction failed",
                extra={"scan_id": str(scan_id)},
                exc_info=True,
            )
            raise
        logger.info(
            "scan: cancelled", extra={"scan_id": str(scan_id), "actor_user_id": user.id}
        )

    async def set_finding_disposition(
        self,
        scan_id: uuid.UUID,
        finding_id: int,
        user: db_models.User,
        request: "api_models.FindingDispositionUpdateRequest",
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
        approved_waiver: bool = False,
        commit: bool = True,
    ) -> "api_models.FindingDispositionResponse":
        """Set a finding's triage disposition (PRD #96 / #97).

        Authorization follows the H.2 visibility model: any user who can
        view the scan can triage its findings (`visible_user_ids is None`
        ⇒ admin, sees everything). The transition is validated against
        `finding_disposition`; the change + an audit event are persisted
        atomically by the repository.
        """
        from app.shared.lib import finding_disposition as fd

        await self._get_triageable_scan_or_404(
            scan_id,
            user,
            visible_user_ids,
            tenant_id=tenant_id,
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

        if request.disposition in {"false_positive", "risk_accepted"}:
            sod_mode = await AuthorizationRepository(
                self.repo.db
            ).separation_of_duties_mode(tenant_id=tenant_id)
            if sod_mode == "critical" and not approved_waiver:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="A distinct approved waiver request is required.",
                )

        note = request.note.strip() if request.note else None
        updated, new_score = await self.repo.apply_finding_disposition(
            finding,
            new_disposition=request.disposition,
            actor_user_id=user.id,
            note=note,
            commit=commit,
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

    @staticmethod
    def _waiver_payload(
        scan_id: uuid.UUID,
        finding_id: int,
        request: "api_models.FindingDispositionUpdateRequest",
    ) -> dict[str, object]:
        return {
            "scan_id": str(scan_id),
            "finding_id": finding_id,
            "disposition": request.disposition,
            "note": request.note.strip() if request.note else None,
        }

    async def request_finding_waiver(
        self,
        scan_id: uuid.UUID,
        finding_id: int,
        user: db_models.User,
        request: "api_models.FindingDispositionUpdateRequest",
        *,
        idempotency_key: str,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> db_models.AuthorizationActionRequest:
        from app.shared.lib import finding_disposition as fd

        if request.disposition not in {"false_positive", "risk_accepted"}:
            raise HTTPException(status_code=400, detail="Not a waiver disposition.")
        await self._get_triageable_scan_or_404(
            scan_id, user, visible_user_ids, tenant_id=tenant_id
        )
        finding = await self.repo.get_finding(finding_id)
        if finding is None or finding.scan_id != scan_id:
            raise HTTPException(status_code=404, detail="Finding not found for this scan.")
        try:
            fd.validate_transition(
                finding.disposition or fd.DEFAULT_DISPOSITION,
                request.disposition,
                request.note,
            )
        except fd.DispositionError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        canonical = self._waiver_payload(scan_id, finding_id, request)
        fingerprint = target_fingerprint(
            resource_type="finding_waiver",
            target_id=f"{scan_id}:{finding_id}",
        )
        authz = AuthorizationRepository(self.repo.db)
        try:
            row = await authz.create_action_request(
                tenant_id=tenant_id,
                requester_user_id=user.id,
                requester_permission=WAIVER_REQUEST,
                approver_permission=WAIVER_APPROVE,
                target_type="finding_waiver",
                target_fingerprint_value=fingerprint,
                payload_digest_value=payload_digest(canonical),
                idempotency_key=idempotency_key,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=24),
            )
        except AuthorizationConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc))
        authz.record_audit(
            tenant_id=tenant_id,
            principal_kind="human",
            principal_id=str(user.id),
            permission=WAIVER_REQUEST,
            resource_type="finding_waiver",
            target_fingerprint_value=fingerprint,
            outcome="requested",
            reason_code="waiver_requested",
            action_request_id=row.id,
        )
        await self.repo.db.commit()
        return row

    async def execute_finding_waiver(
        self,
        scan_id: uuid.UUID,
        finding_id: int,
        action_request_id: uuid.UUID,
        user: db_models.User,
        request: "api_models.FindingDispositionUpdateRequest",
        *,
        permissions: frozenset[str],
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> "api_models.FindingDispositionResponse":
        authz = AuthorizationRepository(self.repo.db)
        action = await authz.get_action_request(
            request_id=action_request_id, tenant_id=tenant_id
        )
        fingerprint = target_fingerprint(
            resource_type="finding_waiver",
            target_id=f"{scan_id}:{finding_id}",
        )
        if (
            action is None
            or action.requester_user_id != user.id
            or action.target_type != "finding_waiver"
            or action.target_fingerprint != fingerprint
        ):
            raise HTTPException(status_code=404, detail="Action request not found.")
        approver_permissions = await authz.permissions_for_user_id(
            user_id=action.approver_user_id or -1,
            tenant_id=tenant_id,
        )
        canonical = self._waiver_payload(scan_id, finding_id, request)
        try:
            await authz.mark_executed(
                request_id=action.id,
                tenant_id=tenant_id,
                payload_digest_value=payload_digest(canonical),
                requester_permissions=permissions,
                approver_permissions=approver_permissions,
            )
            response = await self.set_finding_disposition(
                scan_id,
                finding_id,
                user,
                request,
                visible_user_ids=visible_user_ids,
                tenant_id=tenant_id,
                approved_waiver=True,
                commit=False,
            )
            authz.record_audit(
                tenant_id=tenant_id,
                principal_kind="human",
                principal_id=str(user.id),
                permission=WAIVER_REQUEST,
                resource_type="finding_waiver",
                target_fingerprint_value=fingerprint,
                outcome="executed",
                reason_code="approved_waiver_executed",
                action_request_id=action.id,
                approver_principal_id=str(action.approver_user_id),
            )
            await self.repo.db.commit()
            return response
        except (AuthorizationConflictError, AuthorizationDeniedError) as exc:
            await self.repo.db.rollback()
            raise HTTPException(status_code=409, detail=str(exc))
        except Exception:
            await self.repo.db.rollback()
            raise

    async def _get_triageable_scan_or_404(
        self,
        scan_id: uuid.UUID,
        user: db_models.User,
        visible_user_ids: Optional[list[int]],
        *,
        tenant_id: uuid.UUID,
    ) -> db_models.Scan:
        """Fetch a scan the caller is allowed to triage (PRD #96).

        Authorization follows the H.2 visibility model: any user who can
        view the scan can triage its findings (`visible_user_ids is
        None` ⇒ admin, sees everything). A scan outside the caller's
        scope is reported as 404, not 403, so triage cannot be used to
        probe for scan existence.
        """
        scan = await self._get_scan_or_404(scan_id)
        if not can_view_scan(
            scan,
            user,
            visible_user_ids=visible_user_ids,
            tenant_id=tenant_id,
        ):
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
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
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

        await self._get_triageable_scan_or_404(
            scan_id,
            user,
            visible_user_ids,
            tenant_id=tenant_id,
        )

        if not fd.is_valid_disposition(request.disposition):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unknown disposition {request.disposition!r}.",
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
        if request.disposition in {"false_positive", "risk_accepted"}:
            sod_mode = await AuthorizationRepository(
                self.repo.db
            ).separation_of_duties_mode(tenant_id=tenant_id)
            if sod_mode == "critical":
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="Bulk waivers require approved individual action requests.",
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
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> "list[api_models.FindingDispositionEventResponse]":
        """The disposition-change history for a finding, oldest first
        (PRD #96 / #100). Same H.2 scope as the triage write paths."""
        await self._get_triageable_scan_or_404(
            scan_id,
            user,
            visible_user_ids,
            tenant_id=tenant_id,
        )
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
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> "api_models.FindingDispositionResponse":
        """Reset a finding disposition inside the caller's scan scope."""
        await self._get_triageable_scan_or_404(
            scan_id,
            user,
            visible_user_ids,
            tenant_id=tenant_id,
        )
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
        *,
        visible_user_ids: Optional[list[int]],
        tenant_id: uuid.UUID,
    ) -> "api_models.BulkFindingDispositionResponse":
        """Bulk-reset dispositions inside the caller's scan scope."""
        await self._get_triageable_scan_or_404(
            scan_id,
            user,
            visible_user_ids,
            tenant_id=tenant_id,
        )

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
