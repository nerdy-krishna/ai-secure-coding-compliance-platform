"""Governed candidate lifecycle, quality gates, signing, and tenant rollout."""

from __future__ import annotations

import hashlib
import hmac
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Mapping

from app.api.v1.schemas.rule_foundry import CandidateCreate, ReviewDecision
from app.core.services.rule_foundry_quality import (
    CandidateQualityEvaluator,
    QualityEvaluationError,
    SandboxQualityEvaluator,
)
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
)
from app.infrastructure.database.repositories.rule_foundry_repo import (
    RuleFoundryRepository,
)
from app.infrastructure.signing.digest_signer import DigestSignature, DigestSigner
from app.shared.lib.rule_foundry import (
    RuleFoundryPolicyError,
    assert_quality_gates,
    assert_shadow_gate,
    candidate_expiry,
    canonical_digest,
    decide_representability,
    shadow_review_due,
    stable_identity,
)


DETERMINISTIC_SOURCES = frozenset({"bandit", "semgrep", "gitleaks", "osv"})


class RuleFoundryNotFoundError(RuntimeError):
    pass


class RuleFoundryDeniedError(RuntimeError):
    pass


class RuleFoundryStateError(RuntimeError):
    pass


class RuleFoundryService:
    def __init__(
        self,
        *,
        repo: RuleFoundryRepository,
        authz_repo: AuthorizationRepository,
        signer: DigestSigner | None,
        evaluator: CandidateQualityEvaluator | None = None,
    ) -> None:
        self.repo = repo
        self.authz_repo = authz_repo
        self.signer = signer
        self.evaluator = evaluator

    async def create_candidate(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        payload: CandidateCreate,
    ) -> db_models.RuleFoundryCandidate:
        finding = await self.repo.source_finding(
            tenant_id=tenant_id, finding_id=payload.finding_id
        )
        if finding is None:
            raise RuleFoundryNotFoundError("Confirmed finding not found.")
        if finding.disposition != "confirmed":
            raise RuleFoundryStateError(
                "Only human-confirmed findings may enter the foundry."
            )
        if (finding.source or "agent").lower() in DETERMINISTIC_SOURCES:
            raise RuleFoundryStateError(
                "The foundry accepts AI-only findings, not scanner findings."
            )

        decision = decide_representability(
            predicate_kind=payload.predicate_kind,
            bounded=payload.bounded,
            uses_project_specific_names=payload.uses_project_specific_names,
            requires_hidden_runtime_state=payload.requires_hidden_runtime_state,
        )
        proposed_rule = payload.proposed_rule
        if decision.static_representable:
            if proposed_rule is None or payload.fixtures is None:
                raise RuleFoundryStateError(
                    "Static candidates require a tool-native rule and all fixture classes."
                )
            _validate_registry_payload(decision.registry_kind, proposed_rule)
        elif proposed_rule is not None:
            raise RuleFoundryStateError(
                "Non-representable findings must remain AI/data-flow checks without a static rule."
            )

        lineage = await self.repo.source_lineage(
            tenant_id=tenant_id, finding_id=finding.id
        )
        evidence = _normalized_evidence(finding, lineage)
        identity_payload = proposed_rule or {
            "finding": str(
                finding.canonical_finding_id or finding.raw_finding_id or finding.id
            ),
            "reason": decision.reason,
        }
        now = datetime.now(timezone.utc)
        candidate = db_models.RuleFoundryCandidate(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            source_finding_id=finding.id,
            source_scan_id=finding.scan_id,
            source_attempt_id=getattr(lineage, "attempt_id", None),
            registry_kind=decision.registry_kind,
            predicate_kind=payload.predicate_kind,
            static_representable=decision.static_representable,
            non_representable_reason=decision.reason,
            stable_identity=stable_identity(
                registry_kind=decision.registry_kind, payload=identity_payload
            ),
            status="pending_review" if decision.static_representable else "ai_dataflow",
            severity=str(finding.severity or "medium").lower(),
            cwe=finding.cwe,
            normalized_evidence=evidence,
            fixtures=(
                payload.fixtures.model_dump(mode="json") if payload.fixtures else {}
            ),
            creator_user_id=actor_user_id,
            expires_at=candidate_expiry(now),
            created_at=now,
            updated_at=now,
        )
        await self.repo.create_candidate(candidate=candidate, payload=proposed_rule)
        await self.repo.add_event(
            candidate=candidate,
            action="created",
            actor_user_id=actor_user_id,
            reason="human-confirmed AI finding submitted",
            details={
                "registry": decision.registry_kind,
                "static_representable": decision.static_representable,
            },
        )
        return candidate

    async def review_candidate(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        decision: ReviewDecision,
        candidate_id: uuid.UUID,
    ) -> db_models.RuleFoundryCandidate:
        candidate = await self._candidate(tenant_id, candidate_id, lock=True)
        self._expire_if_due(candidate)
        if candidate.status not in {"pending_review", "review_required", "rolled_back"}:
            raise RuleFoundryStateError("Candidate is not awaiting review.")
        if not candidate.static_representable:
            raise RuleFoundryStateError(
                "AI/data-flow checks cannot be promoted as static rules."
            )
        sod_mode = await self.authz_repo.separation_of_duties_mode(tenant_id=tenant_id)
        if sod_mode == "critical" and candidate.creator_user_id == actor_user_id:
            raise RuleFoundryDeniedError(
                "Critical candidates require a distinct reviewer."
            )

        now = datetime.now(timezone.utc)
        candidate.reviewer_user_id = actor_user_id
        candidate.reviewed_at = now
        if not decision.approved:
            candidate.status = "rejected"
            await self.repo.add_event(
                candidate=candidate,
                action="rejected",
                actor_user_id=actor_user_id,
                reason=decision.reason,
            )
            return candidate
        if self.signer is None:
            raise RuleFoundryStateError("Rule Foundry KMS signing is not configured.")
        rule = await self.repo.candidate_payload(candidate)
        if rule is None:
            raise RuleFoundryStateError("Candidate registry payload is unavailable.")
        evaluator = self.evaluator
        if evaluator is None:
            evaluator = SandboxQualityEvaluator(
                baseline_median_ms=Decimal(await self.repo.baseline_median_ms())
            )
        try:
            metrics = await evaluator.evaluate(
                registry_kind=candidate.registry_kind,
                payload=rule,
                fixtures=candidate.fixtures,
            )
            assert_quality_gates(metrics)
        except (QualityEvaluationError, RuleFoundryPolicyError) as exc:
            await self.repo.add_event(
                candidate=candidate,
                action="quality_failed",
                actor_user_id=actor_user_id,
                reason=str(exc)[:500],
            )
            raise RuleFoundryStateError(str(exc)) from exc
        reviewer_decision = {
            "approved": True,
            "reason": decision.reason,
            "reviewer_user_id": actor_user_id,
            "reviewed_at": now.isoformat(),
        }
        envelope = {
            "schema": "sccap.rule-foundry.version.v1",
            "tenant_id": str(tenant_id),
            "candidate_id": str(candidate.id),
            "registry_kind": candidate.registry_kind,
            "rule": rule,
            "fixtures": candidate.fixtures,
            "metrics": metrics.as_json(),
            "lineage": candidate.normalized_evidence,
            "reviewer_decision": reviewer_decision,
        }
        _encoded, digest_hex = canonical_digest(envelope)
        signature = await self.signer.sign_sha256(bytes.fromhex(digest_hex))
        version = await self.repo.add_version(
            tenant_id=tenant_id,
            candidate_id=candidate.id,
            canonical_payload=envelope,
            payload_sha256=digest_hex,
            signature=signature.signature_b64,
            signature_algorithm=signature.algorithm,
            signing_key_id=signature.key_id,
            quality_metrics=metrics.as_json(),
            reviewer_decision=reviewer_decision,
            reviewer_user_id=actor_user_id,
        )
        candidate.status = "approved"
        await self.repo.add_event(
            candidate=candidate,
            action="approved_signed",
            actor_user_id=actor_user_id,
            reason=decision.reason,
            details={"version_id": str(version.id), "payload_sha256": digest_hex},
        )
        return candidate

    async def start_shadow(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        candidate_id: uuid.UUID,
        reason: str,
    ) -> db_models.RuleFoundryCandidate:
        candidate = await self._candidate(tenant_id, candidate_id, lock=True)
        self._expire_if_due(candidate)
        if candidate.status != "approved":
            raise RuleFoundryStateError(
                "Only an approved signed version may enter shadow."
            )
        await self._assert_promoter(candidate, tenant_id, actor_user_id)
        active = await self.repo.active_deployment(
            tenant_id=tenant_id, candidate_id=candidate.id, lock=True
        )
        prior_version_id = None
        now = datetime.now(timezone.utc)
        if active is not None:
            if active.state != "review_required":
                raise RuleFoundryStateError(
                    "Candidate already has an active deployment."
                )
            # The signed prior version remains the operational fallback while
            # vNext is shadowed; one active deployment row keeps the pointer
            # transition serialized and the prior version explicit.
            prior_version_id = (
                active.version_id if active.promoted_at is not None else None
            )
            active.state = "superseded"
            active.ended_at = now
        version = await self.repo.latest_version(
            tenant_id=tenant_id, candidate_id=candidate.id
        )
        if version is None:
            raise RuleFoundryStateError("Approved signed version is unavailable.")
        await self._verify_version(version)
        deployment = db_models.RuleFoundryDeployment(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            candidate_id=candidate.id,
            version_id=version.id,
            prior_version_id=prior_version_id,
            state="shadow",
            actor_user_id=actor_user_id,
            shadow_started_at=now,
            review_due_at=shadow_review_due(now),
        )
        self.repo.db.add(deployment)
        candidate.status = "shadow"
        candidate.promoter_user_id = actor_user_id
        await self.repo.add_event(
            candidate=candidate,
            action="shadow_started",
            actor_user_id=actor_user_id,
            reason=reason,
            details={
                "deployment_id": str(deployment.id),
                "version_id": str(version.id),
            },
        )
        return candidate

    async def promote(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        candidate_id: uuid.UUID,
        reason: str,
    ) -> db_models.RuleFoundryCandidate:
        candidate = await self._candidate(tenant_id, candidate_id, lock=True)
        await self._assert_promoter(candidate, tenant_id, actor_user_id)
        deployment = await self.repo.active_deployment(
            tenant_id=tenant_id, candidate_id=candidate.id, lock=True
        )
        if deployment is None or deployment.state != "shadow":
            raise RuleFoundryStateError(
                "Candidate does not have an active shadow version."
            )
        now = datetime.now(timezone.utc)
        if deployment.review_due_at is not None and deployment.review_due_at <= now:
            deployment.state = "review_required"
            candidate.status = "review_required"
            raise RuleFoundryStateError("Shadow review is overdue after 90 days.")
        eligible, unexpected = await self.repo.shadow_totals(
            tenant_id=tenant_id, deployment_id=deployment.id
        )
        try:
            assert_shadow_gate(eligible_files=eligible, unexpected_matches=unexpected)
        except RuleFoundryPolicyError as exc:
            raise RuleFoundryStateError(str(exc)) from exc
        deployment.state = "promoted"
        deployment.promoted_at = now
        candidate.status = "promoted"
        candidate.promoted_at = now
        candidate.promoter_user_id = actor_user_id
        await self.repo.add_event(
            candidate=candidate,
            action="promoted",
            actor_user_id=actor_user_id,
            reason=reason,
            details={"eligible_files": eligible, "unexpected_matches": unexpected},
        )
        return candidate

    async def rollback(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        candidate_id: uuid.UUID,
        reason: str,
    ) -> db_models.RuleFoundryCandidate:
        candidate = await self._candidate(tenant_id, candidate_id, lock=True)
        await self._assert_promoter(candidate, tenant_id, actor_user_id)
        active = await self.repo.active_deployment(
            tenant_id=tenant_id, candidate_id=candidate.id, lock=True
        )
        if active is None or active.state not in {"promoted", "review_required"}:
            raise RuleFoundryStateError(
                "Candidate has no promoted version to roll back."
            )
        if active.prior_version_id is None:
            raise RuleFoundryStateError("Candidate has no prior signed version.")
        prior = await self.repo.db.get(
            db_models.RuleFoundryVersion, active.prior_version_id
        )
        if prior is None or prior.tenant_id != tenant_id:
            raise RuleFoundryStateError("Prior signed version is unavailable.")
        await self._verify_version(prior)
        now = datetime.now(timezone.utc)
        active.state = "rolled_back"
        active.ended_at = now
        restored = db_models.RuleFoundryDeployment(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            candidate_id=candidate.id,
            version_id=prior.id,
            prior_version_id=None,
            state="promoted",
            actor_user_id=actor_user_id,
            promoted_at=now,
        )
        self.repo.db.add(restored)
        # The rollback action is append-only audit history; aggregate state
        # remains truthful because the prior signed version is now active.
        candidate.status = "promoted"
        await self.repo.add_event(
            candidate=candidate,
            action="rolled_back",
            actor_user_id=actor_user_id,
            reason=reason,
            details={"restored_version_id": str(prior.id)},
        )
        return candidate

    async def mark_review_required(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        candidate_id: uuid.UUID,
        trigger: str,
        reason: str,
    ) -> db_models.RuleFoundryCandidate:
        candidate = await self._candidate(tenant_id, candidate_id, lock=True)
        deployment = await self.repo.active_deployment(
            tenant_id=tenant_id, candidate_id=candidate.id, lock=True
        )
        if deployment is None or deployment.state != "promoted":
            raise RuleFoundryStateError("Only a promoted candidate can require review.")
        deployment.state = "review_required"
        candidate.status = "review_required"
        await self.repo.add_event(
            candidate=candidate,
            action="review_required",
            actor_user_id=actor_user_id,
            reason=reason,
            details={"trigger": trigger},
        )
        return candidate

    async def record_shadow_observation(
        self,
        *,
        tenant_id: uuid.UUID,
        candidate_id: uuid.UUID,
        scan_id: uuid.UUID,
        attempt_id: uuid.UUID,
        eligible_files: int,
        unexpected_matches: int,
    ) -> None:
        """Trusted scanner hook. It is intentionally not exposed as a user API."""

        if not 0 <= unexpected_matches <= eligible_files <= 5000:
            raise RuleFoundryStateError("Shadow observation is outside bounded limits.")
        candidate = await self._candidate(tenant_id, candidate_id, lock=False)
        deployment = await self.repo.active_deployment(
            tenant_id=tenant_id, candidate_id=candidate.id
        )
        if deployment is None or deployment.state != "shadow":
            raise RuleFoundryStateError("Candidate has no active shadow deployment.")
        scan = await self.repo.db.get(db_models.Scan, scan_id)
        attempt = await self.repo.db.get(db_models.ScanAttempt, attempt_id)
        if (
            scan is None
            or attempt is None
            or scan.tenant_id != tenant_id
            or attempt.tenant_id != tenant_id
            or attempt.scan_id != scan_id
        ):
            raise RuleFoundryDeniedError("Shadow observation lineage is invalid.")
        digest = hashlib.sha256(
            (
                f"{tenant_id}:{deployment.id}:{scan_id}:{attempt_id}:"
                f"{eligible_files}:{unexpected_matches}"
            ).encode()
        ).hexdigest()
        self.repo.db.add(
            db_models.RuleFoundryShadowObservation(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                deployment_id=deployment.id,
                scan_id=scan_id,
                attempt_id=attempt_id,
                eligible_files=eligible_files,
                unexpected_matches=unexpected_matches,
                evidence_digest=digest,
            )
        )

    async def _candidate(
        self, tenant_id: uuid.UUID, candidate_id: uuid.UUID, *, lock: bool
    ) -> db_models.RuleFoundryCandidate:
        candidate = await self.repo.get_candidate(
            tenant_id=tenant_id, candidate_id=candidate_id, lock=lock
        )
        if candidate is None:
            raise RuleFoundryNotFoundError("Candidate not found.")
        return candidate

    async def _assert_promoter(
        self,
        candidate: db_models.RuleFoundryCandidate,
        tenant_id: uuid.UUID,
        actor_user_id: int,
    ) -> None:
        if candidate.creator_user_id == actor_user_id:
            raise RuleFoundryDeniedError(
                "Creators may not promote their own candidates."
            )
        if (
            await self.authz_repo.separation_of_duties_mode(tenant_id=tenant_id)
            == "critical"
            and candidate.reviewer_user_id == actor_user_id
        ):
            raise RuleFoundryDeniedError(
                "Critical candidates require a promoter distinct from the reviewer."
            )

    async def _verify_version(self, version: db_models.RuleFoundryVersion) -> None:
        if self.signer is None:
            raise RuleFoundryStateError("Rule Foundry KMS signing is not configured.")
        _encoded, recomputed = canonical_digest(version.canonical_payload)
        if not hmac.compare_digest(recomputed, version.payload_sha256):
            raise RuleFoundryStateError(
                "Signed rule payload digest does not match its content."
            )
        valid = await self.signer.verify_sha256(
            bytes.fromhex(version.payload_sha256),
            DigestSignature(
                signature_b64=version.signature,
                algorithm=version.signature_algorithm,
                key_id=version.signing_key_id,
            ),
        )
        if not valid:
            raise RuleFoundryStateError("Signed rule version failed verification.")

    @staticmethod
    def _expire_if_due(candidate: db_models.RuleFoundryCandidate) -> None:
        if candidate.status in {
            "pending_review",
            "approved",
            "rejected",
        } and candidate.expires_at <= datetime.now(timezone.utc):
            candidate.status = "expired"
            raise RuleFoundryStateError(
                "Candidate expired after 30 days without promotion."
            )


def _validate_registry_payload(registry_kind: str, payload: Mapping[str, Any]) -> None:
    if registry_kind == "semgrep":
        required = ("id", "languages", "message", "severity")
        if any(not payload.get(key) for key in required):
            raise RuleFoundryStateError("Semgrep rule is missing required fields.")
        if not any(
            key in payload for key in ("pattern", "patterns", "pattern-either", "mode")
        ):
            raise RuleFoundryStateError(
                "Semgrep rule requires a bounded pattern or mode."
            )
    elif registry_kind == "gitleaks":
        if not payload.get("id") or not payload.get("regex"):
            raise RuleFoundryStateError("Gitleaks rule requires id and regex.")
        if len(str(payload["regex"])) > 5_000:
            raise RuleFoundryStateError("Gitleaks regex exceeds 5,000 characters.")
    elif registry_kind == "osv":
        if not payload.get("id") or not isinstance(payload.get("affected"), list):
            raise RuleFoundryStateError(
                "OSV advisory requires id and affected entries."
            )
        if any(not item.get("versions") for item in payload["affected"]):
            raise RuleFoundryStateError(
                "Initial OSV foundry support requires bounded affected version lists."
            )


def _normalized_evidence(
    finding: db_models.Finding,
    lineage: db_models.FindingLineageRecord | None,
) -> dict[str, Any]:
    return {
        "finding": {
            "id": finding.id,
            "raw_finding_id": (
                str(finding.raw_finding_id) if finding.raw_finding_id else None
            ),
            "canonical_finding_id": (
                str(finding.canonical_finding_id)
                if finding.canonical_finding_id
                else None
            ),
            "scan_id": str(finding.scan_id),
            "source_snapshot_hash": finding.source_snapshot_hash,
            "file_path": finding.file_path,
            "line_number": finding.line_number,
            "affected_locations": finding.affected_locations or [],
            "cwe": finding.cwe,
            "source": finding.source or "agent",
            "corroborating_agents": finding.corroborating_agents or [],
            "detected_by_llms": finding.detected_by_llms or [],
        },
        "lineage": {
            "id": str(lineage.id) if lineage else None,
            "attempt_id": (
                str(lineage.attempt_id) if lineage and lineage.attempt_id else None
            ),
            "fingerprint": lineage.fingerprint if lineage else None,
            "exact_ranges": lineage.exact_ranges if lineage else [],
            "dataflow": lineage.dataflow if lineage else {},
            "source_provenance": lineage.source_provenance if lineage else {},
            "producer_provenance": lineage.producer_provenance if lineage else {},
            "coverage_entry_ids": (
                [str(item) for item in (lineage.coverage_entry_ids or [])]
                if lineage
                else []
            ),
            "evidence_object_ids": (
                [str(item) for item in (lineage.evidence_object_ids or [])]
                if lineage
                else []
            ),
        },
    }
