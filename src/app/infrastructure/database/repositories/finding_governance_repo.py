"""Tenant-scoped persistence for evidence-first finding governance."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any, Sequence

from sqlalchemy import and_, not_, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scanner_coverage_repo import (
    summarize_coverage,
)
from app.shared.lib.finding_governance import (
    GatePolicy,
    evaluate_gate,
    exact_ranges,
    finding_fingerprint,
    finding_site_identity,
    waiver_is_eligible,
)


class FindingGovernanceRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    @staticmethod
    def _final_findings() -> Any:
        # `save_results` promotes the final union into `consolidated` while
        # retaining the original SAST rows for diagnostics. Reading both would
        # double-count scanner findings and make predecessor IDs order-dependent.
        return db_models.Finding.finding_bucket == "consolidated"

    async def visible_scan(
        self,
        scan_id: uuid.UUID,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
    ) -> db_models.Scan | None:
        stmt = select(db_models.Scan).where(
            db_models.Scan.id == scan_id,
            db_models.Scan.tenant_id == tenant_id,
        )
        if visible_user_ids is not None:
            stmt = stmt.where(db_models.Scan.user_id.in_(visible_user_ids))
        return await self.db.scalar(stmt)

    async def materialize_scan(
        self, scan_id: uuid.UUID, *, commit: bool = True
    ) -> list[db_models.FindingLineageRecord]:
        """Persist one immutable baseline/evidence generation for a scan."""

        scan = await self.db.get(db_models.Scan, scan_id)
        if scan is None:
            raise LookupError("Scan not found.")
        current = list(
            (
                await self.db.scalars(
                    select(db_models.Finding).where(
                        db_models.Finding.scan_id == scan.id,
                        self._final_findings(),
                    )
                )
            ).all()
        )
        previous_scan = await self.db.scalar(
            select(db_models.Scan)
            .where(
                db_models.Scan.project_id == scan.project_id,
                db_models.Scan.tenant_id == scan.tenant_id,
                db_models.Scan.created_at < scan.created_at,
                db_models.Scan.completed_at.is_not(None),
            )
            .order_by(db_models.Scan.created_at.desc(), db_models.Scan.id.desc())
            .limit(1)
        )
        previous: list[db_models.Finding] = []
        if previous_scan is not None:
            previous = list(
                (
                    await self.db.scalars(
                        select(db_models.Finding).where(
                            db_models.Finding.scan_id == previous_scan.id,
                            self._final_findings(),
                        )
                    )
                ).all()
            )
        historical = list(
            (
                await self.db.scalars(
                    select(db_models.Finding)
                    .join(
                        db_models.Scan, db_models.Scan.id == db_models.Finding.scan_id
                    )
                    .where(
                        db_models.Scan.project_id == scan.project_id,
                        db_models.Scan.tenant_id == scan.tenant_id,
                        db_models.Scan.created_at < scan.created_at,
                        db_models.Scan.completed_at.is_not(None),
                        self._final_findings(),
                    )
                )
            ).all()
        )
        current_groups: dict[str, list[db_models.Finding]] = defaultdict(list)
        previous_groups: dict[str, list[db_models.Finding]] = defaultdict(list)
        for row in current:
            current_groups[finding_fingerprint(row)].append(row)
        for row in previous:
            previous_groups[finding_fingerprint(row)].append(row)
        historical_fingerprints = {finding_fingerprint(row) for row in historical}
        evidence_ids = []
        if scan.current_attempt_id is not None:
            evidence_ids = list(
                (
                    await self.db.scalars(
                        select(db_models.EvidenceObject.id).where(
                            db_models.EvidenceObject.attempt_id
                            == scan.current_attempt_id,
                            db_models.EvidenceObject.state == "available",
                        )
                    )
                ).all()
            )
        dependency_digest = None
        dependency_edges: list[dict[str, Any]] = []
        if scan.dependency_graph:
            dependency_digest = hashlib.sha256(
                json.dumps(scan.dependency_graph, sort_keys=True, default=str).encode()
            ).hexdigest()
            raw_edges = scan.dependency_graph.get("links") or scan.dependency_graph.get(
                "edges"
            )
            if isinstance(raw_edges, list):
                dependency_edges = [
                    dict(edge) for edge in raw_edges if isinstance(edge, dict)
                ]
        payloads: list[dict[str, Any]] = []
        fingerprints = sorted(set(current_groups) | set(previous_groups))
        for fingerprint in fingerprints:
            current_occurrences = sorted(
                current_groups.get(fingerprint, []), key=self._occurrence_sort_key
            )
            unmatched_previous = sorted(
                previous_groups.get(fingerprint, []), key=self._occurrence_sort_key
            )
            matched: list[tuple[db_models.Finding, str, db_models.Finding | None]] = []
            unmatched_current: list[db_models.Finding] = []
            for finding in current_occurrences:
                exact_key = self._occurrence_site_key(finding)
                exact_index = next(
                    (
                        index
                        for index, predecessor in enumerate(unmatched_previous)
                        if self._occurrence_site_key(predecessor) == exact_key
                    ),
                    None,
                )
                if exact_index is None:
                    unmatched_current.append(finding)
                else:
                    matched.append(
                        (finding, "unchanged", unmatched_previous.pop(exact_index))
                    )
            # A harmless line shift may move an existing occurrence. Pair the
            # remaining deterministic order before classifying true additions
            # or removals, so multiplicity is preserved per exact occurrence.
            pair_count = min(len(unmatched_current), len(unmatched_previous))
            for index in range(pair_count):
                matched.append(
                    (
                        unmatched_current[index],
                        "unchanged",
                        unmatched_previous[index],
                    )
                )
            for finding in unmatched_current[pair_count:]:
                state = (
                    "reintroduced"
                    if not previous_groups.get(fingerprint)
                    and fingerprint in historical_fingerprints
                    else "new"
                )
                matched.append((finding, state, None))
            fixed_occurrences = unmatched_previous[pair_count:]

            for finding, state, predecessor in sorted(
                matched, key=lambda item: self._occurrence_sort_key(item[0])
            ):
                coverage_ids = list(finding.coverage_entry_ids or [])
                if (
                    finding.coverage_entry_id
                    and finding.coverage_entry_id not in coverage_ids
                ):
                    coverage_ids.append(finding.coverage_entry_id)
                payloads.append(
                    self._lineage_payload(
                        scan=scan,
                        finding=finding,
                        fingerprint=fingerprint,
                        baseline_state=state,
                        predecessor=predecessor,
                        coverage_ids=coverage_ids,
                        evidence_ids=evidence_ids,
                        dependency_digest=dependency_digest,
                        dependency_edges=dependency_edges,
                    )
                )
            for predecessor in fixed_occurrences:
                payloads.append(
                    self._lineage_payload(
                        scan=scan,
                        finding=None,
                        fingerprint=fingerprint,
                        baseline_state="fixed",
                        predecessor=predecessor,
                        coverage_ids=[],
                        evidence_ids=evidence_ids,
                        dependency_digest=dependency_digest,
                        dependency_edges=dependency_edges,
                    )
                )
        for payload in payloads:
            insert = pg_insert(db_models.FindingLineageRecord).values(**payload)
            if payload["finding_id"] is not None:
                statement = insert.on_conflict_do_update(
                    index_elements=[
                        "scan_id",
                        "attempt_id",
                        "fingerprint",
                        "baseline_state",
                        "site_identity",
                    ],
                    set_={"finding_id": payload["finding_id"]},
                    where=db_models.FindingLineageRecord.finding_id.is_(None),
                )
            else:
                statement = insert.on_conflict_do_nothing(
                    index_elements=[
                        "scan_id",
                        "attempt_id",
                        "fingerprint",
                        "baseline_state",
                        "site_identity",
                    ]
                )
            await self.db.execute(statement)
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return await self.lineage_for_scan(scan.id)

    @staticmethod
    def _occurrence_site_key(finding: db_models.Finding) -> tuple[str, int, str]:
        return (
            str(finding.file_path or "").replace("\\", "/"),
            int(finding.line_number or 0),
            " ".join(str(finding.vulnerable_snippet or "").split()).casefold(),
        )

    @classmethod
    def _occurrence_sort_key(
        cls, finding: db_models.Finding
    ) -> tuple[str, int, str, str, int]:
        site = cls._occurrence_site_key(finding)
        canonical = finding.canonical_finding_id or finding.raw_finding_id or ""
        return (*site, str(canonical), int(finding.id or 0))

    @staticmethod
    def _lineage_payload(
        *,
        scan: db_models.Scan,
        finding: db_models.Finding | None,
        fingerprint: str,
        baseline_state: str,
        predecessor: db_models.Finding | None,
        coverage_ids: list[uuid.UUID],
        evidence_ids: list[uuid.UUID],
        dependency_digest: str | None,
        dependency_edges: list[dict[str, Any]],
    ) -> dict[str, Any]:
        source = finding or predecessor
        assert source is not None
        ranges = exact_ranges(source)
        site_identity = finding_site_identity(
            canonical_finding_id=source.canonical_finding_id,
            raw_finding_id=source.raw_finding_id,
            exact_site_ranges=ranges,
        )
        related_edges = [
            edge
            for edge in dependency_edges
            if source.file_path in {str(edge.get("source")), str(edge.get("target"))}
        ]
        return {
            "id": uuid.uuid4(),
            "tenant_id": scan.tenant_id,
            "project_id": scan.project_id,
            "scan_id": scan.id,
            "attempt_id": scan.current_attempt_id,
            "finding_id": finding.id if finding is not None else None,
            "predecessor_finding_id": predecessor.id if predecessor else None,
            "fingerprint": fingerprint,
            "baseline_state": baseline_state,
            "site_identity": site_identity,
            "exact_ranges": ranges,
            "dataflow": {
                "affected_locations": source.affected_locations or [],
                "cross_file_status": source.cross_file_status,
                "cross_file_rationale": source.cross_file_rationale,
                "dependency_graph_sha256": dependency_digest,
                "dependency_edges": related_edges,
            },
            "source_provenance": {
                "source": source.source or "agent",
                "scanner_rule_id": source.scanner_rule_id,
                "cve_id": source.cve_id,
                "cwe": source.cwe,
                "references": source.references or [],
                "source_snapshot_hash": source.source_snapshot_hash,
            },
            "producer_provenance": {
                "raw_finding_id": (
                    str(source.raw_finding_id) if source.raw_finding_id else None
                ),
                "canonical_finding_id": (
                    str(source.canonical_finding_id)
                    if source.canonical_finding_id
                    else None
                ),
                "contributing_raw_finding_ids": [
                    str(value) for value in source.contributing_raw_finding_ids or []
                ],
                "corroborating_agents": source.corroborating_agents or [],
                "detected_by_llms": source.detected_by_llms or [],
            },
            "coverage_entry_ids": coverage_ids,
            "evidence_object_ids": evidence_ids,
            "remediation_state": {
                "recommendation": source.remediation,
                "fix_selection_status": source.fix_selection_status,
                "is_applied": source.is_applied_in_remediation,
                "fix_verified": source.fix_verified,
                "fixes": source.fixes,
            },
        }

    async def lineage_for_scan(
        self, scan_id: uuid.UUID
    ) -> list[db_models.FindingLineageRecord]:
        """Return the current attempt projection used by results and reports."""
        current_attempt_id = await self.db.scalar(
            select(db_models.Scan.current_attempt_id).where(
                db_models.Scan.id == scan_id
            )
        )
        attempt_clause = (
            db_models.FindingLineageRecord.attempt_id == current_attempt_id
            if current_attempt_id is not None
            else db_models.FindingLineageRecord.attempt_id.is_(None)
        )
        return list(
            (
                await self.db.scalars(
                    select(db_models.FindingLineageRecord)
                    .where(
                        db_models.FindingLineageRecord.scan_id == scan_id,
                        attempt_clause,
                    )
                    .order_by(
                        db_models.FindingLineageRecord.baseline_state,
                        db_models.FindingLineageRecord.fingerprint,
                    )
                )
            ).all()
        )

    async def lineage_history_for_scan(
        self, scan_id: uuid.UUID
    ) -> list[db_models.FindingLineageRecord]:
        """Return immutable generations across attempts for explicit audit views."""
        return list(
            (
                await self.db.scalars(
                    select(db_models.FindingLineageRecord)
                    .where(db_models.FindingLineageRecord.scan_id == scan_id)
                    .order_by(
                        db_models.FindingLineageRecord.created_at,
                        db_models.FindingLineageRecord.attempt_id,
                        db_models.FindingLineageRecord.baseline_state,
                        db_models.FindingLineageRecord.fingerprint,
                    )
                )
            ).all()
        )

    async def latest_policy(
        self, tenant_id: uuid.UUID, *, create_default: bool = False
    ) -> db_models.FindingPolicyVersion | None:
        row = await self.db.scalar(
            select(db_models.FindingPolicyVersion)
            .where(db_models.FindingPolicyVersion.tenant_id == tenant_id)
            .order_by(db_models.FindingPolicyVersion.version.desc())
            .limit(1)
        )
        if row is not None or not create_default:
            return row
        await self.db.execute(
            pg_insert(db_models.FindingPolicyVersion)
            .values(
                id=uuid.uuid4(),
                tenant_id=tenant_id,
                version=1,
                minimum_severity="high",
                minimum_confidence="medium",
                require_complete_coverage=True,
                allow_waivers=True,
                minimum_waiver_remaining_hours=0,
                actor_user_id=None,
                reason="System default finding gate policy.",
            )
            .on_conflict_do_nothing(index_elements=["tenant_id", "version"])
        )
        await self.db.flush()
        return await self.latest_policy(tenant_id)

    async def create_policy_version(
        self,
        *,
        tenant_id: uuid.UUID,
        actor_user_id: int,
        reason: str,
        policy: GatePolicy,
    ) -> db_models.FindingPolicyVersion:
        await self.db.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:tenant_id, 0))"),
            {"tenant_id": str(tenant_id)},
        )
        latest = await self.latest_policy(tenant_id)
        row = db_models.FindingPolicyVersion(
            id=uuid.uuid4(),
            tenant_id=tenant_id,
            version=(latest.version if latest else 0) + 1,
            minimum_severity=policy.minimum_severity.casefold(),
            minimum_confidence=policy.minimum_confidence.casefold(),
            require_complete_coverage=policy.require_complete_coverage,
            allow_waivers=policy.allow_waivers,
            minimum_waiver_remaining_hours=policy.minimum_waiver_remaining_hours,
            actor_user_id=actor_user_id,
            reason=reason,
        )
        self.db.add(row)
        await self.db.commit()
        await self.db.refresh(row)
        return row

    async def grant_waiver(
        self,
        *,
        scan: db_models.Scan,
        finding: db_models.Finding,
        scope: str,
        reason: str,
        expires_at: datetime,
        actor_user_id: int,
        commit: bool = True,
    ) -> db_models.FindingWaiver:
        fingerprint = finding_fingerprint(finding)
        scope_value = {
            "finding": str(finding.id),
            "fingerprint": fingerprint,
            "project": str(scan.project_id),
        }[scope]
        waiver = db_models.FindingWaiver(
            id=uuid.uuid4(),
            tenant_id=scan.tenant_id,
            project_id=scan.project_id,
            scan_id=scan.id,
            finding_id=finding.id,
            fingerprint=fingerprint,
            scope=scope,
            scope_value=scope_value,
            reason=reason,
            expires_at=expires_at,
            actor_user_id=actor_user_id,
        )
        self.db.add(waiver)
        await self.db.flush()
        self.db.add(
            db_models.FindingWaiverEvent(
                tenant_id=scan.tenant_id,
                waiver_id=waiver.id,
                action="granted",
                actor_user_id=actor_user_id,
                reason=reason,
            )
        )
        if commit:
            await self.db.commit()
            await self.db.refresh(waiver)
        else:
            await self.db.flush()
        return waiver

    async def revoke_waiver(
        self,
        waiver: db_models.FindingWaiver,
        *,
        actor_user_id: int,
        reason: str,
        commit: bool = True,
    ) -> None:
        await self.db.execute(
            pg_insert(db_models.FindingWaiverEvent)
            .values(
                tenant_id=waiver.tenant_id,
                waiver_id=waiver.id,
                action="revoked",
                actor_user_id=actor_user_id,
                reason=reason,
            )
            .on_conflict_do_nothing(index_elements=["waiver_id", "action"])
        )
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()

    async def record_expired_waivers(
        self,
        *,
        tenant_id: uuid.UUID,
        now: datetime | None = None,
        commit: bool = False,
    ) -> int:
        """Append one auditable expiry event for every elapsed grant."""
        current = now or datetime.now(timezone.utc)
        expired = list(
            (
                await self.db.scalars(
                    select(db_models.FindingWaiver).where(
                        db_models.FindingWaiver.tenant_id == tenant_id,
                        db_models.FindingWaiver.expires_at <= current,
                    )
                )
            ).all()
        )
        inserted = 0
        for waiver in expired:
            event_id = await self.db.scalar(
                pg_insert(db_models.FindingWaiverEvent)
                .values(
                    tenant_id=tenant_id,
                    waiver_id=waiver.id,
                    action="expired",
                    actor_user_id=None,
                    reason="Waiver expiry reached.",
                )
                .on_conflict_do_nothing(index_elements=["waiver_id", "action"])
                .returning(db_models.FindingWaiverEvent.id)
            )
            inserted += int(event_id is not None)
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return inserted

    async def waiver_history(
        self, waiver_id: uuid.UUID, *, tenant_id: uuid.UUID
    ) -> tuple[db_models.FindingWaiver | None, list[db_models.FindingWaiverEvent]]:
        waiver = await self.db.scalar(
            select(db_models.FindingWaiver).where(
                db_models.FindingWaiver.id == waiver_id,
                db_models.FindingWaiver.tenant_id == tenant_id,
            )
        )
        if waiver is None:
            return None, []
        if waiver.expires_at <= datetime.now(timezone.utc):
            # A history read is the lazy materialization boundary for elapsed
            # waivers. Persist the append-only event here rather than relying on
            # the request-scoped session to commit: `get_db` closes read
            # sessions without an implicit commit. The unique
            # `(waiver_id, action)` constraint keeps repeated reads idempotent.
            await self.record_expired_waivers(tenant_id=tenant_id, commit=True)
        events = list(
            (
                await self.db.scalars(
                    select(db_models.FindingWaiverEvent)
                    .where(db_models.FindingWaiverEvent.waiver_id == waiver_id)
                    .order_by(
                        db_models.FindingWaiverEvent.created_at,
                        db_models.FindingWaiverEvent.id,
                    )
                )
            ).all()
        )
        return waiver, events

    async def _eligible_waived_fingerprints(
        self, scan: db_models.Scan, policy: GatePolicy
    ) -> set[str]:
        now = datetime.now(timezone.utc)
        await self.record_expired_waivers(
            tenant_id=scan.tenant_id, now=now, commit=False
        )
        revoked = select(db_models.FindingWaiverEvent.waiver_id).where(
            db_models.FindingWaiverEvent.action == "revoked"
        )
        rows = list(
            (
                await self.db.scalars(
                    select(db_models.FindingWaiver).where(
                        db_models.FindingWaiver.tenant_id == scan.tenant_id,
                        db_models.FindingWaiver.expires_at > now,
                        not_(db_models.FindingWaiver.id.in_(revoked)),
                        or_(
                            and_(
                                db_models.FindingWaiver.scope == "project",
                                db_models.FindingWaiver.project_id == scan.project_id,
                            ),
                            db_models.FindingWaiver.scope == "fingerprint",
                            and_(
                                db_models.FindingWaiver.scope == "finding",
                                db_models.FindingWaiver.scan_id == scan.id,
                            ),
                        ),
                    )
                )
            ).all()
        )
        return {
            row.fingerprint
            for row in rows
            if waiver_is_eligible(expires_at=row.expires_at, policy=policy, now=now)
        }

    async def evaluate_scan_policy(
        self,
        scan_id: uuid.UUID,
        *,
        commit: bool = True,
        idempotent: bool = False,
    ) -> db_models.FindingPolicyEvaluation:
        scan = await self.db.get(db_models.Scan, scan_id)
        if scan is None:
            raise LookupError("Scan not found.")
        version = await self.latest_policy(scan.tenant_id, create_default=True)
        assert version is not None
        if idempotent:
            existing = await self.db.scalar(
                select(db_models.FindingPolicyEvaluation)
                .where(
                    db_models.FindingPolicyEvaluation.scan_id == scan.id,
                    db_models.FindingPolicyEvaluation.attempt_id
                    == scan.current_attempt_id,
                    db_models.FindingPolicyEvaluation.policy_version_id == version.id,
                )
                .order_by(db_models.FindingPolicyEvaluation.created_at.asc())
                .limit(1)
            )
            if existing is not None:
                return existing
        policy = GatePolicy(
            minimum_severity=version.minimum_severity,
            minimum_confidence=version.minimum_confidence,
            require_complete_coverage=version.require_complete_coverage,
            allow_waivers=version.allow_waivers,
            minimum_waiver_remaining_hours=version.minimum_waiver_remaining_hours,
        )
        findings = list(
            (
                await self.db.scalars(
                    select(db_models.Finding).where(
                        db_models.Finding.scan_id == scan.id,
                        self._final_findings(),
                    )
                )
            ).all()
        )
        coverage_entries: Sequence[Any] = []
        if scan.current_attempt_id:
            coverage_entries = list(
                (
                    await self.db.scalars(
                        select(db_models.ScannerCoverageEntry).where(
                            db_models.ScannerCoverageEntry.attempt_id
                            == scan.current_attempt_id
                        )
                    )
                ).all()
            )
        coverage = summarize_coverage(coverage_entries)
        result = evaluate_gate(
            findings,
            policy=policy,
            coverage_complete=coverage["is_complete"],
            waived_fingerprints=await self._eligible_waived_fingerprints(scan, policy),
        )
        evaluation = db_models.FindingPolicyEvaluation(
            id=uuid.uuid4(),
            tenant_id=scan.tenant_id,
            project_id=scan.project_id,
            scan_id=scan.id,
            attempt_id=scan.current_attempt_id,
            policy_version_id=version.id,
            outcome=result["outcome"],
            coverage_complete=result["coverage_complete"],
            blocking_fingerprints=result["blocking_fingerprints"],
            waived_fingerprints=result["waived_fingerprints"],
            details={**result, "policy_version": version.version},
        )
        self.db.add(evaluation)
        if commit:
            await self.db.commit()
            await self.db.refresh(evaluation)
        else:
            await self.db.flush()
        return evaluation

    async def portfolio_trends(
        self,
        *,
        tenant_id: uuid.UUID,
        visible_user_ids: list[int] | None,
        since: datetime,
    ) -> list[dict[str, Any]]:
        stmt = (
            select(db_models.FindingLineageRecord, db_models.Scan.created_at)
            .join(
                db_models.Scan,
                db_models.Scan.id == db_models.FindingLineageRecord.scan_id,
            )
            .where(
                db_models.FindingLineageRecord.tenant_id == tenant_id,
                db_models.Scan.created_at >= since,
                db_models.FindingLineageRecord.attempt_id.is_not_distinct_from(
                    db_models.Scan.current_attempt_id
                ),
            )
        )
        if visible_user_ids is not None:
            stmt = stmt.where(db_models.Scan.user_id.in_(visible_user_ids))
        rows = (await self.db.execute(stmt)).all()
        buckets: dict[str, Counter[str]] = {}
        for lineage, created_at in rows:
            day = created_at.astimezone(timezone.utc).date().isoformat()
            buckets.setdefault(day, Counter())[lineage.baseline_state] += 1
        return [
            {
                "date": day,
                **{
                    state: counts.get(state, 0)
                    for state in ("new", "fixed", "unchanged", "reintroduced")
                },
            }
            for day, counts in sorted(buckets.items())
        ]
