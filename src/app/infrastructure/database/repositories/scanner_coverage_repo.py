"""Persistence and deterministic policy evaluation for scanner coverage."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


COVERAGE_STATES = frozenset(
    {
        "planned",
        "completed",
        "clean",
        "skipped",
        "failed",
        "timeout",
        "unsupported",
        "truncated",
    }
)
DEGRADED_COVERAGE_STATES = frozenset(
    {"planned", "skipped", "failed", "timeout", "unsupported", "truncated"}
)


def summarize_coverage(entries: Sequence[Any]) -> dict[str, Any]:
    """Deterministically distinguish complete, partial, and total degradation."""
    counts = {state: 0 for state in sorted(COVERAGE_STATES)}
    for entry in entries:
        counts[entry.status] += 1
    degraded = sum(counts[state] for state in DEGRADED_COVERAGE_STATES)
    return {
        "overall_status": (
            "unavailable" if not entries else "degraded" if degraded else "complete"
        ),
        "is_complete": bool(entries) and degraded == 0,
        "counts": counts,
    }


def coverage_policy_outcome(
    entries: Sequence[Any], failing_states: Sequence[str], *, waive: bool
) -> tuple[str, list[Any]]:
    """Pure policy gate used by the repository and deterministic regressions."""
    matching = [entry for entry in entries if entry.status in set(failing_states)]
    return (
        "waived" if matching and waive else "fail" if matching else "pass",
        matching,
    )


@dataclass(frozen=True)
class CoveragePlanItem:
    scanner_name: str
    input_path: str
    status: str = "planned"
    reason_code: str | None = None
    reason: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class CoverageOutcome:
    scanner_name: str
    input_path: str
    status: str
    reason_code: str | None = None
    reason: str | None = None
    finding_count: int = 0
    native_evidence_available: bool = False
    provenance_status: str | None = None
    details: dict[str, Any] = field(default_factory=dict)


class ScannerCoverageRepository:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def _scan(self, scan_id: uuid.UUID) -> db_models.Scan:
        scan = await self.db.get(db_models.Scan, scan_id)
        if scan is None:
            raise LookupError("Scan not found for scanner coverage.")
        if scan.current_attempt_id is None:
            raise ValueError("Scanner coverage requires an active scan attempt.")
        return scan

    async def plan(
        self,
        scan_id: uuid.UUID,
        items: Iterable[CoveragePlanItem],
        *,
        commit: bool = True,
    ) -> dict[tuple[str, str], db_models.ScannerCoverageEntry]:
        scan = await self._scan(scan_id)
        normalized = list(items)
        for item in normalized:
            if item.status not in COVERAGE_STATES:
                raise ValueError(f"Unknown scanner coverage state: {item.status}")
            stmt = (
                pg_insert(db_models.ScannerCoverageEntry)
                .values(
                    id=uuid.uuid4(),
                    scan_id=scan.id,
                    attempt_id=scan.current_attempt_id,
                    tenant_id=scan.tenant_id,
                    scanner_name=item.scanner_name,
                    input_path=item.input_path,
                    status=item.status,
                    reason_code=item.reason_code,
                    reason=item.reason,
                    details=item.details,
                    started_at=datetime.now(timezone.utc),
                    completed_at=(
                        datetime.now(timezone.utc) if item.status != "planned" else None
                    ),
                )
                .on_conflict_do_nothing(
                    index_elements=["attempt_id", "scanner_name", "input_path"]
                )
            )
            await self.db.execute(stmt)
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return await self.entry_map(scan.current_attempt_id)

    async def record_outcomes(
        self,
        scan_id: uuid.UUID,
        outcomes: Iterable[CoverageOutcome],
        *,
        commit: bool = True,
    ) -> dict[tuple[str, str], db_models.ScannerCoverageEntry]:
        scan = await self._scan(scan_id)
        existing = await self.entry_map(scan.current_attempt_id)
        now = datetime.now(timezone.utc)
        for outcome in outcomes:
            if outcome.status not in COVERAGE_STATES - {"planned"}:
                raise ValueError(
                    f"Invalid final scanner coverage state: {outcome.status}"
                )
            entry = existing.get((outcome.scanner_name, outcome.input_path))
            if entry is None:
                raise LookupError(
                    "Scanner coverage outcome did not match a planned input: "
                    f"{outcome.scanner_name}:{outcome.input_path}"
                )
            entry.status = outcome.status
            entry.reason_code = outcome.reason_code
            entry.reason = outcome.reason
            entry.finding_count = max(0, int(outcome.finding_count))
            entry.native_evidence_available = outcome.native_evidence_available
            entry.provenance_status = outcome.provenance_status
            entry.details = outcome.details
            entry.completed_at = now
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return existing

    async def entry_map(
        self, attempt_id: uuid.UUID
    ) -> dict[tuple[str, str], db_models.ScannerCoverageEntry]:
        rows = (
            await self.db.scalars(
                select(db_models.ScannerCoverageEntry).where(
                    db_models.ScannerCoverageEntry.attempt_id == attempt_id
                )
            )
        ).all()
        return {(row.scanner_name, row.input_path): row for row in rows}

    async def manifest(self, scan_id: uuid.UUID) -> dict[str, Any]:
        scan = await self._scan(scan_id)
        entries = sorted(
            (await self.entry_map(scan.current_attempt_id)).values(),
            key=lambda item: (item.scanner_name, item.input_path),
        )
        summary = summarize_coverage(entries)
        decision = await self.latest_decision(scan.current_attempt_id)
        return {
            "attempt_id": str(scan.current_attempt_id),
            **summary,
            "entries": [self.entry_payload(entry) for entry in entries],
            "latest_policy_decision": (
                self.decision_payload(decision) if decision is not None else None
            ),
        }

    async def evaluate_policy(
        self,
        scan_id: uuid.UUID,
        *,
        failing_states: Sequence[str],
        waive: bool,
        audit_reason: str,
        actor_user_id: int,
        commit: bool = True,
    ) -> db_models.ScannerCoveragePolicyDecision:
        scan = await self._scan(scan_id)
        states = sorted(set(failing_states))
        unknown = set(states) - COVERAGE_STATES
        if unknown:
            raise ValueError(f"Unknown coverage states: {', '.join(sorted(unknown))}")
        entries = list((await self.entry_map(scan.current_attempt_id)).values())
        outcome, matching = coverage_policy_outcome(entries, states, waive=waive)
        decision = db_models.ScannerCoveragePolicyDecision(
            id=uuid.uuid4(),
            scan_id=scan.id,
            attempt_id=scan.current_attempt_id,
            tenant_id=scan.tenant_id,
            failing_states=states,
            matching_entry_ids=[str(entry.id) for entry in matching],
            outcome=outcome,
            audit_reason=audit_reason,
            actor_user_id=actor_user_id,
        )
        self.db.add(decision)
        if commit:
            await self.db.commit()
            await self.db.refresh(decision)
        else:
            await self.db.flush()
        return decision

    async def latest_decision(
        self, attempt_id: uuid.UUID
    ) -> db_models.ScannerCoveragePolicyDecision | None:
        return await self.db.scalar(
            select(db_models.ScannerCoveragePolicyDecision)
            .where(db_models.ScannerCoveragePolicyDecision.attempt_id == attempt_id)
            .order_by(db_models.ScannerCoveragePolicyDecision.created_at.desc())
            .limit(1)
        )

    @staticmethod
    def entry_payload(entry: db_models.ScannerCoverageEntry) -> dict[str, Any]:
        return {
            "id": str(entry.id),
            "scanner_name": entry.scanner_name,
            "input_path": entry.input_path,
            "status": entry.status,
            "reason_code": entry.reason_code,
            "reason": entry.reason,
            "finding_count": entry.finding_count,
            "native_evidence_available": entry.native_evidence_available,
            "provenance_status": entry.provenance_status,
            "details": entry.details,
            "started_at": entry.started_at,
            "completed_at": entry.completed_at,
        }

    @staticmethod
    def decision_payload(
        decision: db_models.ScannerCoveragePolicyDecision,
    ) -> dict[str, Any]:
        return {
            "id": str(decision.id),
            "outcome": decision.outcome,
            "failing_states": decision.failing_states,
            "matching_entry_ids": decision.matching_entry_ids,
            "audit_reason": decision.audit_reason,
            "actor_user_id": decision.actor_user_id,
            "created_at": decision.created_at,
        }
