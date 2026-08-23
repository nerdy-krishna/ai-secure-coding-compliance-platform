"""Durable one-shot approval-gate persistence and resume leasing."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database import models as db_models


ACTIVE_GATE_STATES = ("pending", "decided", "resume_claimed")


def approval_evidence_hash(evidence: dict[str, Any]) -> str:
    encoded = json.dumps(
        evidence,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def approval_gate_payload(gate: db_models.ApprovalGate) -> dict[str, Any]:
    """Bounded gate identity carried through state, interrupt, queue, and UI."""
    return {
        "gate_id": str(gate.gate_id),
        "scan_id": str(gate.scan_id),
        "attempt_id": str(gate.attempt_id) if gate.attempt_id else None,
        "kind": gate.kind,
        "sequence": gate.sequence,
        "node_name": gate.node_name,
        "display_name": gate.display_name,
        "purpose": gate.purpose,
        "evidence_hash": gate.evidence_hash,
        "version": gate.version,
    }


class ApprovalGateRepository:
    def __init__(self, db_session: AsyncSession):
        self.db = db_session

    async def create_or_get_pending(
        self,
        *,
        scan_id: uuid.UUID,
        kind: str,
        node_name: str,
        display_name: str,
        purpose: str,
        evidence: dict[str, Any],
        commit: bool = True,
    ) -> db_models.ApprovalGate:
        """Create one active gate, serialized by a lock on the owning scan."""
        scan = await self.db.scalar(
            select(db_models.Scan).where(db_models.Scan.id == scan_id).with_for_update()
        )
        if scan is None:
            raise LookupError("Scan not found for approval gate.")
        evidence_hash = approval_evidence_hash(evidence)
        active = await self.db.scalar(
            select(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.scan_id == scan_id,
                db_models.ApprovalGate.state.in_(ACTIVE_GATE_STATES),
            )
            .order_by(db_models.ApprovalGate.sequence.desc())
            .limit(1)
        )
        if active is not None:
            if (
                active.state == "pending"
                and active.kind == kind
                and active.node_name == node_name
                and active.evidence_hash == evidence_hash
            ):
                return active
            active.state = "cancelled"
            active.completed_at = datetime.now(timezone.utc)
            active.version += 1

        sequence = (
            int(
                await self.db.scalar(
                    select(
                        func.coalesce(func.max(db_models.ApprovalGate.sequence), 0)
                    ).where(db_models.ApprovalGate.scan_id == scan_id)
                )
                or 0
            )
            + 1
        )
        gate = db_models.ApprovalGate(
            scan_id=scan_id,
            attempt_id=scan.current_attempt_id,
            thread_id=str(scan_id),
            node_name=node_name,
            kind=kind,
            sequence=sequence,
            display_name=display_name,
            purpose=purpose,
            evidence_hash=evidence_hash,
            evidence=evidence,
            state="pending",
            version=1,
        )
        self.db.add(gate)
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        await self.db.refresh(gate)
        return gate

    async def get(self, gate_id: uuid.UUID) -> Optional[db_models.ApprovalGate]:
        return await self.db.get(db_models.ApprovalGate, gate_id)

    async def bind_checkpoint(self, gate_id: uuid.UUID, *, checkpoint_id: str) -> bool:
        """Bind the immutable parked checkpoint once (or verify the same value)."""
        result = await self.db.execute(
            update(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.gate_id == gate_id,
                or_(
                    db_models.ApprovalGate.checkpoint_id.is_(None),
                    db_models.ApprovalGate.checkpoint_id == checkpoint_id,
                ),
            )
            .values(checkpoint_id=checkpoint_id)
        )
        await self.db.commit()
        return bool(result.rowcount)

    async def get_pending_for_scan(
        self, scan_id: uuid.UUID
    ) -> Optional[db_models.ApprovalGate]:
        return await self.db.scalar(
            select(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.scan_id == scan_id,
                db_models.ApprovalGate.state == "pending",
            )
            .order_by(db_models.ApprovalGate.sequence.desc())
            .limit(1)
        )

    async def get_active_for_scan(
        self, scan_id: uuid.UUID
    ) -> Optional[db_models.ApprovalGate]:
        return await self.db.scalar(
            select(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.scan_id == scan_id,
                db_models.ApprovalGate.state.in_(ACTIVE_GATE_STATES),
            )
            .order_by(db_models.ApprovalGate.sequence.desc())
            .limit(1)
        )

    async def get_by_decision_key(
        self, scan_id: uuid.UUID, idempotency_key: str
    ) -> Optional[db_models.ApprovalGate]:
        return await self.db.scalar(
            select(db_models.ApprovalGate).where(
                db_models.ApprovalGate.scan_id == scan_id,
                db_models.ApprovalGate.decision_idempotency_key == idempotency_key,
            )
        )

    async def lock_for_decision(
        self, gate_id: uuid.UUID
    ) -> Optional[db_models.ApprovalGate]:
        return await self.db.scalar(
            select(db_models.ApprovalGate)
            .where(db_models.ApprovalGate.gate_id == gate_id)
            .with_for_update()
        )

    async def record_decision(
        self,
        gate: db_models.ApprovalGate,
        *,
        actor_user_id: int,
        approved: bool,
        override_critical_secret: bool,
        idempotency_key: str,
    ) -> None:
        gate.state = "decided"
        gate.decision = approved
        gate.override_critical_secret = override_critical_secret
        gate.actor_user_id = actor_user_id
        gate.decision_idempotency_key = idempotency_key
        gate.decided_at = datetime.now(timezone.utc)
        gate.version += 1
        await self.db.flush()

    async def claim_resume(
        self,
        gate_id: uuid.UUID,
        *,
        owner: str,
        lease_seconds: int = 300,
    ) -> tuple[str, Optional[db_models.ApprovalGate]]:
        """Claim one resume. Returns claimed, busy, completed, or stale."""
        now = datetime.now(timezone.utc)
        lease_until = now + timedelta(seconds=lease_seconds)
        result = await self.db.execute(
            update(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.gate_id == gate_id,
                or_(
                    db_models.ApprovalGate.state == "decided",
                    (
                        (
                            db_models.ApprovalGate.state.in_(
                                ("resume_claimed", "resumed")
                            )
                        )
                        & (
                            db_models.ApprovalGate.resume_lease_expires_at.is_(None)
                            | (db_models.ApprovalGate.resume_lease_expires_at < now)
                        )
                    ),
                ),
            )
            .values(
                state="resume_claimed",
                resume_claimed_by=owner,
                resume_lease_expires_at=lease_until,
            )
            .returning(db_models.ApprovalGate.gate_id)
        )
        claimed_id = result.scalar_one_or_none()
        if claimed_id is not None:
            await self.db.commit()
            return "claimed", await self.get(claimed_id)

        await self.db.rollback()
        gate = await self.get(gate_id)
        if gate is None:
            return "stale", None
        if gate.state in {"completed", "expired", "cancelled"}:
            return "completed", gate
        if gate.state in {"resume_claimed", "resumed"}:
            return "busy", gate
        return "stale", gate

    async def mark_resumed(self, gate_id: uuid.UUID) -> bool:
        """Record that interrupt() returned; checkpoint completion comes later."""
        result = await self.db.execute(
            update(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.gate_id == gate_id,
                db_models.ApprovalGate.state == "resume_claimed",
            )
            .values(state="resumed")
        )
        await self.db.commit()
        return bool(result.rowcount)

    async def release_resume_claim(self, gate_id: uuid.UUID, *, owner: str) -> bool:
        result = await self.db.execute(
            update(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.gate_id == gate_id,
                db_models.ApprovalGate.state.in_(("resume_claimed", "resumed")),
                db_models.ApprovalGate.resume_claimed_by == owner,
            )
            .values(
                state="decided",
                resume_claimed_by=None,
                resume_lease_expires_at=None,
            )
        )
        await self.db.commit()
        return bool(result.rowcount)

    async def complete(self, gate_id: uuid.UUID, *, commit: bool = True) -> bool:
        result = await self.db.execute(
            update(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.gate_id == gate_id,
                db_models.ApprovalGate.state.in_(
                    ("decided", "resume_claimed", "resumed")
                ),
            )
            .values(
                state="completed",
                completed_at=datetime.now(timezone.utc),
                resume_claimed_by=None,
                resume_lease_expires_at=None,
            )
        )
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return bool(result.rowcount)

    async def close_active(
        self, scan_id: uuid.UUID, *, state: str, commit: bool = True
    ) -> int:
        result = await self.db.execute(
            update(db_models.ApprovalGate)
            .where(
                db_models.ApprovalGate.scan_id == scan_id,
                db_models.ApprovalGate.state.in_(ACTIVE_GATE_STATES),
            )
            .values(
                state=state,
                completed_at=datetime.now(timezone.utc),
                resume_claimed_by=None,
                resume_lease_expires_at=None,
                version=db_models.ApprovalGate.version + 1,
            )
        )
        if commit:
            await self.db.commit()
        else:
            await self.db.flush()
        return int(result.rowcount or 0)
