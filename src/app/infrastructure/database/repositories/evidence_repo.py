"""Immutable evidence metadata, manifests, governance, and object I/O."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config.config import settings
from app.config.logging_config import correlation_id_var
from app.infrastructure.database import models as db_models
from app.infrastructure.database.repositories.scan_attempt_repo import (
    ScanAttemptRepository,
)
from app.infrastructure.evidence.object_store import EvidenceObjectStore


def canonical_json(payload: Any) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class EvidenceRepository:
    def __init__(
        self, db: AsyncSession, *, object_store: EvidenceObjectStore | None = None
    ) -> None:
        self.db = db
        self.object_store = object_store or EvidenceObjectStore()

    @staticmethod
    def _aad_fields(
        *,
        evidence_id: uuid.UUID,
        scan_id: uuid.UUID,
        attempt_id: uuid.UUID,
        tenant_id: uuid.UUID | None,
        media_type: str,
        plaintext_sha256: str,
    ) -> dict[str, str]:
        return {
            "tenant_id": str(tenant_id or "unassigned"),
            "scan_id": str(scan_id),
            "attempt_id": str(attempt_id),
            "evidence_id": str(evidence_id),
            "media_type": media_type,
            "plaintext_sha256": plaintext_sha256,
        }

    async def persist_json(
        self,
        *,
        scan: db_models.Scan,
        artifact_type: str,
        version: int,
        payload: dict[str, Any],
        producer: dict[str, Any] | None = None,
        actor_user_id: int | None = None,
        legacy_artifact_id: uuid.UUID | None = None,
        commit: bool = True,
    ) -> db_models.EvidenceObject:
        await self.object_store.ensure_bucket()
        attempt = await ScanAttemptRepository(self.db).get_current(scan.id)
        if attempt is None:
            attempt = await ScanAttemptRepository(self.db).create_initial(
                scan, actor_user_id=actor_user_id or scan.user_id, commit=False
            )
        evidence_id = uuid.uuid4()
        plaintext = canonical_json(payload)
        plaintext_digest = hashlib.sha256(plaintext).hexdigest()
        media_type = "application/json"
        aad_fields = self._aad_fields(
            evidence_id=evidence_id,
            scan_id=scan.id,
            attempt_id=attempt.id,
            tenant_id=scan.tenant_id,
            media_type=media_type,
            plaintext_sha256=plaintext_digest,
        )
        object_key = (
            f"tenants/{scan.tenant_id or 'unassigned'}/attempts/{attempt.id}/"
            f"evidence/{evidence_id}"
        )
        stored = await self.object_store.put(
            object_key=object_key, plaintext=plaintext, aad_fields=aad_fields
        )
        evidence = db_models.EvidenceObject(
            id=evidence_id,
            scan_id=scan.id,
            attempt_id=attempt.id,
            tenant_id=scan.tenant_id,
            artifact_type=artifact_type,
            version=version,
            object_key=stored.object_key,
            object_version=stored.object_version,
            media_type=media_type,
            plaintext_size=stored.plaintext_size,
            ciphertext_size=stored.ciphertext_size,
            plaintext_sha256=stored.plaintext_sha256,
            ciphertext_sha256=stored.ciphertext_sha256,
            producer=producer or {},
            actor_user_id=actor_user_id,
            encryption_algorithm=stored.encryption_algorithm,
            key_provider=stored.key_provider,
            key_id=stored.key_id,
            wrapped_data_key=stored.wrapped_data_key,
            nonce=stored.nonce,
            aad_sha256=stored.aad_sha256,
            retention_policy=f"default-{settings.EVIDENCE_RETENTION_DAYS}d-v1",
            retain_until=datetime.now(timezone.utc)
            + timedelta(days=settings.EVIDENCE_RETENTION_DAYS),
            legal_hold=False,
            state="available",
            legacy_artifact_id=legacy_artifact_id,
        )
        self.db.add(evidence)
        await self.db.flush()
        await self._append_manifest(evidence, actor_user_id=actor_user_id)
        self._audit(evidence, "EVIDENCE_STORED", actor_user_id=actor_user_id)
        if commit:
            await self.db.commit()
            await self.db.refresh(evidence)
        return evidence

    async def _append_manifest(
        self, evidence: db_models.EvidenceObject, *, actor_user_id: int | None
    ) -> db_models.EvidenceManifest:
        prior = await self.db.scalar(
            select(db_models.EvidenceManifest)
            .where(db_models.EvidenceManifest.attempt_id == evidence.attempt_id)
            .order_by(db_models.EvidenceManifest.generation.desc())
            .limit(1)
            .with_for_update()
        )
        if prior is not None and prior.finalized:
            raise RuntimeError(
                "Cannot append evidence to a finalized attempt manifest."
            )
        previous_entries = list(prior.entries) if prior else []
        entry = {
            "evidence_id": str(evidence.id),
            "artifact_type": evidence.artifact_type,
            "version": evidence.version,
            "plaintext_sha256": evidence.plaintext_sha256,
            "object_version": evidence.object_version,
            "created_at": (
                evidence.created_at.isoformat() if evidence.created_at else None
            ),
        }
        entries = [*previous_entries, entry]
        body = {
            "attempt_id": str(evidence.attempt_id),
            "generation": (prior.generation + 1) if prior else 1,
            "previous_manifest_sha256": prior.manifest_sha256 if prior else None,
            "entries": entries,
        }
        manifest = db_models.EvidenceManifest(
            scan_id=evidence.scan_id,
            attempt_id=evidence.attempt_id,
            generation=body["generation"],
            previous_manifest_sha256=body["previous_manifest_sha256"],
            manifest_sha256=hashlib.sha256(canonical_json(body)).hexdigest(),
            entries=entries,
            finalized=False,
            actor_user_id=actor_user_id,
        )
        self.db.add(manifest)
        await self.db.flush()
        return manifest

    async def finalize_attempt(
        self,
        attempt_id: uuid.UUID,
        *,
        actor_user_id: int | None,
        commit: bool = True,
    ) -> db_models.EvidenceManifest:
        """Append one terminal manifest root without mutating prior generations."""
        attempt = await self.db.get(db_models.ScanAttempt, attempt_id)
        if attempt is None:
            raise LookupError("Scan attempt not found.")
        prior = await self.db.scalar(
            select(db_models.EvidenceManifest)
            .where(db_models.EvidenceManifest.attempt_id == attempt_id)
            .order_by(db_models.EvidenceManifest.generation.desc())
            .limit(1)
            .with_for_update()
        )
        if prior is not None and prior.finalized:
            return prior
        entries = list(prior.entries) if prior else []
        body = {
            "attempt_id": str(attempt_id),
            "generation": (prior.generation + 1) if prior else 1,
            "previous_manifest_sha256": prior.manifest_sha256 if prior else None,
            "entries": entries,
            "finalized": True,
        }
        manifest = db_models.EvidenceManifest(
            scan_id=attempt.scan_id,
            attempt_id=attempt.id,
            generation=body["generation"],
            previous_manifest_sha256=body["previous_manifest_sha256"],
            manifest_sha256=hashlib.sha256(canonical_json(body)).hexdigest(),
            entries=entries,
            finalized=True,
            actor_user_id=actor_user_id,
        )
        self.db.add(manifest)
        await self.db.flush()
        if commit:
            await self.db.commit()
            await self.db.refresh(manifest)
        return manifest

    def _audit(
        self,
        evidence: db_models.EvidenceObject,
        action: str,
        *,
        actor_user_id: int | None,
        reason: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        self.db.add(
            db_models.EvidenceGovernanceEvent(
                scan_id=evidence.scan_id,
                attempt_id=evidence.attempt_id,
                evidence_id=evidence.id,
                tenant_id=evidence.tenant_id,
                action=action,
                actor_user_id=actor_user_id,
                reason=reason,
                correlation_id=correlation_id_var.get(),
                details=details or {},
            )
        )

    async def read_json(
        self,
        evidence: db_models.EvidenceObject,
        *,
        actor_user_id: int | None = None,
        audit: bool = True,
    ) -> dict[str, Any]:
        if evidence.state != "available":
            raise FileNotFoundError("Evidence payload is no longer available.")
        aad_fields = self._aad_fields(
            evidence_id=evidence.id,
            scan_id=evidence.scan_id,
            attempt_id=evidence.attempt_id,
            tenant_id=evidence.tenant_id,
            media_type=evidence.media_type,
            plaintext_sha256=evidence.plaintext_sha256,
        )
        plaintext = await self.object_store.get(
            object_key=evidence.object_key,
            object_version=evidence.object_version,
            aad_fields=aad_fields,
            plaintext_sha256=evidence.plaintext_sha256,
            ciphertext_sha256=evidence.ciphertext_sha256,
            wrapped_data_key=evidence.wrapped_data_key,
            key_id=evidence.key_id,
            nonce=evidence.nonce,
            aad_sha256=evidence.aad_sha256,
        )
        payload = json.loads(plaintext)
        if not isinstance(payload, dict):
            raise TypeError("Evidence JSON root must be an object.")
        if audit:
            self._audit(evidence, "DOWNLOAD_VERIFIED", actor_user_id=actor_user_id)
            await self.db.commit()
        return payload

    async def set_legal_hold(
        self,
        evidence_id: uuid.UUID,
        *,
        enabled: bool,
        actor_user_id: int,
        reason: str,
    ) -> db_models.EvidenceObject:
        evidence = await self.db.scalar(
            select(db_models.EvidenceObject)
            .where(db_models.EvidenceObject.id == evidence_id)
            .with_for_update()
        )
        if evidence is None:
            raise LookupError("Evidence not found.")
        evidence.legal_hold = enabled
        self._audit(
            evidence,
            "LEGAL_HOLD_PLACED" if enabled else "LEGAL_HOLD_RELEASED",
            actor_user_id=actor_user_id,
            reason=reason,
        )
        await self.db.commit()
        await self.db.refresh(evidence)
        return evidence

    async def schedule_deletion(
        self,
        evidence: db_models.EvidenceObject,
        *,
        actor_user_id: int | None,
        reason: str,
        commit: bool = True,
    ) -> None:
        if evidence.legal_hold:
            self._audit(
                evidence,
                "DELETION_REJECTED_LEGAL_HOLD",
                actor_user_id=actor_user_id,
                reason=reason,
            )
            if commit:
                await self.db.commit()
            raise PermissionError("Evidence is under legal hold.")
        if evidence.state != "available":
            return
        evidence.state = "deletion_pending"
        self.db.add(db_models.EvidenceDeletionOutbox(evidence_id=evidence.id))
        self._audit(
            evidence,
            "DELETION_SCHEDULED",
            actor_user_id=actor_user_id,
            reason=reason,
        )
        if commit:
            await self.db.commit()
