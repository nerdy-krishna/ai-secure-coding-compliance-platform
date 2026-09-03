"""Production-only evidence adapters for the isolated C13 export worker."""

from __future__ import annotations

import hashlib
from datetime import timedelta
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.services.pentesting.capability13_export_service import (
    C13EvidenceAuthorizationDecision,
    C13EvidenceDescriptor,
    C13EvidenceMaterial,
    C13ProtectedPackage,
    C13RedactedChildResult,
)
from app.core.services.pentesting.capability13_recipient_registry_service import (
    Capability13RecipientRegistryService,
)
from app.infrastructure.database.repositories.authorization_repo import (
    AuthorizationRepository,
    target_fingerprint as authorization_target_fingerprint,
)
from app.infrastructure.database import models as database_models
from app.infrastructure.database.repositories.pentesting.capability13_export_repo import (
    C13ExportRequestRecord,
)
from app.infrastructure.database.repositories.pentesting.capability13_report_repo import (
    C13OwnerScope,
)
from app.infrastructure.database.repositories.user_group_repo import UserGroupRepository
from app.infrastructure.evidence.capability13_export_safety import (
    ExportSafetyPolicy,
    FIXED_LIMITS,
    RedactionPolicy,
    VERIFIER,
    VERIFIER_IMPLEMENTATION_DIGEST,
    redact_export_material,
    verify_export_material,
)
from app.infrastructure.evidence.capability13_recipient_envelope import (
    SUITE,
    RecipientEnvelopeBinding,
    encrypt_recipient_envelope,
)
from app.infrastructure.evidence.object_store import EvidenceObjectStore
from app.pentesting.contracts.canonical import contract_digest
from app.pentesting.persistence import models


PENTEST_READ = "pentest.read"
PENTEST_READ_TENANT = "pentest.read_tenant"
PENTEST_EVIDENCE_EXPORT = "pentest.evidence.export"
PENTEST_EVIDENCE_READ = "pentest.evidence.read"
PENTEST_GOVERNANCE_APPROVE = "pentest.governance.approve"


def _family(row: models.PentestEvidenceObject) -> str:
    media = row.media_type.split(";", 1)[0].strip().lower()
    if media == "application/json" or media.endswith("+json"):
        return "json"
    if media == "application/zip":
        return "zip_archive"
    if "header" in row.evidence_type.lower():
        return "http_headers"
    if media.startswith("text/"):
        return "text"
    raise ValueError("C13_EVIDENCE_FAMILY_UNSUPPORTED")


def _upload_aad(row: models.PentestEvidenceObject, upload: models.PentestEvidenceUpload) -> dict[str, object]:
    return {
        "schema": "sccap.pentest.evidence-upload.v1",
        "tenant_id": str(row.tenant_id), "engagement_id": str(row.engagement_id),
        "attempt_id": str(row.attempt_id), "execution_id": str(row.execution_id),
        "evidence_id": str(row.id), "upload_id": str(upload.id),
        "evidence_type": row.evidence_type, "layer": row.layer,
        "media_type": row.media_type,
        "parent_evidence_ids_digest": upload.parent_evidence_ids_digest,
        "plaintext_sha256": row.plaintext_sha256,
        "producer_generation": upload.producer_generation,
    }


def _direct_aad(row: models.PentestEvidenceObject) -> dict[str, object]:
    return {
        "schema": "sccap.pentest.evidence.v1",
        "tenant_id": str(row.tenant_id), "engagement_id": str(row.engagement_id),
        "attempt_id": str(row.attempt_id), "execution_id": str(row.execution_id),
        "evidence_id": str(row.id), "evidence_type": row.evidence_type,
    }


class SqlC13ReportExportBindingAuthorizer:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def authorize_source_binding(self, *, owner: C13OwnerScope,
        report_id: UUID, report_snapshot_digest: str, source_manifest_id: UUID,
        source_manifest_digest: str, requester_user_id: int) -> bool:
        del requester_user_id
        return bool(await self.db.scalar(select(models.PentestC13ReportSnapshot.id).where(
            models.PentestC13ReportSnapshot.id == report_id,
            models.PentestC13ReportSnapshot.tenant_id == owner.tenant_id,
            models.PentestC13ReportSnapshot.project_id == owner.project_id,
            models.PentestC13ReportSnapshot.engagement_id == owner.engagement_id,
            models.PentestC13ReportSnapshot.attempt_id == owner.attempt_id,
            models.PentestC13ReportSnapshot.resource_owner_user_id == owner.resource_owner_user_id,
            models.PentestC13ReportSnapshot.canonical_digest == report_snapshot_digest,
            models.PentestC13ReportSnapshot.source_manifest_id == source_manifest_id,
            models.PentestC13ReportSnapshot.source_manifest_digest == source_manifest_digest,
            models.PentestC13ReportSnapshot.completeness != "conflict",
        )))


class SqlC13EvidenceReader:
    def __init__(self, db: AsyncSession, object_store: EvidenceObjectStore,
        *, request_id: UUID, forbidden_canaries: tuple[bytes, ...] = ()) -> None:
        self.db = db
        self.store = object_store
        self.request_id = request_id
        self.canaries = forbidden_canaries

    async def _policy(self, owner: C13OwnerScope, family: str):
        policy_id = uuid5(NAMESPACE_URL, f"sccap:c13:verifier-policy:{owner.tenant_id}:{owner.project_id}:{family}:v1")
        row = await self.db.get(models.PentestC13ExportVerifierPolicyVersion, policy_id)
        now = await self.db.scalar(select(func.now()))
        if (
            row is None
            or row.tenant_id != owner.tenant_id
            or row.project_id != owner.project_id
            or row.evidence_family != family
            or row.version != 1
            or row.verifier != VERIFIER
            or row.verifier_implementation_digest != VERIFIER_IMPLEMENTATION_DIGEST
            or not (row.not_before <= now < row.expires_at)
        ):
            raise ValueError("C13_EXPORT_VERIFIER_POLICY_UNAVAILABLE")
        return row

    async def describe_exact(self, *, owner: C13OwnerScope, evidence_id: UUID,
        version_digest: str, content_digest: str) -> C13EvidenceDescriptor:
        row = await self.db.scalar(select(models.PentestEvidenceObject).where(
            models.PentestEvidenceObject.id == evidence_id,
            models.PentestEvidenceObject.tenant_id == owner.tenant_id,
            models.PentestEvidenceObject.engagement_id == owner.engagement_id,
            models.PentestEvidenceObject.attempt_id == owner.attempt_id,
        ))
        if (
            row is None
            or row.committed_at is None
            or row.plaintext_size > 16 * 1024 * 1024
            or contract_digest({"object_version": row.object_version}) != version_digest
            or row.plaintext_sha256 != content_digest
        ):
            raise ValueError("C13_EXPORT_SOURCE_UNAVAILABLE")
        tombstone = None
        if row.upload_id is not None:
            tombstone = await self.db.scalar(
                select(models.PentestEvidenceDeletionTombstone.id).where(
                    models.PentestEvidenceDeletionTombstone.tenant_id == owner.tenant_id,
                    models.PentestEvidenceDeletionTombstone.upload_id == row.upload_id,
                )
            )
        if tombstone is not None:
            raise ValueError("C13_EXPORT_SOURCE_DELETED")
        representation = "redacted" if row.redaction_status in {"redacted", "redacted_derivative"} else ("normalized" if row.layer == "normalized" else "raw")
        return C13EvidenceDescriptor(
            owner=owner, evidence_id=row.id, version_digest=version_digest,
            content_digest=row.plaintext_sha256, category=row.evidence_type,
            classification=row.sensitivity, representation=representation,
            redaction_child_id=(UUID(row.parent_evidence_ids[0]) if representation == "redacted" and row.parent_evidence_ids else None),
            retained=(row.legal_hold or row.retain_until > await self.db.scalar(select(func.now()))),
            deleted=False, integrity_verified=False,
            content_policy_verified=False, content_policy_digest="",
            contains_never_exportable=False, malware_scan_status="unknown",
            malware_scan_digest=None, byte_length=row.plaintext_size,
        )

    async def read_exact(self, *, owner: C13OwnerScope, evidence_id: UUID,
        version_digest: str, content_digest: str,
        include_content: bool) -> C13EvidenceMaterial:
        row = await self.db.scalar(select(models.PentestEvidenceObject).where(
            models.PentestEvidenceObject.id == evidence_id,
            models.PentestEvidenceObject.tenant_id == owner.tenant_id,
            models.PentestEvidenceObject.engagement_id == owner.engagement_id,
            models.PentestEvidenceObject.attempt_id == owner.attempt_id,
        ))
        if row is None or row.committed_at is None:
            raise ValueError("C13_EXPORT_SOURCE_UNAVAILABLE")
        if row.plaintext_size > 16 * 1024 * 1024:
            raise ValueError("C13_EXPORT_OBJECT_SIZE_LIMIT")
        if contract_digest({"object_version": row.object_version}) != version_digest or row.plaintext_sha256 != content_digest:
            raise ValueError("C13_EXPORT_INTEGRITY_FAILED")
        tombstone = None
        if row.upload_id is not None:
            tombstone = await self.db.scalar(
                select(models.PentestEvidenceDeletionTombstone.id).where(
                    models.PentestEvidenceDeletionTombstone.tenant_id
                    == owner.tenant_id,
                    models.PentestEvidenceDeletionTombstone.upload_id
                    == row.upload_id,
                )
            )
        if tombstone is not None:
            raise ValueError("C13_EXPORT_SOURCE_DELETED")
        upload = await self.db.get(models.PentestEvidenceUpload, row.upload_id) if row.upload_id else None
        if upload is not None:
            aad = _upload_aad(row, upload)
        elif row.producer.get("kind") == "c11_reconciler":
            raise ValueError("C13_EXPORT_SOURCE_UNSCANNABLE")
        else:
            aad = _direct_aad(row)
        plaintext = await self.store.get(
            object_key=row.object_key, object_version=row.object_version,
            aad_fields=aad, plaintext_sha256=row.plaintext_sha256,
            ciphertext_sha256=row.ciphertext_sha256,
            wrapped_data_key=row.wrapped_data_key, key_id=row.key_id,
            nonce=row.nonce, aad_sha256=row.aad_sha256,
        )
        family = _family(row)
        policy = await self._policy(owner, family)
        now = await self.db.scalar(select(func.now()))
        expires = min(policy.expires_at, row.retain_until, now + timedelta(hours=24))
        receipt = verify_export_material(
            evidence_id=evidence_id, evidence_version_digest=version_digest,
            content=plaintext, family=family,
            policy=ExportSafetyPolicy(policy.id, policy.version, family,
                policy.canonical_digest, policy.not_before, policy.expires_at),
            verified_at=now, expires_at=expires,
            forbidden_canaries=self.canaries,
        )
        selection = await self.db.scalar(select(models.PentestC13ExportSelection).where(
            models.PentestC13ExportSelection.request_id == self.request_id,
            models.PentestC13ExportSelection.evidence_ref == evidence_id,
            models.PentestC13ExportSelection.evidence_version_digest == version_digest,
        ))
        if selection is None:
            raise ValueError("C13_EXPORT_SELECTION_INVALID")
        existing = await self.db.scalar(select(models.PentestC13ExportVerificationReceipt.id).where(
            models.PentestC13ExportVerificationReceipt.request_id == self.request_id,
            models.PentestC13ExportVerificationReceipt.selection_id == selection.id,
            models.PentestC13ExportVerificationReceipt.target_version_digest == version_digest,
        ))
        if existing is None:
            self.db.add(models.PentestC13ExportVerificationReceipt(
                id=uuid4(), tenant_id=owner.tenant_id, project_id=owner.project_id,
                engagement_id=owner.engagement_id, attempt_id=owner.attempt_id,
                resource_owner_user_id=owner.resource_owner_user_id,
                aggregate_generation=1, source_cutoff_sequence=0,
                canonical_digest=receipt.canonical_digest, request_id=self.request_id,
                selection_id=selection.id, evidence_ref=evidence_id,
                target_version_digest=version_digest, content_digest=content_digest,
                evidence_family=family,
                detected_media_family=receipt.detected_media_family,
                policy_id=policy.id, policy_version=policy.version,
                policy_digest=policy.canonical_digest, limits=FIXED_LIMITS,
                verifier=VERIFIER,
                verifier_implementation_digest=VERIFIER_IMPLEMENTATION_DIGEST,
                outcome="eligible", complete=True, limitation_codes=[],
                verified_at=now, expires_at=expires,
            ))
            await self.db.flush()
        representation = "redacted" if row.redaction_status in {"redacted", "redacted_derivative"} else ("normalized" if row.layer == "normalized" else "raw")
        descriptor = C13EvidenceDescriptor(
            owner=owner, evidence_id=row.id, version_digest=version_digest,
            content_digest=row.plaintext_sha256, category=row.evidence_type,
            classification=row.sensitivity, representation=representation,
            redaction_child_id=(UUID(row.parent_evidence_ids[0]) if representation == "redacted" and row.parent_evidence_ids else None),
            retained=(row.legal_hold or row.retain_until > now), deleted=False,
            integrity_verified=True, content_policy_verified=True,
            content_policy_digest=receipt.canonical_digest,
            contains_never_exportable=False, malware_scan_status="clean",
            malware_scan_digest=receipt.canonical_digest,
            byte_length=len(plaintext),
        )
        return C13EvidenceMaterial(descriptor, plaintext if include_content else None)


class SqlC13PerObjectAuthorizer:
    def __init__(self, db: AsyncSession) -> None:
        self.db = db

    async def authorize_export(self, *, request: C13ExportRequestRecord,
        descriptor: C13EvidenceDescriptor, checked_at) -> C13EvidenceAuthorizationDecision:
        permissions = await AuthorizationRepository(self.db).permissions_for_user_id(
            user_id=request.requester_user_id, tenant_id=request.owner.tenant_id
        )
        needed = {PENTEST_READ, PENTEST_EVIDENCE_EXPORT}
        if request.profile == "protected_forensic":
            needed.add(PENTEST_EVIDENCE_READ)
        visible = request.requester_user_id == request.owner.resource_owner_user_id
        if PENTEST_READ_TENANT in permissions:
            visible = True
        if not visible:
            peers = await UserGroupRepository(self.db).get_peer_user_ids(
                request.requester_user_id, tenant_id=request.owner.tenant_id
            )
            visible = request.owner.resource_owner_user_id in peers
        allowed = (
            needed.issubset(permissions) and visible and descriptor.owner == request.owner
            and descriptor.retained and not descriptor.deleted
        )
        if request.profile == "protected_forensic":
            action = await self.db.get(
                database_models.AuthorizationActionRequest,
                request.authorization_action_request_id,
            )
            approver_permissions = frozenset()
            if action is not None and action.approver_user_id is not None:
                approver_permissions = await AuthorizationRepository(
                    self.db
                ).permissions_for_user_id(
                    user_id=action.approver_user_id,
                    tenant_id=request.owner.tenant_id,
                )
            allowed = allowed and bool(
                action is not None and action.tenant_id == request.owner.tenant_id
                and action.requester_user_id == request.requester_user_id
                and action.approver_user_id not in {None, request.requester_user_id}
                and action.status == "executed"
                and action.expires_at > checked_at
                and action.target_type == "c13_protected_evidence_export"
                and action.requester_permission == PENTEST_EVIDENCE_EXPORT
                and action.approver_permission == PENTEST_EVIDENCE_EXPORT
                and action.payload_digest == request.authorization_action_digest
                and action.target_fingerprint == authorization_target_fingerprint(
                    resource_type="c13_protected_evidence_export",
                    target_id=action.payload_digest,
                )
                and {
                    PENTEST_EVIDENCE_EXPORT,
                    PENTEST_EVIDENCE_READ,
                    PENTEST_GOVERNANCE_APPROVE,
                }.issubset(
                    approver_permissions
                )
                and PENTEST_GOVERNANCE_APPROVE in permissions
            )
        return C13EvidenceAuthorizationDecision(allowed, "authorized" if allowed else "C13_EXPORT_AUTHORIZATION_FAILED")


class SqlC13RedactedChildWriter:
    def __init__(self, db: AsyncSession, store: EvidenceObjectStore,
        *, request_id: UUID) -> None:
        self.db = db
        self.store = store
        self.request_id = request_id

    async def materialize_redacted_child(self, *, owner: C13OwnerScope,
        source: C13EvidenceMaterial, redaction_profile: str,
        redaction_version: str) -> C13RedactedChildResult:
        if source.content is None:
            raise ValueError("C13_EXPORT_SOURCE_UNAVAILABLE")
        source_row = await self.db.get(models.PentestEvidenceObject, source.descriptor.evidence_id)
        if source_row is None:
            raise ValueError("C13_EXPORT_SOURCE_UNAVAILABLE")
        family = _family(source_row)
        if family not in {"http_headers", "json", "text"}:
            raise ValueError("C13_REDACTION_FAMILY_UNSUPPORTED")
        now = await self.db.scalar(select(func.now()))
        policy_id = uuid5(NAMESPACE_URL, f"sccap:c13:redaction-policy:{owner.tenant_id}:{owner.project_id}:{family}:v1")
        policy_row = await self.db.get(models.PentestC13RedactionPolicyVersion, policy_id)
        expected_rules_digest = contract_digest(
            {"transform": "c13-code-redactor-v1", "family": family}
        )
        if (
            policy_row is None
            or policy_row.tenant_id != owner.tenant_id
            or policy_row.project_id != owner.project_id
            or policy_row.evidence_family != family
            or policy_row.version != 1
            or policy_row.transform_id != "c13-code-redactor"
            or policy_row.transform_version != "v1"
            or policy_row.implementation_digest != expected_rules_digest
            or policy_row.rules_digest != expected_rules_digest
            or not (policy_row.not_before <= now < policy_row.expires_at)
        ):
            raise ValueError("C13_REDACTION_POLICY_UNAVAILABLE")
        if redaction_profile != "portable-v1" or redaction_version not in {"1", "1.0.0"}:
            raise ValueError("C13_REDACTION_POLICY_MISMATCH")
        derivative = redact_export_material(
            source_evidence_id=source.descriptor.evidence_id,
            source_version_digest=source.descriptor.version_digest,
            source=source.content, family=family,
            policy=RedactionPolicy(policy_row.id, policy_row.version, family,
                "c13-code-redactor-v1", policy_row.rules_digest,
                policy_row.canonical_digest, policy_row.not_before, policy_row.expires_at),
        )
        storage_generation_id = uuid4()
        key = (f"tenants/{owner.tenant_id}/projects/{owner.project_id}/engagements/"
               f"{owner.engagement_id}/attempts/{owner.attempt_id}/capability13/"
               f"redactions/{derivative.child_id}/{storage_generation_id}")
        aad = {"schema": "sccap.pentest.c13-redaction-child.v1",
               "tenant_id": str(owner.tenant_id), "attempt_id": str(owner.attempt_id),
               "child_id": str(derivative.child_id),
               "storage_generation_id": str(storage_generation_id),
               "content_digest": derivative.child_content_digest,
               "policy_digest": policy_row.canonical_digest}
        stored = await self.store.put(object_key=key, plaintext=derivative.content, aad_fields=aad)
        selection = await self.db.scalar(select(models.PentestC13ExportSelection).where(
            models.PentestC13ExportSelection.request_id == self.request_id,
            models.PentestC13ExportSelection.evidence_ref == source.descriptor.evidence_id,
        ))
        if selection is None:
            raise ValueError("C13_EXPORT_SELECTION_INVALID")
        verifier_policy_id = uuid5(
            NAMESPACE_URL,
            f"sccap:c13:verifier-policy:{owner.tenant_id}:{owner.project_id}:{family}:v1",
        )
        verifier_policy = await self.db.get(
            models.PentestC13ExportVerifierPolicyVersion, verifier_policy_id
        )
        if verifier_policy is None:
            raise ValueError("C13_EXPORT_VERIFIER_POLICY_UNAVAILABLE")
        child_expiry = min(
            verifier_policy.expires_at,
            source_row.retain_until,
            now + timedelta(hours=24),
        )
        child_receipt = verify_export_material(
            evidence_id=derivative.child_id,
            evidence_version_digest=derivative.child_version_digest,
            content=derivative.content,
            family=family,
            policy=ExportSafetyPolicy(
                verifier_policy.id,
                verifier_policy.version,
                family,
                verifier_policy.canonical_digest,
                verifier_policy.not_before,
                verifier_policy.expires_at,
            ),
            verified_at=now,
            expires_at=child_expiry,
        )
        storage_ref = uuid5(NAMESPACE_URL, f"sccap:c13:object:{key}")
        storage_version_ref = uuid5(NAMESPACE_URL, f"sccap:c13:object-version:{key}:{stored.object_version}")
        storage_version_digest = contract_digest(
            {
                "storage_ref": storage_ref,
                "storage_version_ref": storage_version_ref,
                "storage_generation_id": storage_generation_id,
                "object_version": stored.object_version,
                "ciphertext_digest": stored.ciphertext_sha256,
            }
        )
        derivative_receipt_digest = contract_digest(
            {
                "schema_version": "sccap.pentest.c13-redaction-derivative-receipt.v1",
                "request_id": self.request_id,
                "selection_id": selection.id,
                "source_evidence_id": source.descriptor.evidence_id,
                "source_version_digest": source.descriptor.version_digest,
                "source_content_digest": source.descriptor.content_digest,
                "policy_id": policy_row.id,
                "policy_version": policy_row.version,
                "policy_digest": policy_row.canonical_digest,
                "rules_digest": policy_row.rules_digest,
                "child_evidence_id": derivative.child_id,
                "child_version_digest": derivative.child_version_digest,
                "child_content_digest": derivative.child_content_digest,
                "limitation_codes": list(derivative.limitations),
                "verifier": VERIFIER,
                "verifier_implementation_digest": VERIFIER_IMPLEMENTATION_DIGEST,
                "verification_receipt_digest": child_receipt.canonical_digest,
                "storage_version_digest": storage_version_digest,
            }
        )
        self.db.add(models.PentestC13RedactionDerivativeReceipt(
            id=uuid4(), tenant_id=owner.tenant_id, project_id=owner.project_id,
            engagement_id=owner.engagement_id, attempt_id=owner.attempt_id,
            resource_owner_user_id=owner.resource_owner_user_id,
            aggregate_generation=1, source_cutoff_sequence=0,
            canonical_digest=derivative_receipt_digest, request_id=self.request_id,
            selection_id=selection.id, source_evidence_id=source.descriptor.evidence_id,
            source_version_digest=source.descriptor.version_digest,
            source_content_digest=source.descriptor.content_digest,
            policy_id=policy_row.id, policy_digest=policy_row.canonical_digest,
            child_evidence_id=derivative.child_id,
            child_version_digest=derivative.child_version_digest,
            child_content_digest=derivative.child_content_digest,
            media_type="application/json" if family == "json" else "text/plain",
            byte_length=len(derivative.content), limitation_codes=list(derivative.limitations),
            verifier=VERIFIER,
            verifier_implementation_digest=VERIFIER_IMPLEMENTATION_DIGEST,
            verification_receipt_digest=child_receipt.canonical_digest,
            storage_ref=storage_ref, storage_version_ref=storage_version_ref,
            storage_generation_id=storage_generation_id,
            storage_version_digest=storage_version_digest,
            object_version=stored.object_version, ciphertext_size=stored.ciphertext_size,
            ciphertext_digest=stored.ciphertext_sha256,
            encryption_algorithm=stored.encryption_algorithm,
            key_provider=stored.key_provider, key_id=stored.key_id,
            wrapped_data_key=stored.wrapped_data_key, nonce=stored.nonce,
            aad_digest=stored.aad_sha256, retain_until=source_row.retain_until,
            key_state="active",
        ))
        self.db.add(
            models.PentestC13ExportVerificationReceipt(
                id=uuid4(), tenant_id=owner.tenant_id,
                project_id=owner.project_id, engagement_id=owner.engagement_id,
                attempt_id=owner.attempt_id,
                resource_owner_user_id=owner.resource_owner_user_id,
                aggregate_generation=1, source_cutoff_sequence=0,
                canonical_digest=child_receipt.canonical_digest,
                request_id=self.request_id, selection_id=selection.id,
                evidence_ref=derivative.child_id,
                target_version_digest=derivative.child_version_digest,
                content_digest=derivative.child_content_digest,
                evidence_family=family,
                detected_media_family=child_receipt.detected_media_family,
                policy_id=verifier_policy.id,
                policy_version=verifier_policy.version,
                policy_digest=verifier_policy.canonical_digest,
                limits=FIXED_LIMITS,
                verifier=VERIFIER,
                verifier_implementation_digest=VERIFIER_IMPLEMENTATION_DIGEST,
                outcome="eligible", complete=True, limitation_codes=[],
                verified_at=now, expires_at=child_expiry,
            )
        )
        descriptor = C13EvidenceDescriptor(
            owner=owner, evidence_id=derivative.child_id,
            version_digest=derivative.child_version_digest,
            content_digest=derivative.child_content_digest,
            category=source.descriptor.category,
            classification="internal", representation="redacted",
            redaction_child_id=source.descriptor.evidence_id,
            retained=True, deleted=False, integrity_verified=True,
            content_policy_verified=True,
            content_policy_digest=derivative.receipt_digest,
            contains_never_exportable=False, malware_scan_status="clean",
            malware_scan_digest=derivative.receipt_digest,
            byte_length=len(derivative.content),
        )
        return C13RedactedChildResult(
            C13EvidenceMaterial(descriptor, derivative.content),
            policy_row.rules_digest,
        )


class SqlC13RecipientPackageWriter:
    def __init__(self, db: AsyncSession, *, requester_user_id: int) -> None:
        self.db = db
        self.requester_user_id = requester_user_id

    async def protect(self, *, plaintext: bytes, owner: C13OwnerScope,
        request_id: UUID, export_id: UUID, artifact_id: UUID, report_id: UUID,
        report_snapshot_digest: str, source_manifest_id: UUID,
        source_manifest_digest: str, recipient_key_version_id: UUID | None,
        recipient_key_fingerprint: str | None,
        platform_envelope_profile: str | None) -> C13ProtectedPackage:
        del request_id
        if recipient_key_version_id is None or recipient_key_fingerprint is None or platform_envelope_profile is not None:
            raise ValueError("C13_EXPORT_RECIPIENT_INVALID")
        permissions = await AuthorizationRepository(self.db).permissions_for_user_id(
            user_id=self.requester_user_id, tenant_id=owner.tenant_id
        )
        visible_ids = None
        if PENTEST_READ_TENANT not in permissions:
            visible_ids = [self.requester_user_id, *await UserGroupRepository(self.db).get_peer_user_ids(
                self.requester_user_id, tenant_id=owner.tenant_id
            )]
        key_row, key = await Capability13RecipientRegistryService(self.db).resolve_active(
            tenant_id=owner.tenant_id, project_id=owner.project_id,
            key_version_id=recipient_key_version_id,
            visible_user_ids=visible_ids,
        )
        if key.fingerprint != recipient_key_fingerprint:
            raise ValueError("C13_RECIPIENT_KEY_MISMATCH")
        result = encrypt_recipient_envelope(
            plaintext=plaintext, recipient_public_key=key,
            binding=RecipientEnvelopeBinding(
                tenant_id=owner.tenant_id, export_id=export_id,
                artifact_id=artifact_id, report_id=report_id,
                report_digest=report_snapshot_digest,
                source_manifest_id=source_manifest_id,
                source_manifest_digest=source_manifest_digest,
                recipient_key_id=key_row.id,
                recipient_key_generation=key_row.version,
                recipient_key_fingerprint=key_row.fingerprint,
            ),
        )
        return C13ProtectedPackage(
            result.envelope, SUITE, result.header_sha256,
            result.plaintext_sha256, result.envelope_sha256,
        )


__all__ = [
    "SqlC13EvidenceReader", "SqlC13PerObjectAuthorizer",
    "SqlC13RecipientPackageWriter", "SqlC13RedactedChildWriter",
    "SqlC13ReportExportBindingAuthorizer",
]
