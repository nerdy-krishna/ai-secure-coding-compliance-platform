"""Encrypted, create-only storage adapter for Capability 13 artifacts.

Object locators and envelope-key material are deliberately confined to the
persistence/worker boundary.  Ordinary API and generated-client contracts
expose only artifact identifiers, media metadata, sizes, and digests.
"""

from __future__ import annotations

import hashlib
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from app.core.services.pentesting.capability13_export_service import (
    C13StoredExportArtifactReceipt,
)
from app.core.services.pentesting.capability13_report_service import (
    C13StoredReportArtifactReceipt,
)
from app.infrastructure.database.repositories.pentesting.capability13_report_repo import (
    C13OwnerScope,
)
from app.infrastructure.evidence.object_store import EvidenceObjectStore, StoredEvidence


def _object_key(
    owner: C13OwnerScope, *, kind: str, parent_id: UUID,
    artifact_id: UUID, storage_generation_id: UUID,
) -> str:
    return (
        f"tenants/{owner.tenant_id}/projects/{owner.project_id}/"
        f"engagements/{owner.engagement_id}/attempts/{owner.attempt_id}/"
        f"capability13/{kind}/{parent_id}/{artifact_id}/{storage_generation_id}"
    )


def _aad(
    owner: C13OwnerScope,
    *,
    kind: str,
    parent_id: UUID,
    artifact_id: UUID,
    media_type: str,
    plaintext_digest: str,
    storage_generation_id: UUID,
) -> dict[str, str]:
    return {
        "schema_version": "sccap.pentest.c13-artifact-aad.v1",
        "tenant_id": str(owner.tenant_id),
        "project_id": str(owner.project_id),
        "engagement_id": str(owner.engagement_id),
        "attempt_id": str(owner.attempt_id),
        "kind": kind,
        "parent_id": str(parent_id),
        "artifact_id": str(artifact_id),
        "media_type": media_type,
        "plaintext_digest": plaintext_digest,
        "storage_generation_id": str(storage_generation_id),
    }


class Capability13ArtifactStore:
    """Stores report/export bytes through the existing encrypted object store."""

    def __init__(self, object_store: EvidenceObjectStore) -> None:
        self._store = object_store

    async def _put(
        self,
        *,
        owner: C13OwnerScope,
        kind: str,
        parent_id: UUID,
        artifact_id: UUID,
        media_type: str,
        content: bytes,
        expected_sha256: str,
    ) -> tuple[UUID, UUID, UUID, StoredEvidence]:
        actual_digest = hashlib.sha256(content).hexdigest()
        if actual_digest != expected_sha256:
            raise ValueError("C13_ARTIFACT_DIGEST_MISMATCH")
        storage_generation_id = uuid4()
        key = _object_key(
            owner, kind=kind, parent_id=parent_id, artifact_id=artifact_id,
            storage_generation_id=storage_generation_id,
        )
        stored = await self._store.put(
            object_key=key,
            plaintext=content,
            aad_fields=_aad(
                owner,
                kind=kind,
                parent_id=parent_id,
                artifact_id=artifact_id,
                media_type=media_type,
                plaintext_digest=actual_digest,
                storage_generation_id=storage_generation_id,
            ),
        )
        storage_ref = uuid5(NAMESPACE_URL, f"sccap:c13:object:{key}")
        version_ref = uuid5(
            NAMESPACE_URL, f"sccap:c13:object-version:{key}:{stored.object_version}"
        )
        return storage_generation_id, storage_ref, version_ref, stored

    async def put_report_artifact(
        self,
        *,
        owner: C13OwnerScope,
        report_id: UUID,
        artifact_id: UUID,
        format: str,
        media_type: str,
        filename: str,
        content: bytes,
        expected_sha256: str,
    ) -> C13StoredReportArtifactReceipt:
        del format, filename
        storage_generation_id, storage_ref, version_ref, stored = await self._put(
            owner=owner,
            kind="reports",
            parent_id=report_id,
            artifact_id=artifact_id,
            media_type=media_type,
            content=content,
            expected_sha256=expected_sha256,
        )
        return C13StoredReportArtifactReceipt(
            storage_ref=storage_ref,
            storage_version_ref=version_ref,
            byte_length=stored.plaintext_size,
            sha256_digest=stored.plaintext_sha256,
            object_version=stored.object_version,
            ciphertext_size=stored.ciphertext_size,
            ciphertext_digest=stored.ciphertext_sha256,
            encryption_algorithm=stored.encryption_algorithm,
            key_provider=stored.key_provider,
            key_id=stored.key_id,
            wrapped_data_key=stored.wrapped_data_key,
            nonce=stored.nonce,
            aad_digest=stored.aad_sha256,
            storage_generation_id=storage_generation_id,
        )

    async def put_export_artifact(
        self,
        *,
        owner: C13OwnerScope,
        export_id: UUID,
        artifact_id: UUID,
        media_type: str,
        filename: str,
        content: bytes,
        expected_sha256: str,
    ) -> C13StoredExportArtifactReceipt:
        del filename
        storage_generation_id, storage_ref, version_ref, stored = await self._put(
            owner=owner,
            kind="exports",
            parent_id=export_id,
            artifact_id=artifact_id,
            media_type=media_type,
            content=content,
            expected_sha256=expected_sha256,
        )
        return C13StoredExportArtifactReceipt(
            storage_ref=storage_ref,
            storage_version_ref=version_ref,
            byte_length=stored.plaintext_size,
            sha256_digest=stored.plaintext_sha256,
            object_version=stored.object_version,
            ciphertext_size=stored.ciphertext_size,
            ciphertext_digest=stored.ciphertext_sha256,
            encryption_algorithm=stored.encryption_algorithm,
            key_provider=stored.key_provider,
            key_id=stored.key_id,
            wrapped_data_key=stored.wrapped_data_key,
            nonce=stored.nonce,
            aad_digest=stored.aad_sha256,
            storage_generation_id=storage_generation_id,
        )

    async def get_report_artifact(
        self,
        *,
        owner: C13OwnerScope,
        report_id: UUID,
        artifact_id: UUID,
        media_type: str,
        plaintext_digest: str,
        object_version: str,
        ciphertext_digest: str,
        wrapped_data_key: bytes,
        key_id: str,
        nonce: bytes,
        aad_digest: str,
        storage_generation_id: UUID,
    ) -> bytes:
        key = _object_key(
            owner, kind="reports", parent_id=report_id, artifact_id=artifact_id,
            storage_generation_id=storage_generation_id,
        )
        return await self._store.get(
            object_key=key,
            object_version=object_version,
            aad_fields=_aad(
                owner,
                kind="reports",
                parent_id=report_id,
                artifact_id=artifact_id,
                media_type=media_type,
                plaintext_digest=plaintext_digest,
                storage_generation_id=storage_generation_id,
            ),
            plaintext_sha256=plaintext_digest,
            ciphertext_sha256=ciphertext_digest,
            wrapped_data_key=wrapped_data_key,
            key_id=key_id,
            nonce=nonce,
            aad_sha256=aad_digest,
        )

    async def get_export_artifact(
        self,
        *,
        owner: C13OwnerScope,
        export_id: UUID,
        artifact_id: UUID,
        media_type: str,
        plaintext_digest: str,
        object_version: str,
        ciphertext_digest: str,
        wrapped_data_key: bytes,
        key_id: str,
        nonce: bytes,
        aad_digest: str,
        storage_generation_id: UUID,
    ) -> bytes:
        key = _object_key(
            owner, kind="exports", parent_id=export_id, artifact_id=artifact_id,
            storage_generation_id=storage_generation_id,
        )
        return await self._store.get(
            object_key=key,
            object_version=object_version,
            aad_fields=_aad(
                owner,
                kind="exports",
                parent_id=export_id,
                artifact_id=artifact_id,
                media_type=media_type,
                plaintext_digest=plaintext_digest,
                storage_generation_id=storage_generation_id,
            ),
            plaintext_sha256=plaintext_digest,
            ciphertext_sha256=ciphertext_digest,
            wrapped_data_key=wrapped_data_key,
            key_id=key_id,
            nonce=nonce,
            aad_sha256=aad_digest,
        )


__all__ = ["Capability13ArtifactStore"]
