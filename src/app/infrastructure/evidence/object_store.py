"""Private S3-compatible storage with authenticated client-side encryption."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Mapping

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config.config import Settings, settings
from app.infrastructure.evidence.crypto import KeyProvider, build_key_provider


class EvidenceIntegrityError(RuntimeError):
    """Evidence bytes or authenticated context do not match persisted metadata."""


@dataclass(frozen=True)
class StoredEvidence:
    object_key: str
    object_version: str
    plaintext_size: int
    ciphertext_size: int
    plaintext_sha256: str
    ciphertext_sha256: str
    encryption_algorithm: str
    key_provider: str
    key_id: str
    wrapped_data_key: bytes
    nonce: bytes
    aad_sha256: str


def canonical_aad(fields: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(fields), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class EvidenceObjectStore:
    """Create-only encrypted evidence storage; callers own authorization."""

    def __init__(
        self,
        config: Settings = settings,
        *,
        key_provider: KeyProvider | None = None,
        client: Any | None = None,
    ) -> None:
        self.config = config
        self.bucket = config.EVIDENCE_S3_BUCKET
        self.key_provider = key_provider or build_key_provider(config)
        if client is not None:
            self.client = client
            return
        access = config.EVIDENCE_S3_ACCESS_KEY_ID
        secret = config.EVIDENCE_S3_SECRET_ACCESS_KEY
        self.client = boto3.client(
            "s3",
            endpoint_url=config.EVIDENCE_S3_ENDPOINT,
            region_name=config.EVIDENCE_S3_REGION,
            aws_access_key_id=access.get_secret_value() if access else None,
            aws_secret_access_key=secret.get_secret_value() if secret else None,
            config=Config(
                s3={
                    "addressing_style": (
                        "path" if config.EVIDENCE_S3_FORCE_PATH_STYLE else "virtual"
                    )
                }
            ),
        )

    async def ensure_bucket(self) -> None:
        await asyncio.to_thread(self._ensure_bucket_sync)

    def _ensure_bucket_sync(self) -> None:
        try:
            self.client.head_bucket(Bucket=self.bucket)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in {"404", "NoSuchBucket", "NotFound"}:
                raise
            kwargs: dict[str, Any] = {"Bucket": self.bucket}
            if self.config.EVIDENCE_S3_REGION != "us-east-1":
                kwargs["CreateBucketConfiguration"] = {
                    "LocationConstraint": self.config.EVIDENCE_S3_REGION
                }
            self.client.create_bucket(**kwargs)
        self.client.put_bucket_versioning(
            Bucket=self.bucket, VersioningConfiguration={"Status": "Enabled"}
        )

    async def put(
        self,
        *,
        object_key: str,
        plaintext: bytes,
        aad_fields: Mapping[str, Any],
    ) -> StoredEvidence:
        return await asyncio.to_thread(
            self._put_sync,
            object_key=object_key,
            plaintext=plaintext,
            aad_fields=aad_fields,
        )

    def _put_sync(
        self,
        *,
        object_key: str,
        plaintext: bytes,
        aad_fields: Mapping[str, Any],
    ) -> StoredEvidence:
        aad = canonical_aad(aad_fields)
        data_key = self.key_provider.generate_data_key()
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key.plaintext).encrypt(nonce, plaintext, aad)
        plain_digest = hashlib.sha256(plaintext).hexdigest()
        cipher_digest = hashlib.sha256(ciphertext).hexdigest()
        result = self.client.put_object(
            Bucket=self.bucket,
            Key=object_key,
            Body=ciphertext,
            ContentType="application/octet-stream",
            IfNoneMatch="*",
            Metadata={
                "plaintext-sha256": plain_digest,
                "ciphertext-sha256": cipher_digest,
                "algorithm": "AES-256-GCM",
            },
        )
        return StoredEvidence(
            object_key=object_key,
            object_version=str(result.get("VersionId") or "null"),
            plaintext_size=len(plaintext),
            ciphertext_size=len(ciphertext),
            plaintext_sha256=plain_digest,
            ciphertext_sha256=cipher_digest,
            encryption_algorithm="AES-256-GCM",
            key_provider=data_key.provider,
            key_id=data_key.key_id,
            wrapped_data_key=data_key.wrapped,
            nonce=nonce,
            aad_sha256=hashlib.sha256(aad).hexdigest(),
        )

    async def get(
        self,
        *,
        object_key: str,
        object_version: str,
        aad_fields: Mapping[str, Any],
        plaintext_sha256: str,
        ciphertext_sha256: str,
        wrapped_data_key: bytes,
        key_id: str,
        nonce: bytes,
        aad_sha256: str,
    ) -> bytes:
        return await asyncio.to_thread(
            self._get_sync,
            object_key=object_key,
            object_version=object_version,
            aad_fields=aad_fields,
            plaintext_sha256=plaintext_sha256,
            ciphertext_sha256=ciphertext_sha256,
            wrapped_data_key=wrapped_data_key,
            key_id=key_id,
            nonce=nonce,
            aad_sha256=aad_sha256,
        )

    def _get_sync(self, **kwargs: Any) -> bytes:
        request: dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": kwargs["object_key"],
        }
        if kwargs["object_version"] != "null":
            request["VersionId"] = kwargs["object_version"]
        result = self.client.get_object(**request)
        ciphertext = result["Body"].read()
        if hashlib.sha256(ciphertext).hexdigest() != kwargs["ciphertext_sha256"]:
            raise EvidenceIntegrityError("Evidence ciphertext digest mismatch.")
        aad = canonical_aad(kwargs["aad_fields"])
        if hashlib.sha256(aad).hexdigest() != kwargs["aad_sha256"]:
            raise EvidenceIntegrityError("Evidence authenticated context mismatch.")
        try:
            data_key = self.key_provider.unwrap_data_key(
                kwargs["wrapped_data_key"], kwargs["key_id"]
            )
            plaintext = AESGCM(data_key).decrypt(kwargs["nonce"], ciphertext, aad)
        except (InvalidTag, ValueError) as exc:
            raise EvidenceIntegrityError("Evidence authentication failed.") from exc
        if hashlib.sha256(plaintext).hexdigest() != kwargs["plaintext_sha256"]:
            raise EvidenceIntegrityError("Evidence plaintext digest mismatch.")
        return plaintext

    async def delete(self, *, object_key: str, object_version: str) -> None:
        request: dict[str, Any] = {"Bucket": self.bucket, "Key": object_key}
        if object_version != "null":
            request["VersionId"] = object_version
        await asyncio.to_thread(self.client.delete_object, **request)

    async def list_versions_older_than(
        self, cutoff: datetime, *, limit: int = 100
    ) -> list[tuple[str, str]]:
        return await asyncio.to_thread(
            self._list_versions_older_than_sync, cutoff=cutoff, limit=limit
        )

    def _list_versions_older_than_sync(
        self, *, cutoff: datetime, limit: int
    ) -> list[tuple[str, str]]:
        found: list[tuple[str, str]] = []
        paginator = self.client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=self.bucket, Prefix="tenants/"):
            for item in page.get("Versions", []):
                if item["LastModified"] < cutoff:
                    found.append((str(item["Key"]), str(item["VersionId"])))
                    if len(found) >= limit:
                        return found
        return found
