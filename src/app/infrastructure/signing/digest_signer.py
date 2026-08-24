"""Generic digest signing/verifying boundary with AWS KMS production support."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
from dataclasses import dataclass
from typing import Any, Protocol

import boto3


@dataclass(frozen=True)
class DigestSignature:
    signature_b64: str
    algorithm: str
    key_id: str


class DigestSigner(Protocol):
    async def sign_sha256(self, digest: bytes) -> DigestSignature: ...

    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool: ...


class AwsKmsDigestSigner:
    """Sign pre-hashed SHA-256 digests with an asymmetric AWS KMS key."""

    algorithm = "RSASSA_PSS_SHA_256"

    def __init__(self, *, key_id: str, region: str, client: Any | None = None) -> None:
        if not key_id.strip():
            raise ValueError("A KMS signing key id is required.")
        self.client = client or boto3.client("kms", region_name=region)
        metadata = self.client.describe_key(KeyId=key_id).get("KeyMetadata", {})
        canonical_arn = str(metadata.get("Arn") or "")
        if not canonical_arn.startswith("arn:"):
            raise ValueError("KMS signing key must resolve to a canonical ARN.")
        self.key_id = canonical_arn

    async def sign_sha256(self, digest: bytes) -> DigestSignature:
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("Expected a SHA-256 digest.")
        result = await asyncio.to_thread(
            self.client.sign,
            KeyId=self.key_id,
            Message=digest,
            MessageType="DIGEST",
            SigningAlgorithm=self.algorithm,
        )
        return DigestSignature(
            signature_b64=base64.b64encode(bytes(result["Signature"])).decode("ascii"),
            algorithm=self.algorithm,
            # Persist the configured/pinned key reference. Accepting the KMS
            # response ARN here would make an alias-configured verifier either
            # drift or trust any other key its IAM role can access.
            key_id=self.key_id,
        )

    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool:
        if signature.algorithm != self.algorithm or signature.key_id != self.key_id:
            return False
        result = await asyncio.to_thread(
            self.client.verify,
            KeyId=signature.key_id,
            Message=digest,
            MessageType="DIGEST",
            Signature=base64.b64decode(signature.signature_b64, validate=True),
            SigningAlgorithm=signature.algorithm,
        )
        return bool(result.get("SignatureValid"))


class LocalTestDigestSigner:
    """Deterministic test-only signer; deliberately not a production builder option."""

    algorithm = "TEST-HMAC-SHA256"

    def __init__(self, secret: bytes = b"sccap-rule-foundry-test-only") -> None:
        self.secret = secret

    async def sign_sha256(self, digest: bytes) -> DigestSignature:
        return DigestSignature(
            signature_b64=base64.b64encode(
                hmac.new(self.secret, digest, hashlib.sha256).digest()
            ).decode("ascii"),
            algorithm=self.algorithm,
            key_id="local-test-only",
        )

    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool:
        expected = await self.sign_sha256(digest)
        return signature.key_id == expected.key_id and hmac.compare_digest(
            signature.signature_b64, expected.signature_b64
        )
