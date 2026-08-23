"""Portable envelope encryption for immutable evidence objects."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Protocol

import boto3
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config.config import Settings, settings

_WRAP_AAD = b"sccap:evidence:data-key:v1"


@dataclass(frozen=True)
class DataKey:
    plaintext: bytes
    wrapped: bytes
    provider: str
    key_id: str


class KeyProvider(Protocol):
    provider_name: str

    def generate_data_key(self) -> DataKey: ...

    def unwrap_data_key(self, wrapped: bytes, key_id: str) -> bytes: ...


class LocalKeyProvider:
    """Development-only KEK provider with versioned AES-GCM wrapping."""

    provider_name = "local"

    def __init__(self, secret: str, *, key_id: str = "local-v1") -> None:
        self._kek = hashlib.sha256(secret.encode("utf-8")).digest()
        self._key_id = key_id

    def generate_data_key(self) -> DataKey:
        plaintext = os.urandom(32)
        wrap_nonce = os.urandom(12)
        wrapped = wrap_nonce + AESGCM(self._kek).encrypt(
            wrap_nonce, plaintext, _WRAP_AAD
        )
        return DataKey(
            plaintext=plaintext,
            wrapped=wrapped,
            provider=self.provider_name,
            key_id=self._key_id,
        )

    def unwrap_data_key(self, wrapped: bytes, key_id: str) -> bytes:
        if key_id != self._key_id or len(wrapped) < 13:
            raise ValueError("Unknown or malformed local evidence data key.")
        return AESGCM(self._kek).decrypt(wrapped[:12], wrapped[12:], _WRAP_AAD)


class AwsKmsKeyProvider:
    """Production data-key provider backed by AWS KMS-compatible APIs."""

    provider_name = "aws_kms"

    def __init__(self, key_id: str, region: str) -> None:
        self._key_id = key_id
        self._client = boto3.client("kms", region_name=region)

    def generate_data_key(self) -> DataKey:
        result = self._client.generate_data_key(
            KeyId=self._key_id,
            KeySpec="AES_256",
            EncryptionContext={"purpose": "sccap-evidence"},
        )
        return DataKey(
            plaintext=bytes(result["Plaintext"]),
            wrapped=bytes(result["CiphertextBlob"]),
            provider=self.provider_name,
            key_id=str(result.get("KeyId") or self._key_id),
        )

    def unwrap_data_key(self, wrapped: bytes, key_id: str) -> bytes:
        result = self._client.decrypt(
            CiphertextBlob=wrapped,
            KeyId=key_id,
            EncryptionContext={"purpose": "sccap-evidence"},
        )
        return bytes(result["Plaintext"])


def build_key_provider(config: Settings = settings) -> KeyProvider:
    if config.EVIDENCE_KEY_PROVIDER == "aws_kms":
        if not config.EVIDENCE_KMS_KEY_ID:
            raise RuntimeError("EVIDENCE_KMS_KEY_ID is required for AWS KMS.")
        return AwsKmsKeyProvider(config.EVIDENCE_KMS_KEY_ID, config.EVIDENCE_S3_REGION)
    local_secret = config.EVIDENCE_LOCAL_KEK or config.ENCRYPTION_KEY
    return LocalKeyProvider(local_secret.get_secret_value())
