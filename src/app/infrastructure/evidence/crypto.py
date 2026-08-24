"""Portable envelope encryption for immutable evidence objects."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Any, Protocol

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


@dataclass(frozen=True)
class WrappedDataKey:
    wrapped: bytes
    provider: str
    key_id: str


class KeyProvider(Protocol):
    provider_name: str

    @property
    def current_key_id(self) -> str: ...

    def generate_data_key(self) -> DataKey: ...

    def unwrap_data_key(self, wrapped: bytes, key_id: str) -> bytes: ...

    def wrap_data_key(self, plaintext: bytes) -> WrappedDataKey: ...

    def rewrap_data_key(self, wrapped: bytes, key_id: str) -> WrappedDataKey: ...

    def needs_rotation(self, key_id: str) -> bool: ...


class LocalKeyProvider:
    """Development-only KEK provider with versioned AES-GCM wrapping."""

    provider_name = "local"

    def __init__(self, secret: str, *, key_id: str = "local-v1") -> None:
        self._kek = hashlib.sha256(secret.encode("utf-8")).digest()
        self._key_id = key_id

    @property
    def current_key_id(self) -> str:
        return self._key_id

    def generate_data_key(self) -> DataKey:
        plaintext = os.urandom(32)
        wrapped = self.wrap_data_key(plaintext)
        return DataKey(
            plaintext=plaintext,
            wrapped=wrapped.wrapped,
            provider=wrapped.provider,
            key_id=wrapped.key_id,
        )

    def wrap_data_key(self, plaintext: bytes) -> WrappedDataKey:
        if len(plaintext) != 32:
            raise ValueError("Evidence data keys must be 256 bits.")
        wrap_nonce = os.urandom(12)
        return WrappedDataKey(
            wrapped=wrap_nonce
            + AESGCM(self._kek).encrypt(wrap_nonce, plaintext, _WRAP_AAD),
            provider=self.provider_name,
            key_id=self._key_id,
        )

    def unwrap_data_key(self, wrapped: bytes, key_id: str) -> bytes:
        if key_id != self._key_id or len(wrapped) < 13:
            raise ValueError("Unknown or malformed local evidence data key.")
        return AESGCM(self._kek).decrypt(wrapped[:12], wrapped[12:], _WRAP_AAD)

    def rewrap_data_key(self, wrapped: bytes, key_id: str) -> WrappedDataKey:
        # Local KEKs are development-only and intentionally single-version.
        # A changed local key cannot safely decrypt the prior key without the
        # operator explicitly retaining that provider in a RotatingKeyProvider.
        plaintext = self.unwrap_data_key(wrapped, key_id)
        return self.wrap_data_key(plaintext)

    def needs_rotation(self, key_id: str) -> bool:
        return key_id != self._key_id


class AwsKmsKeyProvider:
    """Production data-key provider backed by AWS KMS-compatible APIs."""

    provider_name = "aws_kms"

    def __init__(self, key_id: str, region: str, *, client: Any | None = None) -> None:
        self._client = client or boto3.client("kms", region_name=region)
        metadata = self._client.describe_key(KeyId=key_id).get("KeyMetadata", {})
        canonical_arn = str(metadata.get("Arn") or "")
        if not canonical_arn.startswith("arn:"):
            raise ValueError("AWS KMS key must resolve to a canonical ARN.")
        self._key_id = canonical_arn

    @property
    def current_key_id(self) -> str:
        return self._key_id

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

    def wrap_data_key(self, plaintext: bytes) -> WrappedDataKey:
        if len(plaintext) != 32:
            raise ValueError("Evidence data keys must be 256 bits.")
        result = self._client.encrypt(
            KeyId=self._key_id,
            Plaintext=plaintext,
            EncryptionContext={"purpose": "sccap-evidence"},
        )
        return WrappedDataKey(
            wrapped=bytes(result["CiphertextBlob"]),
            provider=self.provider_name,
            key_id=self._key_id,
        )

    def unwrap_data_key(self, wrapped: bytes, key_id: str) -> bytes:
        result = self._client.decrypt(
            CiphertextBlob=wrapped,
            KeyId=key_id,
            EncryptionContext={"purpose": "sccap-evidence"},
        )
        return bytes(result["Plaintext"])

    def rewrap_data_key(self, wrapped: bytes, key_id: str) -> WrappedDataKey:
        """KMS-to-KMS re-encryption; plaintext DEKs never enter application memory."""
        result = self._client.re_encrypt(
            CiphertextBlob=wrapped,
            SourceKeyId=key_id,
            DestinationKeyId=self._key_id,
            SourceEncryptionContext={"purpose": "sccap-evidence"},
            DestinationEncryptionContext={"purpose": "sccap-evidence"},
        )
        return WrappedDataKey(
            wrapped=bytes(result["CiphertextBlob"]),
            provider=self.provider_name,
            key_id=self._key_id,
        )

    def needs_rotation(self, key_id: str) -> bool:
        return key_id != self._key_id


class RotatingKeyProvider:
    """Primary-write, multi-key-read provider used during zero-downtime rotation.

    New envelopes always use ``primary``. Existing envelopes select their
    provider by the persisted key id and are lazily rewrapped on successful
    reads. Operators can therefore retain old decrypt rights for the rotation
    window without continuing to write with the old key.
    """

    def __init__(
        self,
        primary: KeyProvider,
        *,
        previous: tuple[KeyProvider, ...] = (),
    ) -> None:
        self.primary = primary
        providers = (primary, *previous)
        self._providers = {provider.current_key_id: provider for provider in providers}
        if len(self._providers) != len(providers):
            raise ValueError("Envelope key ids must be unique.")
        self.provider_name = primary.provider_name

    @property
    def current_key_id(self) -> str:
        return self.primary.current_key_id

    def generate_data_key(self) -> DataKey:
        return self.primary.generate_data_key()

    def wrap_data_key(self, plaintext: bytes) -> WrappedDataKey:
        return self.primary.wrap_data_key(plaintext)

    def unwrap_data_key(self, wrapped: bytes, key_id: str) -> bytes:
        provider = self._providers.get(key_id)
        if provider is None:
            raise ValueError("Envelope key id is outside the configured rotation set.")
        return provider.unwrap_data_key(wrapped, key_id)

    def rewrap_data_key(self, wrapped: bytes, key_id: str) -> WrappedDataKey:
        if key_id == self.current_key_id:
            return WrappedDataKey(
                wrapped=wrapped,
                provider=self.provider_name,
                key_id=key_id,
            )
        source = self._providers.get(key_id)
        if source is None:
            raise ValueError("Envelope key id is outside the configured rotation set.")
        # AWS KMS can rewrap without exposing the DEK even when the persisted
        # source key differs from the configured primary key.
        if isinstance(self.primary, AwsKmsKeyProvider):
            return self.primary.rewrap_data_key(wrapped, key_id)
        plaintext = source.unwrap_data_key(wrapped, key_id)
        return self.primary.wrap_data_key(plaintext)

    def needs_rotation(self, key_id: str) -> bool:
        return key_id != self.current_key_id


def build_key_provider(config: Settings = settings) -> KeyProvider:
    if config.EVIDENCE_KEY_PROVIDER == "aws_kms":
        if not config.EVIDENCE_KMS_KEY_ID:
            raise RuntimeError("EVIDENCE_KMS_KEY_ID is required for AWS KMS.")
        primary = AwsKmsKeyProvider(
            config.EVIDENCE_KMS_KEY_ID, config.EVIDENCE_S3_REGION
        )
        previous = tuple(
            AwsKmsKeyProvider(key_id, config.EVIDENCE_S3_REGION)
            for key_id in config.EVIDENCE_KMS_PREVIOUS_KEY_IDS
        )
        return RotatingKeyProvider(primary, previous=previous)
    local_secret = config.EVIDENCE_LOCAL_KEK or config.ENCRYPTION_KEY
    return LocalKeyProvider(local_secret.get_secret_value())
