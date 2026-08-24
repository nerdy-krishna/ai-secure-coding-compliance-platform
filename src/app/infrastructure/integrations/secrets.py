"""KMS-enveloped integration secrets with lazy Fernet/key rotation migration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import uuid
from collections.abc import Mapping
from typing import Any

from sqlalchemy import update

from app.config.config import settings
from app.infrastructure.database import models as db_models
from app.infrastructure.evidence.crypto import build_key_provider
from app.infrastructure.secrets import SecretEnvelopeCipher
from app.shared.lib.encryption import FernetEncrypt

_KMS_PREFIX = b"SCCAP-KMS-ENVELOPE-V1\0"


def _normalize(secrets: Mapping[str, str]) -> bytes:
    normalized: dict[str, str] = {}
    for key, value in secrets.items():
        name = str(key).strip()
        secret = str(value)
        if not name or not secret:
            raise ValueError("integration secret names and values must be non-empty")
        if len(name) > 64 or len(secret) > 32_000:
            raise ValueError("integration secret exceeds storage bounds")
        normalized[name] = secret
    if not normalized:
        raise ValueError("at least one integration secret is required")
    return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()


def _decode(plaintext: bytes) -> dict[str, str]:
    value: Any = json.loads(plaintext)
    if not isinstance(value, dict) or not value:
        raise ValueError("integration secret envelope is invalid")
    secrets = {str(key): str(item) for key, item in value.items()}
    if any(not key or not item for key, item in secrets.items()):
        raise ValueError("integration secret envelope contains empty values")
    return secrets


def _scope(tenant_id: uuid.UUID, principal_id: uuid.UUID) -> dict[str, str]:
    return {
        "tenant_id": str(tenant_id),
        "principal_id": str(principal_id),
        "slot": "integration_service_principal.secrets",
    }


def _cipher() -> SecretEnvelopeCipher:
    if (
        settings.ENVIRONMENT != "development"
        and settings.EVIDENCE_KEY_PROVIDER != "aws_kms"
    ):
        raise RuntimeError(
            "Non-development integration secrets require AWS KMS envelopes."
        )
    return SecretEnvelopeCipher(build_key_provider(settings))


def encrypt_integration_secrets(secrets: Mapping[str, str]) -> tuple[bytes, str]:
    """Legacy helper retained for old callers; persisted rows use the scoped API."""
    serialized = _normalize(secrets).decode("utf-8")
    ciphertext = FernetEncrypt.encrypt(serialized).encode("utf-8")
    return ciphertext, hashlib.sha256(ciphertext).hexdigest()


def decrypt_integration_secrets(ciphertext: bytes) -> dict[str, str]:
    """Read a legacy Fernet value; KMS envelopes require principal identity."""
    if not ciphertext or ciphertext.startswith(_KMS_PREFIX):
        raise ValueError(
            "scoped integration secret envelope requires principal identity"
        )
    return _decode(FernetEncrypt.decrypt(ciphertext.decode("utf-8")).encode())


async def encrypt_principal_secrets(
    secrets: Mapping[str, str], *, tenant_id: uuid.UUID, principal_id: uuid.UUID
) -> tuple[bytes, str]:
    plaintext = _normalize(secrets)
    cipher = _cipher()
    envelope = await asyncio.to_thread(
        cipher.encrypt,
        plaintext,
        scope=_scope(tenant_id, principal_id),
    )
    ciphertext = _KMS_PREFIX + envelope
    return ciphertext, hashlib.sha256(ciphertext).hexdigest()


async def decrypt_principal_secrets(
    principal: db_models.IntegrationServicePrincipal,
) -> dict[str, str]:
    return await _read_principal_secrets(principal, persist_rotation=True)


async def verify_principal_secrets(
    principal: db_models.IntegrationServicePrincipal,
) -> dict[str, str]:
    """Authenticate restored ciphertext without mutating the isolated restore."""
    return await _read_principal_secrets(principal, persist_rotation=False)


async def _read_principal_secrets(
    principal: db_models.IntegrationServicePrincipal, *, persist_rotation: bool
) -> dict[str, str]:
    ciphertext = principal.secrets_encrypted
    if not ciphertext:
        raise ValueError("integration secret ciphertext is empty")
    if not hasattr(principal, "tenant_id") or not hasattr(principal, "id"):
        if ciphertext.startswith(_KMS_PREFIX):
            raise ValueError("scoped integration secret is missing principal identity")
        # Compatibility for non-persistent test/dry-run principals. Every DB
        # model has both identifiers and therefore always takes lazy migration.
        return _decode(FernetEncrypt.decrypt(ciphertext.decode("utf-8")).encode())
    scope = _scope(principal.tenant_id, principal.id)
    cipher = _cipher()
    if ciphertext.startswith(_KMS_PREFIX):
        decrypted = await asyncio.to_thread(
            cipher.decrypt,
            ciphertext.removeprefix(_KMS_PREFIX),
            scope=scope,
        )
        if decrypted.rotated and persist_rotation:
            rotated = _KMS_PREFIX + decrypted.envelope
            await _persist_rotation(principal, ciphertext, rotated)
        return _decode(decrypted.plaintext)

    # Backward-compatible one-read migration. Plaintext remains process-local,
    # is immediately placed in a tenant/principal-bound KMS envelope, and is
    # never persisted or logged.
    plaintext = FernetEncrypt.decrypt(ciphertext.decode("utf-8")).encode()
    if persist_rotation:
        envelope = await asyncio.to_thread(cipher.encrypt, plaintext, scope=scope)
        rotated = _KMS_PREFIX + envelope
        await _persist_rotation(principal, ciphertext, rotated)
    return _decode(plaintext)


async def _persist_rotation(
    principal: db_models.IntegrationServicePrincipal,
    previous: bytes,
    rotated: bytes,
) -> None:
    from app.infrastructure.database import AsyncSessionLocal

    fingerprint = hashlib.sha256(rotated).hexdigest()
    async with AsyncSessionLocal() as db:
        await db.execute(
            update(db_models.IntegrationServicePrincipal)
            .where(
                db_models.IntegrationServicePrincipal.id == principal.id,
                db_models.IntegrationServicePrincipal.tenant_id == principal.tenant_id,
                db_models.IntegrationServicePrincipal.secrets_encrypted == previous,
            )
            .values(
                secrets_encrypted=rotated,
                secret_fingerprint=fingerprint,
            )
        )
        await db.commit()
    principal.secrets_encrypted = rotated
    principal.secret_fingerprint = fingerprint
