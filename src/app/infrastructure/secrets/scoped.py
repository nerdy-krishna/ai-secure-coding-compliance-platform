"""Versioned KMS envelopes for persisted application-secret fields."""

from __future__ import annotations

import asyncio
import base64
from collections.abc import Mapping
from dataclasses import dataclass

from app.config.config import settings
from app.infrastructure.evidence.crypto import build_key_provider
from app.infrastructure.secrets.envelope import SecretEnvelopeCipher
from app.shared.lib.encryption import FernetEncrypt

PREFIX = "SCCAP-KMS-ENVELOPE-V1:"


@dataclass(frozen=True)
class ScopedSecretRead:
    plaintext: str
    persisted_value: str | None


def _cipher() -> SecretEnvelopeCipher:
    if (
        settings.ENVIRONMENT != "development"
        and settings.EVIDENCE_KEY_PROVIDER != "aws_kms"
    ):
        raise RuntimeError(
            "Non-development application secrets require AWS KMS envelopes."
        )
    return SecretEnvelopeCipher(build_key_provider(settings))


async def encrypt_scoped_secret(plaintext: str, *, scope: Mapping[str, str]) -> str:
    envelope = await asyncio.to_thread(
        _cipher().encrypt, plaintext.encode(), scope=scope
    )
    return PREFIX + base64.b64encode(envelope).decode("ascii")


async def decrypt_scoped_secret(
    persisted_value: str, *, scope: Mapping[str, str]
) -> ScopedSecretRead:
    if persisted_value.startswith(PREFIX):
        envelope = base64.b64decode(persisted_value.removeprefix(PREFIX), validate=True)
        decrypted = await asyncio.to_thread(_cipher().decrypt, envelope, scope=scope)
        return ScopedSecretRead(
            plaintext=decrypted.plaintext.decode(),
            persisted_value=(
                PREFIX + base64.b64encode(decrypted.envelope).decode("ascii")
                if decrypted.rotated
                else None
            ),
        )
    plaintext = FernetEncrypt.decrypt(persisted_value)
    return ScopedSecretRead(
        plaintext=plaintext,
        persisted_value=await encrypt_scoped_secret(plaintext, scope=scope),
    )
