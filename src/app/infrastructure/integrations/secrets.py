"""Fernet-encrypted JSON storage for tenant integration secrets."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any

from app.shared.lib.encryption import FernetEncrypt


def encrypt_integration_secrets(secrets: Mapping[str, str]) -> tuple[bytes, str]:
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
    serialized = json.dumps(normalized, sort_keys=True, separators=(",", ":"))
    ciphertext = FernetEncrypt.encrypt(serialized).encode("utf-8")
    return ciphertext, hashlib.sha256(ciphertext).hexdigest()


def decrypt_integration_secrets(ciphertext: bytes) -> dict[str, str]:
    if not ciphertext:
        raise ValueError("integration secret ciphertext is empty")
    plaintext = FernetEncrypt.decrypt(ciphertext.decode("utf-8"))
    value: Any = json.loads(plaintext)
    if not isinstance(value, dict) or not value:
        raise ValueError("integration secret envelope is invalid")
    secrets = {str(key): str(item) for key, item in value.items()}
    if any(not key or not item for key, item in secrets.items()):
        raise ValueError("integration secret envelope contains empty values")
    return secrets
