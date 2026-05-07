"""Fernet helpers for ``sso_providers.config_encrypted``.

Wraps the existing ``app.shared.lib.encryption.FernetEncrypt`` (same key
as LLM API keys + SMTP passwords) and adds JSON envelope serialization.

We store ``bytes`` in Postgres (BYTEA / LargeBinary) but FernetEncrypt
returns ``str`` — encrypt() returns the URL-safe-base64 token; decrypt()
takes the same. We round-trip via UTF-8 for the BYTEA storage layer.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from app.shared.lib.encryption import FernetEncrypt


def encrypt_provider_config(config: Dict[str, Any]) -> bytes:
    """Serialize ``config`` to JSON and Fernet-encrypt; return BYTEA-shaped bytes."""
    serialized = json.dumps(config, ensure_ascii=False, separators=(",", ":"))
    token_str = FernetEncrypt.encrypt(serialized)
    return token_str.encode("utf-8")


def decrypt_provider_config(token_bytes: bytes) -> Dict[str, Any]:
    """Decrypt and parse the JSON envelope. Raises if the token is invalid
    or the plaintext is not a JSON object."""
    if not token_bytes:
        raise ValueError("decrypt_provider_config: empty ciphertext")
    token_str = token_bytes.decode("utf-8")
    plaintext = FernetEncrypt.decrypt(token_str)
    obj = json.loads(plaintext)
    if not isinstance(obj, dict):
        raise ValueError("decrypt_provider_config: payload is not a JSON object")
    return obj
