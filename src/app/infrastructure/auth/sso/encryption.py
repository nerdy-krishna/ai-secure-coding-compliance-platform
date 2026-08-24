"""Read-only legacy SSO decoder retained for one-read repository migration.

New persistence must use :class:`SsoProviderRepository`, which binds a KMS
envelope to the tenant and provider identifiers. This module cannot create a
new legacy value.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from app.shared.lib.encryption import FernetEncrypt


def encrypt_provider_config(config: Dict[str, Any]) -> bytes:
    """Reject obsolete unscoped persistence; use the async repository API."""
    del config
    raise RuntimeError("SSO configuration must use a scoped repository envelope.")


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
