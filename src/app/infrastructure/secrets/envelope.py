"""Versioned, portable envelope encryption for persisted application secrets."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.infrastructure.evidence.crypto import KeyProvider


class SecretEnvelopeIntegrityError(RuntimeError):
    """The envelope or its authenticated scope was altered."""


@dataclass(frozen=True)
class DecryptedSecret:
    plaintext: bytes
    envelope: bytes
    rotated: bool


def _canonical_scope(scope: Mapping[str, Any]) -> bytes:
    return json.dumps(
        dict(scope), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class SecretEnvelopeCipher:
    """Encrypt secrets with per-value DEKs and lazily rotate their wrapped keys.

    The serialized envelope contains ciphertext and key metadata only. The
    caller supplies stable tenant/resource fields as authenticated scope, so a
    valid envelope cannot be transplanted to another tenant or secret slot.
    """

    VERSION = 1

    def __init__(self, key_provider: KeyProvider) -> None:
        self.key_provider = key_provider

    def encrypt(self, plaintext: bytes, *, scope: Mapping[str, Any]) -> bytes:
        data_key = self.key_provider.generate_data_key()
        aad = _canonical_scope(scope)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key.plaintext).encrypt(nonce, plaintext, aad)
        body = {
            "version": self.VERSION,
            "algorithm": "AES-256-GCM",
            "provider": data_key.provider,
            "key_id": data_key.key_id,
            "wrapped_data_key": base64.b64encode(data_key.wrapped).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "aad_sha256": hashlib.sha256(aad).hexdigest(),
        }
        return json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")

    def decrypt(self, envelope: bytes, *, scope: Mapping[str, Any]) -> DecryptedSecret:
        try:
            body = json.loads(envelope)
            if body["version"] != self.VERSION or body["algorithm"] != "AES-256-GCM":
                raise ValueError("Unsupported secret envelope version.")
            aad = _canonical_scope(scope)
            if not hashlib.sha256(aad).hexdigest() == body["aad_sha256"]:
                raise SecretEnvelopeIntegrityError("Secret scope digest mismatch.")
            wrapped = base64.b64decode(body["wrapped_data_key"], validate=True)
            nonce = base64.b64decode(body["nonce"], validate=True)
            ciphertext = base64.b64decode(body["ciphertext"], validate=True)
            data_key = self.key_provider.unwrap_data_key(wrapped, body["key_id"])
            plaintext = AESGCM(data_key).decrypt(nonce, ciphertext, aad)
        except SecretEnvelopeIntegrityError:
            raise
        except (
            InvalidTag,
            KeyError,
            TypeError,
            ValueError,
            json.JSONDecodeError,
        ) as exc:
            raise SecretEnvelopeIntegrityError(
                "Secret envelope verification failed."
            ) from exc

        if not self.key_provider.needs_rotation(body["key_id"]):
            return DecryptedSecret(
                plaintext=plaintext, envelope=envelope, rotated=False
            )
        rotated = self.key_provider.rewrap_data_key(wrapped, body["key_id"])
        body["provider"] = rotated.provider
        body["key_id"] = rotated.key_id
        body["wrapped_data_key"] = base64.b64encode(rotated.wrapped).decode("ascii")
        rotated_envelope = json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
        return DecryptedSecret(
            plaintext=plaintext,
            envelope=rotated_envelope,
            rotated=True,
        )
