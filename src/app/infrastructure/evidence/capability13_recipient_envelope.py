"""Closed recipient-encryption envelope for Capability 13 protected exports.

This module is deliberately independent of API DTOs and object-store locators.
It accepts public keys for encryption; the private-key decoder exists only for
offline recipient verification and qualification fixtures.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from app.pentesting.contracts.canonical import canonical_json_bytes


SUITE: Final = "SCCAP-C13-X25519-HKDF-SHA256-AES256GCM-CHUNKED-V1"
SCHEMA: Final = "sccap.pentest.c13-recipient-envelope.v1"
MAGIC: Final = b"SCC13E1\0"
CHUNK_SIZE: Final = 1024 * 1024
MAX_PLAINTEXT_BYTES: Final = 64 * 1024 * 1024
MAX_HEADER_BYTES: Final = 16 * 1024
_P = 2**255 - 19
_KDF_SALT_DOMAIN = b"sccap:c13:protected-export:kdf-salt:v1\0"
_KDF_INFO = b"sccap:c13:protected-export:key-material:v1"
_HEADER_AAD = b"sccap:c13:protected-export:header:v1\0"
_CHUNK_AAD = b"sccap:c13:protected-export:chunk:v1\0"
_U32 = struct.Struct(">I")
_U64 = struct.Struct(">Q")
IMPLEMENTATION_DIGEST: Final = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()


class C13RecipientEnvelopeError(ValueError):
    """A safe, non-oracular protected-envelope failure."""


@dataclass(frozen=True, slots=True)
class RecipientPublicKey:
    raw: bytes
    der: bytes
    fingerprint: str


@dataclass(frozen=True, slots=True)
class RecipientEnvelopeBinding:
    tenant_id: UUID
    export_id: UUID
    artifact_id: UUID
    report_id: UUID
    report_digest: str
    source_manifest_id: UUID
    source_manifest_digest: str
    recipient_key_id: UUID
    recipient_key_generation: int
    recipient_key_fingerprint: str


@dataclass(frozen=True, slots=True)
class RecipientEnvelopeResult:
    envelope: bytes
    envelope_sha256: str
    header_sha256: str
    plaintext_sha256: str
    plaintext_size: int


def _b64u_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64u_decode(value: str, *, expected_size: int) -> bytes:
    if not isinstance(value, str) or not value or value != value.strip() or "=" in value:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_INVALID")
    try:
        raw = base64.b64decode(
            value + "=" * ((4 - len(value) % 4) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_INVALID") from exc
    if len(raw) != expected_size or _b64u_encode(raw) != value:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_INVALID")
    return raw


def parse_recipient_public_key(encoded: str) -> RecipientPublicKey:
    raw = _b64u_decode(encoded, expected_size=32)
    # RFC 7748 accepts non-canonical aliases during scalar multiplication.
    # Registry identity does not: one mathematical point has one byte string.
    if raw[31] & 0x80 or int.from_bytes(raw, "little") >= _P:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_INVALID")
    try:
        public_key = X25519PublicKey.from_public_bytes(raw)
        shared = X25519PrivateKey.generate().exchange(public_key)
    except ValueError as exc:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_INVALID") from exc
    if shared == b"\0" * 32:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_INVALID")
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return RecipientPublicKey(
        raw=raw,
        der=der,
        fingerprint=f"sha256:{hashlib.sha256(der).hexdigest()}",
    )


def encode_recipient_public_key(public_key: X25519PublicKey) -> str:
    return _b64u_encode(public_key.public_bytes(Encoding.Raw, PublicFormat.Raw))


def _digest(value: str) -> str:
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise C13RecipientEnvelopeError("C13_ENVELOPE_BINDING_INVALID")
    return value


def _header(
    *, binding: RecipientEnvelopeBinding, ephemeral_raw: bytes,
    plaintext_digest: str, plaintext_size: int,
) -> dict[str, object]:
    if not 0 <= plaintext_size <= MAX_PLAINTEXT_BYTES:
        raise C13RecipientEnvelopeError("C13_EXPORT_SIZE_LIMIT")
    if isinstance(binding.recipient_key_generation, bool) or binding.recipient_key_generation < 1:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_BINDING_INVALID")
    if not binding.recipient_key_fingerprint.startswith("sha256:"):
        raise C13RecipientEnvelopeError("C13_ENVELOPE_BINDING_INVALID")
    _digest(binding.recipient_key_fingerprint.removeprefix("sha256:"))
    chunk_count = (plaintext_size + CHUNK_SIZE - 1) // CHUNK_SIZE
    return {
        "schema": SCHEMA,
        "suite": SUITE,
        "tenant_id": str(binding.tenant_id),
        "export_id": str(binding.export_id),
        "artifact_id": str(binding.artifact_id),
        "report_id": str(binding.report_id),
        "report_digest": _digest(binding.report_digest),
        "source_manifest_id": str(binding.source_manifest_id),
        "source_manifest_digest": _digest(binding.source_manifest_digest),
        "recipient_key_id": str(binding.recipient_key_id),
        "recipient_key_generation": binding.recipient_key_generation,
        "recipient_key_fingerprint": binding.recipient_key_fingerprint,
        "ephemeral_public_key": _b64u_encode(ephemeral_raw),
        "plaintext_sha256": _digest(plaintext_digest),
        "plaintext_size": plaintext_size,
        "chunk_size": CHUNK_SIZE,
        "chunk_count": chunk_count,
    }


def _derive(shared: bytes, header_bytes: bytes) -> tuple[bytes, bytes]:
    salt = hashlib.sha256(_KDF_SALT_DOMAIN + header_bytes).digest()
    material = HKDF(
        algorithm=hashes.SHA256(), length=36, salt=salt, info=_KDF_INFO
    ).derive(shared)
    return material[:32], material[32:]


def _chunk_aad(header_digest: bytes, index: int, size: int, final: bool) -> bytes:
    return _CHUNK_AAD + header_digest + _U64.pack(index) + _U32.pack(size) + bytes((int(final),))


def encrypt_recipient_envelope(
    *, plaintext: bytes, recipient_public_key: RecipientPublicKey,
    binding: RecipientEnvelopeBinding,
) -> RecipientEnvelopeResult:
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise C13RecipientEnvelopeError("C13_EXPORT_SIZE_LIMIT")
    if recipient_public_key.fingerprint != binding.recipient_key_fingerprint:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_MISMATCH")
    ephemeral = X25519PrivateKey.generate()
    ephemeral_raw = ephemeral.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    plain_digest = hashlib.sha256(plaintext).hexdigest()
    header_bytes = canonical_json_bytes(_header(
        binding=binding, ephemeral_raw=ephemeral_raw,
        plaintext_digest=plain_digest, plaintext_size=len(plaintext),
    ))
    if len(header_bytes) > MAX_HEADER_BYTES:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_HEADER_LIMIT")
    try:
        recipient = X25519PublicKey.from_public_bytes(recipient_public_key.raw)
        shared = ephemeral.exchange(recipient)
    except ValueError as exc:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_INVALID") from exc
    key, prefix = _derive(shared, header_bytes)
    cipher = AESGCM(key)
    header_digest = hashlib.sha256(header_bytes).digest()
    output = bytearray(MAGIC + _U32.pack(len(header_bytes)) + header_bytes)
    output.extend(cipher.encrypt(prefix + _U64.pack(0), b"", _HEADER_AAD + header_bytes))
    count = int(json.loads(header_bytes)["chunk_count"])
    for offset in range(0, len(plaintext), CHUNK_SIZE):
        index = offset // CHUNK_SIZE + 1
        chunk = plaintext[offset : offset + CHUNK_SIZE]
        output.extend(cipher.encrypt(
            prefix + _U64.pack(index), chunk,
            _chunk_aad(header_digest, index, len(chunk), index == count),
        ))
    envelope = bytes(output)
    return RecipientEnvelopeResult(
        envelope=envelope,
        envelope_sha256=hashlib.sha256(envelope).hexdigest(),
        header_sha256=header_digest.hex(),
        plaintext_sha256=plain_digest,
        plaintext_size=len(plaintext),
    )


def _strict_header(header_bytes: bytes) -> dict[str, object]:
    try:
        value = json.loads(header_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_INVALID") from exc
    required = {
        "schema", "suite", "tenant_id", "export_id", "artifact_id", "report_id",
        "report_digest", "source_manifest_id", "source_manifest_digest",
        "recipient_key_id", "recipient_key_generation", "recipient_key_fingerprint",
        "ephemeral_public_key", "plaintext_sha256", "plaintext_size", "chunk_size",
        "chunk_count",
    }
    if not isinstance(value, dict) or set(value) != required or canonical_json_bytes(value) != header_bytes:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_INVALID")
    if value["schema"] != SCHEMA or value["suite"] != SUITE or value["chunk_size"] != CHUNK_SIZE:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_UNSUPPORTED")
    try:
        for field in ("tenant_id", "export_id", "artifact_id", "report_id", "source_manifest_id", "recipient_key_id"):
            if str(UUID(str(value[field]))) != value[field]:
                raise ValueError
        _digest(str(value["report_digest"]))
        _digest(str(value["source_manifest_digest"]))
        _digest(str(value["plaintext_sha256"]))
        fingerprint = str(value["recipient_key_fingerprint"])
        if not fingerprint.startswith("sha256:"):
            raise ValueError
        _digest(fingerprint[7:])
        ephemeral_key = parse_recipient_public_key(str(value["ephemeral_public_key"]))
        if any(
            type(value[field]) is not int
            for field in (
                "plaintext_size",
                "recipient_key_generation",
                "chunk_count",
            )
        ):
            raise ValueError
        size = value["plaintext_size"]
        generation = value["recipient_key_generation"]
        count = value["chunk_count"]
        if size < 0 or size > MAX_PLAINTEXT_BYTES or generation < 1:
            raise ValueError
        if count != (size + CHUNK_SIZE - 1) // CHUNK_SIZE:
            raise ValueError
    except (TypeError, ValueError, C13RecipientEnvelopeError) as exc:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_INVALID") from exc
    return value


def decrypt_recipient_envelope(
    *, envelope: bytes, recipient_private_key: X25519PrivateKey,
    expected_envelope_sha256: str | None = None,
) -> tuple[bytes, RecipientEnvelopeBinding]:
    if expected_envelope_sha256 is not None and hashlib.sha256(envelope).hexdigest() != _digest(expected_envelope_sha256):
        raise C13RecipientEnvelopeError("C13_ENVELOPE_DIGEST_MISMATCH")
    if len(envelope) < len(MAGIC) + _U32.size + 16 or not envelope.startswith(MAGIC):
        raise C13RecipientEnvelopeError("C13_ENVELOPE_INVALID")
    header_length = _U32.unpack_from(envelope, len(MAGIC))[0]
    if header_length == 0 or header_length > MAX_HEADER_BYTES:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_INVALID")
    position = len(MAGIC) + _U32.size
    end = position + header_length
    if end + 16 > len(envelope):
        raise C13RecipientEnvelopeError("C13_ENVELOPE_INVALID")
    header_bytes = envelope[position:end]
    header = _strict_header(header_bytes)
    private_public = parse_recipient_public_key(encode_recipient_public_key(recipient_private_key.public_key()))
    if private_public.fingerprint != header["recipient_key_fingerprint"]:
        raise C13RecipientEnvelopeError("C13_RECIPIENT_KEY_MISMATCH")
    try:
        ephemeral_key = parse_recipient_public_key(
            str(header["ephemeral_public_key"])
        )
        ephemeral = X25519PublicKey.from_public_bytes(ephemeral_key.raw)
        shared = recipient_private_key.exchange(ephemeral)
        key, prefix = _derive(shared, header_bytes)
        cipher = AESGCM(key)
        cipher.decrypt(prefix + _U64.pack(0), envelope[end : end + 16], _HEADER_AAD + header_bytes)
    except (InvalidTag, ValueError) as exc:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_AUTHENTICATION_FAILED") from exc
    position = end + 16
    size = int(header["plaintext_size"])
    count = int(header["chunk_count"])
    header_digest = hashlib.sha256(header_bytes).digest()
    plaintext = bytearray()
    try:
        for index in range(1, count + 1):
            expected = min(CHUNK_SIZE, size - len(plaintext))
            cipher_size = expected + 16
            if position + cipher_size > len(envelope):
                raise C13RecipientEnvelopeError("C13_ENVELOPE_TRUNCATED")
            plaintext.extend(cipher.decrypt(
                prefix + _U64.pack(index), envelope[position : position + cipher_size],
                _chunk_aad(header_digest, index, expected, index == count),
            ))
            position += cipher_size
    except InvalidTag as exc:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_AUTHENTICATION_FAILED") from exc
    if position != len(envelope) or len(plaintext) != size:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_INVALID")
    result = bytes(plaintext)
    if hashlib.sha256(result).hexdigest() != header["plaintext_sha256"]:
        raise C13RecipientEnvelopeError("C13_ENVELOPE_DIGEST_MISMATCH")
    binding = RecipientEnvelopeBinding(
        tenant_id=UUID(str(header["tenant_id"])), export_id=UUID(str(header["export_id"])),
        artifact_id=UUID(str(header["artifact_id"])), report_id=UUID(str(header["report_id"])),
        report_digest=str(header["report_digest"]),
        source_manifest_id=UUID(str(header["source_manifest_id"])),
        source_manifest_digest=str(header["source_manifest_digest"]),
        recipient_key_id=UUID(str(header["recipient_key_id"])),
        recipient_key_generation=int(header["recipient_key_generation"]),
        recipient_key_fingerprint=str(header["recipient_key_fingerprint"]),
    )
    return result, binding


__all__ = [
    "CHUNK_SIZE", "MAX_PLAINTEXT_BYTES", "SCHEMA", "SUITE",
    "C13RecipientEnvelopeError", "RecipientEnvelopeBinding",
    "RecipientEnvelopeResult", "RecipientPublicKey", "decrypt_recipient_envelope",
    "encode_recipient_public_key", "encrypt_recipient_envelope",
    "parse_recipient_public_key",
]
