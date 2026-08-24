"""Offline digest verification and deployment-ledger signing primitives."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa, utils

from app.infrastructure.signing.digest_signer import DigestSignature

MAX_KEY_BYTES = 64 * 1024
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def _read_key(path: Path, *, private: bool = False) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ValueError("Signing key file cannot be opened safely.") from exc
    try:
        key_stat = os.fstat(descriptor)
        if not stat.S_ISREG(key_stat.st_mode) or key_stat.st_size > MAX_KEY_BYTES:
            raise ValueError("Signing key file exceeds the accepted size limit.")
        if private and (
            key_stat.st_uid != os.geteuid() or stat.S_IMODE(key_stat.st_mode) & 0o077
        ):
            raise ValueError(
                "Deployment private key must be owner-only and owned by this process."
            )
        chunks: list[bytes] = []
        size = 0
        while chunk := os.read(descriptor, min(16 * 1024, MAX_KEY_BYTES + 1 - size)):
            size += len(chunk)
            if size > MAX_KEY_BYTES:
                raise ValueError("Signing key file exceeds the accepted size limit.")
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _public_key_fingerprint(public_key: object) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


class PinnedRsaPublicKeyDigestVerifier:
    """Verify AWS KMS RSA-PSS signatures without a network or KMS dependency."""

    algorithm = "RSASSA_PSS_SHA_256"

    def __init__(
        self,
        *,
        public_key_path: Path,
        public_key_sha256: str,
        expected_key_id: str,
    ) -> None:
        if not _HEX_64.fullmatch(public_key_sha256):
            raise ValueError("A lowercase SHA-256 public-key fingerprint is required.")
        if not expected_key_id.startswith("arn:"):
            raise ValueError("The expected signing key must be a canonical KMS ARN.")
        public_key = serialization.load_pem_public_key(_read_key(public_key_path))
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Offline bundle verification requires an RSA public key.")
        if _public_key_fingerprint(public_key) != public_key_sha256:
            raise ValueError("Offline bundle verification key fingerprint mismatch.")
        self.public_key = public_key
        self.key_id = expected_key_id

    async def sign_sha256(self, digest: bytes) -> DigestSignature:
        raise RuntimeError("The pinned public verifier cannot sign content.")

    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool:
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("Expected a SHA-256 digest.")
        if signature.algorithm != self.algorithm or signature.key_id != self.key_id:
            return False
        try:
            encoded = base64.b64decode(signature.signature_b64, validate=True)
            self.public_key.verify(
                encoded,
                digest,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256.digest_size,
                ),
                utils.Prehashed(hashes.SHA256()),
            )
        except (InvalidSignature, ValueError):
            return False
        return True


class Ed25519FileDigestSigner:
    """Operator-controlled local signer for the restricted deployment ledger."""

    algorithm = "ED25519-SHA256-DIGEST"

    def __init__(self, *, private_key_path: Path, public_key_sha256: str) -> None:
        if not _HEX_64.fullmatch(public_key_sha256):
            raise ValueError(
                "A lowercase SHA-256 deployment-key fingerprint is required."
            )
        private_key = serialization.load_pem_private_key(
            _read_key(private_key_path, private=True), password=None
        )
        if not isinstance(private_key, ed25519.Ed25519PrivateKey):
            raise ValueError(
                "Deployment ledger signing requires an Ed25519 private key."
            )
        public_key = private_key.public_key()
        if _public_key_fingerprint(public_key) != public_key_sha256:
            raise ValueError("Deployment signing key fingerprint mismatch.")
        self.private_key = private_key
        self.public_key = public_key
        self.key_id = f"sha256:{public_key_sha256}"

    async def sign_sha256(self, digest: bytes) -> DigestSignature:
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("Expected a SHA-256 digest.")
        return DigestSignature(
            signature_b64=base64.b64encode(self.private_key.sign(digest)).decode(
                "ascii"
            ),
            algorithm=self.algorithm,
            key_id=self.key_id,
        )

    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool:
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("Expected a SHA-256 digest.")
        if signature.algorithm != self.algorithm or signature.key_id != self.key_id:
            return False
        try:
            self.public_key.verify(
                base64.b64decode(signature.signature_b64, validate=True), digest
            )
        except (InvalidSignature, ValueError):
            return False
        return True


class PinnedEd25519PublicKeyDigestVerifier:
    """Verify the local deployment ledger from a pinned public trust root."""

    algorithm = "ED25519-SHA256-DIGEST"

    def __init__(self, *, public_key_path: Path, public_key_sha256: str) -> None:
        if not _HEX_64.fullmatch(public_key_sha256):
            raise ValueError(
                "A lowercase SHA-256 deployment-key fingerprint is required."
            )
        public_key = serialization.load_pem_public_key(_read_key(public_key_path))
        if not isinstance(public_key, ed25519.Ed25519PublicKey):
            raise ValueError(
                "Deployment ledger verification requires an Ed25519 public key."
            )
        if _public_key_fingerprint(public_key) != public_key_sha256:
            raise ValueError("Deployment verification key fingerprint mismatch.")
        self.public_key = public_key
        self.key_id = f"sha256:{public_key_sha256}"

    async def sign_sha256(self, digest: bytes) -> DigestSignature:
        raise RuntimeError("The pinned deployment public verifier cannot sign content.")

    async def verify_sha256(self, digest: bytes, signature: DigestSignature) -> bool:
        if len(digest) != hashlib.sha256().digest_size:
            raise ValueError("Expected a SHA-256 digest.")
        if signature.algorithm != self.algorithm or signature.key_id != self.key_id:
            return False
        try:
            self.public_key.verify(
                base64.b64decode(signature.signature_b64, validate=True), digest
            )
        except (InvalidSignature, ValueError):
            return False
        return True
