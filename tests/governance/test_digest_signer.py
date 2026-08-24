from __future__ import annotations

import base64
import hashlib
import unittest

from app.infrastructure.signing import AwsKmsDigestSigner, DigestSignature


class _Kms:
    def describe_key(self, *, KeyId):
        return {
            "KeyMetadata": {"Arn": f"arn:aws:kms:us-east-1:123456789012:key/{KeyId}"}
        }

    def sign(self, **kwargs):
        return {"Signature": b"signature", "KeyId": kwargs["KeyId"]}

    def verify(self, **kwargs):
        return {"SignatureValid": True}


class KmsDigestSignerTests(unittest.IsolatedAsyncioTestCase):
    async def test_verification_rejects_another_accessible_kms_key(self) -> None:
        signer = AwsKmsDigestSigner(
            key_id="approved", region="us-east-1", client=_Kms()
        )
        digest = hashlib.sha256(b"payload").digest()
        valid_bytes = base64.b64encode(b"signature").decode("ascii")
        self.assertFalse(
            await signer.verify_sha256(
                digest,
                DigestSignature(
                    signature_b64=valid_bytes,
                    algorithm="RSASSA_PSS_SHA_256",
                    key_id="arn:aws:kms:us-east-1:123456789012:key/other",
                ),
            )
        )

    async def test_signature_persists_canonical_pinned_key(self) -> None:
        signer = AwsKmsDigestSigner(
            key_id="alias/release", region="us-east-1", client=_Kms()
        )
        signature = await signer.sign_sha256(hashlib.sha256(b"payload").digest())
        self.assertEqual(
            signature.key_id,
            "arn:aws:kms:us-east-1:123456789012:key/alias/release",
        )
