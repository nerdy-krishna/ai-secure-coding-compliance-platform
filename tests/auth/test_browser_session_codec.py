"""Pure contracts for the MAC-authenticated browser-session credential."""

from __future__ import annotations

import unittest
import uuid

from app.infrastructure.auth.session import (
    InvalidSessionCredential,
    decode_session_credential,
    encode_session_credential,
)


class BrowserSessionCodecTests(unittest.TestCase):
    def test_round_trip_preserves_locator_generation_and_secret(self) -> None:
        session_id = uuid.uuid4()
        token = encode_session_credential(session_id, 7, "s" * 43)

        claims = decode_session_credential(token)

        self.assertEqual(claims.session_id, session_id)
        self.assertEqual(claims.generation, 7)
        self.assertEqual(claims.secret, "s" * 43)

    def test_tampering_fails_before_session_lookup(self) -> None:
        token = encode_session_credential(uuid.uuid4(), 0, "s" * 43)
        parts = token.split(".")
        parts[1] = uuid.uuid4().hex

        with self.assertRaises(InvalidSessionCredential):
            decode_session_credential(".".join(parts))

    def test_wrong_shape_and_negative_generation_are_rejected(self) -> None:
        with self.assertRaises(InvalidSessionCredential):
            decode_session_credential("not-a-session")
        token = encode_session_credential(uuid.uuid4(), -1, "s" * 43)
        with self.assertRaises(InvalidSessionCredential):
            decode_session_credential(token)


if __name__ == "__main__":
    unittest.main()
