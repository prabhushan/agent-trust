"""Tests for the development-only local JWT verifier."""

from __future__ import annotations

import asyncio
import time
import unittest

from agent_trust.core.policy import PolicyError
from agent_trust.gateway.local_jwt import LocalJwtVerifier, mint_local_jwt


SECRET = b"agenttrust-test-secret-must-be-at-least-32-bytes"


class LocalJwtVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.verifier = LocalJwtVerifier(SECRET, issuer="local-test", audience="http://localhost:8000/mcp")

    def claims(self) -> dict[str, object]:
        return {
            "iss": "local-test",
            "aud": "http://localhost:8000/mcp",
            "exp": int(time.time()) + 60,
            "name": "alice",
            "groups": ["support-managers"],
        }

    def test_valid_token_becomes_access_token(self) -> None:
        token = mint_local_jwt(SECRET, self.claims())
        access = asyncio.run(self.verifier.verify_token(token))
        self.assertIsNotNone(access)
        assert access is not None
        self.assertEqual(access.subject, "alice")
        self.assertEqual(access.claims["groups"], ["support-managers"])

    def test_rejects_bad_signature_expiry_audience_and_groups(self) -> None:
        invalid = []
        invalid.append(mint_local_jwt(b"another-secret-that-is-definitely-long-enough", self.claims()))
        expired = self.claims() | {"exp": int(time.time()) - 1}
        invalid.append(mint_local_jwt(SECRET, expired))
        wrong_audience = self.claims() | {"aud": "https://other.example/mcp"}
        invalid.append(mint_local_jwt(SECRET, wrong_audience))
        wrong_groups = self.claims() | {"groups": "support-managers"}
        invalid.append(mint_local_jwt(SECRET, wrong_groups))
        for token in invalid:
            with self.subTest(token=token[-12:]):
                self.assertIsNone(asyncio.run(self.verifier.verify_token(token)))

    def test_requires_strong_local_secret(self) -> None:
        with self.assertRaisesRegex(PolicyError, "at least 32"):
            LocalJwtVerifier(b"too-short", issuer="local-test", audience="http://localhost/mcp")


if __name__ == "__main__":
    unittest.main()
