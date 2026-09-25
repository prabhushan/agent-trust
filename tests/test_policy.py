"""Unit tests for signed MCP policy construction and verification."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_trust.core.policy import (
    PolicyError,
    ServerRule,
    SignedMcpPolicy,
    StdioServerDescriptor,
    SubjectSelector,
    ToolRule,
    decode_public_key,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
    verify_policy,
)


NOW = datetime(2026, 9, 24, 12, tzinfo=UTC)
SUBJECTS = SubjectSelector(principals=("agent-1",), groups=("support-agents",))


def descriptor(server_id: str = "support-mcp", args: tuple[str, ...] = ()) -> StdioServerDescriptor:
    return StdioServerDescriptor(
        server_id=server_id,
        command=str(Path(sys.executable).absolute()),
        args=args,
        cwd=str(Path.cwd().resolve()),
    )


def rule(server: StdioServerDescriptor | None = None, tool_name: str = "ticket.get") -> ServerRule:
    server = server or descriptor()
    return ServerRule(
        server_id=server.server_id,
        descriptor_sha256=fingerprint_server_descriptor(server),
        tools=(
            ToolRule(
                tool_name,
                {
                    "type": "object",
                    "properties": {"ticket_id": {"const": "481"}},
                    "required": ["ticket_id"],
                    "additionalProperties": False,
                },
                SUBJECTS,
            ),
        ),
    )


def signed_policy(
    private_key: Ed25519PrivateKey,
    *,
    servers: list[ServerRule] | None = None,
    lifetime: timedelta = timedelta(hours=1),
) -> SignedMcpPolicy:
    return sign_policy(
        private_key=private_key,
        policy_id="policy-1",
        issuer="test-admin",
        key_id="test-key",
        approved_servers=servers or [rule()],
        lifetime=lifetime,
        now=NOW,
    )


class SignedPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.keyring = {"test-key": self.private_key.public_key()}

    def test_sign_serialize_parse_and_verify(self) -> None:
        policy = signed_policy(self.private_key)
        parsed = SignedMcpPolicy.from_json(policy.to_json())
        verify_policy(parsed, self.keyring, now=NOW)
        self.assertEqual(parsed.to_dict(), policy.to_dict())

    def test_canonical_signing_ignores_schema_key_order(self) -> None:
        first = ToolRule("x", {"type": "object", "required": [], "properties": {}}, SUBJECTS)
        second = ToolRule("x", {"properties": {}, "required": [], "type": "object"}, SUBJECTS)
        server = descriptor()
        first_policy = signed_policy(
            self.private_key,
            servers=[ServerRule(server.server_id, fingerprint_server_descriptor(server), (first,))],
        )
        second_policy = signed_policy(
            self.private_key,
            servers=[ServerRule(server.server_id, fingerprint_server_descriptor(server), (second,))],
        )
        self.assertEqual(first_policy.signature, second_policy.signature)

    def test_detects_tampering_and_wrong_key(self) -> None:
        policy = signed_policy(self.private_key)
        object.__setattr__(policy, "issuer", "attacker")
        with self.assertRaisesRegex(PolicyError, "signature is invalid"):
            verify_policy(policy, self.keyring, now=NOW)

        untampered = signed_policy(self.private_key)
        with self.assertRaisesRegex(PolicyError, "signature is invalid"):
            verify_policy(untampered, {"test-key": Ed25519PrivateKey.generate().public_key()}, now=NOW)

    def test_rejects_unknown_key_expiry_and_future_policy(self) -> None:
        policy = signed_policy(self.private_key)
        with self.assertRaisesRegex(PolicyError, "Unknown policy signing key"):
            verify_policy(policy, {}, now=NOW)
        with self.assertRaisesRegex(PolicyError, "expired"):
            verify_policy(policy, self.keyring, now=NOW + timedelta(hours=1))
        with self.assertRaisesRegex(PolicyError, "not yet valid"):
            verify_policy(policy, self.keyring, now=NOW - timedelta(seconds=1))

    def test_requires_positive_lifetime(self) -> None:
        with self.assertRaisesRegex(PolicyError, "positive"):
            signed_policy(self.private_key, lifetime=timedelta(0))

    def test_rejects_empty_and_duplicate_rules(self) -> None:
        server = descriptor()
        digest = fingerprint_server_descriptor(server)
        with self.assertRaisesRegex(PolicyError, "at least one tool"):
            ServerRule(server.server_id, digest, ())
        duplicate_tool = ToolRule("ticket.get", {"type": "object"}, SUBJECTS)
        with self.assertRaisesRegex(PolicyError, "unique"):
            ServerRule(server.server_id, digest, (duplicate_tool, duplicate_tool))
        duplicate_server = rule(server)
        with self.assertRaisesRegex(PolicyError, "server IDs must be unique"):
            signed_policy(self.private_key, servers=[duplicate_server, duplicate_server])

    def test_strict_parser_rejects_unknown_fields_and_versions(self) -> None:
        value = signed_policy(self.private_key).to_dict()
        value["unexpected"] = True
        with self.assertRaisesRegex(PolicyError, "unknown"):
            SignedMcpPolicy.from_dict(value)
        value.pop("unexpected")
        value["version"] = 99
        with self.assertRaisesRegex(PolicyError, "Unsupported policy version"):
            SignedMcpPolicy.from_dict(value)
        value["version"] = True
        with self.assertRaisesRegex(PolicyError, "Unsupported policy version"):
            SignedMcpPolicy.from_dict(value)

    def test_rejects_non_json_schema_values(self) -> None:
        with self.assertRaisesRegex(PolicyError, "keys.*strings"):
            ToolRule("x", {1: "not a JSON object key"}, SUBJECTS)
        with self.assertRaisesRegex(PolicyError, "NaN"):
            ToolRule("x", {"const": float("nan")}, SUBJECTS)

    def test_rejects_empty_subjects_and_invalid_effect(self) -> None:
        with self.assertRaisesRegex(PolicyError, "at least one"):
            SubjectSelector()
        with self.assertRaisesRegex(PolicyError, "effect"):
            ToolRule("x", {"type": "object"}, SUBJECTS, effect="audit")

    def test_descriptor_fingerprint_is_deterministic_and_sensitive(self) -> None:
        first = descriptor(args=("-m", "one"))
        same = descriptor(args=("-m", "one"))
        different = descriptor(args=("-m", "two"))
        self.assertEqual(fingerprint_server_descriptor(first), fingerprint_server_descriptor(same))
        self.assertNotEqual(fingerprint_server_descriptor(first), fingerprint_server_descriptor(different))

    def test_descriptor_requires_absolute_paths(self) -> None:
        with self.assertRaisesRegex(PolicyError, "absolute"):
            StdioServerDescriptor("x", "python", (), None)
        with self.assertRaisesRegex(PolicyError, "absolute"):
            StdioServerDescriptor("x", str(Path(sys.executable).absolute()), (), "relative")

    def test_public_key_round_trip(self) -> None:
        encoded = encode_public_key(self.private_key.public_key())
        decoded = decode_public_key(encoded)
        policy = signed_policy(self.private_key)
        verify_policy(policy, {"test-key": decoded}, now=NOW)


if __name__ == "__main__":
    unittest.main()
