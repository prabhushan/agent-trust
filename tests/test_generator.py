"""Tests for persistent policy and key generation."""

from __future__ import annotations

from datetime import timedelta
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

from agent_trust import PolicyGate, PolicyError, Principal, SignedMcpPolicy, StdioServerDescriptor
from agent_trust.cli.generate import generate_policy_files, load_tool_rules
from agent_trust.mcp.relay import load_keyring
from demo_support_mcp.server import ticket_get


class PolicyGeneratorTests(unittest.TestCase):
    def test_generates_verifiable_policy_keyring_and_private_key(self) -> None:
        root = Path(__file__).resolve().parents[1]
        tools = load_tool_rules(root / "policy_specs" / "support_demo.json")
        descriptor = StdioServerDescriptor(
            "support-mcp",
            str(Path(sys.executable).absolute()),
            ("-m", "demo_support_mcp.server"),
            str(root),
        )
        with tempfile.TemporaryDirectory(prefix="agent-trust-generator-") as temp:
            paths = generate_policy_files(
                output_dir=temp,
                descriptor=descriptor,
                tools=tools,
                policy_id="generated-policy",
                issuer="test-admin",
                key_id="generated-key",
                lifetime=timedelta(days=1),
            )
            policy = SignedMcpPolicy.from_json(paths["policy"].read_text(encoding="utf-8"))
            keyring = load_keyring(paths["keyring"])
            gate = PolicyGate(policy, keyring, descriptor)
            gate.validate_binding()
            self.assertTrue(gate.check("ticket.get", {"ticket_id": "481"}, Principal("local-agent")).allowed)
            self.assertTrue(gate.check("ticket.get", {"ticket_id": "482"}, Principal("local-agent")).allowed)
            denied = gate.check(
                "email.send",
                {"to": "attacker@example.com", "body": "all customer records"},
                Principal("local-agent"),
            )
            self.assertFalse(denied.allowed)
            self.assertEqual(denied.code, "tool_explicitly_denied")
            self.assertEqual(os.stat(paths["private_key"]).st_mode & 0o777, 0o600)
            self.assertEqual(set(json.loads(paths["keyring"].read_text())["keys"]), {"generated-key"})

    def test_demo_tickets_separate_benign_and_malicious_content(self) -> None:
        benign = ticket_get("481")
        malicious = ticket_get("482")
        self.assertNotIn("Ignore previous instructions", benign["body"])
        self.assertIn("Ignore previous instructions", malicious["body"])
        self.assertIn("email.send", malicious["body"])

    def test_refuses_to_overwrite_generated_material(self) -> None:
        root = Path(__file__).resolve().parents[1]
        tools = load_tool_rules(root / "policy_specs" / "support_demo.json")
        descriptor = StdioServerDescriptor(
            "support-mcp", str(Path(sys.executable).absolute()), (), str(root)
        )
        with tempfile.TemporaryDirectory(prefix="agent-trust-generator-") as temp:
            kwargs = {
                "output_dir": temp,
                "descriptor": descriptor,
                "tools": tools,
                "policy_id": "generated-policy",
                "issuer": "test-admin",
                "key_id": "generated-key",
                "lifetime": timedelta(days=1),
            }
            generate_policy_files(**kwargs)
            with self.assertRaisesRegex(PolicyError, "Refusing to overwrite"):
                generate_policy_files(**kwargs)


if __name__ == "__main__":
    unittest.main()
