"""Unit tests for deterministic policy enforcement."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sys
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_trust import (
    PolicyGate,
    Principal,
    ServerRule,
    StdioServerDescriptor,
    SubjectSelector,
    ToolRule,
    fingerprint_server_descriptor,
    sign_policy,
)


NOW = datetime(2026, 9, 24, 12, tzinfo=UTC)
PRINCIPAL = Principal("agent-1", ("support-agents",))
SUBJECTS = SubjectSelector(principals=("agent-1",), groups=("support-agents",))


def make_descriptor(server_id: str = "support-mcp", args: tuple[str, ...] = ()) -> StdioServerDescriptor:
    return StdioServerDescriptor(
        server_id,
        str(Path(sys.executable).absolute()),
        args,
        str(Path.cwd().resolve()),
    )


def make_gate(
    *,
    bound_descriptor: StdioServerDescriptor | None = None,
    approved_descriptors: tuple[StdioServerDescriptor, ...] | None = None,
) -> PolicyGate:
    bound = bound_descriptor or make_descriptor()
    approved = approved_descriptors or (make_descriptor(),)
    private_key = Ed25519PrivateKey.generate()
    servers = []
    for descriptor in approved:
        servers.append(
            ServerRule(
                descriptor.server_id,
                fingerprint_server_descriptor(descriptor),
                (
                    ToolRule(
                        "ticket.get",
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
        )
    policy = sign_policy(
        private_key=private_key,
        policy_id="gate-policy",
        issuer="test-admin",
        key_id="key-1",
        approved_servers=servers,
        lifetime=timedelta(hours=1),
        now=NOW,
    )
    return PolicyGate(policy, {"key-1": private_key.public_key()}, bound)


class PolicyGateTests(unittest.TestCase):
    def test_allows_valid_call_and_records_complete_decision(self) -> None:
        gate = make_gate()
        decision = gate.check("ticket.get", {"ticket_id": "481"}, PRINCIPAL, now=NOW)
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.code, "allowed")
        self.assertEqual(decision.policy_id, "gate-policy")
        self.assertEqual(decision.server_id, "support-mcp")
        self.assertEqual(decision.principal_id, "agent-1")
        self.assertEqual(decision.arguments["ticket_id"], "481")
        self.assertIn("arguments_schema", decision.matched_rule or "")
        self.assertEqual(gate.audit_log, [decision])

    def test_blocks_unauthorized_tool(self) -> None:
        decision = make_gate().check("email.send", {"to": "attacker@example.com"}, PRINCIPAL, now=NOW)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.code, "tool_not_authorized")

    def test_blocks_wrong_and_additional_arguments(self) -> None:
        gate = make_gate()
        wrong = gate.check("ticket.get", {"ticket_id": "482"}, PRINCIPAL, now=NOW)
        extra = gate.check("ticket.get", {"ticket_id": "481", "export": True}, PRINCIPAL, now=NOW)
        self.assertEqual(wrong.code, "argument_scope_violation")
        self.assertEqual(extra.code, "argument_scope_violation")
        self.assertIn("unapproved fields", extra.reason)

    def test_blocks_unapproved_server(self) -> None:
        gate = make_gate(bound_descriptor=make_descriptor("other-mcp"))
        decision = gate.check("ticket.get", {"ticket_id": "481"}, PRINCIPAL, now=NOW)
        self.assertEqual(decision.code, "server_not_authorized")

    def test_blocks_descriptor_mismatch(self) -> None:
        gate = make_gate(bound_descriptor=make_descriptor(args=("changed",)))
        decision = gate.check("ticket.get", {"ticket_id": "481"}, PRINCIPAL, now=NOW)
        self.assertEqual(decision.code, "server_fingerprint_mismatch")

    def test_expired_policy_fails_closed(self) -> None:
        decision = make_gate().check("ticket.get", {"ticket_id": "481"}, PRINCIPAL, now=NOW + timedelta(hours=1))
        self.assertEqual(decision.code, "invalid_policy")

    def test_same_tool_name_is_scoped_to_bound_server(self) -> None:
        support = make_descriptor("support-mcp")
        billing = make_descriptor("billing-mcp", args=("billing",))
        private_key = Ed25519PrivateKey.generate()

        def scoped_rule(server: StdioServerDescriptor, ticket_id: str) -> ServerRule:
            return ServerRule(
                server.server_id,
                fingerprint_server_descriptor(server),
                (
                    ToolRule(
                        "ticket.get",
                        {
                            "type": "object",
                            "properties": {"ticket_id": {"const": ticket_id}},
                            "required": ["ticket_id"],
                            "additionalProperties": False,
                        },
                        SUBJECTS,
                    ),
                ),
            )

        policy = sign_policy(
            private_key=private_key,
            policy_id="multi-server",
            issuer="test-admin",
            key_id="key-1",
            approved_servers=[scoped_rule(support, "481"), scoped_rule(billing, "900")],
            lifetime=timedelta(hours=1),
            now=NOW,
        )
        gate = PolicyGate(policy, {"key-1": private_key.public_key()}, billing)
        wrong_server_rule = gate.check("ticket.get", {"ticket_id": "481"}, PRINCIPAL, now=NOW)
        billing_rule = gate.check("ticket.get", {"ticket_id": "900"}, PRINCIPAL, now=NOW)
        self.assertEqual(wrong_server_rule.code, "argument_scope_violation")
        self.assertTrue(billing_rule.allowed)
        self.assertEqual(billing_rule.server_id, "billing-mcp")

    def test_blocked_calls_do_not_change_later_results(self) -> None:
        gate = make_gate()
        gate.check("email.send", {}, PRINCIPAL, now=NOW)
        gate.check("ticket.get", {"ticket_id": "482"}, PRINCIPAL, now=NOW)
        allowed = gate.check("ticket.get", {"ticket_id": "481"}, PRINCIPAL, now=NOW)
        self.assertTrue(allowed.allowed)

    def test_subject_rules_and_explicit_deny_precedence(self) -> None:
        descriptor = make_descriptor()
        private_key = Ed25519PrivateKey.generate()
        manager = SubjectSelector(groups=("support-managers",))
        suspended = SubjectSelector(groups=("suspended-agents",))
        rules = (
            ToolRule("ticket.get", {"type": "object"}, manager),
            ToolRule("ticket.get", {}, suspended, effect="deny"),
        )
        policy = sign_policy(
            private_key=private_key,
            policy_id="subject-policy",
            issuer="test-admin",
            key_id="key-1",
            approved_servers=[ServerRule(descriptor.server_id, fingerprint_server_descriptor(descriptor), rules)],
            lifetime=timedelta(hours=1),
            now=NOW,
        )
        gate = PolicyGate(policy, {"key-1": private_key.public_key()}, descriptor)
        manager_only = gate.check("ticket.get", {}, Principal("manager", ("support-managers",)), now=NOW)
        both = gate.check(
            "ticket.get", {}, Principal("suspended-manager", ("support-managers", "suspended-agents")), now=NOW
        )
        unrelated = gate.check("ticket.get", {}, Principal("outsider", ("engineering",)), now=NOW)
        self.assertTrue(manager_only.allowed)
        self.assertEqual(both.code, "tool_explicitly_denied")
        self.assertEqual(unrelated.code, "tool_not_authorized")


if __name__ == "__main__":
    unittest.main()
