"""Tests for the local Streamlit policy administrator."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from streamlit.testing.v1 import AppTest

from agent_trust.admin.app import _display_policy_json, _relative_path, _safe_error, parse_tool_rows
from agent_trust.admin.auth import AdminCredentials
from agent_trust.admin.service import (
    AdminPaths,
    append_mcp_server,
    delete_mcp_server,
    load_audit_events,
    load_policy_snapshot,
    policy_manifest,
    update_mcp_server,
    validate_new_server,
)
from agent_trust.cli.admin import main as admin_cli_main
from agent_trust.core.policy import (
    PolicyError,
    ServerRule,
    StdioServerDescriptor,
    SubjectSelector,
    ToolRule,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
    verify_policy,
)


SUBJECTS = SubjectSelector(principals=("local-agent",), groups=("support-managers",))


def tool_rule(name: str = "ticket.get") -> ToolRule:
    return ToolRule(name, {"type": "object"}, SUBJECTS)


class AdminCredentialsTests(unittest.TestCase):
    def test_demo_defaults_and_generic_authentication(self) -> None:
        credentials = AdminCredentials.from_environment({})
        self.assertTrue(credentials.uses_demo_defaults)
        self.assertTrue(credentials.authenticate("admin", "password"))
        self.assertFalse(credentials.authenticate("wrong", "password"))
        self.assertFalse(credentials.authenticate("admin", "wrong"))

    def test_environment_credentials_are_isolated_instances(self) -> None:
        first = AdminCredentials.from_environment(
            {"AGENTTRUST_ADMIN_USERNAME": "alice", "AGENTTRUST_ADMIN_PASSWORD": "first-secret"}
        )
        second = AdminCredentials.from_environment(
            {"AGENTTRUST_ADMIN_USERNAME": "bob", "AGENTTRUST_ADMIN_PASSWORD": "second-secret"}
        )
        self.assertFalse(first.uses_demo_defaults)
        self.assertTrue(first.authenticate("alice", "first-secret"))
        self.assertFalse(second.authenticate("alice", "first-secret"))

    def test_tool_row_parser_validates_schema_subjects_and_duplicates(self) -> None:
        rows = [
            {
                "Effect": "allow",
                "Tool name": "invoice.get",
                "Principals": "agent-1",
                "Groups": "billing, managers",
                "Argument schema": '{"type":"object"}',
            }
        ]
        rules = parse_tool_rows(rows)
        self.assertEqual(rules[0].name, "invoice.get")
        self.assertEqual(rules[0].subjects.groups, ("billing", "managers"))
        with self.assertRaisesRegex(PolicyError, "invalid argument-schema JSON"):
            parse_tool_rows([{**rows[0], "Argument schema": "{"}])
        with self.assertRaisesRegex(PolicyError, "at least one"):
            parse_tool_rows([{**rows[0], "Principals": "", "Groups": ""}])
        with self.assertRaisesRegex(PolicyError, "Add at least one"):
            parse_tool_rows([])

        shared = parse_tool_rows(
            [{key: value for key, value in rows[0].items() if key != "Argument schema"}],
            '{"type":"object","properties":{"id":{"type":"string"}}}',
        )
        self.assertEqual(shared[0].arguments_schema["properties"]["id"]["type"], "string")
        with self.assertRaisesRegex(PolicyError, "schema is invalid JSON"):
            parse_tool_rows(rows, "{")

    def test_admin_cli_forces_loopback_binding(self) -> None:
        with patch("agent_trust.cli.admin.streamlit_cli.main", return_value=0), patch.object(
            sys, "argv", ["agent-trust-admin"]
        ):
            with self.assertRaises(SystemExit) as stopped:
                admin_cli_main()
            self.assertEqual(stopped.exception.code, 0)
            self.assertIn("--server.address=127.0.0.1", sys.argv)

    def test_browser_path_rendering_hides_home_directory(self) -> None:
        project = Path.cwd().resolve()
        command = project / ".venv" / "bin" / "python3"
        self.assertEqual(_relative_path(str(command), project), ".venv/bin/python3")
        displayed = _safe_error(f"Unable to read {command}")
        self.assertNotIn(str(Path.home()), displayed)
        self.assertIn(".venv/bin/python3", displayed)


class AdminPolicyServiceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="agent-trust-admin-")
        self.root = Path(self.temporary.name)
        self.paths = AdminPaths(
            policy=self.root / "config" / "policy.json",
            keyring=self.root / "config" / "keyring.json",
            signing_key=self.root / "config" / "signing-key.pem",
            manifest=self.root / "policy_specs" / "admin_policy.json",
            audit_log=self.root / "config" / "audit.jsonl",
        )
        self.private_key = Ed25519PrivateKey.generate()
        descriptor = StdioServerDescriptor(
            "support-mcp",
            str(Path(sys.executable).absolute()),
            ("-m", "demo_support_mcp.server"),
            str(self.root),
        )
        server = ServerRule(
            descriptor.server_id,
            descriptor,
            fingerprint_server_descriptor(descriptor),
            (tool_rule(),),
        )
        policy = sign_policy(
            private_key=self.private_key,
            policy_id="admin-policy",
            issuer="test-admin",
            key_id="admin-key",
            approved_servers=[server],
            lifetime=timedelta(days=7),
        )
        self.paths.policy.parent.mkdir(parents=True)
        self.paths.policy.write_text(policy.to_json() + "\n", encoding="utf-8")
        self.paths.keyring.write_text(
            json.dumps({"keys": {"admin-key": encode_public_key(self.private_key.public_key())}}),
            encoding="utf-8",
        )
        self.paths.signing_key.write_bytes(
            self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _append(self, **overrides: object):
        snapshot = load_policy_snapshot(self.paths)
        values = {
            "paths": self.paths,
            "expected_signature": snapshot.policy.signature,
            "server_id": "billing-mcp",
            "command": str(Path(sys.executable).absolute()),
            "args": ("-m", "billing.server"),
            "cwd": str(self.root),
            "tools": (tool_rule("invoice.get"),),
        }
        values.update(overrides)
        return append_mcp_server(**values)

    def _update(self, **overrides: object):
        snapshot = load_policy_snapshot(self.paths)
        values = {
            "paths": self.paths,
            "expected_signature": snapshot.policy.signature,
            "server_id": "support-mcp",
            "command": str(Path(sys.executable).absolute()),
            "args": ("-m", "demo_support_mcp.server"),
            "cwd": str(self.root),
            "tools": (tool_rule("ticket.get"), tool_rule("summary.save_draft")),
        }
        values.update(overrides)
        return update_mcp_server(**values)

    def test_loads_verified_policy_and_environment_paths(self) -> None:
        snapshot = load_policy_snapshot(self.paths)
        self.assertEqual(snapshot.policy.policy_id, "admin-policy")
        self.assertEqual(snapshot.validity, timedelta(days=7))
        displayed_policy = _display_policy_json(snapshot.policy, self.root)
        self.assertIn('"signature"', displayed_policy)
        self.assertIn('"approved_servers"', displayed_policy)
        self.assertNotIn(str(Path.home()), displayed_policy)
        self.assertIn('"cwd": "."', displayed_policy)
        environment = {
            "AGENTTRUST_POLICY_PATH": "one.json",
            "AGENTTRUST_KEYRING_PATH": "two.json",
            "AGENTTRUST_SIGNING_KEY_PATH": "three.pem",
            "AGENTTRUST_ADMIN_MANIFEST_PATH": "four.json",
        }
        self.assertEqual(
            AdminPaths.from_environment(environment),
            AdminPaths(
                Path("one.json"),
                Path("two.json"),
                Path("three.pem"),
                Path("four.json"),
                Path("config/audit.jsonl"),
            ),
        )

    def test_loads_latest_audit_events_and_rejects_malformed_jsonl(self) -> None:
        events = [
            {"decided_at": f"2026-09-25T12:00:0{index}Z", "allowed": index % 2 == 0}
            for index in range(3)
        ]
        self.paths.audit_log.write_text(
            "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        self.assertEqual(load_audit_events(self.paths.audit_log, limit=2), tuple(events[-2:]))
        with self.assertRaisesRegex(PolicyError, "limit must be positive"):
            load_audit_events(self.paths.audit_log, limit=0)
        self.paths.audit_log.write_text('{"allowed": true}\nnot-json\n', encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "line 2"):
            load_audit_events(self.paths.audit_log)

    def test_appends_resigns_writes_manifest_and_keeps_backup(self) -> None:
        original = self.paths.policy.read_bytes()
        saved = self._append()
        self.assertEqual([server.server_id for server in saved.policy.approved_servers], ["support-mcp", "billing-mcp"])
        verify_policy(saved.policy, saved.trusted_keys)
        self.assertEqual(
            json.loads(self.paths.manifest.read_text(encoding="utf-8")),
            policy_manifest(saved.policy),
        )
        self.assertEqual(self.paths.policy.with_name("policy.json.bak").read_bytes(), original)
        self.assertEqual(saved.validity, timedelta(days=7))
        self.assertTrue(
            all(
                not Path(server.descriptor.command).is_absolute()
                and not Path(server.descriptor.cwd or "").is_absolute()
                for server in saved.policy.approved_servers
            )
        )

    def test_updates_server_resigns_in_place_with_same_key_and_writes_manifest(self) -> None:
        original = self.paths.policy.read_bytes()
        original_public_key = self.paths.keyring.read_text(encoding="utf-8")
        saved = self._update(args=("-m", "demo_support_mcp.server", "--extra-flag"))
        self.assertEqual([server.server_id for server in saved.policy.approved_servers], ["support-mcp"])
        updated_server = saved.policy.approved_servers[0]
        self.assertEqual(
            [tool.name for tool in updated_server.tools], ["ticket.get", "summary.save_draft"]
        )
        self.assertIn("--extra-flag", updated_server.descriptor.args)
        verify_policy(saved.policy, saved.trusted_keys)
        # Re-signed with the same key: the keyring on disk is untouched.
        self.assertEqual(self.paths.keyring.read_text(encoding="utf-8"), original_public_key)
        self.assertEqual(
            json.loads(self.paths.manifest.read_text(encoding="utf-8")),
            policy_manifest(saved.policy),
        )
        self.assertEqual(self.paths.policy.with_name("policy.json.bak").read_bytes(), original)

    def test_update_rejects_unknown_server_without_writes(self) -> None:
        original = self.paths.policy.read_bytes()
        with self.assertRaisesRegex(PolicyError, "Unknown MCP server ID"):
            self._update(server_id="ghost-mcp")
        self.assertEqual(self.paths.policy.read_bytes(), original)
        self.assertFalse(self.paths.manifest.exists())

    def test_rejects_concurrent_change_and_manifest_divergence(self) -> None:
        snapshot = load_policy_snapshot(self.paths)
        replacement = sign_policy(
            private_key=self.private_key,
            policy_id=snapshot.policy.policy_id,
            issuer=snapshot.policy.issuer,
            key_id=snapshot.policy.key_id,
            approved_servers=snapshot.policy.approved_servers,
            lifetime=snapshot.validity,
        )
        self.paths.policy.write_text(replacement.to_json(), encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "changed after it was loaded"):
            self._append(expected_signature=snapshot.policy.signature)

        self.paths.policy.write_text(snapshot.policy.to_json(), encoding="utf-8")
        self.paths.manifest.parent.mkdir(parents=True)
        self.paths.manifest.write_text('{"format_version": 1}', encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "manifest differs"):
            self._append()

    def test_rejects_missing_or_mismatched_private_key_without_writes(self) -> None:
        original = self.paths.policy.read_bytes()
        self.paths.signing_key.unlink()
        with self.assertRaisesRegex(PolicyError, "signing key"):
            self._append()
        self.assertEqual(self.paths.policy.read_bytes(), original)

        self.paths.signing_key.write_bytes(
            Ed25519PrivateKey.generate().private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        with self.assertRaisesRegex(PolicyError, "does not match"):
            self._append()
        self.assertEqual(self.paths.policy.read_bytes(), original)

    def test_rejects_duplicate_server_but_does_not_validate_local_paths(self) -> None:
        snapshot = load_policy_snapshot(self.paths)
        with self.assertRaisesRegex(PolicyError, "already exists"):
            validate_new_server(
                policy=snapshot.policy,
                server_id="support-mcp",
                command=str(Path(sys.executable).absolute()),
                args=(),
                cwd=str(self.root),
                tools=(tool_rule(),),
            )
        missing_paths = validate_new_server(
            policy=snapshot.policy,
            server_id="new-mcp",
            command="bin/missing-mcp",
            args=(),
            cwd="relative-project",
            tools=(tool_rule(),),
        )
        self.assertEqual(missing_paths.descriptor.command, "bin/missing-mcp")
        self.assertEqual(missing_paths.descriptor.cwd, "relative-project")
        resolved_command = validate_new_server(
            policy=snapshot.policy,
            server_id="path-command-mcp",
            command="sh",
            args=(),
            cwd=str(self.root),
            tools=(tool_rule(),),
        )
        self.assertEqual(resolved_command.descriptor.command, "sh")
        self.assertFalse(Path(resolved_command.descriptor.cwd or "").is_absolute())

        relative_command = self.root / "bin" / "relative-mcp"
        relative_command.parent.mkdir()
        relative_command.write_text("#!/bin/sh\n", encoding="utf-8")
        relative_command.chmod(0o700)
        resolved_relative = validate_new_server(
            policy=snapshot.policy,
            server_id="relative-command-mcp",
            command="bin/relative-mcp",
            args=(),
            cwd=str(self.root),
            tools=(tool_rule(),),
        )
        self.assertEqual(resolved_relative.descriptor.command, "bin/relative-mcp")

        missing_command = validate_new_server(
            policy=snapshot.policy,
            server_id="missing-command-mcp",
            command="command-that-does-not-exist-agenttrust",
            args=(),
            cwd=str(self.root),
            tools=(tool_rule(),),
        )
        self.assertEqual(
            missing_command.descriptor.command,
            "command-that-does-not-exist-agenttrust",
        )
        duplicate = tool_rule("duplicate")
        with self.assertRaisesRegex(PolicyError, "unique"):
            validate_new_server(
                policy=snapshot.policy,
                server_id="new-mcp",
                command=str(Path(sys.executable).absolute()),
                args=(),
                cwd=str(self.root),
                tools=(duplicate, duplicate),
            )

    def test_deletes_server_resigns_policy_and_prevents_empty_policy(self) -> None:
        self._append()
        before_delete = self.paths.policy.read_bytes()
        snapshot = load_policy_snapshot(self.paths)
        with self.assertRaisesRegex(PolicyError, "Unknown MCP server"):
            delete_mcp_server(
                paths=self.paths,
                expected_signature=snapshot.policy.signature,
                server_id="unknown-mcp",
            )
        saved = delete_mcp_server(
            paths=self.paths,
            expected_signature=snapshot.policy.signature,
            server_id="billing-mcp",
        )
        self.assertEqual([server.server_id for server in saved.policy.approved_servers], ["support-mcp"])
        verify_policy(saved.policy, saved.trusted_keys)
        self.assertEqual(
            json.loads(self.paths.manifest.read_text(encoding="utf-8")),
            policy_manifest(saved.policy),
        )
        self.assertEqual(self.paths.policy.with_name("policy.json.bak").read_bytes(), before_delete)
        with self.assertRaisesRegex(PolicyError, "at least one"):
            delete_mcp_server(
                paths=self.paths,
                expected_signature=saved.policy.signature,
                server_id="support-mcp",
            )

    def test_invalid_and_expired_policies_disable_loading(self) -> None:
        value = json.loads(self.paths.policy.read_text(encoding="utf-8"))
        value["issuer"] = "tampered"
        self.paths.policy.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "signature is invalid"):
            load_policy_snapshot(self.paths)

        descriptor = StdioServerDescriptor(
            "expired-mcp", str(Path(sys.executable).absolute()), (), str(self.root)
        )
        expired = sign_policy(
            private_key=self.private_key,
            policy_id="expired",
            issuer="test-admin",
            key_id="admin-key",
            approved_servers=[
                ServerRule(
                    descriptor.server_id,
                    descriptor,
                    fingerprint_server_descriptor(descriptor),
                    (tool_rule(),),
                )
            ],
            lifetime=timedelta(minutes=5),
            now=datetime.now(UTC) - timedelta(hours=1),
        )
        self.paths.policy.write_text(expired.to_json(), encoding="utf-8")
        with self.assertRaisesRegex(PolicyError, "expired"):
            load_policy_snapshot(self.paths)

    def test_policy_replace_failure_restores_policy_and_manifest(self) -> None:
        original_policy = self.paths.policy.read_bytes()
        original_manifest = policy_manifest(load_policy_snapshot(self.paths).policy)
        self.paths.manifest.parent.mkdir(parents=True)
        self.paths.manifest.write_text(json.dumps(original_manifest, indent=2, sort_keys=True) + "\n")
        original_manifest_bytes = self.paths.manifest.read_bytes()
        real_replace = os.replace
        failed = False

        def fail_policy_once(source: object, destination: object) -> None:
            nonlocal failed
            if Path(destination) == self.paths.policy and not failed:
                failed = True
                raise OSError("synthetic replacement failure")
            real_replace(source, destination)

        with patch("agent_trust.admin.service.os.replace", side_effect=fail_policy_once):
            with self.assertRaisesRegex(OSError, "synthetic"):
                self._append()
        self.assertEqual(self.paths.policy.read_bytes(), original_policy)
        self.assertEqual(self.paths.manifest.read_bytes(), original_manifest_bytes)

    def test_streamlit_login_gates_policy_and_logout_clears_session(self) -> None:
        self._append()
        app = Path(__file__).resolve().parents[1] / "agent_trust" / "admin" / "app.py"
        environment = {
            "AGENTTRUST_POLICY_PATH": str(self.paths.policy),
            "AGENTTRUST_KEYRING_PATH": str(self.paths.keyring),
            "AGENTTRUST_SIGNING_KEY_PATH": str(self.paths.signing_key),
            "AGENTTRUST_ADMIN_MANIFEST_PATH": str(self.paths.manifest),
            "AGENTTRUST_ADMIN_USERNAME": "test-admin",
            "AGENTTRUST_ADMIN_PASSWORD": "test-password",
        }
        with patch.dict(os.environ, environment, clear=False):
            application = AppTest.from_file(str(app)).run(timeout=15)
            self.assertFalse(application.exception)
            self.assertFalse(any(title.value == "Signed policy" for title in application.subheader))

            application.text_input[0].set_value("wrong")
            application.text_input[1].set_value("wrong")
            application.button[0].click().run(timeout=15)
            self.assertEqual([error.value for error in application.error], ["Invalid username or password"])

            application.text_input[0].set_value("test-admin")
            application.text_input[1].set_value("test-password")
            application.button[0].click().run(timeout=15)
            self.assertFalse(application.exception)
            self.assertTrue(any(title.value == "Signed policy" for title in application.subheader))
            self.assertTrue(
                any(title.value == "Full policy JSON (read-only)" for title in application.subheader)
            )
            self.assertEqual(
                [tab.label for tab in application.tabs],
                ["Policy and MCP servers", "➕ Add MCP server", "Audit logs"],
            )
            self.assertTrue(any(title.value == "Audit logs" for title in application.subheader))
            self.assertTrue(any(title.value == "Add MCP server" for title in application.subheader))
            self.assertTrue(
                any(area.label == "Tool argument schema (JSON)" for area in application.text_area)
            )
            self.assertEqual(
                sum(button.label == "🗑️" for button in application.button),
                2,
            )
            self.assertFalse(application.json)
            displayed_values = [str(item.value) for item in application.text_input]
            self.assertFalse(any(str(Path.home()) in value for value in displayed_values))
            rendered = " ".join(str(element.value) for element in application.markdown)
            self.assertNotIn("test-password", rendered)

            application.button[0].click().run(timeout=15)
            self.assertEqual([title.value for title in application.title], ["AgentTrust Admin"])
            self.assertTrue(any(button.label == "Sign in" for button in application.button))


if __name__ == "__main__":
    unittest.main()
