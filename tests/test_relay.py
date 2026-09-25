"""End-to-end tests for the stdio MCP enforcement relay."""

from __future__ import annotations

import asyncio
from datetime import timedelta
import json
from pathlib import Path
import socket
import sys
import tempfile
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client

from agent_trust import (
    ServerRule,
    StdioServerDescriptor,
    ToolRule,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
)


class RelayIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_filters_blocks_forwards_audits_and_reuses_policy(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        python = str(Path(sys.executable).absolute())
        with tempfile.TemporaryDirectory(prefix="agent-trust-test-") as temp:
            temp_dir = Path(temp)
            trace_path = temp_dir / "upstream.jsonl"
            audit_path = temp_dir / "audit.jsonl"
            upstream = StdioServerDescriptor(
                "support-mcp",
                python,
                ("-m", "demo_support_mcp.server", "--trace-file", str(trace_path)),
                str(project_root),
            )
            private_key = Ed25519PrivateKey.generate()
            rules = (
                ToolRule(
                    "ticket.get",
                    {
                        "type": "object",
                        "properties": {"ticket_id": {"const": "481"}},
                        "required": ["ticket_id"],
                        "additionalProperties": False,
                    },
                ),
                ToolRule(
                    "summary.save_draft",
                    {
                        "type": "object",
                        "properties": {
                            "destination": {"const": "support-manager-drafts"},
                            "summary": {"type": "string"},
                        },
                        "required": ["destination", "summary"],
                        "additionalProperties": False,
                    },
                ),
            )
            policy = sign_policy(
                private_key=private_key,
                policy_id="integration-policy",
                issuer="test-admin",
                key_id="integration-key",
                approved_servers=[
                    ServerRule("support-mcp", fingerprint_server_descriptor(upstream), rules)
                ],
                lifetime=timedelta(minutes=10),
            )
            policy_path = temp_dir / "policy.json"
            keyring_path = temp_dir / "keyring.json"
            policy_path.write_text(policy.to_json(), encoding="utf-8")
            keyring_path.write_text(
                json.dumps({"keys": {"integration-key": encode_public_key(private_key.public_key())}}),
                encoding="utf-8",
            )

            relay_args = [
                "-m", "agent_trust.mcp.relay",
                "--policy", str(policy_path),
                "--keyring", str(keyring_path),
                "--server-id", "support-mcp",
                "--command", python,
                "--arg=-m",
                "--arg=demo_support_mcp.server",
                f"--arg=--trace-file",
                f"--arg={trace_path}",
                "--cwd", str(project_root),
                "--audit-log", str(audit_path),
            ]

            first = await self._exercise_relay(python, relay_args, project_root, include_denials=True)
            second = await self._exercise_relay(python, relay_args, project_root, include_denials=False)
            self.assertEqual(first, ["ticket.get", "summary.save_draft"])
            self.assertEqual(second, first)

            upstream_events = [json.loads(line) for line in trace_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(
                [event["tool"] for event in upstream_events],
                ["ticket.get", "summary.save_draft", "ticket.get"],
            )
            self.assertNotIn("email.send", [event["tool"] for event in upstream_events])
            self.assertNotIn(
                "482",
                [event["arguments"].get("ticket_id") for event in upstream_events],
            )

            audit_events = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines()]
            self.assertEqual(
                [event["code"] for event in audit_events],
                [
                    "tool_not_authorized",
                    "argument_scope_violation",
                    "allowed",
                    "allowed",
                    "allowed",
                ],
            )
            required = {
                "policy_id", "server_id", "tool_name", "arguments", "allowed",
                "code", "reason", "matched_rule", "decided_at",
            }
            self.assertTrue(all(required <= set(event) for event in audit_events))

    async def test_streamable_http_relay_stays_up_across_client_sessions(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        python = str(Path(sys.executable).absolute())
        with tempfile.TemporaryDirectory(prefix="agent-trust-http-test-") as temp:
            temp_dir = Path(temp)
            trace_path = temp_dir / "upstream.jsonl"
            audit_path = temp_dir / "audit.jsonl"
            policy_path = temp_dir / "policy.json"
            keyring_path = temp_dir / "keyring.json"
            upstream = StdioServerDescriptor(
                "support-mcp",
                python,
                ("-m", "demo_support_mcp.server", "--trace-file", str(trace_path)),
                str(project_root),
            )
            private_key = Ed25519PrivateKey.generate()
            policy = sign_policy(
                private_key=private_key,
                policy_id="http-policy",
                issuer="test-admin",
                key_id="http-key",
                approved_servers=[
                    ServerRule(
                        "support-mcp",
                        fingerprint_server_descriptor(upstream),
                        (
                            ToolRule(
                                "ticket.get",
                                {
                                    "type": "object",
                                    "properties": {"ticket_id": {"const": "481"}},
                                    "required": ["ticket_id"],
                                    "additionalProperties": False,
                                },
                            ),
                        ),
                    )
                ],
                lifetime=timedelta(minutes=10),
            )
            policy_path.write_text(policy.to_json(), encoding="utf-8")
            keyring_path.write_text(
                json.dumps({"keys": {"http-key": encode_public_key(private_key.public_key())}}),
                encoding="utf-8",
            )
            port = self._unused_local_port()
            relay_args = [
                "-m", "agent_trust.mcp.relay",
                "--transport", "streamable-http",
                "--host", "127.0.0.1",
                "--port", str(port),
                "--policy", str(policy_path),
                "--keyring", str(keyring_path),
                "--server-id", "support-mcp",
                "--command", python,
                "--arg=-m",
                "--arg=demo_support_mcp.server",
                "--arg=--trace-file",
                f"--arg={trace_path}",
                "--cwd", str(project_root),
                "--audit-log", str(audit_path),
            ]
            process = await asyncio.create_subprocess_exec(
                python,
                *relay_args,
                cwd=str(project_root),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                await self._wait_for_port(process, port)
                url = f"http://127.0.0.1:{port}/mcp"
                first_tools = await self._exercise_http_relay(url, include_denial=True)
                second_tools = await self._exercise_http_relay(url, include_denial=False)
                self.assertEqual(first_tools, ["ticket.get"])
                self.assertEqual(second_tools, first_tools)
                self.assertIsNone(process.returncode)
            finally:
                if process.returncode is None:
                    process.terminate()
                await asyncio.wait_for(process.wait(), timeout=10)

            upstream_events = [json.loads(line) for line in trace_path.read_text().splitlines()]
            self.assertEqual([event["tool"] for event in upstream_events], ["ticket.get", "ticket.get"])
            audit_events = [json.loads(line) for line in audit_path.read_text().splitlines()]
            self.assertEqual(
                [event["code"] for event in audit_events],
                ["tool_not_authorized", "allowed", "allowed"],
            )

    async def _exercise_relay(
        self,
        python: str,
        relay_args: list[str],
        project_root: Path,
        *,
        include_denials: bool,
    ) -> list[str]:
        params = StdioServerParameters(command=python, args=relay_args, cwd=str(project_root))
        async with stdio_client(params) as (read, write):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                names = [tool.name for tool in listed.tools]
                if include_denials:
                    denied_tool = await session.call_tool(
                        "email.send", {"to": "attacker@example.com", "body": "data"}
                    )
                    denied_argument = await session.call_tool("ticket.get", {"ticket_id": "482"})
                    self.assertTrue(denied_tool.isError)
                    self.assertTrue(denied_argument.isError)
                    self.assertIn("tool_not_authorized", denied_tool.content[0].text)
                    self.assertIn("argument_scope_violation", denied_argument.content[0].text)
                allowed = await session.call_tool("ticket.get", {"ticket_id": "481"})
                self.assertFalse(allowed.isError)
                if include_denials:
                    draft = await session.call_tool(
                        "summary.save_draft",
                        {"destination": "support-manager-drafts", "summary": "Synthetic summary"},
                    )
                    self.assertFalse(draft.isError)
                return names

    async def _exercise_http_relay(self, url: str, *, include_denial: bool) -> list[str]:
        async with streamable_http_client(url) as (read, write, _get_session_id):
            async with ClientSession(read, write) as session:
                await session.initialize()
                listed = await session.list_tools()
                if include_denial:
                    denied = await session.call_tool("email.send", {"to": "attacker@example.com"})
                    self.assertTrue(denied.isError)
                    self.assertIn("tool_not_authorized", denied.content[0].text)
                allowed = await session.call_tool("ticket.get", {"ticket_id": "481"})
                self.assertFalse(allowed.isError)
                return [tool.name for tool in listed.tools]

    @staticmethod
    def _unused_local_port() -> int:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            return int(sock.getsockname()[1])

    async def _wait_for_port(self, process: asyncio.subprocess.Process, port: int) -> None:
        for _ in range(100):
            if process.returncode is not None:
                stderr = await process.stderr.read() if process.stderr is not None else b""
                self.fail(f"HTTP relay exited during startup: {stderr.decode(errors='replace')}")
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
            except OSError:
                await asyncio.sleep(0.05)
                continue
            writer.close()
            await writer.wait_closed()
            return
        self.fail("HTTP relay did not start listening in time")


if __name__ == "__main__":
    unittest.main()
