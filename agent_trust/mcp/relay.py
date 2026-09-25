"""A tools-only stdio MCP relay protected by a signed AgentTrust policy."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import AbstractContextManager
import json
from pathlib import Path
import sys
from typing import Any, Mapping, TextIO

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from ..core.gate import GateDecision, PolicyGate
from ..core.policy import (
    PolicyError,
    SignedMcpPolicy,
    StdioServerDescriptor,
    decode_public_key,
    thaw_json,
)


class AuditWriter(AbstractContextManager["AuditWriter"]):
    """Write one JSON object per policy decision without touching stdout."""

    def __init__(self, path: str | None = None) -> None:
        self._owns_stream = path is not None
        self._stream: TextIO = open(path, "a", encoding="utf-8") if path else sys.stderr

    def emit(self, decision: GateDecision) -> None:
        self._stream.write(json.dumps(decision.to_dict(), sort_keys=True) + "\n")
        self._stream.flush()

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        if self._owns_stream:
            self._stream.close()


def load_policy(path: str | Path) -> SignedMcpPolicy:
    try:
        return SignedMcpPolicy.from_json(Path(path).read_text(encoding="utf-8"))
    except OSError as exc:
        raise PolicyError(f"Unable to read policy file: {exc}") from exc


def load_keyring(path: str | Path) -> dict[str, Any]:
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Unable to read keyring: {exc}") from exc
    if not isinstance(raw, dict) or set(raw) != {"keys"} or not isinstance(raw["keys"], dict):
        raise PolicyError("Keyring must be an object with exactly one 'keys' object")
    if not raw["keys"]:
        raise PolicyError("Keyring must contain at least one public key")
    keyring = {}
    for key_id, encoded in raw["keys"].items():
        if not isinstance(key_id, str) or not key_id:
            raise PolicyError("Keyring IDs must be non-empty strings")
        keyring[key_id] = decode_public_key(encoded)
    return keyring


async def _all_upstream_tools(session: ClientSession) -> list[types.Tool]:
    tools: list[types.Tool] = []
    cursor: str | None = None
    while True:
        page = await session.list_tools(cursor=cursor)
        tools.extend(page.tools)
        cursor = page.nextCursor
        if cursor is None:
            return tools


def create_relay_server(
    gate: PolicyGate,
    upstream: ClientSession,
    audit: AuditWriter,
) -> Server:
    """Create the client-facing MCP server for an initialized upstream."""
    server = Server("agent-trust-relay", version="1.0.0")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        server_rule = gate.validate_binding()
        rules = {rule.name: rule for rule in server_rule.tools}
        advertised: list[types.Tool] = []
        for upstream_tool in await _all_upstream_tools(upstream):
            rule = rules.get(upstream_tool.name)
            if rule is None:
                continue
            advertised.append(
                upstream_tool.model_copy(update={"inputSchema": thaw_json(rule.arguments_schema)})
            )
        return advertised

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        decision = gate.check(name, arguments)
        audit.emit(decision)
        if not decision.allowed:
            body = {
                "error": "agent_trust_denied",
                "policy_id": decision.policy_id,
                "code": decision.code,
                "reason": decision.reason,
            }
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=json.dumps(body, sort_keys=True))],
                isError=True,
            )
        return await upstream.call_tool(name, arguments=dict(arguments))

    return server


async def run_relay(
    *,
    policy: SignedMcpPolicy,
    trusted_keys: Mapping[str, Any],
    descriptor: StdioServerDescriptor,
    audit_log: str | None = None,
) -> None:
    """Validate, spawn one upstream, and serve the policy-filtered façade."""
    gate = PolicyGate(policy, trusted_keys, descriptor)
    gate.validate_binding()  # Refuse startup before the upstream process exists.
    params = StdioServerParameters(
        command=descriptor.command,
        args=list(descriptor.args),
        cwd=descriptor.cwd,
    )
    with AuditWriter(audit_log) as audit:
        async with stdio_client(params) as (upstream_read, upstream_write):
            async with ClientSession(upstream_read, upstream_write) as upstream:
                await upstream.initialize()
                relay = create_relay_server(gate, upstream, audit)
                async with stdio_server() as (client_read, client_write):
                    await relay.run(
                        client_read,
                        client_write,
                        relay.create_initialization_options(),
                    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the AgentTrust stdio MCP relay")
    parser.add_argument("--policy", required=True, help="Signed policy JSON file")
    parser.add_argument("--keyring", required=True, help="Trusted Ed25519 public-key JSON file")
    parser.add_argument("--server-id", required=True, help="Approved server identifier")
    parser.add_argument("--command", required=True, help="Absolute upstream executable path")
    parser.add_argument("--arg", action="append", default=[], help="Upstream argument; repeat as needed")
    parser.add_argument("--cwd", help="Absolute upstream working directory")
    parser.add_argument("--audit-log", help="Append decisions as JSONL instead of writing to stderr")
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        policy = load_policy(args.policy)
        keyring = load_keyring(args.keyring)
        descriptor = StdioServerDescriptor(
            server_id=args.server_id,
            command=args.command,
            args=tuple(args.arg),
            cwd=args.cwd,
        )
        asyncio.run(
            run_relay(
                policy=policy,
                trusted_keys=keyring,
                descriptor=descriptor,
                audit_log=args.audit_log,
            )
        )
    except (PolicyError, OSError) as exc:
        print(f"AgentTrust relay refused to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
