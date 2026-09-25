"""Generate a persistent Ed25519 key pair and signed MCP policy."""

from __future__ import annotations

import argparse
from datetime import timedelta
import json
import os
from pathlib import Path
import shlex
import sys
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core.policy import (
    PolicyError,
    ServerRule,
    StdioServerDescriptor,
    ToolRule,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
)


POLICY_FILENAME = "policy.json"
KEYRING_FILENAME = "keyring.json"
PRIVATE_KEY_FILENAME = "signing-key.pem"


def load_tool_rules(path: str | Path) -> tuple[ToolRule, ...]:
    """Load a strict {"tools": [...]} rule document."""
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Unable to read tool rules: {exc}") from exc
    if not isinstance(value, dict) or set(value) != {"tools"} or not isinstance(value["tools"], list):
        raise PolicyError("Tool rules must be an object with exactly one 'tools' list")
    if not value["tools"]:
        raise PolicyError("Tool rules must contain at least one tool")
    rules = tuple(ToolRule.from_dict(rule) for rule in value["tools"])
    serialized = [json.dumps(rule.to_dict(), sort_keys=True) for rule in rules]
    if len(set(serialized)) != len(serialized):
        raise PolicyError("Tool rules in the rule file must be unique")
    return rules


def generate_policy_files(
    *,
    output_dir: str | Path,
    descriptor: StdioServerDescriptor,
    tools: tuple[ToolRule, ...],
    policy_id: str,
    issuer: str,
    key_id: str,
    lifetime: timedelta,
    force: bool = False,
) -> dict[str, Path]:
    """Create signing material and a policy, returning their paths."""
    directory = Path(output_dir).resolve()
    targets = {
        "policy": directory / POLICY_FILENAME,
        "keyring": directory / KEYRING_FILENAME,
        "private_key": directory / PRIVATE_KEY_FILENAME,
    }
    existing = [path for path in targets.values() if path.exists()]
    if existing and not force:
        names = ", ".join(str(path) for path in existing)
        raise PolicyError(f"Refusing to overwrite existing files: {names}; pass --force to replace them")

    directory.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    policy = sign_policy(
        private_key=private_key,
        policy_id=policy_id,
        issuer=issuer,
        key_id=key_id,
        approved_servers=[
            ServerRule(
                server_id=descriptor.server_id,
                descriptor_sha256=fingerprint_server_descriptor(descriptor),
                tools=tools,
            )
        ],
        lifetime=lifetime,
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    keyring = {"keys": {key_id: encode_public_key(private_key.public_key())}}

    targets["policy"].write_text(policy.to_json() + "\n", encoding="utf-8")
    targets["keyring"].write_text(json.dumps(keyring, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    targets["private_key"].write_bytes(private_pem)
    os.chmod(targets["private_key"], 0o600)
    return targets


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate a persistent signed AgentTrust policy")
    parser.add_argument("--output-dir", default="config", help="Destination directory (default: config)")
    parser.add_argument("--tools", required=True, help="JSON file containing the approved tool rules")
    parser.add_argument("--server-id", required=True, help="Stable ID for the approved MCP server")
    parser.add_argument(
        "--command",
        default=str(Path(sys.executable).absolute()),
        help="Absolute upstream executable (default: this uv environment's Python)",
    )
    parser.add_argument("--arg", action="append", default=[], help="Upstream argument; repeat as needed")
    parser.add_argument("--cwd", default=str(Path.cwd().resolve()), help="Absolute upstream working directory")
    parser.add_argument("--policy-id", help="Policy ID (default: <server-id>-policy)")
    parser.add_argument("--issuer", default="local-admin", help="Policy issuer")
    parser.add_argument("--key-id", default="local-ed25519-key", help="Public-key identifier")
    parser.add_argument("--lifetime-days", type=int, default=30, help="Policy lifetime in days")
    parser.add_argument("--force", action="store_true", help="Replace existing generated files")
    return parser


def _relay_command(descriptor: StdioServerDescriptor, paths: dict[str, Path]) -> str:
    command = [
        "uv", "run", "agent-trust-relay",
        "--policy", str(paths["policy"]),
        "--keyring", str(paths["keyring"]),
        "--server-id", descriptor.server_id,
        "--command", descriptor.command,
    ]
    for argument in descriptor.args:
        command.append(f"--arg={argument}")
    if descriptor.cwd is not None:
        command.extend(["--cwd", descriptor.cwd])
    command.extend(["--audit-log", str(paths["policy"].parent / "audit.jsonl")])
    return shlex.join(command)


def main() -> None:
    args = _parser().parse_args()
    try:
        if args.lifetime_days < 1:
            raise PolicyError("--lifetime-days must be positive")
        descriptor = StdioServerDescriptor(
            server_id=args.server_id,
            command=args.command,
            args=tuple(args.arg),
            cwd=args.cwd,
        )
        tools = load_tool_rules(args.tools)
        paths = generate_policy_files(
            output_dir=args.output_dir,
            descriptor=descriptor,
            tools=tools,
            policy_id=args.policy_id or f"{args.server_id}-policy",
            issuer=args.issuer,
            key_id=args.key_id,
            lifetime=timedelta(days=args.lifetime_days),
            force=args.force,
        )
    except (PolicyError, OSError) as exc:
        print(f"Policy generation failed: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc

    print(f"Created policy:     {paths['policy']}")
    print(f"Created keyring:    {paths['keyring']}")
    print(f"Created private key:{paths['private_key']}")
    print("\nKeep signing-key.pem private; the relay needs only policy.json and keyring.json.")
    print("\nRun the relay with:\n")
    print(_relay_command(descriptor, paths))


if __name__ == "__main__":
    main()
