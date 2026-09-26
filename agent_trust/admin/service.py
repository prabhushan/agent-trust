"""Verified policy inspection and re-signing for the local admin UI."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping, Sequence

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..core.policy import (
    PolicyError,
    ServerRule,
    SignedMcpPolicy,
    StdioServerDescriptor,
    ToolRule,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
    verify_policy,
)
from ..mcp.relay import load_keyring, load_policy


ADMIN_MANIFEST_VERSION = 1


@dataclass(frozen=True)
class AdminPaths:
    """Filesystem inputs used by the local policy administrator."""

    policy: Path = Path("config/policy.json")
    keyring: Path = Path("config/keyring.json")
    signing_key: Path = Path("config/signing-key.pem")
    manifest: Path = Path("policy_specs/admin_policy.json")
    audit_log: Path = Path("config/audit.jsonl")

    @classmethod
    def from_environment(cls, environment: Mapping[str, str] | None = None) -> "AdminPaths":
        values = os.environ if environment is None else environment
        return cls(
            policy=Path(values.get("AGENTTRUST_POLICY_PATH", "config/policy.json")),
            keyring=Path(values.get("AGENTTRUST_KEYRING_PATH", "config/keyring.json")),
            signing_key=Path(
                values.get("AGENTTRUST_SIGNING_KEY_PATH", "config/signing-key.pem")
            ),
            manifest=Path(
                values.get("AGENTTRUST_ADMIN_MANIFEST_PATH", "policy_specs/admin_policy.json")
            ),
        )


@dataclass(frozen=True)
class PolicySnapshot:
    """A policy that has passed signature and time validation."""

    policy: SignedMcpPolicy
    trusted_keys: Mapping[str, Any]
    validity: timedelta


def _parse_policy_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _policy_validity(policy: SignedMcpPolicy) -> timedelta:
    validity = _parse_policy_time(policy.expires_at) - _parse_policy_time(policy.issued_at)
    if validity <= timedelta(0):
        raise PolicyError("Policy validity duration must be positive")
    return validity


def load_policy_snapshot(paths: AdminPaths) -> PolicySnapshot:
    """Load and verify the current policy before exposing it as trusted state."""
    policy = load_policy(paths.policy)
    trusted_keys = load_keyring(paths.keyring)
    verify_policy(policy, trusted_keys)
    return PolicySnapshot(policy, trusted_keys, _policy_validity(policy))


def load_audit_events(path: str | Path, limit: int = 500) -> tuple[dict[str, Any], ...]:
    """Load the latest JSONL audit events without reading an unbounded result set."""
    if limit < 1:
        raise PolicyError("Audit event limit must be positive")
    events: deque[dict[str, Any]] = deque(maxlen=limit)
    try:
        with Path(path).open("r", encoding="utf-8") as stream:
            for line_number, line in enumerate(stream, start=1):
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise PolicyError(f"Audit log line {line_number} is not valid JSON") from exc
                if not isinstance(event, dict):
                    raise PolicyError(f"Audit log line {line_number} must contain a JSON object")
                events.append(event)
    except OSError as exc:
        raise PolicyError(f"Unable to read audit log: {exc}") from exc
    return tuple(events)


def _manifest_server(server: ServerRule) -> dict[str, Any]:
    return {
        "server_id": server.server_id,
        "descriptor": server.descriptor.to_dict(),
        "tools": [tool.to_dict() for tool in server.tools],
    }


def policy_manifest(policy: SignedMcpPolicy) -> dict[str, Any]:
    """Return the unsigned, reproducible administration source for a policy."""
    return {
        "format_version": ADMIN_MANIFEST_VERSION,
        "policy": {
            "policy_id": policy.policy_id,
            "issuer": policy.issuer,
            "key_id": policy.key_id,
            "validity_seconds": int(_policy_validity(policy).total_seconds()),
        },
        "servers": [_manifest_server(server) for server in policy.approved_servers],
    }


def _load_manifest(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PolicyError(f"Unable to read admin manifest: {exc}") from exc
    if not isinstance(value, dict):
        raise PolicyError("Admin manifest must be a JSON object")
    return value


def _require_manifest_synchronized(path: Path, policy: SignedMcpPolicy) -> None:
    if not path.exists():
        return
    if _load_manifest(path) != policy_manifest(policy):
        raise PolicyError(
            "Admin manifest differs from the signed policy; reconcile the files before changing MCP servers"
        )


def _load_matching_private_key(
    path: Path,
    policy: SignedMcpPolicy,
    trusted_keys: Mapping[str, Any],
) -> Ed25519PrivateKey:
    try:
        raw = path.read_bytes()
        private_key = serialization.load_pem_private_key(raw, password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise PolicyError(f"Unable to read policy signing key: {exc}") from exc
    if not isinstance(private_key, Ed25519PrivateKey):
        raise PolicyError("Policy signing key must be an Ed25519 private key")
    trusted = trusted_keys.get(policy.key_id)
    if trusted is None or encode_public_key(private_key.public_key()) != encode_public_key(trusted):
        raise PolicyError("Policy signing key does not match the active keyring entry")
    return private_key


def _build_server_rule(
    *,
    server_id: str,
    command: str,
    args: Sequence[str],
    cwd: str,
    tools: Sequence[ToolRule],
) -> ServerRule:
    """Construct a signed server rule from admin form fields, normalizing paths."""
    cwd_value = cwd.strip()
    if not cwd_value:
        raise PolicyError("MCP working directory is required")
    cwd_path = Path(cwd_value)
    stored_cwd = (
        os.path.relpath(cwd_path, Path.cwd())
        if cwd_path.is_absolute()
        else os.path.normpath(cwd_value)
    )
    command_value = command.strip()
    if not command_value:
        raise PolicyError("MCP command is required")
    supplied_path = Path(command_value)
    stored_command = (
        os.path.relpath(supplied_path, Path.cwd())
        if supplied_path.is_absolute()
        else os.path.normpath(command_value)
    )
    descriptor = StdioServerDescriptor(
        server_id=server_id,
        command=stored_command,
        args=tuple(args),
        cwd=stored_cwd,
    )
    return ServerRule(
        server_id=server_id,
        descriptor=descriptor,
        descriptor_sha256=fingerprint_server_descriptor(descriptor),
        tools=tuple(tools),
    )


def validate_new_server(
    *,
    policy: SignedMcpPolicy,
    server_id: str,
    command: str,
    args: Sequence[str],
    cwd: str,
    tools: Sequence[ToolRule],
) -> ServerRule:
    """Validate an admin form submission for a server that must not exist yet."""
    if server_id in {server.server_id for server in policy.approved_servers}:
        raise PolicyError(f"Server ID {server_id!r} already exists in the policy")
    return _build_server_rule(server_id=server_id, command=command, args=args, cwd=cwd, tools=tools)


def validate_updated_server(
    *,
    policy: SignedMcpPolicy,
    server_id: str,
    command: str,
    args: Sequence[str],
    cwd: str,
    tools: Sequence[ToolRule],
) -> ServerRule:
    """Validate an admin form submission that replaces an already-approved server."""
    if server_id not in {server.server_id for server in policy.approved_servers}:
        raise PolicyError(f"Unknown MCP server ID: {server_id!r}")
    return _build_server_rule(server_id=server_id, command=command, args=args, cwd=cwd, tools=tools)


def _relative_server_rule(server: ServerRule) -> ServerRule:
    """Convert absolute local paths to launch-root-relative signed paths."""
    descriptor = server.descriptor
    command_path = Path(descriptor.command)
    cwd_path = Path(descriptor.cwd or ".")
    relative = StdioServerDescriptor(
        server_id=server.server_id,
        command=(
            os.path.relpath(command_path, Path.cwd())
            if command_path.is_absolute()
            else os.path.normpath(descriptor.command)
        ),
        args=descriptor.args,
        cwd=(
            os.path.relpath(cwd_path, Path.cwd())
            if cwd_path.is_absolute()
            else os.path.normpath(descriptor.cwd or ".")
        ),
    )
    return ServerRule(
        server_id=server.server_id,
        descriptor=relative,
        descriptor_sha256=fingerprint_server_descriptor(relative),
        tools=server.tools,
    )


def _stage_text(path: Path, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return temporary


def _restore_file(path: Path, previous: bytes | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
        return
    staged = _stage_text(path, previous.decode("utf-8"))
    os.replace(staged, path)


def _commit_policy_and_manifest(
    *,
    policy_path: Path,
    manifest_path: Path,
    policy_json: str,
    manifest_json: str,
) -> None:
    previous_policy = policy_path.read_bytes()
    previous_manifest = manifest_path.read_bytes() if manifest_path.exists() else None
    staged_policy = _stage_text(policy_path, policy_json)
    staged_manifest = _stage_text(manifest_path, manifest_json)
    backup_path = policy_path.with_name(f"{policy_path.name}.bak")
    staged_backup = _stage_text(backup_path, previous_policy.decode("utf-8"))
    manifest_replaced = False
    try:
        os.replace(staged_backup, backup_path)
        os.replace(staged_manifest, manifest_path)
        manifest_replaced = True
        os.replace(staged_policy, policy_path)
    except Exception:
        staged_policy.unlink(missing_ok=True)
        staged_manifest.unlink(missing_ok=True)
        staged_backup.unlink(missing_ok=True)
        if manifest_replaced:
            _restore_file(manifest_path, previous_manifest)
        _restore_file(policy_path, previous_policy)
        raise


def append_mcp_server(
    *,
    paths: AdminPaths,
    expected_signature: str,
    server_id: str,
    command: str,
    args: Sequence[str],
    cwd: str,
    tools: Sequence[ToolRule],
) -> PolicySnapshot:
    """Append one server, rebuild the manifest, and atomically re-sign the policy."""
    current = load_policy_snapshot(paths)
    if not expected_signature or current.policy.signature != expected_signature:
        raise PolicyError("Policy changed after it was loaded; refresh before saving")
    _require_manifest_synchronized(paths.manifest, current.policy)
    private_key = _load_matching_private_key(paths.signing_key, current.policy, current.trusted_keys)
    new_server = validate_new_server(
        policy=current.policy,
        server_id=server_id,
        command=command,
        args=args,
        cwd=cwd,
        tools=tools,
    )
    updated = sign_policy(
        private_key=private_key,
        policy_id=current.policy.policy_id,
        issuer=current.policy.issuer,
        key_id=current.policy.key_id,
        approved_servers=[
            *(_relative_server_rule(server) for server in current.policy.approved_servers),
            new_server,
        ],
        lifetime=current.validity,
    )
    manifest_json = json.dumps(policy_manifest(updated), indent=2, sort_keys=True) + "\n"
    _commit_policy_and_manifest(
        policy_path=paths.policy,
        manifest_path=paths.manifest,
        policy_json=updated.to_json() + "\n",
        manifest_json=manifest_json,
    )
    saved = load_policy_snapshot(paths)
    if saved.policy.signature != updated.signature:
        raise PolicyError("Saved policy did not match the policy produced by the administrator")
    _require_manifest_synchronized(paths.manifest, saved.policy)
    return saved


def update_mcp_server(
    *,
    paths: AdminPaths,
    expected_signature: str,
    server_id: str,
    command: str,
    args: Sequence[str],
    cwd: str,
    tools: Sequence[ToolRule],
) -> PolicySnapshot:
    """Replace one already-approved server's descriptor and tools, then re-sign in place."""
    current = load_policy_snapshot(paths)
    if not expected_signature or current.policy.signature != expected_signature:
        raise PolicyError("Policy changed after it was loaded; refresh before saving")
    _require_manifest_synchronized(paths.manifest, current.policy)
    private_key = _load_matching_private_key(paths.signing_key, current.policy, current.trusted_keys)
    updated_server = validate_updated_server(
        policy=current.policy,
        server_id=server_id,
        command=command,
        args=args,
        cwd=cwd,
        tools=tools,
    )
    updated = sign_policy(
        private_key=private_key,
        policy_id=current.policy.policy_id,
        issuer=current.policy.issuer,
        key_id=current.policy.key_id,
        approved_servers=[
            updated_server if server.server_id == server_id else _relative_server_rule(server)
            for server in current.policy.approved_servers
        ],
        lifetime=current.validity,
    )
    manifest_json = json.dumps(policy_manifest(updated), indent=2, sort_keys=True) + "\n"
    _commit_policy_and_manifest(
        policy_path=paths.policy,
        manifest_path=paths.manifest,
        policy_json=updated.to_json() + "\n",
        manifest_json=manifest_json,
    )
    saved = load_policy_snapshot(paths)
    if saved.policy.signature != updated.signature:
        raise PolicyError("Saved policy did not match the policy produced by the administrator")
    _require_manifest_synchronized(paths.manifest, saved.policy)
    return saved


def delete_mcp_server(
    *,
    paths: AdminPaths,
    expected_signature: str,
    server_id: str,
) -> PolicySnapshot:
    """Delete one server and atomically regenerate the signed policy and manifest."""
    current = load_policy_snapshot(paths)
    if not expected_signature or current.policy.signature != expected_signature:
        raise PolicyError("Policy changed after it was loaded; refresh before saving")
    _require_manifest_synchronized(paths.manifest, current.policy)
    if server_id not in {server.server_id for server in current.policy.approved_servers}:
        raise PolicyError(f"Unknown MCP server ID: {server_id!r}")
    if len(current.policy.approved_servers) == 1:
        raise PolicyError("A policy must retain at least one approved MCP server")
    private_key = _load_matching_private_key(paths.signing_key, current.policy, current.trusted_keys)
    remaining = tuple(
        _relative_server_rule(server)
        for server in current.policy.approved_servers
        if server.server_id != server_id
    )
    updated = sign_policy(
        private_key=private_key,
        policy_id=current.policy.policy_id,
        issuer=current.policy.issuer,
        key_id=current.policy.key_id,
        approved_servers=remaining,
        lifetime=current.validity,
    )
    _commit_policy_and_manifest(
        policy_path=paths.policy,
        manifest_path=paths.manifest,
        policy_json=updated.to_json() + "\n",
        manifest_json=json.dumps(policy_manifest(updated), indent=2, sort_keys=True) + "\n",
    )
    saved = load_policy_snapshot(paths)
    if saved.policy.signature != updated.signature:
        raise PolicyError("Saved policy did not match the policy produced by the administrator")
    _require_manifest_synchronized(paths.manifest, saved.policy)
    return saved
