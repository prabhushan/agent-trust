"""Signed, reusable authorization policies for MCP tool calls."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import base64
import hashlib
import json
import math
from pathlib import Path
import re
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


POLICY_VERSION = 3
POLICY_AUDIENCE = "agent-trust-relay"
SIGNATURE_ALGORITHM = "Ed25519"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class PolicyError(ValueError):
    """Raised when a policy or server descriptor is invalid."""


def _canonical_json(value: Any) -> bytes:
    try:
        serialized = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise PolicyError("Policy contains a value that cannot be represented as canonical JSON") from exc
    return serialized.encode("utf-8")


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str, field: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise PolicyError(f"{field} must be a non-empty base64url string")
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise PolicyError(f"{field} is not valid base64url") from exc


def encode_public_key(public_key: Ed25519PublicKey) -> str:
    """Encode an Ed25519 public key for a relay keyring."""
    return _b64encode(public_key.public_bytes_raw())


def decode_public_key(value: str) -> Ed25519PublicKey:
    """Decode a raw base64url Ed25519 public key."""
    raw = _b64decode(value, "public key")
    if len(raw) != 32:
        raise PolicyError("An Ed25519 public key must contain 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _freeze_json(value: Any) -> Any:
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise PolicyError("JSON object keys in policy schemas must be strings")
        return MappingProxyType({key: _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, float) and not math.isfinite(value):
        raise PolicyError("Policy schemas cannot contain NaN or infinite numbers")
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise PolicyError(f"Policy schemas may contain only JSON values, not {type(value).__name__}")


def thaw_json(value: Any) -> Any:
    """Return ordinary JSON containers from immutable policy data."""
    if isinstance(value, Mapping):
        return {key: thaw_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw_json(item) for item in value]
    return value


def _timestamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise PolicyError("Policy timestamps must be timezone-aware")
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: str, field: str) -> datetime:
    if not isinstance(value, str):
        raise PolicyError(f"{field} must be a timestamp string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise PolicyError(f"{field} is invalid") from exc
    if parsed.tzinfo is None:
        raise PolicyError(f"{field} must include a timezone")
    return parsed.astimezone(UTC)


def _require_exact_keys(value: Mapping[str, Any], expected: set[str], context: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        details = []
        if missing:
            details.append(f"missing {missing!r}")
        if unknown:
            details.append(f"unknown {unknown!r}")
        raise PolicyError(f"Malformed {context}: {', '.join(details)}")


@dataclass(frozen=True)
class StdioServerDescriptor:
    """The non-secret stdio launch configuration bound into a policy."""

    server_id: str
    command: str
    args: tuple[str, ...] = ()
    cwd: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.server_id, str) or not self.server_id.strip():
            raise PolicyError("server_id must be non-empty")
        if not isinstance(self.command, str) or not self.command.strip():
            raise PolicyError("command must be non-empty")
        if not Path(self.command).is_absolute():
            raise PolicyError("stdio command must be an absolute path")
        if not isinstance(self.args, (tuple, list)) or not all(isinstance(arg, str) for arg in self.args):
            raise PolicyError("stdio args must contain strings")
        if self.cwd is not None and (not isinstance(self.cwd, str) or not Path(self.cwd).is_absolute()):
            raise PolicyError("stdio cwd must be an absolute path when supplied")
        object.__setattr__(self, "args", tuple(self.args))

    def fingerprint_payload(self) -> dict[str, Any]:
        cwd = Path(self.cwd).resolve() if self.cwd is not None else Path.cwd().resolve()
        return {
            "transport": "stdio",
            "command": str(Path(self.command).resolve()),
            "args": list(self.args),
            "cwd": str(cwd),
        }

    def to_dict(self) -> dict[str, Any]:
        """Serialize the complete signed launch descriptor."""
        if self.cwd is None:
            raise PolicyError("Signed stdio descriptors must include an absolute cwd")
        return {
            "transport": "stdio",
            "command": self.command,
            "args": list(self.args),
            "cwd": self.cwd,
        }

    @classmethod
    def from_dict(cls, server_id: str, value: Mapping[str, Any]) -> "StdioServerDescriptor":
        if not isinstance(value, Mapping):
            raise PolicyError("Malformed stdio server descriptor")
        _require_exact_keys(value, {"transport", "command", "args", "cwd"}, "stdio server descriptor")
        if value["transport"] != "stdio":
            raise PolicyError(f"Unsupported server transport: {value['transport']!r}")
        if not isinstance(value["args"], list):
            raise PolicyError("Stdio descriptor args must be a list")
        return cls(
            server_id=server_id,
            command=value["command"],
            args=tuple(value["args"]),
            cwd=value["cwd"],
        )


def fingerprint_server_descriptor(descriptor: StdioServerDescriptor) -> str:
    """Hash a normalized stdio descriptor; this is not binary attestation."""
    return hashlib.sha256(_canonical_json(descriptor.fingerprint_payload())).hexdigest()


@dataclass(frozen=True)
class SubjectSelector:
    """Principals or groups to which a tool rule applies (OR semantics)."""

    principals: tuple[str, ...] = ()
    groups: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        principals = tuple(self.principals)
        groups = tuple(self.groups)
        if not principals and not groups:
            raise PolicyError("Tool rule subjects must contain at least one principal or group")
        for label, values in (("principals", principals), ("groups", groups)):
            if not all(isinstance(value, str) and value.strip() for value in values):
                raise PolicyError(f"Subject {label} must contain non-empty strings")
            if len(set(values)) != len(values):
                raise PolicyError(f"Subject {label} must be unique")
        object.__setattr__(self, "principals", principals)
        object.__setattr__(self, "groups", groups)

    def to_dict(self) -> dict[str, Any]:
        return {"principals": list(self.principals), "groups": list(self.groups)}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SubjectSelector":
        if not isinstance(value, Mapping):
            raise PolicyError("Malformed tool rule subjects")
        _require_exact_keys(value, {"principals", "groups"}, "tool rule subjects")
        if not isinstance(value["principals"], list) or not isinstance(value["groups"], list):
            raise PolicyError("Subject principals and groups must be lists")
        return cls(principals=tuple(value["principals"]), groups=tuple(value["groups"]))


@dataclass(frozen=True)
class ToolRule:
    name: str
    arguments_schema: Mapping[str, Any]
    subjects: SubjectSelector
    effect: str = "allow"

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name.strip():
            raise PolicyError("Tool names must be non-empty")
        if not isinstance(self.arguments_schema, Mapping):
            raise PolicyError("Tool arguments_schema must be an object")
        if self.effect not in {"allow", "deny"}:
            raise PolicyError("Tool rule effect must be 'allow' or 'deny'")
        if not isinstance(self.subjects, SubjectSelector):
            raise PolicyError("Tool rule subjects must be a SubjectSelector")
        object.__setattr__(self, "arguments_schema", _freeze_json(dict(self.arguments_schema)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "effect": self.effect,
            "subjects": self.subjects.to_dict(),
            "arguments_schema": thaw_json(self.arguments_schema),
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ToolRule":
        if not isinstance(value, Mapping):
            raise PolicyError("Malformed tool rule")
        _require_exact_keys(value, {"name", "effect", "subjects", "arguments_schema"}, "tool rule")
        return cls(
            name=value["name"],
            effect=value["effect"],
            subjects=SubjectSelector.from_dict(value["subjects"]),
            arguments_schema=value["arguments_schema"],
        )


@dataclass(frozen=True)
class ServerRule:
    server_id: str
    descriptor: StdioServerDescriptor
    descriptor_sha256: str
    tools: tuple[ToolRule, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.server_id, str) or not self.server_id.strip():
            raise PolicyError("Server rule server_id must be non-empty")
        if not isinstance(self.descriptor, StdioServerDescriptor):
            raise PolicyError("Server rule descriptor must be a StdioServerDescriptor")
        if self.descriptor.server_id != self.server_id:
            raise PolicyError("Server rule and descriptor server IDs must match")
        if self.descriptor.cwd is None:
            raise PolicyError("Signed server descriptors must include an absolute cwd")
        if not isinstance(self.descriptor_sha256, str) or _SHA256_RE.fullmatch(self.descriptor_sha256) is None:
            raise PolicyError("descriptor_sha256 must be a lowercase SHA-256 hex digest")
        if fingerprint_server_descriptor(self.descriptor) != self.descriptor_sha256:
            raise PolicyError(f"Descriptor fingerprint does not match server {self.server_id!r}")
        if not isinstance(self.tools, (tuple, list)) or not self.tools:
            raise PolicyError("Each approved server must contain at least one tool")
        tools = tuple(self.tools)
        if not all(isinstance(tool, ToolRule) for tool in tools):
            raise PolicyError("Server tools must be ToolRule values")
        serialized = [_canonical_json(tool.to_dict()) for tool in tools]
        if len(set(serialized)) != len(serialized):
            raise PolicyError(f"Tool rules must be unique within server {self.server_id!r}")
        object.__setattr__(self, "tools", tools)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "descriptor": self.descriptor.to_dict(),
            "descriptor_sha256": self.descriptor_sha256,
            "tools": [tool.to_dict() for tool in self.tools],
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "ServerRule":
        if not isinstance(value, Mapping):
            raise PolicyError("Malformed server rule")
        _require_exact_keys(value, {"server_id", "descriptor", "descriptor_sha256", "tools"}, "server rule")
        if not isinstance(value["tools"], list):
            raise PolicyError("Server rule tools must be a list")
        return cls(
            server_id=value["server_id"],
            descriptor=StdioServerDescriptor.from_dict(value["server_id"], value["descriptor"]),
            descriptor_sha256=value["descriptor_sha256"],
            tools=tuple(ToolRule.from_dict(tool) for tool in value["tools"]),
        )


@dataclass(frozen=True)
class SignedMcpPolicy:
    version: int
    policy_id: str
    issuer: str
    audience: str
    key_id: str
    signature_algorithm: str
    issued_at: str
    expires_at: str
    approved_servers: tuple[ServerRule, ...]
    signature: str

    def __post_init__(self) -> None:
        if type(self.version) is not int or self.version != POLICY_VERSION:
            raise PolicyError(f"Unsupported policy version: {self.version!r}")
        for field_name in ("policy_id", "issuer", "audience", "key_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise PolicyError(f"{field_name} must be non-empty")
        if self.audience != POLICY_AUDIENCE:
            raise PolicyError(f"Unsupported policy audience: {self.audience!r}")
        if self.signature_algorithm != SIGNATURE_ALGORITHM:
            raise PolicyError(f"Unsupported signature algorithm: {self.signature_algorithm!r}")
        issued = _parse_timestamp(self.issued_at, "issued_at")
        expires = _parse_timestamp(self.expires_at, "expires_at")
        if expires <= issued:
            raise PolicyError("Policy expiry must be later than issuance")
        if not isinstance(self.approved_servers, (tuple, list)) or not self.approved_servers:
            raise PolicyError("A policy must approve at least one server")
        servers = tuple(self.approved_servers)
        if not all(isinstance(server, ServerRule) for server in servers):
            raise PolicyError("approved_servers must contain ServerRule values")
        if len({server.server_id for server in servers}) != len(servers):
            raise PolicyError("Approved server IDs must be unique")
        if not isinstance(self.signature, str):
            raise PolicyError("signature must be a string")
        object.__setattr__(self, "approved_servers", servers)

    def unsigned_payload(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "policy_id": self.policy_id,
            "issuer": self.issuer,
            "audience": self.audience,
            "key_id": self.key_id,
            "signature_algorithm": self.signature_algorithm,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "approved_servers": [server.to_dict() for server in self.approved_servers],
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_payload(), "signature": self.signature}

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedMcpPolicy":
        if not isinstance(value, Mapping):
            raise PolicyError("Malformed signed MCP policy")
        expected = {
            "version", "policy_id", "issuer", "audience", "key_id", "signature_algorithm",
            "issued_at", "expires_at", "approved_servers", "signature",
        }
        _require_exact_keys(value, expected, "signed MCP policy")
        if not isinstance(value["approved_servers"], list):
            raise PolicyError("approved_servers must be a list")
        return cls(
            version=value["version"],
            policy_id=value["policy_id"],
            issuer=value["issuer"],
            audience=value["audience"],
            key_id=value["key_id"],
            signature_algorithm=value["signature_algorithm"],
            issued_at=value["issued_at"],
            expires_at=value["expires_at"],
            approved_servers=tuple(ServerRule.from_dict(server) for server in value["approved_servers"]),
            signature=value["signature"],
        )

    @classmethod
    def from_json(cls, value: str) -> "SignedMcpPolicy":
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise PolicyError("Policy is not valid JSON") from exc
        return cls.from_dict(parsed)


def sign_policy(
    *,
    private_key: Ed25519PrivateKey,
    policy_id: str,
    issuer: str,
    key_id: str,
    approved_servers: list[ServerRule] | tuple[ServerRule, ...],
    lifetime: timedelta,
    now: datetime | None = None,
    audience: str = POLICY_AUDIENCE,
) -> SignedMcpPolicy:
    """Create a reusable policy in a trusted administrative path."""
    if not isinstance(private_key, Ed25519PrivateKey):
        raise PolicyError("private_key must be an Ed25519PrivateKey")
    if lifetime <= timedelta(0):
        raise PolicyError("Policy lifetime must be positive")
    issued = now or datetime.now(UTC)
    if issued.tzinfo is None:
        raise PolicyError("Policy issuance time must be timezone-aware")
    unsigned = SignedMcpPolicy(
        version=POLICY_VERSION,
        policy_id=policy_id,
        issuer=issuer,
        audience=audience,
        key_id=key_id,
        signature_algorithm=SIGNATURE_ALGORITHM,
        issued_at=_timestamp(issued),
        expires_at=_timestamp(issued + lifetime),
        approved_servers=tuple(approved_servers),
        signature="",
    )
    signature = _b64encode(private_key.sign(_canonical_json(unsigned.unsigned_payload())))
    return SignedMcpPolicy.from_dict({**unsigned.unsigned_payload(), "signature": signature})


def verify_policy(
    policy: SignedMcpPolicy,
    trusted_keys: Mapping[str, Ed25519PublicKey],
    now: datetime | None = None,
) -> None:
    """Verify structure, signer, signature, and validity period; fail closed."""
    if not isinstance(policy, SignedMcpPolicy):
        raise PolicyError("Expected a SignedMcpPolicy")
    # Reparse to re-run structural checks even if frozen fields were forcibly changed.
    try:
        SignedMcpPolicy.from_dict(policy.to_dict())
    except PolicyError:
        raise
    except Exception as exc:
        raise PolicyError("Malformed signed MCP policy") from exc
    public_key = trusted_keys.get(policy.key_id)
    if public_key is None:
        raise PolicyError(f"Unknown policy signing key: {policy.key_id!r}")
    if not isinstance(public_key, Ed25519PublicKey):
        raise PolicyError(f"Trusted key {policy.key_id!r} is not an Ed25519 public key")
    signature = _b64decode(policy.signature, "signature")
    try:
        public_key.verify(signature, _canonical_json(policy.unsigned_payload()))
    except (InvalidSignature, ValueError) as exc:
        raise PolicyError("Policy signature is invalid") from exc
    current = now or datetime.now(UTC)
    if current.tzinfo is None:
        raise PolicyError("Verification time must be timezone-aware")
    current = current.astimezone(UTC)
    issued = _parse_timestamp(policy.issued_at, "issued_at")
    expires = _parse_timestamp(policy.expires_at, "expires_at")
    if current < issued:
        raise PolicyError("Policy is not yet valid")
    if current >= expires:
        raise PolicyError("Policy has expired")


def select_server_rule(policy: SignedMcpPolicy, server_id: str | None = None) -> ServerRule:
    """Select one signed server, requiring an ID only when selection is ambiguous."""
    if not isinstance(policy, SignedMcpPolicy):
        raise PolicyError("Expected a SignedMcpPolicy")
    if server_id is None:
        if len(policy.approved_servers) == 1:
            return policy.approved_servers[0]
        available = ", ".join(sorted(server.server_id for server in policy.approved_servers))
        raise PolicyError(f"Policy approves multiple servers; pass --server-id with one of: {available}")
    selected = next((server for server in policy.approved_servers if server.server_id == server_id), None)
    if selected is None:
        available = ", ".join(sorted(server.server_id for server in policy.approved_servers))
        raise PolicyError(f"Unknown server ID {server_id!r}; approved servers: {available}")
    return selected
