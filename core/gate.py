"""Deterministic server, tool, and argument authorization."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import re
from types import MappingProxyType
from typing import Any, Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .policy import (
    PolicyError,
    ServerRule,
    SignedMcpPolicy,
    StdioServerDescriptor,
    ToolRule,
    fingerprint_server_descriptor,
    thaw_json,
    verify_policy,
)


@dataclass(frozen=True)
class GateDecision:
    allowed: bool
    code: str
    reason: str
    policy_id: str
    server_id: str
    tool_name: str
    arguments: Mapping[str, Any]
    matched_rule: str | None
    decided_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "code": self.code,
            "reason": self.reason,
            "policy_id": self.policy_id,
            "server_id": self.server_id,
            "tool_name": self.tool_name,
            "arguments": thaw_json(self.arguments),
            "matched_rule": self.matched_rule,
            "decided_at": self.decided_at,
        }


class PolicyGate:
    """Fail-closed enforcement bound to one policy and one stdio upstream."""

    def __init__(
        self,
        policy: SignedMcpPolicy,
        trusted_keys: Mapping[str, Ed25519PublicKey],
        server_descriptor: StdioServerDescriptor,
    ) -> None:
        self.policy = policy
        self._trusted_keys = dict(trusted_keys)
        self.server_descriptor = server_descriptor
        self.audit_log: list[GateDecision] = []

    def validate_binding(self, now: datetime | None = None) -> ServerRule:
        """Validate the policy and return the rule bound to this server."""
        verify_policy(self.policy, self._trusted_keys, now=now)
        server = next(
            (candidate for candidate in self.policy.approved_servers if candidate.server_id == self.server_descriptor.server_id),
            None,
        )
        if server is None:
            raise PolicyError(f"Server {self.server_descriptor.server_id!r} is not authorized by this policy")
        actual = fingerprint_server_descriptor(self.server_descriptor)
        if actual != server.descriptor_sha256:
            raise PolicyError(f"Descriptor fingerprint does not match server {self.server_descriptor.server_id!r}")
        return server

    def check(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        now: datetime | None = None,
    ) -> GateDecision:
        checked_at = now or datetime.now(UTC)
        if checked_at.tzinfo is None:
            checked_at = checked_at.replace(tzinfo=UTC)
        if not isinstance(arguments, Mapping):
            arguments = MappingProxyType({"_invalid_arguments": repr(arguments)})
        else:
            arguments = MappingProxyType(dict(arguments))

        try:
            verify_policy(self.policy, self._trusted_keys, now=checked_at)
        except PolicyError as exc:
            return self._record(False, "invalid_policy", str(exc), tool_name, arguments, None, checked_at)

        server = next(
            (candidate for candidate in self.policy.approved_servers if candidate.server_id == self.server_descriptor.server_id),
            None,
        )
        if server is None:
            return self._record(
                False,
                "server_not_authorized",
                f"Server {self.server_descriptor.server_id!r} is not approved",
                tool_name,
                arguments,
                None,
                checked_at,
            )
        if fingerprint_server_descriptor(self.server_descriptor) != server.descriptor_sha256:
            return self._record(
                False,
                "server_fingerprint_mismatch",
                f"Server {self.server_descriptor.server_id!r} has an unapproved launch descriptor",
                tool_name,
                arguments,
                f"approved_servers[{server.server_id}]",
                checked_at,
            )

        tool = next((candidate for candidate in server.tools if candidate.name == tool_name), None)
        if tool is None:
            return self._record(
                False,
                "tool_not_authorized",
                f"Tool {tool_name!r} is not approved for server {server.server_id!r}",
                tool_name,
                arguments,
                f"approved_servers[{server.server_id}].tools",
                checked_at,
            )

        rule_path = f"approved_servers[{server.server_id}].tools[{tool.name}].arguments_schema"
        violations = _validate(thaw_json(arguments), thaw_json(tool.arguments_schema))
        if violations:
            return self._record(
                False,
                "argument_scope_violation",
                "; ".join(violations),
                tool_name,
                arguments,
                rule_path,
                checked_at,
            )
        return self._record(
            True,
            "allowed",
            "Call satisfies the signed MCP authorization policy",
            tool_name,
            arguments,
            rule_path,
            checked_at,
        )

    def tool_rule(self, tool_name: str, now: datetime | None = None) -> ToolRule | None:
        server = self.validate_binding(now=now)
        return next((tool for tool in server.tools if tool.name == tool_name), None)

    def _record(
        self,
        allowed: bool,
        code: str,
        reason: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        matched_rule: str | None,
        decided_at: datetime,
    ) -> GateDecision:
        decision = GateDecision(
            allowed=allowed,
            code=code,
            reason=reason,
            policy_id=getattr(self.policy, "policy_id", "unknown"),
            server_id=self.server_descriptor.server_id,
            tool_name=tool_name,
            arguments=arguments,
            matched_rule=matched_rule,
            decided_at=decided_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        )
        self.audit_log.append(decision)
        return decision


def _validate(value: Any, schema: Mapping[str, Any], path: str = "arguments") -> list[str]:
    """Validate the deliberately small JSON Schema subset used by policies."""
    errors: list[str] = []
    if "const" in schema and value != schema["const"]:
        errors.append(f"{path} must equal {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path} must be one of {schema['enum']!r}")

    expected_type = schema.get("type")
    if expected_type == "object":
        if not isinstance(value, dict):
            return [f"{path} must be an object"]
        for field in schema.get("required", []):
            if field not in value:
                errors.append(f"{path}.{field} is required")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties", True) is False:
            unknown = set(value) - set(properties)
            if unknown:
                errors.append(f"{path} has unapproved fields: {sorted(unknown)!r}")
        for field, field_value in value.items():
            if field in properties:
                errors.extend(_validate(field_value, properties[field], f"{path}.{field}"))
    elif expected_type == "string":
        if not isinstance(value, str):
            return [f"{path} must be a string"]
        if "pattern" in schema and re.fullmatch(schema["pattern"], value) is None:
            errors.append(f"{path} does not match the approved pattern")
    elif expected_type == "integer":
        if not isinstance(value, int) or isinstance(value, bool):
            return [f"{path} must be an integer"]
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path} must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path} must be at most {schema['maximum']}")
    elif expected_type == "number":
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return [f"{path} must be a number"]
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path} must be at least {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path} must be at most {schema['maximum']}")
    elif expected_type == "boolean" and not isinstance(value, bool):
        return [f"{path} must be a boolean"]
    elif expected_type == "array":
        if not isinstance(value, list):
            return [f"{path} must be an array"]
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path} may contain at most {schema['maxItems']} values")
        if "items" in schema:
            for index, item in enumerate(value):
                errors.extend(_validate(item, schema["items"], f"{path}[{index}]"))
    return errors
