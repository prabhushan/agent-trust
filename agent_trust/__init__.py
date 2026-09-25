"""AgentTrust signed MCP authorization policies and deterministic gate."""

from .core.gate import GateDecision, PolicyGate, Principal
from .core.policy import (
    PolicyError,
    ServerRule,
    SignedMcpPolicy,
    StdioServerDescriptor,
    ToolRule,
    SubjectSelector,
    decode_public_key,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
    select_server_rule,
    verify_policy,
)

__all__ = [
    "GateDecision",
    "PolicyError",
    "PolicyGate",
    "Principal",
    "ServerRule",
    "SignedMcpPolicy",
    "StdioServerDescriptor",
    "ToolRule",
    "SubjectSelector",
    "decode_public_key",
    "encode_public_key",
    "fingerprint_server_descriptor",
    "sign_policy",
    "select_server_rule",
    "verify_policy",
]
