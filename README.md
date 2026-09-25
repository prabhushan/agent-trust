# AgentTrust Signed MCP Policy

AgentTrust is a deterministic authorization layer for MCP tool calls. A trusted
administrator signs a reusable policy that approves specific MCP server launch
descriptors, tools, and argument constraints. A stdio relay verifies that
policy and checks every proposed `tools/call` before forwarding it.

This model is intentionally not session-based. A policy can be reused by
independent relay processes until it expires.

## Security boundary

AgentTrust answers three questions:

1. Is this configured MCP server approved?
2. Is this tool approved for that server?
3. Do the proposed arguments satisfy the approved constraints?

It does **not** prove that an otherwise allowed call belongs to the user's
current goal. For example, a broad policy permitting any ticket ID cannot stop
prompt injection from selecting the wrong ticket. Use narrow argument rules
such as `const`, `enum`, or restrictive patterns when resource boundaries
matter.

The server fingerprint covers normalized stdio configuration: transport,
command, arguments, and working directory. It binds the relay to an approved
launch descriptor; it does not hash or attest the executable's contents.

## Policy format

A signed policy contains:

- Policy identity, issuer, audience, signing key ID, and required expiry
- One or more server IDs and SHA-256 descriptor fingerprints
- An allowlist of tools for each server
- A small JSON-Schema-style argument policy for each tool
- An Ed25519 signature over canonical JSON

The argument validator supports `const`, `enum`, `type`, object properties,
required fields, `additionalProperties`, string patterns, numeric bounds,
arrays, and `maxItems`.

Relays receive only trusted Ed25519 public keys. The private signing key belongs
in a separate administrative path and must never be exposed to an agent or MCP
tool.

## Package layout

```text
agent_trust/
├── core/       # Signed policy model, verification, and authorization gate
├── cli/        # Persistent policy and Ed25519 key generator
├── mcp/        # Stdio relay and synthetic support MCP server
└── examples/   # Runnable end-to-end demonstration
tests/          # Unit and stdio integration tests
```

The top-level `agent_trust` package re-exports the supported policy and gate
API, so application imports such as `from agent_trust import PolicyGate` remain
stable.

## Install and test

From the repository root, let uv create and synchronize `.venv` from the
committed lockfile:

```bash
uv sync
uv run python -m unittest discover -s tests -p 'test_*.py' -v
uv run agent-trust-demo
```

The demo creates an ephemeral key and policy, starts the relay and synthetic
support server, and shows:

- `email.send` is not advertised and a direct call is blocked.
- `ticket.get` for ticket `482` is blocked.
- Ticket `481` and the approved summary destination are allowed.
- Blocked attempts do not interfere with later valid calls.

No email is delivered and all ticket data is synthetic.

## Generating a persistent policy

From the repository root, generate a policy for the included synthetic support
server:

```bash
uv run agent-trust-generate \
  --output-dir config \
  --tools agent_trust/examples/support-tools.json \
  --server-id support-mcp \
  --arg=-m \
  --arg=agent_trust.mcp.support_server
```

The command uses the uv environment's Python executable and the current
directory as the approved server descriptor. It creates:

```text
config/
├── policy.json       # Signed authorization policy used by the relay
├── keyring.json      # Public verification key used by the relay
└── signing-key.pem   # Private signing key; keep secret and do not give to the relay
```

Existing files are not overwritten. Use `--force` only when intentionally
rotating all three files. The generated private key has owner-only permissions
and is ignored by this repository's `.gitignore`.

The generator prints the exact `agent-trust-relay` command matching the signed
descriptor. To define another policy, provide a JSON file with the same
`{"tools": [...]}` structure as `support-tools.json` and supply that server's
command, repeated `--arg` values, and working directory.

### Programmatic generation

Policy creation is a trusted administrative operation:

```python
from datetime import timedelta
from pathlib import Path
import sys

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from agent_trust import (
    ServerRule,
    StdioServerDescriptor,
    ToolRule,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
)

descriptor = StdioServerDescriptor(
    server_id="support-mcp",
    command=str(Path(sys.executable).absolute()),
    args=("-m", "agent_trust.mcp.support_server"),
    cwd=str(Path.cwd().resolve()),
)

private_key = Ed25519PrivateKey.generate()
policy = sign_policy(
    private_key=private_key,
    policy_id="support-policy-v1",
    issuer="security-admin",
    key_id="policy-key-2026-09",
    approved_servers=[
        ServerRule(
            server_id="support-mcp",
            descriptor_sha256=fingerprint_server_descriptor(descriptor),
            tools=(
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
    lifetime=timedelta(days=30),
)

Path("policy.json").write_text(policy.to_json())
public_key = encode_public_key(private_key.public_key())
Path("keyring.json").write_text(
    '{"keys":{"policy-key-2026-09":"' + public_key + '"}}'
)
```

Store and distribute the private key using a real key-management process in
production. The example keeps it in memory only.

## Running the relay

The relay fronts exactly one stdio upstream:

```bash
uv run agent-trust-relay \
  --policy /absolute/path/policy.json \
  --keyring /absolute/path/keyring.json \
  --server-id support-mcp \
  --command /absolute/path/to/repository/.venv/bin/python \
  --arg=-m \
  --arg=agent_trust.mcp.support_server \
  --cwd /absolute/path/to/repository \
  --audit-log /absolute/path/agent-trust-audit.jsonl
```

The command, arguments, and working directory must exactly match the descriptor
used to create the signed fingerprint. Use `--arg=<value>` for arguments that
begin with a hyphen.

At startup the relay verifies the signature, key ID, audience, timestamps,
server ID, and descriptor fingerprint before spawning the upstream. It then:

- Filters `tools/list` to approved tools and publishes the policy argument schemas.
- Checks every `tools/call` again, including policy expiry.
- Returns an `isError=true` tool result for denied calls without forwarding them.
- Passes allowed upstream results through unchanged.

When `--audit-log` is omitted, decisions are written to stderr. Stdout remains
reserved for MCP protocol traffic. Audit events contain full arguments for
evidence, so protect the audit file as potentially sensitive data.

## Operations

- One relay loads one policy and fronts one upstream. Run separate relay
  instances for other approved servers.
- Update dependencies with `uv lock --upgrade` and commit the resulting
  `uv.lock`; use `uv sync --frozen` in reproducible automation.
- Rotate policies before their required expiry. Removing a public key from the
  keyring also prevents policies signed by that key from starting.
- There is no live revocation service in this MVP.
- Streamable HTTP, environment-bearing descriptors, binary attestation,
  resources, prompts, and policy merging are out of scope.
