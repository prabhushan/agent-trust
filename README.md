# AgentTrust Signed MCP Policy

AgentTrust is a deterministic authorization layer for MCP tool calls. A trusted
administrator signs a reusable policy that approves specific MCP server launch
descriptors, tools, and argument constraints. A relay verifies that policy and
checks every proposed `tools/call` before forwarding it. Clients can connect
over stdio or Streamable HTTP; the approved upstream remains a stdio server.

This model is intentionally not session-based. A policy can be reused by
independent relay processes until it expires.

## Security boundary

AgentTrust answers four questions:

1. Is this configured MCP server approved?
2. Which trusted principal and groups are making the call?
3. Is this tool allowed or explicitly denied for that subject?
4. Do the proposed arguments satisfy an applicable allow rule?

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
- Subject-aware `allow` and `deny` tool rules for each server
- Principal IDs and groups on every rule (either match uses OR semantics)
- A small JSON-Schema-style argument policy for every rule
- An Ed25519 signature over canonical JSON

The argument validator supports `const`, `enum`, `type`, object properties,
required fields, `additionalProperties`, string patterns, numeric bounds,
arrays, and `maxItems`.

Policies fail closed. A matching `deny` rule takes precedence over every
matching `allow`; without a matching allow, the tool is unauthorized. Multiple
matching allow rules are useful for roles with different argument scopes: a
call is accepted when its arguments satisfy at least one of them.

Relays receive only trusted Ed25519 public keys. The private signing key belongs
in a separate administrative path and must never be exposed to an agent or MCP
tool.

## Package layout

```text
agent_trust/
├── core/       # Signed policy model, verification, and authorization gate
├── cli/        # Persistent policy and Ed25519 key generator
├── mcp/        # Production stdio enforcement relay
└── examples/   # Runnable end-to-end demonstration
demo_support_mcp/ # Separate synthetic third-party-style upstream MCP server
policy_specs/      # Administrator-controlled unsigned policy inputs
config/            # Generated signed policy, keyring, and local audit output
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
  --tools policy_specs/support_demo.json \
  --server-id support-mcp \
  --arg=-m \
  --arg=demo_support_mcp.server
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
`{"tools": [...]}` structure as `policy_specs/support_demo.json`. Each entry
contains `name`, `effect`, `subjects`, and `arguments_schema`. Supply that server's
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
    SubjectSelector,
    ToolRule,
    encode_public_key,
    fingerprint_server_descriptor,
    sign_policy,
)

descriptor = StdioServerDescriptor(
    server_id="support-mcp",
    command=str(Path(sys.executable).absolute()),
    args=("-m", "demo_support_mcp.server"),
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
                    SubjectSelector(groups=("support-agents",)),
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

The relay fronts exactly one stdio upstream. Stdio remains the default
client-facing transport and is normally launched by an MCP client:

```bash
uv run agent-trust-relay \
  --transport stdio \
  --policy /absolute/path/policy.json \
  --keyring /absolute/path/keyring.json \
  --server-id support-mcp \
  --principal-id local-agent \
  --principal-group support-managers \
  --command /absolute/path/to/repository/.venv/bin/python \
  --arg=-m \
  --arg=demo_support_mcp.server \
  --cwd /absolute/path/to/repository \
  --audit-log /absolute/path/agent-trust-audit.jsonl
```

To run the same `agent-trust-relay` command as an always-on Streamable HTTP
service:

```bash
uv run agent-trust-relay \
  --transport streamable-http \
  --host 127.0.0.1 \
  --port 8000 \
  --policy /absolute/path/policy.json \
  --keyring /absolute/path/keyring.json \
  --server-id support-mcp \
  --principal-id local-agent \
  --principal-group support-managers \
  --command /absolute/path/to/repository/.venv/bin/python \
  --arg=-m \
  --arg=demo_support_mcp.server \
  --cwd /absolute/path/to/repository \
  --audit-log /absolute/path/config/audit.jsonl
```

HTTP clients connect to `http://127.0.0.1:8000/mcp`. The process remains alive
across independent client sessions until it receives a termination signal. It
owns one long-lived upstream MCP subprocess and closes that subprocess during
shutdown.

By default, the relay binds one trusted static principal and zero or more groups
at startup. This is appropriate for stdio and isolated service identities. In
Streamable HTTP static mode every client shares that identity. Local JWT mode,
described below, supplies a verified identity per request. Never accept identity
headers directly from a client.

### Local JWT development mode

For local integration tests, Streamable HTTP can instead require a short-lived
HS256 JWT on every request. Create a random secret of at least 32 bytes and keep
it outside source control. Start the relay with `--jwt-secret-file`,
`--jwt-issuer`, and `--jwt-audience`. In this mode the static principal options
are ignored and the relay obtains the principal name and groups from the
verified token.

Mint a short-lived development token with:

```bash
uv run agent-trust-mint-jwt \
  --secret-file /secure/path/local-jwt-secret \
  --issuer agenttrust-local \
  --audience http://127.0.0.1:8000/mcp \
  --name alice \
  --group support-managers
```

The MCP HTTP client sends the resulting value as an `Authorization: Bearer`
header. Missing, malformed, expired, incorrectly signed, wrong-issuer, and
wrong-audience tokens receive HTTP 401 before MCP request processing.

This is not production identity. Anyone holding the shared signing secret can
mint arbitrary names and groups, so the secret belongs only to the trusted
local token issuer—not to an untrusted MCP client. Production deployments still
require OIDC/JWKS validation in phase 4.

The HTTP relay binds to loopback by default and enables MCP SDK DNS-rebinding
protection. For another hostname, repeat `--allowed-host`; browser clients with
an Origin header must also repeat `--allowed-origin`. This MVP does not provide
HTTP authentication or TLS, so do not expose it directly to an untrusted
network—place an authenticated TLS reverse proxy in front first.

The command, arguments, and working directory must exactly match the descriptor
used to create the signed fingerprint. Use `--arg=<value>` for arguments that
begin with a hyphen.

At startup the relay verifies the signature, key ID, audience, timestamps,
server ID, and descriptor fingerprint before spawning the upstream. It then:

- Filters `tools/list` using the bound principal, group rules, and deny precedence.
- Checks every `tools/call` again, including policy expiry.
- Returns an `isError=true` tool result for denied calls without forwarding them.
- Passes allowed upstream results through unchanged.

When `--audit-log` is omitted, decisions are written to stderr. Stdout remains
reserved for MCP protocol traffic. Audit events contain full arguments for
evidence, so protect the audit file as potentially sensitive data.

## Operations

- One relay loads one policy and fronts one upstream. Run separate relay
  instances for other approved servers.
- Stdio mode follows the launching client's lifecycle. Streamable HTTP mode is
  long-running and serves multiple MCP client sessions through `/mcp`.
- The HTTP service does not automatically restart a failed upstream process;
  restart the relay through a process supervisor if the upstream exits.
- Update dependencies with `uv lock --upgrade` and commit the resulting
  `uv.lock`; use `uv sync --frozen` in reproducible automation.
- Rotate policies before their required expiry. Removing a public key from the
  keyring also prevents policies signed by that key from starting.
- There is no live revocation service in this MVP.
- Environment-bearing descriptors, binary attestation, resources, prompts,
  and policy merging are out of scope.

## Gateway roadmap placeholders

The replacement-gateway controls intentionally left unimplemented are recorded
in `agent_trust/gateway/placeholders.py` and fail loudly if invoked:

4. Production OIDC/JWKS authentication. A local HS256 JWT development mode is
   available, but it is not a substitute for an identity provider.
5. Per-principal/tool rate limiting and atomic signed-policy hot reload.
6. TLS termination, either in-process or through a trusted load balancer.

Until those phases exist, the HTTP relay is not a complete Kong replacement and
must remain on a trusted network boundary.
