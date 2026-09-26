# AgentTrust

**AgentTrust** is a policy-enforcing relay between MCP clients and approved MCP servers. It verifies signed policies, authenticates callers, filters available tools, and authorizes tool calls using principal, group, and argument constraints. It records authorization decisions for review.

#### Overview

A trusted administrator, working through the **Admin UI** registers different upstream MCP servers along with the different tools available and which are specifically allowed to which groups based on his/her organization. This is a **signed policy.** The relay validates arguments against signed policy constraints and gatekeeper prevents any calls to the upstream MCP servers if it fails validation.

The **AgentTrust Gatekeeper** loads the policy on load and to authorize every call before an MCP client's request reaches an upstream MCP server.

AgentTrust provides:

- Signed authorization policies
- MCP server identity binding
- Principal- and group-based tool permissions
- Explicit allow and deny rules
- Tool argument validation
- Filtered tool discovery
- Auditable authorization decisions

The gateway follows three core rules:

1. Access is denied by default.
2. An applicable deny rule overrides every allow rule.
3. Tool arguments must satisfy at least one applicable allow rule.

AgentTrust addresses these OWASP Agentic Security Initiative threat classes:

| **Threat**                           | **How it shows up here**                                                                              |
| ------------------------------------ | ----------------------------------------------------------------------------------------------------- |
| ASI01 — Agent Goal Hijack            | Untrusted tool output (the ticket body) proposes actions outside the task the user actually asked for |
| ASI02 — Tool Misuse and Exploitation | The agent selects an unauthorized tool (email.send), server, or argument value                        |

![AgentTrust architecture](architecture.png)

## Components

### Admin UI

The local Streamlit app (agent-trust-admin) which the admin uses to review and add 3<sup>rd</sup> party MCP servers and cryptographically signs it. It can also be used to look at audit logs

- **MCP Registry** — not a separate database; this is the approved_servers  
  list inside the signed policy itself, edited through  
  agent_trust/admin/service.py's append/update/delete functions.
- **Policy Generator** — agent-trust-generate  
  (agent_trust/cli/generate.py): the bootstrapping tool that creates a  
  brand-new policy, keyring, and signing key from scratch.
- **Policy Signer** — sign_policy(): used by both the Policy Generator and  
  every Admin UI edit, re-signing the complete policy with the same key.
- **Audit reviewer** — the Admin UI's "Audit logs" tab  
  (load_audit_events): reads and summarizes config/audit.jsonl.

### AgentTrust Gatekeeper

The relay process (agent-trust-relay). It loads a signed policy once,  
verifies it, spawns the approved upstream MCP server, and runs every proposed  
call through the boxes below before forwarding anything.

- **JWT Authentication** — LocalJwtVerifier  
  (agent_trust/gateway/local_jwt.py): verifies a bearer token via local  
  HS256 against a shared secret file. This is explicitly a development-only  
  mechanism, not OAuth or OIDC — production-grade OIDC/JWKS authentication is in roadmap.
- **Policy Verifier** — verify_policy(): checks the signature, key ID,  
  audience, and expiry. This runs on _every_ call, not only at startup.
- **Custom Verifier** — **not yet implemented**. An admin-approved,  
  hash-pinned custom validation function attached to a specific tool rule,  
  running after the schema check for business logic a static JSON Schema  
  can't express.
- **Authorisation Gatekeeper** — PolicyGate.check(): matches the server and  
  descriptor fingerprint, matches the caller's principal/groups against each  
  tool rule's subjects, applies deny-before-allow precedence, then validates  
  arguments against the matching allow rule's schema.
- **Audit Logger** — AuditWriter: appends one JSON line per authorization  
  decision to config/audit.jsonl, whether allowed or denied.

### MCP Servers

The upstream MCP server(s) a policy can approve — demo_support_mcp in this  
demo.

### MCP Client / AI Agents

This is the start of the flow, where an AI agent or any MCP client initiates a call to the upstream MCP servers through AgentTrust. For this demo 2 different clients are available.

mcp_client_llm.py - an LLM-driven client (via  
OpenRouter) — connects to the Gatekeeper over Streamable HTTP with a bearer  
JWT. (Stdio is also supported, using a static principal instead of a JWT; not  
shown in this diagram.)

mcp_client_direct.py – python based MCP client to call the upstream MCP servers through AgentTrust.

## Policy

A signed policy contains:

1. Policy identity, issuer, audience, signing key ID, and required expiry
2. One or more complete stdio launch descriptors and their SHA-256 fingerprints
3. Subject-aware allow and deny tool rules for each server
4. Principal IDs and groups on every rule (either match uses OR semantics)
5. A small JSON-Schema-style argument policy for every rule
6. An Ed25519 signature over canonical JSON

## Package layout
```
agent_trust/
├── core/       # Signed policy model, verification, and authorization gate
├── cli/        # Policy generator, JWT minting, and Admin UI launcher
├── mcp/        # Production stdio / Streamable HTTP enforcement relay
├── admin/      # Streamlit policy administration UI and its service layer
├── gateway/    # Local JWT verifier and unimplemented-phase placeholders
└── examples/   # Runnable end-to-end demonstration
demo_support_mcp/     # Separate synthetic third-party-style upstream MCP server
policy_specs/         # Administrator-controlled unsigned policy inputs
config/               # Generated signed policy, keyring, and local audit output
docs/                 # Architecture diagram referenced from the README
mcp_client_direct.py  # Minimal client: fixed tool calls, no LLM in the loop
mcp_client_llm.py     # LLM-driven client (OpenRouter) demonstrating the prompt-injection scenario
tests/                # Unit and stdio/HTTP integration tests
```
## Required tools and runtimes

The local demo and Streamable HTTP quickstart require:

- Python 3.11 or newer.
- uv for creating the virtual environment,  
  installing dependencies, and running the AgentTrust commands.
- OpenSSL for generating the local development JWT secret.
- A POSIX-compatible terminal such as bash or zsh for the documented shell  
  commands.
- Local TCP port 8000 available for the Streamable HTTP relay.

Confirm the tools are available:

```
    python3 --version
    uv --version
    openssl version
```

## Local setup

This walkthrough creates the relay's local JWT server key, generates a signed  
policy, starts the Admin UI to review it, starts the authenticated relay, then  
mints a token and runs the demo MCP client. Run every command from the  
agent-trust directory

### 1\. Install dependencies

```
    unset VIRTUAL_ENV
    cd agent-trust
    uv sync
```

unset VIRTUAL_ENV avoids uv selecting an unrelated active virtual  
environment. It is unnecessary if no other environment is active.

### 2\. Create the JWT server key

Create the relay's local HS256 signing secret once. This is the _server_  
key the relay uses to verify tokens — not a token itself, and never given to  
an MCP client:

```
    openssl rand -hex 32 > config/local-jwt-secret
    chmod 600 config/local-jwt-secret
```

### 3\. Generate the signed policy

The policy embeds the approved upstream command, ordered arguments, working  
directory, tool rules, and subject rules. The relay will not accept runtime  
overrides for this launch configuration. By default, generation records the  
current environment Python relative to this repository and uses . as the MCP  
working directory.

```
    uv run agent-trust-generate \
      --output-dir config \
      --tools policy_specs/support_demo.json \
      --server-id support-mcp \
      --arg=-m \
      --arg=demo_support_mcp.server
```

This creates config/policy.json, config/keyring.json, and the private  
config/signing-key.pem. Existing files are not overwritten. If these files  
already exist and are still valid, reuse them. Use --force only when you  
intend to rotate and replace all three policy files.

### 4\. Start the relay

Run the relay in its own terminal and leave it running:

```
    uv run agent-trust-relay \
      --transport streamable-http \
      --host 127.0.0.1 \
      --port 8000 \
      --http-path /mcp \
      --policy config/policy.json \
      --keyring config/keyring.json \
      --audit-log config/audit.jsonl \
      --jwt-secret-file config/local-jwt-secret \
      --jwt-issuer agenttrust-local \
      --jwt-audience http://127.0.0.1:8000/mcp
```

The relay should report that Uvicorn is listening on  
<http://127.0.0.1:8000>. Lines such as Processing request of type  
CallToolRequest confirm that requests reached the relay. Tool results are  
returned to the MCP client; they are not printed in the relay terminal.

### 5\. Generate a JWT token and run the demo

Create a test token whose group matches the policy:

```
    uv run agent-trust-mint-jwt \
      --secret-file config/local-jwt-secret \
      --issuer agenttrust-local \
      --audience http://127.0.0.1:8000/mcp \
      --name test-agent \
      --group support-managers \
      --lifetime-seconds 3600
```

Copy the token printed by this command. The issuer and audience must exactly  
match the relay options from step 5. Mint another token after it expires.

In a second terminal, place the token—not the signing secret—in an environment  
variable:

```
    export AGENTTRUST_JWT='paste-the-token-here'
```

Run the included mcp_client.py:

```
    uv run python mcp_client.py 481
    uv run python mcp_client.py 482
```

Ticket 481 exercises the benign path. Ticket 482 returns malicious content.  
An ordinary ClientSession does not interpret tool results or autonomously  
call another tool, so this controlled client deliberately recognizes the known  
synthetic instruction and attempts email.send. AgentTrust returns  
tool_explicitly_denied, and the denied call is added to the audit log. Other  
ticket IDs can also be passed and will be rejected by the signed argument  
policy.

To inspect authorization decisions in another terminal, run:

```
    tail -f config/audit.jsonl
```

Because --audit-log is configured, allow and deny decisions are written to  
that file instead of the relay terminal. Stop tail and the relay with  
Ctrl+C, and remove the JWT from the client shell when finished:

```
    unset AGENTTRUST_JWT
```

Local HS256 JWT mode is for development only. Anyone with  
config/local-jwt-secret can mint any principal or group. Production use  
requires TLS and validation against a trusted OIDC/JWKS identity provider.

## 6\. Local admin UI

```
    uv run agent-trust-admin
```

Open <http://127.0.0.1:8501> and sign in with the local demo credentials:

```
    Username: admin
    Password: password
```

Override both values before any shared use:

export AGENTTRUST_ADMIN_USERNAME='local-admin'  
export AGENTTRUST_ADMIN_PASSWORD= &lt;a-strong-password&gt;  
uv run agent-trust-admin

The UI verifies config/policy.json with config/keyring.json, displays the  
approved MCP launch descriptors and tool rules, and can append a new stdio MCP  
server. A successful addition updates policy_specs/admin_policy.json, backs  
up the previous policy as config/policy.json.bak, and re-signs the complete  
policy with config/signing-key.pem.

For local testing, the signed policy stores executable and working-directory  
paths relative to the AgentTrust repository. Start the relay from the  
agent-trust root: it resolves both values against that launch directory.  
Policy metadata and MCP descriptors are shown as labeled fields. A read-only  
full-policy JSON view appears below the approved MCP server cards without  
exposing a user-specific absolute repository path.

Use the **Add MCP server** tab to enter an executable name or path and an  
absolute or relative working directory. Absolute inputs are converted to paths  
relative to the directory where the admin UI is running; relative inputs are  
stored as entered after normalization. The local-only admin UI intentionally  
does not verify that the command or directory exists. Invalid paths will cause  
the relay to fail when that server is selected. Run the UI and relay from the  
agent-trust root so both use the same base directory. Enter launch arguments  
one per line in execution order, then enter the shared tool argument schema as  
a JSON object. Below the schema, each tool  
authorization row accepts an allow or deny effect, tool name, and  
comma-separated principals and groups. The schema is applied to every rule in  
that submission.

The policy tab can delete an approved MCP server after explicit confirmation.  
Deletion regenerates and re-signs both the policy and admin manifest. The final  
remaining server cannot be deleted because an AgentTrust policy must approve at  
least one MCP server.

The **Audit logs** tab reads the latest authorization decisions from  
config/audit.jsonl, summarizes allowed and denied calls, and displays the  
principal, groups, MCP server, tool, decision code, reason, and arguments. Use  
the Refresh button to reload decisions written by a running relay.

The UI never launches the configured MCP process. Restart the relay after a  
policy change. A policy containing multiple MCP servers also requires the  
relay's --server-id option.

## Gateway roadmap placeholders

The replacement-gateway controls intentionally left unimplemented are recorded  
in agent_trust/gateway/placeholders.py and fail loudly if invoked:

4\. Production OIDC/JWKS authentication. A local HS256 JWT development mode is  
available, but it is not a substitute for an identity provider.

5\. Per-principal/tool rate limiting and atomic signed-policy hot reload.

6\. TLS termination, either in-process or through a trusted load balancer.
