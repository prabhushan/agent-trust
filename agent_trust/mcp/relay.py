"""A tools-only stdio or Streamable HTTP relay protected by AgentTrust."""

from __future__ import annotations

import argparse
import asyncio
from contextlib import AbstractContextManager, asynccontextmanager
import json
import os
from pathlib import Path
import sys
from typing import Any, AsyncIterator, Mapping, TextIO

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.server.lowlevel import Server
from mcp.server.auth.middleware.bearer_auth import (
    AuthenticatedUser,
    BearerAuthBackend,
    RequireAuthMiddleware,
)
from mcp.server.stdio import stdio_server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.server.transport_security import TransportSecuritySettings
import mcp.types as types
from starlette.applications import Starlette
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Route
import uvicorn

from ..core.gate import GateDecision, PolicyGate, Principal
from ..core.policy import (
    PolicyError,
    SignedMcpPolicy,
    StdioServerDescriptor,
    decode_public_key,
    select_server_rule,
)
from ..gateway.local_jwt import LocalJwtVerifier


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
    principal: Principal | None,
) -> Server:
    """Create the client-facing MCP server for an initialized upstream."""
    server = Server("agent-trust-relay", version="1.0.0")

    def current_principal() -> Principal:
        if principal is not None:
            return principal
        request = server.request_context.request
        user = getattr(request, "user", None)
        if not isinstance(user, AuthenticatedUser):
            raise PolicyError("HTTP request has no authenticated principal")
        claims = user.access_token.claims or {}
        groups = claims.get("groups", [])
        return Principal(user.access_token.subject or claims["name"], tuple(groups))

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        gate.validate_binding()
        advertised: list[types.Tool] = []
        for upstream_tool in await _all_upstream_tools(upstream):
            schema = gate.tool_schema(upstream_tool.name, current_principal())
            if schema is None:
                continue
            advertised.append(
                upstream_tool.model_copy(update={"inputSchema": schema})
            )
        return advertised

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        decision = gate.check(name, arguments, current_principal())
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


@asynccontextmanager
async def relay_runtime(
    *,
    policy: SignedMcpPolicy,
    trusted_keys: Mapping[str, Any],
    descriptor: StdioServerDescriptor,
    principal: Principal | None,
    audit_log: str | None = None,
) -> AsyncIterator[Server]:
    """Validate policy and own the audit writer and one upstream process."""
    gate = PolicyGate(policy, trusted_keys, descriptor)
    gate.validate_binding()  # Refuse startup before the upstream process exists.
    launch_root = Path.cwd()
    launch_cwd = Path(descriptor.cwd or ".")
    if not launch_cwd.is_absolute():
        launch_cwd = (launch_root / launch_cwd).absolute()
    launch_command = descriptor.command
    command_path = Path(launch_command)
    is_path_command = os.sep in launch_command or (
        os.altsep is not None and os.altsep in launch_command
    )
    if not command_path.is_absolute() and is_path_command:
        launch_command = str((launch_root / command_path).absolute())
    params = StdioServerParameters(
        command=launch_command,
        args=list(descriptor.args),
        cwd=str(launch_cwd),
    )
    with AuditWriter(audit_log) as audit:
        async with stdio_client(params) as (upstream_read, upstream_write):
            async with ClientSession(upstream_read, upstream_write) as upstream:
                await upstream.initialize()
                yield create_relay_server(gate, upstream, audit, principal)


async def run_stdio_relay(
    *,
    policy: SignedMcpPolicy,
    trusted_keys: Mapping[str, Any],
    descriptor: StdioServerDescriptor,
    principal: Principal,
    audit_log: str | None = None,
) -> None:
    """Serve one client over stdio for the lifetime of that client."""
    if principal is None:
        raise PolicyError("stdio transport requires a static principal")
    async with relay_runtime(
        policy=policy,
        trusted_keys=trusted_keys,
        descriptor=descriptor,
        principal=principal,
        audit_log=audit_log,
    ) as relay:
        async with stdio_server() as (client_read, client_write):
            await relay.run(
                client_read,
                client_write,
                relay.create_initialization_options(),
            )


class _StreamableHttpEndpoint:
    """Expose the SDK session manager as a Starlette ASGI route."""

    def __init__(self, manager: StreamableHTTPSessionManager) -> None:
        self._manager = manager

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        await self._manager.handle_request(scope, receive, send)


def _default_allowed_hosts(host: str, port: int) -> list[str]:
    hosts = {host, f"{host}:{port}"}
    if host in {"127.0.0.1", "0.0.0.0", "::1"}:
        hosts.update({"localhost", f"localhost:{port}", "127.0.0.1", f"127.0.0.1:{port}"})
    return sorted(hosts)


async def run_http_relay(
    *,
    policy: SignedMcpPolicy,
    trusted_keys: Mapping[str, Any],
    descriptor: StdioServerDescriptor,
    principal: Principal | None,
    host: str,
    port: int,
    http_path: str = "/mcp",
    allowed_hosts: list[str] | None = None,
    allowed_origins: list[str] | None = None,
    audit_log: str | None = None,
    jwt_verifier: LocalJwtVerifier | None = None,
) -> None:
    """Serve the relay continuously over MCP Streamable HTTP."""
    if not http_path.startswith("/"):
        raise PolicyError("--http-path must start with '/'")
    if not 1 <= port <= 65535:
        raise PolicyError("--port must be between 1 and 65535")
    if (principal is None) == (jwt_verifier is None):
        raise PolicyError("HTTP relay requires exactly one static principal or JWT verifier")

    async with relay_runtime(
        policy=policy,
        trusted_keys=trusted_keys,
        descriptor=descriptor,
        principal=principal,
        audit_log=audit_log,
    ) as relay:
        security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=allowed_hosts or _default_allowed_hosts(host, port),
            allowed_origins=allowed_origins or [],
        )
        manager = StreamableHTTPSessionManager(
            app=relay,
            stateless=False,
            security_settings=security,
        )
        app: Any = Starlette(
            routes=[
                Route(
                    http_path,
                    endpoint=_StreamableHttpEndpoint(manager),
                    methods=["GET", "POST", "DELETE"],
                )
            ]
        )
        if jwt_verifier is not None:
            app = AuthenticationMiddleware(
                RequireAuthMiddleware(app, required_scopes=[]),
                backend=BearerAuthBackend(jwt_verifier),
            )
        config = uvicorn.Config(
            app,
            host=host,
            port=port,
            log_level="info",
            access_log=False,
            lifespan="off",
        )
        http_server = uvicorn.Server(config)
        async with manager.run():
            await http_server.serve()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the AgentTrust MCP relay")
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default="stdio",
        help="Client-facing MCP transport (default: stdio)",
    )
    parser.add_argument(
        "--jwt-secret-file",
        help="Enable local development JWT authentication using an HS256 secret file",
    )
    parser.add_argument(
        "--jwt-issuer",
        default="agenttrust-local",
        help="Required issuer for local JWT authentication (default: agenttrust-local)",
    )
    parser.add_argument(
        "--jwt-audience",
        help="Required audience for local JWT authentication, normally the canonical MCP URL",
    )
    parser.add_argument("--policy", required=True, help="Signed policy JSON file")
    parser.add_argument("--keyring", required=True, help="Trusted Ed25519 public-key JSON file")
    parser.add_argument(
        "--server-id",
        help="Approved server identifier; required only when the policy contains multiple servers",
    )
    parser.add_argument("--audit-log", help="Append decisions as JSONL instead of writing to stderr")
    parser.add_argument(
        "--principal-id",
        default="local-agent",
        help="Trusted static caller identity (ignored when local JWT authentication is enabled)",
    )
    parser.add_argument(
        "--principal-group",
        action="append",
        default=[],
        help="Trusted static caller group; repeat for multiple groups",
    )
    parser.add_argument("--host", default="127.0.0.1", help="HTTP bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="HTTP bind port (default: 8000)")
    parser.add_argument("--http-path", default="/mcp", help="Streamable HTTP endpoint (default: /mcp)")
    parser.add_argument(
        "--allowed-host",
        action="append",
        default=[],
        help="Allowed HTTP Host header; repeat for multiple values",
    )
    parser.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        help="Allowed browser Origin; repeat for multiple values",
    )
    return parser


def main() -> None:
    args = _parser().parse_args()
    try:
        policy = load_policy(args.policy)
        keyring = load_keyring(args.keyring)
        descriptor = select_server_rule(policy, args.server_id).descriptor
        jwt_verifier = None
        if args.jwt_secret_file:
            if args.transport != "streamable-http":
                raise PolicyError("--jwt-secret-file is supported only with streamable-http")
            if not args.jwt_audience:
                raise PolicyError("--jwt-audience is required with --jwt-secret-file")
            try:
                jwt_secret = Path(args.jwt_secret_file).read_bytes().strip()
            except OSError as exc:
                raise PolicyError(f"Unable to read local JWT secret: {exc}") from exc
            jwt_verifier = LocalJwtVerifier(jwt_secret, issuer=args.jwt_issuer, audience=args.jwt_audience)
        principal = None if jwt_verifier is not None else Principal(args.principal_id, tuple(args.principal_group))
        common = {
            "policy": policy,
            "trusted_keys": keyring,
            "descriptor": descriptor,
            "principal": principal,
            "audit_log": args.audit_log,
        }
        if args.transport == "stdio":
            asyncio.run(run_stdio_relay(**common))
        else:
            asyncio.run(
                run_http_relay(
                    **common,
                    host=args.host,
                    port=args.port,
                    http_path=args.http_path,
                    allowed_hosts=args.allowed_host or None,
                    allowed_origins=args.allowed_origin or None,
                    jwt_verifier=jwt_verifier,
                )
            )
    except (PolicyError, OSError) as exc:
        print(f"AgentTrust relay refused to start: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc


if __name__ == "__main__":
    main()
